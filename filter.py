#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Domain Filter - 域名过滤工具
Repository: https://github.com/cjchxgxhc/domain-filter
"""

import datetime
import json
import re
import sys
import time
import traceback
import gc
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

import requests
import yaml
from concurrent.futures import ThreadPoolExecutor, as_completed
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from zoneinfo import ZoneInfo

# ═════════════════════════════════════════════════════════════════════════════
# 全局配置常量
# ═════════════════════════════════════════════════════════════════════════════

CHUNK_SIZE = 40000
FILTER_CHUNK_SIZE = 25000
MAX_DOMAIN_LEN = 253

DOWNLOAD_WORKERS = 10
FILTER_WORKERS = 8
EXTRACT_WORKERS = 6

CONNECT_TIMEOUT = 4
READ_TIMEOUT = 12
RETRY_COUNT = 3
RETRY_DELAY = 1.5

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/128.0.0.0 Safari/537.36"
)

DOMAIN_PATTERN = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$", re.IGNORECASE
)

REPO_URL = "https://github.com/cjchxgxhc/domain-filter"
RAW_BASE = "https://raw.githubusercontent.com/cjchxgxhc/domain-filter/refs/heads/main/OUTPUT"

# ═════════════════════════════════════════════════════════════════════════════
# Trie 节点
# ═════════════════════════════════════════════════════════════════════════════

class TrieNode:
    """Trie树节点，用于高效域名匹配"""
    __slots__ = ('children', 'is_end')
    
    def __init__(self):
        self.children: Dict[str, 'TrieNode'] = {}
        self.is_end: bool = False

# ═════════════════════════════════════════════════════════════════════════════
# 日志系统
# ═════════════════════════════════════════════════════════════════════════════

def log(message: str, error: bool = False, log_file: Optional[Path] = None) -> None:
    """
    统一日志输出函数
    
    Args:
        message: 日志消息
        error: 是否为错误日志
        log_file: 可选的日志文件路径
    """
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    level = "ERROR" if error else "INFO"
    line = f"[{ts}] [{level}] {message}"
    print(line, flush=True)
    
    if log_file:
        try:
            log_file.parent.mkdir(parents=True, exist_ok=True)
            with log_file.open("a", encoding="utf-8") as f:
                f.write(line + "\n")
        except Exception:
            pass  # 日志写入失败不应中断主流程

# ═════════════════════════════════════════════════════════════════════════════
# 域名验证与清理
# ═════════════════════════════════════════════════════════════════════════════

def is_valid_domain(domain: str) -> bool:
    """
    验证域名格式是否合法
    
    Args:
        domain: 待验证的域名
        
    Returns:
        是否为合法域名
    """
    if not domain:
        return False
    
    domain = domain.strip().lower()
    
    # 基本长度和格式检查
    if len(domain) > MAX_DOMAIN_LEN or "." not in domain:
        return False
    
    # 不允许以点开头或结尾
    if domain.startswith(".") or domain.endswith("."):
        return False
    
    # 正则表达式严格验证
    return bool(DOMAIN_PATTERN.fullmatch(domain))


def clean_domain(raw: str) -> str:
    """
    清理原始域名字符串，移除常见前缀和后缀
    
    Args:
        raw: 原始字符串
        
    Returns:
        清理后的域名
    """
    raw = raw.strip().lower()
    
    # 跳过注释行
    if "##" in raw:
        return ""
    
    # 移除常见前缀
    raw = re.sub(
        r"^(?:0\.0\.0\.0|127\.0\.0\.1|::1|local=|https?://|\|\||\*\.|\+\.|@@\|\|)\s*",
        "", raw, flags=re.IGNORECASE
    )
    
    # 移除特殊字符和注释
    raw = re.sub(r"[\^$#].*$", "", raw)
    
    return raw.strip(".")

# ═════════════════════════════════════════════════════════════════════════════
# 规则行预处理
# ═════════════════════════════════════════════════════════════════════════════

def strip_comments(line: str) -> str:
    """
    移除行内注释
    
    Args:
        line: 输入行
        
    Returns:
        去除注释后的内容
    """
    line = line.strip()
    
    # 空行或注释行
    if not line or line.startswith(("#", "!")):
        return ""
    
    # 移除行内注释（# 前有空格）
    if " #" in line:
        line = line.split(" #", 1)[0].rstrip()
    
    return line.strip()

# ═════════════════════════════════════════════════════════════════════════════
# 核心提取函数
# ═════════════════════════════════════════════════════════════════════════════

def extract_domain(line: str, is_whitelist: bool = False) -> Optional[str]:
    """
    从规则行中提取域名
    
    支持多种格式：
    - AdBlock: ||example.com^
    - Hosts: 0.0.0.0 example.com
    - Clash: DOMAIN-SUFFIX,example.com
    - Plain: example.com
    
    Args:
        line: 规则行
        is_whitelist: 是否为白名单规则
        
    Returns:
        提取的域名或None
    """
    cleaned = strip_comments(line)
    if not cleaned:
        return None

    # 移除YAML列表前缀
    cleaned = re.sub(r"^\s*-\s*", "", cleaned).strip()

    candidate = None

    # 白名单规则：@@||example.com^
    if is_whitelist:
        m = re.match(
            r"^@@\|{0,2}([a-z0-9][a-z0-9\.-]*[a-z0-9])(?:\^)?(?:\$important)?(?:\$?)?$",
            cleaned, re.IGNORECASE
        )
        if m:
            candidate = m.group(1).lower().strip()
    else:
        # 黑名单：跳过白名单标记
        if cleaned.startswith("@@"):
            return None

        # AdBlock格式：||example.com^
        m = re.match(
            r"^\|{1,2}([a-z0-9][a-z0-9\.-]*[a-z0-9])(?:\^)?(?:\$important)?(?:\$?)?$",
            cleaned, re.IGNORECASE
        )
        if m:
            candidate = m.group(1).lower().strip()

    # Clash/Surge格式
    if not candidate:
        no_quote = cleaned.strip("'\"").strip()

        # DOMAIN-SUFFIX,example.com
        m = re.match(
            r"^(DOMAIN|DOMAIN-SUFFIX|HOST|HOST-SUFFIX)\s*,\s*([a-z0-9][a-z0-9\.-]*[a-z0-9])(?:\s*,.*)?$",
            no_quote, re.IGNORECASE
        )
        if m:
            candidate = m.group(2).strip().lower()

        # 通配符格式：+.example.com, *.example.com
        elif no_quote.startswith(("+.", "*.")):
            candidate = no_quote[2:].strip().lower()

        # 纯域名
        elif is_valid_domain(no_quote):
            candidate = no_quote

    # Hosts格式：0.0.0.0 example.com
    if not candidate:
        if re.match(r"^(0\.0\.0\.0|127\.0\.0\.1|::1|local=)\s", cleaned, re.IGNORECASE):
            parts = re.split(r"\s+", cleaned.strip(), maxsplit=1)
            if len(parts) >= 2:
                candidate = clean_domain(parts[1])

    # 兜底：移除特殊字符后尝试验证
    if not candidate:
        cleaned_no_mark = re.sub(r"[\^\$\*\+@\|'\"]", "", cleaned).strip()
        if is_valid_domain(cleaned_no_mark):
            candidate = cleaned_no_mark

    # 最终验证
    if candidate and is_valid_domain(candidate):
        return candidate

    return None


def parallel_extract(lines: List[str], is_whitelist: bool = False) -> Set[str]:
    """
    并行提取域名
    
    Args:
        lines: 规则行列表
        is_whitelist: 是否为白名单
        
    Returns:
        提取的域名集合
    """
    if not lines:
        return set()

    result = set()
    chunks = [lines[i:i + CHUNK_SIZE] for i in range(0, len(lines), CHUNK_SIZE)]

    def process_chunk(chunk: List[str]) -> Set[str]:
        """处理单个数据块"""
        local = set()
        for ln in chunk:
            d = extract_domain(ln, is_whitelist)
            if d:
                local.add(d)
        return local

    with ThreadPoolExecutor(max_workers=EXTRACT_WORKERS) as executor:
        futures = [executor.submit(process_chunk, c) for c in chunks]
        for future in as_completed(futures):
            result.update(future.result())
            gc.collect()

    return result

# ═════════════════════════════════════════════════════════════════════════════
# Trie 相关函数
# ═════════════════════════════════════════════════════════════════════════════

def build_trie(domains: Set[str]) -> TrieNode:
    """
    构建域名Trie树（反向存储）
    
    Args:
        domains: 域名集合
        
    Returns:
        Trie树根节点
    """
    root = TrieNode()
    for domain in domains:
        # 反向分割：example.com -> ['com', 'example']
        parts = domain.lower().split('.')[::-1]
        node = root
        for part in parts:
            node = node.children.setdefault(part, TrieNode())
        node.is_end = True
    return root


def is_excluded(domain: str, root: TrieNode) -> bool:
    """
    检查域名是否被Trie树覆盖（父域名存在）
    
    Args:
        domain: 待检查的域名
        root: Trie树根节点
        
    Returns:
        是否被覆盖
    """
    if not domain:
        return False
    
    parts = domain.lower().split('.')[::-1]
    node = root
    
    for part in parts:
        if part not in node.children:
            return False
        node = node.children[part]
        # 找到父域名，当前域名被覆盖
        if node.is_end:
            return True
    
    return False

# ═════════════════════════════════════════════════════════════════════════════
# 白名单过滤
# ═════════════════════════════════════════════════════════════════════════════

def filter_whitelist(black: Set[str], white: Set[str]) -> Set[str]:
    """
    使用白名单过滤黑名单
    
    Args:
        black: 黑名单域名集合
        white: 白名单域名集合
        
    Returns:
        过滤后的域名集合
    """
    if not white:
        return black.copy()

    white_suffixes = {d.lower() for d in white if d}
    if not white_suffixes:
        return black.copy()

    # 构建白名单Trie树
    trie = build_trie(white_suffixes)

    # 过滤：保留未被白名单覆盖的域名
    result = set()
    for domain in black:
        if not is_excluded(domain, trie):
            result.add(domain)

    return result

# ═════════════════════════════════════════════════════════════════════════════
# 去子域
# ═════════════════════════════════════════════════════════════════════════════

def remove_subdomains(domains: Set[str]) -> Set[str]:
    """
    移除冗余子域名
    
    例如：如果存在 example.com，则移除 www.example.com, api.example.com 等
    
    Args:
        domains: 域名集合
        
    Returns:
        去重后的域名集合
    """
    if not domains:
        return set()

    valid = {d.lower() for d in domains if d}
    if not valid:
        return set()

    # 按长度排序，先处理短域名（父域名）
    sorted_domains = sorted(valid, key=len)

    trie = TrieNode()
    keep = set()

    for domain in sorted_domains:
        parts = domain.split(".")[::-1]
        node = trie
        covered = False

        # 检查是否已被父域名覆盖
        for i, part in enumerate(parts):
            if part not in node.children:
                # 未找到匹配路径，未被覆盖
                covered = False
                break
            node = node.children[part]
            # 找到父域名标记，且当前不是完整路径
            if node.is_end and i < len(parts) - 1:
                covered = True
                break

        # 未被覆盖，保留并加入Trie树
        if not covered:
            keep.add(domain)
            node = trie
            for p in parts:
                node = node.children.setdefault(p, TrieNode())
            node.is_end = True

    return keep

# ═════════════════════════════════════════════════════════════════════════════
# 下载相关
# ═════════════════════════════════════════════════════════════════════════════

def get_session() -> requests.Session:
    """
    创建配置好的HTTP会话
    
    Returns:
        requests.Session对象
    """
    session = requests.Session()
    session.headers.update({
        "User-Agent": USER_AGENT,
        "Accept": "*/*",
        "Accept-Encoding": "gzip, deflate"
    })
    
    # 重试策略
    retry = Retry(
        total=RETRY_COUNT,
        backoff_factor=1.2,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET", "HEAD"]  # 改进：明确允许的方法
    )
    
    adapter = HTTPAdapter(
        max_retries=retry,
        pool_connections=32,
        pool_maxsize=32
    )
    
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    
    return session


def download_url(url: str) -> Tuple[str, List[str]]:
    """
    下载单个URL内容
    
    Args:
        url: 目标URL
        
    Returns:
        (url, 行列表) 元组
    """
    # 跳过本地文件协议（预留）
    if url.startswith("file://"):
        return url, []
    
    session = get_session()
    
    for attempt in range(1, RETRY_COUNT + 1):
        try:
            resp = session.get(
                url,
                timeout=(CONNECT_TIMEOUT, READ_TIMEOUT),
                allow_redirects=True
            )
            resp.raise_for_status()
            
            # 处理响应文本
            text = resp.text.strip()
            lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
            
            log(f"下载成功: {url} ({len(lines):,} 行)")
            return url, lines
            
        except requests.exceptions.Timeout:
            log(f"下载超时 (尝试 {attempt}/{RETRY_COUNT}): {url}", error=True)
        except requests.exceptions.RequestException as e:
            log(f"下载失败 (尝试 {attempt}/{RETRY_COUNT}): {url} - {e}", error=True)
        except Exception as e:
            log(f"未知错误 (尝试 {attempt}/{RETRY_COUNT}): {url} - {e}", error=True)
        
        if attempt < RETRY_COUNT:
            time.sleep(RETRY_DELAY * attempt)  # 渐进延迟
    
    return url, []


def download_all(urls: List[str]) -> Dict[str, List[str]]:
    """
    并行下载所有URL
    
    Args:
        urls: URL列表
        
    Returns:
        {url: 行列表} 字典
    """
    # 去重并过滤无效URL
    unique_urls = list(dict.fromkeys(
        u.strip() for u in urls 
        if u.strip() and not u.startswith(("#", "!"))
    ))
    
    if not unique_urls:
        return {}
    
    log(f"开始下载 {len(unique_urls)} 个URL...")
    
    results = {}
    with ThreadPoolExecutor(max_workers=DOWNLOAD_WORKERS) as executor:
        future_map = {executor.submit(download_url, u): u for u in unique_urls}
        
        for future in as_completed(future_map):
            url, lines = future.result()
            results[url] = lines
            gc.collect()
    
    success_count = sum(1 for lines in results.values() if lines)
    log(f"下载完成: {success_count}/{len(unique_urls)} 成功")
    
    return results

# ═════════════════════════════════════════════════════════════════════════════
# 输出相关
# ═════════════════════════════════════════════════════════════════════════════

def build_header(
    title: str,
    description: str,
    count: int,
    timestamp: str,
    group_key: str,
    format_type: str = "adblock"
) -> str:
    """
    构建规则文件头部
    
    Args:
        title: 标题
        description: 描述
        count: 规则数量
        timestamp: 时间戳
        group_key: 组键名
        format_type: 格式类型
        
    Returns:
        头部文本
    """
    version = datetime.datetime.now(ZoneInfo("Asia/Shanghai")).strftime("%y%m%d")
    prefix = "!" if format_type == "adblock" else "#"
    
    lines = [
        f"{prefix} Title: {title}",
        f"{prefix} Description: {description or 'Merged advertising/tracking domains'}",
        f"{prefix} Homepage: {REPO_URL}",
        f"{prefix} Version: {version}",
        f"{prefix} Last modified: {timestamp}",
        f"{prefix} Blocked domains: {count:,}",
        f"{prefix}",
    ]
    
    return "\n".join(lines) + "\n"


def save_domains(
    domains: Set[str],
    group_dir: Path,
    group_name: str,
    description: str,
    block_sources: List[str],
    white_sources: List[str],
    custom_black: List[str],
    custom_white: List[str],
    presets: List[str],
    formats: List[str],
    is_preset: bool = False
) -> int:
    """
    保存域名到各种格式文件
    
    关键修复：此函数不再重复应用 custom_blacklist 和 custom_whitelist
    这些已经在 process_group 中处理过了
    
    Args:
        domains: 已经完全处理好的最终域名集合
        group_dir: 输出目录
        group_name: 组名
        description: 描述
        block_sources: 黑名单源列表（仅用于日志）
        white_sources: 白名单源列表（仅用于日志）
        custom_black: 自定义黑名单（仅用于日志）
        custom_white: 自定义白名单（仅用于日志）
        presets: 预设列表（仅用于日志）
        formats: 输出格式列表
        is_preset: 是否为预设组
        
    Returns:
        最终域名数量
    """
    # 预设组且无格式：仅缓存
    if is_preset and not formats:
        return len(domains)

    group_dir.mkdir(parents=True, exist_ok=True)
    
    now_cst = datetime.datetime.now(ZoneInfo("Asia/Shanghai"))
    timestamp = now_cst.strftime("%Y-%m-%d %H:%M:%S") + " CST"

    final_domains = sorted(domains)
    count = len(final_domains)

    # 生成各种格式
    if "adblock" in formats:
        header = build_header(group_name, description, count, timestamp, group_name, "adblock")
        content = header + "\n".join(f"||{d}^" for d in final_domains) + "\n"
        (group_dir / "adblock.txt").write_text(content, encoding="utf-8")

    if "clash" in formats:
        header = build_header(group_name, description, count, timestamp, group_name, "clash")
        lines = [header.rstrip(), "", "payload:"] + [f"  - '+.{d}'" for d in final_domains]
        (group_dir / "clash.yaml").write_text("\n".join(lines) + "\n", encoding="utf-8")

    if "domains" in formats:
        header = build_header(group_name, description, count, timestamp, group_name, "domains")
        content = header + "\n".join(final_domains) + "\n"
        (group_dir / "domains.txt").write_text(content, encoding="utf-8")

    if "singbox" in formats or "sing-box" in formats:
        data = {
            "version": 3,
            "rules": [
                {
                    "domain_suffix": [f"{d}" for d in final_domains]
                }
            ]
        }
        with (group_dir / "singbox.json").open("w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)

    log(f"✓ 组 {group_name} 保存完成: {count:,} 条规则")
    return count

# ═════════════════════════════════════════════════════════════════════════════
# 日志与 README
# ═════════════════════════════════════════════════════════════════════════════

def generate_group_log(group_dir: Path, stats: Dict) -> None:
    """
    生成组日志文件
    
    Args:
        group_dir: 组目录
        stats: 统计信息
    """
    path = group_dir / "group-log.txt"
    
    lines = [
        f"规则组: {stats['display_name']} ({stats['key']})",
        f"生成时间: {datetime.datetime.now(ZoneInfo('Asia/Shanghai')).strftime('%Y-%m-%d %H:%M:%S')} CST",
        f"最终数量: {stats['final_count']:,}",
        "",
        "=" * 60,
        "黑名单源:",
    ]
    
    for url, cnt in stats.get("block_sources", {}).items():
        lines.append(f"  • {url}")
        lines.append(f"    提取: {cnt:,} 条")

    if stats.get("presets"):
        lines.append("")
        lines.append("使用预设:")
        lines.extend(f"  • {p}" for p in stats["presets"])

    lines.append("")
    lines.append("=" * 60)
    lines.append("白名单源:")
    
    for url, cnt in stats.get("white_sources", {}).items():
        lines.append(f"  • {url}")
        lines.append(f"    提取: {cnt:,} 条")

    lines.extend([
        "",
        "=" * 60,
        "处理流程:",
        f"  1. 黑名单提取后: {stats.get('black_after_extract', 0):,} 条",
        f"  2. 白名单过滤后: {stats.get('after_filter', 0):,} 条",
        f"  3. 去除子域后: {stats['final_count']:,} 条",
    ])

    try:
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        log(f"  └─ 组日志: {path.name}")
    except Exception as e:
        log(f"组日志写入失败: {e}", error=True)


def generate_readme(out_dir: Path, info: Dict, groups_config: Dict) -> None:
    """
    生成 README.md
    
    Args:
        out_dir: 输出目录
        info: 统计信息
        groups_config: 组配置
    """
    now_cst = datetime.datetime.now(ZoneInfo("Asia/Shanghai"))
    timestamp = now_cst.strftime("%Y-%m-%d %H:%M:%S")
    date_badge = now_cst.strftime("%Y--%m--%d_%H:%M:%S")
    
    # 修复：只统计实际的规则组（非预设组）
    total = sum(v.get("final_count", 0) for k, v in info.items() if k in groups_config)

    lines = [
        "# 🛡️ Domain Filter",
        "",
        f"![Total Rules](https://img.shields.io/badge/Total_Rules-{total:,}-blue?style=flat-square)",
        f"![Last Update](https://img.shields.io/badge/Last_Update-{date_badge}-green?style=flat-square)",
        "",
        "这是一个自动合并多源规则、精准去重并移除冗余子域的过滤列表。",
        "",
        "## 📊 规则组详情统计",
        "",
        "| 规则组名称 | 描述 | 规则数量 | 获取链接 |",
        "| :--- | :--- | :--- | :--- |",
    ]

    # 按规则数量排序
    sorted_groups = sorted(
        groups_config.keys(),
        key=lambda k: info.get(k, {}).get("final_count", 0),
        reverse=True
    )

    for key in sorted_groups:
        if key not in info:
            continue
        
        d = info[key]
        name = d.get("display_name", key)
        desc = d.get("description", "无描述")
        count = d.get("final_count", 0)
        
        # 构建链接
        links = []
        
        # 检查实际存在的文件
        group_dir = out_dir / key
        if (group_dir / "domains.txt").exists():
            links.append(f"[`Domains`]({RAW_BASE}/{key}/domains.txt)")
        if (group_dir / "adblock.txt").exists():
            links.append(f"[`AdBlock`]({RAW_BASE}/{key}/adblock.txt)")
        if (group_dir / "clash.yaml").exists():
            links.append(f"[`Clash`]({RAW_BASE}/{key}/clash.yaml) · [`Mrs`]({RAW_BASE}/{key}/clash.mrs)")
        if (group_dir / "singbox.json").exists():
            links.append(f"[`Sing-box`]({RAW_BASE}/{key}/singbox.json) · [`Srs`]({RAW_BASE}/{key}/singbox.srs)")
        
        link_text = " · ".join(links) if links else "—"
        
        lines.append(f"| **{name}** | {desc} | `{count:,}` | {link_text} |")

    lines.extend([
        "",
        "---",
        f"*更新时间: {timestamp} (北京时间)*",
    ])

    readme_path = Path.cwd() / "README.md"
    readme_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    log(f"✓ 生成 README.md")

# ═════════════════════════════════════════════════════════════════════════════
# 组处理
# ═════════════════════════════════════════════════════════════════════════════

def process_group(
    key: str,
    config: Dict,
    downloaded: Dict[str, List[str]],
    output_root: Path,
    final_cache: Dict[str, Set[str]],
    stats_collection: Dict,
    is_preset: bool = False,
) -> None:
    """
    处理单个规则组
    
    Args:
        key: 组键名
        config: 组配置
        downloaded: 已下载的内容
        output_root: 输出根目录
        final_cache: 最终结果缓存
        stats_collection: 统计信息收集
        is_preset: 是否为预设组
    """
    title = config.get("title", key)
    desc = config.get("description", "")
    block_urls = config.get("blocklist", [])
    white_urls = config.get("whitelist", [])
    custom_black = config.get("custom_blacklist", [])
    custom_white = config.get("custom_whitelist", [])
    formats = config.get("formats", []) if is_preset else config.get("formats", ["domains"])
    presets = config.get("preset_names", [])

    log(f"\n{'═' * 60}")
    log(f"处理 {'预设组' if is_preset else '规则组'}: {title} ({key})")
    log(f"{'═' * 60}")

    group_dir = output_root / key
    group_dir.mkdir(parents=True, exist_ok=True)

    # 处理黑名单
    black_domains = set()
    block_stats = {}
    
    for url in block_urls:
        lines = downloaded.get(url, [])
        if lines:
            domains = parallel_extract(lines, is_whitelist=False)
            black_domains.update(domains)
            block_stats[url] = len(domains)
            log(f"  ├─ 黑名单源: {len(domains):,} 条 <- {url}")
        else:
            log(f"  ├─ 黑名单源: 0 条 (下载失败) <- {url}", error=True)
        
        del lines
        gc.collect()

    # 处理白名单
    white_domains = set()
    white_stats = {}
    
    for url in white_urls:
        lines = downloaded.get(url, [])
        if lines:
            domains = parallel_extract(lines, is_whitelist=True)
            white_domains.update(domains)
            white_stats[url] = len(domains)
            log(f"  ├─ 白名单源: {len(domains):,} 条 <- {url}")
        else:
            log(f"  ├─ 白名单源: 0 条 (下载失败) <- {url}", error=True)
        
        del lines
        gc.collect()

    # 自定义黑名单
    custom_b = {d.strip().lower() for d in custom_black if is_valid_domain(d.strip())}
    if custom_b:
        log(f"  ├─ 自定义黑名单: {len(custom_b):,} 条")

    # 预设域名
    preset_domains = set()
    for pkey in presets:
        if pkey in final_cache:
            preset_count = len(final_cache[pkey])
            preset_domains.update(final_cache[pkey])
            log(f"  ├─ 预设 {pkey}: {preset_count:,} 条")

    # 合并所有黑名单
    all_black = black_domains | preset_domains | custom_b
    log(f"  ├─ 黑名单合并后: {len(all_black):,} 条")

    # 白名单过滤（包括自定义白名单）
    # 修复：将 custom_whitelist 也在这里处理，而不是在 save_domains 中重复处理
    custom_white_set = {d.strip().lower() for d in custom_white if d.strip()}
    all_white = white_domains | custom_white_set
    if custom_white_set:
        log(f"  ├─ 自定义白名单: {len(custom_white_set):,} 条")
    
    after_filter = filter_whitelist(all_black, all_white)
    log(f"  ├─ 白名单过滤后: {len(after_filter):,} 条")

    # 去除子域
    final_domains = remove_subdomains(after_filter)
    final_count = len(final_domains)
    log(f"  └─ 去除子域后: {final_count:,} 条 (最终)")

    # 保存文件
    # 修复：传入已经完全处理好的 final_domains，save_domains 不再重复处理
    save_domains(
        final_domains, group_dir, title, desc,
        block_urls, white_urls, custom_black, custom_white,
        presets, formats, is_preset
    )

    # 缓存结果
    final_cache[key] = final_domains

    # 收集统计信息
    stats = {
        "key": key,
        "display_name": title,
        "description": desc,
        "final_count": final_count,
        "block_sources": block_stats,
        "white_sources": white_stats,
        "black_after_extract": len(all_black),
        "after_filter": len(after_filter),
        "presets": presets,
    }
    stats_collection[key] = stats
    
    # 生成组日志
    generate_group_log(group_dir, stats)

# ═════════════════════════════════════════════════════════════════════════════
# 配置加载
# ═════════════════════════════════════════════════════════════════════════════

def load_config() -> Tuple[Dict, Dict]:
    """
    加载 config.yaml 配置文件
    
    Returns:
        (预设配置, 组配置) 元组
    """
    path = Path("config.yaml")
    
    if not path.is_file():
        log("错误: 缺少 config.yaml 文件", error=True)
        sys.exit(1)
    
    try:
        with path.open(encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
    except yaml.YAMLError as e:
        log(f"config.yaml 解析失败: {e}", error=True)
        sys.exit(1)
    except Exception as e:
        log(f"config.yaml 读取失败: {e}", error=True)
        sys.exit(1)

    presets = data.get("presets", {})
    groups = data.get("groups", {})

    # 标准化组配置
    for conf in groups.values():
        # use_presets -> preset_names
        use_presets = conf.pop("use_presets", [])
        conf["preset_names"] = use_presets if isinstance(use_presets, list) else []
        
        # 设置默认值
        conf.setdefault("blocklist", [])
        conf.setdefault("whitelist", [])
        conf.setdefault("custom_blacklist", [])
        conf.setdefault("custom_whitelist", [])
        conf.setdefault("formats", ["domains"])

    log(f"✓ 加载配置: {len(presets)} 个预设, {len(groups)} 个规则组")
    
    return presets, groups

# ═════════════════════════════════════════════════════════════════════════════
# 主入口
# ═════════════════════════════════════════════════════════════════════════════

def main():
    """主函数"""
    start = time.time()
    
    print("=" * 80)
    print("Domain Filter - 域名过滤工具".center(80))
    print("=" * 80)
    print()
    
    out_root = Path("OUTPUT")
    out_root.mkdir(exist_ok=True)

    main_log = out_root / "domain-filter.log"
    log("启动域名过滤工具", log_file=main_log)

    # 加载配置
    try:
        presets_cfg, groups_cfg = load_config()
    except Exception as e:
        log(f"配置加载失败: {e}", error=True, log_file=main_log)
        traceback.print_exc()
        sys.exit(1)

    # 收集所有URL
    all_urls = set()
    for c in {**presets_cfg, **groups_cfg}.values():
        all_urls.update(c.get("blocklist", []))
        all_urls.update(c.get("whitelist", []))

    # 下载所有规则源
    try:
        downloaded = download_all(list(all_urls))
    except Exception as e:
        log(f"下载失败: {e}", error=True, log_file=main_log)
        traceback.print_exc()
        sys.exit(1)

    final_cache = {}
    all_stats = {}

    # 阶段1：处理预设组
    log("\n" + "=" * 80)
    log("阶段 1: 处理预设组")
    log("=" * 80)
    
    with ThreadPoolExecutor(max_workers=4) as ex:
        futures = [
            ex.submit(
                process_group,
                k, v, downloaded, out_root, final_cache, all_stats, True
            )
            for k, v in presets_cfg.items()
        ]
        
        for future in as_completed(futures):
            try:
                future.result()
            except Exception as e:
                log(f"预设组处理异常: {e}", error=True, log_file=main_log)
                traceback.print_exc()

    # 阶段2：处理普通组
    log("\n" + "=" * 80)
    log("阶段 2: 处理规则组")
    log("=" * 80)
    
    with ThreadPoolExecutor(max_workers=4) as ex:
        futures = [
            ex.submit(
                process_group,
                k, v, downloaded, out_root, final_cache, all_stats, False
            )
            for k, v in groups_cfg.items()
        ]
        
        for future in as_completed(futures):
            try:
                future.result()
            except Exception as e:
                log(f"规则组处理异常: {e}", error=True, log_file=main_log)
                traceback.print_exc()

    # 生成 README
    try:
        generate_readme(out_root, all_stats, groups_cfg)
    except Exception as e:
        log(f"README 生成失败: {e}", error=True, log_file=main_log)
        traceback.print_exc()

    # 完成
    elapsed = time.time() - start
    total_rules = sum(v.get("final_count", 0) for k, v in all_stats.items() if k in groups_cfg)
    
    log("\n" + "=" * 80)
    log(f"✓ 处理完成! 总计 {total_rules:,} 条规则")
    log(f"✓ 用时: {elapsed:.2f} 秒")
    log("=" * 80, log_file=main_log)
    
    gc.collect()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n用户中断 (Ctrl+C)")
        log("用户中断", error=True)
        sys.exit(130)
    except Exception as e:
        log(f"程序异常退出: {e}", error=True)
        traceback.print_exc()
        sys.exit(1)
