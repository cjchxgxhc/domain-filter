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
RAW_BASE = "https://raw.githubusercontent.com/cjchxgxhc/domain-filter/refs/heads/main/data/rules"

# ═════════════════════════════════════════════════════════════════════════════
# Trie 节点
# ═════════════════════════════════════════════════════════════════════════════

class TrieNode:
    """Trie树节点,用于高效域名匹配"""
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
    # 控制台输出(带时间戳)
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    level = "ERROR" if error else "INFO"
    console_line = f"[{ts}] [{level}] {message}"
    print(console_line, flush=True)
    
    # 文件输出(不带时间戳和级别,更简洁)
    if log_file:
        try:
            log_file.parent.mkdir(parents=True, exist_ok=True)
            with log_file.open("a", encoding="utf-8") as f:
                # 如果是错误,添加 ERROR 标记
                file_line = f"[ERROR] {message}" if error else message
                f.write(file_line + "\n")
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
    清理原始域名字符串,移除常见前缀和后缀
    
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
    
    # 移除行内注释(# 前有空格)
    if " #" in line:
        line = line.split(" #", 1)[0].rstrip()
    
    return line.strip()

# ═════════════════════════════════════════════════════════════════════════════
# 核心提取函数
# ═════════════════════════════════════════════════════════════════════════════

def extract_domain(line: str, is_whitelist: bool = False) -> Optional[str]:
    """
    从规则行中提取域名
    
    支持多种格式:
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

    # 白名单规则:@@||example.com^
    if is_whitelist:
        m = re.match(
            r"^@@\|{0,2}([a-z0-9][a-z0-9\.-]*[a-z0-9])(?:\^)?(?:\$important)?(?:\$?)?$",
            cleaned, re.IGNORECASE
        )
        if m:
            candidate = m.group(1).lower().strip()
    else:
        # 黑名单:跳过白名单标记
        if cleaned.startswith("@@"):
            return None

        # AdBlock格式:||example.com^
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

        # 通配符格式:+.example.com, *.example.com
        elif no_quote.startswith(("+.", "*.")):
            candidate = no_quote[2:].strip().lower()

        # 纯域名
        elif is_valid_domain(no_quote):
            candidate = no_quote

    # Hosts格式:0.0.0.0 example.com
    if not candidate:
        if re.match(r"^(0\.0\.0\.0|127\.0\.0\.1|::1|local=)\s", cleaned, re.IGNORECASE):
            parts = re.split(r"\s+", cleaned.strip(), maxsplit=1)
            if len(parts) >= 2:
                candidate = clean_domain(parts[1])

    # 兜底:移除特殊字符后尝试验证
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
# 白名单过滤
# ═════════════════════════════════════════════════════════════════════════════

def build_trie(domains: Set[str]) -> TrieNode:
    """
    构建Trie树
    
    Args:
        domains: 域名集合
        
    Returns:
        Trie树根节点
    """
    root = TrieNode()
    
    for d in domains:
        parts = d.split(".")[::-1]
        node = root
        for part in parts:
            if part not in node.children:
                node.children[part] = TrieNode()
            node = node.children[part]
        node.is_end = True
    
    return root


def is_subdomain_of_any(domain: str, trie: TrieNode) -> bool:
    """
    检查域名是否为Trie中任何域名的子域
    
    Args:
        domain: 待检查的域名
        trie: Trie树根节点
        
    Returns:
        是否为子域
    """
    parts = domain.split(".")[::-1]
    node = trie
    
    for part in parts:
        if node.is_end:
            return True
        if part not in node.children:
            return False
        node = node.children[part]
    
    return node.is_end


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
        return black
    
    if not black:
        return set()
    
    white_trie = build_trie(white)
    result = set()
    
    black_list = list(black)
    chunks = [black_list[i:i + FILTER_CHUNK_SIZE] for i in range(0, len(black_list), FILTER_CHUNK_SIZE)]
    
    def process_chunk(chunk: List[str]) -> Set[str]:
        """处理单个数据块"""
        local = set()
        for d in chunk:
            if not is_subdomain_of_any(d, white_trie):
                local.add(d)
        return local
    
    with ThreadPoolExecutor(max_workers=FILTER_WORKERS) as executor:
        futures = [executor.submit(process_chunk, c) for c in chunks]
        for future in as_completed(futures):
            result.update(future.result())
            gc.collect()
    
    return result

# ═════════════════════════════════════════════════════════════════════════════
# 子域去重
# ═════════════════════════════════════════════════════════════════════════════

def remove_subdomains(domains: Set[str]) -> Set[str]:
    """
    移除重复的子域名
    
    Args:
        domains: 域名集合
        
    Returns:
        去重后的域名集合
    """
    if not domains:
        return set()
    
    sorted_domains = sorted(domains, key=lambda x: (len(x.split(".")), x))
    trie = TrieNode()
    result = set()
    
    for d in sorted_domains:
        if not is_subdomain_of_any(d, trie):
            result.add(d)
            # 添加到Trie
            parts = d.split(".")[::-1]
            node = trie
            for part in parts:
                if part not in node.children:
                    node.children[part] = TrieNode()
                node = node.children[part]
            node.is_end = True
    
    return result

# ═════════════════════════════════════════════════════════════════════════════
# 网络下载
# ═════════════════════════════════════════════════════════════════════════════

def create_session() -> requests.Session:
    """
    创建带重试机制的请求会话
    
    Returns:
        配置好的Session对象
    """
    session = requests.Session()
    
    retry_strategy = Retry(
        total=RETRY_COUNT,
        backoff_factor=RETRY_DELAY,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET", "HEAD"]
    )
    
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.headers.update({"User-Agent": USER_AGENT})
    
    return session


def download_url(url: str, session: requests.Session) -> List[str]:
    """
    下载单个URL的内容
    
    Args:
        url: 目标URL
        session: 请求会话
        
    Returns:
        文本行列表
    """
    try:
        resp = session.get(url, timeout=(CONNECT_TIMEOUT, READ_TIMEOUT))
        resp.raise_for_status()
        return resp.text.splitlines()
    except Exception as e:
        log(f"下载失败: {url} - {e}", error=True)
        return []


def download_all(urls: List[str]) -> Dict[str, List[str]]:
    """
    并行下载所有URL
    
    Args:
        urls: URL列表
        
    Returns:
        URL到内容的映射
    """
    if not urls:
        return {}
    
    log(f"\n开始下载 {len(urls)} 个规则源...")
    
    session = create_session()
    result = {}
    success = 0
    
    with ThreadPoolExecutor(max_workers=DOWNLOAD_WORKERS) as executor:
        future_to_url = {executor.submit(download_url, url, session): url for url in urls}
        
        for future in as_completed(future_to_url):
            url = future_to_url[future]
            try:
                lines = future.result()
                result[url] = lines
                if lines:
                    success += 1
                    log(f"  ✓ {url}")
                else:
                    log(f"  ✗ {url}", error=True)
            except Exception as e:
                log(f"  ✗ {url} - {e}", error=True)
                result[url] = []
    
    log(f"下载完成: {success}/{len(urls)} 成功\n")
    
    return result

# ═════════════════════════════════════════════════════════════════════════════
# 文件保存
# ═════════════════════════════════════════════════════════════════════════════

def save_domains(
    domains: Set[str],
    output_dir: Path,
    title: str,
    description: str,
    formats: List[str],
) -> None:
    """
    保存域名到各种格式文件
    
    Args:
        domains: 域名集合
        output_dir: 输出目录
        title: 规则组标题
        description: 描述
        formats: 输出格式列表
    """
    if not domains:
        log(f"  警告: {title} 没有域名可保存", error=True)
        return
    
    sorted_domains = sorted(domains)
    count = len(sorted_domains)
    now = datetime.datetime.now(ZoneInfo("Asia/Shanghai"))
    
    # 生成头部注释
    header_lines = [
        f"# Title: {title}",
        f"# Description: {description}" if description else None,
        f"# Homepage: {REPO_URL}",
        f"# Total: {count:,}",
        f"# Updated: {now.strftime('%Y-%m-%d %H:%M:%S %Z')}",
        "#",
    ]
    header = "\n".join(line for line in header_lines if line)
    
    # 1. domains.txt (纯域名列表)
    if "domains" in formats:
        domains_file = output_dir / "domains.txt"
        with domains_file.open("w", encoding="utf-8") as f:
            f.write(header + "\n")
            for d in sorted_domains:
                f.write(d + "\n")
        log(f"  ✓ 已保存: {domains_file.name}")
    
    # 2. adblock.txt (AdBlock格式)
    if "adblock" in formats:
        adblock_file = output_dir / "adblock.txt"
        with adblock_file.open("w", encoding="utf-8") as f:
            f.write("[Adblock Plus 2.0]\n")
            f.write(header + "\n")
            for d in sorted_domains:
                f.write(f"||{d}^\n")
        log(f"  ✓ 已保存: {adblock_file.name}")
    
    # 3. hosts.txt (Hosts格式)
    if "hosts" in formats:
        hosts_file = output_dir / "hosts.txt"
        with hosts_file.open("w", encoding="utf-8") as f:
            f.write(header + "\n")
            for d in sorted_domains:
                f.write(f"0.0.0.0 {d}\n")
        log(f"  ✓ 已保存: {hosts_file.name}")
    
    # 4. clash.yaml (Mihomo格式)
    if "clash" in formats:
        clash_file = output_dir / "clash.yaml"
        clash_data = {
            "payload": [f"+.{d}" for d in sorted_domains]
        }
        with clash_file.open("w", encoding="utf-8") as f:
            f.write(header + "\n")
            yaml.dump(clash_data, f, allow_unicode=True, default_flow_style=False, sort_keys=False)
        log(f"  ✓ 已保存: {clash_file.name}")
    
    # 5. singbox.json (sing-box格式)
    if "singbox" in formats:
        singbox_file = output_dir / "singbox.json"
        singbox_data = {
            "version": 2,
            "rules": [
                {
                    "domain_suffix": sorted_domains
                }
            ]
        }
        with singbox_file.open("w", encoding="utf-8") as f:
            json.dump(singbox_data, f, indent=2, ensure_ascii=False)
        log(f"  ✓ 已保存: {singbox_file.name}")

# ═════════════════════════════════════════════════════════════════════════════
# README 生成
# ═════════════════════════════════════════════════════════════════════════════

def generate_readme(output_root: Path, stats: Dict, groups_cfg: Dict) -> None:
    """
    生成 README.md
    
    Args:
        output_root: 输出根目录
        stats: 统计信息
        groups_cfg: 组配置
    """
    now_cst = datetime.datetime.now(ZoneInfo("Asia/Shanghai"))
    timestamp = now_cst.strftime("%Y-%m-%d %H:%M:%S")
    date_badge = now_cst.strftime("%Y--%m--%d_%H:%M:%S")
    
    # 只统计实际的规则组(非预设组)
    total = sum(v.get("final_count", 0) for k, v in stats.items() if k in groups_cfg)
    
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
        groups_cfg.keys(),
        key=lambda k: stats.get(k, {}).get("final_count", 0),
        reverse=True
    )
    
    for key in sorted_groups:
        if key not in stats:
            continue
        
        d = stats[key]
        name = d.get("display_name", key)
        desc = d.get("description", "无描述")
        count = d.get("final_count", 0)
        
        # 构建链接
        links = []
        
        # 检查实际存在的文件
        group_dir = output_root / key
        if (group_dir / "domains.txt").exists():
            links.append(f"[`Domains`]({RAW_BASE}/{key}/domains.txt)")
        if (group_dir / "adblock.txt").exists():
            links.append(f"[`AdBlock`]({RAW_BASE}/{key}/adblock.txt)")
        if (group_dir / "hosts.txt").exists():
            links.append(f"[`Hosts`]({RAW_BASE}/{key}/hosts.txt)")
        if (group_dir / "clash.yaml").exists():
            links.append(f"[`Clash`]({RAW_BASE}/{key}/clash.yaml) · [`Mrs`]({RAW_BASE}/{key}/clash.mrs)")
        if (group_dir / "singbox.json").exists():
            links.append(f"[`Sing-box`]({RAW_BASE}/{key}/singbox.json) · [`Srs`]({RAW_BASE}/{key}/singbox.srs)")
        
        link_text = " · ".join(links) if links else "—"
        
        lines.append(f"| **{name}** | {desc} | `{count:,}` | {link_text} |")
    
    lines.extend([
        "",
        "## 📖 使用说明",
        "",
        "### Clash/Mihomo",
        "```yaml",
        "rule-providers:",
        "  example:",
        "    type: http",
        "    behavior: domain",
        "    format: mrs  # 推荐使用编译后的 mrs 格式",
        f"    url: {RAW_BASE}/example/clash.mrs",
        "    interval: 86400",
        "",
        "rules:",
        "  - RULE-SET,example,REJECT",
        "```",
        "",
        "### sing-box",
        "```json",
        "{",
        '  "route": {',
        '    "rule_set": [',
        "      {",
        '        "type": "remote",',
        '        "tag": "example",',
        '        "format": "binary",',
        f'        "url": "{RAW_BASE}/example/singbox.srs",',
        '        "download_detour": "direct"',
        "      }",
        "    ],",
        '    "rules": [',
        "      {",
        '        "rule_set": ["example"],',
        '        "outbound": "block"',
        "      }",
        "    ]",
        "  }",
        "}",
        "```",
        "",
        "### AdBlock",
        "直接添加订阅链接到 AdGuard、uBlock Origin 等扩展:",
        "```",
        f"{RAW_BASE}/example/adblock.txt",
        "```",
        "",
        "### Hosts",
        "下载 hosts 文件并合并到系统 hosts 文件:",
        "```bash",
        f"curl {RAW_BASE}/example/hosts.txt >> /etc/hosts",
        "```",
        "",
        "---",
        f"*更新时间: {timestamp} (北京时间)*",
    ])
    
    readme_path = Path("README.md")
    with readme_path.open("w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    
    log(f"\n✓ README.md 已生成")

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
    log_file: Path,
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
        log_file: 主日志文件
        is_preset: 是否为预设组
    """
    title = config.get("title", key)
    desc = config.get("description", "")
    block_urls = config.get("blocklist", [])
    white_urls = config.get("whitelist", [])
    custom_black = config.get("custom_blacklist", [])
    custom_white = config.get("custom_whitelist", [])
    formats = config.get("formats", ["domains"])
    presets = config.get("preset_names", [])

    log(f"\n{'═' * 60}", log_file=log_file)
    log(f"处理 {'预设组' if is_preset else '规则组'}: {title} ({key})", log_file=log_file)
    log(f"{'═' * 60}", log_file=log_file)

    # 处理黑名单
    black_domains = set()
    block_stats = {}
    
    for url in block_urls:
        lines = downloaded.get(url, [])
        if lines:
            domains = parallel_extract(lines, is_whitelist=False)
            black_domains.update(domains)
            block_stats[url] = len(domains)
            log(f"  ├─ 黑名单源: {len(domains):,} 条 <- {url}", log_file=log_file)
        else:
            log(f"  ├─ 黑名单源: 0 条 (下载失败) <- {url}", error=True, log_file=log_file)
        
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
            log(f"  ├─ 白名单源: {len(domains):,} 条 <- {url}", log_file=log_file)
        else:
            log(f"  ├─ 白名单源: 0 条 (下载失败) <- {url}", error=True, log_file=log_file)
        
        del lines
        gc.collect()

    # 自定义黑名单处理(支持外部规则源和直接域名)
    custom_b = set()
    custom_black_urls = []
    
    for item in custom_black:
        # 跳过非字符串类型(如布尔值)
        if not isinstance(item, str):
            continue
            
        item_stripped = item.strip()
        if not item_stripped:
            continue
        
        # 判断是否为URL(支持http/https开头的外部规则源)
        if item_stripped.startswith(('http://', 'https://')):
            custom_black_urls.append(item_stripped)
        else:
            # 直接添加为域名(不进行格式验证)
            custom_b.add(item_stripped.lower())
    
    # 下载并处理自定义黑名单中的外部规则源
    if custom_black_urls:
        log(f"  ├─ 自定义黑名单包含 {len(custom_black_urls)} 个外部规则源", log_file=log_file)
        for url in custom_black_urls:
            lines = downloaded.get(url, [])
            if lines:
                # 直接逐行添加,不进行格式验证
                for line in lines:
                    line_clean = line.strip().lower()
                    if line_clean and not line_clean.startswith('#'):
                        custom_b.add(line_clean)
                log(f"    ├─ 外部规则源: {len([l for l in lines if l.strip() and not l.strip().startswith('#')])} 条 <- {url}", log_file=log_file)
            else:
                log(f"    ├─ 外部规则源: 0 条 (下载失败) <- {url}", error=True, log_file=log_file)
    
    if custom_b:
        log(f"  ├─ 自定义黑名单: {len(custom_b):,} 条", log_file=log_file)

    # 预设域名
    preset_domains = set()
    for pkey in presets:
        if pkey in final_cache:
            preset_count = len(final_cache[pkey])
            preset_domains.update(final_cache[pkey])
            log(f"  ├─ 预设 {pkey}: {preset_count:,} 条", log_file=log_file)

    # 合并所有黑名单
    all_black = black_domains | preset_domains | custom_b
    log(f"  ├─ 黑名单合并后: {len(all_black):,} 条", log_file=log_file)

    # 自定义白名单处理(支持外部规则源和直接域名)
    custom_white_set = set()
    custom_white_urls = []
    
    for item in custom_white:
        # 跳过非字符串类型
        if not isinstance(item, str):
            continue
            
        item_stripped = item.strip()
        if not item_stripped:
            continue
        
        # 判断是否为URL
        if item_stripped.startswith(('http://', 'https://')):
            custom_white_urls.append(item_stripped)
        else:
            # 直接添加为域名
            custom_white_set.add(item_stripped.lower())
    
    # 下载并处理自定义白名单中的外部规则源
    if custom_white_urls:
        log(f"  ├─ 自定义白名单包含 {len(custom_white_urls)} 个外部规则源", log_file=log_file)
        for url in custom_white_urls:
            lines = downloaded.get(url, [])
            if lines:
                for line in lines:
                    line_clean = line.strip().lower()
                    if line_clean and not line_clean.startswith('#'):
                        custom_white_set.add(line_clean)
                log(f"    ├─ 外部规则源: {len([l for l in lines if l.strip() and not l.strip().startswith('#')])} 条 <- {url}", log_file=log_file)
            else:
                log(f"    ├─ 外部规则源: 0 条 (下载失败) <- {url}", error=True, log_file=log_file)
    
    all_white = white_domains | custom_white_set
    if custom_white_set:
        log(f"  ├─ 自定义白名单: {len(custom_white_set):,} 条", log_file=log_file)
    
    after_filter = filter_whitelist(all_black, all_white)
    log(f"  ├─ 白名单过滤后: {len(after_filter):,} 条", log_file=log_file)

    # 去除子域
    final_domains = remove_subdomains(after_filter)
    final_count = len(final_domains)
    log(f"  └─ 去除子域后: {final_count:,} 条 (最终)", log_file=log_file)

    # 缓存结果(所有组都缓存,包括预设组)
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

    # 只有非预设组才保存文件
    if not is_preset:
        group_dir = output_root / key
        group_dir.mkdir(parents=True, exist_ok=True)
        save_domains(final_domains, group_dir, title, desc, formats)

# ═════════════════════════════════════════════════════════════════════════════
# 配置加载
# ═════════════════════════════════════════════════════════════════════════════

def load_config() -> Tuple[Dict, Dict]:
    """
    加载 config.yaml 配置文件
    
    Returns:
        (预设配置, 组配置) 元组
    """
    path = Path("data/script/config.yaml")
    
    if not path.is_file():
        log("错误: 缺少 data/script/config.yaml 文件", error=True)
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
    
    out_root = Path("data/rules")
    out_root.mkdir(parents=True, exist_ok=True)

    main_log = out_root / "log.txt"
    
    # 清空旧日志
    if main_log.exists():
        main_log.unlink()
    
    log("启动域名过滤工具", log_file=main_log)

    # 加载配置
    try:
        presets_cfg, groups_cfg = load_config()
    except Exception as e:
        log(f"配置加载失败: {e}", error=True, log_file=main_log)
        traceback.print_exc()
        sys.exit(1)

    # 收集所有URL(包括custom_blacklist和custom_whitelist中的URL)
    all_urls = set()
    for c in {**presets_cfg, **groups_cfg}.values():
        all_urls.update(c.get("blocklist", []))
        all_urls.update(c.get("whitelist", []))
        
        # 添加custom_blacklist中的URL
        for item in c.get("custom_blacklist", []):
            if isinstance(item, str) and item.strip().startswith(('http://', 'https://')):
                all_urls.add(item.strip())
        
        # 添加custom_whitelist中的URL
        for item in c.get("custom_whitelist", []):
            if isinstance(item, str) and item.strip().startswith(('http://', 'https://')):
                all_urls.add(item.strip())

    # 下载所有规则源
    try:
        downloaded = download_all(list(all_urls))
    except Exception as e:
        log(f"下载失败: {e}", error=True, log_file=main_log)
        traceback.print_exc()
        sys.exit(1)

    final_cache = {}
    all_stats = {}

    # 阶段1:处理预设组(不输出文件)
    log("\n" + "=" * 80, log_file=main_log)
    log("阶段 1: 处理预设组", log_file=main_log)
    log("=" * 80, log_file=main_log)
    
    for k, v in presets_cfg.items():
        try:
            process_group(
                k, v, downloaded, out_root, final_cache, all_stats, main_log, True
            )
        except Exception as e:
            log(f"预设组处理异常: {e}", error=True, log_file=main_log)
            traceback.print_exc()

    # 阶段2:处理普通组(输出文件)
    log("\n" + "=" * 80, log_file=main_log)
    log("阶段 2: 处理规则组", log_file=main_log)
    log("=" * 80, log_file=main_log)
    
    for k, v in groups_cfg.items():
        try:
            process_group(
                k, v, downloaded, out_root, final_cache, all_stats, main_log, False
            )
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
    
    log("\n" + "=" * 80, log_file=main_log)
    log(f"✓ 处理完成! 总计 {total_rules:,} 条规则", log_file=main_log)
    log(f"✓ 用时: {elapsed:.2f} 秒", log_file=main_log)
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
