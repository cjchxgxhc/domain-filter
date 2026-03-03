#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Domain Filter
https://github.com/cjchxgxhc/domain-filter
"""

import datetime
import gc
import json
import re
import sys
import threading
import time
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

import requests
import yaml
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from zoneinfo import ZoneInfo


# ─────────────────────────── 常量 ────────────────────────────────────────────

CHUNK_SIZE        = 40000
FILTER_CHUNK_SIZE = 25000
MAX_DOMAIN_LEN    = 253

DOWNLOAD_WORKERS = 10
FILTER_WORKERS   = 8
EXTRACT_WORKERS  = 6

CONNECT_TIMEOUT = 4
READ_TIMEOUT    = 12
RETRY_COUNT     = 3
RETRY_DELAY     = 1.5

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/128.0.0.0 Safari/537.36"
)

REPO_URL = "https://github.com/cjchxgxhc/domain-filter"
RAW_BASE = (
    "https://raw.githubusercontent.com/cjchxgxhc/domain-filter"
    "/refs/heads/main/data/rules"
)

VALID_RULE_TYPES = frozenset({"blocklist", "whitelist", "whitelist_suffix"})
# url 字段支持的规则来源类型（配置中 key 名）
URL_FIELDS = ("url", "pureurl", "adblockurl")


# ─────────────────────────── 枚举 ────────────────────────────────────────────

class LogLevel(Enum):
    INFO    = "INFO"
    WARNING = "WARNING"
    ERROR   = "ERROR"


# ─────────────────────────── 正则 ────────────────────────────────────────────

DOMAIN_PATTERN = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$",
    re.IGNORECASE,
)
# adblock 黑名单：||domain^
REGEX_ADBLOCK = re.compile(
    r"^\|\|([a-z0-9][a-z0-9.\-]*[a-z0-9])\^",
    re.IGNORECASE,
)
# adblock 白名单：@@||domain^
REGEX_WHITELIST = re.compile(
    r"^@@\|\|([a-z0-9][a-z0-9.\-]*[a-z0-9])\^",
    re.IGNORECASE,
)
REGEX_CLASH = re.compile(
    r"^(?:DOMAIN|DOMAIN-SUFFIX|HOST|HOST-SUFFIX)\s*,\s*"
    r"([a-z0-9][a-z0-9.\-]*[a-z0-9])(?:\s*,.*)?$",
    re.IGNORECASE,
)
REGEX_HOSTS = re.compile(
    r"^(?:0\.0\.0\.0|127\.0\.0\.1|::1)\s",
    re.IGNORECASE,
)
REGEX_LEAD_DASH  = re.compile(r"^\s*-\s*")
REGEX_IMPORTANT  = re.compile(r"\$important\b")

_REGEX_INVALID_CHARS = re.compile(r"[^a-z0-9.\-]", re.IGNORECASE)
_REGEX_IPV4          = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}(?:/\d+)?$")
_REGEX_PURE_DIGITS   = re.compile(r"^\d+$")


# ─────────────────────────── 日志 ────────────────────────────────────────────

_log_lock   = threading.Lock()
_log_buffer: List[Tuple[Path, str]] = []
_LOG_FLUSH_THRESHOLD = 10


def log(
    message: str,
    level: LogLevel = LogLevel.INFO,
    log_file: Optional[Path] = None,
) -> None:
    with _log_lock:
        timestamp = datetime.datetime.now().strftime("%m-%d %H:%M:%S.%f")[:-3]
        print(f"[{timestamp}] [{level.value}] {message}", flush=True)
        if log_file:
            try:
                log_file.parent.mkdir(parents=True, exist_ok=True)
                prefix = "" if level == LogLevel.INFO else f"[{level.value}] "
                _log_buffer.append((log_file, f"{prefix}{message}"))
                if (
                    len(_log_buffer) >= _LOG_FLUSH_THRESHOLD
                    or level in (LogLevel.ERROR, LogLevel.WARNING)
                ):
                    _flush_log_buffer()
            except Exception:
                pass


def _flush_log_buffer() -> None:
    global _log_buffer
    if not _log_buffer:
        return
    logs_by_file: Dict[Path, List[str]] = {}
    for path, msg in _log_buffer:
        logs_by_file.setdefault(path, []).append(msg)
    for path, msgs in logs_by_file.items():
        try:
            with path.open("a", encoding="utf-8") as f:
                f.write("\n".join(msgs) + "\n")
        except Exception:
            pass
    _log_buffer = []


def log_error(msg: str, log_file: Optional[Path] = None) -> None:
    log(msg, LogLevel.ERROR, log_file)


# ─────────────────────────── 域名验证 ────────────────────────────────────────

def is_valid_domain(domain: str) -> bool:
    if not domain:
        return False
    if len(domain) > MAX_DOMAIN_LEN or "." not in domain:
        return False
    if domain.startswith(".") or domain.endswith("."):
        return False
    return bool(DOMAIN_PATTERN.fullmatch(domain))


# ─────────────────────────── 行预处理 ────────────────────────────────────────

def strip_comments(line: str) -> str:
    """去除行首尾空白、整行注释及行内注释。"""
    line = line.strip()
    if not line or line.startswith(("#", "!")):
        return ""
    if " #" in line:
        line = line.split(" #", 1)[0].rstrip()
    if " !" in line:
        line = line.split(" !", 1)[0].rstrip()
    return line.strip()


# ─────────────────────────── 域名提取 ────────────────────────────────────────

def _extract_adblock_line(line: str, is_whitelist: bool) -> Optional[str]:
    """从 adblockurl 专用：仅识别 ||domain^ 或 @@||domain^，去注释后匹配。"""
    cleaned = strip_comments(line)
    if not cleaned:
        return None
    regex = REGEX_WHITELIST if is_whitelist else REGEX_ADBLOCK
    m = regex.match(cleaned)
    return m.group(1).lower() if m else None


def _clean_general_line(line: str, is_whitelist: bool) -> Optional[str]:
    """url/pureurl 通用预处理：去注释、去前导 '-'、去引号、去 $important。"""
    cleaned = strip_comments(line)
    if not cleaned:
        return None
    cleaned = REGEX_LEAD_DASH.sub("", cleaned).strip()
    cleaned = cleaned.strip("'\"")
    cleaned = REGEX_IMPORTANT.sub("", cleaned).strip()
    if not is_whitelist and cleaned.startswith("@@"):
        return None
    return cleaned or None


def _try_extract_domain(cleaned: str, is_whitelist: bool) -> Optional[str]:
    """按优先级尝试各格式提取，返回域名或 None（不含纯域名行兜底）。"""
    regex = REGEX_WHITELIST if is_whitelist else REGEX_ADBLOCK
    m = regex.match(cleaned)
    if m:
        return m.group(1).lower()

    m = REGEX_CLASH.match(cleaned)
    if m:
        return m.group(1).strip().lower()

    if cleaned.startswith(("+.", "*.")):
        return cleaned[2:].strip().lower()
    if cleaned.startswith(".") and len(cleaned) > 1:
        return cleaned[1:].lower()

    if REGEX_HOSTS.match(cleaned):
        parts = cleaned.split(None, 1)
        return parts[1].strip().lower() if len(parts) >= 2 else None

    return None


def _extract_url_line(line: str, is_whitelist: bool) -> Optional[str]:
    """url 字段：提取并验证域名合法性。"""
    cleaned = _clean_general_line(line, is_whitelist)
    if not cleaned:
        return None
    domain = _try_extract_domain(cleaned, is_whitelist)
    if domain is None:
        domain = cleaned.lower()
    return domain if is_valid_domain(domain) else None


def _is_pureurl_invalid(s: str) -> bool:
    """pureurl 纯域名无效检测：含非法字符 / 点开头或结尾 / IPv4 / 纯数字。"""
    return (
        bool(_REGEX_INVALID_CHARS.search(s))
        or s.startswith(".")
        or s.endswith(".")
        or bool(_REGEX_IPV4.match(s))
        or bool(_REGEX_PURE_DIGITS.match(s))
    )


def _extract_pureurl_line(line: str, is_whitelist: bool) -> Optional[str]:
    """pureurl 字段：提取但不验证域名合法性。"""
    cleaned = _clean_general_line(line, is_whitelist)
    if not cleaned:
        return None
    domain = _try_extract_domain(cleaned, is_whitelist)
    target = domain if domain is not None else cleaned.lower()
    return None if _is_pureurl_invalid(target) else target


# ─────────────────────────── 域名提取（列表级）────────────────────────────────

def _extract_chunk(chunk: List[str], extractor, is_whitelist: bool) -> Set[str]:
    result: Set[str] = set()
    for line in chunk:
        domain = extractor(line, is_whitelist)
        if domain:
            result.add(domain)
    return result


def _parallel_extract(
    lines: List[str],
    extractor,
    is_whitelist: bool,
    log_file: Optional[Path] = None,
) -> Set[str]:
    if not lines:
        return set()
    chunks = [lines[i : i + CHUNK_SIZE] for i in range(0, len(lines), CHUNK_SIZE)]
    result: Set[str] = set()
    with ThreadPoolExecutor(max_workers=EXTRACT_WORKERS) as executor:
        futures = [
            executor.submit(_extract_chunk, c, extractor, is_whitelist)
            for c in chunks
        ]
        for future in as_completed(futures):
            try:
                result.update(future.result())
            except Exception as e:
                log(f"并行提取失败: {e}", LogLevel.WARNING, log_file)
    return result


def extract_from_lines(
    lines: List[str],
    field: str,
    is_whitelist: bool,
    log_file: Optional[Path] = None,
) -> Set[str]:
    """根据字段类型从规则行列表中提取域名。

    url        → 提取并验证域名（支持所有格式）
    pureurl    → 提取但不验证（支持所有格式）
    adblockurl → 仅提取 ||domain^ 或 @@||domain^
    """
    if field == "adblockurl":
        return _parallel_extract(lines, _extract_adblock_line, is_whitelist, log_file)
    if field == "pureurl":
        return _parallel_extract(lines, _extract_pureurl_line, is_whitelist, log_file)
    # url
    return _parallel_extract(lines, _extract_url_line, is_whitelist, log_file)


# ─────────────────────────── Trie 树 ─────────────────────────────────────────

class TrieNode:
    __slots__ = ("children", "is_end")

    def __init__(self) -> None:
        self.children: Dict[str, "TrieNode"] = {}
        self.is_end: bool = False


def _build_trie(domains: Set[str]) -> TrieNode:
    root = TrieNode()
    for domain in domains:
        node = root
        for part in reversed(domain.split(".")):
            node = node.children.setdefault(part, TrieNode())
        node.is_end = True
    return root


def _is_subdomain_of_any(domain: str, trie: TrieNode) -> bool:
    node = trie
    for part in reversed(domain.split(".")):
        if node.is_end:
            return True
        if part not in node.children:
            return False
        node = node.children[part]
    return node.is_end


# ─────────────────────────── 白名单过滤 ──────────────────────────────────────

def filter_whitelist(black: Set[str], white: Set[str]) -> Set[str]:
    """子域名 Trie 过滤：移除黑名单中被白名单父域覆盖的条目。"""
    if not white or not black:
        return black
    trie = _build_trie(white)
    black_list = list(black)
    chunks = [
        black_list[i : i + FILTER_CHUNK_SIZE]
        for i in range(0, len(black_list), FILTER_CHUNK_SIZE)
    ]
    result: Set[str] = set()
    with ThreadPoolExecutor(max_workers=FILTER_WORKERS) as executor:
        futures = [
            executor.submit(lambda c: {d for d in c if not _is_subdomain_of_any(d, trie)}, chunk)
            for chunk in chunks
        ]
        for future in as_completed(futures):
            try:
                result.update(future.result())
            except Exception as e:
                log(f"白名单过滤失败: {e}", LogLevel.WARNING)
    return result


def filter_whitelist_exact(black: Set[str], white: Set[str]) -> Set[str]:
    """精确匹配过滤：仅移除与白名单完全相同的条目。"""
    return black - white if white and black else black


# ─────────────────────────── 子域去重 ────────────────────────────────────────

def remove_subdomains(domains: Set[str]) -> Set[str]:
    """移除冗余子域名，保留最短的父域名。"""
    if not domains:
        return set()
    sorted_domains = sorted(domains, key=lambda x: (x.count("."), x))
    trie   = TrieNode()
    result: Set[str] = set()
    for domain in sorted_domains:
        if not _is_subdomain_of_any(domain, trie):
            result.add(domain)
            node = trie
            for part in reversed(domain.split(".")):
                node = node.children.setdefault(part, TrieNode())
            node.is_end = True
    return result


# ─────────────────────────── 下载 ────────────────────────────────────────────

def create_session() -> requests.Session:
    session = requests.Session()
    retry = Retry(
        total=RETRY_COUNT,
        backoff_factor=RETRY_DELAY,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET", "HEAD"],
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.headers["User-Agent"] = USER_AGENT
    return session


def download_url(url: str, session: requests.Session) -> Tuple[bool, List[str]]:
    try:
        resp = session.get(url, timeout=(CONNECT_TIMEOUT, READ_TIMEOUT))
        resp.raise_for_status()
        return True, resp.text.splitlines()
    except Exception:
        return False, []


def download_all(
    urls: List[str],
    log_file: Optional[Path] = None,
) -> Dict[str, List[str]]:
    if not urls:
        return {}

    log(f"开始下载 {len(urls)} 个规则源...", log_file=log_file)
    t0      = time.time()
    session = create_session()
    result: Dict[str, List[str]] = {}
    failed: List[str] = []

    with ThreadPoolExecutor(max_workers=DOWNLOAD_WORKERS) as executor:
        fut_map = {executor.submit(download_url, url, session): url for url in urls}
        for future in as_completed(fut_map):
            url = fut_map[future]
            try:
                ok, lines = future.result()
                result[url] = lines
                if not ok:
                    failed.append(url)
            except Exception:
                failed.append(url)
                result[url] = []

    success = len(urls) - len(failed)
    log(
        f"下载完成：{success}/{len(urls)} 成功，耗时 {time.time() - t0:.2f} 秒",
        log_file=log_file,
    )
    if failed:
        log(f"下载失败（共 {len(failed)} 个）：", LogLevel.WARNING, log_file=log_file)
        for url in failed:
            log(f"  ✗ {url}", LogLevel.WARNING, log_file=log_file)
    log("", log_file=log_file)
    return result


# ─────────────────────────── 文件保存 ────────────────────────────────────────

def save_domains(
    simple_domains: Set[str],
    deduped_domains: Set[str],
    output_dir: Path,
    title: str,
    description: str,
    formats: List[str],
) -> Dict[str, int]:
    """将域名保存到各格式文件，返回各格式实际条目数。

    domain / hosts        → simple_domains（精确去重）
    adblock / clash / singbox → deduped_domains（子域去重）
    """
    if not simple_domains and not deduped_domains:
        log_error(f"警告：没有域名可保存（{output_dir.name}）")
        return {}

    now     = datetime.datetime.now(ZoneInfo("Asia/Shanghai"))
    now_str = now.strftime("%Y-%m-%d %H:%M:%S %Z")
    counts: Dict[str, int] = {}
    sorted_simple  = sorted(simple_domains)
    sorted_deduped = sorted(deduped_domains)

    def _bang_header(count: int) -> str:
        if not title:
            return ""
        parts = [
            f"! Title: {title}",
            f"! Description: {description}" if description else "",
            f"! Homepage: {REPO_URL}",
            f"! Total: {count:,}",
            f"! Updated: {now_str}",
            "!",
        ]
        return "\n".join(p for p in parts if p) + "\n"

    def _hash_header(count: int) -> str:
        if not title:
            return ""
        parts = [
            f"# Title: {title}",
            f"# Description: {description}" if description else "",
            f"# Homepage: {REPO_URL}",
            f"# Total: {count:,}",
            f"# Updated: {now_str}",
            "#",
        ]
        return "\n".join(p for p in parts if p) + "\n"

    if "domain" in formats:
        count = len(sorted_simple)
        counts["domain"] = count
        path = output_dir / "domain.txt"
        with path.open("w", encoding="utf-8") as f:
            f.write(_hash_header(count))
            f.write("\n".join(sorted_simple) + "\n")
        log(f"  ✓ 已保存：{path.name}（{count:,} 条，精确去重）")

    if "hosts" in formats:
        count = len(sorted_simple)
        counts["hosts"] = count
        path = output_dir / "hosts.txt"
        with path.open("w", encoding="utf-8") as f:
            f.write(_hash_header(count))
            for domain in sorted_simple:
                f.write(f"0.0.0.0 {domain}\n")
        log(f"  ✓ 已保存：{path.name}（{count:,} 条，精确去重）")

    if "adblock" in formats:
        count = len(sorted_deduped)
        counts["adblock"] = count
        path = output_dir / "adblock.txt"
        with path.open("w", encoding="utf-8") as f:
            f.write("[Adblock Plus 2.0]\n")
            f.write(_bang_header(count))
            for domain in sorted_deduped:
                f.write(f"||{domain}^\n")
        log(f"  ✓ 已保存：{path.name}（{count:,} 条，子域去重）")

    if "clash" in formats:
        count = len(sorted_deduped)
        counts["clash"] = count
        path = output_dir / "clash.yaml"
        with path.open("w", encoding="utf-8") as f:
            f.write(_hash_header(count))
            f.write("payload:\n")
            for domain in sorted_deduped:
                f.write(f"  - +.{domain}\n")
        log(f"  ✓ 已保存：{path.name}（{count:,} 条，子域去重）")

    if "singbox" in formats:
        count = len(sorted_deduped)
        counts["singbox"] = count
        path = output_dir / "singbox.json"
        with path.open("w", encoding="utf-8") as f:
            json.dump(
                {"version": 3, "rules": [{"domain_suffix": sorted_deduped}]},
                f,
                indent=2,
                ensure_ascii=False,
            )
        log(f"  ✓ 已保存：{path.name}（{count:,} 条，子域去重）")

    return counts


# ─────────────────────────── README 生成 ─────────────────────────────────────

def generate_readme(output_root: Path, stats: Dict) -> None:
    now_cst    = datetime.datetime.now(ZoneInfo("Asia/Shanghai"))
    timestamp  = now_cst.strftime("%Y-%m-%d %H:%M:%S")
    date_badge = now_cst.strftime("%Y--%m--%d_%H:%M:%S")

    fmt_labels = {
        "domain":  "Domain",
        "adblock": "AdBlock",
        "hosts":   "Hosts",
        "clash":   "Clash / Mrs",
        "singbox": "Sing-box / Srs",
    }
    fmt_files = {
        "domain":  lambda k: [f"{RAW_BASE}/{k}/domain.txt"],
        "adblock": lambda k: [f"{RAW_BASE}/{k}/adblock.txt"],
        "hosts":   lambda k: [f"{RAW_BASE}/{k}/hosts.txt"],
        "clash":   lambda k: [f"{RAW_BASE}/{k}/clash.yaml", f"{RAW_BASE}/{k}/clash.mrs"],
        "singbox": lambda k: [f"{RAW_BASE}/{k}/singbox.json", f"{RAW_BASE}/{k}/singbox.srs"],
    }

    lines = [
        "# 🛡️ Domain Filter",
        "",
        f"![Last Update](https://img.shields.io/badge/Last_Update-{date_badge}-green?style=flat-square)",
        "",
        "这是一个自动合并多源规则、精准去重并移除冗余子域的过滤列表。",
        "",
        "## 📊 规则组",
        "",
    ]

    for key in sorted(stats.keys(), key=lambda k: stats[k].get("id", 0)):
        data = stats[key]
        name = data.get("display_name", "")
        if not name:
            continue

        desc          = data.get("description", "")
        format_counts = data.get("format_counts", {})
        base_count    = data.get("final_count", 0)
        source_urls   = data.get("source_urls", [])

        lines.append(f"### {name}")
        lines.append("")
        if desc:
            lines.append(desc)
            lines.append("")

        unique_counts = set(format_counts.values()) if format_counts else set()
        if len(unique_counts) <= 1:
            lines.append(f"**规则数量**：`{base_count:,}`")
        else:
            parts = [
                f"{fmt_labels.get(fmt, fmt)} `{cnt:,}`"
                for fmt, cnt in format_counts.items()
            ]
            lines.append(f"**规则数量**：{'　'.join(parts)}")
        lines.append("")

        group_dir = output_root / key
        for fmt, file_getter in fmt_files.items():
            if fmt not in format_counts:
                continue
            file_urls  = file_getter(key)
            first_file = group_dir / Path(file_urls[0]).name
            if not first_file.exists():
                continue
            lines.append(f"<details><summary>{fmt_labels[fmt]}</summary>")
            lines.append("")
            for fu in file_urls:
                lines.append("```")
                lines.append(fu)
                lines.append("```")
                lines.append("")
            lines.append("</details>")
            lines.append("")

        if source_urls:
            lines.append("<details><summary>引用源</summary>")
            lines.append("")
            for src_url in sorted(source_urls):
                lines.append(f"- {src_url}")
            lines.append("")
            lines.append("</details>")
            lines.append("")

        lines.append("---")
        lines.append("")

    lines.append(f"*更新时间：{timestamp}（北京时间）*")

    readme_path = Path("README.md")
    with readme_path.open("w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")

    log("✓ README.md 已生成")


# ─────────────────────────── 配置加载 ────────────────────────────────────────

def load_config() -> List[Dict]:
    """加载配置文件，返回按 id 升序排列的规则组列表。

    字段说明：
      id:      int   处理顺序（小的先处理）
      enabled: bool  默认 true
      rules:   dict  key 为数字字符串，value 为规则定义
      output:  dict  enabled（默认 false）/ title / description / formats
    """
    path = Path("data/script/config.yaml")
    if not path.is_file():
        log_error("错误：缺少 data/script/config.yaml 文件")
        sys.exit(1)

    try:
        with path.open(encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
    except yaml.YAMLError as e:
        log_error(f"config.yaml 解析失败：{e}")
        sys.exit(1)
    except Exception as e:
        log_error(f"config.yaml 读取失败：{e}")
        sys.exit(1)

    groups = []
    for cfg_key, cfg in data.items():
        if not isinstance(cfg, dict) or "rules" not in cfg:
            continue
        groups.append({
            "cfg_key": cfg_key,
            "id":      int(cfg.get("id", 0)),
            "enabled": bool(cfg.get("enabled", True)),
            "rules":   cfg.get("rules") or {},
            "output":  cfg.get("output") or {},
        })

    groups.sort(key=lambda g: g["id"])
    enabled_count = sum(1 for g in groups if g["enabled"])
    log(f"✓ 配置已加载：共 {len(groups)} 个规则组，{enabled_count} 个已启用")
    return groups


# ─────────────────────────── 配置校验 ────────────────────────────────────────

def validate_config(groups: List[Dict], log_file: Optional[Path] = None) -> bool:
    errors: List[str] = []
    seen_ids: Dict[int, str] = {}

    for group in groups:
        key = group["cfg_key"]
        gid = group["id"]

        if gid in seen_ids:
            errors.append(f"规则组 '{key}' 与 '{seen_ids[gid]}' 的 id={gid} 重复")
        else:
            seen_ids[gid] = key

        rules = group.get("rules", {})
        if not isinstance(rules, dict):
            errors.append(f"规则组 '{key}' 的 rules 必须是字典")
            continue

        for rule_id, rule in rules.items():
            if not isinstance(rule, dict):
                errors.append(f"规则组 '{key}' rule[{rule_id}] 必须是字典")
                continue
            rule_type = rule.get("type", "blocklist")
            if rule_type not in VALID_RULE_TYPES:
                errors.append(
                    f"规则组 '{key}' rule[{rule_id}] type '{rule_type}' 无效，"
                    f"必须是 {'/'.join(sorted(VALID_RULE_TYPES))}"
                )

    for err in errors:
        log(err, LogLevel.ERROR, log_file)
    return not errors


# ─────────────────────────── URL 收集 ────────────────────────────────────────

def collect_urls(groups: List[Dict]) -> Set[str]:
    """从配置中收集所有需要下载的 URL。"""
    all_urls: Set[str] = set()
    for group in groups:
        if not group["enabled"]:
            continue
        for rule in (group.get("rules") or {}).values():
            if not isinstance(rule, dict):
                continue
            for field in URL_FIELDS:
                for url in rule.get(field) or []:
                    if isinstance(url, str):
                        url = url.strip()
                        if url.startswith(("http://", "https://")):
                            all_urls.add(url)
    return all_urls


# ─────────────────────────── 规则组处理 ──────────────────────────────────────

_cfg_key_to_id_map: Dict[str, int] = {}


def process_group(
    group: Dict,
    downloaded: Dict[str, List[str]],
    output_root: Path,
    group_cache: Dict[int, Set[str]],
    group_cache_urls: Dict[int, Set[str]],
    all_stats: Dict,
    log_file: Path,
) -> None:
    """处理单个规则组。

    按 rule id 升序遍历，根据 type 对当前域名集合执行：
      blocklist        → 并入
      whitelist        → 精确匹配过滤
      whitelist_suffix → 子域名 Trie 过滤
    """
    cfg_key    = group["cfg_key"]
    gid        = group["id"]
    output_cfg = group.get("output", {})

    output_enabled = output_cfg.get("enabled", False)
    title          = output_cfg.get("title", "")
    description    = output_cfg.get("description", "")
    formats        = output_cfg.get("formats", ["domain"])
    if isinstance(formats, str):
        formats = [formats]

    log(f"\n{'═' * 70}", log_file=log_file)
    log(f"处理规则组：{title or cfg_key} ({cfg_key}, id={gid})", log_file=log_file)
    log(f"{'═' * 70}", log_file=log_file)

    rules = group.get("rules", {})
    try:
        sorted_rule_ids = sorted(rules.keys(), key=lambda k: int(k))
    except (ValueError, TypeError):
        sorted_rule_ids = sorted(rules.keys())

    current_domains:  Set[str] = set()
    group_source_urls: Set[str] = set()

    for rule_id in sorted_rule_ids:
        rule = rules[rule_id]
        if not isinstance(rule, dict):
            continue

        rule_type = rule.get("type", "blocklist")
        is_wl     = rule_type in ("whitelist", "whitelist_suffix")

        log(f"  │  rule[{rule_id}] type={rule_type}", log_file=log_file)
        rule_domains: Set[str] = set()

        # url / pureurl / adblockurl：各字段对应各自提取逻辑
        for field in URL_FIELDS:
            for url in rule.get(field) or []:
                if not isinstance(url, str):
                    continue
                url = url.strip()
                group_source_urls.add(url)
                lines = downloaded.get(url, [])
                if lines:
                    domains = extract_from_lines(lines, field, is_wl, log_file)
                    rule_domains.update(domains)
                    log(f"  │    {field}：{len(domains):,} 条 <- {url}", log_file=log_file)
                else:
                    log(
                        f"  │    {field}：0 条（下载失败）<- {url}",
                        LogLevel.ERROR,
                        log_file=log_file,
                    )

        # domain：自定义域名条目
        custom = [
            d.strip().lower()
            for d in (rule.get("domain") or [])
            if isinstance(d, str) and d.strip()
        ]
        if custom:
            rule_domains.update(custom)
            log(f"  │    domain：{len(custom):,} 条自定义", log_file=log_file)

        # preset：引用已缓存规则组（id 必须小于当前组）
        for ref_key in rule.get("preset") or []:
            if not isinstance(ref_key, str):
                continue
            ref_key = ref_key.strip()
            ref_id  = _cfg_key_to_id_map.get(ref_key)
            if ref_id is not None and ref_id < gid and ref_id in group_cache:
                ref_set = group_cache[ref_id]
                rule_domains.update(ref_set)
                group_source_urls.update(group_cache_urls.get(ref_id, set()))
                log(f"  │    preset：{len(ref_set):,} 条 <- {ref_key}", log_file=log_file)
            else:
                log(
                    f"  │    preset：引用 '{ref_key}' 无效或 id 不小于当前组，跳过",
                    LogLevel.WARNING,
                    log_file=log_file,
                )

        log(f"  │    rule[{rule_id}] 共 {len(rule_domains):,} 条", log_file=log_file)

        before = len(current_domains)
        if rule_type == "blocklist":
            current_domains.update(rule_domains)
            added = len(current_domains) - before
            log(
                f"  │    → 加入黑名单，新增 {added:,} 条（合计 {len(current_domains):,}）",
                log_file=log_file,
            )
        elif rule_type == "whitelist":
            current_domains = filter_whitelist_exact(current_domains, rule_domains)
            removed = before - len(current_domains)
            log(
                f"  │    → 精确白名单过滤，移除 {removed:,} 条（剩余 {len(current_domains):,}）",
                log_file=log_file,
            )
        elif rule_type == "whitelist_suffix":
            current_domains = filter_whitelist(current_domains, rule_domains)
            removed = before - len(current_domains)
            log(
                f"  │    → 子域名白名单过滤，移除 {removed:,} 条（剩余 {len(current_domains):,}）",
                log_file=log_file,
            )

    log(f"  │  处理完毕，共 {len(current_domains):,} 条", log_file=log_file)

    group_cache[gid]      = current_domains
    group_cache_urls[gid] = group_source_urls

    if not output_enabled:
        log("  └─ 不输出文件（output.enabled=false）", log_file=log_file)
        return

    needs_dedup = any(f in formats for f in ("adblock", "clash", "singbox"))
    if needs_dedup:
        deduped_domains = remove_subdomains(current_domains)
        removed = len(current_domains) - len(deduped_domains)
        log(f"  │  子域去重：移除 {removed:,} 条冗余子域", log_file=log_file)
        final_count = len(deduped_domains)
    else:
        deduped_domains = current_domains
        final_count     = len(current_domains)

    log(f"  └─ 最终输出：{final_count:,} 条", log_file=log_file)

    group_dir = output_root / cfg_key
    group_dir.mkdir(parents=True, exist_ok=True)
    format_counts = save_domains(
        current_domains, deduped_domains, group_dir, title, description, formats
    )

    gc.collect()

    all_stats[cfg_key] = {
        "id":            gid,
        "display_name":  title,
        "description":   description,
        "final_count":   final_count,
        "format_counts": format_counts,
        "source_urls":   sorted(group_source_urls),
    }


# ─────────────────────────── 主入口 ──────────────────────────────────────────

def main() -> None:
    start_time = time.time()

    print("=" * 80)
    print("Domain Filter - 域名过滤工具".center(80))
    print("=" * 80)
    print()

    output_root = Path("data/rules")
    output_root.mkdir(parents=True, exist_ok=True)
    main_log = output_root / "log.txt"
    if main_log.exists():
        main_log.unlink()

    log("开始执行域名过滤工具", log_file=main_log)

    try:
        groups = load_config()
    except Exception as e:
        log_error(f"配置加载失败：{e}")
        log(traceback.format_exc(), LogLevel.ERROR, main_log)
        sys.exit(1)

    if not validate_config(groups, main_log):
        sys.exit(1)

    global _cfg_key_to_id_map
    _cfg_key_to_id_map = {g["cfg_key"]: g["id"] for g in groups}

    all_urls = collect_urls(groups)
    try:
        downloaded = download_all(list(all_urls), main_log)
    except Exception as e:
        log_error(f"下载过程中出现错误：{e}")
        log(traceback.format_exc(), LogLevel.ERROR, main_log)
        sys.exit(1)

    group_cache:      Dict[int, Set[str]] = {}
    group_cache_urls: Dict[int, Set[str]] = {}
    all_stats:        Dict = {}

    log("\n" + "=" * 80, log_file=main_log)
    log("处理规则组", log_file=main_log)
    log("=" * 80, log_file=main_log)

    for group in groups:
        if not group["enabled"]:
            log(
                f"  跳过规则组（已禁用）：{group['cfg_key']} (id={group['id']})",
                log_file=main_log,
            )
            continue
        try:
            process_group(
                group, downloaded, output_root,
                group_cache, group_cache_urls,
                all_stats, main_log,
            )
        except Exception as e:
            log_error(f"规则组处理异常 [{group['cfg_key']}]：{e}")
            log(traceback.format_exc(), LogLevel.ERROR, main_log)

    try:
        generate_readme(output_root, all_stats)
    except Exception as e:
        log_error(f"README 生成失败：{e}")
        log(traceback.format_exc(), LogLevel.ERROR, main_log)

    elapsed = time.time() - start_time
    log("\n" + "=" * 80, log_file=main_log)
    log(f"✓ 处理完成！耗时：{elapsed:.2f} 秒", log_file=main_log)
    log("=" * 80, log_file=main_log)

    _flush_log_buffer()
    gc.collect()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n用户中断（Ctrl+C）")
        log("用户中断", LogLevel.ERROR)
        sys.exit(130)
    except Exception as e:
        log_error(f"程序异常退出：{e}")
        traceback.print_exc()
        sys.exit(1)
