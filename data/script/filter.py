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

# 有效规则类型
# add             → 并入域名集合（原 blocklist）
# discard         → 精确匹配过滤（原 whitelist）
# discard_suffix  → 子域名 Trie 过滤（原 whitelist_suffix）
# match           → 仅保留与给定集合精确匹配的域名（discard 的反逻辑）
# match_suffix    → 仅保留被给定集合父域覆盖的域名（discard_suffix 的反逻辑）
VALID_RULE_TYPES = frozenset({"add", "discard", "discard_suffix", "match", "match_suffix"})

# url 字段支持的规则来源类型（配置中 key 名）
URL_FIELDS = ("url", "pureurl", "adblockurl")

# 配置文件路径
CONFIG_PATH = Path("data/script/config.yaml")

# ghproxy 默认反代前缀（可在 config.yaml global.ghproxy 中覆盖）
GHPROXY_DEFAULT = "https://ghproxy.net/"


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

# 匹配 raw.githubusercontent.com URL，提取各段
# https://raw.githubusercontent.com/{user}/{repo}/refs/heads/{branch}/{path}
# https://raw.githubusercontent.com/{user}/{repo}/{branch}/{path}
_REGEX_RAW_GH = re.compile(
    r"^https://raw\.githubusercontent\.com/"
    r"(?P<user>[^/]+)/(?P<repo>[^/]+)/"
    r"(?:refs/heads/)?"
    r"(?P<branch>[^/]+)/"
    r"(?P<path>.+)$"
)


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

def _extract_adblock_line(line: str, is_discard: bool) -> Optional[str]:
    """从 adblockurl 专用：仅识别 ||domain^ 或 @@||domain^，去注释后匹配。"""
    cleaned = strip_comments(line)
    if not cleaned:
        return None
    regex = REGEX_WHITELIST if is_discard else REGEX_ADBLOCK
    m = regex.match(cleaned)
    return m.group(1).lower() if m else None


def _clean_general_line(line: str, is_discard: bool) -> Optional[str]:
    """url/pureurl 通用预处理：去注释、去前导 '-'、去引号、去 $important。"""
    cleaned = strip_comments(line)
    if not cleaned:
        return None
    cleaned = REGEX_LEAD_DASH.sub("", cleaned).strip()
    cleaned = cleaned.strip("'\"")
    cleaned = REGEX_IMPORTANT.sub("", cleaned).strip()
    if not is_discard and cleaned.startswith("@@"):
        return None
    return cleaned or None


def _try_extract_domain(cleaned: str, is_discard: bool) -> Optional[str]:
    """按优先级尝试各格式提取，返回域名或 None（不含纯域名行兜底）。"""
    regex = REGEX_WHITELIST if is_discard else REGEX_ADBLOCK
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


def _extract_url_line(line: str, is_discard: bool) -> Optional[str]:
    """url 字段：提取并验证域名合法性。"""
    cleaned = _clean_general_line(line, is_discard)
    if not cleaned:
        return None
    domain = _try_extract_domain(cleaned, is_discard)
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


def _extract_pureurl_line(line: str, is_discard: bool) -> Optional[str]:
    """pureurl 字段：提取但不验证域名合法性。"""
    cleaned = _clean_general_line(line, is_discard)
    if not cleaned:
        return None
    domain = _try_extract_domain(cleaned, is_discard)
    target = domain if domain is not None else cleaned.lower()
    return None if _is_pureurl_invalid(target) else target


# ─────────────────────────── 域名提取（列表级）────────────────────────────────

def _extract_chunk(chunk: List[str], extractor, is_discard: bool) -> Set[str]:
    result: Set[str] = set()
    for line in chunk:
        domain = extractor(line, is_discard)
        if domain:
            result.add(domain)
    return result


def _parallel_extract(
    lines: List[str],
    extractor,
    is_discard: bool,
    log_file: Optional[Path] = None,
) -> Set[str]:
    if not lines:
        return set()
    chunks = [lines[i : i + CHUNK_SIZE] for i in range(0, len(lines), CHUNK_SIZE)]
    result: Set[str] = set()
    with ThreadPoolExecutor(max_workers=EXTRACT_WORKERS) as executor:
        futures = [
            executor.submit(_extract_chunk, c, extractor, is_discard)
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
    is_discard: bool,
    log_file: Optional[Path] = None,
) -> Set[str]:
    """根据字段类型从规则行列表中提取域名。

    url        → 提取并验证域名（支持所有格式）
    pureurl    → 提取但不验证（支持所有格式）
    adblockurl → 仅提取 ||domain^ 或 @@||domain^
    """
    if field == "adblockurl":
        return _parallel_extract(lines, _extract_adblock_line, is_discard, log_file)
    if field == "pureurl":
        return _parallel_extract(lines, _extract_pureurl_line, is_discard, log_file)
    return _parallel_extract(lines, _extract_url_line, is_discard, log_file)


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


# ─────────────────────────── 过滤操作 ────────────────────────────────────────

def filter_discard_suffix(current: Set[str], ref: Set[str]) -> Set[str]:
    """子域名 Trie 过滤：移除 current 中被 ref 父域覆盖的条目（原 whitelist_suffix）。"""
    if not ref or not current:
        return current
    trie = _build_trie(ref)
    current_list = list(current)
    chunks = [
        current_list[i : i + FILTER_CHUNK_SIZE]
        for i in range(0, len(current_list), FILTER_CHUNK_SIZE)
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
                log(f"discard_suffix 过滤失败: {e}", LogLevel.WARNING)
    return result


def filter_discard_exact(current: Set[str], ref: Set[str]) -> Set[str]:
    """精确匹配过滤：移除与 ref 完全相同的条目（原 whitelist）。"""
    return current - ref if ref and current else current


def filter_match_exact(current: Set[str], ref: Set[str]) -> Set[str]:
    """精确保留过滤：仅保留 current 中与 ref 精确匹配的条目（discard 的反逻辑）。"""
    return current & ref if ref and current else set()


def filter_match_suffix(current: Set[str], ref: Set[str]) -> Set[str]:
    """子域名 Trie 保留过滤：仅保留 current 中被 ref 父域覆盖的条目（discard_suffix 的反逻辑）。"""
    if not ref or not current:
        return set()
    trie = _build_trie(ref)
    current_list = list(current)
    chunks = [
        current_list[i : i + FILTER_CHUNK_SIZE]
        for i in range(0, len(current_list), FILTER_CHUNK_SIZE)
    ]
    result: Set[str] = set()
    with ThreadPoolExecutor(max_workers=FILTER_WORKERS) as executor:
        futures = [
            executor.submit(lambda c: {d for d in c if _is_subdomain_of_any(d, trie)}, chunk)
            for chunk in chunks
        ]
        for future in as_completed(futures):
            try:
                result.update(future.result())
            except Exception as e:
                log(f"match_suffix 过滤失败: {e}", LogLevel.WARNING)
    return result


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

def create_session(user_agent: str) -> requests.Session:
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
    session.headers["User-Agent"] = user_agent
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
    user_agent: str,
    log_file: Optional[Path] = None,
) -> Dict[str, List[str]]:
    if not urls:
        return {}

    log(f"开始下载 {len(urls)} 个规则源...", log_file=log_file)
    t0      = time.time()
    session = create_session(user_agent)
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


# ─────────────────────────── 文件头生成 ──────────────────────────────────────

def build_header(
    count: int,
    title: str,
    description: str,
    now_str: str,
    header_cfg: Dict,
    comment_char: str,
) -> str:
    """根据配置生成文件头注释。

    header_cfg 字段（均可在配置文件中自定义）：
      enabled      → bool，是否写入文件头，默认 true
      repo_url     → str，Homepage 行的 URL
      show_title   → bool，是否输出 Title 行，默认 true
      show_desc    → bool，是否输出 Description 行，默认 true
      show_homepage→ bool，是否输出 Homepage 行，默认 true
      show_total   → bool，是否输出 Total 行，默认 true
      show_updated → bool，是否输出 Updated 行，默认 true
      extra_lines  → list[str]，额外追加的注释行（不含前缀）
    """
    if not header_cfg.get("enabled", True):
        return ""
    if not title:
        return ""

    repo_url      = header_cfg.get("repo_url", "")
    show_title    = header_cfg.get("show_title", True)
    show_desc     = header_cfg.get("show_desc", True)
    show_homepage = header_cfg.get("show_homepage", True)
    show_total    = header_cfg.get("show_total", True)
    show_updated  = header_cfg.get("show_updated", True)
    extra_lines   = header_cfg.get("extra_lines", []) or []

    c = comment_char
    parts = []
    if show_title:
        parts.append(f"{c} Title: {title}")
    if show_desc and description:
        parts.append(f"{c} Description: {description}")
    if show_homepage and repo_url:
        parts.append(f"{c} Homepage: {repo_url}")
    if show_total:
        parts.append(f"{c} Total: {count:,}")
    if show_updated:
        parts.append(f"{c} Updated: {now_str}")
    for line in extra_lines:
        parts.append(f"{c} {line}")
    parts.append(c)

    return "\n".join(parts) + "\n"


# ─────────────────────────── 文件保存 ────────────────────────────────────────

def save_domains(
    simple_domains: Set[str],
    deduped_domains: Set[str],
    output_dir: Path,
    title: str,
    description: str,
    formats: List[str],
    header_cfg: Dict,
    timezone: str,
) -> Dict[str, int]:
    """将域名保存到各格式文件，返回各格式实际条目数。

    domain / hosts            → simple_domains（精确去重）
    adblock / clash / singbox → deduped_domains（子域去重）
    """
    if not simple_domains and not deduped_domains:
        log_error(f"警告：没有域名可保存（{output_dir.name}）")
        return {}

    now     = datetime.datetime.now(ZoneInfo(timezone))
    now_str = now.strftime("%Y-%m-%d %H:%M:%S %Z")
    counts: Dict[str, int] = {}
    sorted_simple  = sorted(simple_domains)
    sorted_deduped = sorted(deduped_domains)

    def _bang_header(count: int) -> str:
        return build_header(count, title, description, now_str, header_cfg, "!")

    def _hash_header(count: int) -> str:
        return build_header(count, title, description, now_str, header_cfg, "#")

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
                f.write(f"::1 {domain}\n")
                f.write(f"127.0.0.1 {domain}\n")
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


# ─────────────────────────── URL 加速转换 ────────────────────────────────────

def raw_to_accelerated(raw_url: str, ghproxy: str) -> Dict[str, str]:
    """将 raw.githubusercontent.com URL 转换为各加速地址。

    返回字典：
      jsdelivr_cdn    → https://cdn.jsdelivr.net/gh/{user}/{repo}@{branch}/{path}
      jsdelivr_fastly → https://fastly.jsdelivr.net/gh/{user}/{repo}@{branch}/{path}
      ghproxy         → {ghproxy}{raw_url}

    若 raw_url 不匹配 raw.githubusercontent.com，则 jsdelivr 两项为空字符串，
    ghproxy 项仍正常生成。
    """
    # 确保 ghproxy 前缀以 / 结尾
    proxy_prefix = ghproxy.rstrip("/") + "/"

    m = _REGEX_RAW_GH.match(raw_url)
    if m:
        user   = m.group("user")
        repo   = m.group("repo")
        branch = m.group("branch")
        path   = m.group("path")
        jsd_base = f"gh/{user}/{repo}@{branch}/{path}"
        return {
            "jsdelivr_cdn":    f"https://cdn.jsdelivr.net/{jsd_base}",
            "jsdelivr_fastly": f"https://fastly.jsdelivr.net/{jsd_base}",
            "ghproxy":         f"{proxy_prefix}{raw_url}",
        }
    return {
        "jsdelivr_cdn":    "",
        "jsdelivr_fastly": "",
        "ghproxy":         f"{proxy_prefix}{raw_url}",
    }


# ─────────────────────────── README 生成 ─────────────────────────────────────

def generate_readme(
    output_root: Path,
    stats: Dict,
    repo_url: str,
    raw_base: str,
    ghproxy: str,
) -> None:
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
        "domain":  lambda k: [f"{raw_base}/{k}/domain.txt"],
        "adblock": lambda k: [f"{raw_base}/{k}/adblock.txt"],
        "hosts":   lambda k: [f"{raw_base}/{k}/hosts.txt"],
        "clash":   lambda k: [f"{raw_base}/{k}/clash.yaml", f"{raw_base}/{k}/clash.mrs"],
        "singbox": lambda k: [f"{raw_base}/{k}/singbox.json", f"{raw_base}/{k}/singbox.srs"],
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
                accel = raw_to_accelerated(fu, ghproxy)
                cdn_url     = accel["jsdelivr_cdn"]
                fastly_url  = accel["jsdelivr_fastly"]
                ghproxy_url = accel["ghproxy"]

                # 原始链接
                lines.append("**原始**")
                lines.append("```")
                lines.append(fu)
                lines.append("```")
                lines.append("")

                # jsDelivr CDN
                if cdn_url:
                    lines.append("**jsDelivr CDN**（国内加速）")
                    lines.append("```")
                    lines.append(cdn_url)
                    lines.append("```")
                    lines.append("")

                # jsDelivr Fastly
                if fastly_url:
                    lines.append("**jsDelivr Fastly**（国内加速）")
                    lines.append("```")
                    lines.append(fastly_url)
                    lines.append("```")
                    lines.append("")

                # ghproxy
                lines.append("**ghproxy**（国内加速）")
                lines.append("```")
                lines.append(ghproxy_url)
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

def load_config() -> Tuple[Dict, List[Dict]]:
    """加载配置文件，返回 (全局设置, 规则组列表)。

    全局设置（global 键）：
      repo_url     → str  仓库主页 URL
      raw_base     → str  原始文件基础 URL（用于 README）
      output_root  → str  输出根目录，默认 data/rules
      timezone     → str  时区，默认 Asia/Shanghai
      user_agent   → str  HTTP User-Agent
      ghproxy      → str  ghproxy 反代前缀，默认 https://ghproxy.net/
      header       → dict 文件头配置（各格式通用）

    规则组（其他键）：
      id:      int   处理顺序（小的先处理）
      enabled: bool  默认 true
      rules:   list  规则列表（按顺序处理）
      output:  dict  enabled / title / description / formats
    """
    if not CONFIG_PATH.is_file():
        log_error(f"错误：缺少 {CONFIG_PATH} 文件")
        sys.exit(1)

    try:
        with CONFIG_PATH.open(encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
    except yaml.YAMLError as e:
        log_error(f"config.yaml 解析失败：{e}")
        sys.exit(1)
    except Exception as e:
        log_error(f"config.yaml 读取失败：{e}")
        sys.exit(1)

    # 全局设置
    global_cfg = data.pop("global", {}) or {}

    groups = []
    for cfg_key, cfg in data.items():
        if not isinstance(cfg, dict):
            continue

        # rules 支持 list（新格式）和 dict（旧格式，key 为数字字符串）
        raw_rules = cfg.get("rules") or []
        if isinstance(raw_rules, dict):
            # 兼容旧格式：按数字 key 排序转换为 list
            try:
                raw_rules = [raw_rules[k] for k in sorted(raw_rules.keys(), key=lambda x: int(x))]
            except (ValueError, TypeError):
                raw_rules = list(raw_rules.values())

        groups.append({
            "cfg_key": cfg_key,
            "id":      int(cfg.get("id", 0)),
            "enabled": bool(cfg.get("enabled", True)),
            "rules":   raw_rules,
            "output":  cfg.get("output") or {},
        })

    groups.sort(key=lambda g: g["id"])
    enabled_count = sum(1 for g in groups if g["enabled"])
    log(f"✓ 配置已加载：共 {len(groups)} 个规则组，{enabled_count} 个已启用")
    return global_cfg, groups


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

        rules = group.get("rules", [])
        if not isinstance(rules, list):
            errors.append(f"规则组 '{key}' 的 rules 必须是列表")
            continue

        for idx, rule in enumerate(rules):
            if not isinstance(rule, dict):
                errors.append(f"规则组 '{key}' rules[{idx}] 必须是字典")
                continue
            rule_type = rule.get("type", "add")
            if rule_type not in VALID_RULE_TYPES:
                errors.append(
                    f"规则组 '{key}' rules[{idx}] type '{rule_type}' 无效，"
                    f"必须是 {' / '.join(sorted(VALID_RULE_TYPES))}"
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
        for rule in (group.get("rules") or []):
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
    header_cfg: Dict,
    timezone: str,
) -> None:
    """处理单个规则组。

    按 rules 列表顺序遍历，根据 type 对当前域名集合执行：
      add            → 并入（原 blocklist）
      discard        → 精确匹配过滤（原 whitelist）
      discard_suffix → 子域名 Trie 过滤（原 whitelist_suffix）
      match          → 精确保留（discard 的反逻辑）
      match_suffix   → 子域名 Trie 保留（discard_suffix 的反逻辑）
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

    rules = group.get("rules", [])
    current_domains:   Set[str] = set()
    group_source_urls: Set[str] = set()

    for idx, rule in enumerate(rules):
        if not isinstance(rule, dict):
            continue

        rule_type  = rule.get("type", "add")
        is_discard = rule_type in ("discard", "discard_suffix", "match", "match_suffix")

        log(f"  │  rules[{idx}] type={rule_type}", log_file=log_file)
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
                    domains = extract_from_lines(lines, field, is_discard, log_file)
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

        log(f"  │    rules[{idx}] 共 {len(rule_domains):,} 条", log_file=log_file)

        before = len(current_domains)
        if rule_type == "add":
            current_domains.update(rule_domains)
            added = len(current_domains) - before
            log(
                f"  │    → 加入集合，新增 {added:,} 条（合计 {len(current_domains):,}）",
                log_file=log_file,
            )
        elif rule_type == "discard":
            current_domains = filter_discard_exact(current_domains, rule_domains)
            removed = before - len(current_domains)
            log(
                f"  │    → 精确丢弃，移除 {removed:,} 条（剩余 {len(current_domains):,}）",
                log_file=log_file,
            )
        elif rule_type == "discard_suffix":
            current_domains = filter_discard_suffix(current_domains, rule_domains)
            removed = before - len(current_domains)
            log(
                f"  │    → 后缀丢弃，移除 {removed:,} 条（剩余 {len(current_domains):,}）",
                log_file=log_file,
            )
        elif rule_type == "match":
            current_domains = filter_match_exact(current_domains, rule_domains)
            kept = len(current_domains)
            log(
                f"  │    → 精确保留，保留 {kept:,} 条（移除 {before - kept:,}）",
                log_file=log_file,
            )
        elif rule_type == "match_suffix":
            current_domains = filter_match_suffix(current_domains, rule_domains)
            kept = len(current_domains)
            log(
                f"  │    → 后缀保留，保留 {kept:,} 条（移除 {before - kept:,}）",
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
        current_domains, deduped_domains, group_dir,
        title, description, formats, header_cfg, timezone,
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

    try:
        global_cfg, groups = load_config()
    except Exception as e:
        log_error(f"配置加载失败：{e}")
        traceback.print_exc()
        sys.exit(1)

    # 从全局配置读取参数，未配置则使用内置默认值
    repo_url    = global_cfg.get("repo_url", REPO_URL)
    raw_base    = global_cfg.get("raw_base", RAW_BASE)
    output_root = Path(global_cfg.get("output_root", "data/rules"))
    timezone    = global_cfg.get("timezone", "Asia/Shanghai")
    user_agent  = global_cfg.get("user_agent", USER_AGENT)
    ghproxy     = global_cfg.get("ghproxy", GHPROXY_DEFAULT)
    header_cfg  = global_cfg.get("header", {}) or {}
    # 将 repo_url 注入 header_cfg（若未单独配置）
    header_cfg.setdefault("repo_url", repo_url)

    output_root.mkdir(parents=True, exist_ok=True)
    main_log = output_root / "log.txt"
    if main_log.exists():
        main_log.unlink()

    log("开始执行域名过滤工具", log_file=main_log)

    if not validate_config(groups, main_log):
        sys.exit(1)

    global _cfg_key_to_id_map
    _cfg_key_to_id_map = {g["cfg_key"]: g["id"] for g in groups}

    all_urls = collect_urls(groups)
    try:
        downloaded = download_all(list(all_urls), user_agent, main_log)
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
                header_cfg, timezone,
            )
        except Exception as e:
            log_error(f"规则组处理异常 [{group['cfg_key']}]：{e}")
            log(traceback.format_exc(), LogLevel.ERROR, main_log)

    try:
        generate_readme(output_root, all_stats, repo_url, raw_base, ghproxy)
    except Exception as e:
        log_error(f"README 生成失败：{e}")
        log(traceback.format_exc(), LogLevel.ERROR, main_log)

    elapsed = time.time() - start_time
    log("\n" + "=" * 80, log_file=main_log)
    log(f"✓ 处理完成！耗时：{elapsed:.2f} 秒", log_file=main_log)
    log("=" * 80, log_file=main_log)

    _flush_log_buffer()
    gc.collect()


# ─────────────────────────── 内置默认值（兜底）────────────────────────────────

REPO_URL = "https://github.com/cjchxgxhc/domain-filter"
RAW_BASE = (
    "https://raw.githubusercontent.com/cjchxgxhc/domain-filter"
    "/refs/heads/main/data/rules"
)

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
