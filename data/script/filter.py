#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Domain Filter
https://github.com/cjchxgxhc/domain-filter
"""

import datetime
import json
import re
import sys
import threading
import time
import traceback
import gc
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from enum import Enum

import requests
import yaml
from concurrent.futures import ThreadPoolExecutor, as_completed
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from zoneinfo import ZoneInfo


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

REPO_URL = "https://github.com/cjchxgxhc/domain-filter"
RAW_BASE = "https://raw.githubusercontent.com/cjchxgxhc/domain-filter/refs/heads/main/data/rules"


class LogLevel(Enum):
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"


class TrieNode:
    __slots__ = ('children', 'is_end')

    def __init__(self):
        self.children: Dict[str, 'TrieNode'] = {}
        self.is_end: bool = False


DOMAIN_PATTERN = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$",
    re.IGNORECASE
)
REGEX_ADBLOCK = re.compile(
    r"^\|\|([a-z0-9][a-z0-9\.-]*[a-z0-9])\^$",
    re.IGNORECASE
)
REGEX_WHITELIST = re.compile(
    r"^@@\|\|([a-z0-9][a-z0-9\.-]*[a-z0-9])\^$",
    re.IGNORECASE
)
REGEX_CLASH = re.compile(
    r"^(DOMAIN|DOMAIN-SUFFIX|HOST|HOST-SUFFIX)\s*,\s*([a-z0-9][a-z0-9\.-]*[a-z0-9])(?:\s*,.*)?$",
    re.IGNORECASE
)
REGEX_HOSTS = re.compile(
    r"^(0\.0\.0\.0|127\.0\.0\.1|::1|local=)\s",
    re.IGNORECASE
)


_log_lock = threading.Lock()
_log_buffer = []
_buffer_size_threshold = 10


def log(message: str, level: LogLevel = LogLevel.INFO, log_file: Optional[Path] = None) -> None:
    with _log_lock:
        timestamp = datetime.datetime.now().strftime("%m-%d %H:%M:%S.%f")[:-3]
        print(f"[{timestamp}] [{level.value}] {message}", flush=True)

        if log_file:
            try:
                log_file.parent.mkdir(parents=True, exist_ok=True)
                file_message = message if level == LogLevel.INFO else f"[{level.value}] {message}"
                _log_buffer.append((log_file, file_message))
                if len(_log_buffer) >= _buffer_size_threshold or level in (LogLevel.ERROR, LogLevel.WARNING):
                    _flush_log_buffer()
            except Exception:
                pass


def _flush_log_buffer() -> None:
    global _log_buffer
    if not _log_buffer:
        return
    logs_by_file: Dict[Path, List[str]] = {}
    for log_file, message in _log_buffer:
        logs_by_file.setdefault(log_file, []).append(message)
    for log_file, messages in logs_by_file.items():
        try:
            with log_file.open("a", encoding="utf-8") as f:
                f.write("\n".join(messages) + "\n")
        except Exception:
            pass
    _log_buffer = []


def log_error(msg: str, log_file: Optional[Path] = None) -> None:
    log(msg, LogLevel.ERROR, log_file)


def is_valid_domain(domain: str) -> bool:
    if not domain:
        return False
    domain = domain.strip().lower()
    if len(domain) > MAX_DOMAIN_LEN or "." not in domain:
        return False
    if domain.startswith(".") or domain.endswith("."):
        return False
    return bool(DOMAIN_PATTERN.fullmatch(domain))


def strip_comments(line: str) -> str:
    line = line.strip()
    if not line or line.startswith(("#", "!")):
        return ""
    if " #" in line:
        line = line.split(" #", 1)[0].rstrip()
    if " !" in line:
        line = line.split(" !", 1)[0].rstrip()
    return line.strip()


class DomainExtractor:

    @staticmethod
    def _extract_adblock(cleaned: str, is_whitelist: bool = False) -> Optional[str]:
        match = (REGEX_WHITELIST if is_whitelist else REGEX_ADBLOCK).match(cleaned)
        return match.group(1).lower().strip() if match else None

    @staticmethod
    def _extract_other_formats(cleaned: str) -> Optional[str]:
        match = REGEX_CLASH.match(cleaned)
        if match:
            domain = match.group(2).strip().lower()
            if is_valid_domain(domain):
                return domain

        if cleaned.startswith(("+.", "*.")):
            domain = cleaned[2:].strip().lower()
            if is_valid_domain(domain):
                return domain

        if cleaned.startswith(".") and len(cleaned) > 1:
            domain = cleaned[1:].lower()
            if is_valid_domain(domain):
                return domain

        if REGEX_HOSTS.match(cleaned):
            parts = re.split(r"\s+", cleaned.strip(), maxsplit=1)
            if len(parts) >= 2:
                domain = parts[1].strip().lower()
                if is_valid_domain(domain):
                    return domain

        if is_valid_domain(cleaned):
            return cleaned.lower()

        return None

    @classmethod
    def extract(cls, line: str, is_whitelist: bool = False) -> Optional[str]:
        cleaned = strip_comments(line)
        if not cleaned:
            return None

        cleaned = re.sub(r"^\s*-\s*", "", cleaned).strip()
        cleaned = cleaned.strip("'\"")
        cleaned = re.sub(r"\$important(?=\^|$)", "", cleaned)

        if not is_whitelist and cleaned.startswith("@@"):
            return None

        result = cls._extract_adblock(cleaned, is_whitelist)
        if result and is_valid_domain(result):
            return result

        return cls._extract_other_formats(cleaned)


def parse_url_with_format(url: str) -> Tuple[str, Optional[str]]:
    if '#' in url:
        base_url, format_type = url.rsplit('#', 1)
        format_type = format_type.lower().strip()
        if format_type in ('domain', 'adblock', 'hosts', 'proxy'):
            return (base_url, format_type)
    return (url, None)


def extract_domains_from_list(
    lines: List[str],
    url: str,
    is_whitelist: bool = False,
    log_file: Optional[Path] = None
) -> Set[str]:
    _, format_type = parse_url_with_format(url)

    if format_type == 'domain':
        return {
            stripped.lower()
            for line in lines
            if (stripped := strip_comments(line))
        }

    if format_type == 'adblock':
        regex = REGEX_WHITELIST if is_whitelist else REGEX_ADBLOCK
        result = set()

        def process_chunk(chunk: List[str]) -> Set[str]:
            local = set()
            for line in chunk:
                cleaned = strip_comments(line)
                if not cleaned:
                    continue
                cleaned = re.sub(r"\$important(?=\^|$)", "", cleaned)
                match = regex.match(cleaned)
                if match:
                    domain = match.group(1).lower().strip()
                    if is_valid_domain(domain):
                        local.add(domain)
            return local

        chunks = [lines[i:i + CHUNK_SIZE] for i in range(0, len(lines), CHUNK_SIZE)]
        with ThreadPoolExecutor(max_workers=EXTRACT_WORKERS) as executor:
            futures = [executor.submit(process_chunk, c) for c in chunks]
            for future in as_completed(futures):
                try:
                    result.update(future.result())
                except Exception as e:
                    log(f"AdBlock 格式提取失败: {e}", LogLevel.WARNING, log_file)
        return result

    return parallel_extract(lines, is_whitelist)


def parallel_extract(lines: List[str], is_whitelist: bool = False) -> Set[str]:
    if not lines:
        return set()

    result = set()
    chunks = [lines[i:i + CHUNK_SIZE] for i in range(0, len(lines), CHUNK_SIZE)]

    def process_chunk(chunk: List[str]) -> Set[str]:
        local = set()
        for line in chunk:
            domain = DomainExtractor.extract(line, is_whitelist)
            if domain:
                local.add(domain)
        return local

    with ThreadPoolExecutor(max_workers=EXTRACT_WORKERS) as executor:
        futures = [executor.submit(process_chunk, c) for c in chunks]
        for future in as_completed(futures):
            try:
                result.update(future.result())
            except Exception as e:
                log(f"并行提取失败: {e}", LogLevel.WARNING)
    return result


def _build_trie(domains) -> TrieNode:
    root = TrieNode()
    for domain in domains:
        node = root
        for part in domain.split(".")[::-1]:
            node = node.children.setdefault(part, TrieNode())
        node.is_end = True
    return root


def _is_subdomain_of_any(domain: str, trie: TrieNode) -> bool:
    node = trie
    for part in domain.split(".")[::-1]:
        if node.is_end:
            return True
        if part not in node.children:
            return False
        node = node.children[part]
    return node.is_end


def filter_whitelist(black: Set[str], white: Set[str]) -> Set[str]:
    if not white:
        return black
    if not black:
        return set()

    white_trie = _build_trie(white)
    black_list = list(black)
    chunks = [black_list[i:i + FILTER_CHUNK_SIZE] for i in range(0, len(black_list), FILTER_CHUNK_SIZE)]

    def process_chunk(chunk: List[str]) -> Set[str]:
        return {d for d in chunk if not _is_subdomain_of_any(d, white_trie)}

    result = set()
    with ThreadPoolExecutor(max_workers=FILTER_WORKERS) as executor:
        futures = [executor.submit(process_chunk, c) for c in chunks]
        for future in as_completed(futures):
            try:
                result.update(future.result())
            except Exception as e:
                log(f"白名单过滤失败: {e}", LogLevel.WARNING)
    return result


def remove_subdomains(domains: Set[str]) -> Set[str]:
    """子域去重：移除冗余子域名，保留最短的父域名。"""
    if not domains:
        return set()

    sorted_domains = sorted(domains, key=lambda x: (x.count("."), x))
    trie = TrieNode()
    result = set()

    for domain in sorted_domains:
        if not _is_subdomain_of_any(domain, trie):
            result.add(domain)
            node = trie
            for part in domain.split(".")[::-1]:
                node = node.children.setdefault(part, TrieNode())
            node.is_end = True

    return result


def create_session() -> requests.Session:
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


def download_url(url: str, session: requests.Session) -> Tuple[bool, List[str]]:
    try:
        response = session.get(url, timeout=(CONNECT_TIMEOUT, READ_TIMEOUT))
        response.raise_for_status()
        return (True, response.text.splitlines())
    except Exception:
        return (False, [])


def download_all(urls: List[str], log_file: Optional[Path] = None) -> Dict[str, List[str]]:
    if not urls:
        return {}

    start_time = time.time()
    log(f"开始下载 {len(urls)} 个规则源...", log_file=log_file)

    session = create_session()
    result = {}
    success = 0
    failed_urls = []

    with ThreadPoolExecutor(max_workers=DOWNLOAD_WORKERS) as executor:
        future_to_url = {executor.submit(download_url, url, session): url for url in urls}
        for future in as_completed(future_to_url):
            url = future_to_url[future]
            try:
                is_success, lines = future.result()
                result[url] = lines
                if is_success:
                    success += 1
                else:
                    failed_urls.append(url)
            except Exception:
                failed_urls.append(url)
                result[url] = []

    elapsed = time.time() - start_time
    log(f"下载完成：{success}/{len(urls)} 成功，耗时 {elapsed:.2f} 秒", log_file=log_file)

    if failed_urls:
        log(f"下载失败的链接（共 {len(failed_urls)} 个）：", LogLevel.WARNING, log_file=log_file)
        for url in failed_urls:
            log(f"  ✗ {url}", LogLevel.WARNING, log_file=log_file)

    log("", log_file=log_file)
    return result


def save_domains(
    simple_domains: Set[str],
    deduped_domains: Set[str],
    output_dir: Path,
    title: str,
    description: str,
    formats: List[str],
) -> Dict[str, int]:
    """将域名保存到各种格式的文件，返回各格式实际规则数量。

    domains / hosts  → simple_domains（简单去重，保留所有精确条目）
    adblock / clash / singbox → deduped_domains（子域去重，父域覆盖子域）
    """
    if not simple_domains and not deduped_domains:
        log_error(f"警告：{title} 没有域名可保存")
        return {}

    now = datetime.datetime.now(ZoneInfo("Asia/Shanghai"))
    counts: Dict[str, int] = {}
    sorted_simple = sorted(simple_domains)
    sorted_deduped = sorted(deduped_domains)

    def make_header(count: int) -> str:
        header_lines = [
            f"# Title: {title}",
            f"# Description: {description}" if description else None,
            f"# Homepage: {REPO_URL}",
            f"# Total: {count:,}",
            f"# Updated: {now.strftime('%Y-%m-%d %H:%M:%S %Z')}",
            "#",
        ]
        return "\n".join(line for line in header_lines if line is not None)

    if "domains" in formats:
        count = len(sorted_simple)
        counts["domains"] = count
        path = output_dir / "domains.txt"
        with path.open("w", encoding="utf-8") as f:
            f.write(make_header(count) + "\n")
            f.write("\n".join(sorted_simple) + "\n")
        log(f"  ✓ 已保存：{path.name}（{count:,} 条，简单去重）")

    if "hosts" in formats:
        count = len(sorted_simple)
        counts["hosts"] = count
        path = output_dir / "hosts.txt"
        with path.open("w", encoding="utf-8") as f:
            f.write(make_header(count) + "\n")
            for domain in sorted_simple:
                f.write(f"0.0.0.0 {domain}\n")
        log(f"  ✓ 已保存：{path.name}（{count:,} 条，简单去重）")

    if "adblock" in formats:
        count = len(sorted_deduped)
        counts["adblock"] = count
        path = output_dir / "adblock.txt"
        with path.open("w", encoding="utf-8") as f:
            f.write("[Adblock Plus 2.0]\n")
            f.write(make_header(count) + "\n")
            for domain in sorted_deduped:
                f.write(f"||{domain}^\n")
        log(f"  ✓ 已保存：{path.name}（{count:,} 条，子域去重）")

    if "clash" in formats:
        count = len(sorted_deduped)
        counts["clash"] = count
        path = output_dir / "clash.yaml"
        with path.open("w", encoding="utf-8") as f:
            f.write(make_header(count) + "\n")
            f.write("payload:\n")
            for domain in sorted_deduped:
                f.write(f"  - +.{domain}\n")
        log(f"  ✓ 已保存：{path.name}（{count:,} 条，子域去重）")

    if "singbox" in formats:
        count = len(sorted_deduped)
        counts["singbox"] = count
        singbox_data = {
            "version": 3,
            "rules": [{"domain_suffix": sorted_deduped}]
        }
        path = output_dir / "singbox.json"
        with path.open("w", encoding="utf-8") as f:
            json.dump(singbox_data, f, indent=2, ensure_ascii=False)
        log(f"  ✓ 已保存：{path.name}（{count:,} 条，子域去重）")

    return counts


def generate_readme(output_root: Path, stats: Dict, groups_cfg: Dict) -> None:
    now_cst = datetime.datetime.now(ZoneInfo("Asia/Shanghai"))
    timestamp = now_cst.strftime("%Y-%m-%d %H:%M:%S")
    date_badge = now_cst.strftime("%Y--%m--%d_%H:%M:%S")

    lines = [
        "# 🛡️ Domain Filter",
        "",
        f"![Last Update](https://img.shields.io/badge/Last_Update-{date_badge}-green?style=flat-square)",
        "",
        "这是一个自动合并多源规则、精准去重并移除冗余子域的过滤列表。",
        "",
        "## 📊 规则组详情统计",
        "",
        "| 规则组名称 | 描述 | 规则数量 | 获取链接 |",
        "| :--- | :--- | :--- | :--- |",
    ]

    sorted_groups = sorted(
        groups_cfg.keys(),
        key=lambda k: stats.get(k, {}).get("final_count", 0),
        reverse=True
    )

    for key in sorted_groups:
        if key not in stats:
            continue

        data = stats[key]
        name = data.get("display_name", key)
        desc = data.get("description", "无描述")
        format_counts: Dict[str, int] = data.get("format_counts", {})
        base_count = data.get("final_count", 0)

        unique_counts = set(format_counts.values()) if format_counts else {base_count}
        if len(unique_counts) <= 1:
            count_str = f"`{base_count:,}`"
        else:
            fmt_labels = {"domains": "Domains", "adblock": "AdBlock", "hosts": "Hosts", "clash": "Clash", "singbox": "Sing-box"}
            parts = [f"{fmt_labels.get(k, k)}: {v:,}" for k, v in format_counts.items()]
            count_str = " / ".join(parts)

        group_dir = output_root / key
        link_parts = []
        if (group_dir / "domains.txt").exists():
            link_parts.append(f"[`Domains`]({RAW_BASE}/{key}/domains.txt)")
        if (group_dir / "adblock.txt").exists():
            link_parts.append(f"[`AdBlock`]({RAW_BASE}/{key}/adblock.txt)")
        if (group_dir / "hosts.txt").exists():
            link_parts.append(f"[`Hosts`]({RAW_BASE}/{key}/hosts.txt)")
        if (group_dir / "clash.yaml").exists():
            link_parts.append(f"[`Clash`]({RAW_BASE}/{key}/clash.yaml) · [`Mrs`]({RAW_BASE}/{key}/clash.mrs)")
        if (group_dir / "singbox.json").exists():
            link_parts.append(f"[`Sing-box`]({RAW_BASE}/{key}/singbox.json) · [`Srs`]({RAW_BASE}/{key}/singbox.srs)")

        link_text = " · ".join(link_parts) if link_parts else "—"
        lines.append(f"| **{name}** | {desc} | {count_str} | {link_text} |")

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
        "    format: mrs",
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
        f"*更新时间：{timestamp}（北京时间）*",
    ])

    readme_path = Path("README.md")
    with readme_path.open("w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")

    log("✓ README.md 已生成")


def process_custom_list(
    custom_list: List,
    downloaded: Dict[str, List[str]],
    list_type: str = "黑名单",
    log_file: Optional[Path] = None
) -> Set[str]:
    result_set = set()
    external_urls = []

    for item in custom_list:
        if not isinstance(item, str):
            continue
        item_stripped = item.strip()
        if not item_stripped:
            continue
        if item_stripped.startswith(('http://', 'https://')):
            external_urls.append(item_stripped)
        else:
            result_set.add(item_stripped.lower())

    if external_urls:
        log(f"自定义{list_type}包含 {len(external_urls)} 个外部规则源", log_file=log_file)
        for url in external_urls:
            lines = downloaded.get(url, [])
            if lines:
                valid = {c for line in lines if (c := strip_comments(line))}
                result_set.update(d.lower() for d in valid)
                log(f"  └─ 外部规则源：{len(valid)} 条（不验证） <- {url}", log_file=log_file)
            else:
                log(f"  └─ 外部规则源：0 条（下载失败） <- {url}", LogLevel.ERROR, log_file=log_file)

    return result_set


def process_preset_group(
    key: str,
    config: Dict,
    downloaded: Dict[str, List[str]],
    final_cache: Dict[str, Set[str]],
    log_file: Path,
) -> None:
    title = config.get("display_name", config.get("title", key))
    block_urls = config.get("blocklist", [])
    white_urls = config.get("whitelist", [])
    custom_black = config.get("custom_blocklist", [])
    custom_white = config.get("custom_whitelist", [])

    log(f"\n{'═' * 70}", log_file=log_file)
    log(f"处理预设组：{title} ({key})", log_file=log_file)
    log(f"{'═' * 70}", log_file=log_file)

    black_domains: Set[str] = set()
    for url in block_urls:
        lines = downloaded.get(url, [])
        if lines:
            domains = extract_domains_from_list(lines, url, is_whitelist=False, log_file=log_file)
            black_domains.update(domains)
            log(f"  │  黑名单源：{len(domains):,} 条 <- {url}", log_file=log_file)
        else:
            log(f"  │  黑名单源：0 条（下载失败）<- {url}", LogLevel.ERROR, log_file=log_file)

    white_domains: Set[str] = set()
    for url in white_urls:
        lines = downloaded.get(url, [])
        if lines:
            domains = extract_domains_from_list(lines, url, is_whitelist=True, log_file=log_file)
            white_domains.update(domains)
            log(f"  │  白名单源：{len(domains):,} 条 <- {url}", log_file=log_file)
        else:
            log(f"  │  白名单源：0 条（下载失败）<- {url}", LogLevel.ERROR, log_file=log_file)

    after_source_filter = filter_whitelist(black_domains, white_domains)
    filtered_by_source = len(black_domains) - len(after_source_filter)
    if filtered_by_source > 0:
        log(f"  │  源级白名单过滤：移除 {filtered_by_source:,} 条", log_file=log_file)

    all_black = after_source_filter
    custom_black_set = process_custom_list(custom_black, downloaded, "黑名单", log_file)
    if custom_black_set:
        log(f"  │  自定义黑名单：{len(custom_black_set):,} 条", log_file=log_file)
        all_black = all_black | custom_black_set

    log(f"  │  黑名单合计：{len(all_black):,} 条", log_file=log_file)

    custom_white_set = process_custom_list(custom_white, downloaded, "白名单", log_file)
    if custom_white_set:
        log(f"  │  自定义白名单：{len(custom_white_set):,} 条", log_file=log_file)
        final_domains = filter_whitelist(all_black, custom_white_set)
        filtered_by_custom = len(all_black) - len(final_domains)
        if filtered_by_custom > 0:
            log(f"  │  自定义白名单过滤：移除 {filtered_by_custom:,} 条", log_file=log_file)
    else:
        final_domains = all_black

    log(f"  └─ 预设结果：{len(final_domains):,} 条（缓存）", log_file=log_file)
    final_cache[key] = final_domains


def process_normal_group(
    key: str,
    config: Dict,
    downloaded: Dict[str, List[str]],
    output_root: Path,
    final_cache: Dict[str, Set[str]],
    stats_collection: Dict,
    log_file: Path,
) -> None:
    title = config.get("display_name", config.get("title", key))
    description = config.get("description", "")
    block_urls = config.get("blocklist", [])
    white_urls = config.get("whitelist", [])
    custom_black = config.get("custom_blocklist", [])
    custom_white = config.get("custom_whitelist", [])
    formats = config.get("formats", ["domains"])
    use_presets_blocklist = config.get("use_presets_blocklist", [])
    use_presets_whitelist = config.get("use_presets_whitelist", [])

    log(f"\n{'═' * 70}", log_file=log_file)
    log(f"处理规则组：{title} ({key})", log_file=log_file)
    log(f"{'═' * 70}", log_file=log_file)

    black_domains: Set[str] = set()
    for preset_key in use_presets_blocklist:
        if preset_key in final_cache:
            black_domains.update(final_cache[preset_key])
            log(f"  │  预设黑名单：{len(final_cache[preset_key]):,} 条 <- {preset_key}", log_file=log_file)

    white_domains: Set[str] = set()
    for preset_key in use_presets_whitelist:
        if preset_key in final_cache:
            white_domains.update(final_cache[preset_key])
            log(f"  │  预设白名单：{len(final_cache[preset_key]):,} 条 <- {preset_key}", log_file=log_file)

    for url in block_urls:
        lines = downloaded.get(url, [])
        if lines:
            domains = extract_domains_from_list(lines, url, is_whitelist=False, log_file=log_file)
            black_domains.update(domains)
            log(f"  │  黑名单源：{len(domains):,} 条 <- {url}", log_file=log_file)
        else:
            log(f"  │  黑名单源：0 条（下载失败）<- {url}", LogLevel.ERROR, log_file=log_file)

    for url in white_urls:
        lines = downloaded.get(url, [])
        if lines:
            domains = extract_domains_from_list(lines, url, is_whitelist=True, log_file=log_file)
            white_domains.update(domains)
            log(f"  │  白名单源：{len(domains):,} 条 <- {url}", log_file=log_file)
        else:
            log(f"  │  白名单源：0 条（下载失败）<- {url}", LogLevel.ERROR, log_file=log_file)

    after_source_filter = filter_whitelist(black_domains, white_domains)
    filtered_by_source = len(black_domains) - len(after_source_filter)
    if filtered_by_source > 0:
        log(f"  │  源级白名单过滤：移除 {filtered_by_source:,} 条", log_file=log_file)

    all_black = after_source_filter
    custom_black_set = process_custom_list(custom_black, downloaded, "黑名单", log_file)
    if custom_black_set:
        log(f"  │  自定义黑名单：{len(custom_black_set):,} 条", log_file=log_file)
        all_black = all_black | custom_black_set

    log(f"  │  黑名单合计：{len(all_black):,} 条", log_file=log_file)

    custom_white_set = process_custom_list(custom_white, downloaded, "白名单", log_file)
    if custom_white_set:
        log(f"  │  自定义白名单：{len(custom_white_set):,} 条", log_file=log_file)
        after_filter = filter_whitelist(all_black, custom_white_set)
        filtered_by_custom = len(all_black) - len(after_filter)
        if filtered_by_custom > 0:
            log(f"  │  自定义白名单过滤：移除 {filtered_by_custom:,} 条", log_file=log_file)
    else:
        after_filter = all_black

    simple_domains = after_filter
    simple_count = len(simple_domains)

    needs_subdomain_dedup = any(f in formats for f in ("adblock", "clash", "singbox"))
    if needs_subdomain_dedup:
        deduped_domains = remove_subdomains(simple_domains)
        subdomain_removed = simple_count - len(deduped_domains)
        log(f"  │  子域去重：移除 {subdomain_removed:,} 条冗余子域", log_file=log_file)
        final_count = len(deduped_domains)
    else:
        deduped_domains = simple_domains
        final_count = simple_count

    log(f"  └─ 最终结果：{final_count:,} 条", log_file=log_file)

    group_dir = output_root / key
    group_dir.mkdir(parents=True, exist_ok=True)
    format_counts = save_domains(simple_domains, deduped_domains, group_dir, title, description, formats)

    gc.collect()

    stats_collection[key] = {
        "key": key,
        "display_name": title,
        "description": description,
        "final_count": final_count,
        "format_counts": format_counts,
    }


def validate_config(presets: Dict, groups: Dict, log_file: Optional[Path] = None) -> bool:
    errors = []

    for name, cfg in presets.items():
        if not isinstance(cfg, dict):
            errors.append(f"预设'{name}' 配置必须是字典")
            continue
        if not isinstance(cfg.get("blocklist", []), list):
            errors.append(f"预设'{name}' blocklist 必须是列表")
        if not isinstance(cfg.get("whitelist", []), list):
            errors.append(f"预设'{name}' whitelist 必须是列表")

    for name, cfg in groups.items():
        if not isinstance(cfg, dict):
            errors.append(f"规则组'{name}' 配置必须是字典")
            continue
        if "title" not in cfg and "display_name" not in cfg:
            errors.append(f"规则组'{name}' 缺少必需的 title 或 display_name")
        if not isinstance(cfg.get("blocklist", []), list):
            errors.append(f"规则组'{name}' blocklist 必须是列表")
        if not isinstance(cfg.get("whitelist", []), list):
            errors.append(f"规则组'{name}' whitelist 必须是列表")

    for error in errors:
        log(error, LogLevel.ERROR, log_file)

    return not errors


def load_config() -> Tuple[Dict, Dict]:
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

    presets = data.get("presets", {})
    groups = data.get("groups", {})

    for conf in groups.values():
        use_presets = conf.pop("use_presets", [])
        if use_presets and isinstance(use_presets, list):
            conf.setdefault("use_presets_blocklist", use_presets)

        if "display_name" not in conf and "title" in conf:
            conf["display_name"] = conf["title"]

        conf.setdefault("enabled", True)
        conf.setdefault("blocklist", [])
        conf.setdefault("whitelist", [])
        conf.setdefault("custom_blocklist", [])
        conf.setdefault("custom_whitelist", [])
        conf.setdefault("use_presets_blocklist", [])
        conf.setdefault("use_presets_whitelist", [])
        conf.setdefault("formats", ["domains"])

    for conf in presets.values():
        conf.setdefault("enabled", True)

    enabled_groups = sum(1 for v in groups.values() if v.get("enabled", True))
    enabled_presets = sum(1 for v in presets.values() if v.get("enabled", True))
    log(f"✓ 配置已加载：{enabled_presets}/{len(presets)} 个预设，{enabled_groups}/{len(groups)} 个规则组已启用")
    return presets, groups


def main():
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
        presets_cfg, groups_cfg = load_config()
    except Exception as e:
        log_error(f"配置加载失败：{e}")
        log(traceback.format_exc(), LogLevel.ERROR, main_log)
        sys.exit(1)

    if not validate_config(presets_cfg, groups_cfg, main_log):
        sys.exit(1)

    all_urls: Set[str] = set()
    for config in {**presets_cfg, **groups_cfg}.values():
        if not config.get("enabled", True):
            continue
        all_urls.update(config.get("blocklist", []))
        all_urls.update(config.get("whitelist", []))
        for item in config.get("custom_blocklist", []):
            if isinstance(item, str) and item.strip().startswith(('http://', 'https://')):
                all_urls.add(item.strip())
        for item in config.get("custom_whitelist", []):
            if isinstance(item, str) and item.strip().startswith(('http://', 'https://')):
                all_urls.add(item.strip())

    try:
        downloaded = download_all(list(all_urls), main_log)
    except Exception as e:
        log_error(f"下载过程中出现错误：{e}")
        log(traceback.format_exc(), LogLevel.ERROR, main_log)
        sys.exit(1)

    final_cache: Dict[str, Set[str]] = {}
    all_stats: Dict = {}

    log("\n" + "=" * 80, log_file=main_log)
    log("阶段 1：处理预设规则组", log_file=main_log)
    log("=" * 80, log_file=main_log)

    for key, config in presets_cfg.items():
        if not config.get("enabled", True):
            log(f"  跳过预设组（已禁用）：{key}", log_file=main_log)
            continue
        try:
            process_preset_group(key, config, downloaded, final_cache, main_log)
        except Exception as e:
            log_error(f"预设规则组处理异常：{e}")
            log(traceback.format_exc(), LogLevel.ERROR, main_log)

    log("\n" + "=" * 80, log_file=main_log)
    log("阶段 2：处理规则组并输出文件", log_file=main_log)
    log("=" * 80, log_file=main_log)

    for key, config in groups_cfg.items():
        if not config.get("enabled", True):
            log(f"  跳过规则组（已禁用）：{key}", log_file=main_log)
            continue
        try:
            process_normal_group(key, config, downloaded, output_root, final_cache, all_stats, main_log)
        except Exception as e:
            log_error(f"规则组处理异常：{e}")
            log(traceback.format_exc(), LogLevel.ERROR, main_log)

    try:
        generate_readme(output_root, all_stats, groups_cfg)
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
