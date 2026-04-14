#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Domain Filter - 主脚本
https://github.com/cjchxgxhc/domain-filter

执行顺序：filter.py → domain_filter（Rust）→ 转换 MRS/SRS → gen_readme.py
本脚本负责：下载源 → 提取域名 → 规则组处理 → 保存规则文件 → 输出 stats.json
"""

import datetime
import gc
import json
import os
import re
import subprocess
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


# ─────────────────────────── 内部常量 ────────────────────────────────────────

_CHUNK_SIZE       = 50000
_MAX_DOMAIN_LEN   = 253
_DOWNLOAD_WORKERS = 16
_EXTRACT_WORKERS  = os.cpu_count() or 4
_CONNECT_TIMEOUT  = 10
_READ_TIMEOUT     = 30
_RETRY_COUNT      = 3
_RETRY_DELAY      = 1.0
_USER_AGENT       = (
    "Mozilla/5.0 (compatible; GitHubActions/1.0; "
    "+https://github.com/cjchxgxhc/domain-filter)"
)

_RUST_TOOL = Path("data/tools/domain_filter")


# ─────────────────────────── 枚举 ────────────────────────────────────────────

class LogLevel(Enum):
    INFO    = "INFO"
    WARNING = "WARNING"
    ERROR   = "ERROR"


class ExtractMode(Enum):
    COMMON       = "common"
    ADBLOCKWHITE = "adblockwhite"
    SKIP         = "skip"


VALID_RULE_TYPES = frozenset({"add", "discard", "discard_suffix", "match", "match_suffix"})


# ─────────────────────────── 正则 ────────────────────────────────────────────

DOMAIN_PATTERN  = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$", re.IGNORECASE)
REGEX_ADBLOCK   = re.compile(r"^\|\|([a-z0-9][a-z0-9.\-]*[a-z0-9])\^", re.IGNORECASE)
REGEX_WHITELIST = re.compile(r"^@@\|\|([a-z0-9][a-z0-9.\-]*[a-z0-9])\^", re.IGNORECASE)
REGEX_CLASH     = re.compile(
    r"^(?:DOMAIN|DOMAIN-SUFFIX|HOST|HOST-SUFFIX)\s*,\s*"
    r"([a-z0-9][a-z0-9.\-]*[a-z0-9])(?:\s*,.*)?$",
    re.IGNORECASE,
)
REGEX_HOSTS     = re.compile(r"^(?:0\.0\.0\.0|127\.0\.0\.1|::1)\s", re.IGNORECASE)
REGEX_LEAD_DASH = re.compile(r"^\s*-\s*")
REGEX_IMPORTANT = re.compile(r"\$important\b")

_REGEX_INVALID_CHARS = re.compile(r"[^a-z0-9.\-]", re.IGNORECASE)
_REGEX_IPV4          = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}(?:/\d+)?$")
_REGEX_PURE_DIGITS   = re.compile(r"^\d+$")

# 合法域名字符集（快速预筛，避免正则回溯）
_VALID_DOMAIN_CHARS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-")


# ─────────────────────────── 日志 ────────────────────────────────────────────
# INFO 行不打标签，WARNING/ERROR 加标签前缀，时间戳格式保持不变

_log_lock   = threading.Lock()
_log_buffer: List[Tuple[Path, str]] = []
_LOG_FLUSH_THRESHOLD = 20


def log(
    message: str,
    level: LogLevel = LogLevel.INFO,
    log_file: Optional[Path] = None,
) -> None:
    with _log_lock:
        timestamp = datetime.datetime.now().strftime("%m-%d %H:%M:%S.%f")[:-3]
        prefix = "" if level == LogLevel.INFO else f"[{level.value}] "
        print(f"[{timestamp}] {prefix}{message}", flush=True)
        if log_file:
            try:
                log_file.parent.mkdir(parents=True, exist_ok=True)
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
    """验证域名合法性。先用廉价检查快速排除，再走正则。"""
    if not domain or len(domain) > _MAX_DOMAIN_LEN or "." not in domain:
        return False
    if domain[0] == "." or domain[-1] == ".":
        return False
    # 字符集预筛：含非法字符直接排除，无需走正则
    if not _VALID_DOMAIN_CHARS.issuperset(domain):
        return False
    return bool(DOMAIN_PATTERN.fullmatch(domain))


def _is_pureurl_invalid(s: str) -> bool:
    return (
        bool(_REGEX_INVALID_CHARS.search(s))
        or s.startswith(".")
        or s.endswith(".")
        or bool(_REGEX_IPV4.match(s))
        or bool(_REGEX_PURE_DIGITS.match(s))
    )


# ─────────────────────────── 行预处理 ────────────────────────────────────────

def strip_comments(line: str) -> str:
    line = line.strip()
    if not line or line[0] in ("#", "!"):
        return ""
    if " #" in line:
        line = line.split(" #", 1)[0].rstrip()
    return line.strip()


# ─────────────────────────── 域名提取（行级）────────────────────────────────

def _clean_general_line(line: str) -> Optional[str]:
    cleaned = strip_comments(line)
    if not cleaned:
        return None
    cleaned = REGEX_LEAD_DASH.sub("", cleaned).strip()
    cleaned = cleaned.strip("'\"")
    cleaned = REGEX_IMPORTANT.sub("", cleaned).strip()
    return cleaned or None


def _try_extract_domain(cleaned: str, is_discard: bool) -> Optional[str]:
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


def _extract_common_line(line: str, is_discard: bool, validate: bool) -> Optional[str]:
    cleaned = _clean_general_line(line)
    if not cleaned:
        return None
    if not is_discard and cleaned.startswith("@@"):
        return None
    domain = _try_extract_domain(cleaned, is_discard)
    if domain is None:
        # fallback：清理后字符串先做快速无效检查
        candidate = cleaned.lower()
        if _is_pureurl_invalid(candidate):
            return None
        domain = candidate
    if validate:
        return domain if is_valid_domain(domain) else None
    return None if _is_pureurl_invalid(domain) else domain


def _extract_adblockwhite_line(line: str) -> Optional[str]:
    # 白名单行必须以 @@ 开头，无需完整 strip_comments
    line = line.strip()
    if not line or line[0] in ("#", "!"):
        return None
    m = REGEX_WHITELIST.match(line)
    return m.group(1).lower() if m else None


def _extract_skip_line(line: str, validate: bool) -> Optional[str]:
    cleaned = strip_comments(line)
    if not cleaned:
        return None
    domain = cleaned.lower()
    if validate:
        return domain if is_valid_domain(domain) else None
    return None if _is_pureurl_invalid(domain) else domain


# ─────────────────────────── 域名提取（列表级）────────────────────────────────

def _extract_chunk(
    chunk: List[str],
    mode: ExtractMode,
    is_discard: bool,
    validate: bool,
) -> Set[str]:
    result: Set[str] = set()
    if mode == ExtractMode.COMMON:
        for line in chunk:
            domain = _extract_common_line(line, is_discard, validate)
            if domain:
                result.add(domain)
    elif mode == ExtractMode.ADBLOCKWHITE:
        for line in chunk:
            domain = _extract_adblockwhite_line(line)
            if domain:
                result.add(domain)
    else:
        for line in chunk:
            domain = _extract_skip_line(line, validate)
            if domain:
                result.add(domain)
    return result


def extract_from_lines(
    lines: List[str],
    mode: ExtractMode,
    is_discard: bool,
    validate: bool,
    log_file: Optional[Path] = None,
) -> Set[str]:
    if not lines:
        return set()
    chunks = [lines[i : i + _CHUNK_SIZE] for i in range(0, len(lines), _CHUNK_SIZE)]
    result: Set[str] = set()
    with ThreadPoolExecutor(max_workers=_EXTRACT_WORKERS) as executor:
        futures = [
            executor.submit(_extract_chunk, c, mode, is_discard, validate)
            for c in chunks
        ]
        for future in as_completed(futures):
            try:
                result.update(future.result())
            except Exception as e:
                log(f"并行提取失败: {e}", LogLevel.WARNING, log_file)
    return result


# ─────────────────────────── Rust 工具调用 ───────────────────────────────────

def _call_rust(mode: str, current: Set[str], ref_domains: Optional[Set[str]] = None) -> Set[str]:
    """调用 Rust domain_filter 二进制执行高性能过滤。"""
    if not _RUST_TOOL.exists():
        raise FileNotFoundError(f"Rust 工具不存在：{_RUST_TOOL}，请先编译")

    if mode == "dedup":
        inp = "\n".join(current)
    else:
        refs = ref_domains or set()
        inp = "\n".join(current) + "\n---\n" + "\n".join(refs)

    try:
        proc = subprocess.run(
            [str(_RUST_TOOL), mode],
            input=inp,
            capture_output=True,
            text=True,
            check=True,
        )
        return set(proc.stdout.splitlines())
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"domain_filter {mode} 失败：{e.stderr[:200]}")


def filter_discard_exact(current: Set[str], ref: Set[str]) -> Set[str]:
    return current - ref if ref and current else current


def filter_discard_suffix(
    current: Set[str], ref: Set[str], log_file: Optional[Path] = None
) -> Set[str]:
    if not ref or not current:
        return current
    try:
        return _call_rust("discard_suffix", current, ref)
    except Exception as e:
        log(f"discard_suffix Rust 调用失败，跳过：{e}", LogLevel.WARNING, log_file)
        return current


def filter_match_exact(current: Set[str], ref: Set[str]) -> Set[str]:
    return current & ref if ref and current else set()


def filter_match_suffix(
    current: Set[str], ref: Set[str], log_file: Optional[Path] = None
) -> Set[str]:
    if not ref or not current:
        return set()
    try:
        return _call_rust("match_suffix", current, ref)
    except Exception as e:
        log(f"match_suffix Rust 调用失败，跳过：{e}", LogLevel.WARNING, log_file)
        return set()


def remove_subdomains(domains: Set[str], log_file: Optional[Path] = None) -> Set[str]:
    if not domains:
        return set()
    try:
        return _call_rust("dedup", domains)
    except Exception as e:
        log(f"dedup Rust 调用失败，跳过去重：{e}", LogLevel.WARNING, log_file)
        return domains


# ─────────────────────────── 下载 ────────────────────────────────────────────

def _create_session() -> requests.Session:
    session = requests.Session()
    retry = Retry(
        total=_RETRY_COUNT,
        backoff_factor=_RETRY_DELAY,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET"],
        raise_on_status=False,
    )
    adapter = HTTPAdapter(
        max_retries=retry,
        pool_connections=_DOWNLOAD_WORKERS,
        pool_maxsize=_DOWNLOAD_WORKERS * 2,
    )
    session.mount("http://",  adapter)
    session.mount("https://", adapter)
    session.headers["User-Agent"] = _USER_AGENT
    return session


def _download_one(url: str, session: requests.Session) -> Tuple[str, bool, List[str]]:
    try:
        resp = session.get(url, timeout=(_CONNECT_TIMEOUT, _READ_TIMEOUT))
        resp.raise_for_status()
        return url, True, resp.text.splitlines()
    except Exception:
        return url, False, []


def download_all(
    urls: List[str],
    log_file: Optional[Path] = None,
) -> Dict[str, List[str]]:
    if not urls:
        return {}
    log(f"开始下载 {len(urls)} 个规则源...", log_file=log_file)
    t0      = time.time()
    session = _create_session()
    result: Dict[str, List[str]] = {}
    failed: List[str] = []

    with ThreadPoolExecutor(max_workers=_DOWNLOAD_WORKERS) as executor:
        futures = {executor.submit(_download_one, url, session): url for url in urls}
        for future in as_completed(futures):
            try:
                url, ok, lines = future.result()
                result[url] = lines
                if not ok:
                    failed.append(url)
            except Exception:
                url = futures[future]
                failed.append(url)
                result[url] = []

    success = len(urls) - len(failed)
    log(f"下载完成：{success}/{len(urls)} 成功，耗时 {time.time() - t0:.2f}s", log_file=log_file)
    if failed:
        log(f"下载失败（{len(failed)} 个）：", LogLevel.WARNING, log_file=log_file)
        for url in failed:
            log(f"  ✗ {url}", LogLevel.WARNING, log_file=log_file)
    return result


# ─────────────────────────── 文件头生成 ──────────────────────────────────────

def build_header(
    count: int,
    title: str,
    description: str,
    now_str: str,
    comment_char: str,
) -> str:
    if not title:
        return ""
    c = comment_char
    parts = [f"{c} Title: {title}"]
    if description:
        parts.append(f"{c} Description: {description}")
    parts.append(f"{c} Total: {count:,}")
    parts.append(f"{c} Updated: {now_str}")
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
    timezone: str,
) -> Dict[str, int]:
    if not simple_domains and not deduped_domains:
        log_error(f"警告：没有域名可保存（{output_dir.name}）")
        return {}

    now     = datetime.datetime.now(ZoneInfo(timezone))
    now_str = now.strftime("%Y-%m-%d %H:%M:%S %Z")
    counts: Dict[str, int] = {}
    sorted_simple  = sorted(simple_domains)
    sorted_deduped = sorted(deduped_domains)

    def _bang_header(count: int) -> str:
        return build_header(count, title, description, now_str, "!")

    def _hash_header(count: int) -> str:
        return build_header(count, title, description, now_str, "#")

    if "domain" in formats:
        count = len(sorted_simple)
        counts["domain"] = count
        path = output_dir / "domain.txt"
        with path.open("w", encoding="utf-8") as f:
            f.write(_hash_header(count))
            f.write("\n".join(sorted_simple) + "\n")
        log(f"  ✓ {path.name}（{count:,} 条）")

    if "hosts" in formats:
        count = len(sorted_simple)
        counts["hosts"] = count
        path = output_dir / "hosts.txt"
        with path.open("w", encoding="utf-8") as f:
            f.write(_hash_header(count))
            for domain in sorted_simple:
                f.write(f"127.0.0.1 {domain}\n")
                # f.write(f"::1 {domain}\n")
        log(f"  ✓ {path.name}（{count:,} 条）")

    if "adblock" in formats:
        count = len(sorted_deduped)
        counts["adblock"] = count
        path = output_dir / "adblock.txt"
        with path.open("w", encoding="utf-8") as f:
            f.write("[Adblock Plus 2.0]\n")
            f.write(_bang_header(count))
            for domain in sorted_deduped:
                f.write(f"||{domain}^\n")
        log(f"  ✓ {path.name}（{count:,} 条，子域去重）")

    if "clash" in formats:
        count = len(sorted_deduped)
        counts["clash"] = count
        path = output_dir / "clash.yaml"
        with path.open("w", encoding="utf-8") as f:
            f.write(_hash_header(count))
            f.write("payload:\n")
            for domain in sorted_deduped:
                f.write(f"  - +.{domain}\n")
        log(f"  ✓ {path.name}（{count:,} 条，子域去重）")

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
        log(f"  ✓ {path.name}（{count:,} 条，子域去重）")

    return counts


# ─────────────────────────── 配置加载 ────────────────────────────────────────

def _parse_mode(raw: Optional[str]) -> ExtractMode:
    mapping = {
        "common":       ExtractMode.COMMON,
        "adblockwhite": ExtractMode.ADBLOCKWHITE,
        "skip":         ExtractMode.SKIP,
    }
    return mapping.get((raw or "").strip().lower(), ExtractMode.COMMON)


def load_config(config_path: Path) -> Tuple[Dict, List[Dict], Dict[str, Dict]]:
    if not config_path.is_file():
        log_error(f"错误：缺少配置文件 {config_path}")
        sys.exit(1)

    try:
        with config_path.open(encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
    except yaml.YAMLError as e:
        log_error(f"配置文件解析失败：{e}")
        sys.exit(1)
    except Exception as e:
        log_error(f"配置文件读取失败：{e}")
        sys.exit(1)

    global_cfg  = data.pop("global",  {}) or {}
    sources_raw = data.pop("sources", {}) or {}

    sources: Dict[str, Dict] = {}
    for sname, scfg in sources_raw.items():
        if not isinstance(scfg, dict):
            continue
        raw_url = (scfg.get("url") or "").strip()
        if not raw_url:
            continue
        sources[sname] = {
            "url":      raw_url,
            "mode":     _parse_mode(scfg.get("mode")),
            "validate": bool(scfg.get("validate", False)),
        }

    groups = []
    for idx, (cfg_key, cfg) in enumerate(data.items()):
        if not isinstance(cfg, dict):
            continue

        raw_rules = cfg.get("rules") or []
        if isinstance(raw_rules, dict):
            try:
                raw_rules = [raw_rules[k] for k in sorted(raw_rules.keys(), key=lambda x: int(x))]
            except (ValueError, TypeError):
                raw_rules = list(raw_rules.values())

        raw_dedup = cfg.get("dedup_subdomain")
        dedup_subdomain = None if raw_dedup is None else bool(raw_dedup)

        output_cfg = cfg.get("output") or {}
        formats    = output_cfg.get("formats", ["domain"])
        if isinstance(formats, str):
            formats = [formats]

        groups.append({
            "cfg_key":         cfg_key,
            "idx":             idx,
            "enabled":         bool(cfg.get("enabled", True)),
            "dedup_subdomain": dedup_subdomain,
            "title":           cfg.get("title", ""),
            "description":     cfg.get("description", ""),
            "rules":           raw_rules,
            "formats":         formats,
            "output_enabled":  bool(output_cfg.get("enabled", False)),
        })

    enabled_count = sum(1 for g in groups if g["enabled"])
    log(f"✓ 配置已加载：{len(sources)} 个外部源，{len(groups)} 个规则组（{enabled_count} 个已启用）")
    return global_cfg, groups, sources


# ─────────────────────────── 配置校验 ────────────────────────────────────────

def validate_config(
    groups: List[Dict],
    sources: Dict[str, Dict],
    log_file: Optional[Path] = None,
) -> bool:
    errors: List[str] = []
    key_to_idx: Dict[str, int] = {g["cfg_key"]: g["idx"] for g in groups}

    for group in groups:
        key   = group["cfg_key"]
        gidx  = group["idx"]
        rules = group.get("rules", [])

        if not isinstance(rules, list):
            errors.append(f"规则组 '{key}' 的 rules 必须是列表")
            continue

        for ridx, rule in enumerate(rules):
            if not isinstance(rule, dict):
                errors.append(f"规则组 '{key}' rules[{ridx}] 必须是字典")
                continue

            rule_type = rule.get("type", "add")
            if rule_type not in VALID_RULE_TYPES:
                errors.append(f"规则组 '{key}' rules[{ridx}] type '{rule_type}' 无效")

            for src_name in rule.get("source") or []:
                if isinstance(src_name, str) and src_name.strip() not in sources:
                    errors.append(
                        f"规则组 '{key}' rules[{ridx}] source '{src_name}' 未在 sources 中定义"
                    )

            for ref_key in rule.get("preset") or []:
                if not isinstance(ref_key, str):
                    continue
                ref_key = ref_key.strip()
                ref_idx = key_to_idx.get(ref_key)
                if ref_idx is None:
                    errors.append(f"规则组 '{key}' rules[{ridx}] preset '{ref_key}' 不存在")
                elif ref_idx >= gidx:
                    errors.append(f"规则组 '{key}' rules[{ridx}] preset '{ref_key}' 不允许向后引用")

    for err in errors:
        log(err, LogLevel.ERROR, log_file)
    return not errors


# ─────────────────────────── 规则组处理 ──────────────────────────────────────

_cfg_key_to_idx_map: Dict[str, int] = {}


def process_group(
    group: Dict,
    downloaded_sources: Dict[str, Set[str]],
    output_root: Path,
    group_cache: Dict[int, Set[str]],
    group_cache_names: Dict[int, Set[str]],
    all_stats: Dict,
    log_file: Path,
    timezone: str,
) -> None:
    cfg_key         = group["cfg_key"]
    gidx            = group["idx"]
    title           = group.get("title", "")
    description     = group.get("description", "")
    formats         = group.get("formats", ["domain"])
    output_enabled  = group.get("output_enabled", False)
    dedup_subdomain = group.get("dedup_subdomain")

    t_group = time.time()
    sep = "═" * 70
    log(sep, log_file=log_file)
    log(f"处理规则组：{title or cfg_key} ({cfg_key})", log_file=log_file)
    log(sep, log_file=log_file)

    current_domains:    Set[str] = set()
    group_source_names: Set[str] = set()

    for idx, rule in enumerate(group.get("rules", [])):
        if not isinstance(rule, dict):
            continue

        rule_type  = rule.get("type", "add")
        is_discard = rule_type in ("discard", "discard_suffix", "match", "match_suffix")
        log(f"  │  rules[{idx}] type={rule_type}", log_file=log_file)

        rule_domains: Set[str] = set()

        for src_name in rule.get("source") or []:
            if not isinstance(src_name, str):
                continue
            src_name    = src_name.strip()
            src_domains = downloaded_sources.get(src_name, set())
            rule_domains.update(src_domains)
            group_source_names.add(src_name)
            log(f"  │    source：{len(src_domains):,} 条 <- {src_name}", log_file=log_file)

        custom = [
            d.strip().lower()
            for d in (rule.get("domain") or [])
            if isinstance(d, str) and d.strip()
        ]
        if custom:
            rule_domains.update(custom)
            log(f"  │    domain：{len(custom):,} 条自定义", log_file=log_file)

        for ref_key in rule.get("preset") or []:
            if not isinstance(ref_key, str):
                continue
            ref_key = ref_key.strip()
            ref_idx = _cfg_key_to_idx_map.get(ref_key)
            if ref_idx is not None and ref_idx < gidx and ref_idx in group_cache:
                ref_set = group_cache[ref_idx]
                rule_domains.update(ref_set)
                group_source_names.update(group_cache_names.get(ref_idx, set()))
                log(f"  │    preset：{len(ref_set):,} 条 <- {ref_key}", log_file=log_file)
            else:
                log(
                    f"  │    preset '{ref_key}' 无效或不在当前组之前，跳过",
                    LogLevel.WARNING,
                    log_file=log_file,
                )

        log(f"  │    rules[{idx}] 共 {len(rule_domains):,} 条", log_file=log_file)

        before = len(current_domains)
        if rule_type == "add":
            current_domains.update(rule_domains)
            log(f"  │    → 加入，新增 {len(current_domains)-before:,} 条（合计 {len(current_domains):,}）", log_file=log_file)
        elif rule_type == "discard":
            current_domains = filter_discard_exact(current_domains, rule_domains)
            log(f"  │    → 精确丢弃，移除 {before-len(current_domains):,} 条（剩余 {len(current_domains):,}）", log_file=log_file)
        elif rule_type == "discard_suffix":
            current_domains = filter_discard_suffix(current_domains, rule_domains, log_file)
            log(f"  │    → 后缀丢弃，移除 {before-len(current_domains):,} 条（剩余 {len(current_domains):,}）", log_file=log_file)
        elif rule_type == "match":
            current_domains = filter_match_exact(current_domains, rule_domains)
            log(f"  │    → 精确保留，保留 {len(current_domains):,} 条（移除 {before-len(current_domains):,}）", log_file=log_file)
        elif rule_type == "match_suffix":
            current_domains = filter_match_suffix(current_domains, rule_domains, log_file)
            log(f"  │    → 后缀保留，保留 {len(current_domains):,} 条（移除 {before-len(current_domains):,}）", log_file=log_file)

    log(f"  │  处理完毕，共 {len(current_domains):,} 条", log_file=log_file)

    group_cache[gidx]       = current_domains
    group_cache_names[gidx] = group_source_names

    if not output_enabled:
        t_elapsed = time.time() - t_group
        log(f"  └─ 不输出文件（output.enabled=false），耗时 {t_elapsed:.2f}s", log_file=log_file)
        all_stats[cfg_key] = {
            "idx":            gidx,
            "title":          title,
            "description":    description,
            "output_enabled": False,
            "final_count":    len(current_domains),
            "format_counts":  {},
            "source_names":   sorted(group_source_names),
        }
        return

    if dedup_subdomain is True:
        deduped_domains = remove_subdomains(current_domains, log_file)
        log(f"  │  子域去重（强制）：移除 {len(current_domains)-len(deduped_domains):,} 条冗余子域", log_file=log_file)
    elif dedup_subdomain is False:
        deduped_domains = current_domains
        log("  │  子域去重（强制跳过）", log_file=log_file)
    else:
        if any(f in formats for f in ("adblock", "clash", "singbox")):
            deduped_domains = remove_subdomains(current_domains, log_file)
            log(f"  │  子域去重：移除 {len(current_domains)-len(deduped_domains):,} 条冗余子域", log_file=log_file)
        else:
            deduped_domains = current_domains

    final_count = len(deduped_domains)

    group_dir = output_root / cfg_key
    group_dir.mkdir(parents=True, exist_ok=True)
    format_counts = save_domains(
        current_domains, deduped_domains, group_dir,
        title, description, formats, timezone,
    )

    gc.collect()

    t_elapsed = time.time() - t_group
    log(f"  └─ 最终输出：{final_count:,} 条，耗时 {t_elapsed:.2f}s", log_file=log_file)

    all_stats[cfg_key] = {
        "idx":            gidx,
        "title":          title,
        "description":    description,
        "output_enabled": True,
        "final_count":    final_count,
        "format_counts":  format_counts,
        "source_names":   sorted(group_source_names),
    }


# ─────────────────────────── 主入口 ──────────────────────────────────────────

def main() -> None:
    start_time = time.time()

    print("=" * 80)
    print("Domain Filter - 域名过滤工具".center(80))
    print("=" * 80)
    print()

    config_path = Path("data/script/config.yaml")

    try:
        global_cfg, groups, sources = load_config(config_path)
    except Exception as e:
        log_error(f"配置加载失败：{e}")
        traceback.print_exc()
        sys.exit(1)

    output_root = Path(global_cfg.get("output_root", "data/rules"))
    timezone    = global_cfg.get("timezone", "Asia/Shanghai")

    output_root.mkdir(parents=True, exist_ok=True)
    main_log = output_root / "log.txt"
    if main_log.exists():
        main_log.unlink()

    log("开始执行域名过滤工具", log_file=main_log)

    if not validate_config(groups, sources, main_log):
        sys.exit(1)

    global _cfg_key_to_idx_map
    _cfg_key_to_idx_map = {g["cfg_key"]: g["idx"] for g in groups}

    all_urls = list({
        s["url"] for s in sources.values()
        if s["url"].startswith(("http://", "https://"))
    })
    try:
        raw_downloaded = download_all(all_urls, main_log)
    except Exception as e:
        log_error(f"下载过程中出现错误：{e}")
        log(traceback.format_exc(), LogLevel.ERROR, main_log)
        sys.exit(1)

    # ── 提取外部源域名（并行，结果按配置顺序输出）──────────────────────────
    log(f"提取外部源域名（{len(sources)} 个）...", log_file=main_log)
    t_extract = time.time()
    downloaded_sources: Dict[str, Set[str]] = {}

    with ThreadPoolExecutor(max_workers=_EXTRACT_WORKERS) as executor:
        future_to_sname: Dict = {}
        for sname, scfg in sources.items():
            url      = scfg["url"]
            mode     = scfg["mode"]
            validate = scfg["validate"]
            lines    = raw_downloaded.get(url, [])
            if lines:
                future_to_sname[
                    executor.submit(extract_from_lines, lines, mode, False, validate)
                ] = (sname, url, mode)
            else:
                downloaded_sources[sname] = set()

        # 收集所有 future 结果（不在此处打日志，避免 as_completed 乱序）
        future_results: Dict[str, Tuple[Set[str], str]] = {}
        for future, (sname, url, mode) in future_to_sname.items():
            try:
                domains = future.result()
            except Exception as e:
                log(f"  {sname}：提取失败 {e}", LogLevel.ERROR, log_file=main_log)
                domains = set()
            future_results[sname] = (domains, mode.value)
            downloaded_sources[sname] = domains

    # 按配置顺序打印提取结果
    for sname, scfg in sources.items():
        if sname in future_results:
            domains, mode_val = future_results[sname]
            log(f"  {sname}：{len(domains):,} 条 [{mode_val}]", log_file=main_log)
        else:
            log(f"  {sname}：0 条（下载失败）", LogLevel.ERROR, log_file=main_log)

    log(f"提取完成，耗时 {time.time() - t_extract:.2f}s", log_file=main_log)

    # ── 规则组处理 ─────────────────────────────────────────────────────────
    group_cache:       Dict[int, Set[str]] = {}
    group_cache_names: Dict[int, Set[str]] = {}
    all_stats:         Dict = {}

    log("=" * 80, log_file=main_log)
    log("处理规则组", log_file=main_log)
    log("=" * 80, log_file=main_log)

    for group in groups:
        if not group["enabled"]:
            log(f"  跳过规则组（已禁用）：{group['cfg_key']}", log_file=main_log)
            continue
        try:
            process_group(
                group, downloaded_sources, output_root,
                group_cache, group_cache_names,
                all_stats, main_log, timezone,
            )
        except Exception as e:
            log_error(f"规则组处理异常 [{group['cfg_key']}]：{e}")
            log(traceback.format_exc(), LogLevel.ERROR, main_log)

    # ── 写出 stats.json ────────────────────────────────────────────────────
    stats_path = output_root / "stats.json"
    try:
        with stats_path.open("w", encoding="utf-8") as f:
            json.dump(all_stats, f, ensure_ascii=False, indent=2)
        log(f"✓ stats.json 已写出：{stats_path}", log_file=main_log)
    except Exception as e:
        log_error(f"stats.json 写出失败：{e}", log_file=main_log)

    elapsed = time.time() - start_time
    log("=" * 80, log_file=main_log)
    log(f"✓ 处理完成！总耗时 {elapsed:.2f}s", log_file=main_log)
    log("=" * 80, log_file=main_log)

    _flush_log_buffer()
    gc.collect()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n用户中断（Ctrl+C）")
        sys.exit(130)
    except Exception as e:
        log_error(f"程序异常退出：{e}")
        traceback.print_exc()
        sys.exit(1)
