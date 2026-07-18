#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Domain Filter - 主脚本（含规则格式生成 + README 生成）
https://github.com/cjchxgxhc/domain-filter

执行顺序：filter.py -> domain_filter（Rust）-> 转换 MRS/SRS
本脚本负责：下载源 -> 提取域名 -> 规则组处理 -> 生成规则文件 -> 生成 README
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


# ─────────────────────────── 常量 ────────────────────────────────────────────

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

_RUST_TOOL   = Path("data/tools/domain_filter")
_CONFIG_PATH = Path("data/script/config.yaml")
_README_ROOT = Path("README.md")

_SIMPLE_FORMATS  = frozenset({"domain", "hosts", "hostsipv6"})
_DEDUPED_FORMATS = frozenset({
    "adblock", "adblockwhite", "clash", "singbox", "wildcard",
    "loon", "surge", "quantumultx", "shadowrocket", "smartdns",
})
ALL_FORMATS = _SIMPLE_FORMATS | _DEDUPED_FORMATS

_FMT_LABEL: Dict[str, str] = {
    "domain":       "Domain",
    "hosts":        "Hosts",
    "hostsipv6":    "Hosts IPv6",
    "smartdns":     "SmartDNS",
    "adblock":      "AdBlock",
    "adblockwhite": "AdBlock White",
    "clash":        "Clash",
    "singbox":      "Sing-box",
    "wildcard":     "Wildcard",
    "loon":         "Loon",
    "surge":        "Surge",
    "quantumultx":  "QuantumultX",
    "shadowrocket": "ShadowRocket",
}

_FMT_FILE: Dict[str, str] = {
    "domain":       "domain.txt",
    "hosts":        "hosts.txt",
    "hostsipv6":    "hosts_ipv6.txt",
    "smartdns":     "smartdns.conf",
    "adblock":      "adblock.txt",
    "adblockwhite": "adblockwhite.txt",
    "clash":        "clash.yaml",
    "singbox":      "singbox.json",
    "wildcard":     "wildcard.txt",
    "loon":         "loon.list",
    "surge":        "surge.list",
    "quantumultx":  "quantumultx.list",
    "shadowrocket": "shadowrocket.list",
}

_CONV_FILE: Dict[str, str] = {
    "clash":   "clash.mrs",
    "singbox": "singbox.srs",
}

_REGEX_RAW_GH = re.compile(
    r"^https://raw\.githubusercontent\.com/"
    r"(?P<user>[^/]+)/(?P<repo>[^/]+)/(?:refs/heads/)?"
    r"(?P<branch>[^/]+)/(?P<path>.+)$"
)


class LogLevel(Enum):
    INFO    = "INFO"
    WARNING = "WARNING"
    ERROR   = "ERROR"


class ExtractMode(Enum):
    COMMON       = "common"
    ADBLOCKWHITE = "adblockwhite"
    SKIP         = "skip"


VALID_RULE_TYPES = frozenset({"add", "discard", "discard_suffix", "match", "match_suffix"})


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

_REGEX_INVALID  = re.compile(r"[^a-z0-9.\-]", re.IGNORECASE)
_REGEX_IPV4     = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}(?:/\d+)?$")
_REGEX_DIGITS   = re.compile(r"^\d+$")
_VALID_CHARS    = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-")


_log_lock   = threading.Lock()
_log_buffer: List[Tuple[Path, str]] = []


def log(msg: str, level: LogLevel = LogLevel.INFO, log_file: Optional[Path] = None) -> None:
    with _log_lock:
        ts = datetime.datetime.now().strftime("%m-%d %H:%M:%S.%f")[:-3]
        prefix = "" if level == LogLevel.INFO else f"[{level.value}] "
        print(f"[{ts}] {prefix}{msg}", flush=True)
        if log_file:
            try:
                log_file.parent.mkdir(parents=True, exist_ok=True)
                _log_buffer.append((log_file, f"{prefix}{msg}"))
            except Exception:
                pass


def _flush_log() -> None:
    global _log_buffer
    if not _log_buffer:
        return
    by_file: Dict[Path, List[str]] = {}
    for path, msg in _log_buffer:
        by_file.setdefault(path, []).append(msg)
    for path, msgs in by_file.items():
        try:
            with path.open("a", encoding="utf-8") as f:
                f.write("\n".join(msgs) + "\n")
        except Exception:
            pass
    _log_buffer = []


def _is_valid(domain: str) -> bool:
    if not domain or len(domain) > _MAX_DOMAIN_LEN or "." not in domain:
        return False
    if domain[0] == "." or domain[-1] == ".":
        return False
    if not _VALID_CHARS.issuperset(domain):
        return False
    return bool(DOMAIN_PATTERN.fullmatch(domain))


def _is_invalid_bare(s: str) -> bool:
    return (
        bool(_REGEX_INVALID.search(s))
        or s.startswith(".") or s.endswith(".")
        or bool(_REGEX_IPV4.match(s))
        or bool(_REGEX_DIGITS.match(s))
    )


def _strip_comment(line: str) -> str:
    line = line.strip()
    if not line or line[0] in ("#", "!"):
        return ""
    if " #" in line:
        line = line.split(" #", 1)[0].rstrip()
    return line.strip()


def _extract_common(line: str, validate: bool) -> Optional[str]:
    cleaned = _strip_comment(line)
    if not cleaned:
        return None
    cleaned = REGEX_LEAD_DASH.sub("", cleaned).strip().strip("'\"")
    cleaned = REGEX_IMPORTANT.sub("", cleaned).strip()
    if not cleaned or cleaned.startswith("@@"):
        return None

    m = REGEX_ADBLOCK.match(cleaned)
    if m:
        d = m.group(1).lower()
        return d if (not validate or _is_valid(d)) else None

    m = REGEX_CLASH.match(cleaned)
    if m:
        d = m.group(1).strip().lower()
        return d if (not validate or _is_valid(d)) else None

    if cleaned.startswith(("+.", "*.")):
        d = cleaned[2:].strip().lower()
        return d if (not validate or _is_valid(d)) else None

    if cleaned.startswith(".") and len(cleaned) > 1:
        d = cleaned[1:].lower()
        return d if (not validate or _is_valid(d)) else None

    if REGEX_HOSTS.match(cleaned):
        parts = cleaned.split(None, 1)
        if len(parts) < 2:
            return None
        d = parts[1].strip().lower()
        return d if (not validate or _is_valid(d)) else None

    d = cleaned.lower()
    if _is_invalid_bare(d):
        return None
    return d if (not validate or _is_valid(d)) else None


def _extract_adblockwhite(line: str) -> Optional[str]:
    line = line.strip()
    if not line or line[0] in ("#", "!"):
        return None
    m = REGEX_WHITELIST.match(line)
    return m.group(1).lower() if m else None


def _extract_skip(line: str, validate: bool) -> Optional[str]:
    d = _strip_comment(line).lower()
    if not d:
        return None
    if validate:
        return d if _is_valid(d) else None
    return None if _is_invalid_bare(d) else d


def _extract_chunk(chunk: List[str], mode: ExtractMode, validate: bool) -> Set[str]:
    result: Set[str] = set()
    if mode == ExtractMode.COMMON:
        for line in chunk:
            d = _extract_common(line, validate)
            if d:
                result.add(d)
    elif mode == ExtractMode.ADBLOCKWHITE:
        for line in chunk:
            d = _extract_adblockwhite(line)
            if d:
                result.add(d)
    else:
        for line in chunk:
            d = _extract_skip(line, validate)
            if d:
                result.add(d)
    return result


def _extract_lines(
    lines: List[str], mode: ExtractMode, validate: bool,
    log_file: Optional[Path] = None,
) -> Set[str]:
    if not lines:
        return set()
    chunks = [lines[i : i + _CHUNK_SIZE] for i in range(0, len(lines), _CHUNK_SIZE)]
    result: Set[str] = set()
    with ThreadPoolExecutor(max_workers=_EXTRACT_WORKERS) as ex:
        for future in as_completed([ex.submit(_extract_chunk, c, mode, validate) for c in chunks]):
            try:
                result.update(future.result())
            except Exception as e:
                log(f"并行提取失败: {e}", LogLevel.WARNING, log_file)
    return result


def _rust(mode: str, current: Set[str], ref: Optional[Set[str]] = None) -> Set[str]:
    if not _RUST_TOOL.exists():
        raise FileNotFoundError(f"Rust 工具不存在：{_RUST_TOOL}")
    inp = "\n".join(current) if mode == "dedup" else (
        "\n".join(current) + "\n---\n" + "\n".join(ref or set())
    )
    try:
        p = subprocess.run([str(_RUST_TOOL), mode], input=inp, capture_output=True, text=True, check=True)
        return set(p.stdout.splitlines())
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"domain_filter {mode} 失败：{e.stderr[:200]}")


def _discard_exact(cur: Set[str], ref: Set[str]) -> Set[str]:
    return cur - ref if ref and cur else cur

def _discard_suffix(cur: Set[str], ref: Set[str], lf: Optional[Path] = None) -> Set[str]:
    if not ref or not cur:
        return cur
    try:
        return _rust("discard_suffix", cur, ref)
    except Exception as e:
        log(f"discard_suffix 失败，跳过：{e}", LogLevel.WARNING, lf)
        return cur

def _match_exact(cur: Set[str], ref: Set[str]) -> Set[str]:
    return cur & ref if ref and cur else set()

def _match_suffix(cur: Set[str], ref: Set[str], lf: Optional[Path] = None) -> Set[str]:
    if not ref or not cur:
        return set()
    try:
        return _rust("match_suffix", cur, ref)
    except Exception as e:
        log(f"match_suffix 失败，跳过：{e}", LogLevel.WARNING, lf)
        return set()

def _dedup(domains: Set[str], lf: Optional[Path] = None) -> Set[str]:
    if not domains:
        return set()
    try:
        return _rust("dedup", domains)
    except Exception as e:
        log(f"dedup 失败，跳过去重：{e}", LogLevel.WARNING, lf)
        return domains


def _download(urls: List[str], log_file: Optional[Path] = None) -> Dict[str, List[str]]:
    if not urls:
        return {}
    log(f"开始下载 {len(urls)} 个规则源...", log_file=log_file)
    t0 = time.time()
    session = requests.Session()
    adapter = HTTPAdapter(
        max_retries=Retry(
            total=_RETRY_COUNT, backoff_factor=_RETRY_DELAY,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET"], raise_on_status=False,
        ),
        pool_connections=_DOWNLOAD_WORKERS, pool_maxsize=_DOWNLOAD_WORKERS * 2,
    )
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.headers["User-Agent"] = _USER_AGENT

    result: Dict[str, List[str]] = {}
    failed: List[str] = []

    def _fetch(url: str) -> Tuple[str, bool, List[str]]:
        try:
            r = session.get(url, timeout=(_CONNECT_TIMEOUT, _READ_TIMEOUT))
            r.raise_for_status()
            return url, True, r.text.splitlines()
        except Exception:
            return url, False, []

    with ThreadPoolExecutor(max_workers=_DOWNLOAD_WORKERS) as ex:
        futures = {ex.submit(_fetch, url): url for url in urls}
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

    log(f"下载完成：{len(urls)-len(failed)}/{len(urls)} 成功，耗时 {time.time()-t0:.2f}s", log_file=log_file)
    for url in failed:
        log(f"  FAIL {url}", LogLevel.WARNING, log_file)
    return result


def _hdr(count: int, tool: str, desc: str, now: str, c: str) -> str:
    """通用简单头部：描述 + 适用工具 + 规则数 + 更新时间"""
    parts: List[str] = []
    if desc:
        parts.append(f"{c} {desc}")
    parts.append(f"{c} 适用：{tool}  规则数：{count:,}  更新：{now}")
    parts.append(c)
    return "\n".join(parts) + "\n"


def _hdr_adblock(count: int, title: str, desc: str, now: str) -> str:
    """AdGuard 兼容头部：使用 AdGuard/AdGuard Home 可识别的元数据字段
    （Title / Description / Last modified / Expires / Homepage / Total count），
    便于在 AdGuard 系产品的过滤器信息面板中正常显示。
    """
    lines: List[str] = []
    if title:
        lines.append(f"! Title: {title}")
    if desc:
        lines.append(f"! Description: {desc}")
    lines.append(f"! Homepage: https://github.com/cjchxgxhc/domain-filter")
    lines.append(f"! Last modified: {now}")
    lines.append("! Expires: 1 days (update frequency)")
    lines.append(f"! Total count: {count:,}")
    return "\n".join(lines) + "\n"


def _write_fmt(
    fmt: str, out: Path,
    simple: List[str], deduped: List[str],
    title: str, desc: str, now: str,
) -> Tuple[str, int]:
    s, d = simple, deduped
    tool = _FMT_LABEL.get(fmt, fmt)

    if fmt == "domain":
        p = out / "domain.txt"
        p.write_text("\n".join(s) + "\n", encoding="utf-8")
        return p.name, len(s)

    if fmt == "hosts":
        p = out / "hosts.txt"
        with p.open("w", encoding="utf-8") as f:
            f.write(_hdr(len(s), tool, desc, now, "#"))
            for x in s: f.write(f"127.0.0.1 {x}\n")
        return p.name, len(s)

    if fmt == "hostsipv6":
        p = out / "hosts_ipv6.txt"
        with p.open("w", encoding="utf-8") as f:
            f.write(_hdr(len(s), tool, desc, now, "#"))
            for x in s: f.write(f"127.0.0.1 {x}\n::1 {x}\n")
        return p.name, len(s)

    if fmt == "smartdns":
        p = out / "smartdns.conf"
        with p.open("w", encoding="utf-8") as f:
            f.write(_hdr(len(d), tool, desc, now, "#"))
            for x in d: f.write(f"address /{x}/#\n")
        return p.name, len(d)

    if fmt == "adblock":
        p = out / "adblock.txt"
        with p.open("w", encoding="utf-8") as f:
            f.write("[Adblock Plus 2.0]\n")
            f.write(_hdr_adblock(len(d), title, desc, now))
            for x in d: f.write(f"||{x}^\n")
        return p.name, len(d)

    if fmt == "adblockwhite":
        p = out / "adblockwhite.txt"
        with p.open("w", encoding="utf-8") as f:
            f.write("[Adblock Plus 2.0]\n")
            f.write(_hdr_adblock(len(d), title, desc, now))
            for x in d: f.write(f"@@||{x}^\n")
        return p.name, len(d)

    if fmt == "clash":
        p = out / "clash.yaml"
        with p.open("w", encoding="utf-8") as f:
            f.write(_hdr(len(d), tool, desc, now, "#"))
            f.write("payload:\n")
            for x in d: f.write(f"  - +.{x}\n")
        return p.name, len(d)

    if fmt == "singbox":
        p = out / "singbox.json"
        with p.open("w", encoding="utf-8") as f:
            json.dump({"version": 3, "rules": [{"domain_suffix": d}]}, f, indent=2, ensure_ascii=False)
        return p.name, len(d)

    if fmt == "wildcard":
        p = out / "wildcard.txt"
        with p.open("w", encoding="utf-8") as f:
            for x in d: f.write(f"*.{x}\n")
        return p.name, len(d)

    if fmt == "loon":
        p = out / "loon.list"
        with p.open("w", encoding="utf-8") as f:
            f.write(_hdr(len(d), tool, desc, now, "#"))
            for x in d: f.write(f"DOMAIN-SUFFIX,{x}\n")
        return p.name, len(d)

    if fmt == "surge":
        p = out / "surge.list"
        with p.open("w", encoding="utf-8") as f:
            f.write(_hdr(len(d), tool, desc, now, "#"))
            for x in d: f.write(f"DOMAIN-SUFFIX,{x}\n")
        return p.name, len(d)

    if fmt == "quantumultx":
        p = out / "quantumultx.list"
        with p.open("w", encoding="utf-8") as f:
            f.write(_hdr(len(d), tool, desc, now, "#"))
            for x in d: f.write(f"host-suffix,{x},reject\n")
        return p.name, len(d)

    if fmt == "shadowrocket":
        p = out / "shadowrocket.list"
        with p.open("w", encoding="utf-8") as f:
            f.write("[Rule]\n")
            for x in d: f.write(f"DOMAIN-SUFFIX,{x},REJECT-DROP\n")
        return p.name, len(d)

    raise ValueError(f"未知格式：{fmt}")


def _save(
    simple: Set[str], deduped: Set[str],
    out: Path, title: str, desc: str,
    formats: List[str], tz: str,
    log_file: Optional[Path] = None,
) -> Dict[str, int]:
    if not simple and not deduped:
        log(f"警告：没有域名可保存（{out.name}）", LogLevel.ERROR, log_file)
        return {}
    out.mkdir(parents=True, exist_ok=True)
    now = datetime.datetime.now(ZoneInfo(tz)).strftime("%Y-%m-%d %H:%M:%S %Z")
    ss, dd = sorted(simple), sorted(deduped)
    counts: Dict[str, int] = {}
    for fmt in formats:
        fname, count = _write_fmt(fmt, out, ss, dd, title, desc, now)
        counts[fmt] = count
        note = "（去重）" if fmt in _DEDUPED_FORMATS else ""
        log(f"  OK {fname}（{count:,} 条{note}）", log_file=log_file)
    return counts


def _jsd_url(raw_url: str) -> Tuple[str, str]:
    m = _REGEX_RAW_GH.match(raw_url)
    if not m:
        return "", ""
    jsd = f"gh/{m.group('user')}/{m.group('repo')}@{m.group('branch')}/{m.group('path')}"
    return f"https://cdn.jsdelivr.net/{jsd}", f"https://fastly.jsdelivr.net/{jsd}"


def _group_readme(
    cfg_key: str, data: Dict,
    out_root: Path, raw_base: str, ghproxy: str,
    now: datetime.datetime,
) -> None:
    title       = data.get("title", cfg_key)
    desc        = data.get("description", "")
    fmt_counts  = data.get("format_counts", {})
    final_count = data.get("final_count", 0)
    forced_off  = data.get("dedup_forced_off", False)
    group_dir   = out_root / cfg_key
    ts          = now.strftime("%Y-%m-%d %H:%M:%S")

    rows: List[Tuple[str, str, str, str, str, str]] = []
    for fmt, count in fmt_counts.items():
        fname = _FMT_FILE.get(fmt)
        if not fname or not (group_dir / fname).exists():
            continue
        raw_url = f"{raw_base.rstrip('/')}/{cfg_key}/{fname}"
        cdn_url, fastly_url = _jsd_url(raw_url)
        ghp_url = f"{ghproxy.rstrip('/')}/{raw_url}"
        cdn    = f"[CDN]({cdn_url})"    if cdn_url    else "—"
        fastly = f"[Fastly]({fastly_url})" if fastly_url else "—"
        ghp    = f"[ghproxy]({ghp_url})"

        if fmt in _DEDUPED_FORMATS:
            dedup = "原始(强制)" if forced_off else "OK"
        else:
            dedup = "—"

        rows.append((fname, f"{count:,}", dedup, f"[↓]({raw_url})", cdn, fastly, ghp))

        conv = _CONV_FILE.get(fmt)
        if conv and (group_dir / conv).exists():
            raw_conv = f"{raw_base.rstrip('/')}/{cfg_key}/{conv}"
            cdn_c, fastly_c = _jsd_url(raw_conv)
            ghp_c = f"{ghproxy.rstrip('/')}/{raw_conv}"
            rows.append((
                conv, f"{count:,}", dedup,
                f"[↓]({raw_conv})",
                f"[CDN]({cdn_c})" if cdn_c else "—",
                f"[Fastly]({fastly_c})" if fastly_c else "—",
                f"[ghproxy]({ghp_c})",
            ))

    lines: List[str] = [f"# {title}", ""]
    if desc:
        lines += [f"> {desc}", ""]
    lines += [
        f"**规则总数：{final_count:,}**    **更新时间：{ts} (CST)**",
        "",
        "| 文件 | 规则数 | 去重 | 直链 | CDN | Fastly | ghproxy |",
        "| :--- | ---: | :---: | :---: | :---: | :---: | :---: |",
    ]
    for fname, count, dedup, raw, cdn, fastly, ghp in rows:
        lines.append(f"| `{fname}` | {count} | {dedup} | {raw} | {cdn} | {fastly} | {ghp} |")
    lines.append("")

    (group_dir / "README.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    log(f"  OK {cfg_key}/README.md")


def _main_readme(all_stats: Dict, now: datetime.datetime) -> None:
    ts    = now.strftime("%Y-%m-%d %H:%M:%S")
    badge = now.strftime("%Y--%m--%d_%H:%M:%S")
    lines: List[str] = [
        "# Domain Filter",
        "",
        f"![Updated](https://img.shields.io/badge/Updated-{badge}-brightgreen?style=flat-square)",
        "",
        "## 规则列表",
        "",
    ]
    visible = sorted(
        [(k, v) for k, v in all_stats.items() if v.get("output_enabled") and v.get("title")],
        key=lambda x: x[1].get("idx", 0),
    )
    for cfg_key, data in visible:
        fmts = " - ".join(_FMT_LABEL.get(f, f) for f in data.get("format_counts", {}))
        lines.append(
            f"- **{data['title']}** — {data.get('description', '')}  \n"
            f"  `{fmts}` - [查看详情](data/rules/{cfg_key})"
        )
    lines += ["", f"*{ts} (CST)*", ""]
    _README_ROOT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    log("OK README.md")


def _readmes(
    all_stats: Dict, out_root: Path,
    raw_base: str, ghproxy: str, tz: str,
) -> None:
    now = datetime.datetime.now(ZoneInfo(tz))
    log("生成子目录 README...")
    for cfg_key, data in all_stats.items():
        if not data.get("output_enabled") or not data.get("title"):
            continue
        if not (out_root / cfg_key).is_dir():
            continue
        try:
            _group_readme(cfg_key, data, out_root, raw_base, ghproxy, now)
        except Exception as e:
            log(f"子目录 README 失败 [{cfg_key}]：{e}", LogLevel.WARNING)
    log("生成主 README...")
    try:
        _main_readme(all_stats, now)
    except Exception as e:
        log(f"主 README 失败：{e}", LogLevel.ERROR)


def _parse_mode(raw: Optional[str]) -> ExtractMode:
    return {
        "common": ExtractMode.COMMON,
        "adblockwhite": ExtractMode.ADBLOCKWHITE,
        "skip": ExtractMode.SKIP,
    }.get((raw or "").strip().lower(), ExtractMode.COMMON)


def _parse_src(entry) -> Optional[Dict]:
    if isinstance(entry, str):
        s = entry.strip()
        if s.startswith(("http://", "https://")):
            return {"kind": "url", "url": s, "mode": ExtractMode.COMMON, "validate": True}
        if s.startswith("@"):
            return {"kind": "group", "key": s[1:]}
        if s:
            return {"kind": "named", "name": s}
    elif isinstance(entry, dict):
        url = (entry.get("url") or "").strip()
        if url:
            return {
                "kind": "url", "url": url,
                "mode": _parse_mode(entry.get("mode")),
                "validate": bool(entry.get("validate", True)),
            }
    return None


def _load_config(path: Path) -> Tuple[Dict, List[Dict], Dict[str, Dict]]:
    if not path.is_file():
        log(f"错误：缺少配置文件 {path}", LogLevel.ERROR)
        sys.exit(1)
    try:
        with path.open(encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
    except yaml.YAMLError as e:
        log(f"配置文件解析失败：{e}", LogLevel.ERROR)
        sys.exit(1)

    global_cfg  = data.pop("global",  {}) or {}
    sources_raw = data.pop("sources", {}) or {}

    named: Dict[str, Dict] = {}
    for name, cfg in sources_raw.items():
        if isinstance(cfg, str) and cfg.strip():
            named[name] = {"url": cfg.strip(), "mode": ExtractMode.COMMON, "validate": True}
        elif isinstance(cfg, dict) and (cfg.get("url") or "").strip():
            named[name] = {
                "url":      cfg["url"].strip(),
                "mode":     _parse_mode(cfg.get("mode")),
                "validate": bool(cfg.get("validate", True)),
            }

    groups = []
    for idx, (key, cfg) in enumerate(data.items()):
        if not isinstance(cfg, dict):
            continue
        fmts = cfg.get("formats")
        if fmts is None:
            enabled_out, fmts = False, []
        else:
            enabled_out = True
            if isinstance(fmts, str):
                fmts = [fmts]
        raw_dedup = cfg.get("dedup_subdomain")
        groups.append({
            "cfg_key":         key,
            "idx":             idx,
            "enabled":         bool(cfg.get("enabled", True)),
            "dedup_subdomain": None if raw_dedup is None else bool(raw_dedup),
            "title":           cfg.get("title", ""),
            "description":     cfg.get("description", ""),
            "rules":           cfg.get("rules") or [],
            "formats":         fmts,
            "output_enabled":  enabled_out,
        })

    enabled_count = sum(1 for g in groups if g["enabled"])
    log(f"OK 配置已加载：{len(named)} 个命名源，{len(groups)} 个规则组（{enabled_count} 个已启用）")
    return global_cfg, groups, named


def _validate(
    groups: List[Dict], named: Dict[str, Dict],
    log_file: Optional[Path] = None,
) -> bool:
    errors: List[str] = []
    idx_map = {g["cfg_key"]: g["idx"] for g in groups}

    for g in groups:
        key, gidx = g["cfg_key"], g["idx"]
        for fmt in g.get("formats", []):
            if fmt not in ALL_FORMATS:
                errors.append(f"规则组 '{key}' formats 包含未知格式：'{fmt}'")
        if not isinstance(g["rules"], list):
            errors.append(f"规则组 '{key}' rules 必须是列表")
            continue
        for ri, rule in enumerate(g["rules"]):
            if not isinstance(rule, dict):
                errors.append(f"规则组 '{key}' rules[{ri}] 必须是字典")
                continue
            if "type" not in rule:
                errors.append(f"规则组 '{key}' rules[{ri}] 缺少 type")
                continue
            if rule["type"] not in VALID_RULE_TYPES:
                errors.append(f"规则组 '{key}' rules[{ri}] type '{rule['type']}' 无效")
            for entry in rule.get("source") or []:
                p = _parse_src(entry)
                if p is None:
                    errors.append(f"规则组 '{key}' rules[{ri}] source 无法识别：{entry!r}")
                elif p["kind"] == "named" and p["name"] not in named:
                    errors.append(f"规则组 '{key}' rules[{ri}] source '{p['name']}' 未定义")
                elif p["kind"] == "group":
                    ref = idx_map.get(p["key"])
                    if ref is None:
                        errors.append(f"规则组 '{key}' rules[{ri}] source '@{p['key']}' 不存在")
                    elif ref >= gidx:
                        errors.append(f"规则组 '{key}' rules[{ri}] source '@{p['key']}' 不允许向后引用")

    for err in errors:
        log(err, LogLevel.ERROR, log_file)
    return not errors


def _process(
    group: Dict,
    dl: Dict[str, Set[str]],
    cache: Dict[int, Set[str]],
    idx_map: Dict[str, int],
    out_root: Path,
    all_stats: Dict,
    log_file: Path,
    tz: str,
) -> None:
    key    = group["cfg_key"]
    gidx   = group["idx"]
    title  = group.get("title", "")
    desc   = group.get("description", "")
    fmts   = group.get("formats", [])
    out_en = group.get("output_enabled", False)
    dedup  = group.get("dedup_subdomain")

    t0 = time.time()
    log("=" * 70, log_file=log_file)
    log(f"处理规则组：{title or key} ({key})", log_file=log_file)
    log("=" * 70, log_file=log_file)

    cur: Set[str] = set()

    for ri, rule in enumerate(group.get("rules", [])):
        if not isinstance(rule, dict):
            continue
        rtype = rule["type"]
        log(f"  |  rules[{ri}] type={rtype}", log_file=log_file)
        rd: Set[str] = set()

        for entry in rule.get("source") or []:
            p = _parse_src(entry)
            if p is None:
                continue
            if p["kind"] == "url":
                s = dl.get(p["url"], set())
                rd.update(s)
                log(f"  |    url：{len(s):,} <- {p['url']}", log_file=log_file)
            elif p["kind"] == "named":
                s = dl.get(p["name"], set())
                rd.update(s)
                log(f"  |    named：{len(s):,} <- {p['name']}", log_file=log_file)
            elif p["kind"] == "group":
                ref = idx_map.get(p["key"])
                if ref is not None and ref < gidx and ref in cache:
                    s = cache[ref]
                    rd.update(s)
                    log(f"  |    @{p['key']}：{len(s):,}", log_file=log_file)
                else:
                    log(f"  |    @{p['key']} 无效，跳过", LogLevel.WARNING, log_file)

        custom = [d.strip().lower() for d in (rule.get("domain") or []) if isinstance(d, str) and d.strip()]
        if custom:
            rd.update(custom)
            log(f"  |    domain：{len(custom):,} 条自定义", log_file=log_file)

        log(f"  |    共 {len(rd):,} 条", log_file=log_file)
        before = len(cur)

        if rtype == "add":
            cur.update(rd)
            log(f"  |    -> 加入 {len(cur)-before:,}（合计 {len(cur):,}）", log_file=log_file)
        elif rtype == "discard":
            cur = _discard_exact(cur, rd)
            log(f"  |    -> 精确丢弃 {before-len(cur):,}（剩余 {len(cur):,}）", log_file=log_file)
        elif rtype == "discard_suffix":
            cur = _discard_suffix(cur, rd, log_file)
            log(f"  |    -> 后缀丢弃 {before-len(cur):,}（剩余 {len(cur):,}）", log_file=log_file)
        elif rtype == "match":
            cur = _match_exact(cur, rd)
            log(f"  |    -> 精确保留 {len(cur):,}（移除 {before-len(cur):,}）", log_file=log_file)
        elif rtype == "match_suffix":
            cur = _match_suffix(cur, rd, log_file)
            log(f"  |    -> 后缀保留 {len(cur):,}（移除 {before-len(cur):,}）", log_file=log_file)

    log(f"  |  完毕，共 {len(cur):,} 条", log_file=log_file)
    cache[gidx] = cur

    if not out_en:
        log(f"  `- 不输出（无 formats），耗时 {time.time()-t0:.2f}s", log_file=log_file)
        all_stats[key] = {"idx": gidx, "title": title, "description": desc,
                          "output_enabled": False, "final_count": len(cur),
                          "format_counts": {}, "dedup_forced_off": False}
        return

    needs_dedup    = any(f in _DEDUPED_FORMATS for f in fmts)
    forced_off     = dedup is False

    if dedup is True:
        dd = _dedup(cur, log_file)
        log(f"  |  子域去重（强制）：移除 {len(cur)-len(dd):,}", log_file=log_file)
    elif forced_off:
        dd = cur
        log("  |  子域去重（强制跳过）", log_file=log_file)
    elif needs_dedup:
        dd = _dedup(cur, log_file)
        log(f"  |  子域去重：移除 {len(cur)-len(dd):,}", log_file=log_file)
    else:
        dd = cur

    gdir = out_root / key
    gdir.mkdir(parents=True, exist_ok=True)
    try:
        fmt_counts = _save(cur, dd, gdir, title, desc, fmts, tz, log_file)
    except Exception as e:
        log(f"规则文件生成失败 [{key}]：{e}", LogLevel.ERROR, log_file)
        fmt_counts = {}

    gc.collect()
    log(f"  `- 输出 {len(dd):,} 条，耗时 {time.time()-t0:.2f}s", log_file=log_file)
    all_stats[key] = {"idx": gidx, "title": title, "description": desc,
                      "output_enabled": True, "final_count": len(dd),
                      "format_counts": fmt_counts, "dedup_forced_off": forced_off}


def main() -> None:
    t_start = time.time()
    print("=" * 80)
    print("Domain Filter - 域名过滤工具".center(80))
    print("=" * 80)
    print()

    global_cfg, groups, named = _load_config(_CONFIG_PATH)

    out_root = Path(global_cfg.get("output_root", "data/rules"))
    tz       = global_cfg.get("timezone",  "Asia/Shanghai")
    raw_base = global_cfg.get("raw_base",  "https://raw.githubusercontent.com/cjchxgxhc/domain-filter/refs/heads/main/data/rules")
    ghproxy  = global_cfg.get("ghproxy",   "https://ghproxy.net/")

    out_root.mkdir(parents=True, exist_ok=True)
    log_file = out_root / "log.txt"
    if log_file.exists():
        log_file.unlink()

    log("开始执行", log_file=log_file)

    if not _validate(groups, named, log_file):
        sys.exit(1)

    idx_map = {g["cfg_key"]: g["idx"] for g in groups}

    all_urls: Set[str] = {s["url"] for s in named.values()}
    for g in groups:
        for rule in g.get("rules", []):
            if not isinstance(rule, dict):
                continue
            for entry in rule.get("source") or []:
                p = _parse_src(entry)
                if p and p["kind"] == "url":
                    all_urls.add(p["url"])

    try:
        raw_dl = _download(list(all_urls), log_file)
    except Exception as e:
        log(f"下载失败：{e}", LogLevel.ERROR, log_file)
        log(traceback.format_exc(), LogLevel.ERROR, log_file)
        sys.exit(1)

    src_cfgs: Dict[str, Dict] = {s["url"]: s for s in named.values()}
    for g in groups:
        for rule in g.get("rules", []):
            if not isinstance(rule, dict):
                continue
            for entry in rule.get("source") or []:
                p = _parse_src(entry)
                if not p or p["kind"] != "url":
                    continue
                url = p["url"]
                if url in src_cfgs:
                    ex = src_cfgs[url]
                    if ex["mode"] != p["mode"] or ex["validate"] != p["validate"]:
                        log(
                            f"警告：'{url}' 多次内联且 mode/validate 不同，"
                            f"使用首次配置（mode={ex['mode'].value}, validate={ex['validate']}）",
                            LogLevel.WARNING, log_file,
                        )
                else:
                    src_cfgs[url] = p

    log(f"提取域名（{len(src_cfgs)} 个源）...", log_file=log_file)
    t_ex = time.time()
    dl: Dict[str, Set[str]] = {}

    with ThreadPoolExecutor(max_workers=_EXTRACT_WORKERS) as ex:
        fut: Dict = {}
        for url, cfg in src_cfgs.items():
            lines = raw_dl.get(url, [])
            if lines:
                fut[ex.submit(_extract_lines, lines, cfg["mode"], cfg["validate"])] = url
            else:
                dl[url] = set()
        for future, url in fut.items():
            try:
                dl[url] = future.result()
            except Exception as e:
                log(f"  {url}：提取失败 {e}", LogLevel.ERROR, log_file)
                dl[url] = set()

    for sname, cfg in named.items():
        dl[sname] = dl.get(cfg["url"], set())
        log(f"  {sname}：{len(dl[sname]):,} 条 [{cfg['mode'].value}]", log_file=log_file)

    log(f"提取完成，耗时 {time.time()-t_ex:.2f}s", log_file=log_file)

    cache: Dict[int, Set[str]] = {}
    all_stats: Dict = {}

    log("=" * 80, log_file=log_file)
    log("处理规则组", log_file=log_file)
    log("=" * 80, log_file=log_file)

    for g in groups:
        if not g["enabled"]:
            log(f"  跳过（已禁用）：{g['cfg_key']}", log_file=log_file)
            continue
        try:
            _process(g, dl, cache, idx_map, out_root, all_stats, log_file, tz)
        except Exception as e:
            log(f"规则组异常 [{g['cfg_key']}]：{e}", LogLevel.ERROR, log_file)
            log(traceback.format_exc(), LogLevel.ERROR, log_file)

    log("=" * 80, log_file=log_file)
    log("生成 README", log_file=log_file)
    log("=" * 80, log_file=log_file)
    try:
        _readmes(all_stats, out_root, raw_base, ghproxy, tz)
    except Exception as e:
        log(f"README 失败：{e}", LogLevel.WARNING, log_file)

    log("=" * 80, log_file=log_file)
    log(f"OK 完成，总耗时 {time.time()-t_start:.2f}s", log_file=log_file)
    log("=" * 80, log_file=log_file)

    _flush_log()
    gc.collect()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n用户中断")
        sys.exit(130)
    except Exception as e:
        log(f"程序异常退出：{e}", LogLevel.ERROR)
        traceback.print_exc()
        sys.exit(1)
