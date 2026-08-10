#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import datetime
import gc
import json
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

_DOWNLOAD_WORKERS = 16   # 同时也是并发调用 Rust 提取子进程的数量（下载+提取按源融合并发）
_CONNECT_TIMEOUT  = 10
_READ_TIMEOUT     = 30
_RETRY_COUNT      = 3
_RETRY_DELAY      = 1.0
_USER_AGENT       = (
    "Mozilla/5.0 (compatible; GitHubActions/1.0; "
    "+https://github.com/cjchxgxhc/domain-filter)"
)

_RUST_TOOL      = Path("data/tools/domain_filter")
_CONFIG_PATH    = Path("data/script/config.yaml")
_FORMATS_PATH   = Path("data/script/formats.yaml")
_README_ROOT    = Path("README.md")

_REGEX_RAW_GH = re.compile(
    r"^https://raw\.githubusercontent\.com/"
    r"(?P<user>[^/]+)/(?P<repo>[^/]+)/(?:refs/heads/)?"
    r"(?P<branch>[^/]+)/(?P<path>.+)$"
)

_LOCAL_PREFIX = "local:"


class LogLevel(Enum):
    INFO    = "INFO"
    WARNING = "WARNING"
    ERROR   = "ERROR"


class ExtractMode(Enum):
    COMMON       = "common"
    ADBLOCKWHITE = "adblockwhite"
    SKIP         = "skip"


VALID_RULE_TYPES = frozenset({"add", "discard", "discard_suffix", "match", "match_suffix"})


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


# ─────────────────────────── 格式定义（formats.yaml） ─────────────────────────

_FORMATS: Optional[Dict[str, Dict]] = None


def _load_formats(path: Path) -> Dict[str, Dict]:
    if not path.is_file():
        log(f"错误：缺少格式配置文件 {path}", LogLevel.ERROR)
        sys.exit(1)
    try:
        with path.open(encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
    except yaml.YAMLError as e:
        log(f"格式配置文件解析失败：{e}", LogLevel.ERROR)
        sys.exit(1)

    raw = data.get("formats") or {}
    formats: Dict[str, Dict] = {}
    for fid, spec in raw.items():
        if not isinstance(spec, dict):
            log(f"格式 '{fid}' 定义无效，已跳过", LogLevel.WARNING)
            continue
        spec = dict(spec)
        spec.setdefault("label", fid)
        spec.setdefault("filename", f"{fid}.txt")
        spec.setdefault("dedup", False)
        spec.setdefault("header", "none")
        spec.setdefault("prefix", "")
        spec.setdefault("prefix_before_header", False)
        spec.setdefault("lines", [])
        spec.setdefault("kind", "line")
        spec.setdefault("convert", None)
        if spec["header"] not in ("none", "simple", "adblock"):
            log(f"格式 '{fid}' header 取值无效：{spec['header']}", LogLevel.WARNING)
            spec["header"] = "none"
        formats[fid] = spec

    log(f"OK 格式配置已加载：{len(formats)} 种输出格式")
    return formats


def _get_formats() -> Dict[str, Dict]:
    global _FORMATS
    if _FORMATS is None:
        _FORMATS = _load_formats(_FORMATS_PATH)
    return _FORMATS


# ─────────────────────────── 域名过滤 / 去重（调用 Rust） ─────────────────────

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


def _rust_extract(
    lines: List[str], mode: ExtractMode, validate: bool,
    log_file: Optional[Path] = None,
) -> Set[str]:
    """调用 Rust `extract` 子命令完成域名提取 + 格式校验，替代原 Python 正则实现。"""
    if not lines:
        return set()
    if not _RUST_TOOL.exists():
        raise FileNotFoundError(f"Rust 工具不存在：{_RUST_TOOL}")
    inp = "\n".join(lines)
    try:
        p = subprocess.run(
            [str(_RUST_TOOL), "extract", mode.value, "1" if validate else "0"],
            input=inp, capture_output=True, text=True, check=True,
        )
        return set(p.stdout.splitlines())
    except subprocess.CalledProcessError as e:
        log(f"Rust 提取失败（{mode.value}）：{e.stderr[:200]}", LogLevel.WARNING, log_file)
        return set()


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


def _download_and_extract(
    src_cfgs: Dict[str, Dict],
    log_file: Optional[Path] = None,
) -> Dict[str, Set[str]]:
    """按源并发下载 + 调 Rust 提取，融合成一步（不必等全部下载完成才开始提取）。
    不做跨次运行缓存——每次都是一次完整下载 + 提取。
    """
    if not src_cfgs:
        return {}

    log(f"下载并提取（{len(src_cfgs)} 个源）...", log_file=log_file)
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

    stats = {"ok": 0, "failed": 0}

    def _one(url: str, cfg: Dict) -> Tuple[str, Set[str], bool]:
        try:
            r = session.get(url, timeout=(_CONNECT_TIMEOUT, _READ_TIMEOUT))
            r.raise_for_status()
        except Exception as e:
            log(f"  FAIL {url}：{e}", LogLevel.WARNING, log_file)
            return url, set(), False
        domains = _rust_extract(r.text.splitlines(), cfg["mode"], cfg["validate"], log_file)
        return url, domains, True

    result: Dict[str, Set[str]] = {}
    with ThreadPoolExecutor(max_workers=_DOWNLOAD_WORKERS) as ex:
        futures = {ex.submit(_one, url, cfg): url for url, cfg in src_cfgs.items()}
        for future in as_completed(futures):
            url = futures[future]
            try:
                u, domains, ok = future.result()
            except Exception as e:
                result[url] = set()
                stats["failed"] += 1
                log(f"  FAIL {url}：{e}", LogLevel.WARNING, log_file)
                continue
            result[u] = domains
            stats["ok" if ok else "failed"] += 1

    log(
        f"完成：{stats['ok']} 个成功，{stats['failed']} 个失败，耗时 {time.time()-t0:.2f}s",
        log_file=log_file,
    )
    return result


def _read_and_extract_local(
    local_cfgs: Dict[str, Dict],
    log_file: Optional[Path] = None,
) -> Dict[str, Set[str]]:
    """读取仓库内本地文件并提取域名（local: 前缀），用于引用仓库自身维护的名单，
    避免通过 raw.githubusercontent.com 回环拉取自己仓库（刚提交还没生效时
    会读到旧内容甚至 404）。key 统一为 "local:<path>"。

    本地文件不存在或读取失败时，只记警告并当作空集合处理，不会导致整个任务失败
    ——本地清单文件可能只是临时还没建，不应该阻塞其它规则组的产出。
    """
    result: Dict[str, Set[str]] = {}
    if not local_cfgs:
        return result

    log(f"读取本地文件（{len(local_cfgs)} 个）...", log_file=log_file)
    t0 = time.time()
    ok, failed = 0, 0
    for key, cfg in local_cfgs.items():
        p = Path(cfg["path"])
        if not p.is_file():
            log(f"  跳过：本地文件不存在（当作空集合处理）：{p}", LogLevel.WARNING, log_file)
            result[key] = set()
            failed += 1
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="ignore")
        except Exception as e:
            log(f"  跳过：读取本地文件失败 {p}：{e}", LogLevel.WARNING, log_file)
            result[key] = set()
            failed += 1
            continue
        domains = _rust_extract(text.splitlines(), cfg["mode"], cfg["validate"], log_file)
        result[key] = domains
        log(f"  OK {p}：{len(domains):,} 条 [{cfg['mode'].value}]", log_file=log_file)
        ok += 1

    log(f"完成：{ok} 个成功，{failed} 个跳过，耗时 {time.time()-t0:.2f}s", log_file=log_file)
    return result


# ─────────────────────────── 输出头部（不含时间戳，避免内容未变也产生 diff） ────

def _hdr(count: int, tool: str, desc: str, c: str) -> str:
    """通用简单头部：描述 + 适用工具 + 规则数（不含更新时间）"""
    parts: List[str] = []
    if desc:
        parts.append(f"{c} {desc}")
    parts.append(f"{c} 适用：{tool}  规则数：{count:,}")
    parts.append(c)
    return "\n".join(parts) + "\n"


def _hdr_adblock(count: int, title: str, desc: str) -> str:
    """AdGuard 兼容头部（不含 Last modified，避免内容未变也产生 diff）"""
    lines: List[str] = []
    if title:
        lines.append(f"! Title: {title}")
    if desc:
        lines.append(f"! Description: {desc}")
    lines.append(f"! Homepage: https://github.com/cjchxgxhc/domain-filter")
    lines.append("! Expires: 1 days (update frequency)")
    lines.append(f"! Total count: {count:,}")
    return "\n".join(lines) + "\n"


def _write_fmt(
    fmt: str, out: Path,
    simple: List[str], deduped: List[str],
    title: str, desc: str,
) -> Tuple[str, int]:
    """按 formats.yaml 中的格式定义生成单个规则文件。"""
    spec = _get_formats().get(fmt)
    if spec is None:
        raise ValueError(f"未知格式：{fmt}")

    values = deduped if spec["dedup"] else simple
    fname  = spec["filename"]
    p      = out / fname
    tool   = spec["label"]

    # sing-box 的 JSON 结构不是逐行文本，单独处理
    if spec["kind"] == "singbox_json":
        with p.open("w", encoding="utf-8") as f:
            json.dump({"version": 3, "rules": [{"domain_suffix": values}]}, f, indent=2, ensure_ascii=False)
        return fname, len(values)

    header  = spec["header"]
    prefix  = spec.get("prefix") or ""
    pre_hdr = bool(spec.get("prefix_before_header"))

    with p.open("w", encoding="utf-8") as f:
        if pre_hdr and prefix:
            f.write(prefix)
        if header == "simple":
            f.write(_hdr(len(values), tool, desc, "#"))
        elif header == "adblock":
            f.write(_hdr_adblock(len(values), title, desc))
        if not pre_hdr and prefix:
            f.write(prefix)
        for x in values:
            for tmpl in spec["lines"]:
                f.write(tmpl.format(domain=x) + "\n")

    return fname, len(values)


def _save(
    simple: Set[str], deduped: Set[str],
    out: Path, title: str, desc: str,
    formats: List[str],
    log_file: Optional[Path] = None,
) -> Dict[str, int]:
    if not simple and not deduped:
        log(f"警告：没有域名可保存（{out.name}）", LogLevel.ERROR, log_file)
        return {}
    out.mkdir(parents=True, exist_ok=True)
    ss, dd = sorted(simple), sorted(deduped)
    counts: Dict[str, int] = {}
    fmt_registry = _get_formats()
    for fmt in formats:
        fname, count = _write_fmt(fmt, out, ss, dd, title, desc)
        counts[fmt] = count
        note = "（去重）" if fmt_registry.get(fmt, {}).get("dedup") else ""
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
    fmt_registry = _get_formats()

    rows: List[Tuple[str, str, str, str, str, str, str]] = []
    for fmt, count in fmt_counts.items():
        spec = fmt_registry.get(fmt)
        fname = spec.get("filename") if spec else None
        if not fname or not (group_dir / fname).exists():
            continue
        raw_url = f"{raw_base.rstrip('/')}/{cfg_key}/{fname}"
        cdn_url, fastly_url = _jsd_url(raw_url)
        ghp_url = f"{ghproxy.rstrip('/')}/{raw_url}"
        cdn    = f"[CDN]({cdn_url})"    if cdn_url    else "—"
        fastly = f"[Fastly]({fastly_url})" if fastly_url else "—"
        ghp    = f"[ghproxy]({ghp_url})"

        dedup = ("原始(强制)" if forced_off else "OK") if spec.get("dedup") else "—"

        rows.append((fname, f"{count:,}", dedup, f"[↓]({raw_url})", cdn, fastly, ghp))

        conv = spec.get("convert")
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

    for fname, count in data.get("custom_files", []):
        if not (group_dir / fname).exists():
            continue
        raw_url = f"{raw_base.rstrip('/')}/{cfg_key}/{fname}"
        cdn_url, fastly_url = _jsd_url(raw_url)
        ghp_url = f"{ghproxy.rstrip('/')}/{raw_url}"
        cdn    = f"[CDN]({cdn_url})"    if cdn_url    else "—"
        fastly = f"[Fastly]({fastly_url})" if fastly_url else "—"
        ghp    = f"[ghproxy]({ghp_url})"
        rows.append((fname, f"{count:,}", "OK", f"[↓]({raw_url})", cdn, fastly, ghp))

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
    fmt_registry = _get_formats()
    visible = sorted(
        [(k, v) for k, v in all_stats.items() if v.get("output_enabled") and v.get("title")],
        key=lambda x: x[1].get("idx", 0),
    )
    for cfg_key, data in visible:
        fmts = " - ".join(fmt_registry.get(f, {}).get("label", f) for f in data.get("format_counts", {}))
        if not fmts and data.get("custom_files"):
            fmts = "Adblock"
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
        if s.startswith(_LOCAL_PREFIX):
            return {"kind": "local", "path": s[len(_LOCAL_PREFIX):].strip(),
                     "mode": ExtractMode.COMMON, "validate": True}
        if s.startswith("@"):
            return {"kind": "group", "key": s[1:]}
        if s:
            return {"kind": "named", "name": s}
    elif isinstance(entry, dict):
        local = (entry.get("local") or "").strip()
        url   = (entry.get("url") or "").strip()
        if local:
            return {
                "kind": "local", "path": local,
                "mode": _parse_mode(entry.get("mode")),
                "validate": bool(entry.get("validate", True)),
            }
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
            s = cfg.strip()
            if s.startswith(_LOCAL_PREFIX):
                named[name] = {"kind": "local", "path": s[len(_LOCAL_PREFIX):].strip(),
                               "mode": ExtractMode.COMMON, "validate": True}
            else:
                named[name] = {"kind": "url", "url": s, "mode": ExtractMode.COMMON, "validate": True}
        elif isinstance(cfg, dict):
            local = (cfg.get("local") or "").strip()
            url   = (cfg.get("url") or "").strip()
            if local:
                named[name] = {
                    "kind": "local", "path": local,
                    "mode": _parse_mode(cfg.get("mode")),
                    "validate": bool(cfg.get("validate", True)),
                }
            elif url:
                named[name] = {
                    "kind": "url", "url": url,
                    "mode": _parse_mode(cfg.get("mode")),
                    "validate": bool(cfg.get("validate", True)),
                }

    groups = []
    for idx, (key, cfg) in enumerate(data.items()):
        if not isinstance(cfg, dict):
            continue
        enabled = bool(cfg.get("enabled", cfg.get("enable", True)))

        # 有 sources 无 rules 的组被识别为「Adblock 聚合组」：直接聚合
        # uBlock/ABP 格式规则文本本身，走独立处理逻辑，而不是域名规则体系。
        if "sources" in cfg and "rules" not in cfg:
            groups.append({
                "cfg_key":            key,
                "idx":                idx,
                "kind":               "adblock",
                "enabled":            enabled,
                "title":              cfg.get("title", ""),
                "description":        cfg.get("description", ""),
                "sources":            cfg.get("sources") or [],
                "exclude_pure_domain": bool(cfg.get("exclude_pure_domain", True)),
                "output_enabled":     True,
                "dedup_subdomain":    None,
                "rules":              [],
                "formats":            [],
            })
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
            "kind":            "domain",
            "enabled":         enabled,
            "dedup_subdomain": None if raw_dedup is None else bool(raw_dedup),
            "title":           cfg.get("title", ""),
            "description":     cfg.get("description", ""),
            "rules":           cfg.get("rules") or [],
            "formats":         fmts,
            "output_enabled":  enabled_out,
            "sources":         [],
            "exclude_pure_domain": False,
        })

    enabled_count = sum(1 for g in groups if g["enabled"])
    log(f"OK 配置已加载：{len(named)} 个命名源，{len(groups)} 个规则组（{enabled_count} 个已启用）")
    return global_cfg, groups, named


def _validate(
    groups: List[Dict], named: Dict[str, Dict],
    log_file: Optional[Path] = None,
) -> bool:
    """校验配置结构性问题（会导致任务失败的错误）。
    本地文件是否存在不在这里检查——那只是运行时警告，不应该阻塞整个任务，
    详见 _read_and_extract_local。
    """
    errors: List[str] = []
    idx_map = {g["cfg_key"]: g["idx"] for g in groups}
    known_formats = _get_formats()

    for g in groups:
        key, gidx = g["cfg_key"], g["idx"]

        if g.get("kind") == "adblock":
            srcs = g.get("sources")
            if not isinstance(srcs, list) or not srcs:
                errors.append(f"Adblock 聚合组 '{key}' sources 不能为空")
            else:
                for u in srcs:
                    if not isinstance(u, str) or not u.strip():
                        errors.append(f"Adblock 聚合组 '{key}' sources 含无效条目：{u!r}")
            continue

        for fmt in g.get("formats", []):
            if fmt not in known_formats:
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
            elif p["kind"] == "local":
                s = dl.get(_LOCAL_PREFIX + p["path"], set())
                rd.update(s)
                log(f"  |    local：{len(s):,} <- {p['path']}", log_file=log_file)
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

    fmt_registry = _get_formats()
    needs_dedup  = any(fmt_registry.get(f, {}).get("dedup") for f in fmts)
    forced_off   = dedup is False

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
        fmt_counts = _save(cur, dd, gdir, title, desc, fmts, log_file)
    except Exception as e:
        log(f"规则文件生成失败 [{key}]：{e}", LogLevel.ERROR, log_file)
        fmt_counts = {}

    gc.collect()
    log(f"  `- 输出 {len(dd):,} 条，耗时 {time.time()-t0:.2f}s", log_file=log_file)
    all_stats[key] = {"idx": gidx, "title": title, "description": desc,
                      "output_enabled": True, "final_count": len(dd),
                      "format_counts": fmt_counts, "dedup_forced_off": forced_off}


# ─────────────────────────── Adblock CSS Rule 聚合（仅面向 uBlock Origin） ────
#
# 与上面基于域名的 rules 体系不同，这里直接聚合 uBlock/ABP 格式的规则文本本身。
# 目标只有 uBlock Origin，因此：
#   1. 只保留 uBlock 能解析的语法，AdGuard 专属语法（CSS 注入 #$#/#@$#、
#      脚本注入 #%#/#@%#、以及少量 AdGuard 专属网络规则选项）一律剔除；
#   2. 剔除已知会拖慢 uBlock 匹配性能的写法（正则规则、未锚定的超短泛匹配）；
#   3. 剔除明显格式不规范（残缺）的规则；
#   4. 剔除「纯域名拦截规则」（如 ||example.com^），因为域名维度的拦截已经由
#      上面 ads / ads_big 等基于域名的规则组覆盖，没必要重复维护两份；
#   5. 按 uBlock 支持的规则大类分类输出：通用元素隐藏 / 域名限定元素隐藏
#      （含 uBlock 的扩展 CSS 选择器、HTML 过滤 ##^、脚本注入 ##+js() —— 这些
#      都共用 ## / #@# / #?# / #@?# 标记，天然落在同一类里）与网络规则。
#
# 以下判定均为启发式规则，不追求 100% 精确覆盖 uBlock 的完整语法定义，
# 只处理常见、明确的情况；如果发现误判，可按需调整下面的正则/集合。

# uBlock 支持解析的元素标记
_UBO_CSS_RE      = re.compile(r'##|#@#|#\?#|#@\?#')
# AdGuard 专属、uBlock 不支持的标记（CSS 注入 / 脚本注入）——直接剔除
_ADG_ONLY_CSS_RE = re.compile(r'#\$#|#@\$#|#%#|#@%#')
# 任意一种「元素/脚本类」标记（用于先把这类规则和普通网络规则分开）
_ANY_COSMETIC_RE = re.compile(r'##|#@#|#\?#|#\$#|#%#|#@\?#|#@\$#|#@%#')
# 用于定位标记具体位置，从而拆出「域名限定部分」和「选择器部分」
_UBO_MARKER_SPLIT_RE = re.compile(r'(##|#@#|#\?#|#@\?#)')
_HTML_FILTER_RE  = re.compile(r'##\^')
_SCRIPTLET_RE    = re.compile(r'#@?#\+js\(')
# 通用（无 domain 限定）选择器里，纯裸标签/通配符的选择器（如 ##div、##*、
# ##body）——站点级别一刀切隐藏整个标签，几乎总是垃圾/误配置规则，予以剔除。
_BARE_TAG_SELECTOR_RE = re.compile(r'^(\*|[a-zA-Z][a-zA-Z0-9]*)$')

_COMMENT_RE = re.compile(r'^\s*[!\[]')

# 「纯域名拦截规则」：||domain^ 及其只做整域封锁、不带更细粒度匹配条件的简单
# 变体（$important/$third-party/$all/$badfilter 这类不改变匹配范围的修饰符）。
# 带 $domain=、$script、$xmlhttprequest 等精细选项的不算「纯」，予以保留。
_PURE_DOMAIN_RE = re.compile(
    r'^\|\|[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?'
    r'(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?)+\^'
    r'(\$(third-party|important|all|badfilter)(,(third-party|important|all|badfilter))*)?$'
)

# 正则形式的网络规则（/pattern/ ），uBlock 官方文档明确指出这类规则匹配开销
# 远高于普通字符串规则，数量一多会拖慢整体过滤性能，予以剔除。
_REGEX_FILTER_RE = re.compile(r'^(@@)?/.+/(\$[^$]*)?$')

# 未锚定、且去掉通配符/选项后剩余有效字符过短的网络规则——这类规则匹配面
# 过宽，是 uBlock 明确警示的性能反模式，予以剔除。
_MIN_UNANCHORED_PATTERN_LEN = 4

# AdGuard 专属、uBlock 确定不支持的网络规则选项，出现即整条剔除。
# 这个集合刻意收得比较窄：只放"确定不支持"的选项，避免把 uBlock 真正支持、
# 只是不太常见的选项（比如 $removeparam 这种全局/纯选项写法）也一并误杀。
_ADG_ONLY_NET_OPTIONS = {
    "replace", "cookie", "hls", "jsonprune", "app", "extension",
}


def _is_low_value_network_rule(line: str) -> Optional[str]:
    """返回丢弃原因（用于统计/日志），能保留则返回 None。

    注意：纯选项、不带匹配主体的规则（如 `$removeparam=eml-name`）是 uBlock
    里合法且常见的「全局规则」写法（对所有请求生效），不应该当成残缺规则剔除。
    """
    body = line[2:] if line.startswith("@@") else line

    if not body.strip():
        return "空规则"

    if _REGEX_FILTER_RE.match(line):
        return "正则规则（性能）"

    pattern_part = body
    opt_part = ""
    if "$" in body:
        pattern_part, _, opt_part = body.partition("$")

    if not pattern_part.strip() and not opt_part.strip():
        return "空规则"

    if opt_part:
        opts = {o.split("=", 1)[0].strip().lstrip("~").lower() for o in opt_part.split(",") if o.strip()}
        hit = opts & _ADG_ONLY_NET_OPTIONS
        if hit:
            return f"AdGuard 专属选项（{','.join(sorted(hit))}）"

    # 未锚定的超短泛匹配：既不是 || 开头，也不是 | 开头，去掉通配符后太短。
    # pattern_part 为空（纯选项全局规则）不在此列剔除范围内。
    if pattern_part and not pattern_part.startswith(("||", "|")):
        core = pattern_part.strip("*^")
        if len(core) < _MIN_UNANCHORED_PATTERN_LEN:
            return "未锚定超短泛匹配（性能）"

    return None


def _classify_ubo_lines(text: str, exclude_pure_domain: bool = True) -> Dict[str, object]:
    """把一份 uBlock/ABP 格式规则文本分类为：
      generic_css / domain_css   —— uBlock 支持的元素隐藏（含扩展 CSS/HTML 过滤/脚本注入）
      net_rules                  —— 网络规则（已剔除低质量/非标准/纯域名的）
    以及各类丢弃计数，供统计展示。

    对通用（无 domain 限定）元素规则额外做两项清理：
      - 通用白名单/例外规则（#@#、#@?# 且不带 domain）：脱离具体站点语境的
        全局例外规则几乎没有实际意义，只会增加体积，予以剔除；
      - 裸标签/通配符选择器（##div、##*、##body 这类）：站点级一刀切隐藏
        整个标签，几乎总是垃圾或误配置规则，予以剔除。
    这两项只针对「通用」规则；带 domain 限定的同类规则语境明确，予以保留。
    """
    generic_css: List[str] = []
    domain_css:  List[str] = []
    net_rules:   List[str] = []
    seen: Set[str] = set()

    stats = {
        "adg_only_cosmetic": 0,   # AdGuard 专属元素/脚本注入语法
        "malformed_cosmetic": 0,  # 选择器为空等残缺元素规则
        "generic_exception": 0,   # 通用（无 domain）白名单/例外规则
        "overbroad_generic": 0,   # 通用裸标签/通配符选择器
        "pure_domain":       0,   # 纯域名拦截规则
        "low_value_net":     0,   # 性能差/不规范的网络规则
        "html_filter":       0,   # 落在元素隐藏分类里的 HTML 过滤规则数（信息统计）
        "scriptlet":         0,   # 落在元素隐藏分类里的脚本注入规则数（信息统计）
    }

    for raw in text.splitlines():
        line = raw.strip()
        if not line or _COMMENT_RE.match(line):
            continue
        if line in seen:
            continue
        seen.add(line)

        if _ANY_COSMETIC_RE.search(line):
            if _ADG_ONLY_CSS_RE.search(line) and not _UBO_CSS_RE.search(line):
                stats["adg_only_cosmetic"] += 1
                continue

            m = _UBO_MARKER_SPLIT_RE.search(line)
            if not m:
                stats["adg_only_cosmetic"] += 1
                continue

            domains_part = line[:m.start()]
            marker       = m.group(1)
            selector     = line[m.end():]

            if not selector.strip():
                stats["malformed_cosmetic"] += 1
                continue

            is_generic   = not domains_part.strip()
            is_exception = marker in ("#@#", "#@?#")

            if is_generic and is_exception:
                stats["generic_exception"] += 1
                continue
            if is_generic and not is_exception and _BARE_TAG_SELECTOR_RE.match(selector.strip()):
                stats["overbroad_generic"] += 1
                continue

            if _HTML_FILTER_RE.search(line):
                stats["html_filter"] += 1
            if _SCRIPTLET_RE.search(line):
                stats["scriptlet"] += 1
            (generic_css if is_generic else domain_css).append(line)
            continue

        # 网络规则
        is_pure_domain = bool(_PURE_DOMAIN_RE.match(line) and not line.startswith("@@"))
        if is_pure_domain:
            stats["pure_domain"] += 1
            if exclude_pure_domain:
                continue
            net_rules.append(line)
            continue

        reason = _is_low_value_network_rule(line)
        if reason:
            stats["low_value_net"] += 1
            continue

        net_rules.append(line)

    return {
        "generic_css": generic_css, "domain_css": domain_css, "net_rules": net_rules,
        **stats,
    }


def _download_raw_texts(urls: List[str], log_file: Optional[Path] = None) -> Dict[str, str]:
    """仅下载原始文本，不做域名提取，供 Adblock CSS Rule 聚合组使用。"""
    if not urls:
        return {}

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

    def _one(url: str) -> Tuple[str, str]:
        try:
            r = session.get(url, timeout=(_CONNECT_TIMEOUT, _READ_TIMEOUT))
            r.raise_for_status()
            return url, r.text
        except Exception as e:
            log(f"  FAIL {url}：{e}", LogLevel.WARNING, log_file)
            return url, ""

    result: Dict[str, str] = {}
    with ThreadPoolExecutor(max_workers=_DOWNLOAD_WORKERS) as ex:
        futures = {ex.submit(_one, url): url for url in urls}
        for future in as_completed(futures):
            u, text = future.result()
            result[u] = text
    return result


def _dedup_keep_order(items: List[str]) -> List[str]:
    seen: Set[str] = set()
    out: List[str] = []
    for x in items:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


def _process_adblock(
    group: Dict, out_root: Path, all_stats: Dict, log_file: Path,
) -> None:
    key   = group["cfg_key"]
    title = group.get("title", "")
    desc  = group.get("description", "")
    urls  = group.get("sources", [])
    exclude_pure = group.get("exclude_pure_domain", True)

    t0 = time.time()
    log("=" * 70, log_file=log_file)
    log(f"处理 Adblock CSS Rule 聚合组：{title or key} ({key})", log_file=log_file)
    log("=" * 70, log_file=log_file)

    texts = _download_raw_texts(urls, log_file)

    generic_css: List[str] = []
    domain_css:  List[str] = []
    net_rules:   List[str] = []
    totals = {
        "adg_only_cosmetic": 0, "malformed_cosmetic": 0,
        "generic_exception": 0, "overbroad_generic": 0,
        "pure_domain": 0, "low_value_net": 0,
        "html_filter": 0, "scriptlet": 0,
    }

    for url in urls:
        text = texts.get(url, "")
        if not text:
            continue
        r = _classify_ubo_lines(text, exclude_pure)
        generic_css.extend(r["generic_css"])
        domain_css.extend(r["domain_css"])
        net_rules.extend(r["net_rules"])
        for k in totals:
            totals[k] += r[k]
        log(
            f"  |  {url}：元素 {len(r['generic_css'])+len(r['domain_css']):,}"
            f"（含 HTML过滤 {r['html_filter']:,}/脚本注入 {r['scriptlet']:,}），"
            f"网络 {len(r['net_rules']):,}，"
            f"丢弃：AdGuard专属 {r['adg_only_cosmetic']:,}/残缺 {r['malformed_cosmetic']:,}/"
            f"通用白名单 {r['generic_exception']:,}/过泛通用选择器 {r['overbroad_generic']:,}/"
            f"纯域名 {r['pure_domain'] if exclude_pure else 0:,}/低质量网络规则 {r['low_value_net']:,}",
            log_file=log_file,
        )

    if not exclude_pure:
        totals["pure_domain"] = 0  # 保留时不计入"丢弃"统计

    generic_css = _dedup_keep_order(generic_css)
    domain_css  = _dedup_keep_order(domain_css)
    net_rules   = _dedup_keep_order(net_rules)

    gdir = out_root / key
    gdir.mkdir(parents=True, exist_ok=True)
    fname = "adblock.txt"
    total = len(generic_css) + len(domain_css) + len(net_rules)

    with (gdir / fname).open("w", encoding="utf-8") as f:
        f.write("[Adblock Plus 2.0]\n")
        if title:
            f.write(f"! Title: {title}\n")
        if desc:
            f.write(f"! Description: {desc}\n")
        f.write("! Homepage: https://github.com/cjchxgxhc/domain-filter\n")
        f.write("! Expires: 1 days (update frequency)\n")
        f.write(
            f"! Element hiding rules: {len(generic_css)+len(domain_css):,} "
            f"(generic: {len(generic_css):,}, domain-specific: {len(domain_css):,}, "
            f"html-filter: {totals['html_filter']:,}, scriptlet: {totals['scriptlet']:,})\n"
        )
        f.write(f"! Network rules: {len(net_rules):,}\n")
        f.write(
            f"! Dropped: AdGuard-only syntax {totals['adg_only_cosmetic']:,}, "
            f"malformed {totals['malformed_cosmetic']:,}, "
            f"generic exception {totals['generic_exception']:,}, "
            f"overbroad generic selector {totals['overbroad_generic']:,}, "
            f"pure domain-block {totals['pure_domain']:,}, "
            f"low-value network rules {totals['low_value_net']:,}\n"
        )
        f.write("!\n")
        f.write("!" + "-" * 76 + "!\n")
        f.write("! Element hiding rules (generic rules first)\n")
        f.write("!" + "-" * 76 + "!\n")
        for x in generic_css:
            f.write(x + "\n")
        for x in domain_css:
            f.write(x + "\n")
        f.write("!\n")
        f.write("!" + "-" * 76 + "!\n")
        f.write("! Network rules\n")
        f.write("!" + "-" * 76 + "!\n")
        for x in net_rules:
            f.write(x + "\n")

    log(f"  OK {fname}（{total:,} 条）", log_file=log_file)
    log(f"  `- 完毕，耗时 {time.time()-t0:.2f}s", log_file=log_file)

    all_stats[key] = {
        "idx": group["idx"], "title": title, "description": desc,
        "output_enabled": True, "final_count": total,
        "format_counts": {}, "dedup_forced_off": False,
        "custom_files": [(fname, total)],
    }


def main() -> None:
    t_start = time.time()
    print("=" * 80)
    print("Domain Filter - 域名过滤工具".center(80))
    print("=" * 80)
    print()

    # 提前加载格式定义：一是让 _validate 能校验 formats 字段，二是尽早暴露 formats.yaml 的配置错误
    _get_formats()

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

    # 只收集「已启用」规则组实际引用到的源，未被启用组用到的源（包括 sources 里
    # 定义了但没人引用的命名源）一律不下载/不处理，省下不必要的网络与提取开销。
    disabled_keys = [g["cfg_key"] for g in groups if not g["enabled"]]
    if disabled_keys:
        log(f"已禁用（跳过）：{', '.join(disabled_keys)}", log_file=log_file)

    src_cfgs:   Dict[str, Dict] = {}
    local_cfgs: Dict[str, Dict] = {}
    used_named: Set[str] = set()

    for g in groups:
        if not g["enabled"]:
            continue
        for rule in g.get("rules", []):
            if not isinstance(rule, dict):
                continue
            for entry in rule.get("source") or []:
                p = _parse_src(entry)
                if not p:
                    continue
                if p["kind"] == "url":
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
                elif p["kind"] == "local":
                    key = _LOCAL_PREFIX + p["path"]
                    if key in local_cfgs:
                        ex = local_cfgs[key]
                        if ex["mode"] != p["mode"] or ex["validate"] != p["validate"]:
                            log(
                                f"警告：本地文件 '{p['path']}' 多次内联且 mode/validate 不同，"
                                f"使用首次配置（mode={ex['mode'].value}, validate={ex['validate']}）",
                                LogLevel.WARNING, log_file,
                            )
                    else:
                        local_cfgs[key] = p
                elif p["kind"] == "named":
                    used_named.add(p["name"])

    unused_named = set(named) - used_named
    if unused_named:
        log(f"命名源未被任何启用组引用，跳过下载：{', '.join(sorted(unused_named))}", log_file=log_file)

    for sname in used_named:
        cfg = named.get(sname)
        if not cfg:
            continue
        if cfg["kind"] == "local":
            local_cfgs.setdefault(_LOCAL_PREFIX + cfg["path"], cfg)
        else:
            src_cfgs.setdefault(cfg["url"], cfg)

    # 下载 + 提取融合为一步（按源并发，不必等全部下载完才开始提取），不做跨次运行缓存
    dl: Dict[str, Set[str]] = {}
    try:
        dl.update(_download_and_extract(src_cfgs, log_file))
        dl.update(_read_and_extract_local(local_cfgs, log_file))
    except Exception as e:
        log(f"下载/提取失败：{e}", LogLevel.ERROR, log_file)
        log(traceback.format_exc(), LogLevel.ERROR, log_file)
        sys.exit(1)

    for sname in used_named:
        cfg = named.get(sname)
        if not cfg:
            continue
        key = (_LOCAL_PREFIX + cfg["path"]) if cfg["kind"] == "local" else cfg["url"]
        dl[sname] = dl.get(key, set())
        log(f"  {sname}：{len(dl[sname]):,} 条 [{cfg['mode'].value}]", log_file=log_file)

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
            if g.get("kind") == "adblock":
                _process_adblock(g, out_root, all_stats, log_file)
            else:
                _process(g, dl, cache, idx_map, out_root, all_stats, log_file)
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
