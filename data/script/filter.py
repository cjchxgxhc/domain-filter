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


# discard_parent：新增规则类型，见 `_discard_parent` 的说明。
VALID_RULE_TYPES = frozenset(
    {"add", "discard", "discard_suffix", "discard_parent", "match", "match_suffix"}
)


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


def _rust_classify_adblock(
    text: str, exclude_pure_domain: bool, log_file: Optional[Path] = None,
) -> Tuple[List[str], List[str], List[str], int]:
    """调用 Rust `classify_adblock` 子命令完成 Adblock 规则分类（元素隐藏 /
    HTML 过滤 / 网络规则 + 纯域名封锁规则识别），替代原 Python 正则实现。
    返回 (generic_css, domain_css, url_rules, 剔除的纯域名规则数)。
    """
    if not text:
        return [], [], [], 0
    if not _RUST_TOOL.exists():
        raise FileNotFoundError(f"Rust 工具不存在：{_RUST_TOOL}")
    try:
        p = subprocess.run(
            [str(_RUST_TOOL), "classify_adblock", "1" if exclude_pure_domain else "0"],
            input=text, capture_output=True, text=True, check=True,
        )
    except subprocess.CalledProcessError as e:
        log(f"Rust adblock 分类失败：{e.stderr[:200]}", LogLevel.WARNING, log_file)
        return [], [], [], 0

    lines = p.stdout.splitlines()
    if not lines:
        return [], [], [], 0
    try:
        _, _, _, dropped = (int(x) for x in lines[0].split())
    except ValueError:
        log("Rust adblock 分类输出格式异常，已跳过", LogLevel.WARNING, log_file)
        return [], [], [], 0

    sections: Dict[str, List[str]] = {"---G---": [], "---D---": [], "---U---": []}
    cur_marker: Optional[str] = None
    for line in lines[1:]:
        if line in sections:
            cur_marker = line
            continue
        if cur_marker is not None:
            sections[cur_marker].append(line)

    return sections["---G---"], sections["---D---"], sections["---U---"], dropped


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

def _discard_parent(cur: Set[str], ref: Set[str], lf: Optional[Path] = None) -> Set[str]:
    """discard_parent：若 ref 中存在某域名是 cur 中某条目的子域名（或与之
    相等），则丢弃 cur 中的那个（更粗粒度的父域名）条目。方向与
    discard_suffix 相反（discard_suffix 用 ref 覆盖 cur；这里用 cur 反过来
    "覆盖" ref）。

    典型场景：广告规则维护中，某个父域名的封锁规则（如 example.com）已被
    更细粒度的子域名规则（如 sub.example.com，出现在参考名单/待处理列表中）
    取代或排除时，用它清理掉那条粗粒度的父域名规则。
    """
    if not ref or not cur:
        return cur
    try:
        return _rust("discard_parent", cur, ref)
    except Exception as e:
        log(f"discard_parent 失败，跳过：{e}", LogLevel.WARNING, lf)
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
            log(f"  FAIL 本地文件不存在：{p}", LogLevel.WARNING, log_file)
            result[key] = set()
            failed += 1
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="ignore")
        except Exception as e:
            log(f"  FAIL 读取本地文件失败 {p}：{e}", LogLevel.WARNING, log_file)
            result[key] = set()
            failed += 1
            continue
        domains = _rust_extract(text.splitlines(), cfg["mode"], cfg["validate"], log_file)
        result[key] = domains
        log(f"  OK {p}：{len(domains):,} 条 [{cfg['mode'].value}]", log_file=log_file)
        ok += 1

    log(f"完成：{ok} 个成功，{failed} 个失败，耗时 {time.time()-t0:.2f}s", log_file=log_file)
    return result


def _download_raw_texts(urls: List[str], log_file: Optional[Path] = None) -> Dict[str, str]:
    """仅下载原始文本，不做域名提取，供 Adblock 聚合组使用。"""
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
    lines.append("! Expires: 7 days (update frequency)")
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

    # Adblock 聚合组等不走 formats.yaml 的自定义产出文件
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
        is_adblock = "sources" in cfg and "rules" not in cfg

        if is_adblock:
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
    errors: List[str] = []
    idx_map = {g["cfg_key"]: g["idx"] for g in groups}
    known_formats = _get_formats()

    for g in groups:
        key, gidx = g["cfg_key"], g["idx"]

        if g["kind"] == "adblock":
            if not isinstance(g.get("sources"), list) or not g["sources"]:
                errors.append(f"Adblock 聚合组 '{key}' sources 不能为空")
            else:
                for u in g["sources"]:
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
                elif p["kind"] == "local" and not Path(p["path"]).is_file():
                    errors.append(f"规则组 '{key}' rules[{ri}] 本地文件不存在：{p['path']}")
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
        elif rtype == "discard_parent":
            cur = _discard_parent(cur, rd, log_file)
            log(f"  |    -> 父域名反向丢弃 {before-len(cur):,}（剩余 {len(cur):,}）", log_file=log_file)
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


# ─────────────────────────── Adblock 规则聚合（元素隐藏 + 网络规则） ───────────
#
# 分类逻辑（cosmetic / HTML 过滤 / 网络规则 判定，以及"纯域名封锁"规则识别）
# 已迁移至 Rust `classify_adblock` 子命令（见 `_rust_classify_adblock`），
# 覆盖 uBlock Origin 完整语法标记：##、#@#、#?#、#$#、#%#、#@?#、#@$#、#@%#
# （cosmetic/procedural/scriptlet）以及 $$、$@$（HTML 过滤，uBO/AdGuard）。
# 这里只保留跨多个源合并后的去重（简单 O(n) 集合操作，放在 Python 侧即可，
# 没必要为此再起一次子进程）。


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
    log(f"处理 Adblock 聚合组：{title or key} ({key})", log_file=log_file)
    log("=" * 70, log_file=log_file)

    texts = _download_raw_texts(urls, log_file)

    generic_css: List[str] = []
    domain_css:  List[str] = []
    url_rules:   List[str] = []
    dropped_total = 0

    for url in urls:
        text = texts.get(url, "")
        if not text:
            continue
        try:
            g, d, u, dropped = _rust_classify_adblock(text, exclude_pure, log_file)
        except Exception as e:
            log(f"  FAIL 分类失败 {url}：{e}", LogLevel.WARNING, log_file)
            continue
        generic_css.extend(g)
        domain_css.extend(d)
        url_rules.extend(u)
        if exclude_pure:
            dropped_total += dropped
        log(
            f"  |  {url}：元素 {len(g)+len(d):,}（通用 {len(g):,}/域名限定 {len(d):,}），"
            f"网络 {len(u):,}，丢弃纯域名 {dropped if exclude_pure else 0:,}",
            log_file=log_file,
        )

    generic_css = _dedup_keep_order(generic_css)
    domain_css  = _dedup_keep_order(domain_css)
    url_rules   = _dedup_keep_order(url_rules)

    gdir = out_root / key
    gdir.mkdir(parents=True, exist_ok=True)
    fname = "adblock.txt"
    total = len(generic_css) + len(domain_css) + len(url_rules)

    with (gdir / fname).open("w", encoding="utf-8") as f:
        f.write("[Adblock Plus 2.0]\n")
        if title:
            f.write(f"! Title: {title}\n")
        if desc:
            f.write(f"! Description: {desc}\n")
        f.write("! Homepage: https://github.com/cjchxgxhc/domain-filter\n")
        f.write("! Expires: 7 days (update frequency)\n")
        f.write(
            f"! Element hiding rules: {len(generic_css)+len(domain_css):,} "
            f"(generic: {len(generic_css):,}, domain-specific: {len(domain_css):,})\n"
        )
        f.write(f"! URL / network rules: {len(url_rules):,}\n")
        if exclude_pure:
            f.write(f"! Pure domain-block rules excluded: {dropped_total:,}\n")
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
        f.write(
            "! URL / network rules (pure domain-block rules excluded)\n"
            if exclude_pure else "! URL / network rules\n"
        )
        f.write("!" + "-" * 76 + "!\n")
        for x in url_rules:
            f.write(x + "\n")

    log(f"  OK {fname}（{total:,} 条，丢弃纯域名 {dropped_total:,}）", log_file=log_file)
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
    raw_base = global_cfg.get("raw_base",  "https://raw.githubusercontent.com/cjchxgxhc/domain-filter/refs/heads/rule/data/rules")
    ghproxy  = global_cfg.get("ghproxy",   "https://ghproxy.net/")

    out_root.mkdir(parents=True, exist_ok=True)
    log_file = out_root / "log.txt"
    if log_file.exists():
        log_file.unlink()

    log("开始执行", log_file=log_file)

    if not _validate(groups, named, log_file):
        sys.exit(1)

    idx_map = {g["cfg_key"]: g["idx"] for g in groups}

    src_cfgs:   Dict[str, Dict] = {}
    local_cfgs: Dict[str, Dict] = {}

    for sname, cfg in named.items():
        if cfg["kind"] == "local":
            local_cfgs.setdefault(_LOCAL_PREFIX + cfg["path"], cfg)
        else:
            src_cfgs.setdefault(cfg["url"], cfg)

    for g in groups:
        if g["kind"] != "domain":
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

    # 下载 + 提取融合为一步（按源并发，不必等全部下载完才开始提取），不做跨次运行缓存
    dl: Dict[str, Set[str]] = {}
    try:
        dl.update(_download_and_extract(src_cfgs, log_file))
        dl.update(_read_and_extract_local(local_cfgs, log_file))
    except Exception as e:
        log(f"下载/提取失败：{e}", LogLevel.ERROR, log_file)
        log(traceback.format_exc(), LogLevel.ERROR, log_file)
        sys.exit(1)

    for sname, cfg in named.items():
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
            if g["kind"] == "adblock":
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
