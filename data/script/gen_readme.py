#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
gen_readme.py - README 生成脚本
https://github.com/cjchxgxhc/domain-filter

读取 filter.py 输出的 stats.json 和 config.yaml，
生成：
  - README.md（仓库根目录，简化列表：名称、格式、描述、仓库路径）
  - data/rules/{key}/README.md（各规则组子目录，包含加速链接、规则数量）
  - data/rules/log_history.json（历史统计追加）
"""

import datetime
import json
import re
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import yaml
from zoneinfo import ZoneInfo


# ─────────────────────────── 常量 ────────────────────────────────────────────

_HISTORY_MAX  = 3
_HISTORY_PATH = Path("data/rules/log_history.json")
_STATS_PATH   = Path("data/rules/stats.json")
_CONFIG_PATH  = Path("data/script/config.yaml")
_README_ROOT  = Path("README.md")
_RULES_ROOT   = Path("data/rules")

_REGEX_RAW_GH = re.compile(
    r"^https://raw\.githubusercontent\.com/"
    r"(?P<user>[^/]+)/(?P<repo>[^/]+)/"
    r"(?:refs/heads/)?"
    r"(?P<branch>[^/]+)/"
    r"(?P<path>.+)$"
)

# 格式名 → 显示标签（未在此表中的格式 fallback 到格式名首字母大写）
_FMT_LABELS: Dict[str, str] = {
    "domain":    "Domain",
    "hosts":     "Hosts",
    "hostsipv6": "Hosts (IPv4+IPv6)",
    "smartdns":  "SmartDNS",
    "adblock":   "AdBlock",
    "clash":     "Clash / Mrs",
    "singbox":   "Sing-box / Srs",
    "wildcard":  "Wildcard",
}

# 格式名 → gen_rules.py 生成的主文件名（用于 README 中计数列显示）
# 扫目录时会自动发现同名的 .mrs/.srs 转换产物，无需在此维护
_FMT_PRIMARY_FILE: Dict[str, str] = {
    "domain":    "domain.txt",
    "hosts":     "hosts.txt",
    "hostsipv6": "hosts_ipv6.txt",
    "smartdns":  "smartdns.txt",
    "adblock":   "adblock.txt",
    "clash":     "clash.yaml",
    "singbox":   "singbox.json",
    "wildcard":  "wildcard.txt",
}

# 转换产物后缀（clash.yaml → clash.mrs，singbox.json → singbox.srs）
# 仅用于在表格中附加行，计数显示为 "-"
_CONVERTED_SUFFIXES: Dict[str, str] = {
    "clash":   ".mrs",
    "singbox": ".srs",
}


# ─────────────────────────── URL 加速转换 ────────────────────────────────────

def raw_to_accelerated(raw_url: str, ghproxy: str) -> Dict[str, str]:
    proxy_prefix = ghproxy.rstrip("/") + "/"
    m = _REGEX_RAW_GH.match(raw_url)
    if m:
        user   = m.group("user")
        repo   = m.group("repo")
        branch = m.group("branch")
        path   = m.group("path")
        jsd    = f"gh/{user}/{repo}@{branch}/{path}"
        return {
            "jsdelivr_cdn":    f"https://cdn.jsdelivr.net/{jsd}",
            "jsdelivr_fastly": f"https://fastly.jsdelivr.net/{jsd}",
            "ghproxy":         f"{proxy_prefix}{raw_url}",
        }
    return {
        "jsdelivr_cdn":    "",
        "jsdelivr_fastly": "",
        "ghproxy":         f"{proxy_prefix}{raw_url}",
    }


def _accel_cells(raw_url: str, ghproxy: str) -> Tuple[str, str, str]:
    accel  = raw_to_accelerated(raw_url, ghproxy)
    cdn    = f"[加速1]({accel['jsdelivr_cdn']})"    if accel["jsdelivr_cdn"]    else "-"
    fastly = f"[加速2]({accel['jsdelivr_fastly']})" if accel["jsdelivr_fastly"] else "-"
    gp     = f"[加速3]({accel['ghproxy']})"
    return cdn, fastly, gp


# ─────────────────────────── 历史统计 ────────────────────────────────────────

def load_history() -> List[Dict]:
    try:
        if _HISTORY_PATH.is_file():
            with _HISTORY_PATH.open(encoding="utf-8") as f:
                return json.load(f)
    except Exception:
        pass
    return []


def save_history(history: List[Dict]) -> None:
    try:
        _HISTORY_PATH.parent.mkdir(parents=True, exist_ok=True)
        with _HISTORY_PATH.open("w", encoding="utf-8") as f:
            json.dump(history, f, ensure_ascii=False, indent=2)
    except Exception as e:
        print(f"[WARNING] 历史统计写出失败：{e}", flush=True)


def append_history(all_stats: Dict, timezone: str) -> List[Dict]:
    now_str = datetime.datetime.now(ZoneInfo(timezone)).strftime("%Y-%m-%d %H:%M:%S %Z")
    entry = {
        "time":   now_str,
        "counts": {
            key: data.get("final_count", 0)
            for key, data in all_stats.items()
            if data.get("output_enabled")
        },
    }
    history = load_history()
    history.append(entry)
    history = history[-_HISTORY_MAX:]
    save_history(history)
    return history


# ─────────────────────────── 文件行生成（动态扫目录）────────────────────────

def _build_file_rows(
    cfg_key: str,
    fmt_counts: Dict[str, int],
    group_dir: Path,
    raw_base: str,
    ghproxy: str,
) -> List[Tuple[str, str, str, str, str, str]]:
    """
    返回每个文件一行的元组列表：
        (fname, count_cell, raw_link, cdn_link, fastly_link, gp_link)

    策略：
      1. 按 fmt_counts 中的格式顺序遍历
      2. 对每个格式，先输出主文件（若存在）
      3. 再扫目录，找同前缀的转换产物（.mrs / .srs）附加输出
      4. 目录中存在但不在 fmt_counts 里的文件也补充输出（兜底）
    """
    rows: List[Tuple[str, str, str, str, str, str]] = []
    emitted: set = set()

    def make_row(fname: str, count_cell: str) -> Optional[Tuple]:
        fpath = group_dir / fname
        if not fpath.exists():
            return None
        raw_url = f"{raw_base.rstrip('/')}/{cfg_key}/{fname}"
        cdn, fastly, gp = _accel_cells(raw_url, ghproxy)
        return (fname, count_cell, f"[原始]({raw_url})", cdn, fastly, gp)

    # 按 fmt_counts 顺序输出已知格式
    for fmt, count in fmt_counts.items():
        primary = _FMT_PRIMARY_FILE.get(fmt)
        if primary:
            row = make_row(primary, f"{count:,}")
            if row:
                rows.append(row)
                emitted.add(primary)

        # 转换产物（.mrs / .srs）
        conv_suffix = _CONVERTED_SUFFIXES.get(fmt)
        if conv_suffix and primary:
            stem      = primary.rsplit(".", 1)[0]
            conv_name = stem + conv_suffix
            row = make_row(conv_name, "-")
            if row:
                rows.append(row)
                emitted.add(conv_name)

    # 兜底：目录中存在但尚未输出的文件（可能是未来新增的格式或手动放置的文件）
    for fpath in sorted(group_dir.iterdir()):
        if fpath.is_file() and fpath.name not in emitted and fpath.suffix != ".md":
            row = make_row(fpath.name, "-")
            if row:
                rows.append(row)
                emitted.add(fpath.name)

    return rows


# ─────────────────────────── 各规则组子目录 README ───────────────────────────

def generate_group_readme(
    cfg_key: str,
    data: Dict,
    raw_base: str,
    ghproxy: str,
    group_dir: Path,
    now_cst: datetime.datetime,
) -> None:
    title       = data.get("title", cfg_key)
    description = data.get("description", "")
    fmt_counts  = data.get("format_counts", {})
    final_count = data.get("final_count", 0)
    timestamp   = now_cst.strftime("%Y-%m-%d %H:%M:%S")

    rows = _build_file_rows(cfg_key, fmt_counts, group_dir, raw_base, ghproxy)

    lines: List[str] = []
    lines.append(f"# {title}")
    lines.append("")
    if description:
        lines.append(f"> {description}")
        lines.append("")

    lines.append(f"规则总数：**{final_count:,}**")
    lines.append(f"最后更新：{timestamp}（北京时间）")
    lines.append("")

    lines.append("## 订阅链接")
    lines.append("")
    lines.append("| 文件 | 规则数 | 原始链接 | 加速链接1 (jsDelivr CDN) | 加速链接2 (jsDelivr Fastly) | 加速链接3 (ghproxy) |")
    lines.append("| --- | --- | --- | --- | --- | --- |")

    for fname, count_cell, raw_link, cdn, fastly, gp in rows:
        lines.append(f"| `{fname}` | {count_cell} | {raw_link} | {cdn} | {fastly} | {gp} |")

    lines.append("")
    lines.append("")

    readme_path = group_dir / "README.md"
    with readme_path.open("w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    print(f"  ✓ 子目录 README：{readme_path}", flush=True)


# ─────────────────────────── 主 README（列表格式）────────────────────────────

def generate_main_readme(
    all_stats: Dict,
    repo_url: str,
    now_cst: datetime.datetime,
) -> None:
    timestamp  = now_cst.strftime("%Y-%m-%d %H:%M:%S")
    date_badge = now_cst.strftime("%Y--%m--%d_%H:%M:%S")

    lines: List[str] = []
    lines.append("# 🛡️ Domain Filter")
    lines.append("")
    lines.append(
        f"![Last Update](https://img.shields.io/badge/Last_Update-{date_badge}-green?style=flat-square)"
    )
    lines.append("")
    lines.append("## 📋 规则订阅")
    lines.append("")

    visible = [
        (key, data)
        for key, data in all_stats.items()
        if data.get("output_enabled") and data.get("title")
    ]
    visible.sort(key=lambda x: x[1].get("idx", 0))

    for cfg_key, data in visible:
        title       = data["title"]
        description = data.get("description", "-")
        fmt_counts  = data.get("format_counts", {})

        # 格式标签：优先用 _FMT_LABELS，未知格式 fallback 到首字母大写
        fmt_labels = [
            _FMT_LABELS.get(fmt, fmt.capitalize())
            for fmt in fmt_counts
        ]
        format_str = ", ".join(fmt_labels) if fmt_labels else "-"

        group_readme_rel = f"data/rules/{cfg_key}"
        lines.append(
            f"- **{title}** · `{format_str}` · {description} · "
            f"[查看详情]({group_readme_rel})"
        )

    lines.append("")
    lines.append(f"*最后更新：{timestamp}（北京时间）*")
    lines.append("")

    with _README_ROOT.open("w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    print("✓ README.md 已生成", flush=True)


# ─────────────────────────── 主入口 ──────────────────────────────────────────

def main() -> None:
    print("=" * 80, flush=True)
    print("gen_readme.py - README 生成工具".center(80), flush=True)
    print("=" * 80, flush=True)
    print(flush=True)

    if not _STATS_PATH.is_file():
        print(f"[ERROR] 找不到 {_STATS_PATH}，请先运行 filter.py", flush=True)
        sys.exit(1)
    with _STATS_PATH.open(encoding="utf-8") as f:
        all_stats: Dict = json.load(f)

    if not _CONFIG_PATH.is_file():
        print(f"[ERROR] 找不到 {_CONFIG_PATH}", flush=True)
        sys.exit(1)
    with _CONFIG_PATH.open(encoding="utf-8") as f:
        cfg_data = yaml.safe_load(f) or {}
    global_cfg = cfg_data.get("global", {}) or {}

    repo_url = global_cfg.get("repo_url",  "https://github.com/cjchxgxhc/domain-filter")
    raw_base = global_cfg.get("raw_base",
        "https://raw.githubusercontent.com/cjchxgxhc/domain-filter/refs/heads/main/data/rules")
    ghproxy  = global_cfg.get("ghproxy",   "https://ghproxy.net/")
    timezone = global_cfg.get("timezone",  "Asia/Shanghai")

    now_cst = datetime.datetime.now(ZoneInfo(timezone))

    append_history(all_stats, timezone)

    print("生成子目录 README...", flush=True)
    for cfg_key, data in all_stats.items():
        if not data.get("output_enabled") or not data.get("title"):
            continue
        group_dir = _RULES_ROOT / cfg_key
        if not group_dir.is_dir():
            continue
        try:
            generate_group_readme(
                cfg_key, data, raw_base, ghproxy, group_dir, now_cst
            )
        except Exception as e:
            print(f"  [WARNING] 子目录 README 生成失败 [{cfg_key}]：{e}", flush=True)

    print("生成主 README...", flush=True)
    try:
        generate_main_readme(all_stats, repo_url, now_cst)
    except Exception as e:
        print(f"[ERROR] 主 README 生成失败：{e}", flush=True)
        sys.exit(1)

    print(flush=True)
    print("✓ 完成", flush=True)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n用户中断（Ctrl+C）")
        sys.exit(130)
    except Exception as e:
        print(f"[ERROR] 程序异常退出：{e}", flush=True)
        import traceback
        traceback.print_exc()
        sys.exit(1)
