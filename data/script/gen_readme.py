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
from typing import Dict, List, Tuple

import yaml
from zoneinfo import ZoneInfo


# ─────────────────────────── 常量 ────────────────────────────────────────────

_HISTORY_MAX   = 3
_HISTORY_PATH  = Path("data/rules/log_history.json")
_STATS_PATH    = Path("data/rules/stats.json")
_CONFIG_PATH   = Path("data/script/config.yaml")
_README_ROOT   = Path("README.md")
_RULES_ROOT    = Path("data/rules")

_REGEX_RAW_GH = re.compile(
    r"^https://raw\.githubusercontent\.com/"
    r"(?P<user>[^/]+)/(?P<repo>[^/]+)/"
    r"(?:refs/heads/)?"
    r"(?P<branch>[^/]+)/"
    r"(?P<path>.+)$"
)

_FMT_LABELS = {
    "domain":  "Domain",
    "adblock": "AdBlock",
    "hosts":   "Hosts",
    "clash":   "Clash / Mrs",
    "singbox": "Sing-box / Srs",
}

# 每种格式对应的输出文件（fname, 是否为二进制转换产物）
_FMT_FILES: Dict[str, List[Tuple[str, bool]]] = {
    "domain":  [("domain.txt",    False)],
    "adblock": [("adblock.txt",   False)],
    "hosts":   [("hosts.txt",     False)],
    "clash":   [("clash.yaml",    False), ("clash.mrs",     True)],
    "singbox": [("singbox.json",  False), ("singbox.srs",   True)],
}


# ─────────────────────────── URL 加速转换 ────────────────────────────────────

def raw_to_accelerated(raw_url: str, ghproxy: str) -> Dict[str, str]:
    proxy_prefix = ghproxy.rstrip("/") + "/"
    m = _REGEX_RAW_GH.match(raw_url)
    if m:
        user     = m.group("user")
        repo     = m.group("repo")
        branch   = m.group("branch")
        path     = m.group("path")
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


# ─────────────────────────── 辅助：构建文件的 raw URL ────────────────────────

def make_raw_url(raw_base: str, cfg_key: str, fname: str) -> str:
    return f"{raw_base.rstrip('/')}/{cfg_key}/{fname}"


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

    lines: List[str] = []
    lines.append(f"# {title}")
    lines.append("")
    if description:
        lines.append(f"> {description}")
        lines.append("")

    lines.append(f"规则总数：**{final_count:,}**")
    lines.append(f"最后更新：{timestamp}（北京时间）")
    lines.append("")

    # 订阅链接表格
    lines.append("## 订阅链接")
    lines.append("")
    lines.append("| 文件 | 规则数 | 原始链接 | 加速链接1 (jsDelivr CDN) | 加速链接2 (jsDelivr Fastly) | 加速链接3 (ghproxy) |")
    lines.append("| --- | --- | --- | --- | --- | --- |")

    for fmt, file_list in _FMT_FILES.items():
        if fmt not in fmt_counts:
            continue
        count = fmt_counts[fmt]
        for fname, is_binary in file_list:
            fpath = group_dir / fname
            if not fpath.exists():
                continue
            raw_url = make_raw_url(raw_base, cfg_key, fname)
            accel   = raw_to_accelerated(raw_url, ghproxy)
            cdn     = f"[加速1]({accel['jsdelivr_cdn']})"    if accel["jsdelivr_cdn"]    else "-"
            fastly  = f"[加速2]({accel['jsdelivr_fastly']})" if accel["jsdelivr_fastly"] else "-"
            gp      = f"[加速3]({accel['ghproxy']})"
            label   = _FMT_LABELS.get(fmt, fmt)
            if is_binary:
                label = fname.rsplit(".", 1)[-1].upper()
                count_cell = "-"
            else:
                count_cell = f"{count:,}"
            lines.append(
                f"| `{fname}` | {count_cell} "
                f"| [原始]({raw_url}) "
                f"| {cdn} "
                f"| {fastly} "
                f"| {gp} |"
            )

    lines.append("")
    lines.append(f"[← 返回主页](../../../README.md)")
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
    lines.append(f"![Last Update](https://img.shields.io/badge/Last_Update-{date_badge}-green?style=flat-square)")
    lines.append("")
    lines.append("## 📋 规则订阅")
    lines.append("")

    # 筛选启用的规则组，按 idx 排序
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

        # 构建格式列表字符串
        formats = []
        for fmt in fmt_counts.keys():
            if fmt in _FMT_LABELS:
                formats.append(_FMT_LABELS[fmt])
        format_str = ", ".join(formats) if formats else "-"

        # 相对路径
        group_readme_rel = f"data/rules/{cfg_key}/README.md"

        # 生成列表项（一行包含所有信息）
        item_line = (
            f"- **{title}** · `{format_str}` · {description} · "
            f"[查看详情]({group_readme_rel})"
        )
        lines.append(item_line)

    lines.append("")
    lines.append(f"*最后更新：{timestamp}（北京时间）*")
    lines.append("")

    with _README_ROOT.open("w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    print(f"✓ README.md 已生成", flush=True)


# ─────────────────────────── 主入口 ──────────────────────────────────────────

def main() -> None:
    print("=" * 80, flush=True)
    print("gen_readme.py - README 生成工具".center(80), flush=True)
    print("=" * 80, flush=True)
    print(flush=True)

    # 读取 stats.json
    if not _STATS_PATH.is_file():
        print(f"[ERROR] 找不到 {_STATS_PATH}，请先运行 filter.py", flush=True)
        sys.exit(1)
    with _STATS_PATH.open(encoding="utf-8") as f:
        all_stats: Dict = json.load(f)

    # 读取 config.yaml（只取 global 节）
    if not _CONFIG_PATH.is_file():
        print(f"[ERROR] 找不到 {_CONFIG_PATH}", flush=True)
        sys.exit(1)
    with _CONFIG_PATH.open(encoding="utf-8") as f:
        cfg_data = yaml.safe_load(f) or {}
    global_cfg = cfg_data.get("global", {}) or {}

    repo_url = global_cfg.get("repo_url", "https://github.com/cjchxgxhc/domain-filter")
    raw_base = global_cfg.get("raw_base",
        "https://raw.githubusercontent.com/cjchxgxhc/domain-filter/refs/heads/main/data/rules")
    timezone = global_cfg.get("timezone", "Asia/Shanghai")

    now_cst = datetime.datetime.now(ZoneInfo(timezone))

    # 追加历史
    append_history(all_stats, timezone)

    # 生成各规则组子目录 README
    print("生成子目录 README...", flush=True)
    for cfg_key, data in all_stats.items():
        if not data.get("output_enabled") or not data.get("title"):
            continue
        group_dir = _RULES_ROOT / cfg_key
        if not group_dir.is_dir():
            continue
        try:
            generate_group_readme(
                cfg_key, data, raw_base,
                global_cfg.get("ghproxy", "https://ghproxy.net/"),
                group_dir, now_cst
            )
        except Exception as e:
            print(f"  [WARNING] 子目录 README 生成失败 [{cfg_key}]：{e}", flush=True)

    # 生成主 README
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
