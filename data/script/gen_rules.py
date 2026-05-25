#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Domain Filter - 规则格式生成脚本
https://github.com/cjchxgxhc/domain-filter

用法：
    gen_rules.py <output_dir> <title> <description> <timezone> <format1> [format2 ...]

stdin 格式：
    <simple 域名，换行分隔>
    ---
    <deduped 域名，换行分隔>

支持格式：
    domain         domain.txt           纯域名列表（simple）
    hosts          hosts.txt            127.0.0.1 domain（simple）
    hostsipv6      hosts_ipv6.txt       127.0.0.1 + ::1 domain（simple）
    smartdns       smartdns.txt         server=/domain/#（simple）
    adblock        adblock.txt          ||domain^（deduped）
    clash          clash.yaml           +.domain（deduped）
    singbox        singbox.json         domain_suffix（deduped）
    wildcard       wildcard.txt         *.domain（deduped）
    loon           loon.list            DOMAIN-SUFFIX,domain（deduped）
    surge          surge.list           DOMAIN-SUFFIX,domain（deduped）
    quantumultx    quantumultx.list     host-suffix,domain,reject（deduped）
    shadowrocket   shadowrocket.list    DOMAIN-SUFFIX,domain,REJECT-DROP（deduped）
"""

import datetime
import json
import sys
from pathlib import Path
from zoneinfo import ZoneInfo


_SIMPLE_FORMATS  = frozenset({"domain", "hosts", "hostsipv6", "smartdns"})

_DEDUPED_FORMATS = frozenset({
    "adblock",
    "clash",
    "singbox",
    "wildcard",
    "loon",
    "surge",
    "quantumultx",
    "shadowrocket",
})

ALL_FORMATS = _SIMPLE_FORMATS | _DEDUPED_FORMATS


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


def write_format(
    fmt: str,
    output_dir: Path,
    sorted_simple: list,
    sorted_deduped: list,
    title: str,
    description: str,
    now_str: str,
) -> tuple[str, int]:

    def hash_hdr(count: int) -> str:
        return build_header(count, title, description, now_str, "#")

    def bang_hdr(count: int) -> str:
        return build_header(count, title, description, now_str, "!")

    # ───────── simple formats ─────────
    if fmt == "domain":
        count = len(sorted_simple)
        path = output_dir / "domain.txt"
        with path.open("w", encoding="utf-8") as f:
            f.write("\n".join(sorted_simple) + "\n")
        return path.name, count

    if fmt == "hosts":
        count = len(sorted_simple)
        path = output_dir / "hosts.txt"
        with path.open("w", encoding="utf-8") as f:
            f.write(hash_hdr(count))
            for domain in sorted_simple:
                f.write(f"127.0.0.1 {domain}\n")
        return path.name, count

    if fmt == "hostsipv6":
        count = len(sorted_simple)
        path = output_dir / "hosts_ipv6.txt"
        with path.open("w", encoding="utf-8") as f:
            f.write(hash_hdr(count))
            for domain in sorted_simple:
                f.write(f"127.0.0.1 {domain}\n")
                f.write(f"::1 {domain}\n")
        return path.name, count

    if fmt == "smartdns":
        count = len(sorted_simple)
        path = output_dir / "smartdns.txt"
        with path.open("w", encoding="utf-8") as f:
            for domain in sorted_simple:
                f.write(f"server=/{domain}/#\n")
        return path.name, count

    # ───────── dedup formats ─────────
    if fmt == "adblock":
        count = len(sorted_deduped)
        path = output_dir / "adblock.txt"
        with path.open("w", encoding="utf-8") as f:
            f.write("[Adblock Plus 2.0]\n")
            f.write(bang_hdr(count))
            for domain in sorted_deduped:
                f.write(f"||{domain}^\n")
        return path.name, count

    if fmt == "clash":
        count = len(sorted_deduped)
        path = output_dir / "clash.yaml"
        with path.open("w", encoding="utf-8") as f:
            f.write("payload:\n")
            for domain in sorted_deduped:
                f.write(f"  - +.{domain}\n")
        return path.name, count

    if fmt == "singbox":
        count = len(sorted_deduped)
        path = output_dir / "singbox.json"
        with path.open("w", encoding="utf-8") as f:
            json.dump(
                {"version": 3, "rules": [{"domain_suffix": sorted_deduped}]},
                f,
                indent=2,
                ensure_ascii=False,
            )
        return path.name, count

    if fmt == "wildcard":
        count = len(sorted_deduped)
        path = output_dir / "wildcard.txt"
        with path.open("w", encoding="utf-8") as f:
            for domain in sorted_deduped:
                f.write(f"*.{domain}\n")
        return path.name, count

    if fmt == "loon":
        count = len(sorted_deduped)
        path = output_dir / "loon.list"
        with path.open("w", encoding="utf-8") as f:
            for domain in sorted_deduped:
                f.write(f"DOMAIN-SUFFIX,{domain}\n")
        return path.name, count

    if fmt == "surge":
        count = len(sorted_deduped)
        path = output_dir / "surge.list"
        with path.open("w", encoding="utf-8") as f:
            for domain in sorted_deduped:
                f.write(f"DOMAIN-SUFFIX,{domain}\n")
        return path.name, count

    if fmt == "quantumultx":
        count = len(sorted_deduped)
        path = output_dir / "quantumultx.list"
        with path.open("w", encoding="utf-8") as f:
            for domain in sorted_deduped:
                f.write(f"host-suffix,{domain},reject\n")
        return path.name, count

    if fmt == "shadowrocket":
        count = len(sorted_deduped)
        path = output_dir / "shadowrocket.list"
        with path.open("w", encoding="utf-8") as f:
            f.write("[Rule]\n")
            for domain in sorted_deduped:
                f.write(f"DOMAIN-SUFFIX,{domain},REJECT-DROP\n")
        return path.name, count

    raise ValueError(f"未知格式：{fmt}")


def main() -> None:
    if len(sys.argv) < 6:
        print(
            "用法：gen_rules.py <output_dir> <title> <description> <timezone> <format1> [format2 ...]",
            file=sys.stderr,
        )
        sys.exit(1)

    output_dir = Path(sys.argv[1])
    title = sys.argv[2]
    description = sys.argv[3]
    timezone = sys.argv[4]
    formats = sys.argv[5:]

    unknown = [f for f in formats if f not in ALL_FORMATS]
    if unknown:
        print(f"错误：未知格式 {unknown}，支持：{sorted(ALL_FORMATS)}", file=sys.stderr)
        sys.exit(1)

    raw = sys.stdin.read()
    if "---" in raw:
        simple_part, deduped_part = raw.split("---", 1)
    else:
        simple_part = raw
        deduped_part = ""

    simple_domains = sorted(filter(None, (l.strip() for l in simple_part.splitlines())))
    deduped_domains = sorted(filter(None, (l.strip() for l in deduped_part.splitlines())))

    output_dir.mkdir(parents=True, exist_ok=True)

    now = datetime.datetime.now(ZoneInfo(timezone))
    now_str = now.strftime("%Y-%m-%d %H:%M:%S %Z")

    counts = {}
    for fmt in formats:
        fname, count = write_format(
            fmt,
            output_dir,
            simple_domains,
            deduped_domains,
            title,
            description,
            now_str,
        )
        counts[fmt] = count
        dedup_note = "（子域去重）" if fmt in _DEDUPED_FORMATS else ""
        print(f"  ✓ {fname}（{count:,} 条{dedup_note}）")

    print(json.dumps(counts))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
    except Exception as e:
        print(f"错误：{e}", file=sys.stderr)
        sys.exit(1)
