#!/usr/bin/env python3
import re
import sys
import time
import datetime
from pathlib import Path
from typing import Set, List, Dict, Optional
import requests
import yaml
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# ── 配置 ────────────────────────────────────────────────────────────────
CHUNK_SIZE         = 40_000
FILTER_CHUNK_SIZE  = 25_000
MAX_DOMAIN_LEN     = 253
DOWNLOAD_WORKERS   = 10
FILTER_WORKERS     = 8
CONNECT_TIMEOUT    = 4
READ_TIMEOUT       = 12
RETRY_COUNT        = 3
RETRY_DELAY        = 1.5
USER_AGENT         = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"

DOMAIN_RE     = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$", re.I)
ADBLOCK_BLACK = re.compile(r"^\|{1,2}([a-z0-9-\.]+)\^(?:\$(all|important))?$", re.I)
ADBLOCK_WHITE = re.compile(r"^@@\|{1,2}([a-z0-9-\.]+)\^(?:\$(all|important))?$", re.I)
RULE_RE       = re.compile(r"^(?:DOMAIN-SUFFIX|HOST-SUFFIX|host-suffix|DOMAIN|HOST|host)[,\s]+(.+)$", re.I)
PREFIX_STRIP  = re.compile(r"^(0\.0\.0\.0\s+|127\.0\.0\.1\s+|local=|\|\||\*\.|\+\.|@@\|\|)")
SUFFIX_STRIP  = re.compile(r"[\^#].*$")

class TrieNode:
    def __init__(self):
        self.children = {}
        self.is_end = False

def build_trie(domains: Set[str]) -> TrieNode:
    root = TrieNode()
    for d in domains:
        parts = d.lower().split('.')[::-1]
        node = root
        for p in parts:
            node = node.children.setdefault(p, TrieNode())
        node.is_end = True
    return root

def is_excluded(domain: str, root: TrieNode) -> bool:
    if not domain: return False
    parts = domain.lower().split('.')[::-1]
    node = root
    for p in parts:
        if p not in node.children:
            return False
        node = node.children[p]
        if node.is_end:
            return True
    return False

def log(msg: str, err=False):
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{ts}] [{'ERROR' if err else 'INFO'}] {msg}", flush=True)

def is_valid_domain(d: str) -> bool:
    d = d.strip().lower()
    return bool(d and len(d) <= MAX_DOMAIN_LEN and '.' in d and DOMAIN_RE.fullmatch(d))

def clean_domain(d: str) -> str:
    d = d.strip().lower()
    if '##' in d: return ''
    d = PREFIX_STRIP.sub('', d)
    d = SUFFIX_STRIP.sub('', d)
    return d.strip('.')

def extract_domain(line: str, whitelist: bool = False) -> Optional[str]:
    line = line.strip()
    if not line or line[0] in '#!/': return None

    pat = ADBLOCK_WHITE if whitelist else ADBLOCK_BLACK
    m = pat.match(line)
    if m:
        dom = m.group(1).strip().lower()
        return dom if is_valid_domain(dom) else None

    m = RULE_RE.match(line)
    if m:
        dom = clean_domain(m.group(1).split(',')[0])
        return dom if is_valid_domain(dom) else None

    if line.startswith(('*.', '+.')):
        dom = line[2:].strip().lower()
        return dom if is_valid_domain(dom) else None

    dom = clean_domain(line)
    return dom if is_valid_domain(dom) else None

def parallel_extract(lines: List[str], is_white: bool = False) -> Set[str]:
    if not lines: return set()
    chunks = [lines[i:i+CHUNK_SIZE] for i in range(0, len(lines), CHUNK_SIZE)]
    with ThreadPoolExecutor(max_workers=6) as ex:
        futures = [ex.submit(lambda c: {extract_domain(ln, is_white) for ln in c if extract_domain(ln, is_white)}, c) for c in chunks]
        return set().union(*(f.result() for f in as_completed(futures)))

def remove_subdomains(domains: Set[str]) -> Set[str]:
    """保留最顶层域名（最宽松匹配）"""
    if not domains: return set()

    domains = {d.lower().strip() for d in domains if is_valid_domain(d)}
    if not domains: return set()

    # 按域名长度从短到长排序
    sorted_d = sorted(domains, key=len)
    keep = set()
    
    for domain in sorted_d:
        # 检查是否已被更短（更顶层）的域名覆盖
        is_covered = False
        parts = domain.split('.')
        
        # 检查是否是已保留域名的子域名
        for i in range(1, len(parts)):
            parent = '.'.join(parts[i:])
            if parent in keep:
                is_covered = True
                break
        
        if not is_covered:
            keep.add(domain)
    
    log(f"去子域（最宽松）: {len(domains):,} → {len(keep):,}")
    return keep

def filter_whitelist(black: Set[str], white: Set[str]) -> Set[str]:
    """并行化过滤：黑名单分块 + Trie 判断"""
    if not white:
        return black

    white_clean = {d.lower().strip() for d in white if is_valid_domain(d)}
    if not white_clean:
        return black

    trie = build_trie(white_clean)
    black_list = list(black)
    
    def check_chunk(chunk: List[str]) -> Set[str]:
        filtered = set()
        for domain in chunk:
            # 检查域名或其任意父域名是否在白名单中
            is_whitelisted = False
            parts = domain.lower().split('.')
            
            # 构建所有可能的父域名后缀
            for i in range(len(parts)):
                suffix = '.'.join(parts[i:])
                if is_excluded(suffix, trie):
                    is_whitelisted = True
                    break
            
            if not is_whitelisted:
                filtered.add(domain)
        
        return filtered
    
    chunks = [black_list[i:i+FILTER_CHUNK_SIZE] for i in range(0, len(black_list), FILTER_CHUNK_SIZE)]

    with ThreadPoolExecutor(max_workers=FILTER_WORKERS) as ex:
        futures = [ex.submit(check_chunk, c) for c in chunks]
        filtered = set().union(*(f.result() for f in as_completed(futures)))

    log(f"白名单过滤（并行）: {len(black):,} → {len(filtered):,}")
    return filtered

def get_session() -> requests.Session:
    s = requests.Session()
    s.headers.update({"User-Agent": USER_AGENT, "Accept": "text/plain,text/html"})
    retry = Retry(total=3, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504])
    adapter = HTTPAdapter(max_retries=retry, pool_connections=32, pool_maxsize=32)
    s.mount("http://", adapter)
    s.mount("https://", adapter)
    return s

def download_url(url: str) -> tuple[str, List[str]]:
    if url.startswith("file://"):
        log(f"禁用 file://: {url}", err=True)
        return url, []
    for attempt in range(1, RETRY_COUNT + 1):
        try:
            r = get_session().get(url, timeout=(CONNECT_TIMEOUT, READ_TIMEOUT), allow_redirects=True)
            r.raise_for_status()
            txt = r.text.strip()
            if not txt: return url, []
            return url, [ln.strip() for ln in txt.splitlines() if ln.strip()]
        except Exception as e:
            if attempt == RETRY_COUNT:
                log(f"下载失败 {url} ({attempt}次): {type(e).__name__} {str(e)[:120]}", err=True)
            time.sleep(RETRY_DELAY)
    return url, []

def download_all(urls: List[str]) -> Dict[str, List[str]]:
    unique = list(dict.fromkeys(u.strip() for u in urls if u.strip()))
    if not unique: return {}
    log(f"下载 {len(unique)} 个唯一源...")
    results = {}
    with ThreadPoolExecutor(max_workers=DOWNLOAD_WORKERS) as ex:
        for future in as_completed(ex.submit(download_url, u) for u in unique):
            url, lines = future.result()
            results[url] = lines
            log(f"完成 {url} ({len(lines)} 行)")
    return results

def build_header(
    key: str,
    desc: str,
    count: int,
    block_urls: List[str],
    white_urls: List[str],
    c_black: List[str],
    c_white: List[str],
    now: str
) -> str:
    lines = [
        "!",
        f"! Title: {key} Blocklist",
        f"! Description: {desc or 'Merged advertising/tracking domains'}",
        "! Generated by: domain-filter",
        "! Homepage: https://github.com/cjchxgxhc/domain-filter/",
        f"! Last modified: {now}",
        f"! Blocked domains: {count:,}",
        "!",
        "! Blacklist sources:"
    ]
    lines.extend(f"!   {u}" for u in block_urls)
    if white_urls:
        lines += ["!", "! Whitelist sources:"] + [f"!   {u}" for u in white_urls]
    if c_black:
        lines += ["!", "! Custom blacklist domains:"] + [f"!   {d}" for d in sorted({d.strip().lower() for d in c_black if is_valid_domain(d)})]
    if c_white:
        lines += ["!", "! Custom whitelist (forced remove):"] + [f"!   {d}" for d in sorted({d.strip().lower() for d in c_white if is_valid_domain(d)})]
    lines += ["!", "! Blocked domains", "!"]
    return "\n".join(lines) + "\n"

def save_domains(
    domains: Set[str],
    out_dir: Path,
    key: str,
    desc: str,
    block_urls: List[str],
    white_urls: List[str],
    c_black: List[str],
    c_white: List[str],
    formats: List[str]
) -> int:
    if not domains and not c_black: return 0

    group_dir = out_dir / key
    group_dir.mkdir(parents=True, exist_ok=True)
    now = (datetime.datetime.utcnow() + datetime.timedelta(hours=8)).strftime("%Y-%m-%d %H:%M:%S") + " CST"

    c_black_clean = {d.strip().lower() for d in c_black if is_valid_domain(d)}
    c_white_clean = {d.strip().lower() for d in c_white if is_valid_domain(d)}

    final_list = sorted(set(domains) | c_black_clean - c_white_clean)
    count = len(final_list)

    header = build_header(key, desc, count, block_urls, white_urls, c_black, c_white, now)

    if "adblock" in formats:
        (group_dir / "adblock.txt").write_text(header + "\n".join(f"||{d}^" for d in final_list) + "\n", encoding="utf-8")

    if "clash" in formats:
        clash_lines = [
            f"# {key} - Clash payload",
            f"# {desc or 'Merged rules'}",
            f"# 更新: {now}",
            f"# 数量: {count:,}",
            "#",
            "# 黑名单:"
        ] + [f"#   {u}" for u in block_urls]

        if white_urls:
            clash_lines += ["# 白名单:"] + [f"#   {u}" for u in white_urls]

        if c_black:
            clash_lines += ["# 自定义黑名单:"] + [f"#   {d}" for d in sorted(c_black_clean)]

        if c_white:
            clash_lines += ["# 自定义白名单 (强制移除):"] + [f"#   {d}" for d in sorted(c_white_clean)]

        clash_lines += ["", "payload:"] + [f"  - '+.{d}'" for d in final_list]

        (group_dir / "clash.yaml").write_text("\n".join(clash_lines) + "\n", encoding="utf-8")

    if "domains" in formats:
        (group_dir / "domains.txt").write_text("\n".join(final_list) + "\n", encoding="utf-8")

    if "singbox" in formats or "sing-box" in formats:
        json.dump(
            {"version": 3, "rules": [{"domain_suffix": final_list}]},
            (group_dir / "singbox.json").open("w", encoding="utf-8"),
            ensure_ascii=False, indent=2
        )

    log(f"{key} 保存完成 ({count:,} 条)")
    return count

def generate_readme(out_dir: Path, info: Dict):
    now = (datetime.datetime.utcnow() + datetime.timedelta(hours=8)).strftime("%Y-%m-%d %H:%M:%S") + " CST"
    total = sum(v.get("domain_count", 0) for v in info.values())
    lines = [
        "# Domain Filter Rules\n",
        f"最后更新时间 (北京时间): {now}\n",
        "## 规则组概览\n"
    ]
    for k, v in info.items():
        lines += [
            f"### {v.get('display_name', k)} ({k})",
            f"- 域名数量: {v.get('domain_count', 0):,}",
            f"- 输出目录: OUTPUT/{k}/\n"
        ]
        if v.get("description"):
            lines.insert(-1, f"- 描述: {v['description']}")

    lines += [
        "## 统计",
        f"- 规则组数量: {len(info)}",
        f"- 总域名数量: {total:,}\n",
        "规则由 domain-filter 工具自动生成。"
    ]
    (Path.cwd() / "README.md").write_text("\n".join(lines), encoding="utf-8")
    log("README 已生成")

def process_group(
    key: str,
    conf: Dict,
    downloaded: Dict[str, List[str]],
    out_dir: Path,
    info: Dict
):
    title = conf.get("title", key)
    desc = conf.get("description", "")
    block_urls = conf.get("blocklist", [])
    white_urls = conf.get("whitelist", [])
    c_black = conf.get("custom_blacklist", [])
    c_white = conf.get("custom_whitelist", [])
    formats = conf.get("formats", ["domains"])

    log(f"处理 {title} ({key})")

    black_lines = sum((downloaded.get(u, []) for u in block_urls), [])
    white_lines = sum((downloaded.get(u, []) for u in white_urls), [])

    black_d = parallel_extract(black_lines, False)
    white_d = parallel_extract(white_lines, True)

    filtered = filter_whitelist(black_d, white_d)
    deduped = remove_subdomains(filtered)

    count = save_domains(deduped, out_dir, key, desc, block_urls, white_urls, c_black, c_white, formats)

    info[key] = {
        "display_name": title,
        "description": desc,
        "domain_count": count,
        "block_urls": block_urls,
        "white_urls": white_urls
    }

def load_config() -> Dict:
    p = Path("config.yaml")
    if not p.is_file():
        log("缺少 config.yaml", err=True)
        sys.exit(1)
    with p.open(encoding="utf-8") as f:
        return yaml.safe_load(f).get("groups", {})

def main():
    start = time.time()
    out_dir = Path("OUTPUT")
    out_dir.mkdir(parents=True, exist_ok=True)

    config = load_config()
    if not config:
        log("config.yaml 无 groups", err=True)
        sys.exit(1)

    all_urls = set()
    for c in config.values():
        all_urls.update(c.get("blocklist", []), c.get("whitelist", []))

    downloaded = download_all(list(all_urls))

    info = {}
    with ThreadPoolExecutor(max_workers=4) as ex:
        futures = [ex.submit(process_group, k, c, downloaded, out_dir, info) for k, c in config.items()]
        for f in as_completed(futures):
            try:
                f.result()
            except Exception as e:
                log(f"组处理异常: {e}", err=True)

    generate_readme(out_dir, info)
    log(f"完成，用时 {time.time() - start:.2f} 秒")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log("用户中断", err=True)
        sys.exit(1)
    except Exception as e:
        log(f"程序异常退出: {e}", err=True)
        sys.exit(1)
