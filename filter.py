#!/usr/bin/env python3
import re
import sys
import time
import datetime
import multiprocessing as mp
from pathlib import Path
from typing import Set, List, Optional, Tuple, Dict, Callable
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

CHUNK_SIZE = 50_000
MAX_DOMAIN_LENGTH = 253
WORKER_COUNT = min(max(1, mp.cpu_count()), 4)
RULEGROUP_WORKERS = min(max(1, mp.cpu_count()), 2)
DOWNLOAD_WORKERS = 5
CONNECT_TIMEOUT = 3
READ_TIMEOUT = 10
RETRY_COUNT = 3
RETRY_DELAY = 2
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/114.0.0.0 Safari/537.36"

CONFIG = {
    "ads": {
        "blocklist": [
            "https://raw.githubusercontent.com/cjchxgxhc/domain-filter/refs/heads/main/rules/ads.txt",
            "https://raw.githubusercontent.com/Aethersailor/adblockfilters-modified/refs/heads/main/rules/adblockdnslite.txt",
            "https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/AWAvenue-Ads-Rule.txt",
            "https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockdnslite.txt",
            "https://raw.githubusercontent.com/lingeringsound/10007_auto/refs/heads/master/configure/%E8%87%AA%E5%AE%9A%E4%B9%89.prop",
            "https://raw.githubusercontent.com/privacy-protection-tools/anti-AD/refs/heads/adlist-maker/scripts/origin-files/anti-ad-origin-block.txt",
           # "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/BanProgramAD.list",
            "https://raw.githubusercontent.com/Cats-Team/AdRules/refs/heads/script/mod/rules/dns-rules.txt",
            "https://raw.githubusercontent.com/qq5460168/666/master/dns.txt",
            "https://raw.githubusercontent.com/hagezi/dns-blocklists/refs/heads/main/domains/native.oppo-realme.txt",
            "https://raw.githubusercontent.com/hagezi/dns-blocklists/refs/heads/main/adblock/native.xiaomi.txt"
        ],
        "whitelist": [
            "https://raw.githubusercontent.com/cjchxgxhc/domain-filter/refs/heads/main/rules/ads_white.txt",
            "https://raw.githubusercontent.com/qq5460168/Who520/refs/heads/main/white.txt",
            "https://raw.githubusercontent.com/neodevpro/neodevhost/refs/heads/master/allow",
            "https://raw.githubusercontent.com/217heidai/adblockfilters/refs/heads/main/rules/white.txt"
        ],
        "formats": ["clash", "domain", "adblock"]  # 默认只输出 domains，可以修改为 ["adblock"], ["clash"], ["adblock", "clash", "domains"] 等
    },
    "HaGeZi's Pro++ mini Blocklist": {
        "blocklist": [
            "https://raw.githubusercontent.com/hagezi/dns-blocklists/refs/heads/main/adblock/pro.plus.mini.txt"
        ],
        "whitelist": [
            "https://raw.githubusercontent.com/cjchxgxhc/domain-filter/refs/heads/main/rules/ads_white.txt",
            "https://raw.githubusercontent.com/217heidai/adblockfilters/refs/heads/main/rules/white.txt"
        ],
        "formats": ["clash"]
    }
}

DOMAIN_PATTERN = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$",
    re.IGNORECASE
)
# 仅接受没有其它后缀的特定 $ 修饰符：$all 或 $important
ADBLOCK_BLACK_PATTERN = re.compile(r"^\|{1,2}([a-z0-9-\.]+)\^(?:\$(all|important))?$", re.IGNORECASE)
ADBLOCK_WHITE_PATTERN = re.compile(r"^@@\|{1,2}([a-z0-9-\.]+)\^(?:\$(all|important))?$", re.IGNORECASE)
RULE_PATTERN = re.compile(r"^(?:DOMAIN-SUFFIX|HOST-SUFFIX|host-suffix|DOMAIN|HOST|host)[,\s]+(.+)$", re.IGNORECASE)
INVALID_CHARS = re.compile(r'[\\/*?:"<>|\t\r\n]')
UNWANTED_PREFIX = re.compile(r"^(0\.0\.0\.0\s+|127\.0\.0\.1\s+|local=|\|\||\*\.|\+\.|@@\|\|)")
UNWANTED_SUFFIX = re.compile(r"[\^#].*$")

_thread_local = threading.local()

def log(msg: str, critical: bool = False) -> None:
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    lvl = "错误" if critical else "信息"
    print(f"[{ts}] [{lvl}] {msg}", flush=True)

def sanitize(name: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", name).strip("_")
    return cleaned[:100]

def get_parent_domains(domain: str) -> Set[str]:
    parts = domain.split('.')
    return {'.'.join(parts[i:]) for i in range(1, len(parts))}

def get_session() -> requests.Session:
    s = getattr(_thread_local, "session", None)
    if s is None:
        s = requests.Session()
        s.headers.update({"User-Agent": USER_AGENT, "Accept": "text/plain,text/html"})
        _thread_local.session = s
    return s

def download_url(url: str) -> Tuple[str, List[str]]:
    try:
        if url.startswith("file://"):
            log(f"file:// 链接已禁用: {url}", critical=True)
            return url, []
        session = get_session()
        for attempt in range(1, RETRY_COUNT + 1):
            try:
                r = session.get(url, timeout=(CONNECT_TIMEOUT, READ_TIMEOUT), allow_redirects=True, verify=True)
                r.raise_for_status()
                txt = r.text or ""
                if not txt.strip():
                    log(f"内容为空: {url}", critical=True)
                    return url, []
                return url, [ln.strip() for ln in txt.splitlines() if ln.strip()]
            except requests.RequestException as e:
                is_final = attempt == RETRY_COUNT
                log(f"下载失败 ({type(e).__name__}) {url} ({attempt}/{RETRY_COUNT})" + (" - 放弃" if is_final else ""))
                if not is_final:
                    time.sleep(RETRY_DELAY)
        return url, []
    except Exception as e:
        log(f"下载异常 {url}: {str(e)[:120]}", critical=True)
        return url, []

def download_all_urls(url_list: List[str]) -> Dict[str, List[str]]:
    unique = list(dict.fromkeys(u.strip() for u in url_list if u.strip()))
    log(f"开始下载 {len(unique)} 个源...")
    results: Dict[str, List[str]] = {}
    with ThreadPoolExecutor(max_workers=DOWNLOAD_WORKERS) as ex:
        futures = {ex.submit(download_url, u): u for u in unique}
        for f in as_completed(futures):
            u = futures[f]
            try:
                _, content = f.result()
                results[u] = content
                log(f"已下载: {u} (行数: {len(content)})")
            except Exception as e:
                log(f"下载任务异常 {u}: {str(e)[:120]}", critical=True)
                results[u] = []
    ok = sum(1 for v in results.values() if v)
    log(f"下载汇总: 成功 {ok}/{len(unique)}")
    return results

def is_valid_domain(domain: str) -> bool:
    d = domain.strip().lower()
    if not d or len(d) > MAX_DOMAIN_LENGTH:
        return False
    if '.' not in d:
        return False
    return bool(DOMAIN_PATTERN.fullmatch(d))

def clean_domain_string(domain: str) -> str:
    domain = domain.strip().lower()
    if '##' in domain:
        return ''
    domain = UNWANTED_PREFIX.sub('', domain)
    domain = UNWANTED_SUFFIX.sub('', domain)
    return domain.strip('.')

def extract_domain(line: str, is_whitelist: bool) -> Optional[str]:
    line = line.strip()
    if not line or line[0] in ('#', '!', '/'):
        return None

    match = ADBLOCK_WHITE_PATTERN.match(line) if is_whitelist else ADBLOCK_BLACK_PATTERN.match(line)
    if match:
        dom = match.group(1).strip()
        return dom if is_valid_domain(dom) else None

    match = RULE_PATTERN.match(line)
    if match:
        dom = match.group(1).strip().split(',')[0]
        dom = clean_domain_string(dom)
        return dom if is_valid_domain(dom) else None

    if line.startswith(('*.', '+.')):
        dom = line[2:].strip()
        return dom if is_valid_domain(dom) else None

    dom = clean_domain_string(line)
    return dom if is_valid_domain(dom) else None

def extract_black_domain(line: str) -> Optional[str]:
    return extract_domain(line, False)

def extract_white_domain(line: str) -> Optional[str]:
    return extract_domain(line, True)

def process_chunk(chunk: List[str], extractor: Callable[[str], Optional[str]]) -> Set[str]:
    return {d for l in chunk if (d := extractor(l)) and d}  # 确保 d 不为空

def parallel_extract_domains(lines: List[str], extractor: Callable[[str], Optional[str]]) -> Set[str]:
    if not lines:
        return set()
    if len(lines) < CHUNK_SIZE:
        return process_chunk(lines, extractor)
    chunks = [lines[i:i + CHUNK_SIZE] for i in range(0, len(lines), CHUNK_SIZE)]
    results: List[Set[str]] = []
    with ThreadPoolExecutor(max_workers=WORKER_COUNT) as ex:
        futures = [ex.submit(process_chunk, c, extractor) for c in chunks]
        for f in as_completed(futures):
            try:
                results.append(f.result())
            except Exception as e:
                log(f"分块处理异常: {str(e)[:120]}", critical=True)
    return set().union(*results) if results else set()

def process_blacklist_rules(lines: List[str]) -> Set[str]:
    return parallel_extract_domains(lines, extract_black_domain)

def process_whitelist_rules(lines: List[str]) -> Set[str]:
    return parallel_extract_domains(lines, extract_white_domain)

def remove_subdomains(domains: Set[str]) -> Set[str]:
    if not domains:
        return set()
    sorted_domains = sorted(domains, key=lambda x: (x.count('.'), x))
    keep: Set[str] = set()
    for d in sorted_domains:
        if not any(p in keep for p in get_parent_domains(d)):
            keep.add(d)
    log(f"去重: {len(domains)} -> {len(keep)}")
    return keep

def filter_exact_whitelist(black_domains: Set[str], white_domains: Set[str]) -> Set[str]:
    if not white_domains:
        return black_domains
    filtered = black_domains - white_domains
    log(f"白名单精确过滤: {len(black_domains)} -> {len(filtered)}")
    return filtered

def blacklist_dedup_and_filter(black: Set[str], white: Set[str]) -> Set[str]:
    filtered = filter_exact_whitelist(black, white)
    deduped = remove_subdomains(filtered)
    log(f"黑名单处理完成: {len(filtered)} -> {len(deduped)}")
    return deduped

def _beijing_now_str() -> str:
    utc_now = datetime.datetime.utcnow()
    bj = utc_now + datetime.timedelta(hours=8)
    return bj.strftime("%Y-%m-%d %H:%M:%S") + " CST"

def save_domains_to_files(domains: Set[str], output_path: Path, group_name: str, source_urls: List[str], white_source_urls: List[str], formats: List[str]) -> int:
    """
    保存域名到文件，并返回最终域名数量用于 README 生成。
    """
    if not domains:
        log(f"{group_name} 无域名可保存")
        return 0
    sorted_domains = sorted(domains)
    group_dir = output_path / group_name
    group_dir.mkdir(parents=True, exist_ok=True)
    beijing_time = _beijing_now_str()

    if "adblock" in formats:
        adblock_path = group_dir / "adblock.txt"
        with open(adblock_path, "w", encoding="utf-8") as f:
            f.write(f"! Title: {group_name} Blocklist\n")
            f.write(f"! Description: Generated by domain-filter\n")
            f.write(f"! Last modified: {beijing_time}\n")
            f.write(f"! Entries: {len(sorted_domains)}\n")
            f.write("! Applies to: AdBlock, AdGuard, uBlock Origin\n")
            f.write("! Blacklist sources:\n")
            for src in source_urls:
                f.write(f"! {src}\n")
            if white_source_urls:
                f.write("! Whitelist sources:\n")
                for src in white_source_urls:
                    f.write(f"! {src}\n")
            f.write("\n")
            for d in sorted_domains:
                f.write(f"||{d}^\n")
        log(f"已写入 AdBlock 文件: {adblock_path} ({len(sorted_domains)} 个域名)")

    if "clash" in formats or "yaml" in formats:
        clash_path = group_dir / "clash.yaml"
        with open(clash_path, "w", encoding="utf-8") as f:
            f.write("# Generated by domain-filter\n")
            f.write(f"# 规则: {group_name}\n")
            f.write(f"# 更新时间 (北京时间): {beijing_time}\n")
            f.write(f"# 域名数量: {len(sorted_domains)}\n")
            f.write("# 适用: Clash (domain payload list)\n")
            f.write("# 黑名单来源:\n")
            for src in source_urls:
                f.write(f"# - {src}\n")
            if white_source_urls:
                f.write("# 白名单来源:\n")
                for src in white_source_urls:
                    f.write(f"# - {src}\n")
            f.write("# payload 为 YAML 字符串列表，条目格式为 \"+.domain\"\n\n")
            f.write("payload:\n")
            for d in sorted_domains:
                f.write(f"  - \"+.{d}\"\n")
        log(f"已写入 Clash 文件: {clash_path} ({len(sorted_domains)} 个域名)")

    if "domains" in formats:
        domains_path = group_dir / "domains.txt"
        with open(domains_path, "w", encoding="utf-8") as f:
            for d in sorted_domains:
                f.write(f"{d}\n")
        log(f"已写入 Domains 文件: {domains_path} ({len(sorted_domains)} 个域名)")

    return len(sorted_domains)

def generate_readme(output_dir: Path, group_info: Dict[str, Dict]) -> None:
    """
    生成根目录下的 README.md 文件，汇总所有规则组信息。
    """
    beijing_time = _beijing_now_str()
    readme_path = Path.cwd() / "README.md"  # 生成在当前工作目录（脚本同目录）
    
    with open(readme_path, "w", encoding="utf-8") as f:
        f.write("# Domain Filter Rules\n\n")
        f.write("这是一个由 domain-filter 工具生成的规则集仓库。\n\n")
        f.write(f"**最后更新时间 (北京时间):** {beijing_time}\n\n")
        f.write("## 规则组概览\n\n")
        
        total_domains = 0
        for display_name, info in group_info.items():
            domain_count = info.get("domain_count", 0)
            block_urls = info.get("block_urls", [])
            white_urls = info.get("white_urls", [])
            
            f.write(f"### {display_name}\n")
            f.write(f"- **域名数量:** {domain_count}\n")
            f.write("- **黑名单来源:**\n")
            for url in block_urls:
                filename = url.split('/')[-1] if '/' in url else url
                f.write(f"  - [{filename}]({url})\n")
            if white_urls:
                f.write("- **白名单来源:**\n")
                for url in white_urls:
                    filename = url.split('/')[-1] if '/' in url else url
                    f.write(f"  - [{filename}]({url})\n")
            f.write(f"- **输出目录:** [OUTPUT/{sanitize(display_name)}/](OUTPUT/{sanitize(display_name)}/)\n\n")
            total_domains += domain_count
        
        f.write(f"## 统计\n")
        f.write(f"- **总规则组数:** {len(group_info)}\n")
        f.write(f"- **总域名数量:** {total_domains}\n\n")
        f.write("## 使用说明\n")
        f.write("1. 每个规则组目录下包含相应的格式文件（如 adblock.txt、clash.yaml、domains.txt）。\n")
        f.write("2. 支持的格式包括 AdBlock、Clash YAML 和纯域名列表。\n")
        f.write("3. 规则由多个源自动聚合、去重和过滤生成。\n\n")
        f.write("## 生成工具\n")
        f.write("此仓库由 [domain-filter](https://github.com/cjchxgxhc/domain-filter) 工具自动生成和更新。\n")
    
    log(f"已生成 README.md: {readme_path.absolute()}")

def process_rule_group(name: str, block_urls: List[str], white_urls: List[str], downloaded_black: Dict[str, List[str]], downloaded_white: Dict[str, List[str]], output_dir: Path, formats: List[str], group_info: Dict[str, Dict]) -> None:
    sanitized = sanitize(name)
    if not sanitized or not block_urls:
        log(f"跳过无效组: {name}", critical=True)
        return
    log(f"开始处理组: {name}")
    black_lines: List[str] = []
    for url in block_urls:
        black_lines.extend(downloaded_black.get(url, []))
    if not black_lines:
        log(f"组 {name} 无黑名单内容，跳过")
        return
    white_lines: List[str] = []
    for url in white_urls:
        white_lines.extend(downloaded_white.get(url, []))
    black_domains = process_blacklist_rules(black_lines)
    white_domains = process_whitelist_rules(white_lines)
    final_domains = blacklist_dedup_and_filter(black_domains, white_domains)
    domain_count = save_domains_to_files(final_domains, output_dir, sanitized, block_urls, white_urls, formats)
    
    # 更新 group_info 用于 README 生成
    group_info[name] = {
        "domain_count": domain_count,
        "block_urls": block_urls,
        "white_urls": white_urls
    }

def main():
    start_time = time.time()
    output_dir = Path("OUTPUT")
    output_dir.mkdir(parents=True, exist_ok=True)
    log(f"输出目录: {output_dir.absolute()}")

    all_white_urls = [u for group in CONFIG.values() for u in group.get("whitelist", [])]
    downloaded_white = download_all_urls(all_white_urls) if all_white_urls else {}

    all_black_urls = [u for group in CONFIG.values() for u in group.get("blocklist", [])]
    downloaded_black = download_all_urls(all_black_urls) if all_black_urls else {}

    group_info: Dict[str, Dict] = {}  # 用于收集每个组的信息

    with ThreadPoolExecutor(max_workers=RULEGROUP_WORKERS) as ex:
        futures = []
        for name, conf in CONFIG.items():
            block_urls = conf.get("blocklist", [])
            white_urls = conf.get("whitelist", [])
            formats = conf.get("formats", ["domains"])
            futures.append(ex.submit(process_rule_group, name, block_urls, white_urls, downloaded_black, downloaded_white, output_dir, formats, group_info))
        for f in as_completed(futures):
            try:
                f.result()
            except Exception as e:
                log(f"组处理异常: {str(e)[:120]}", critical=True)

    # 在所有组处理完成后生成 README.md
    generate_readme(output_dir, group_info)

    log(f"全部完成，耗时 {time.time() - start_time:.2f}s")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log("用户中断", critical=True)
        sys.exit(1)
    except Exception as e:
        log(f"程序终止: {str(e)[:200]}", critical=True)
        sys.exit(1)
