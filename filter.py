#!/usr/bin/env python3
import re
import sys
import time
import multiprocessing as mp
from pathlib import Path
from urllib.parse import urlparse
from typing import Set, List, Optional, Tuple, Dict
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

# 配置常量（调整优化参数）
CHUNK_SIZE = 500_000  # 增大分块大小，减少线程切换开销
MAX_DOMAIN_LENGTH = 253
WORKER_COUNT = min(mp.cpu_count() * 2, 8)  # 使用线程池，减少进程开销
RULEGROUP_WORKERS = min(mp.cpu_count(), 4)  # 动态调整规则组处理线程
DOWNLOAD_WORKERS = min(mp.cpu_count(), 8)  # 动态调整下载线程
CONNECT_TIMEOUT = 3
READ_TIMEOUT = 10
RETRY_COUNT = 3
RETRY_DELAY = 3
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/114.0.0.0 Safari/537.36"

# 内嵌黑白名单配置（与原脚本一致，保持不变）
BLACKLIST_CONFIG = {
    "ads": [
        "https://raw.githubusercontent.com/cjchxgxhc/domain-filter/refs/heads/main/rules/ads.txt",
        "https://adrules.top/dns.txt",
        "https://anti-ad.net/adguard.txt",
        "https://raw.githubusercontent.com/privacy-protection-tools/anti-AD/master/anti-ad-domains.txt",
        "https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/AWAvenue-Ads-Rule.txt",
        "https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockdomainlite.txt",
        "https://big.oisd.nl",
        "https://raw.githubusercontent.com/hagezi/dns-blocklists/refs/heads/main/domains/native.oppo-realme.txt",
        "https://raw.githubusercontent.com/LM-Firefly/Rules/refs/heads/master/Adblock/Adblock.list"
    ],
    "ads_lite": [
        "https://raw.githubusercontent.com/cjchxgxhc/domain-filter/refs/heads/main/rules/ads.txt",
        "https://adrules.top/dns.txt",
        "https://anti-ad.net/adguard.txt",
        "https://raw.githubusercontent.com/privacy-protection-tools/anti-AD/master/anti-ad-domains.txt",
        "https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/AWAvenue-Ads-Rule.txt"
    ],
    "gfw": [
        "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/gfw.txt"
    ],
    "proxy": [
        "https://raw.githubusercontent.com/cjchxgxhc/domain-filter/refs/heads/main/rules/proxy.txt",
        "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/proxy-list.txt",
        "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Clash/Global/Global.list",
        "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/gfw.txt",
        "https://raw.githubusercontent.com/cutethotw/ClashRule/refs/heads/main/Rule/Outside.list",
        "https://raw.githubusercontent.com/LM-Firefly/Rules/refs/heads/master/SpeedTest.list",
        "https://raw.githubusercontent.com/LM-Firefly/Rules/refs/heads/master/PROXY.list"
    ],
    "bypass": [
        "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/doh.txt",
        "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/dyndns-onlydomains.txt",
        "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Clash/DNS/DNS.list"
    ]
}
WHITELIST_CONFIG = {
    "ads": [
        "https://raw.githubusercontent.com/cjchxgxhc/domain-filter/refs/heads/main/rules/ads_white.txt",
        "https://raw.githubusercontent.com/qq5460168/666/refs/heads/master/allow.txt",
        "https://raw.githubusercontent.com/hagezi/dns-blocklists/refs/heads/main/domains/tif.txt",
        "https://raw.githubusercontent.com/hagezi/dns-blocklists/refs/heads/main/share/dead.list-aa",
        "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/nsfw-onlydomains.txt"
    ],
    "ads_lite": [
        "https://raw.githubusercontent.com/cjchxgxhc/domain-filter/refs/heads/main/rules/ads_white.txt",
        "https://raw.githubusercontent.com/hagezi/dns-blocklists/refs/heads/main/domains/tif.txt",
        "https://raw.githubusercontent.com/hagezi/dns-blocklists/refs/heads/main/share/dead.list-aa",
        "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/nsfw-onlydomains.txt"
    ],
    "proxy": [
        "https://raw.githubusercontent.com/cjchxgxhc/domain-filter/refs/heads/main/rules/proxy_white.txt",
        "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Clash/Notion/Notion.list",
        "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Clash/ChinaMaxNoIP/ChinaMaxNoIP.list",
        "https://raw.githubusercontent.com/hagezi/dns-blocklists/refs/heads/main/domains/pro.txt",
        "https://raw.githubusercontent.com/Aethersailor/Custom_OpenClash_Rules/refs/heads/main/rule/Custom_Direct.list"
    ]
}

# 正则表达式（优化：合并匹配逻辑，移除不必要捕获组）
DOMAIN_PATTERN = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$",
    re.IGNORECASE
)
ADBLOCK_BLACK_PATTERN = re.compile(r"^\|{1,2}([a-z0-9\-\.]+)\^$", re.IGNORECASE)
ADBLOCK_WHITE_PATTERN = re.compile(r"^@@\|{1,2}([a-z0-9\-\.]+)\^$", re.IGNORECASE)
RULE_PATTERN = re.compile(
    r"^(?:DOMAIN-SUFFIX|HOST-SUFFIX|host-suffix|DOMAIN|HOST|host)[,\s]+(.+)$",
    re.IGNORECASE
)
INVALID_CHARS = re.compile(r'[\\/*?:"<>|]')
UNWANTED_PREFIX = re.compile(r"^(?:0\.0\.0\.0\s+|127\.0\.0\.1\s+|local=|\|{1,2}|\*\.|\+\.|@@\|\|)")
UNWANTED_SUFFIX = re.compile(r"[\^#].*$")

def log(msg: str, critical: bool = False) -> None:
    # 优化：减少非关键日志输出
    if critical or not msg.startswith("下载成功"):
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        level = "CRITICAL" if critical else "INFO"
        print(f"[{timestamp}] [{level}] {msg}", flush=True)

def sanitize(name: str) -> str:
    return INVALID_CHARS.sub('_', name).strip()

def get_parent_domains(domain: str) -> Set[str]:
    """获取域名的所有父域名（不含自身），保持原逻辑"""
    parts = domain.split('.')
    return {'.'.join(parts[i:]) for i in range(1, len(parts))}

def download_url(url: str) -> Tuple[str, List[str]]:
    try:
        if url.startswith("file://"):
            parsed = urlparse(url)
            file_path = Path(parsed.path.lstrip('/')) if sys.platform.startswith('win32') else Path(parsed.path)
            if not file_path.exists():
                log(f"本地文件不存在: {file_path}", critical=True)
                return url, []
            # 优化：流式读取本地文件
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                return url, [line.strip() for line in f if line.strip()]
        
        headers = {"User-Agent": USER_AGENT, "Accept": "text/plain", "Connection": "keep-alive"}
        with requests.Session() as session:
            for attempt in range(1, RETRY_COUNT + 1):
                try:
                    response = session.get(
                        url, headers=headers, timeout=(CONNECT_TIMEOUT, READ_TIMEOUT),
                        verify=True, allow_redirects=True, stream=True
                    )
                    response.raise_for_status()
                    # 优化：流式处理响应
                    lines = [line.strip() for line in response.iter_lines(decode_unicode=True, chunk_size=8192) if line.strip()]
                    if not lines:
                        log(f"下载内容为空: {url}", critical=True)
                    return url, lines
                except requests.RequestException as e:
                    error_type = type(e).__name__
                    is_final = attempt == RETRY_COUNT
                    log(f"下载失败({error_type}) {url} ({attempt}/{RETRY_COUNT}){' | 最大重试' if is_final else ''}", critical=is_final)
                    if not is_final:
                        time.sleep(RETRY_DELAY)
        return url, []
    except Exception as e:
        log(f"下载异常 {url}: {str(e)[:80]}", critical=True)
        return url, []

def download_all_urls(url_list: List[str]) -> Dict[str, List[str]]:
    unique_urls = list(dict.fromkeys(u.strip() for u in url_list if u.strip()))  # 优化：高效去重
    log(f"开始下载{len(unique_urls)}个唯一资源...")
    results = {}
    with ThreadPoolExecutor(max_workers=DOWNLOAD_WORKERS) as executor:
        futures = {executor.submit(download_url, url): url for url in unique_urls}
        for future in as_completed(futures):
            url = futures[future]
            try:
                _, content = future.result()
                results[url] = content
                log(f"下载成功: {url} (有效行: {len(content)})")
            except Exception as e:
                log(f"下载异常 {url}: {str(e)[:80]}", critical=True)
                results[url] = []
    success_count = sum(bool(v) for v in results.values())
    log(f"下载完成: 成功{success_count}/{len(unique_urls)}")
    return results

def is_valid_domain(domain: str) -> bool:
    domain = domain.strip().lower()  # 确保小写
    if not domain or len(domain) > MAX_DOMAIN_LENGTH or '.' not in domain:
        return False
    return bool(DOMAIN_PATTERN.match(domain))

def clean_domain_string(domain: str) -> str:
    domain = UNWANTED_PREFIX.sub('', domain.strip()).lower()  # 确保小写
    domain = UNWANTED_SUFFIX.sub('', domain)
    return domain.strip('.')

def extract_domain(line: str, is_whitelist: bool) -> Optional[str]:
    # 优化：合并正则匹配逻辑，确保小写
    line = line.strip()
    if not line or line[0] in ('#', '!', '/'):
        return None
    pattern = ADBLOCK_WHITE_PATTERN if is_whitelist else ADBLOCK_BLACK_PATTERN
    if match := pattern.match(line):
        domain = match.group(1).strip().lower()
        return domain if is_valid_domain(domain) else None
    if match := RULE_PATTERN.match(line):
        domain = match.group(1).strip().lower()
        return domain if is_valid_domain(domain) else None
    if line.startswith(('*.', '+.')):
        domain = line[2:].strip().lower()
        return domain if is_valid_domain(domain) else None
    domain = clean_domain_string(line)
    return domain if is_valid_domain(domain) else None

def extract_black_domain(line: str) -> Optional[str]:
    return extract_domain(line, False)

def extract_white_domain(line: str) -> Optional[str]:
    return extract_domain(line, True)

def process_chunk(chunk: List[str], extractor: callable) -> Set[str]:
    return {d for line in chunk if (d := extractor(line))}

def parallel_extract_domains(lines: List[str], extractor: callable) -> Set[str]:
    # 优化：使用线程池替代多进程，适合 I/O 密集型任务
    if not lines:
        return set()
    if len(lines) < CHUNK_SIZE:
        return process_chunk(lines, extractor)
    chunks = [lines[i:i + CHUNK_SIZE] for i in range(0, len(lines), CHUNK_SIZE)]
    with ThreadPoolExecutor(max_workers=WORKER_COUNT) as executor:
        results = executor.map(lambda c: process_chunk(c, extractor), chunks)
        return set.union(*results) if results else set()

def process_blacklist_rules(lines: List[str]) -> Set[str]:
    return parallel_extract_domains(lines, extract_black_domain)

def process_whitelist_rules(lines: List[str]) -> Set[str]:
    return parallel_extract_domains(lines, extract_white_domain)

def remove_subdomains(domains: Set[str]) -> Set[str]:
    """保持原去重逻辑：移除子域名，保留父域名（AdBlock规则语义）"""
    if not domains:
        return set()
    sorted_domains = sorted(domains, key=lambda x: (x.count('.'), x))  # 父域名先处理
    keep = set()
    for domain in sorted_domains:
        if not any(parent in keep for parent in get_parent_domains(domain)):
            keep.add(domain)
    log(f"去重: 输入{len(domains)} → 输出{len(keep)}")
    return keep

def filter_exact_whitelist(black_domains: Set[str], white_domains: Set[str]) -> Set[str]:
    """保持原逻辑：仅过滤与白名单完全匹配的域名"""
    if not white_domains:
        return black_domains
    filtered = black_domains - white_domains
    log(f"白名单完全匹配过滤: 输入{len(black_domains)} → 输出{len(filtered)}")
    return filtered

def blacklist_dedup_and_filter(black: Set[str], white: Set[str]) -> Set[str]:
    """保持原逻辑：先过滤完全匹配的白名单，再对黑名单去重"""
    filtered_black = filter_exact_whitelist(black, white)
    deduped_black = remove_subdomains(filtered_black)
    log(f"黑名单处理: 过滤后{len(filtered_black)} → 去重后{len(deduped_black)}")
    return deduped_black

def save_domains_to_files(domains: Set[str], output_path: Path, group_name: str) -> None:
    if not domains:
        log(f"无域名保存: {output_path}")
        return
    sorted_domains = sorted(domains)  # 确保输出有序
    group_dir = output_path / group_name
    group_dir.mkdir(parents=True, exist_ok=True)
    
    adblock_path = group_dir / "adblock.txt"
    with open(adblock_path, "w", encoding="utf-8") as f:
        f.write('\n'.join(f"||{d}^" for d in sorted_domains) + '\n')
    log(f"保存AdBlock: {adblock_path} ({len(sorted_domains)}域名)")
    
    clash_path = group_dir / "clash.yaml"
    with open(clash_path, "w", encoding="utf-8") as f:
        f.write("payload:\n" + '\n'.join(f"  - +.{d}" for d in sorted_domains) + '\n')
    log(f"保存Clash: {clash_path} ({len(sorted_domains)}域名)")

def process_rule_group(name: str, urls: List[str], white_domains: Set[str],
                       downloaded: Dict[str, List[str]], output_dir: Path) -> None:
    sanitized = sanitize(name)
    if not sanitized or not urls:
        log(f"无效组: {name}", critical=True)
        return
    log(f"处理组: {name}")
    lines = set()
    for url in urls:
        lines.update(downloaded.get(url, []))
    if not lines:
        log(f"组{name}无内容，跳过")
        return
    black_domains = process_blacklist_rules(list(lines))
    final_domains = blacklist_dedup_and_filter(black_domains, white_domains)
    save_domains_to_files(final_domains, output_dir, sanitized)

def main():
    start_time = time.time()
    output_dir = Path("OUTPUT")
    output_dir.mkdir(parents=True, exist_ok=True)
    log(f"输出目录: {output_dir.absolute()}")

    all_white_urls = list(dict.fromkeys(u for urls in WHITELIST_CONFIG.values() for u in urls))  # 优化：高效去重
    downloaded_white = download_all_urls(all_white_urls) if all_white_urls else {}
    whitelist = {}
    for name, urls in WHITELIST_CONFIG.items():
        sanitized = sanitize(name)
        if sanitized and urls:
            lines = [line for url in urls for line in downloaded_white.get(url, [])]
            domains = process_whitelist_rules(lines)
            if domains:
                whitelist[sanitized] = domains
                log(f"白名单{name}: 提取{len(domains)}个域名")

    all_black_urls = list(dict.fromkeys(u for urls in BLACKLIST_CONFIG.values() for u in urls))  # 优化：高效去重
    downloaded_black = download_all_urls(all_black_urls) if all_black_urls else {}

    with ThreadPoolExecutor(max_workers=RULEGROUP_WORKERS) as executor:
        futures = [
            executor.submit(process_rule_group, name, urls, whitelist.get(sanitize(name), set()), downloaded_black, output_dir)
            for name, urls in BLACKLIST_CONFIG.items()
        ]
        for future in as_completed(futures):
            try:
                future.result()
            except Exception as e:
                log(f"组处理异常: {str(e)[:100]}", critical=True)

    log(f"所有处理完成，总耗时{time.time() - start_time:.2f}s")

if __name__ == "__main__":
    if sys.platform.startswith('win32'):
        mp.set_start_method('spawn')
    try:
        main()
    except KeyboardInterrupt:
        log("用户中断", critical=True)
        sys.exit(1)
    except Exception as e:
        log(f"程序终止: {str(e)[:100]}", critical=True)
        sys.exit(1)
