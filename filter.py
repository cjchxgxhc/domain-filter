#!/usr/bin/env python3
import re
import sys
import time
import multiprocessing as mp
from pathlib import Path
from typing import Set, List, Optional, Tuple, Dict
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

# 配置常量
CHUNK_SIZE = 200_000  # 处理块大小
MAX_DOMAIN_LENGTH = 253  # 域名最大长度
WORKER_COUNT = min(mp.cpu_count() * 4, 16)  # 工作进程数
RULEGROUP_WORKERS = min(mp.cpu_count() * 2, 8)  # 规则组处理线程数
DOWNLOAD_WORKERS = 5  # 并发下载线程数
CONNECT_TIMEOUT = 3  # 连接超时（秒）
READ_TIMEOUT = 10  # 读取超时（秒）
RETRY_COUNT = 3  # 重试次数
RETRY_DELAY = 3  # 重试间隔（秒）
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/114.0.0.0 Safari/537.36"

# 内嵌黑白名单配置
BLACKLIST_CONFIG = {
    "ads": [
        "https://adrules.top/dns.txt",
        "https://anti-ad.net/adguard.txt",
        "https://gitlab.com/hagezi/mirror/-/raw/main/dns-blocklists/domains/native.oppo-realme.txt"
    ],
    "proxy": [
        "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Clash/Speedtest/Speedtest.list",
        "https://raw.githubusercontent.com/v2fly/domain-list-community/refs/heads/master/data/category-speedtest",
        "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Clash/Global/Global.list",
        "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/proxy-list.txt"
    ]
}
WHITELIST_CONFIG = {
    "ads": [
        "https://gcore.jsdelivr.net/gh/qq5460168/666@master/allow.txt"
    ],
    "proxy": []  # PROXY 组无白名单
}

# 正则表达式（不含KEYWORD规则）
DOMAIN_PATTERN = re.compile(
    r"^(?:(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*)?[a-z]{2,}$",
    re.IGNORECASE
)
ADBLOCK_BLACK_PATTERN = re.compile(r"^(?:\|{1,2})([a-z0-9\-\.]+)\^$", re.IGNORECASE)
ADBLOCK_WHITE_PATTERN = re.compile(r"^@@(?:\|{1,2})([a-z0-9\-\.]+)\^$", re.IGNORECASE)
RULE_PATTERN = re.compile(
    r"^(?:DOMAIN-SUFFIX|HOST-SUFFIX|host-suffix|DOMAIN|HOST|host)[,\s]+(.+)$",
    re.IGNORECASE
)
INVALID_CHARS = re.compile(r'[\\/*?:"<>|]')
UNWANTED_PREFIX = re.compile(r"^(0\.0\.0\.0\s+|127\.0\.0\.1\s+|local=|\|\||\*\.|\+\.|@@\|\|)")
UNWANTED_SUFFIX = re.compile(r"[\^#].*$")


def log(msg: str, critical: bool = False) -> None:
    """记录日志"""
    timestamp = time.strftime("%Y-%m-%d %H:%M")
    level = "CRITICAL" if critical else "INFO"
    print(f"[{timestamp}] [{level}] {msg}", flush=True)


def sanitize(name: str) -> str:
    """清理文件名中的无效字符"""
    return INVALID_CHARS.sub('_', name).strip()


def get_parent_domains(domain: str) -> Set[str]:
    """获取域名的所有父域名（不含自身）"""
    parts = domain.split('.')
    return {'.'.join(parts[i:]) for i in range(1, len(parts))}


def download_url(url: str) -> Tuple[str, List[str]]:
    """下载单个URL内容，过滤空行"""
    try:
        if url.startswith("file://"):
            file_path = Path(url[7:])
            if not file_path.exists():
                log(f"本地文件不存在: {file_path}", critical=True)
                return url, []
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                return url, [line.strip() for line in f.readlines() if line.strip()]
        
        headers = {"User-Agent": USER_AGENT, "Accept": "text/plain,text/html", "Connection": "keep-alive"}
        for attempt in range(1, RETRY_COUNT + 1):
            try:
                response = requests.get(
                    url, headers=headers, timeout=(CONNECT_TIMEOUT, READ_TIMEOUT), verify=True, allow_redirects=True
                )
                response.raise_for_status()
                return url, [line.strip() for line in response.text.splitlines() if line.strip()]
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
    """并发下载多个URL"""
    unique_urls = list(set(u.strip() for u in url_list if u.strip()))
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
    """验证域名有效性"""
    domain = domain.strip().lower()
    if not domain or len(domain) > MAX_DOMAIN_LENGTH:
        return False
    if '.' not in domain:
        return len(domain) >= 2 and DOMAIN_PATTERN.match(domain)
    return DOMAIN_PATTERN.match(domain) and domain.count('.') >= 1


def clean_domain_string(domain: str) -> str:
    """清理域名字符串"""
    domain = UNWANTED_PREFIX.sub('', domain.strip()).lower()
    domain = UNWANTED_SUFFIX.sub('', domain)
    return domain.strip('.')


def extract_domain(line: str, is_whitelist: bool) -> Optional[str]:
    """从规则行提取域名"""
    line = line.strip()
    if not line or line[0] in ('#', '!', '/'):
        return None
    match = ADBLOCK_WHITE_PATTERN.match(line) if is_whitelist else ADBLOCK_BLACK_PATTERN.match(line)
    if match:
        domain = match.group(1).strip()
        return domain if is_valid_domain(domain) else None
    match = RULE_PATTERN.match(line)
    if match:
        domain = match.group(1).strip()
        return domain if is_valid_domain(domain) else None
    if line.startswith(('*.', '+.')):
        domain = line[2:].strip()
        return domain if is_valid_domain(domain) else None
    domain = clean_domain_string(line)
    return domain if is_valid_domain(domain) else None


def process_chunk(args: Tuple[List[str], callable]) -> Set[str]:
    """处理数据块提取域名"""
    chunk, extractor = args
    return {d for line in chunk if (d := extractor(line))}


def parallel_extract_domains(lines: List[str], extractor: callable) -> Set[str]:
    """并行提取域名"""
    if not lines:
        return set()
    if len(lines) < CHUNK_SIZE:
        return process_chunk((lines, extractor))
    chunks = [lines[i:i + CHUNK_SIZE] for i in range(0, len(lines), CHUNK_SIZE)]
    with mp.Pool(WORKER_COUNT) as pool:
        results = pool.starmap(process_chunk, [(c, extractor) for c in chunks])
        return set.union(*results) if results else set()


def process_blacklist_rules(lines: List[str]) -> Set[str]:
    """提取黑名单域名"""
    return parallel_extract_domains(lines, lambda l: extract_domain(l, False))


def process_whitelist_rules(lines: List[str]) -> Set[str]:
    """提取白名单域名"""
    return parallel_extract_domains(lines, lambda l: extract_domain(l, True))


def remove_subdomains(domains: Set[str]) -> Set[str]:
    """移除子域名，保留父域名（AdBlock规则语义）"""
    if not domains:
        return set()
    sorted_domains = sorted(domains, key=lambda x: (-x.count('.'), x))
    keep = set()
    for domain in sorted_domains:
        if not any(parent in keep for parent in get_parent_domains(domain)):
            keep.add(domain)
    log(f"去重: 输入{len(domains)} → 输出{len(keep)}")
    return keep


def mixed_dedup_and_filter(black: Set[str], white: Set[str]) -> Set[str]:
    """混合去重后移除完全匹配的白名单域名"""
    mixed = black | white
    deduped = remove_subdomains(mixed)
    filtered = deduped - white
    log(f"混合{len(mixed)} → 去重{len(deduped)} → 过滤{len(filtered)}")
    return filtered


def save_domains_to_files(domains: Set[str], output_path: Path, group_name: str) -> None:
    """保存域名到AdBlock和Clash格式文件"""
    if not domains:
        log(f"无域名保存: {output_path}")
        return
    sorted_domains = sorted(domains)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    # AdBlock格式
    adblock_path = output_path / f"{group_name}_adblock.txt"
    with open(adblock_path, "w", encoding="utf-8") as f:
        f.write('\n'.join(f"||{d}^" for d in sorted_domains))
    log(f"保存AdBlock: {adblock_path} ({len(sorted_domains)}域名)")
    
    # Clash YAML格式
    clash_path = output_path / f"{group_name}_clash.yaml"
    with open(clash_path, "w", encoding="utf-8") as f:
        f.write("payload:\n")
        f.write('\n'.join(f"  - +.{d}" for d in sorted_domains))
    log(f"保存Clash: {clash_path} ({len(sorted_domains)}域名)")


def process_rule_group(name: str, urls: List[str], white_domains: Set[str],
                       downloaded: Dict[str, List[str]], output_dir: Path) -> None:
    """处理单个规则组"""
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
    final_domains = mixed_dedup_and_filter(black_domains, white_domains)
    save_domains_to_files(final_domains, output_dir, sanitized)


def main():
    start_time = time.time()
    output_dir = Path("domain")
    output_dir.mkdir(parents=True, exist_ok=True)
    log(f"输出目录: {output_dir.absolute()}")

    all_white_urls = [u for urls in WHITELIST_CONFIG.values() for u in urls]
    downloaded_white = download_all_urls(all_white_urls) if all_white_urls else {}
    whitelist = {}
    for name, urls in WHITELIST_CONFIG.items():
        sanitized = sanitize(name)
        if sanitized and urls:
            lines = [line for url in urls for line in downloaded_white.get(url, [])]
            domains = process_whitelist_rules(lines)
            if domains:
                whitelist[sanitized] = domains
                log(f"白名单{name}: {len(domains)}域名")

    all_black_urls = [u for urls in BLACKLIST_CONFIG.values() for u in urls]
    downloaded_black = download_all_urls(all_black_urls) if all_black_urls else {}

    with ThreadPoolExecutor(max_workers=RULEGROUP_WORKERS) as executor:
        futures = []
        for name, urls in BLACKLIST_CONFIG.items():
            white = whitelist.get(sanitize(name), set())
            futures.append(executor.submit(process_rule_group, name, urls, white, downloaded_black, output_dir))
        for future in as_completed(futures):
            try:
                future.result()
            except Exception as e:
                log(f"组处理异常: {str(e)[:100]}", critical=True)

    log(f"所有处理完成，总耗时{time.time() - start_time:.2f}s")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log("用户中断", critical=True)
        sys.exit(1)
    except Exception as e:
        log(f"程序终止: {str(e)[:100]}", critical=True)
        sys.exit(1)
