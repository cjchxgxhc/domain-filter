#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Domain Filter - 域名过滤工具

一个自动化的域名过滤和去重工具，支持多种格式的规则源、并行处理和智能过滤。

项目地址：https://github.com/cjchxgxhc/domain-filter

主要功能：
  • 支持多种规则格式（AdBlock、Clash、Hosts、纯域名等）
  • 并行下载和处理规则源
  • 使用Trie树进行高效的子域检测和去重
  • 灵活的黑/白名单过滤机制
  • 多格式输出（Domains、AdBlock、Hosts、Clash、Sing-box）
"""

import datetime
import json
import re
import sys
import threading
import time
import traceback
import gc
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from enum import Enum

import requests
import yaml
from concurrent.futures import ThreadPoolExecutor, as_completed
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from zoneinfo import ZoneInfo


# ═══════════════════════════════════════════════════════════════════════════════
# 全局配置常量
# ═══════════════════════════════════════════════════════════════════════════════

# 并行处理配置
CHUNK_SIZE = 40000                  # 域名提取时的数据块大小
FILTER_CHUNK_SIZE = 25000           # 白名单过滤时的数据块大小
MAX_DOMAIN_LEN = 253                # 域名最大长度（RFC 1035）

# 并发参数
DOWNLOAD_WORKERS = 10               # 下载线程数
FILTER_WORKERS = 8                  # 过滤线程数
EXTRACT_WORKERS = 6                 # 提取线程数

# 网络连接配置
CONNECT_TIMEOUT = 4                 # 连接超时（秒）
READ_TIMEOUT = 12                   # 读取超时（秒）
RETRY_COUNT = 3                     # 重试次数
RETRY_DELAY = 1.5                   # 重试延迟倍数

# HTTP 请求头
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/128.0.0.0 Safari/537.36"
)

# 项目链接
REPO_URL = "https://github.com/cjchxgxhc/domain-filter"
RAW_BASE = "https://raw.githubusercontent.com/cjchxgxhc/domain-filter/refs/heads/main/data/rules"


# ═══════════════════════════════════════════════════════════════════════════════
# 日志级别枚举
# ═══════════════════════════════════════════════════════════════════════════════

class LogLevel(Enum):
    """
    日志级别定义
    """
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"


# ═══════════════════════════════════════════════════════════════════════════════
# Trie 树数据结构
# ═══════════════════════════════════════════════════════════════════════════════

class TrieNode:
    """
    Trie 树节点
    
    用于构建前缀树，高效地进行域名匹配和子域检测。
    每个节点代表域名中的一个部分。
    
    属性：
        children: 子节点字典，key为域名部分，value为TrieNode
        is_end: 标记当前节点是否为一个完整的域名结尾
    """
    __slots__ = ('children', 'is_end')
    
    def __init__(self):
        self.children: Dict[str, 'TrieNode'] = {}
        self.is_end: bool = False


# ═══════════════════════════════════════════════════════════════════════════════
# 预编译的正则表达式
# ═══════════════════════════════════════════════════════════════════════════════

# 域名格式验证：标准域名格式（如 example.com）
DOMAIN_PATTERN = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$",
    re.IGNORECASE
)

# AdBlock 格式：||example.com^
REGEX_ADBLOCK = re.compile(
    r"^\|{1,2}([a-z0-9][a-z0-9\.-]*[a-z0-9])(?:\^)?(?:\$important)?(?:\$?)?$",
    re.IGNORECASE
)

# 白名单格式：@@||example.com^
REGEX_WHITELIST = re.compile(
    r"^@@\|{0,2}([a-z0-9][a-z0-9\.-]*[a-z0-9])(?:\^)?(?:\$important)?(?:\$?)?$",
    re.IGNORECASE
)

# Clash/Surge 格式：DOMAIN,example.com 或 DOMAIN-SUFFIX,example.com
REGEX_CLASH = re.compile(
    r"^(DOMAIN|DOMAIN-SUFFIX|HOST|HOST-SUFFIX)\s*,\s*([a-z0-9][a-z0-9\.-]*[a-z0-9])(?:\s*,.*)?$",
    re.IGNORECASE
)

# Hosts 格式：0.0.0.0 example.com 或 127.0.0.1 example.com
REGEX_HOSTS = re.compile(
    r"^(0\.0\.0\.0|127\.0\.0\.1|::1|local=)\s",
    re.IGNORECASE
)


# ═══════════════════════════════════════════════════════════════════════════════
# 日志系统
# ═══════════════════════════════════════════════════════════════════════════════

# 全局日志锁，防止并发日志输出混乱
_log_lock = threading.Lock()

# 日志缓冲，用于批量写入
_log_buffer = []
_buffer_size_threshold = 10  # 每 10 条日志刷新一次


def log(message: str, level: LogLevel = LogLevel.INFO, log_file: Optional[Path] = None) -> None:
    """
    统一的日志记录函数
    
    参数：
        message: 日志消息内容
        level: 日志级别（DEBUG、INFO、WARNING、ERROR）
        log_file: 日志文件路径（如果为None则仅输出到控制台）
    """
    with _log_lock:
        # 生成时间戳（包含毫秒）
        timestamp = datetime.datetime.now().strftime("%m-%d %H:%M:%S.%f")[:-3]
        
        # 控制台输出（包含时间戳和级别）
        console_message = f"[{timestamp}] [{level.value}] {message}"
        print(console_message, flush=True)
        
        # 文件输出（如果指定了日志文件）
        if log_file:
            try:
                # 确保日志目录存在
                log_file.parent.mkdir(parents=True, exist_ok=True)
                
                # 文件日志格式：仅保留级别和消息（不重复时间戳）
                if level == LogLevel.INFO:
                    file_message = message
                else:
                    file_message = f"[{level.value}] {message}"
                
                # 添加到缓冲
                _log_buffer.append((log_file, file_message))
                
                # 缓冲达到阈值或出现错误时立即刷新
                if len(_log_buffer) >= _buffer_size_threshold or level in (LogLevel.ERROR, LogLevel.WARNING):
                    _flush_log_buffer()
                    
            except Exception:
                # 日志写入失败不应中断主程序流程
                pass


def _flush_log_buffer() -> None:
    """刷新日志缓冲到文件"""
    global _log_buffer
    
    if not _log_buffer:
        return
    
    # 按文件分组缓冲
    logs_by_file = {}
    for log_file, message in _log_buffer:
        if log_file not in logs_by_file:
            logs_by_file[log_file] = []
        logs_by_file[log_file].append(message)
    
    # 一次性写入每个文件
    for log_file, messages in logs_by_file.items():
        try:
            with log_file.open("a", encoding="utf-8") as f:
                for msg in messages:
                    f.write(msg + "\n")
        except Exception:
            pass
    
    _log_buffer = []


def log_error(msg: str, log_file: Optional[Path] = None) -> None:
    """
    便利函数：记录错误级别的日志
    
    参数：
        msg: 错误消息
        log_file: 日志文件路径
    """
    log(msg, LogLevel.ERROR, log_file)


# ═══════════════════════════════════════════════════════════════════════════════
# 域名验证和处理
# ═══════════════════════════════════════════════════════════════════════════════

def is_valid_domain(domain: str) -> bool:
    """
    验证域名格式是否合法
    
    执行多层验证：长度、是否包含点、是否以点开头/结尾、正则匹配。
    
    参数：
        domain: 待验证的域名字符串
    
    返回：
        True 如果是合法的域名格式，否则 False
    """
    if not domain:
        return False
    
    domain = domain.strip().lower()
    
    # 基本长度和格式检查
    if len(domain) > MAX_DOMAIN_LEN or "." not in domain:
        return False
    
    # 不允许以点开头或结尾
    if domain.startswith(".") or domain.endswith("."):
        return False
    
    # 使用预编译的正则表达式进行验证
    return bool(DOMAIN_PATTERN.fullmatch(domain))


def clean_domain(raw: str) -> str:
    """
    清理原始域名字符串
    
    移除常见的前缀（IP地址、协议、通配符等）、注释和特殊字符。
    
    参数：
        raw: 原始的域名字符串
    
    返回：
        清理后的域名（小写）
    """
    raw = raw.strip().lower()
    
    # 跳过注释行（包含##）
    if "##" in raw:
        return ""
    
    # 移除常见的前缀
    # 包括：IP地址、HTTP(S)协议、通配符、AdBlock语法等
    raw = re.sub(
        r"^(?:0\.0\.0\.0|127\.0\.0\.1|::1|local=|https?://|\|\||\*\.|\+\.|@@\|\|)\s*",
        "",
        raw,
        flags=re.IGNORECASE
    )
    
    # 移除特殊字符和行内注释（^、$、#等）
    raw = re.sub(r"[\^$#].*$", "", raw)
    
    # 移除两端的点
    return raw.strip(".")


# ═══════════════════════════════════════════════════════════════════════════════
# 规则行预处理
# ═══════════════════════════════════════════════════════════════════════════════

def strip_comments(line: str) -> str:
    """
    从规则行中移除注释
    
    识别并移除以下注释格式：
    - 行开头的 # 或 !（整行注释）
    - 行内注释（前面有空格的 #）
    
    参数：
        line: 输入的规则行
    
    返回：
        去除注释后的内容（如果整行是注释则返回空字符串）
    """
    line = line.strip()
    
    # 空行或整行注释
    if not line or line.startswith(("#", "!")):
        return ""
    
    # 移除行内注释（# 前面有空格）
    if " #" in line:
        line = line.split(" #", 1)[0].rstrip()
    
    return line.strip()


# ═══════════════════════════════════════════════════════════════════════════════
# 域名提取器（支持多种格式）
# ═══════════════════════════════════════════════════════════════════════════════

class DomainExtractor:
    """
    多格式域名提取器
    
    从各种格式的规则行中智能提取域名，包括：
    - AdBlock 格式：||example.com^
    - 白名单格式：@@||example.com^
    - Clash/Surge：DOMAIN,example.com 或 +.example.com
    - Hosts：0.0.0.0 example.com
    - 纯域名：example.com
    
    使用级联的格式检测，按优先级尝试各种格式。
    """
    
    @staticmethod
    def _extract_adblock(cleaned: str) -> Optional[str]:
        """
        提取 AdBlock 格式的域名
        
        格式：||example.com^ 或 |example.com^
        """
        match = REGEX_ADBLOCK.match(cleaned)
        return match.group(1).lower().strip() if match else None
    
    @staticmethod
    def _extract_whitelist(cleaned: str) -> Optional[str]:
        """
        提取白名单格式的域名
        
        格式：@@||example.com^ 或 @@|example.com^
        """
        match = REGEX_WHITELIST.match(cleaned)
        return match.group(1).lower().strip() if match else None
    
    @staticmethod
    def _extract_clash(cleaned: str) -> Optional[str]:
        """
        提取 Clash/Surge 格式的域名
        
        支持格式：
        - DOMAIN,example.com
        - DOMAIN-SUFFIX,example.com
        - +.example.com（通配符）
        - *.example.com（通配符）
        """
        no_quote = cleaned.strip("'\"").strip()
        
        # 尝试匹配标准的 Clash 格式
        match = REGEX_CLASH.match(no_quote)
        if match:
            return match.group(2).strip().lower()
        
        # 尝试匹配通配符格式（+. 或 *.）
        if no_quote.startswith(("+.", "*.")):
            return no_quote[2:].strip().lower()
        
        # 尝试作为纯域名处理
        if is_valid_domain(no_quote):
            return no_quote
        
        return None
    
    @staticmethod
    def _extract_hosts(cleaned: str) -> Optional[str]:
        """
        提取 Hosts 文件格式的域名
        
        格式：0.0.0.0 example.com 或 127.0.0.1 example.com
        """
        if REGEX_HOSTS.match(cleaned):
            # 按空格分割，取第二部分
            parts = re.split(r"\s+", cleaned.strip(), maxsplit=1)
            if len(parts) >= 2:
                return clean_domain(parts[1])
        return None
    
    @staticmethod
    def _extract_fallback(cleaned: str) -> Optional[str]:
        """
        备用方案：移除特殊字符后验证
        
        用于处理非标准格式的输入。
        """
        cleaned_no_mark = re.sub(r"[\^\$\*\+@\|'\"]", "", cleaned).strip()
        return cleaned_no_mark if is_valid_domain(cleaned_no_mark) else None
    
    @classmethod
    def extract(cls, line: str, is_whitelist: bool = False) -> Optional[str]:
        """
        主提取方法 - 按优先级尝试各种格式
        
        提取流程：
        1. 移除注释和 YAML 前缀
        2. 如果是白名单规则，先尝试白名单格式
        3. 如果是黑名单规则，跳过白名单标记
        4. 按优先级尝试：AdBlock、Clash、Hosts、备用方案
        5. 对提取的结果进行域名验证
        
        参数：
            line: 输入的规则行
            is_whitelist: 是否为白名单规则
        
        返回：
            提取的域名（小写），或 None 如果无法提取
        """
        # 移除注释和空白
        cleaned = strip_comments(line)
        if not cleaned:
            return None
        
        # 移除 YAML 列表前缀（- 符号）
        cleaned = re.sub(r"^\s*-\s*", "", cleaned).strip()
        
        # 白名单规则特殊处理
        if is_whitelist:
            result = cls._extract_whitelist(cleaned)
            if result and is_valid_domain(result):
                return result
        else:
            # 黑名单：跳过白名单标记
            if cleaned.startswith("@@"):
                return None
            
            # 尝试提取 AdBlock 格式
            result = cls._extract_adblock(cleaned)
            if result and is_valid_domain(result):
                return result
        
        # 尝试提取 Clash 格式
        result = cls._extract_clash(cleaned)
        if result and is_valid_domain(result):
            return result
        
        # 尝试提取 Hosts 格式
        result = cls._extract_hosts(cleaned)
        if result and is_valid_domain(result):
            return result
        
        # 备用方案
        result = cls._extract_fallback(cleaned)
        if result and is_valid_domain(result):
            return result
        
        return None


def extract_domain(line: str, is_whitelist: bool = False) -> Optional[str]:
    """
    包装函数：提取域名
    
    为了向后兼容而提供的简化接口。
    
    参数：
        line: 规则行
        is_whitelist: 是否为白名单规则
    
    返回：
        提取的域名或 None
    """
    return DomainExtractor.extract(line, is_whitelist)


# ═══════════════════════════════════════════════════════════════════════════════
# 并行提取
# ═══════════════════════════════════════════════════════════════════════════════

def parallel_extract(lines: List[str], is_whitelist: bool = False) -> Set[str]:
    """
    并行提取域名
    
    将输入行分割成多个数据块，使用线程池并行处理，
    提高处理速度。每个线程独立处理一个块，避免线程安全问题。
    
    参数：
        lines: 规则行列表
        is_whitelist: 是否为白名单
    
    返回：
        提取的域名集合
    """
    if not lines:
        return set()

    result = set()
    
    # 将数据分块
    chunks = [lines[i:i + CHUNK_SIZE] for i in range(0, len(lines), CHUNK_SIZE)]

    def process_chunk(chunk: List[str]) -> Set[str]:
        """处理单个数据块"""
        local = set()
        for line in chunk:
            domain = extract_domain(line, is_whitelist)
            if domain:
                local.add(domain)
        return local

    # 使用线程池并行处理
    with ThreadPoolExecutor(max_workers=EXTRACT_WORKERS) as executor:
        futures = [executor.submit(process_chunk, c) for c in chunks]
        for future in as_completed(futures):
            try:
                result.update(future.result())
            except Exception as e:
                log(f"并行提取失败: {e}", LogLevel.WARNING)
                continue
    
    gc.collect()
    return result


# ═══════════════════════════════════════════════════════════════════════════════
# 白名单过滤（使用 Trie 树）
# ═══════════════════════════════════════════════════════════════════════════════

def build_trie(domains: Set[str]) -> TrieNode:
    """
    构建 Trie 树
    
    将域名集合构建成 Trie 树结构，用于快速的子域匹配。
    域名部分按反向顺序存储（TLD 在前）。
    
    例如：example.com 存储为 com -> example
    
    参数：
        domains: 域名集合
    
    返回：
        Trie 树的根节点
    """
    root = TrieNode()
    
    for domain in domains:
        # 将域名按点分割，反向存储（从 TLD 开始）
        parts = domain.split(".")[::-1]
        node = root
        
        for part in parts:
            if part not in node.children:
                node.children[part] = TrieNode()
            node = node.children[part]
        
        node.is_end = True
    
    return root


def is_subdomain_of_any(domain: str, trie: TrieNode) -> bool:
    """
    检查域名是否为 Trie 中任何域名的子域
    
    例如：sub.example.com 是 example.com 的子域。
    
    算法：沿着 Trie 树遍历，如果在某个节点发现 is_end 为 True，
    则说明找到了一个匹配的父域名。
    
    参数：
        domain: 待检查的域名
        trie: Trie 树根节点
    
    返回：
        True 如果是任何域名的子域，否则 False
    """
    # 反向分割域名
    parts = domain.split(".")[::-1]
    node = trie
    
    for part in parts:
        if node.is_end:
            # 找到了一个匹配的父域名
            return True
        if part not in node.children:
            # 未找到匹配
            return False
        node = node.children[part]
    
    # 检查最后一个节点是否是完整的域名
    return node.is_end


def filter_whitelist(black: Set[str], white: Set[str]) -> Set[str]:
    """
    使用白名单过滤黑名单
    
    移除黑名单中所有在白名单中的域名及其子域。
    例如：白名单包含 example.com，则黑名单中的 example.com、sub.example.com 等都会被移除。
    
    参数：
        black: 黑名单域名集合
        white: 白名单域名集合
    
    返回：
        过滤后的黑名单（不包含白名单中的域名及其子域）
    """
    # 白名单为空，直接返回黑名单
    if not white:
        return black
    
    # 黑名单为空，返回空集
    if not black:
        return set()
    
    # 从白名单构建 Trie 树
    white_trie = build_trie(white)
    result = set()
    
    # 将黑名单分块并行处理
    black_list = list(black)
    chunks = [black_list[i:i + FILTER_CHUNK_SIZE] for i in range(0, len(black_list), FILTER_CHUNK_SIZE)]
    
    def process_chunk(chunk: List[str]) -> Set[str]:
        """处理单个数据块 - 过滤出不在白名单中的域名"""
        local = set()
        for domain in chunk:
            if not is_subdomain_of_any(domain, white_trie):
                local.add(domain)
        return local
    
    # 使用线程池并行处理
    with ThreadPoolExecutor(max_workers=FILTER_WORKERS) as executor:
        futures = [executor.submit(process_chunk, c) for c in chunks]
        for future in as_completed(futures):
            try:
                result.update(future.result())
            except Exception as e:
                log(f"白名单过滤失败: {e}", LogLevel.WARNING)
                continue
    
    gc.collect()
    return result


# ═══════════════════════════════════════════════════════════════════════════════
# 子域去重
# ═══════════════════════════════════════════════════════════════════════════════

def remove_subdomains(domains: Set[str]) -> Set[str]:
    """
    移除重复的子域名
    
    保留仅顶级或二级域名，移除其下的所有子域。
    例如：example.com 和 sub.example.com 同时存在时，移除 sub.example.com。
    
    算法：
    1. 按域名部分数和字母顺序排序（短域名在前）
    2. 遍历排序后的域名，对每个新域名检查是否为已有域名的子域
    3. 如果不是，则保留并添加到 Trie 树
    4. 使用 Trie 树加速子域检测
    
    对于大数据集（> 50000 条），使用并发分块处理。
    
    参数：
        domains: 域名集合
    
    返回：
        去重后的域名集合（仅包含顶级域名）
    """
    if not domains:
        return set()
    
    # 按域名部分数（从少到多）和字母顺序排序
    # 这样确保父域名先被处理
    sorted_domains = sorted(domains, key=lambda x: (len(x.split(".")), x))
    
    # 对于小数据集，使用单线程处理；大数据集使用并发处理
    if len(sorted_domains) < 50000:
        # 小数据集：单线程处理
        trie = TrieNode()
        result = set()
        
        def add_to_trie(d: str, node: TrieNode) -> None:
            """将域名添加到 Trie 树中"""
            parts = d.split(".")[::-1]
            for part in parts:
                if part not in node.children:
                    node.children[part] = TrieNode()
                node = node.children[part]
            node.is_end = True
        
        # 处理每个域名
        for domain in sorted_domains:
            # 检查是否为已有域名的子域
            if not is_subdomain_of_any(domain, trie):
                result.add(domain)
                # 添加到 Trie 树中
                add_to_trie(domain, trie)
        
        return result
    else:
        # 大数据集：并发分块处理
        import math
        
        # 计算分块大小和工作线程数
        num_workers = min(EXTRACT_WORKERS, math.ceil(len(sorted_domains) / 20000))
        chunk_size = math.ceil(len(sorted_domains) / num_workers)
        chunks = [
            sorted_domains[i:i + chunk_size] 
            for i in range(0, len(sorted_domains), chunk_size)
        ]
        
        def process_chunk(chunk: List[str]) -> Set[str]:
            """处理单个数据块中的域名去重"""
            trie = TrieNode()
            result = set()
            
            def add_to_trie(d: str, node: TrieNode) -> None:
                """将域名添加到 Trie 树中"""
                parts = d.split(".")[::-1]
                for part in parts:
                    if part not in node.children:
                        node.children[part] = TrieNode()
                    node = node.children[part]
                node.is_end = True
            
            for domain in chunk:
                if not is_subdomain_of_any(domain, trie):
                    result.add(domain)
                    add_to_trie(domain, trie)
            
            return result
        
        # 并发处理各数据块
        chunk_results = []
        with ThreadPoolExecutor(max_workers=num_workers) as executor:
            futures = [executor.submit(process_chunk, c) for c in chunks]
            for future in as_completed(futures):
                try:
                    chunk_results.append(future.result())
                except Exception as e:
                    log(f"子域去重处理失败: {e}", LogLevel.WARNING)
                    continue
        
        # 合并各块的结果，进行最终去重
        merged = set()
        for chunk_result in chunk_results:
            merged.update(chunk_result)
        
        # 最终去重：检查合并结果中的子域关系
        final_trie = TrieNode()
        result = set()
        
        def add_to_trie(d: str, node: TrieNode) -> None:
            """将域名添加到 Trie 树中"""
            parts = d.split(".")[::-1]
            for part in parts:
                if part not in node.children:
                    node.children[part] = TrieNode()
                node = node.children[part]
            node.is_end = True
        
        # 对合并结果中的域名再次排序和去重
        for domain in sorted(merged, key=lambda x: (len(x.split(".")), x)):
            if not is_subdomain_of_any(domain, final_trie):
                result.add(domain)
                add_to_trie(domain, final_trie)
        
        gc.collect()
        return result


# ═══════════════════════════════════════════════════════════════════════════════
# 网络下载
# ═══════════════════════════════════════════════════════════════════════════════

def create_session() -> requests.Session:
    """
    创建带重试机制的 HTTP 会话
    
    配置包括：
    - 自动重试（指数退避）
    - 连接和读取超时
    - 自定义 User-Agent
    
    返回：
        配置好的 requests.Session 对象
    """
    session = requests.Session()
    
    # 配置重试策略
    retry_strategy = Retry(
        total=RETRY_COUNT,                              # 总重试次数
        backoff_factor=RETRY_DELAY,                     # 指数退避因子
        status_forcelist=[429, 500, 502, 503, 504],     # 需要重试的 HTTP 状态码
        allowed_methods=["GET", "HEAD"]                 # 允许重试的 HTTP 方法
    )
    
    # 为 HTTP 和 HTTPS 都应用重试策略
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    
    # 设置 User-Agent
    session.headers.update({"User-Agent": USER_AGENT})
    
    return session


def download_url(url: str, session: requests.Session) -> Tuple[bool, List[str]]:
    """
    下载单个 URL 的内容
    
    参数：
        url: 要下载的 URL
        session: HTTP 会话对象
    
    返回：
        (成功标志, 内容行列表) 元组
        - 下载成功且有内容：(True, [行...])
        - 下载成功但文件为空：(True, [])
        - 下载失败：(False, [])
    """
    try:
        response = session.get(url, timeout=(CONNECT_TIMEOUT, READ_TIMEOUT))
        response.raise_for_status()
        return (True, response.text.splitlines())
    except requests.exceptions.Timeout:
        return (False, [])
    except requests.exceptions.ConnectionError:
        return (False, [])
    except requests.exceptions.HTTPError:
        return (False, [])
    except Exception:
        return (False, [])


def download_all(urls: List[str], log_file: Optional[Path] = None) -> Dict[str, List[str]]:
    """
    并行下载所有 URL
    
    使用线程池并行下载多个 URL，加快下载速度。
    失败的 URL 返回空列表。
    
    参数：
        urls: URL 列表
        log_file: 日志文件路径
    
    返回：
        URL 到内容行列表的映射字典
    """
    if not urls:
        return {}
    
    log(f"开始下载 {len(urls)} 个规则源...", log_file=log_file)
    
    session = create_session()
    result = {}
    success = 0
    
    # 使用线程池并行下载
    with ThreadPoolExecutor(max_workers=DOWNLOAD_WORKERS) as executor:
        future_to_url = {executor.submit(download_url, url, session): url for url in urls}
        
        for future in as_completed(future_to_url):
            url = future_to_url[future]
            try:
                is_success, lines = future.result()
                result[url] = lines
                
                if is_success:
                    success += 1
                    if lines:
                        log(f"  ✓ {url}", log_file=log_file)
                    else:
                        log(f"  ⊘ {url} (文件为空)", LogLevel.WARNING, log_file=log_file)
                else:
                    log(f"  ✗ {url}", LogLevel.ERROR, log_file=log_file)
            except Exception as e:
                log(f"  ✗ {url} - {e}", LogLevel.ERROR, log_file=log_file)
                result[url] = []
    
    log(f"下载完成：{success}/{len(urls)} 成功\n", log_file=log_file)
    
    return result


# ═══════════════════════════════════════════════════════════════════════════════
# 文件保存
# ═══════════════════════════════════════════════════════════════════════════════

def save_domains(
    domains: Set[str],
    output_dir: Path,
    title: str,
    description: str,
    formats: List[str],
) -> None:
    """
    将域名保存到各种格式的文件
    
    支持的格式：
    - domains: 纯域名列表（每行一个域名）
    - adblock: AdBlock Plus 格式（||domain^）
    - hosts: Hosts 文件格式（0.0.0.0 domain）
    - clash: Clash/Mihomo YAML 格式
    - singbox: sing-box JSON 规则集格式
    
    每个文件都包含头部注释，包括标题、描述、更新时间等信息。
    
    参数：
        domains: 域名集合
        output_dir: 输出目录
        title: 规则组标题
        description: 规则组描述
        formats: 输出格式列表
    """
    if not domains:
        log_error(f"警告：{title} 没有域名可保存")
        return
    
    # 排序域名以保持一致性
    sorted_domains = sorted(domains)
    count = len(sorted_domains)
    
    # 获取当前时间（北京时区）
    now = datetime.datetime.now(ZoneInfo("Asia/Shanghai"))
    
    # 生成文件头注释
    header_lines = [
        f"# Title: {title}",
        f"# Description: {description}" if description else None,
        f"# Homepage: {REPO_URL}",
        f"# Total: {count:,}",
        f"# Updated: {now.strftime('%Y-%m-%d %H:%M:%S %Z')}",
        "#",
    ]
    header = "\n".join(line for line in header_lines if line)
    
    # 1. 纯域名格式（domains.txt）
    if "domains" in formats:
        domains_file = output_dir / "domains.txt"
        with domains_file.open("w", encoding="utf-8") as f:
            f.write(header + "\n")
            for domain in sorted_domains:
                f.write(domain + "\n")
        log(f"  ✓ 已保存：{domains_file.name}")
    
    # 2. AdBlock 格式（adblock.txt）
    if "adblock" in formats:
        adblock_file = output_dir / "adblock.txt"
        with adblock_file.open("w", encoding="utf-8") as f:
            f.write("[Adblock Plus 2.0]\n")
            f.write(header + "\n")
            for domain in sorted_domains:
                f.write(f"||{domain}^\n")
        log(f"  ✓ 已保存：{adblock_file.name}")
    
    # 3. Hosts 格式（hosts.txt）
    if "hosts" in formats:
        hosts_file = output_dir / "hosts.txt"
        with hosts_file.open("w", encoding="utf-8") as f:
            f.write(header + "\n")
            for domain in sorted_domains:
                f.write(f"0.0.0.0 {domain}\n")
        log(f"  ✓ 已保存：{hosts_file.name}")
    
    # 4. Clash 格式（clash.yaml）
    if "clash" in formats:
        clash_file = output_dir / "clash.yaml"
        with clash_file.open("w", encoding="utf-8") as f:
            f.write(header + "\n")
            f.write("payload:\n")
            for domain in sorted_domains:
                f.write(f"  - +.{domain}\n")
        log(f"  ✓ 已保存：{clash_file.name}")
    
    # 5. Sing-box 格式（singbox.json）
    if "singbox" in formats:
        singbox_file = output_dir / "singbox.json"
        singbox_data = {
            "version": 2,
            "rules": [
                {
                    "domain_suffix": sorted_domains
                }
            ]
        }
        with singbox_file.open("w", encoding="utf-8") as f:
            json.dump(singbox_data, f, indent=2, ensure_ascii=False)
        log(f"  ✓ 已保存：{singbox_file.name}")


# ═══════════════════════════════════════════════════════════════════════════════
# README 生成
# ═══════════════════════════════════════════════════════════════════════════════

def generate_readme(output_root: Path, stats: Dict, groups_cfg: Dict) -> None:
    """
    生成项目的 README.md 文件
    
    创建一个包含以下内容的 README：
    - 规则统计信息和徽章
    - 各规则组的详细信息表格
    - 使用说明（Clash、Sing-box、AdBlock、Hosts 等）
    
    参数：
        output_root: 输出根目录
        stats: 统计信息字典
        groups_cfg: 规则组配置
    """
    # 获取当前时间（北京时区）
    now_cst = datetime.datetime.now(ZoneInfo("Asia/Shanghai"))
    timestamp = now_cst.strftime("%Y-%m-%d %H:%M:%S")
    date_badge = now_cst.strftime("%Y--%m--%d_%H:%M:%S")
    
    # 计算总规则数（仅统计实际的规则组，不包括预设组）
    total = sum(v.get("final_count", 0) for k, v in stats.items() if k in groups_cfg)
    
    # 构建 README 内容
    lines = [
        "# 🛡️ Domain Filter",
        "",
        f"![Total Rules](https://img.shields.io/badge/Total_Rules-{total:,}-blue?style=flat-square)",
        f"![Last Update](https://img.shields.io/badge/Last_Update-{date_badge}-green?style=flat-square)",
        "",
        "这是一个自动合并多源规则、精准去重并移除冗余子域的过滤列表。",
        "",
        "## 📊 规则组详情统计",
        "",
        "| 规则组名称 | 描述 | 规则数量 | 获取链接 |",
        "| :--- | :--- | :--- | :--- |",
    ]
    
    # 按规则数量排序规则组
    sorted_groups = sorted(
        groups_cfg.keys(),
        key=lambda k: stats.get(k, {}).get("final_count", 0),
        reverse=True
    )
    
    # 添加每个规则组的信息
    for key in sorted_groups:
        if key not in stats:
            continue
        
        data = stats[key]
        name = data.get("display_name", key)
        desc = data.get("description", "无描述")
        count = data.get("final_count", 0)
        
        # 构建可用文件的链接
        links = []
        
        # 检查实际存在的文件
        group_dir = output_root / key
        if (group_dir / "domains.txt").exists():
            links.append(f"[`Domains`]({RAW_BASE}/{key}/domains.txt)")
        if (group_dir / "adblock.txt").exists():
            links.append(f"[`AdBlock`]({RAW_BASE}/{key}/adblock.txt)")
        if (group_dir / "hosts.txt").exists():
            links.append(f"[`Hosts`]({RAW_BASE}/{key}/hosts.txt)")
        if (group_dir / "clash.yaml").exists():
            links.append(f"[`Clash`]({RAW_BASE}/{key}/clash.mrs) · [`Mrs`]({RAW_BASE}/{key}/clash.mrs)")
        if (group_dir / "singbox.json").exists():
            links.append(f"[`Sing-box`]({RAW_BASE}/{key}/singbox.srs) · [`Srs`]({RAW_BASE}/{key}/singbox.srs)")
        
        # 合并链接
        link_text = " · ".join(links) if links else "—"
        
        lines.append(f"| **{name}** | {desc} | `{count:,}` | {link_text} |")
    
    # 添加使用说明
    lines.extend([
        "",
        "## 📖 使用说明",
        "",
        "### Clash/Mihomo",
        "```yaml",
        "rule-providers:",
        "  example:",
        "    type: http",
        "    behavior: domain",
        "    format: mrs  # 推荐使用编译后的 mrs 格式",
        f"    url: {RAW_BASE}/example/clash.mrs",
        "    interval: 86400",
        "",
        "rules:",
        "  - RULE-SET,example,REJECT",
        "```",
        "",
        "### sing-box",
        "```json",
        "{",
        '  "route": {',
        '    "rule_set": [',
        "      {",
        '        "type": "remote",',
        '        "tag": "example",',
        '        "format": "binary",',
        f'        "url": "{RAW_BASE}/example/singbox.srs",',
        '        "download_detour": "direct"',
        "      }",
        "    ],",
        '    "rules": [',
        "      {",
        '        "rule_set": ["example"],',
        '        "outbound": "block"',
        "      }",
        "    ]",
        "  }",
        "}",
        "```",
        "",
        "### AdBlock",
        "直接添加订阅链接到 AdGuard、uBlock Origin 等扩展:",
        "```",
        f"{RAW_BASE}/example/adblock.txt",
        "```",
        "",
        "### Hosts",
        "下载 hosts 文件并合并到系统 hosts 文件:",
        "```bash",
        f"curl {RAW_BASE}/example/hosts.txt >> /etc/hosts",
        "```",
        "",
        "---",
        f"*更新时间：{timestamp}（北京时间）*",
    ])
    
    # 写入 README 文件
    readme_path = Path("README.md")
    with readme_path.open("w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    
    log("✓ README.md 已生成")


# ═══════════════════════════════════════════════════════════════════════════════
# 自定义列表处理
# ═══════════════════════════════════════════════════════════════════════════════

def process_custom_list(
    custom_list: List,
    downloaded: Dict[str, List[str]],
    list_type: str = "黑名单",
    log_file: Optional[Path] = None
) -> Set[str]:
    """
    统一处理自定义黑/白名单
    
    支持两种配置方式：
    1. 直接域名：custom_blacklist: [example.com, test.com]
    2. 外部规则源 URL：custom_blacklist: [https://example.com/rules.txt]
    
    直接域名会被直接添加（支持自定义格式）。
    外部 URL 的内容会被逐行处理。
    
    参数：
        custom_list: 配置中的自定义列表
        downloaded: 已下载的规则源内容
        list_type: 列表类型标记（用于日志）
        log_file: 日志文件路径
    
    返回：
        处理后的域名集合
    """
    result_set = set()
    external_urls = []
    
    # 第一步：分离 URL 和直接域名
    for item in custom_list:
        # 跳过非字符串类型
        if not isinstance(item, str):
            continue
        
        item_stripped = item.strip()
        if not item_stripped:
            continue
        
        # 判断是否为 URL
        if item_stripped.startswith(('http://', 'https://')):
            external_urls.append(item_stripped)
        else:
            # 直接添加为自定义项（支持用户自定义格式）
            result_set.add(item_stripped.lower())
    
    # 第二步：处理外部规则源
    if external_urls:
        log(
            f"自定义{list_type}包含 {len(external_urls)} 个外部规则源",
            log_file=log_file
        )
        
        for url in external_urls:
            lines = downloaded.get(url, [])
            if lines:
                # 过滤出有效行（非空且非注释）
                valid_lines = [
                    line for line in lines
                    if line.strip() and not line.strip().startswith('#')
                ]
                
                # 添加所有有效行
                for line in valid_lines:
                    line_clean = line.strip().lower()
                    if line_clean:
                        result_set.add(line_clean)
                
                log(
                    f"  └─ 外部规则源：{len(valid_lines)} 条 <- {url}",
                    log_file=log_file
                )
            else:
                log(
                    f"  └─ 外部规则源：0 条（下载失败） <- {url}",
                    LogLevel.ERROR,
                    log_file=log_file
                )
    
    return result_set


# ═══════════════════════════════════════════════════════════════════════════════
# 规则组处理
# ═══════════════════════════════════════════════════════════════════════════════

def process_group(
    key: str,
    config: Dict,
    downloaded: Dict[str, List[str]],
    output_root: Path,
    final_cache: Dict[str, Set[str]],
    stats_collection: Dict,
    log_file: Path,
    is_preset: bool = False,
) -> None:
    """
    处理单个规则组
    
    流程：
    1. 加载黑名单源和自定义黑名单
    2. 加载白名单源和自定义白名单
    3. 引入预设规则组（如果配置）
    4. 合并所有黑名单
    5. 使用白名单过滤黑名单
    6. 移除重复的子域名
    7. 保存结果到文件（如果非预设组）
    8. 记录统计信息
    
    参数：
        key: 规则组键名
        config: 规则组配置字典
        downloaded: 已下载的规则源内容
        output_root: 输出根目录
        final_cache: 最终结果缓存（用于预设组的引用）
        stats_collection: 统计信息收集
        log_file: 主日志文件路径
        is_preset: 是否为预设组（预设组不输出文件）
    """
    # 读取配置
    title = config.get("display_name", config.get("title", key))
    description = config.get("description", "")
    block_urls = config.get("blocklist", [])
    white_urls = config.get("whitelist", [])
    custom_black = config.get("custom_blacklist", [])
    custom_white = config.get("custom_whitelist", [])
    formats = config.get("formats", ["domains"])
    presets = config.get("preset_names", [])

    # 记录开始处理日志
    log(f"\n{'═' * 70}", log_file=log_file)
    log(f"处理 {'预设组' if is_preset else '规则组'}：{title} ({key})", log_file=log_file)
    log(f"{'═' * 70}", log_file=log_file)

    # ─────────────────────────────────────────────────────────────────────────
    # 处理黑名单源
    # ─────────────────────────────────────────────────────────────────────────
    black_domains = set()
    block_stats = {}
    
    for url in block_urls:
        lines = downloaded.get(url, [])
        if lines:
            domains = parallel_extract(lines, is_whitelist=False)
            black_domains.update(domains)
            block_stats[url] = len(domains)
            log(f"  │  黑名单源：{len(domains):,} 条 <- {url}", log_file=log_file)
        else:
            log(f"  │  黑名单源：0 条（下载失败）<- {url}", LogLevel.ERROR, log_file=log_file)
        
        del lines
        gc.collect()

    # ─────────────────────────────────────────────────────────────────────────
    # 处理白名单源
    # ─────────────────────────────────────────────────────────────────────────
    white_domains = set()
    white_stats = {}
    
    for url in white_urls:
        lines = downloaded.get(url, [])
        if lines:
            domains = parallel_extract(lines, is_whitelist=True)
            white_domains.update(domains)
            white_stats[url] = len(domains)
            log(f"  │  白名单源：{len(domains):,} 条 <- {url}", log_file=log_file)
        else:
            log(f"  │  白名单源：0 条（下载失败）<- {url}", LogLevel.ERROR, log_file=log_file)
        
        del lines
        gc.collect()

    # ─────────────────────────────────────────────────────────────────────────
    # 处理预设规则组
    # ─────────────────────────────────────────────────────────────────────────
    preset_domains = set()
    for preset_key in presets:
        if preset_key in final_cache:
            preset_count = len(final_cache[preset_key])
            preset_domains.update(final_cache[preset_key])
            log(f"  │  预设规则：{preset_count:,} 条 <- {preset_key}", log_file=log_file)

    # ─────────────────────────────────────────────────────────────────────────
    # 合并黑名单
    # ─────────────────────────────────────────────────────────────────────────
    all_black = black_domains | preset_domains
    
    # 处理自定义黑名单
    custom_black_set = process_custom_list(custom_black, downloaded, "黑名单", log_file)
    if custom_black_set:
        log(f"  │  自定义黑名单：{len(custom_black_set):,} 条", log_file=log_file)
        all_black.update(custom_black_set)
    
    log(f"  │  黑名单合计：{len(all_black):,} 条", log_file=log_file)

    # ─────────────────────────────────────────────────────────────────────────
    # 处理白名单
    # ─────────────────────────────────────────────────────────────────────────
    all_white = white_domains.copy()
    
    # 处理自定义白名单
    custom_white_set = process_custom_list(custom_white, downloaded, "白名单", log_file)
    if custom_white_set:
        log(f"  │  自定义白名单：{len(custom_white_set):,} 条", log_file=log_file)
        all_white.update(custom_white_set)

    # ─────────────────────────────────────────────────────────────────────────
    # 白名单过滤
    # ─────────────────────────────────────────────────────────────────────────
    after_filter = filter_whitelist(all_black, all_white)
    filtered_count = len(all_black) - len(after_filter)
    log(f"  │  白名单过滤：移除 {filtered_count:,} 条", log_file=log_file)

    # ─────────────────────────────────────────────────────────────────────────
    # 子域去重
    # ─────────────────────────────────────────────────────────────────────────
    final_domains = remove_subdomains(after_filter)
    removed_count = len(after_filter) - len(final_domains)
    final_count = len(final_domains)
    log(f"  │  子域去重：移除 {removed_count:,} 条", log_file=log_file)
    log(f"  └─ 最终结果：{final_count:,} 条（已保存到缓存）", log_file=log_file)

    # 缓存最终结果（供预设组引用）
    final_cache[key] = final_domains

    # ─────────────────────────────────────────────────────────────────────────
    # 统计信息
    # ─────────────────────────────────────────────────────────────────────────
    stats = {
        "key": key,
        "display_name": title,
        "description": description,
        "final_count": final_count,
        "block_sources": block_stats,
        "white_sources": white_stats,
        "black_after_extract": len(all_black),
        "after_filter": len(after_filter),
        "presets": presets,
    }
    stats_collection[key] = stats

    # ─────────────────────────────────────────────────────────────────────────
    # 保存文件（非预设组）
    # ─────────────────────────────────────────────────────────────────────────
    if not is_preset:
        group_dir = output_root / key
        group_dir.mkdir(parents=True, exist_ok=True)
        save_domains(final_domains, group_dir, title, description, formats)


# ═══════════════════════════════════════════════════════════════════════════════
# 配置加载和验证
# ═══════════════════════════════════════════════════════════════════════════════

def validate_config(presets: Dict, groups: Dict, log_file: Optional[Path] = None) -> bool:
    """
    验证配置的有效性
    
    检查项：
    - 预设和规则组必须是字典
    - 预设和规则组的 blocklist/whitelist 必须是列表
    - 每个规则组必须有 title 或 display_name
    - 规则组的 preset_names 必须是列表
    
    参数：
        presets: 预设配置字典
        groups: 规则组配置字典
        log_file: 日志文件路径
    
    返回：
        True 如果配置有效，否则 False
    """
    errors = []
    
    # 验证预设
    for name, cfg in presets.items():
        if not isinstance(cfg, dict):
            errors.append(f"预设'{name}' 配置必须是字典")
            continue
        
        if not isinstance(cfg.get("blocklist", []), list):
            errors.append(f"预设'{name}' blocklist 必须是列表")
        
        if not isinstance(cfg.get("whitelist", []), list):
            errors.append(f"预设'{name}' whitelist 必须是列表")
    
    # 验证规则组
    for name, cfg in groups.items():
        if not isinstance(cfg, dict):
            errors.append(f"规则组'{name}' 配置必须是字典")
            continue
        
        if "title" not in cfg and "display_name" not in cfg:
            errors.append(f"规则组'{name}' 缺少必需的 title 或 display_name")
        
        if not isinstance(cfg.get("preset_names", []), list):
            errors.append(f"规则组'{name}' preset_names 必须是列表")
        
        if not isinstance(cfg.get("blocklist", []), list):
            errors.append(f"规则组'{name}' blocklist 必须是列表")
        
        if not isinstance(cfg.get("whitelist", []), list):
            errors.append(f"规则组'{name}' whitelist 必须是列表")
    
    # 输出所有错误
    if errors:
        for error in errors:
            log(error, LogLevel.ERROR, log_file)
        return False
    
    return True


def load_config() -> Tuple[Dict, Dict]:
    """
    加载配置文件（config.yaml）
    
    期望的配置文件位置：data/script/config.yaml
    
    配置结构：
        presets:
            preset_name:
                blocklist: [urls...]
                whitelist: [urls...]
        
        groups:
            group_name:
                title: "显示名称"          # 或 display_name
                description: "描述"
                blocklist: [urls...]
                whitelist: [urls...]
                preset_names: [names...]   # 要引用的预设
                custom_blacklist: [...]    # 自定义黑名单
                custom_whitelist: [...]    # 自定义白名单
                formats: [domains, adblock, hosts, clash, singbox]
    
    返回：
        (预设配置字典, 规则组配置字典) 元组
    """
    path = Path("data/script/config.yaml")
    
    if not path.is_file():
        log_error("错误：缺少 data/script/config.yaml 文件")
        sys.exit(1)
    
    try:
        with path.open(encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
    except yaml.YAMLError as e:
        log_error(f"config.yaml 解析失败：{e}")
        sys.exit(1)
    except Exception as e:
        log_error(f"config.yaml 读取失败：{e}")
        sys.exit(1)

    presets = data.get("presets", {})
    groups = data.get("groups", {})

    # 标准化规则组配置
    for conf in groups.values():
        # use_presets 兼容性处理 -> preset_names
        use_presets = conf.pop("use_presets", [])
        conf["preset_names"] = use_presets if isinstance(use_presets, list) else []
        
        # 标准化 display_name 字段
        if "display_name" not in conf and "title" in conf:
            conf["display_name"] = conf["title"]
        
        # 设置默认值
        conf.setdefault("blocklist", [])
        conf.setdefault("whitelist", [])
        conf.setdefault("custom_blacklist", [])
        conf.setdefault("custom_whitelist", [])
        conf.setdefault("formats", ["domains"])

    log(f"✓ 配置已加载：{len(presets)} 个预设，{len(groups)} 个规则组")
    
    return presets, groups


# ═══════════════════════════════════════════════════════════════════════════════
# 主程序入口
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    """
    主函数
    
    执行流程：
    1. 初始化输出目录和日志文件
    2. 加载并验证配置
    3. 收集所有需要下载的 URL
    4. 并行下载所有规则源
    5. 分两个阶段处理规则组：
       - 阶段 1：处理预设组（不输出文件）
       - 阶段 2：处理普通规则组（输出文件）
    6. 生成 README.md
    7. 输出统计信息
    """
    start_time = time.time()
    
    # 打印欢迎信息
    print("=" * 80)
    print("Domain Filter - 域名过滤工具".center(80))
    print("=" * 80)
    print()
    
    # 初始化输出目录
    output_root = Path("data/rules")
    output_root.mkdir(parents=True, exist_ok=True)

    main_log = output_root / "log.txt"
    
    # 清空旧日志文件
    if main_log.exists():
        main_log.unlink()
    
    log("开始执行域名过滤工具", log_file=main_log)

    # ─────────────────────────────────────────────────────────────────────────
    # 加载和验证配置
    # ─────────────────────────────────────────────────────────────────────────
    try:
        presets_cfg, groups_cfg = load_config()
    except (yaml.YAMLError, IOError, OSError) as e:
        log_error(f"配置加载失败：{e}")
        log(traceback.format_exc(), LogLevel.ERROR, main_log)
        sys.exit(1)
    except Exception as e:
        log_error(f"未预期的错误：{e}")
        log(traceback.format_exc(), LogLevel.ERROR, main_log)
        sys.exit(1)

    # 验证配置有效性
    if not validate_config(presets_cfg, groups_cfg, main_log):
        sys.exit(1)

    # ─────────────────────────────────────────────────────────────────────────
    # 收集所有 URL
    # ─────────────────────────────────────────────────────────────────────────
    all_urls = set()
    for config in {**presets_cfg, **groups_cfg}.values():
        all_urls.update(config.get("blocklist", []))
        all_urls.update(config.get("whitelist", []))
        
        # 添加自定义黑名单中的 URL
        for item in config.get("custom_blacklist", []):
            if isinstance(item, str) and item.strip().startswith(('http://', 'https://')):
                all_urls.add(item.strip())
        
        # 添加自定义白名单中的 URL
        for item in config.get("custom_whitelist", []):
            if isinstance(item, str) and item.strip().startswith(('http://', 'https://')):
                all_urls.add(item.strip())

    # ─────────────────────────────────────────────────────────────────────────
    # 下载所有规则源
    # ─────────────────────────────────────────────────────────────────────────
    try:
        downloaded = download_all(list(all_urls), main_log)
    except (IOError, OSError) as e:
        log_error(f"文件 I/O 错误：{e}")
        log(traceback.format_exc(), LogLevel.ERROR, main_log)
        sys.exit(1)
    except Exception as e:
        log_error(f"下载过程中出现错误：{e}")
        log(traceback.format_exc(), LogLevel.ERROR, main_log)
        sys.exit(1)

    final_cache = {}
    all_stats = {}

    # ─────────────────────────────────────────────────────────────────────────
    # 阶段 1：处理预设组（不输出文件）
    # ─────────────────────────────────────────────────────────────────────────
    log("\n" + "=" * 80, log_file=main_log)
    log("阶段 1：处理预设规则组", log_file=main_log)
    log("=" * 80, log_file=main_log)
    
    for key, config in presets_cfg.items():
        try:
            process_group(
                key, config, downloaded, output_root, final_cache, all_stats, main_log, True
            )
        except Exception as e:
            log_error(f"预设规则组处理异常：{e}")
            log(traceback.format_exc(), LogLevel.ERROR, main_log)

    # ─────────────────────────────────────────────────────────────────────────
    # 阶段 2：处理普通规则组（输出文件）
    # ─────────────────────────────────────────────────────────────────────────
    log("\n" + "=" * 80, log_file=main_log)
    log("阶段 2：处理规则组并输出文件", log_file=main_log)
    log("=" * 80, log_file=main_log)
    
    for key, config in groups_cfg.items():
        try:
            process_group(
                key, config, downloaded, output_root, final_cache, all_stats, main_log, False
            )
        except Exception as e:
            log_error(f"规则组处理异常：{e}")
            log(traceback.format_exc(), LogLevel.ERROR, main_log)

    # ─────────────────────────────────────────────────────────────────────────
    # 生成 README
    # ─────────────────────────────────────────────────────────────────────────
    try:
        generate_readme(output_root, all_stats, groups_cfg)
    except Exception as e:
        log_error(f"README 生成失败：{e}")
        log(traceback.format_exc(), LogLevel.ERROR, main_log)

    # ─────────────────────────────────────────────────────────────────────────
    # 最终统计
    # ─────────────────────────────────────────────────────────────────────────
    elapsed = time.time() - start_time
    total_rules = sum(v.get("final_count", 0) for k, v in all_stats.items() if k in groups_cfg)
    
    log("\n" + "=" * 80, log_file=main_log)
    log(f"✓ 处理完成！总计 {total_rules:,} 条规则", log_file=main_log)
    log(f"✓ 耗时：{elapsed:.2f} 秒", log_file=main_log)
    log("=" * 80, log_file=main_log)
    
    # 刷新日志缓冲，确保所有日志都被写入
    _flush_log_buffer()
    
    gc.collect()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n用户中断（Ctrl+C）")
        log("用户中断", LogLevel.ERROR)
        sys.exit(130)
    except Exception as e:
        log_error(f"程序异常退出：{e}")
        traceback.print_exc()
        sys.exit(1)
