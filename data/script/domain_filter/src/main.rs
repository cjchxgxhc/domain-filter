// domain_filter — 高性能域名过滤工具
//
// 用法：
//   domain_filter discard_suffix   # stdin: current\n---\nref  → stdout: 过滤后
//   domain_filter match_suffix     # stdin: current\n---\nref  → stdout: 保留的
//   domain_filter dedup            # stdin: domains           → stdout: 去冗余子域后
//
// stdin/stdout 均为每行一个域名，UTF-8，LF 分隔。
// discard_suffix / match_suffix 用 "---" 单独一行分隔 current 和 ref 两段。

use std::io::{self, BufWriter, Read, Write};
use rustc_hash::FxHashMap;

// ── Trie ─────────────────────────────────────────────────────────────────────
//
// Arena Trie，所有节点存在连续 Vec 中，用 u32 索引，避免指针追踪和堆碎片。
// 键为反转的域名标签序列：
//   "foo.bar.cn" → 依次查 cn → bar → foo
//
// 标签字符串池（intern）：每个唯一标签只存一份，查找时用 u32 id 比较，
// 比字符串比较快，且 FxHashMap 对 u32 key 几乎无哈希开销。

/// 单个 Trie 节点，children 和 is_end 合并，减少随机寻址。
struct Node {
    /// label_id → child node index
    children: FxHashMap<u32, u32>,
    is_end: bool,
}

impl Node {
    #[inline]
    fn new() -> Self {
        Self { children: FxHashMap::default(), is_end: false }
    }
}

struct Trie {
    nodes:     Vec<Node>,
    /// 标签字符串 → intern id（用 FxHashMap 加速短字符串查找）
    label_map: FxHashMap<Box<str>, u32>,
    label_cnt: u32,
}

impl Trie {
    fn new() -> Self {
        let mut nodes = Vec::with_capacity(4096);
        nodes.push(Node::new()); // root = index 0
        Self {
            nodes,
            label_map: FxHashMap::default(),
            label_cnt: 0,
        }
    }

    /// 返回 label 的 intern id，不存在则插入。
    /// if-let 两步：先借用查，缺失时再插入，稳定 API 且无额外 clone。
    #[inline]
    fn intern(&mut self, label: &str) -> u32 {
        if let Some(&id) = self.label_map.get(label) {
            return id;
        }
        let id = self.label_cnt;
        self.label_cnt += 1;
        self.label_map.insert(label.into(), id); // Box<str>：省一个 usize
        id
    }

    fn insert(&mut self, domain: &str) {
        let mut node_idx = 0u32;
        for label in domain.split('.').rev() {
            let lid = self.intern(label);
            // 先查再插，避免借用冲突
            if !self.nodes[node_idx as usize].children.contains_key(&lid) {
                let new_idx = self.nodes.len() as u32;
                self.nodes.push(Node::new());
                self.nodes[node_idx as usize].children.insert(lid, new_idx);
            }
            node_idx = self.nodes[node_idx as usize].children[&lid];
        }
        self.nodes[node_idx as usize].is_end = true;
    }

    /// domain 是否被 trie 中某条目覆盖（精确匹配或父域名匹配）。
    #[inline]
    fn is_covered(&self, domain: &str) -> bool {
        let mut node = &self.nodes[0];
        for label in domain.split('.').rev() {
            if node.is_end {
                return true;
            }
            let lid = match self.label_map.get(label) {
                Some(&id) => id,
                None      => return false,
            };
            match node.children.get(&lid) {
                Some(&idx) => node = &self.nodes[idx as usize],
                None       => return false,
            }
        }
        node.is_end
    }
}

// ── 输入解析 ─────────────────────────────────────────────────────────────────

fn read_stdin() -> String {
    // 预分配 8 MiB，域名列表通常在这个量级
    let mut buf = String::with_capacity(8 * 1024 * 1024);
    io::stdin().read_to_string(&mut buf).expect("读取 stdin 失败");
    buf
}

/// 按 "\n---\n" 分割为 (current, ref) 两段，借用原始字符串切片，零拷贝。
fn split_two_sets(input: &str) -> (Vec<&str>, Vec<&str>) {
    let sep = "\n---\n";
    if let Some(pos) = input.find(sep) {
        let a = parse_lines(&input[..pos]);
        let b = parse_lines(&input[pos + sep.len()..]);
        (a, b)
    } else {
        // 无分隔符：ref 为空
        (parse_lines(input), vec![])
    }
}

#[inline]
fn parse_lines(s: &str) -> Vec<&str> {
    s.lines()
        .map(str::trim)
        .filter(|s| !s.is_empty() && *s != "---")
        .collect()
}

// ── 过滤逻辑 ─────────────────────────────────────────────────────────────────

/// discard_suffix：移除 current 中被 ref 任意域名（或其父域名）覆盖的条目。
fn discard_suffix<'a>(current: &[&'a str], ref_domains: &[&str]) -> Vec<&'a str> {
    if ref_domains.is_empty() {
        return current.to_vec();
    }
    let mut trie = Trie::new();
    for d in ref_domains {
        trie.insert(d);
    }
    current.iter().copied().filter(|d| !trie.is_covered(d)).collect()
}

/// match_suffix：只保留 current 中被 ref 任意域名（或其父域名）覆盖的条目。
fn match_suffix<'a>(current: &[&'a str], ref_domains: &[&str]) -> Vec<&'a str> {
    if ref_domains.is_empty() {
        return vec![];
    }
    let mut trie = Trie::new();
    for d in ref_domains {
        trie.insert(d);
    }
    current.iter().copied().filter(|d| trie.is_covered(d)).collect()
}

/// dedup：去除冗余子域名。
/// 按层级数升序排列（父域名先处理），每个域名若尚未被 trie 覆盖则保留并插入。
fn dedup<'a>(domains: &[&'a str]) -> Vec<&'a str> {
    if domains.is_empty() {
        return vec![];
    }
    let mut sorted = domains.to_vec();
    // 按点数升序（层级浅的先处理），同层按字母序保证确定性
    sorted.sort_unstable_by_key(|d| {
        // 统计 '.' 个数：字节扫描，比 str::matches 快
        let dots = d.as_bytes().iter().filter(|&&b| b == b'.').count();
        (dots, *d)
    });

    let mut trie = Trie::new();
    let mut result: Vec<&'a str> = Vec::with_capacity(sorted.len() / 2);
    for domain in sorted {
        if !trie.is_covered(domain) {
            trie.insert(domain);
            result.push(domain);
        }
    }
    result
}

// ── 输出 ─────────────────────────────────────────────────────────────────────

/// 将域名列表写入 stdout，4 MiB BufWriter 减少系统调用次数。
fn write_lines(lines: &[&str]) {
    let stdout = io::stdout();
    let mut out = BufWriter::with_capacity(4 * 1024 * 1024, stdout.lock());
    for &line in lines {
        out.write_all(line.as_bytes()).unwrap();
        out.write_all(b"\n").unwrap();
    }
}

// ── 主入口 ────────────────────────────────────────────────────────────────────

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("用法：domain_filter <discard_suffix|match_suffix|dedup>");
        std::process::exit(1);
    }

    let mode  = args[1].as_str();
    let input = read_stdin();

    match mode {
        "discard_suffix" => {
            let (current, refs) = split_two_sets(&input);
            let result = discard_suffix(&current, &refs);
            write_lines(&result);
        }
        "match_suffix" => {
            let (current, refs) = split_two_sets(&input);
            let result = match_suffix(&current, &refs);
            write_lines(&result);
        }
        "dedup" => {
            let domains = parse_lines(&input);
            let result  = dedup(&domains);
            write_lines(&result);
        }
        _ => {
            eprintln!("未知模式：{mode}，可选：discard_suffix | match_suffix | dedup");
            std::process::exit(1);
        }
    }
}

// ── 单元测试 ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trie_exact() {
        let mut t = Trie::new();
        t.insert("example.com");
        assert!(t.is_covered("example.com"));
        assert!(!t.is_covered("other.com"));
    }

    #[test]
    fn test_trie_subdomain() {
        let mut t = Trie::new();
        t.insert("example.com");
        assert!(t.is_covered("foo.example.com"));
        assert!(t.is_covered("a.b.example.com"));
        assert!(!t.is_covered("notexample.com"));
    }

    #[test]
    fn test_trie_tld() {
        let mut t = Trie::new();
        t.insert("cn");
        assert!(t.is_covered("cn"));
        assert!(t.is_covered("foo.cn"));
        assert!(t.is_covered("foo.bar.cn"));
        assert!(!t.is_covered("com"));
    }

    #[test]
    fn test_discard_suffix_basic() {
        let current = vec!["foo.cn", "bar.com", "baz.io"];
        let refs    = vec!["cn", "io"];
        let result  = discard_suffix(&current, &refs);
        assert_eq!(result, vec!["bar.com"]);
    }

    #[test]
    fn test_match_suffix_basic() {
        let current = vec!["foo.cn", "bar.com", "baz.io"];
        let refs    = vec!["cn", "io"];
        let mut result = match_suffix(&current, &refs);
        result.sort();
        assert_eq!(result, vec!["baz.io", "foo.cn"]);
    }

    #[test]
    fn test_dedup_basic() {
        let domains    = vec!["foo.example.com", "example.com", "bar.example.com", "other.com"];
        let mut result = dedup(&domains);
        result.sort();
        assert_eq!(result, vec!["example.com", "other.com"]);
    }

    #[test]
    fn test_dedup_preserves_unrelated() {
        let domains    = vec!["a.com", "b.com", "c.a.com"];
        let mut result = dedup(&domains);
        result.sort();
        assert_eq!(result, vec!["a.com", "b.com"]);
    }

    #[test]
    fn test_empty_ref_discard() {
        let current = vec!["foo.com", "bar.com"];
        let result  = discard_suffix(&current, &[]);
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn test_empty_ref_match() {
        let current = vec!["foo.com", "bar.com"];
        let result  = match_suffix(&current, &[]);
        assert!(result.is_empty());
    }

    #[test]
    fn test_split_two_sets() {
        let input = "a.com\nb.com\n---\ncn\nio";
        let (cur, refs) = split_two_sets(input);
        assert_eq!(cur,  vec!["a.com", "b.com"]);
        assert_eq!(refs, vec!["cn", "io"]);
    }

    #[test]
    fn test_split_no_sep() {
        let input = "a.com\nb.com";
        let (cur, refs) = split_two_sets(input);
        assert_eq!(cur, vec!["a.com", "b.com"]);
        assert!(refs.is_empty());
    }
}
