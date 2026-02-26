# 🛡️ Domain Filter

![Last Update](https://img.shields.io/badge/Last_Update-2026--02--26_18:34:55-green?style=flat-square)

这是一个自动合并多源规则、精准去重并移除冗余子域的过滤列表。

## 📊 规则组详情统计

| 规则组名称 | 描述 | 规则数量 | 获取链接 |
| :--- | :--- | :--- | :--- |
| **Ads Blocklist Large** | 适用于代理程序。 | `114,398` | [`AdBlock`](https://raw.githubusercontent.com/cjchxgxhc/domain-filter/refs/heads/main/data/rules/ads_big/adblock.txt) · [`Clash`](https://raw.githubusercontent.com/cjchxgxhc/domain-filter/refs/heads/main/data/rules/ads_big/clash.yaml) · [`Mrs`](https://raw.githubusercontent.com/cjchxgxhc/domain-filter/refs/heads/main/data/rules/ads_big/clash.mrs) · [`Sing-box`](https://raw.githubusercontent.com/cjchxgxhc/domain-filter/refs/heads/main/data/rules/ads_big/singbox.json) · [`Srs`](https://raw.githubusercontent.com/cjchxgxhc/domain-filter/refs/heads/main/data/rules/ads_big/singbox.srs) |
| **Ads Blocklist China** | 针对中文移动端广告。 | Domains: 43,183 / Hosts: 43,183 / AdBlock: 36,338 / Clash: 36,338 / Sing-box: 36,338 | [`Domains`](https://raw.githubusercontent.com/cjchxgxhc/domain-filter/refs/heads/main/data/rules/ads/domains.txt) · [`AdBlock`](https://raw.githubusercontent.com/cjchxgxhc/domain-filter/refs/heads/main/data/rules/ads/adblock.txt) · [`Hosts`](https://raw.githubusercontent.com/cjchxgxhc/domain-filter/refs/heads/main/data/rules/ads/hosts.txt) · [`Clash`](https://raw.githubusercontent.com/cjchxgxhc/domain-filter/refs/heads/main/data/rules/ads/clash.yaml) · [`Mrs`](https://raw.githubusercontent.com/cjchxgxhc/domain-filter/refs/heads/main/data/rules/ads/clash.mrs) · [`Sing-box`](https://raw.githubusercontent.com/cjchxgxhc/domain-filter/refs/heads/main/data/rules/ads/singbox.json) · [`Srs`](https://raw.githubusercontent.com/cjchxgxhc/domain-filter/refs/heads/main/data/rules/ads/singbox.srs) |
| **Proxy** | 需要被代理的域名。 | `23,140` | [`Clash`](https://raw.githubusercontent.com/cjchxgxhc/domain-filter/refs/heads/main/data/rules/proxy/clash.yaml) · [`Mrs`](https://raw.githubusercontent.com/cjchxgxhc/domain-filter/refs/heads/main/data/rules/proxy/clash.mrs) · [`Sing-box`](https://raw.githubusercontent.com/cjchxgxhc/domain-filter/refs/heads/main/data/rules/proxy/singbox.json) · [`Srs`](https://raw.githubusercontent.com/cjchxgxhc/domain-filter/refs/heads/main/data/rules/proxy/singbox.srs) |
| **Direct Fix** | 不应被代理的域名。 | `618` | [`Clash`](https://raw.githubusercontent.com/cjchxgxhc/domain-filter/refs/heads/main/data/rules/direct_fix/clash.yaml) · [`Mrs`](https://raw.githubusercontent.com/cjchxgxhc/domain-filter/refs/heads/main/data/rules/direct_fix/clash.mrs) · [`Sing-box`](https://raw.githubusercontent.com/cjchxgxhc/domain-filter/refs/heads/main/data/rules/direct_fix/singbox.json) · [`Srs`](https://raw.githubusercontent.com/cjchxgxhc/domain-filter/refs/heads/main/data/rules/direct_fix/singbox.srs) |

## 📖 使用说明

### Clash/Mihomo
```yaml
rule-providers:
  example:
    type: http
    behavior: domain
    format: mrs
    url: https://raw.githubusercontent.com/cjchxgxhc/domain-filter/refs/heads/main/data/rules/example/clash.mrs
    interval: 86400

rules:
  - RULE-SET,example,REJECT
```

### sing-box
```json
{
  "route": {
    "rule_set": [
      {
        "type": "remote",
        "tag": "example",
        "format": "binary",
        "url": "https://raw.githubusercontent.com/cjchxgxhc/domain-filter/refs/heads/main/data/rules/example/singbox.srs",
        "download_detour": "direct"
      }
    ],
    "rules": [
      {
        "rule_set": ["example"],
        "outbound": "block"
      }
    ]
  }
}
```

### AdBlock
直接添加订阅链接到 AdGuard、uBlock Origin 等扩展:
```
https://raw.githubusercontent.com/cjchxgxhc/domain-filter/refs/heads/main/data/rules/example/adblock.txt
```

### Hosts
下载 hosts 文件并合并到系统 hosts 文件:
```bash
curl https://raw.githubusercontent.com/cjchxgxhc/domain-filter/refs/heads/main/data/rules/example/hosts.txt >> /etc/hosts
```

---
*更新时间：2026-02-26 18:34:55（北京时间）*
