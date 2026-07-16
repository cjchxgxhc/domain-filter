# 🛡️ Domain Filter

![Updated](https://img.shields.io/badge/Updated-2026--07--17_06:03:50-brightgreen?style=flat-square)

## 规则列表

- **Ads Hosts** — 主要引用 217heidai/adblockfilters (lite) 项目规则，增添：手机端应用程序广告、子域名（用于hosts格式）；删除：白名单域名、proxy_tld（减小大小）。  
  `Hosts · Domain` · [查看详情](data/rules/ads_hosts)
- **Ads** — 主要引用 217heidai/adblockfilters (lite)、lingeringsound/10007、privacy-protection-tools/anti-AD 项目规则，增添：手机端应用程序广告；删除：白名单域名、proxy_tld（减小大小）。  
  `AdBlock · Clash · Sing-box · QuantumultX · ShadowRocket · Surge · SmartDNS · Domain · Wildcard` · [查看详情](data/rules/ads)
- **Ads Proxy** — 国外广告规则，不保证正常网络环境误杀和拦截率，国内流量不应经过此规则过滤。  
  `Clash · Sing-box · QuantumultX · ShadowRocket · Surge · SmartDNS · Domain · Wildcard` · [查看详情](data/rules/ads_proxy)
- **Proxy** — 所有需要被代理分流的域名。  
  `Clash · Sing-box · QuantumultX · ShadowRocket · Surge · Domain · Wildcard` · [查看详情](data/rules/proxy)
- **Direct Fix** — 修复可能被proxy组错误分流的直连域名。  
  `Clash · Sing-box · QuantumultX · ShadowRocket · Surge · Domain · Wildcard` · [查看详情](data/rules/direct_fix)

*2026-07-17 06:03:50 (CST)*

