# 🛡️ Domain Filter

![Updated](https://img.shields.io/badge/Updated-2026--06--21_06:07:25-brightgreen?style=flat-square)

## 规则列表

- **Ads White** — 广告白名单列表。  
  `Domain · Wildcard` · [查看详情](data/rules/addata_white)
- **Ads Hosts** — 自用的轻量规则，包含稳定的国内维护源，去除白名单。日常去广告使用，hosts 格式无法拦截部分广告子域名。  
  `Hosts · Domain · Wildcard · AdBlock` · [查看详情](data/rules/ads_hosts)
- **Ads** — 额外收录一些国外域名，去除白名单，代理软件使用。  
  `AdBlock · Clash · Sing-box · QuantumultX · ShadowRocket · Surge · SmartDNS · Domain · Wildcard` · [查看详情](data/rules/ads)
- **Proxy** — 国内无法稳定连接、用于代理环境测试、国外TLD域名。  
  `Clash · Sing-box · QuantumultX · ShadowRocket · Surge · Domain · Wildcard` · [查看详情](data/rules/proxy)
- **Direct Fix** — 国内连接状态好、代理可能出现问题域名，要优先于proxy组。  
  `Clash · Sing-box · QuantumultX · ShadowRocket · Surge · Domain · Wildcard` · [查看详情](data/rules/direct_fix)

*2026-06-21 06:07:25 (CST)*

