# Domain Filter Rules

这是一个由 domain-filter 工具生成的规则集仓库。

**最后更新时间 (北京时间):** 2026-01-28 17:51:32 CST

## 规则组概览

### HaGeZi's Pro++ mini Blocklist
- **域名数量:** 95071
- **黑名单来源:**
  - [pro.plus.mini.txt](https://raw.githubusercontent.com/hagezi/dns-blocklists/refs/heads/main/adblock/pro.plus.mini.txt)
- **白名单来源:**
  - [ads_white.txt](https://raw.githubusercontent.com/cjchxgxhc/domain-filter/refs/heads/main/rules/ads_white.txt)
  - [white.txt](https://raw.githubusercontent.com/217heidai/adblockfilters/refs/heads/main/rules/white.txt)
- **输出目录:** [OUTPUT/HaGeZi_s_Pro_mini_Blocklist/](OUTPUT/HaGeZi_s_Pro_mini_Blocklist/)

### ads
- **域名数量:** 20892
- **黑名单来源:**
  - [ads.txt](https://raw.githubusercontent.com/cjchxgxhc/domain-filter/refs/heads/main/rules/ads.txt)
  - [adblockdnslite.txt](https://raw.githubusercontent.com/Aethersailor/adblockfilters-modified/refs/heads/main/rules/adblockdnslite.txt)
  - [AWAvenue-Ads-Rule.txt](https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/AWAvenue-Ads-Rule.txt)
  - [adblockdnslite.txt](https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockdnslite.txt)
  - [%E8%87%AA%E5%AE%9A%E4%B9%89.prop](https://raw.githubusercontent.com/lingeringsound/10007_auto/refs/heads/master/configure/%E8%87%AA%E5%AE%9A%E4%B9%89.prop)
  - [abp.txt](https://raw.githubusercontent.com/Cats-Team/dns-filter/main/abp.txt)
  - [dnslist.txt](https://raw.githubusercontent.com/damengzhu/banad/refs/heads/main/dnslist.txt)
  - [native.oppo-realme.txt](https://raw.githubusercontent.com/hagezi/dns-blocklists/refs/heads/main/domains/native.oppo-realme.txt)
  - [native.xiaomi.txt](https://raw.githubusercontent.com/hagezi/dns-blocklists/refs/heads/main/adblock/native.xiaomi.txt)
- **白名单来源:**
  - [ads_white.txt](https://raw.githubusercontent.com/cjchxgxhc/domain-filter/refs/heads/main/rules/ads_white.txt)
  - [anti-ad-white-for-clash.yaml](https://raw.githubusercontent.com/privacy-protection-tools/dead-horse/master/anti-ad-white-for-clash.yaml)
  - [white.txt](https://raw.githubusercontent.com/217heidai/adblockfilters/refs/heads/main/rules/white.txt)
- **输出目录:** [OUTPUT/ads/](OUTPUT/ads/)

### proxy
- **域名数量:** 25322
- **黑名单来源:**
  - [proxy.list](https://github.com/DustinWin/ruleset_geodata/releases/download/mihomo-ruleset/proxy.list)
  - [tld-proxy.list](https://github.com/DustinWin/ruleset_geodata/releases/download/mihomo-ruleset/tld-proxy.list)
  - [networktest.list](https://github.com/DustinWin/ruleset_geodata/releases/download/mihomo-ruleset/networktest.list)
  - [proxy.txt](https://raw.githubusercontent.com/cjchxgxhc/domain-filter/refs/heads/main/rules/proxy.txt)
- **白名单来源:**
  - [Microsoft.list](https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Clash/Microsoft/Microsoft.list)
  - [Apple.list](https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Clash/Apple/Apple.list)
  - [GoogleFCM.list](https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Clash/GoogleFCM/GoogleFCM.list)
  - [doh-vpn-proxy-bypass-onlydomains.txt](https://gitlab.com/hagezi/mirror/-/raw/main/dns-blocklists/wildcard/doh-vpn-proxy-bypass-onlydomains.txt)
- **输出目录:** [OUTPUT/proxy/](OUTPUT/proxy/)

## 统计
- **总规则组数:** 3
- **总域名数量:** 141285

## 使用说明
1. 每个规则组目录下包含相应的格式文件（如 adblock.txt、clash.yaml、domains.txt）。
2. 支持的格式包括 AdBlock、Clash YAML 和纯域名列表。
3. 规则由多个源自动聚合、去重和过滤生成。

## 生成工具
此仓库由 [domain-filter](https://github.com/cjchxgxhc/domain-filter) 工具自动生成和更新。
