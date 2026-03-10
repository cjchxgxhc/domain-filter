# 🛡️ Domain Filter

![Last Update](https://img.shields.io/badge/Last_Update-2026--03--11_05:30:12-green?style=flat-square)

这是一个自动合并多源规则、精准去重并移除冗余子域的过滤列表。

## 📊 规则组

### Ads Blocklist China

主要屏蔽手机端广告，包含限制应用功能的域名。

**规则数量**：Domain `10,801`　Hosts `10,801`　AdBlock `8,664`　Clash / Mrs `8,664`　Sing-box / Srs `8,664`

<details><summary>Domain</summary>

```
https://raw.githubusercontent.com/cjchxgxhc/domain-filter/refs/heads/main/data/rules/ads/domain.txt
```

</details>

<details><summary>AdBlock</summary>

```
https://raw.githubusercontent.com/cjchxgxhc/domain-filter/refs/heads/main/data/rules/ads/adblock.txt
```

</details>

<details><summary>Hosts</summary>

```
https://raw.githubusercontent.com/cjchxgxhc/domain-filter/refs/heads/main/data/rules/ads/hosts.txt
```

</details>

<details><summary>Clash / Mrs</summary>

```
https://raw.githubusercontent.com/cjchxgxhc/domain-filter/refs/heads/main/data/rules/ads/clash.yaml
```

```
https://raw.githubusercontent.com/cjchxgxhc/domain-filter/refs/heads/main/data/rules/ads/clash.mrs
```

</details>

<details><summary>Sing-box / Srs</summary>

```
https://raw.githubusercontent.com/cjchxgxhc/domain-filter/refs/heads/main/data/rules/ads/singbox.json
```

```
https://raw.githubusercontent.com/cjchxgxhc/domain-filter/refs/heads/main/data/rules/ads/singbox.srs
```

</details>

<details><summary>引用源</summary>

- https://github.com/DustinWin/ruleset_geodata/releases/download/mihomo-ruleset/tld-proxy.list
- https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockdomainlite.txt
- https://raw.githubusercontent.com/217heidai/adblockfilters/refs/heads/main/rules/white.txt
- https://raw.githubusercontent.com/Cats-Team/AdRules/refs/heads/script/mod/rules/dns-allowlist.txt
- https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/AWAvenue-Ads-Rule.txt
- https://raw.githubusercontent.com/afwfv/DD-AD/refs/heads/main/rule/DD-AD.txt
- https://raw.githubusercontent.com/cjchxgxhc/domain-filter/refs/heads/main/data/self/ads.txt
- https://raw.githubusercontent.com/cjchxgxhc/domain-filter/refs/heads/main/data/self/ads_white.txt
- https://raw.githubusercontent.com/cjchxgxhc/self/refs/heads/main/rules/domains.txt
- https://raw.githubusercontent.com/hagezi/dns-blocklists/refs/heads/main/domains/native.oppo-realme.txt
- https://raw.githubusercontent.com/lingeringsound/10007_auto/refs/heads/master/Adaway_white_list.prop
- https://raw.githubusercontent.com/lingeringsound/10007_auto/refs/heads/master/configure/%E8%87%AA%E5%AE%9A%E4%B9%89.prop
- https://raw.githubusercontent.com/privacy-protection-tools/anti-AD/master/anti-ad-domains.txt
- https://raw.githubusercontent.com/qq5460168/666/refs/heads/master/allow-ublock.txt
- https://raw.githubusercontent.com/qq5460168/dangchu/main/black.txt

</details>

---

### Ads Blocklist Big

优秀规则源的合并，尽量避免误杀。

**规则数量**：`456,901`

<details><summary>AdBlock</summary>

```
https://raw.githubusercontent.com/cjchxgxhc/domain-filter/refs/heads/main/data/rules/ads_big/adblock.txt
```

</details>

<details><summary>Clash / Mrs</summary>

```
https://raw.githubusercontent.com/cjchxgxhc/domain-filter/refs/heads/main/data/rules/ads_big/clash.yaml
```

```
https://raw.githubusercontent.com/cjchxgxhc/domain-filter/refs/heads/main/data/rules/ads_big/clash.mrs
```

</details>

<details><summary>Sing-box / Srs</summary>

```
https://raw.githubusercontent.com/cjchxgxhc/domain-filter/refs/heads/main/data/rules/ads_big/singbox.json
```

```
https://raw.githubusercontent.com/cjchxgxhc/domain-filter/refs/heads/main/data/rules/ads_big/singbox.srs
```

</details>

<details><summary>引用源</summary>

- https://raw.githubusercontent.com/217heidai/adblockfilters/refs/heads/main/rules/white.txt
- https://raw.githubusercontent.com/Cats-Team/AdRules/main/adrules_domainset.txt
- https://raw.githubusercontent.com/Cats-Team/AdRules/refs/heads/script/mod/rules/dns-allowlist.txt
- https://raw.githubusercontent.com/cjchxgxhc/domain-filter/refs/heads/main/data/self/ads_white.txt
- https://raw.githubusercontent.com/cjchxgxhc/self/refs/heads/main/rules/domains.txt
- https://raw.githubusercontent.com/lingeringsound/10007_auto/refs/heads/master/Adaway_white_list.prop
- https://raw.githubusercontent.com/privacy-protection-tools/anti-AD/master/anti-ad-clash.yaml
- https://raw.githubusercontent.com/privacy-protection-tools/anti-AD/master/anti-ad-domains.txt
- https://raw.githubusercontent.com/qq5460168/666/refs/heads/master/allow-ublock.txt
- https://raw.githubusercontent.com/sjhgvr/oisd/refs/heads/main/abp_big.txt

</details>

---

### Proxy

需要被代理的域名。

**规则数量**：`23,024`

<details><summary>Clash / Mrs</summary>

```
https://raw.githubusercontent.com/cjchxgxhc/domain-filter/refs/heads/main/data/rules/proxy/clash.yaml
```

```
https://raw.githubusercontent.com/cjchxgxhc/domain-filter/refs/heads/main/data/rules/proxy/clash.mrs
```

</details>

<details><summary>Sing-box / Srs</summary>

```
https://raw.githubusercontent.com/cjchxgxhc/domain-filter/refs/heads/main/data/rules/proxy/singbox.json
```

```
https://raw.githubusercontent.com/cjchxgxhc/domain-filter/refs/heads/main/data/rules/proxy/singbox.srs
```

</details>

<details><summary>引用源</summary>

- https://github.com/DustinWin/ruleset_geodata/releases/download/mihomo-ruleset/proxy.list
- https://github.com/DustinWin/ruleset_geodata/releases/download/mihomo-ruleset/tld-proxy.list
- https://raw.githubusercontent.com/LM-Firefly/Rules/refs/heads/master/PROXY.list
- https://raw.githubusercontent.com/cjchxgxhc/domain-filter/refs/heads/main/data/self/FlClash_IP_Check.txt

</details>

---

### Direct Fix

不应被代理的域名。

**规则数量**：`741`

<details><summary>Clash / Mrs</summary>

```
https://raw.githubusercontent.com/cjchxgxhc/domain-filter/refs/heads/main/data/rules/direct_fix/clash.yaml
```

```
https://raw.githubusercontent.com/cjchxgxhc/domain-filter/refs/heads/main/data/rules/direct_fix/clash.mrs
```

</details>

<details><summary>Sing-box / Srs</summary>

```
https://raw.githubusercontent.com/cjchxgxhc/domain-filter/refs/heads/main/data/rules/direct_fix/singbox.json
```

```
https://raw.githubusercontent.com/cjchxgxhc/domain-filter/refs/heads/main/data/rules/direct_fix/singbox.srs
```

</details>

<details><summary>引用源</summary>

- https://github.com/DustinWin/ruleset_geodata/releases/download/mihomo-ruleset/fakeip-filter.list
- https://github.com/DustinWin/ruleset_geodata/releases/download/mihomo-ruleset/games-cn.list
- https://github.com/DustinWin/ruleset_geodata/releases/download/mihomo-ruleset/microsoft-cn.list
- https://github.com/DustinWin/ruleset_geodata/releases/download/mihomo-ruleset/private.list
- https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Clash/GoogleFCM/GoogleFCM.list
- https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Clash/NTPService/NTPService.list
- https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Clash/Notion/Notion_No_Resolve.yaml

</details>

---

*更新时间：2026-03-11 05:30:12（北京时间）*
