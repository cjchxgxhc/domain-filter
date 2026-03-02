# 🛡️ Domain Filter

![Last Update](https://img.shields.io/badge/Last_Update-2026--03--03_05:36:06-green?style=flat-square)

这是一个自动合并多源规则、精准去重并移除冗余子域的过滤列表。

## 📊 规则组

### Ads Blocklist Big

额外添加了国外维护的规则源，建议用于代理程序。

**规则数量**：`101,170`

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

---

### Ads Blocklist China

针对中国地区，屏蔽广告联盟、应用广告、日志收集，包含限制应用功能的域名，建议有经验的用户使用。

**规则数量**：Domains `47,358`　Hosts `47,358`　AdBlock `38,273`　Clash / Mrs `38,273`　Sing-box / Srs `38,273`

<details><summary>Domains</summary>

```
https://raw.githubusercontent.com/cjchxgxhc/domain-filter/refs/heads/main/data/rules/ads/domains.txt
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

---

### Proxy

需要被代理的域名。

**规则数量**：`22,999`

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

---

### Direct Fix

不应被代理的域名。

**规则数量**：`744`

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

---

*更新时间：2026-03-03 05:36:06（北京时间）*
