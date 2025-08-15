# 域名过滤器

一个高效的 Python 脚本，用于处理域名黑名单和白名单，生成 AdBlock、Clash YAML 和 Mihomo MRS 格式的规则文件。

## 功能
- 从 URL 或本地文件下载规则。
- 提取 AdBlock（`||domain^`）、Clash（`DOMAIN-SUFFIX`）等格式的域名。
- 去重：允许父域名和子域名共存，优先保留父域名（如 `example.com` 覆盖 `sub.sub.example.com`）。
- 精确过滤白名单（完全匹配），如 `example.com` 在白名单中被移除。
- 输出：
  - `OUTPUT/ads/adblock.txt`：AdBlock 格式（`||domain^`）
  - `OUTPUT/ads/clash.yaml`：Clash YAML 格式（`payload: - +.domain`）
  - `OUTPUT/ads/clash.mrs`：Mihomo MRS 格式
  - 类似文件在 `OUTPUT/proxy/`

## 安装
1. 克隆仓库：
   ```bash
   git clone https://github.com/yourusername/domain-filter.git
   cd domain-filter
   ```
2. 安装依赖：
   ```bash
   pip install requests
   ```

## 使用
1. **准备本地规则文件**：
   - 创建 `rules/ads.txt`、`rules/proxy.txt`、`rules/ads_white.txt`、`rules/proxy_white.txt`。
   - 示例 `rules/ads.txt`：
     ```
     ||example.com^
     DOMAIN-SUFFIX,tracker.com
     *.test.com
     ```
   - 示例 `rules/ads_white.txt`：
     ```
     @@||example.com^
     ```
   - 如果不需要本地文件，从 `filter.py` 的 `BLACKLIST_CONFIG` 和 `WHITELIST_CONFIG` 中移除 `file://` 条目。

2. **运行脚本**：
   ```bash
   python filter.py
   ```
   输出文件生成在：
   - `OUTPUT/ads/adblock.txt`, `OUTPUT/ads/clash.yaml`, `OUTPUT/ads/clash.mrs`
   - `OUTPUT/proxy/adblock.txt`, `OUTPUT/proxy/clash.yaml`, `OUTPUT/proxy/clash.mrs`

3. **验证输出**：
   - 检查 `adblock.txt`：每行格式为 `||domain^`。
   - 检查 `clash.yaml`：格式为 `payload:\n  - +.domain`。
   - MRS 文件由 GitHub Actions 生成。

## 配置
编辑 `filter.py` 中的 `BLACKLIST_CONFIG` 和 `WHITELIST_CONFIG`：
- `ads` 组：广告过滤规则。
- `proxy` 组：代理相关规则。
- 确保本地文件存在，或移除 `file://` 配置。
- 示例：
  ```python
  BLACKLIST_CONFIG = {
      "ads": [
          "file://./rules/ads.txt",
          "https://adrules.top/dns.txt",
          ...
      ],
      ...
  }
  ```

## GitHub Actions
- 工作流（`.github/workflows/ci.yml`）在 push、pull request、每天定时（UTC 00:00）或手动触发时运行。
- 生成并提交 `OUTPUT/组名/` 下的 `.txt`、`.yaml`、`.mrs` 文件。
