# 域名过滤器

一个Python脚本，用于处理域名黑名单和白名单，生成AdBlock、Clash YAML和Mihomo MRS格式的输出。

## 功能
- 从URL下载规则
- 提取AdBlock格式和自定义规则中的域名
- 按AdBlock规则去重（父域名覆盖子域名）
- 移除完全匹配的白名单域名
- 输出AdBlock（`||domain^`）、Clash YAML（`payload: - +.domain`）和Mihomo MRS格式

## 安装
1. 克隆仓库：
   ```bash
   git clone https://github.com/yourusername/domain-filter.git
   cd domain-filter
