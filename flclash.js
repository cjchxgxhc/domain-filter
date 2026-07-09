// FlClash 脚本覆写 v3
// 修复：\b 在 JS 正则里把下划线算作"单词字符"，导致类似 RO_speednode_0043
// 这种命名无法被 \bRO\b 匹配到（O 和 _ 之间没有边界）。
// 现在改用基于字母的手动边界 (?<![A-Za-z])CODE(?![A-Za-z])，
// 下划线/短横线/数字都能正确断词。

// ============ 国家/地区库 ============
const COUNTRY_MAP = [
  { code: "HK", cn: "香港", zh: ["香港", "港"], en: ["Hong Kong"] },
  { code: "TW", cn: "台湾", zh: ["台湾", "台灣"], en: ["Taiwan"] },
  { code: "MO", cn: "澳门", zh: ["澳门", "澳門"], en: ["Macau"] },
  { code: "CN", cn: "中国", zh: ["中国", "中國"], en: ["China"] },
  { code: "JP", cn: "日本", zh: ["日本"], en: ["Japan"] },
  { code: "KR", cn: "韩国", zh: ["韩国", "韓國"], en: ["Korea"] },
  { code: "MN", cn: "蒙古", zh: ["蒙古"], en: ["Mongolia"] },
  { code: "SG", cn: "新加坡", zh: ["新加坡", "狮城"], en: ["Singapore"] },
  { code: "MY", cn: "马来西亚", zh: ["马来西亚", "馬來西亞"], en: ["Malaysia"] },
  { code: "TH", cn: "泰国", zh: ["泰国", "泰國"], en: ["Thailand"] },
  { code: "VN", cn: "越南", zh: ["越南"], en: ["Vietnam"] },
  { code: "PH", cn: "菲律宾", zh: ["菲律宾", "菲律賓"], en: ["Philippines"] },
  { code: "ID", cn: "印尼", zh: ["印尼", "印度尼西亚"], en: ["Indonesia"] },
  { code: "KH", cn: "柬埔寨", zh: ["柬埔寨"], en: ["Cambodia"] },
  { code: "LA", cn: "老挝", zh: ["老挝", "寮國"], en: ["Laos"] },
  { code: "MM", cn: "缅甸", zh: ["缅甸", "緬甸"], en: ["Myanmar"] },
  { code: "BN", cn: "文莱", zh: ["文莱"], en: ["Brunei"] },
  { code: "IN", cn: "印度", zh: ["印度"], en: ["India"] },
  { code: "PK", cn: "巴基斯坦", zh: ["巴基斯坦"], en: ["Pakistan"] },
  { code: "BD", cn: "孟加拉", zh: ["孟加拉"], en: ["Bangladesh"] },
  { code: "LK", cn: "斯里兰卡", zh: ["斯里兰卡", "斯里蘭卡"], en: ["Sri Lanka"] },
  { code: "NP", cn: "尼泊尔", zh: ["尼泊尔", "尼泊爾"], en: ["Nepal"] },
  { code: "KZ", cn: "哈萨克斯坦", zh: ["哈萨克斯坦"], en: ["Kazakhstan"] },
  { code: "UZ", cn: "乌兹别克斯坦", zh: ["乌兹别克斯坦"], en: ["Uzbekistan"] },
  { code: "GE", cn: "格鲁吉亚", zh: ["格鲁吉亚", "格魯吉亞"], en: ["Georgia"] },
  { code: "AM", cn: "亚美尼亚", zh: ["亚美尼亚", "亞美尼亞"], en: ["Armenia"] },
  { code: "AZ", cn: "阿塞拜疆", zh: ["阿塞拜疆"], en: ["Azerbaijan"] },
  { code: "TR", cn: "土耳其", zh: ["土耳其"], en: ["Turkey", "Türkiye"] },
  { code: "IL", cn: "以色列", zh: ["以色列"], en: ["Israel"] },
  { code: "AE", cn: "阿联酋", zh: ["阿联酋", "阿聯酋"], en: ["UAE"] },
  { code: "SA", cn: "沙特阿拉伯", zh: ["沙特"], en: ["Saudi"] },
  { code: "QA", cn: "卡塔尔", zh: ["卡塔尔", "卡塔爾"], en: ["Qatar"] },
  { code: "KW", cn: "科威特", zh: ["科威特"], en: ["Kuwait"] },
  { code: "BH", cn: "巴林", zh: ["巴林"], en: ["Bahrain"] },
  { code: "OM", cn: "阿曼", zh: ["阿曼"], en: ["Oman"] },
  { code: "JO", cn: "约旦", zh: ["约旦", "約旦"], en: ["Jordan"] },
  { code: "LB", cn: "黎巴嫩", zh: ["黎巴嫩"], en: ["Lebanon"] },
  { code: "IQ", cn: "伊拉克", zh: ["伊拉克"], en: ["Iraq"] },
  { code: "IR", cn: "伊朗", zh: ["伊朗"], en: ["Iran"] },
  { code: "GB", cn: "英国", zh: ["英国", "英國"], en: ["United Kingdom"] },
  { code: "DE", cn: "德国", zh: ["德国", "德國"], en: ["Germany"] },
  { code: "FR", cn: "法国", zh: ["法国", "法國"], en: ["France"] },
  { code: "NL", cn: "荷兰", zh: ["荷兰", "荷蘭"], en: ["Netherlands"] },
  { code: "IE", cn: "爱尔兰", zh: ["爱尔兰", "愛爾蘭"], en: ["Ireland"] },
  { code: "IT", cn: "意大利", zh: ["意大利"], en: ["Italy"] },
  { code: "ES", cn: "西班牙", zh: ["西班牙"], en: ["Spain"] },
  { code: "PT", cn: "葡萄牙", zh: ["葡萄牙"], en: ["Portugal"] },
  { code: "CH", cn: "瑞士", zh: ["瑞士"], en: ["Switzerland"] },
  { code: "AT", cn: "奥地利", zh: ["奥地利", "奧地利"], en: ["Austria"] },
  { code: "BE", cn: "比利时", zh: ["比利时", "比利時"], en: ["Belgium"] },
  { code: "LU", cn: "卢森堡", zh: ["卢森堡", "盧森堡"], en: ["Luxembourg"] },
  { code: "SE", cn: "瑞典", zh: ["瑞典"], en: ["Sweden"] },
  { code: "NO", cn: "挪威", zh: ["挪威"], en: ["Norway"] },
  { code: "DK", cn: "丹麦", zh: ["丹麦", "丹麥"], en: ["Denmark"] },
  { code: "FI", cn: "芬兰", zh: ["芬兰", "芬蘭"], en: ["Finland"] },
  { code: "IS", cn: "冰岛", zh: ["冰岛", "冰島"], en: ["Iceland"] },
  { code: "PL", cn: "波兰", zh: ["波兰", "波蘭"], en: ["Poland"] },
  { code: "CZ", cn: "捷克", zh: ["捷克"], en: ["Czech"] },
  { code: "SK", cn: "斯洛伐克", zh: ["斯洛伐克"], en: ["Slovakia"] },
  { code: "HU", cn: "匈牙利", zh: ["匈牙利"], en: ["Hungary"] },
  { code: "RO", cn: "罗马尼亚", zh: ["罗马尼亚", "羅馬尼亞"], en: ["Romania"] },
  { code: "BG", cn: "保加利亚", zh: ["保加利亚", "保加利亞"], en: ["Bulgaria"] },
  { code: "GR", cn: "希腊", zh: ["希腊", "希臘"], en: ["Greece"] },
  { code: "HR", cn: "克罗地亚", zh: ["克罗地亚", "克羅地亞"], en: ["Croatia"] },
  { code: "RS", cn: "塞尔维亚", zh: ["塞尔维亚", "塞爾維亞"], en: ["Serbia"] },
  { code: "SI", cn: "斯洛文尼亚", zh: ["斯洛文尼亚"], en: ["Slovenia"] },
  { code: "LT", cn: "立陶宛", zh: ["立陶宛"], en: ["Lithuania"] },
  { code: "LV", cn: "拉脱维亚", zh: ["拉脱维亚", "拉脫維亞"], en: ["Latvia"] },
  { code: "EE", cn: "爱沙尼亚", zh: ["爱沙尼亚", "愛沙尼亞"], en: ["Estonia"] },
  { code: "CY", cn: "塞浦路斯", zh: ["塞浦路斯"], en: ["Cyprus"] },
  { code: "MT", cn: "马耳他", zh: ["马耳他", "馬耳他"], en: ["Malta"] },
  { code: "UA", cn: "乌克兰", zh: ["乌克兰", "烏克蘭"], en: ["Ukraine"] },
  { code: "RU", cn: "俄罗斯", zh: ["俄罗斯", "俄羅斯"], en: ["Russia"] },
  { code: "US", cn: "美国", zh: ["美国", "美國"], en: ["United States", "USA"] },
  { code: "CA", cn: "加拿大", zh: ["加拿大"], en: ["Canada"] },
  { code: "MX", cn: "墨西哥", zh: ["墨西哥"], en: ["Mexico"] },
  { code: "BR", cn: "巴西", zh: ["巴西"], en: ["Brazil"] },
  { code: "AR", cn: "阿根廷", zh: ["阿根廷"], en: ["Argentina"] },
  { code: "CL", cn: "智利", zh: ["智利"], en: ["Chile"] },
  { code: "CO", cn: "哥伦比亚", zh: ["哥伦比亚", "哥倫比亞"], en: ["Colombia"] },
  { code: "PE", cn: "秘鲁", zh: ["秘鲁", "秘魯"], en: ["Peru"] },
  { code: "PA", cn: "巴拿马", zh: ["巴拿马", "巴拿馬"], en: ["Panama"] },
  { code: "CR", cn: "哥斯达黎加", zh: ["哥斯达黎加"], en: ["Costa Rica"] },
  { code: "ZA", cn: "南非", zh: ["南非"], en: ["South Africa"] },
  { code: "EG", cn: "埃及", zh: ["埃及"], en: ["Egypt"] },
  { code: "NG", cn: "尼日利亚", zh: ["尼日利亚", "尼日利亞"], en: ["Nigeria"] },
  { code: "KE", cn: "肯尼亚", zh: ["肯尼亚", "肯尼亞"], en: ["Kenya"] },
  { code: "MA", cn: "摩洛哥", zh: ["摩洛哥"], en: ["Morocco"] },
  { code: "AU", cn: "澳大利亚", zh: ["澳大利亚", "澳洲"], en: ["Australia"] },
  { code: "NZ", cn: "新西兰", zh: ["新西兰", "紐西蘭"], en: ["New Zealand"] },
];

// ============ 工具函数 ============
function escapeRegex(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

// 安全边界：只把英文字母当作"词内字符"，下划线/短横线/数字都算边界，
// 这样 RO_speednode_0043、US-01、JP1 之类的命名都能正确匹配到代码。
function wb(token) {
  return `(?<![A-Za-z])${escapeRegex(token)}(?![A-Za-z])`;
}

function codeToFlag(code) {
  try {
    return code.replace(/./g, (c) => String.fromCodePoint(127397 + c.charCodeAt(0)));
  } catch (e) {
    return "🏳️";
  }
}

// 预编译每个国家的匹配正则（中文关键字直接拼，代码/英文名走安全边界）
for (const item of COUNTRY_MAP) {
  const parts = [];
  item.zh.forEach((z) => parts.push(escapeRegex(z)));
  item.en.forEach((e) => parts.push(wb(e)));
  parts.push(wb(item.code));
  parts.push(escapeRegex(codeToFlag(item.code)));
  item.pattern = new RegExp(parts.join("|"), "i");
}

function detectCountry(name) {
  for (const item of COUNTRY_MAP) {
    if (item.pattern.test(name)) return item;
  }
  return { code: "UN", cn: "未知地区" };
}

// ============ 节点有效性校验 + 去重 ============
// mihomo/FlClash 目前支持的代理协议类型
const SUPPORTED_TYPES = new Set([
  "ss", "ssr", "vmess", "vless", "trojan",
  "http", "socks5", "snell", "wireguard",
  "hysteria", "hysteria2", "tuic",
]);

function isValidProxy(p) {
  if (!p || typeof p !== "object") return false;
  if (!p.name || typeof p.name !== "string") return false;
  if (!p.type || !SUPPORTED_TYPES.has(String(p.type).toLowerCase())) return false;
  if (!p.server || typeof p.server !== "string" || !p.server.trim()) return false;
  const port = Number(p.port);
  if (!Number.isInteger(port) || port <= 0 || port > 65535) return false;
  return true;
}

// 按 server+port 去重，同一节点被多个源重复收录时只保留第一个
function dedupeByServerPort(list) {
  const seen = new Set();
  const result = [];
  for (const p of list) {
    const key = `${p.server}:${p.port}`.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    result.push(p);
  }
  return result;
}

// ============ 主函数 ============
function main(config) {
  try {
    // ---- 1. 过滤畸形/不支持的节点 -> 按 server+port 去重 -> 重命名 + 排序 ----
    const raw = Array.isArray(config.proxies) ? config.proxies : [];
    const validOnly = raw.filter(isValidProxy);
    const deduped = dedupeByServerPort(validOnly);

    const counters = {};
    const renamed = deduped
      .map((p) => {
        const info = detectCountry(p.name);
        counters[info.code] = (counters[info.code] || 0) + 1;
        const flag = info.code === "UN" ? "🏳️" : codeToFlag(info.code);
        p.name = `${flag} ${info.cn} ${info.code} ${counters[info.code]}`;
        p._sortKey = `${info.code}-${String(counters[info.code]).padStart(3, "0")}`;
        return p;
      });
    renamed.sort((a, b) => a._sortKey.localeCompare(b._sortKey));
    renamed.forEach((p) => delete p._sortKey);
    config.proxies = renamed;

    delete config["proxy-providers"];

    // ---- 2. 代理组（已取消"全球直连"分组） ----
    config["proxy-groups"] = [
      {
        name: "代理选择",
        type: "select",
        proxies: ["👍👍智能选择", "👍自动选择"],
        "include-all": true,
      },
      {
        name: "附加功能-广告拦截",
        type: "select",
        proxies: ["REJECT", "PASS"],
      },
      {
        name: "👍自动选择",
        type: "url-test",
        url: "https://www.gstatic.com/generate_204",
        interval: 300,
        tolerance: 100,
        "include-all": true,
        hidden: true,
      },
      {
        name: "👍👍智能选择",
        type: "smart",
        url: "https://www.gstatic.com/generate_204",
        interval: 300,
        "include-all": true,
        hidden: true,
        uselightgbm: true,
      },
    ];

    // ---- 3. rule-providers：jsDelivr 镜像 ----
    const RP = (path) => ({
      type: "http",
      behavior: "domain",
      format: "mrs",
      interval: 86400,
      url: `https://cdn.jsdelivr.net/gh/cjchxgxhc/domain-filter@main/data/rules/${path}/clash.mrs`,
    });
    config["rule-providers"] = {
      ADS: RP("ads"),
      PROXY: RP("proxy"),
      DIRECT_FIX: RP("direct_fix"),
    };

    // ---- 4. 分流规则（收尾规则改回 DIRECT；自动校验 rule-provider 是否存在） ----
    const desiredRules = [
      "RULE-SET,ADS,附加功能-广告拦截",
      "RULE-SET,DIRECT_FIX,DIRECT",
      "RULE-SET,PROXY,代理选择",
      "MATCH,DIRECT",
    ];
    const providerNames = new Set(Object.keys(config["rule-providers"]));
    config["rules"] = desiredRules.filter((rule) => {
      const parts = rule.split(",");
      if (parts[0] !== "RULE-SET") return true;
      return providerNames.has(parts[1]);
    });

    // ---- 5. 基础网络参数 ----
    config["mixed-port"] = 8080;
    config["ipv6"] = true;
    config["unified-delay"] = true;
    config["tcp-concurrent"] = true;
    config["global-client-fingerprint"] = "chrome";

    // ---- 6. sniffer ----
    config["sniffer"] = {
      enable: false,
      "parse-pure-ip": true,
      sniff: {
        TLS: { ports: [443, 8443] },
        HTTP: { ports: [80, "8080-8880"] },
        QUIC: { ports: [443, 8443] },
      },
      "skip-domain": ["+.push.apple.com"],
    };

    // ---- 7. DNS ----
    config["dns"] = {
      enable: true,
      ipv6: true,
      "enhanced-mode": "fake-ip",
      "fake-ip-range": "28.0.0.0/8",
      "fake-ip-range6": "fc00::/16",
      "fake-ip-filter-mode": "whitelist",
      "fake-ip-filter": ["rule-set:ADS,PROXY"],
      nameserver: ["system"],
    };

    // ---- 8. geodata ----
    config["geodata-mode"] = true;
    config["geo-auto-update"] = false;
    config["geo-update-interval"] = 7200;
    config["geox-url"] = {
      geoip: "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geoip.dat",
      geosite: "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geosite.dat",
      mmdb: "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/country.mmdb",
    };

    // ---- 9. 保留手动选择的节点/分组 ----
    config["profile"] = {
      "store-selected": true,
      "store-fake-ip": true,
    };

    return config;
  } catch (e) {
    config.__scriptError = String(e && e.message ? e.message : e);
    return config;
  }
}
