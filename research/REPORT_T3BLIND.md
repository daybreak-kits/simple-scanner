# T3ENV-B 盲测报告：simple-scanner 对 4 个身份未知靶场端点的检出与覆盖分析

- 任务编号：T3ENV-B（盲测员）
- 执行工具：`/opt/workspace/labs/simple-scanner/ss.py`（v0.2.4 派生）+ `plugins_corpus/` 插件库
- 盲测前提：测试开始时对 4 个端点的产品/漏洞**不作任何假设**，产品身份由探测结果反推，插件侧结论由实际响应复现得出
- 报告日期：2026-10-26
- 原始数据目录：`research/t2b_raw/`（路径清单见 §8）

---

## 1. 结论先行

**四轮扫描 4796 次插件执行，VULN 命中 0 次。**这不是"靶场无漏洞"，而是**插件库的产品覆盖空洞 + 引擎不做产品门控**共同导致的系统性结果。

| 轮次 | 端点 | 退出码 | 耗时 | VULN | SAFE | WARN | SKIP | total | 结论一句话 |
|---|---|---|---|---|---|---|---|---|---|
| 1 | `http://192.168.255.128:28081/` | 0 | 18s | 0 | 1196 | 3 | 0 | 1199 | GitList 产品在插件库中**完全不存在**，全部 1198 个插件是"别的产品的探针" |
| 2 | `http://192.168.255.128:28161/` | 0 | 9s | 0 | 1196 | 3 | 0 | 1199 | ActiveMQ Web 控制台整体挂在 Basic Auth 后面，**引擎无凭据通道**，无一插件能取证 |
| 3 | `192.168.255.128:28162`（TCP） | 0 | 34s | 0 | 1199 | 0 | 0 | 1199 | 100% 为**协议不匹配**归因（1198/1198），非工具误报；插件库**无任何 OpenWire/TCP 插件** |
| 4 | `http://192.168.255.128:28180/` | 0 | 9s | 0 | 1196 | 3 | 0 | 1199 | Solr 8.11.0 管理台**无鉴权敞开**，但唯一 read_only 插件因匹配器过度要求而漏报（已复现） |

**四轮 summary 行原文**（摘自 `research/t2b_raw/ep*.log`）：

```
2026-10-26 18:46:23,292 [INF]: plugin outcome summary: VULN=0 SAFE=1196 WARN=3 SKIP=0 total=1199   # ep1 28081
2026-10-26 18:49:23,410 [INF]: plugin outcome summary: VULN=0 SAFE=1196 WARN=3 SKIP=0 total=1199   # ep2 28161
2026-10-26 18:52:19,456 [INF]: plugin outcome summary: VULN=0 SAFE=1199 WARN=0 SKIP=0 total=1199   # ep3 28162
2026-10-26 18:50:47,281 [INF]: plugin outcome summary: VULN=0 SAFE=1196 WARN=3 SKIP=0 total=1199   # ep4 28180
```

**引擎自洽性**：4/4 轮 `LoopExit=0`、`Traceback=0`、`[ERR]=0`、退出码均为 0；`x+y+z+w == total` 恒成立（1199 = 1196+3+0）。引擎的四态契约本身在本次盲测中**没有崩**。

---

## 2. 方法与口径（含假设披露）

### 2.1 staging 口径

| 项 | 取值 | 依据 |
|---|---|---|
| 插件选取 | 两个 manifest 中 `risk_class == read_only` 的全部条目 | 任务卡"按 manifest*.json 选 read_only 插件" |
| 插件数 | **1198**（`manifest.json` 833 + `manifest-vulns.json` 365） | 见 §2.2 的数量差异说明 |
| 端口替换 | `port=NN` → `port=<目标端口>`；`ssl_port=NN` → `ssl_port=<目标端口>`；`ports=[...]` → `ports=[<目标端口>]` | 三个字段在 1198/1198 个插件里都是独立成行，替换确定性 100%（脚本内置复核，0 例外） |
| 落地文件名 | `plugins/T2B_<原basename>.py` | 1198 个 basename 无冲突（已校验） |
| 不改动 | `plugins_corpus/`、`utils/`、`ss.py` | 见 §7 校验证据 |

**数量差异说明（假设披露）**：任务卡写"约 1385 个"。`833 + 552 = 1385` 恰好等于"`manifest.json` 的 read_only + `manifest-vulns.json` 的**全部**"，即卡面隐含把 `risky`/`excluded` 类也算进可用集。但 `manifest-vulns.json` 的 `risky` 181 个插件的 `risk_detail` 明确是 `command-execution-payload`（对真实目标执行命令载荷），`excluded` 51 个是 `data-exfiltration-OOB` / `file-delete-payload`。**按"只扫 read_only"且"不执行不可逆/攻击性动作"的约束，本轮只装 1198 个**，不跑 risky/excluded。若后续要补齐全量 1385，需单独授权。

### 2.2 扫描命令（每轮一个端点，规避已知 argparse 缺陷）

```bash
# 轮次 1
.venv/bin/python ss.py -t http://192.168.255.128:28081/ -dps -p 4
# 轮次 2
.venv/bin/python ss.py -t http://192.168.255.128:28161/ -dps -p 4
# 轮次 3
.venv/bin/python ss.py -t 192.168.255.128:28162 -dps -p 4
# 轮次 4
.venv/bin/python ss.py -t http://192.168.255.128:28180/ -dps -p 4
```

多 `-t` 只保留最后一个的缺陷未触发（每轮单端点）。

### 2.3 归因原则

- **SAFE**：插件正常执行、未命中。必须进一步区分"产品不匹配/路径不存在/前提不满足/匹配器超出响应"四类，不允许笼统记"未检出"。
- **WARN**：执行异常 → 逐条定位根因（本轮 12 条 WARN 全部定位到同一类插件库缺陷）。
- **SKIP**：本轮全为 0，原因见 §6.4。
- **协议不匹配**：轮次 3 整轮单列归因，不计入工具误报。

---

## 3. 端点 1 —— `http://192.168.255.128:28081/`

### 3.1 独立面分析（暴露面）

| 项 | 实测值 | 取证方式 |
|---|---|---|
| 服务端 | `Server: Apache/2.4.10 (Debian)` | `curl -i /` |
| 运行时 | `X-Powered-By: PHP/7.1.16` | `curl -i /` |
| 产品 | **GitList**（`<title>GitList - GitList</title>`，页脚指向 `github.com/klaussilveira/gitlist`） | 根页 HTML |
| 根响应 | 200，2969B，`text/html; charset=UTF-8` | 根页 |
| 代码库浏览 | `/example/` 200(5050B)、`/example/master/` 200(5050B) | 路径枚举 |
| 仓库功能面 | `/example/commits/master`、`/example/stats/master`、`/example/network/master`、`/example/treegraph?branch=master`、`/example/zipball/master`、`/example/tarball/master`、`/example/blob/master/README.md`、`/example/master/rss/` | 根页链接抽取 |
| 特有端点 | `/refresh` → **500**（2402B，GitList 缓存刷新端点） | 路径枚举 |
| 依赖目录 | `/vendor/` → **403**（300B，目录存在、列表被禁） | 路径枚举 |
| 静态资源 | `/themes/default/{css,js,img}/...` 200 | 根页引用 |
| Apache 侧 | `/server-status` → **403**（mod_status 存在） | 路径枚举 |
| 不存在 | `/.git/HEAD`、`/.git/config`、`/robots.txt`、`/favicon.ico` 均 404 | 路径枚举 |

该产品（GitList）为 PHP 应用，Apache 2.4.10 (Debian) 与 PHP 7.1.16 均为已停止维护的版本线（版本事实来自响应头原文；**是否存在可利用漏洞 → 未知**）。

### 3.2 扫描结果

`VULN=0 SAFE=1196 WARN=3 SKIP=0 total=1199`，退出码 0，18s。WARN 3 条根因见 §6.3。

### 3.3 指纹命中的插件有几个？判定是证据型还是别的？

**产品级指纹命中：0 个。**

- 在 `plugins_corpus/` 全部 **2063** 个 `.py` 文件中检索 `gitlist`（大小写不敏感）→ **0 处命中**（含 fingerprint 元数据、请求路径、描述文本三个维度）。manifest 两个文件中亦无任何条目的 fingerprint 含 `gitlist`。
- 结论：**插件库对 GitList 的覆盖率是 0**。这不是"漏了一个 CVE"，而是"这个产品没有一行代码"。

**技术栈级指纹命中（供参考，非本产品）**：`apache` 23 个、`php` 34 个（均在 read_only 集内）。这些插件探测的是**别的产品**的路径（NiFi / Struts / ThinkPHP / Airflow / Kylin 等），对本端点只有"栈相同、产品不同"的意义。

**判定类型**：全库 1198 个 read_only 插件中，只有 **17 个**是"只 GET 根路径、靠响应内容判定"的证据型插件，且这 17 个**全部是后门/OOB 注入检测器**（`host-header-injection`、`php-zerodium-backdoor-rce`、`deadbolt-ransomware`、`openvpn-hhi` 等），**没有一个是通用产品指纹识别器**。把它们的匹配器逐条在 GitList 根响应上实跑（`research/t2b_raw/evidence_fingerprint.py`）→ **0 命中**。

> 关键结构性事实：插件文件里的 `FINGERPRINT = [...]` 是**惰性元数据**。`grep -rn "fingerprint" ss.py utils/*.py` → **0 处引用**，引擎完全不做产品门控。因此 1198 个插件对每个端点 100% 全量开火，"指纹命中"在当前引擎里根本不存在这个概念。

### 3.4 代表性 SAFE 的"没命中原因"（6 例，全部现场复现）

| 插件（catalog） | 探测路径 | 实测响应 | 没命中原因（归类） |
|---|---|---|---|
| `apache-nifi-rce` | `GET /nifi-api/process-groups/root` | **404** 2434B（返回的是 GitList 主题 404 页） | **路径不存在 + 产品不匹配**：匹配器要求 body 同时含 `revision`/`canRead`/`permissions` 且 header 含 `application/json` 且 status=200；NiFi API 在 GitList 上不存在 |
| `CVE-2017-9791`（Struts OGNL） | `POST /integration/saveGangster.action` | **404** 2437B | **路径不存在 + 产品不匹配**：需 body 含 `added successfully`+status 200；Struts 动作映射不存在 |
| `CVE-2018-7490`（PHP 路径穿越） | `GET /..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd` | **404** 313B（Apache 原生 404，非 GitList 主题页） | **前提不满足**：编码穿越路径被 Apache 在进入 PHP 前就规范化并 404，body 无 `root:.*:0:0:` |
| `CVE-2018-20062`（ThinkPHP RCE） | `GET ?s=index/think\app/invokefunction&function=call_user_func_array&vars[0]=phpinfo...` | **200** 2969B | **匹配器要求超出响应**：status 与长度都"像"命中（返回的是 GitList 首页，查询串被路由忽略），但 body 无 `PHP Extension`/`PHP Version`/`ThinkPHP` 三词 → AND 组失败 |
| `CVE-2021-37704`（phpfastcache phpinfo） | `GET /vendor/phpfastcache/phpfastcache/docs/examples/phpinfo.php` | **404** 2464B | **路径不存在（子路径）**：`/vendor/` 本身 403 存在，但该插件的**具体子路径**不存在；11 个含 `vendor/` 的插件全是产品特定子路径，无一做"vendor 目录暴露"通用检测 |
| `CVE-2019-10098` | `GET /http%3A%2F%2Fwww.interact.sh` | **404** 304B | **双重不可取证**：① 路径不存在；② 匹配器是 OOB 回调正则（要求响应 `Location` 头指向 `interact.sh`），**依赖外部协作者基础设施**，离线环境永远 SAFE |

### 3.5 覆盖缺口清单（暴露面 → 无插件对应）

| # | 暴露面 | 插件库现状 | 缺口性质 |
|---|---|---|---|
| G1-1 | GitList 整个产品（代码浏览/提交/RSS/下载） | 2063 个插件中 0 处提及 | **产品级空洞** |
| G1-2 | `/refresh`（GitList 特有端点，当前 500） | 检索 `refresh` 仅命中无关产品插件 | 端点级空洞 |
| G1-3 | `/example/zipball/master`、`/example/tarball/master`（源码打包下载） | 检索 `zipball`/`tarball` → 0 个插件 | 端点级空洞 |
| G1-4 | `/vendor/`（composer 依赖目录，403） | 11 个 `vendor/` 插件全为产品特定子路径 | **模式级空洞**：无"vendor 目录暴露"通用检测 |
| G1-5 | `/server-status`（Apache mod_status，403） | 检索 `server-status` → 0 | 模式级空洞 |
| G1-6 | `X-Powered-By: PHP/7.1.16` / `Server: Apache/2.4.10` 版本泄露与 EOL 判定 | 检索 `X-Powered-By` → **0** 个插件在 REQS/MATCHERS 中使用 | **模式级空洞**：全库无任何通用响应头版本识别插件 |
| G1-7 | `/example/master/rss/`、`/example/commits/master`、`/example/treegraph` | `rss/`/`commits`/`treegraph` → 0 | 端点级空洞 |
| G1-8 | 组件版本适用性（PHP 7.1.16 / Apache 2.4.10 哪些 CVE 适用） | 引擎与插件均无版本感知逻辑；`FINGERPRINT` 不被引用 | **契约级空洞**：无法表达"仅当版本 <X 时才判定" |

> 说明：G1-1~G1-8 均为"暴露面存在 → 插件库无对应插件"。**不对具体漏洞编号或利用方式做任何猜测**：本端点是否存在可利用漏洞 = **未知**（插件库对该产品无任何条目，无证据可依）。

---

## 4. 端点 2 —— `http://192.168.255.128:28161/`

### 4.1 独立面分析（暴露面）

| 项 | 实测值 | 取证方式 |
|---|---|---|
| 状态码 | **全部路径均 401 Unauthorized** | 14 条路径枚举结果全为 401 |
| 认证 | `WWW-Authenticate: basic realm="ActiveMQRealm"` | `curl -i /` |
| 错误页 | Jetty 风格（`<meta http-equiv="Content-Type" .../>` + `<table><tr><th>URI:</th>`），`Content-Type: text/html;charset=iso-8859-1` | 401 响应体 |
| 响应头 | 无 `Server`、无 `X-Powered-By`；`Cache-Control: must-revalidate,no-cache,no-store` | `curl -i` |
| 路径可枚举性 | **不可枚举**：连 `/nonexistent-xyz` 也是 401（响应体回显请求 URI，长度 366~404B 随路径变化） | 路径枚举 |
| 探测过的代表性路径 | `/`、`/admin/`、`/console/`、`/api/`、`/index.html`、`/jolokia/`、`/api/jolokia/read/java.lang:type=Memory`、`/cgi-bin/`、`/WEB-INF/web.xml`、`/admin/index.jsp`、`/admin/index.html`、`/admin/queues.jsp`、`/shutdown.jsp`、`/console/index.jsp` → 全部 401 | — |

产品身份（ActiveMQ）由 **`WWW-Authenticate: basic realm="ActiveMQRealm"`** 这一响应头直接给出，是四轮中"指纹最清晰"的一个端点。

### 4.2 扫描结果

`VULN=0 SAFE=1196 WARN=3 SKIP=0 total=1199`，退出码 0，9s。

### 4.3 指纹命中的插件有几个？

| 维度 | 命中数 | 清单 |
|---|---|---|
| `activemq` 指纹（全库 2052 条 manifest，含 risky/excluded） | **2** | `CVE-2018-8006`（read_only，本轮已装载）、`CVE-2022-41678`（risky/command-execution，**按口径未装载**） |
| `jolokia` 指纹 | 8 | 其中 read_only 4 个（`CVE-2018-1000129`、`jolokia-logback-jndi-rce`、`jolokia-acceslogvalve-rce`、`jolokia-createstandardhost-rce`、`jolokia-tomcat-creds-leak`），risky 4 个未装载 |
| `jetty` 指纹 | 1 | `CVE-2021-28169` |

**判定类型**：全部为**路径+响应内容型**（探测 `/admin/queues.jsp`、`/jolokia/list` 等具体路径并对 body 做词/正则匹配），**无一个是指纹/响应头型**——也就是说，即使插件库知道"这可能是 ActiveMQ"，它也无法靠 `ActiveMQRealm` 这个唯一的产品证据字符串确认身份（检索 `ActiveMQRealm` → **0 个插件**）。

### 4.4 代表性 SAFE 的"没命中原因"（6 例，现场复现）

| 插件 | 探测路径 | 实测 | 没命中原因（归类） |
|---|---|---|---|
| `CVE-2018-8006` | `GET /admin/queues.jsp?QueueFilter=<XSS>` | **401** 382B | **认证墙 + 产品路径**：ActiveMQ Web 管理队列页需要凭据，匹配器要求 status 200 + 反射 XSS 串 + header 含 `/html`，401 全部不满足 |
| `CVE-2018-1000129`（jolokia XSS） | `GET /api/jolokia/read<svg onload=...>` | **401** 423B | **认证墙**：需 body 含 `java.lang.IllegalArgumentException` 等 Jolokia 错误特征，401 页无此特征 |
| `jolokia-logback-jndi-rce` | `GET /jolokia/list` | **401** 378B | **认证墙 + 路径不存在**：需 body 含 `ch.qos.logback.classic.jmx.JMXConfigurator`/`reloadByURL` + status 200 |
| `jolokia-acceslogvalve-rce` | `GET /jolokia/list` | **401** 378B | 同上，匹配器还额外要求 `"host=localhost,name=AccessLogValve,type=Valve"` 精确串 |
| `jolokia-createstandardhost-rce` | `GET /jolokia/list` | **401** 378B | **认证墙 + 匹配器要求超出响应**：需 `"desc":"Create a new StandardHost"` 等精确 JSON 片段 |
| `jolokia-tomcat-creds-leak` | `GET /jolokia/read/Users:database=UserDatabase,type=UserDatabase` | **401** 424B | **认证墙 + 匹配器要求超出响应**：需 `"mbean":"Users:database=..."` + `"users":` 且**不**含某关键词（negative matcher） |

**共性根因**：6/6 全部死于**认证墙**。这是**引擎级**而非插件级问题：插件契约里 `Info.params` 是预留的插件参数字段，但 `ss.py` 的 `_task_wrapper` 调 `plugin.do_testing(url)` **从不传 data**，命令行也没有任何传参入口 → **凭据型插件永远无法运行**（见 §6.5）。

### 4.5 覆盖缺口清单

| # | 暴露面 | 插件库现状 | 缺口性质 |
|---|---|---|---|
| G2-1 | `WWW-Authenticate: basic realm="ActiveMQRealm"`（**唯一产品证据**） | 检索 `ActiveMQRealm` → 0 | **产品识别空洞**：无法把"ActiveMQ 认证墙"识别为"ActiveMQ 存在" |
| G2-2 | `/api/`（ActiveMQ REST API）、`/fileserver/`、`/cgi-bin/` | 无任何 ActiveMQ API/文件服务插件 | 端点级空洞 |
| G2-3 | 认证墙后的管理台（`/admin/queues.jsp` 等） | 唯一相关插件 `CVE-2018-8006` 需要 status 200 | **取证能力空洞**（见 G2-5） |
| G2-4 | ActiveMQ 版本（realm 名不携带版本） | 无版本探测插件 | 契约级空洞（与 G1-8 同源） |
| G2-5 | 带凭据访问（admin/admin 等常见默认凭据） | **引擎无凭据通道**：`Info.params` 未被 `ss.py` 填充，CLI 无参数入口 | **契约级空洞**：认证墙型目标在当前引擎下**原理上不可检出** |
| G2-6 | 61616 OpenWire 端口（同产品的另一面） | 见端点 3 §5.5 | 产品级空洞 |
| G2-7 | `CVE-2022-41678`（activemq+jndi+jolokia 指纹，唯一另一个 ActiveMQ 条目） | risk_class=risky，本轮未装载 | **口径级缺口**：read_only 口径内不可能覆盖 |

> 本端点是否存在可利用漏洞 = **未知**。无任何插件能取得 401 之后的任何证据。

---

## 5. 端点 3 —— `192.168.255.128:28162`（TCP 二进制）

### 5.1 独立面分析（暴露面）

原始 TCP banner（`research/t2b_raw/` 未存二进制，此处为 socket 直连 4096 字节实录，342 字节）：

```
b"\x00\x00\x01R\x01ActiveMQ\x00\x00\x00\x0c\x01\x00\x00\x01@\x00\x00\x00\r\x00\x11StackTraceEnabled
\x01\x01\x00\x0fPlatformDetails\t\x00\x04Java\x00\x0cCacheEnabled\x01\x01\x00\x11TcpNoDelayEnabled
\x01\x01\x00\x12SizePrefixDisabled\x01\x00\x00\tCacheSize\x05\x00\x00\x04\x00\x00\x0cProviderName
\t\x00\x08ActiveMQ\x00\x14TightEncodingEnabled\x01\x01\x00\x0cMaxFrameSize\x06\x00\x00\x00\x00\x06@
\x00\x00\x00\x15MaxInactivityDuration\x06\x00\x00\x00\x00\x00\x00u0\x00 MaxInactivityDurationInitalDelay
\x06\x00\x00\x00\x00\x00\x27\x10\x00\x13MaxFrameSizeEnabled\x01\x01\x00\x0fProviderVersion\t\x00\x065.17.3"
```

可读字段（OpenWire `WIREFORMAT_INFO` 命令）：

| 字段 | 值 |
|---|---|
| ProviderName | **ActiveMQ** |
| ProviderVersion | **5.17.3** |
| PlatformDetails | **Java** |
| CacheEnabled | true |
| TcpNoDelayEnabled | true |
| SizePrefixDisabled | true |
| TightEncodingEnabled | true |
| MaxFrameSizeEnabled | true |
| MaxFrameSize | 409600（0x00064000） |
| MaxInactivityDuration | 30000 ms（0x00007500） |
| MaxInactivityDurationInitalDelay | 0 |
| StackTraceEnabled | true |

`curl http://192.168.255.128:28162/` → `curl: (1) Received HTTP/0.9 when not allowed`（即服务端回的是二进制而非 HTTP）。

### 5.2 扫描结果与归因

`VULN=0 SAFE=1199 WARN=0 SKIP=0 total=1199`，退出码 0，34s（比其他轮慢 3~4 倍，因为每个插件都先做一次 https+http 双协议探测）。

**协议不匹配归因（按任务卡要求单列，不计入工具误报）**：

| DATA 原文 | 行数 | 归因 |
|---|---|---|
| `the network protocol does not match.` | **1198** | 1198 个已装载的 http 插件：目标写作裸 `host:port`（无协议）→ `url.protocol` 为空 → 插件内 `https_or_http()` 对 28162 做 https+http 双向探测均失败 → 插件主动返回"协议不匹配" |
| `network protocol does not match.` | 1 | 仓库自带 `WhatWAF.py`（catalog `PLG-2024-0001`）自带的同义文案 |

即：**整轮 1199/1199 均为协议不匹配，工具零误报**。3 个 `{{RootURL}}` 缺陷插件在本轮也未 WARN（因协议探测阶段就返回，根本没发请求）。

### 5.3 指纹命中的插件有几个？

**0 个。**全库检索 `activemq` / `openswire` / `wireformat` / `providerversion` / `cacheenabled` → 插件源码层面 0 处匹配（manifest 的 `activemq` 指纹共 2 条，都属 HTTP 类插件，见 §4.3）。

### 5.4 代表性 SAFE 的"没命中原因"

本轮 SAFE 原因**单一且可完整枚举**（1198/1198 同一原因），故列出归类 + 抽样 4 例：

| 插件 | 判定 | 没命中原因 |
|---|---|---|
| `CVE-2021-45232` | SAFE | **协议不匹配**（`the network protocol does not match.`）：插件的 `https_or_http()` 对 28162 的 TLS/HTTP 探测均失败 |
| `CVE-2022-35405` | SAFE | 同上 |
| `servicenow-helpdesk-credential` | SAFE | 同上 |
| `CVE-2023-50290`（Solr 插件） | SAFE | 同上（同一机制：插件无法自行识别非 HTTP 协议） |

**更深一层的原因**（插件库侧，非工具误报）：插件契约 `PluginBase.run(url)` 以 **URL** 为唯一入参，`Info` 只有 `protocol`/`port`/`ssl_protocol`/`ssl_port` 四个网络字段，**没有 banner 抓取或二进制协议解析的位置**。全库 2052 条 manifest 中 `protocol != 'http'` 的**只有 1 条**：`vulns/CVE-2022-0543.py`（Redis Lua 沙箱逃逸，risk=risky，ports=[6379]）——既非 read_only，也与 ActiveMQ 无关。

### 5.5 覆盖缺口清单

| # | 暴露面 | 插件库现状 | 缺口性质 |
|---|---|---|---|
| G3-1 | OpenWire `WIREFORMAT_INFO` banner 结构本身 | 0 | 模式级空洞 |
| G3-2 | `ProviderVersion=5.17.3`（可精确定位版本线） | 0 个插件解析二进制版本字段 | 模式级空洞 |
| G3-3 | `ProviderName=ActiveMQ` / `PlatformDetails=Java` | 0 | 模式级空洞 |
| G3-4 | `CacheEnabled` / `SizePrefixDisabled` / `TightEncodingEnabled` 等协议能力位 | 0 | 模式级空洞 |
| G3-5 | ActiveMQ OpenWire 传输层任何检测 | 全库 **0 个** | 产品级空洞 |
| G3-6 | 插件契约缺"二进制/原始 banner"类型的插件位 | `Info` 无 banner 字段、`run(url)` 入参仅 URL | **契约级空洞**：即使想写也无处安放 |
| G3-7 | 非 http 协议插件的可装载性 | 全库唯一 tcp 插件是 `risky` 类 Redis 插件 | **口径 + 契约双重空洞** |

> 本端点是否存在可利用漏洞 = **未知**。已确认的事实只有：ActiveMQ 5.17.3 OpenWire 端口对匿名 TCP 客户端完整暴露 wire-format-info。

---

## 6. 端点 4 —— `http://192.168.255.128:28180/`

### 6.1 独立面分析（暴露面）

| 项 | 实测值 | 取证方式 |
|---|---|---|
| 根响应 | 302 → `Location: http://192.168.255.128:28180/solr/` | `curl -i /` |
| 产品 | **Apache Solr 管理台**（`<html ng-app="solrAdminApp" ng-csp>`，ASF 许可头） | `/solr/` |
| 版本 | `solr-spec-version: 8.11.0`，`solr-impl-version: 8.11.0 e912fdd5b632267a9088507a2a6bcbc75108f381`；Lucene 8.11.0 | `/solr/admin/info/system` |
| 运行时 | OpenJDK **1.8.0_102**（Oracle），2 核 / 128MB | 同上 |
| 安装路径 | `solr_home: /opt/solr/server/solr` | 同上 |
| **鉴权状态** | `/solr/admin/authentication` → `{"errorMessages":["No authentication configured"]}` | 直连 |
| 敏感泄露面 1 | `/solr/admin/info/properties` **200**（3497B）→ 泄露 `solr.log.dir`、`solr.default.confdir`、`java.home` 系列、**`STOP.KEY=solrrocks`**、`user.dir=/opt/solr/server` | 直连 |
| 敏感泄露面 2 | `/solr/admin/metrics` **200**（108220B），指标分组 `solr.jetty` / `solr.jvm` / `solr.node` / `solr.core.demo` | 直连（已存档 `research/t2b_raw/solr_metrics.json`） |
| 敏感泄露面 3 | `/solr/admin/info/system` **200**（3643B）→ JVM/版本/路径 | 直连 |
| 其他 | `/solr/admin/cores` 200(1128B)、`/solr/admin/collections` 400(290B)、`/solr/admin/zookeeper` **500**(11966B) | 路径枚举 |
| 根路径重定向范围 | 仅裸 `/` → `/solr/`；`/admin/info/system`（无前缀）**404**，不会被重定向救回 | 复测 |

**这是四轮中暴露面最严重的一个端点**：管理台完全无鉴权，版本、路径、密钥、指标全部可读。

### 6.2 扫描结果

`VULN=0 SAFE=1196 WARN=3 SKIP=0 total=1199`，退出码 0，9s。

### 6.3 指纹命中与"**已复现的漏报**"

| 维度 | 命中数 | 清单 |
|---|---|---|
| `solr` 指纹（全库） | **2** | `CVE-2023-50290`（read_only，本轮已装载）、`CVE-2024-45216`（risky/command-execution，未装载） |
| `apache` 指纹（read_only） | 23 | 均为其它 Apache 子产品 |
| `java`/`tomcat`/`jetty` 指纹 | 6 / 7 / 1 | 均指向其它 Java 产品 |

**判定类型**：`CVE-2023-50290` 是**路径 + 响应内容型**（GET `/solr/admin/metrics`，对 body 做词匹配），非纯响应头指纹型。

**★ 已复现的漏报（本轮最有价值的发现）**：

`CVE-2023-50290` 在本端点判 **SAFE（"no match"）**，但它探测的路径**是敞开的**。用插件自身的 `_match_one()` 逐条 matcher 实跑真实响应（`research/t2b_raw/ep4_28180.log` 同源复现脚本）：

```
err: None | status: 200 | ctype: application/json;charset=utf-8 | len: 108449
matcher {'type':'word','part':'body','condition':'and','words':['"responseHeader":','"solr.jetty":','system.env']}  -> False
matcher {'type':'word','part':'header','condition':'or','words':['application/json']}                                  -> True
matcher {'type':'status','part':'body','condition':'or','status':[200]}                                                -> True
```

单词级复核：`"responseHeader":` → **True**、`"solr.jetty":` → **True**、`system.env` → **False**。

**根因**：Solr 8.11.0 的 `/solr/admin/metrics` 指标分组为 `solr.jetty / solr.jvm / solr.node / solr.core.demo`，**不含 `system.env`**（全文检索 `env` 仅命中 `"java.awt.graphicsenv"` 一处）。而该插件把 3 个词放进**同一个 AND 组**，任一词缺席即整体失败 → **版本脆弱的匹配器造成确定性漏报**。同时该端点的环境变量/系统属性实际是通过**另一个端点** `/solr/admin/info/properties` 泄露的，而**插件库中没有任何 read_only 插件探测该路径**（检索 `info/properties` → 0）。

### 6.4 代表性 SAFE 的"没命中原因"（6 例）

| 插件 | 探测路径 | 实测 | 没命中原因（归类） |
|---|---|---|---|
| `CVE-2023-50290`（Solr Metrics 泄露） | `GET /solr/admin/metrics` | **200** 108449B | **匹配器要求超出响应（确定性漏报）**：2/3 词命中，`system.env` 在 Solr 8.11.0 不存在 → AND 组失败（详见 §6.3） |
| `CVE-2021-28169`（Jetty WEB-INF 泄露） | `GET /static?/%2557EB-INF/web.xml` | **404** 363B | **路径不存在 + 产品不匹配**：Solr 的 Jetty 未开放该路径；匹配器还需 header `application/xml` + body `</web-app>`/`java.sun.com` |
| `jolokia-logback-jndi-rce` | `GET /jolokia/list` | **404** 369B | **路径不存在**：Solr 8.x 未启用 Jolokia；匹配器需 `ch.qos.logback...JMXConfigurator`/`reloadByURL` |
| `CVE-2017-12637`（WebLogic JS 泄露） | `GET /scheduler/ui/js/ffffffffbca41eb4/UIUtilJavaScriptJS?/..` | **404** 408B | **路径不存在 + 产品不匹配**（WebLogic 专属路径） |
| `java-melody-xss` | `GET /monitoring?part=graph&graph=usedMemory<script>...` | **404** 367B | **路径不存在 + 产品不匹配**（JavaMelody 监控页，Solr 无此组件） |
| `CVE-2019-10092`（HTTP 代理滥用） | `GET /%5cgoogle.com/evil.html` | **404** 380B | **路径不存在 + 匹配器要求超出响应**：需 body 含 `Proxy Error` 与 `<a href="/\google.com/evil.html">` |

### 6.5 覆盖缺口清单

| # | 暴露面 | 插件库现状 | 缺口性质 |
|---|---|---|---|
| G4-1 | `/solr/admin/info/properties`（泄露 `STOP.KEY=solrrocks`、全部系统属性、solr_home） | 检索 `info/properties` → **0** 个 read_only 插件 | **端点级空洞**（唯一相关的是 risky 类 `CVE-2024-45216`） |
| G4-2 | `/solr/admin/info/system`（版本/路径/JVM） | 检索 `info/system` → **0** | 端点级空洞 |
| G4-3 | `/solr/admin/authentication` → `No authentication configured`（**无鉴权事实**） | 0 | 模式级空洞 |
| G4-4 | `/solr/admin/cores`（core 清单，本端点有 `solr.core.demo`） | 检索 `admin/cores` → 0 | 端点级空洞 |
| G4-5 | `/solr/admin/collections`（400）、`/solr/admin/zookeeper`（500） | 0 | 端点级空洞 |
| G4-6 | `configoverlay` 参数面 | 检索 `configoverlay` → 0 | 模式级空洞 |
| G4-7 | Solr 8.11.0 的具体适用性（版本区间判定） | 插件无版本逻辑，引擎无版本逻辑 | 契约级空洞 |
| G4-8 | 唯一 Solr read_only 插件的匹配器对 8.11.0 必然失败 | `system.env` 词在 8.11.0 不存在 | **插件级缺陷**（见 §6.3） |
| G4-9 | 根路径 302 → `/solr/`：1191/1198 个插件 `redirects=False` | 引擎按模板逐个决定是否跟随重定向 | **引擎级约束**：不跟随重定向的插件对"入口带 302"的目标天然受限 |

> 本端点是否存在可利用漏洞 = **未知**。本报告只陈述"无鉴权管理台 + 信息泄露"这一**已实测**的事实，不做利用推断。

---

## 7. 引擎行为观察（跨端点汇总）

### 7.1 正常项

- 4/4 轮退出码 0，`LoopExit=0`、`Traceback=0`、`[ERR]=0`（`grep -c` 逐文件核验）。
- 四态计数恒等式 `VULN+SAFE+WARN+SKIP == total` 在 4/4 轮成立。
- 进程池 `spawn` 上下文在 4 轮长任务（18s/9s/34s/9s）中未复现 LoopExit。
- WARN 行与 SKIP 行独立落盘（`-warn.csv`），主 CSV 只含结论行。

### 7.2 `total` 比装载插件数多 1 的原因

每轮 `total=1199` = 1198 个 `T2B_*` + **仓库自带的 `plugins/WhatWAF.py`**（catalog `PLG-2024-0001`）。引擎的加载规则是 `plugins/` 下所有不以 `__` 开头、以 `.py` 结尾的文件，因此 staging 的插件会与仓库自带插件**混装在同一结果表**里，无法按来源区分。

### 7.3 WARN 的唯一根因：插件库 `{{RootURL}}` 丢端口（12 条 WARN 全部同因）

12 条 WARN 分布在轮次 1/2/4（每轮 3 条），插件固定为：
`CVE-2021-45232`、`CVE-2022-35405`、`servicenow-helpdesk-credential`。

实测证据（`research/t2b_raw/ep1_28081-warn.csv`）：

```
requests.exceptions.ConnectionError: HTTPConnectionPool(host='192.168.255.128', port=80):
Max retries exceeded with url: /apisix/admin/migrate/export
(Caused by NewConnectionError(... Failed to establish a new connection: [Errno 111] Connection refused))
```

**根因**：这 3 个插件的 REQS 路径用的是 `{{RootURL}}` 而非 `{{BaseURL}}`；生成的 `_sub()` 中 `{{RootURL}}` 展开为 `'{}://{}'.format(url.protocol, url.host)`——**丢掉了端口**。于是请求实际打到 `http://192.168.255.128:80`（不是目标端口），连接被拒 → 异常上抛 → 引擎按四态契约记 **WARN**（正确分类，未折叠成 SAFE）。

- 全库范围：REQS 中使用 `{{RootURL}}` 的插件**恰为这 3 个**（其余 1195 个用 `{{BaseURL}}`，`get_origin()` 保留端口）。因此在**任何非标准端口**的目标上，这 3 个插件必然误报 WARN；若目标恰好在 80 端口开放，则会静默打错目标。
- 轮次 3（TCP）这 3 个插件未 WARN——协议探测阶段就返回，连请求都没发。

**判定：这是插件库的移植缺陷，不是引擎误报。** 引擎把它记成 WARN 而不是 SAFE，行为正确。

### 7.4 协议不匹配被记成 SAFE 而非 SKIP（四态语义缺陷）

`ss.py` 的协议门控是 `if url.protocol and url.protocol != _plugin.info.protocol and ...`——**`url.protocol` 为空时短路**，不产生 SKIP。`utils/plugin.py` 的 `is_vaild_url()` 里协议检查被整段注释掉。后果：

- 轮次 3（裸 `host:port` 目标）1198 个 http 插件全部被判 **SAFE**，DATA 写 `the network protocol does not match.`——但按四态契约，SKIP 才是"目标不适用"的正确状态。
- 同一现象在轮次 1/2/4 的 3 个 `{{RootURL}}` 插件上也会出现（它们没发请求就返回 SAFE）。
- **影响**：SAFE 计数被系统性抬高，"vuln 未检出"与"根本不适用"在结果表里**无法区分**。若只看主 CSV 的 SAFE 列，会把"插件根本没跑"误读为"跑过了，没中"。

### 7.5 插件参数 / 凭据通道缺失（端点 2 的直接死因）

- `Info.params` 字段存在，语义是"插件必需参数"（`utils/plugin.py:96-97`）。
- `ss.py` 的 `_task_wrapper(url, plugin)` 调 `plugin.do_testing(url)`，**从不传 `data`** → `do_testing` 的 `data` 恒为 `{}`。
- 命令行**没有任何**传参入口（`-t/-m/-p/-o/-i/-is/-dps`）。
- 因此：任何声明了 `params` 的插件必然落入 `missing required param(s)` → WARN。
- 实测：1198 个 read_only 插件**无一**声明 `params`（检索 `params\s*=\s*\[` → 0）→ 这条 WARN 路径在本轮从未被触发，属于**事实上的死代码**。
- 结论：**认证墙型目标在当前引擎下原理上不可检出**，与插件质量无关。

### 7.6 SAFE 行无证据，不可诊断

轮次 1/2/4 中 **1195 条 SAFE 行的 DATA 全部是字面量 `no match`**（第 1196 条 SAFE 是仓库自带的 `WhatWAF`，它的 DATA 反而带回了完整响应体）——**不含探测的 URL、请求方法、HTTP 状态码、响应长度**。这使得"为什么没中"无法从结果 CSV 回答（本次全部靠 `research/t2b_raw/why_safe.py` 现场复现才补上）。这直接放大了 §3.4 / §4.4 / §6.4 的分析成本。

### 7.7 URL 列在协议探测失败时损坏

轮次 3 的 URL 列渲染为 `None://192.168.255.128:28162/`（`url.protocol` 被赋值为 `None` 后 `get_full()` 直接拼串）。该列不可被下游解析器直接消费。

### 7.8 SKIP CSV 缺失

`_write_outputs()` 无条件调用 `save_csv(skip_rows, path_skip)`，但 0 条 SKIP 时**不产生文件**（4 轮均无 `-skip.csv`），而 `-warn.csv` 有文件。空结果与"没写"在文件系统上不可区分。

### 7.9 `-dps` 的副作用

`-dps` 时不写 `hosts-info-*.csv`（引擎日志明确提示 "port scanning is disabled"），且 `port_alive` 直接由插件目标 key 构造（`ss.py:237`）——即端口"存活"未经探测确认，是**假定**而非**观测**。本轮 4 个端点的端口可达性由我独立用 curl/socket 另行确认。

### 7.10 已知缺陷的规避确认

argparse 多个 `-t` 只保留最后一个——本轮每轮单端点，未触发。规避方式记录在 §2.2。

---

## 8. 工具/插件库覆盖洞清单（汇总，按可行动性排序）

### A. 产品级空洞（暴露面有、插件库整个产品缺失）

| 优先级 | 缺口 | 证据 |
|---|---|---|
| P0 | **GitList 全产品** | 2063 个插件文件中 `gitlist` 0 命中 |
| P0 | **ActiveMQ OpenWire / TCP** | 全库 0 个 OpenWire 插件；`protocol != http` 的插件仅 1 个（Redis, risky） |
| P1 | **ActiveMQ Web 管理台（认证墙后）** | 认证墙 + 引擎无凭据通道，双重不可达 |
| P1 | **Solr `/solr/admin/info/properties`（含 `STOP.KEY`）** | 检索 `info/properties` → 0 个 read_only 插件 |

### B. 模式级空洞（有一类暴露面，插件库一类都没有）

| 缺口 | 检索证据（read_only 集，1198 个） |
|---|---|
| 通用响应头版本识别（`X-Powered-By` / `Server`） | `X-Powered-By` → **0** |
| Apache `mod_status`（`/server-status`） | `server-status` → **0** |
| 通用"依赖/资源目录暴露"（`/vendor/`） | 11 个 `vendor/` 插件全是产品特定子路径，无通用检测 |
| 通用"认证 realm 识别"（`ActiveMQRealm`） | `ActiveMQRealm` → **0** |
| 二进制 banner 字段解析（`ProviderVersion`/`CacheEnabled`/wire-format-info） | 全部 → **0** |
| Solr 管理台其余端点（`info/system`/`cores`/`authentication`/`collections`/`zookeeper`） | 全部 → **0** |
| `configoverlay` 参数面 | → **0** |
| GitList 功能面（`/refresh`、`zipball`、`tarball`、`rss/`、`commits/`、`treegraph`） | 全部 → **0** |

### C. 契约级空洞（插件模型表达不了的东西）

| 缺口 | 说明 |
|---|---|
| C1 | **无二进制/原始协议插件位**：`Info` 无 banner 字段，`run(url)` 入参仅 URL → TCP 类端点无法被任何插件表达（对应 G3-6） |
| C2 | **无凭据/认证参数通道**：`Info.params` 存在但 `ss.py` 从不填充，CLI 无入口 → 认证墙目标原理上不可检出（对应 G2-5） |
| C3 | **无版本感知适用性**：无法表达"仅当版本 < X 时判定"→ EOL 组件与版本相关 CVE 均无法收敛（对应 G1-8、G2-4、G4-7） |
| C4 | **无产品门控**：`FINGERPRINT` 在 `ss.py`/`utils/` 中 0 引用 → 每端点 1198 插件全量开火，噪声底 100% |
| C5 | **无通用产品指纹插件**：全库"只取根路径"的 17 个插件全是后门/OOB 检测器，**没有一个做产品识别**（§3.3）→ 指纹命中这一能力在插件库中不存在 |
| C6 | **SAFE 行不携带证据**：DATA 恒为 `no match`，不记录探测 URL/状态码 → 结果不可诊断（§7.6） |
| C7 | **协议不匹配语义错误**：应 SKIP 却记 SAFE，SAFE 计数虚高且掩盖"未执行"（§7.4） |

### D. 插件级缺陷（已复现）

| 缺陷 | 证据 |
|---|---|
| D1 | `{{RootURL}}` 展开丢端口 → 3 个插件在非标准端口目标上必然打到 :80，表现为 3×3=9 条 WARN + 1 条 TCP 轮 SAFE（§7.3） |
| D2 | `CVE-2023-50290` 匹配器 AND 组含 `system.env`，Solr 8.11.0 的 `/solr/admin/metrics` 不含该词 → 敞开的端点被判 SAFE（§6.3，附逐 matcher 复现输出） |
| D3 | 词匹配器把"版本差异"当"不存在漏洞"：AND 组要求 3 个词同时出现，版本升级任一改名即整体漏报（D2 是其具体实例） |

---

## 9. 清理与残留校验（残留 = 0 的证据）

**清理动作**：`rm -f plugins/T2B_*.py`、`rm -rf plugins/__pycache__`、删除本轮小程序测试残留 `hosts-plugin-result-261026.1845.csv`。

**校验 1 — `plugins/` 目录内容与扫描前逐字节一致**

```
$ find plugins/ -type f | sort
plugins/WhatWAF.py
plugins/__GitLab-ATO-CVE-2023-7028.py
plugins/__plugin_tpl.py

$ md5sum -c research/t2b_raw/plugins_baseline.md5
plugins/WhatWAF.py: OK
plugins/__GitLab-ATO-CVE-2023-7028.py: OK
plugins/__plugin_tpl.py: OK
```

**校验 2 — staging 残留计数**

```
$ find plugins/ -name 'T2B_*' | wc -l          → 0
$ find plugins/ -name '__pycache__' -o -name '*.pyc' | wc -l   → 0
```

**校验 3 — 未改动 `plugins_corpus/`、`utils/`、`ss.py`**

```
$ find plugins_corpus/ utils/ ss.py -newermt "2026-10-26 18:40" -type f | wc -l   → 0
$ find __pycache__/ -newermt "2026-10-26 18:40" -type f | wc -l                    → 0
```

（`git status --porcelain plugins_corpus/ utils/ ss.py` 中显示的 `M ss.py` / `M utils/*.py` / `?? plugins_corpus/` 是**本任务开始前**就存在的仓库状态，基线快照 `research/t2b_raw/git_baseline.txt` 记录了同一组条目；`plugins_corpus/` 在 git 中为未跟踪目录，故以 mtime 判定为准。）

**校验 4 — 仓库根无本轮残留产物**

仓库根 `hosts-plugin-result-*.csv` 仅剩本任务开始前就存在的 3 组（`261026.0857` / `.1555` / `.1733`）；本轮 4 轮的 CSV 已按端点重命名移入 `research/t2b_raw/`。

**唯一非 staging 的写入**：`.cache/ss.log`（引擎自带轮转日志，4 轮扫描被追加）——属引擎正常运行产物，非 staging 残留。

---

## 10. 原始数据路径清单

全部位于 `/opt/workspace/labs/simple-scanner/research/t2b_raw/`：

| 文件 | 内容 |
|---|---|
| `ep1_28081.log` | 轮次 1 引擎日志（含 summary 行原文、`=== EXIT_CODE=0 ELAPSED=18s ===`） |
| `ep1_28081-result.csv` | 轮次 1 主结果表（1199 行） |
| `ep1_28081-warn.csv` | 轮次 1 WARN 明细（3 行，含完整 traceback） |
| `ep2_28161.log` / `ep2_28161-result.csv` / `ep2_28161-warn.csv` | 轮次 2 同上（9s / 1199 行 / 3 行） |
| `ep3_28162.log` / `ep3_28162-result.csv` | 轮次 3 同上（34s / 1199 行 / 无 WARN） |
| `ep4_28180.log` / `ep4_28180-result.csv` / `ep4_28180-warn.csv` | 轮次 4 同上（9s / 1199 行 / 3 行） |
| `ep1_root.html` | 端点 1 根页原始 HTML（2969B，GitList 身份取证） |
| `solr_metrics.json` | 端点 4 `/solr/admin/metrics` 原始响应（108220B，`system.env` 缺失的取证） |
| `plugins_baseline.md5` | 扫描前 `plugins/` 三个基线文件的 md5 |
| `git_baseline.txt` | 扫描前 `git status --porcelain` 快照 |
| `stage_t2b.py` | staging 脚本（端口替换 + 落地校验） |
| `why_safe.py` | SAFE 归因脚本（打印 REQS/MATCHERS + 现场复现请求） |
| `evidence_fingerprint.py` | 证据型插件匹配器实跑脚本（17 个根路径插件 × 3 端点） |

> 说明：`research/t2b_raw/` 是本任务新建目录；`research/` 下已有的 `REPORT_T1.md`、`REPORT_T2FIX.md` 等为既往任务产物，未被修改。

---

## 11. 明确标注为 unknown 的项

1. 4 个端点各自是否存在**可利用漏洞**：**未知**。本报告不引用任何未在插件目录中实际出现的 CVE 编号，也不对利用方式做任何推断。
2. GitList 的**具体版本号**：未从响应中取到（页面无版本串），**未知**。
3. ActiveMQ HTTP 端（28161）的**具体版本**：realm 名不含版本，**未知**（TCP 端 banner 明确给出 5.17.3，但不能据此断定两个端点同版本）。
4. 认证墙之后的内容：**未知**（无凭据，不尝试猜测）。
5. 端点 1 的 `/refresh` 返回 500 的具体原因：**未知**（未做进一步攻击性排查）。
6. 端点 4 `/solr/admin/zookeeper` 返回 500 的原因：**未知**。
7. 端点 3 的 OpenWire 握手后行为：**未知**（未构造协议报文）。
