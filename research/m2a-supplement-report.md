# M2A 补充插件包报告 — 「大名鼎鼎 CVE」OOB/DSL 类 + 2026 PHP 新洞

> 2026-10-26 · 任务 M2A · 执行: worker（subagent）
> 目录: `plugins_corpus/supplement/`（12 个手工插件）、`tools/build_poc_index.py`、`tools/verify_supplement_m2a.py`、`research/poc-in-github-index.json`
> **2026-10-26 修订（任务 T2FIX）**：用户裁决「版本型 POC 无意义」→ 删除本包 2 个版本型插件
> （CVE-2026-109618/109619），本报告第 1、2 节内容仅作历史留档，**当前这两个洞无检测插件**。

## 1. 交付物清单

| 文件 | CVE | 类型/设计 | read_only/params | 验证结果（mock do_testing） |
|---|---|---|---|---|
| plugin CVE-2026-109618.py | ~~CVE-2026-109618 (PHP2Shell)~~ | ~~只读版本指纹（X-Powered-By/Server PHP/x.y.z 与修复版对照）~~ | ~~read_only~~ | **2026-10-26 已删除（版本型 POC）** |
| plugin CVE-2026-109619.py | ~~CVE-2026-109619 (PHP2Shell)~~ | ~~同上（共享修复版本表）~~ | ~~read_only~~ | **2026-10-26 已删除（版本型 POC）** |
| plugin CVE-2021-44228.py | CVE-2021-44228 (Log4Shell) | JNDI 回连注入（3 变体 × headers+path）+ error-based 降级 | params=['oob_domain'] | VULN（error-based signal）; 无参 WARN + direct False |
| plugin CVE-2022-22965.py | CVE-2022-22965 (Spring4Shell) | configFile 数据绑定注入（POST+GET）+ error-based 降级 | params=['oob_domain'] | VULN（error-based signal）; 无参 WARN + direct False |
| plugin CVE-2021-26084.py | CVE-2021-26084 (Confluence OGNL) | 算术 OGNL oracle（16*8787 回显计算值, 13 路径） | read_only | VULN（OGNL oracle 命中） |
| plugin CVE-2022-26134.py | CVE-2022-26134 (Confluence OGNL RCE) | whoami 只读 id 证明（X-Cmd-Response）+ 可选 OOB nslookup 腿 | read_only（whoami 无害 id 查询） | VULN（X-Cmd-Response） |
| plugin CVE-2020-14882.py | CVE-2020-14882 (WebLogic Console RCE) | 路径穿越到 console.portal + FileSystemXmlApplicationContext 回连 | params=['oob_domain'] | VULN（ADMINCONSOLESESSION 穿越信号）; 无参 WARN + direct False |
| plugin CVE-2018-2628.py | CVE-2018-2628 (WebLogic T3 反序列化) | T3 握手 + 模板原样序列化探针, 响应 \$Proxy 标记 | read_only（protocol=t3, 7001/7002） | VULN（TCP mock $Proxy114） |
| plugin CVE-2021-26855.py | CVE-2021-26855 (ProxyLogon) | 单步 SSRF 腿（X-AnonResource-Backend 回连, 模板判据） | params=['oob_domain'] | SAFE（回调待确认, 设计内无本地正例）; 无参 WARN + direct False |
| plugin CVE-2023-34362.py | CVE-2023-34362 (MOVEit SQLi) | 产品指纹 + 单引号错误注入探针（全链 INSERT 写库段不转写） | read_only | VULN（SQL 引擎报错信号） |
| plugin CVE-2024-3400.py | CVE-2024-3400 (PAN-OS GP 命令注入) | 模板三腿文件伪影探测（SESSID 穿越写入空文件验证 404→403） | **intrusive（非 read_only, 写文件伪影）** | VULN（file-artifact probe） |
| plugin CVE-2023-4966.py | CVE-2023-4966 (Citrix Bleed) | 超长 Host 头内存泄漏 + 泄漏会话令牌验证 | read_only | VULN（memory-leak proof） |

说明：CVE-2019-2725、CVE-2017-5638 语料已存在（plugins_corpus/2019、2017），本包按任务卡跳过。

## 1.1 删除裁决记录（2026-10-26，任务 T2FIX）

**用户裁决：版本型 POC 无意义——客户要证据，版本对照无法证明漏洞存在。**
合法 VULN 判定必须是响应回显证据（payload 算术结果、命令输出、注入反射、协议特征响应等）。
版本对照只能给出「潜在易受」，既不能证明漏洞存在，又会因回修版本/改版头而误报。

据此删除以下版本型插件（备份 `/tmp/opencode/t2fix-backup/`）：

| 已删文件 | 位置 | 判据类型 | 处置 |
|---|---|---|---|
| `CVE-2026-109618.py` | `plugins_corpus/supplement/` | PHP 版本号 vs 修复版本表 | 删除 |
| `CVE-2026-109619.py` | `plugins_corpus/supplement/` | 同上（共享修复版本表） | 删除 |
| `GitLab-RCE-CVE-2021-22205.py` | `plugins/`（常驻） | 从 `/users/sign_in` 或 `/help` 页面解析版本号 < 13.10.3 即判 VULN | 删除（T2 实测误报根因） |

连带改动：
- `tools/verify_supplement_m2a.py`：PHP 两洞的正负断言删除（文件已不存在，断言改为 skip 并注明）。
- `tools/verify_t1.py`：SUPPLEMENT_CASES 中两条 PHP2Shell 断言删除；T1 报告总数 843 → 841
  （833 语料 + 4 supplement read_only + 4 参数化），复跑结果 837 pass + 4 param-warn-pass、0 failed。
- `plugins_corpus/supplement/README.md`：新增「删除裁决记录」章节。

**遗留**：PHP2Shell（CVE-2026-109618/109619）当前无检测插件（宁可漏报不可误报）；
`plugins_corpus/2021/CVE-2021-22205.py`（语料转换产物）判据是 body 内 SHA-256 特征串匹配、
非版本号对照，按「语料 1500 既有文件不动」保留，但其同属指纹型，是否清理待后续裁决。

## 2. PHP 两洞调研结论（CVE-2026-109618 / CVE-2026-109619, "PHP2Shell"）〔历史留档〕

**结论先行**：两洞为 PHP 引擎内存安全 RCE（CVSS 4.0 = 9.2，CVSS 3.1 = 9.8），影响 PHP 5.4+ 全部受支持分支
（8.2/8.3/8.4/8.5 及更早 EOL 分支），2026-10-21 应急发布修复（8.2.35 / 8.3.36 / 8.4.27 / 8.5.12；
PHP 7.4/8.0/8.1 仅有源码级 backport，由发行版/LTS 维护者跟进）。已在野利用（截至 10-23 CISA KEV 未收录）。
**检测方法**：可无 OOB 检出——只读版本指纹（响应头 `X-Powered-By` / `Server` 中 `PHP/x.y.z` 低于修复号即“潜在易受”）。
nuclei 模板（CVE-2026-109618.yaml）的主动 OOM 崩溃探测腿属破坏性（触发 memory limit 中断/worker 不稳定），
本包刻意不转写；其内置的版本指纹腿（version-verdict）被本包 1:1 采纳。CVE-2026-109619 尚无独立模板，
nuclei 以同一模板合并覆盖（共享修复版本表），本包按同判据实现。

来源与原文片段：

1. **watchTowr FAQ（watchtowr.com/intelligence/php-cve-2026-109618-faq，2026-10-23 抓取）**
   - "CVE-2026-109618 is triggered when PHP runs out of memory partway through setting up a request, leaving internal data half built for the cleanup code to trust. CVE-2026-109619 comes from internal state that outlives the request memory it points to, so the next request that the same PHP worker picks up can act on that leftover data."
   - "Both allow an unauthenticated attacker to execute their own code on a server running PHP… Both are rated CVSS v4.0 9.2."
   - "Exploitation has been observed in the wild since October 21, 2026, through watchTowr's Attacker Eye global honeypot network. As of October 22, 2026, CISA has not added either CVE to its Known Exploited Vulnerabilities catalog."
   - 受影响版本表：PHP 8.2.x < 8.2.35 / 8.3.x < 8.3.36 / 8.4.x < 8.4.27 / 8.5.x < 8.5.12；7.4/8.0/8.1 无官方发布、7.3 及更早（含 PHP 5）无修复。

2. **Unit 42 Threat Brief（unit42.paloaltonetworks.com/cve-2026-109618-cve-2026-109619，检索快照）**
   - "CVE-2026-109618 involves a remote code execution vulnerability where handling out-of-memory errors via longjmp() leaves request memory uninitialized due to improper control flow management, allowing attackers to reliably achieve RCE using out-of-memory (OOM) triggers."
   - "CVE-2026-109619 describes a remote code execution vulnerability where longjmp() fatal error handling leaves global memory pointing to freed memory regions. These regions can later be read or branched on during subsequent requests, enabling attackers to execute arbitrary code."

3. **Sansec（sansec.io/research/php2shell）**："CVE-2026-109618 also discloses server memory on its own. PHP's upload-progress handler can return freed worker memory to the client inside a PHPSESSID response cookie."（内存泄漏附带效应，非稳定检测信号）

4. **PHP 官方**：`https://www.php.net/index.php#2026-10-21-5`（nuclei 模板 reference 内嵌）；GitHub Security Advisories：
   GHSA-w8hw-w9fx-j79w（109618）、GHSA-6wmf-4rv5-p3rp（109619）。

5. **VulnCheck（vulncheck.com/blog/php2shell-vulnerabilities）**：在野扫描器 UA `php2shell-scan/109618` 发送 multipart 文件上传请求到 `index.php`——针对 109618 的 upload-progress/OOM 触发。

## 3. Log4j 降级检测实测说明（CVE-2021-44228）

- **主路径（有 oob_domain）**：注入 `${jndi:ldap://{oob_domain}/x}`（+ `${${lower:j}ndi:...}`、`${${::-j}${::-n}...}` 两种 WAF 绕过变体）到 GET query path 与 User-Agent/Referer/X-Forwarded-For/Cookie/X-CSRF-Token 等多个请求头。**强信号 = oob_domain 上收到 DNS/LDAP 回调**；本地无法代替。
- **无 oob_domain（params 声明）**：引擎层 `do_testing` 记 `WARN: missing required param(s): oob_domain`（四态契约潜在漏报信号）；`run()` 直调时走降级：payload 指向失效 sink `127.0.0.1:1`，若响应 5xx 或 body 含 JNDI 报错特征（`javax.naming.NamingException`/`log4j`/`lookup` 等 10 个不敏感标记）→ `(True,'error-based signal: ...')`，否则 `(False,'no OOB configured, manual check required')`。
- **实测输出（本地 mock）**：
  - 回显错误应用（503 + `javax.naming.NamingException...`）→ `OUTCOME=vuln`，DATA=`error-based signal: JNDI injection into query path triggered abnormal response (status=503)`
  - 非回显应用（200 正常页）→ `(False,'OOB payload injected ... confirm DNS/LDAP callback on <domain>')`（有参）/ `(False,'no OOB configured, manual check required')`（无参直调）
  - 无参 `do_testing` → `OUTCOME=warn`，DATA=`missing required param(s): oob_domain`
- **限界**：error-based 是弱启发（依赖应用回显 log4j 报错）；仅靠本地响应无法证明被攻击向量真实执行，报告标注"OOB 待确认/人工核验"。

## 4. PoC-in-GitHub 补充索引（P2）

- 通道实测：`api.github.com`（仓库元数据）与 `cdn.jsdelivr.net/gh/nomi-sec/PoC-in-GitHub@master/...`（逐文件）可达；仓库体积 ~1GB（GitHub API size=1026053KB），**整包 tarball 方案不可行**，改用 jsDelivr 逐文件下载（并发 6、0.03s 节流、404 视为无条目跳过、磁盘缓存断点续跑）。
- 索引范围：`2023/2024/2025/2026` 四个年份目录共 4332 个 CVE JSON（data.jsdelivr flat list 枚举）。
- 产物：`research/poc-in-github-index.json` = `{cve: [poc_repo_urls]}`（仅含至少 1 个 PoC 仓库的 CVE）。
- **最终统计（实测输出）**：
  | 项 | 数值 |
  |---|---|
  | 2023-2026 年 CVE JSON 总数（flat list 枚举） | 4332 |
  | 索引条目数（≥1 个 PoC 仓库的 CVE） | **4236** |
  | PoC 仓库 URL 总数 | **10597** |
  | 无条目/404（flat list 与 CDN 不一致的陈旧文件） | 96 |
  | 语料(1500)+本包已覆盖且在索引中 | 134（语料 2023-2026 共 465，其中 131 在索引内；本包 3 个 2023-2024 洞在索引内） |
  | **本索引新增补充覆盖的 CVE（此前语料+本包未覆盖）** | **4102** |
- 重建方式：`cd /opt/workspace/labs/simple-scanner && .venv/bin/python tools/build_poc_index.py --years 2023 2024 2025 2026 --concurrency 6`（原始 json 缓存在 `/tmp/opencode/poc-json/`，可断点续跑）。
- 边界：这些仓库是 PoC 脚本/工具源码，**非 nuclei 可转换模板**，只做索引不转代码（任务卡明示）。

## 5. 遗留与提示

1. `CVE-2024-3400` 非 read_only（写文件伪影）——load 层如需"可用集=仅 read_only"过滤，请排除；文件头已标注。
2. `CVE-2022-26134` whoami 腿按任务卡判据归 read_only（幂等无害命令），但确属命令执行——发行评审时可改 risky 标记。
3. `CVE-2021-26855`/`CVE-2021-44228`/`CVE-2022-22965`/`CVE-2020-14882` 的强检出需外部 oob_domain 回调基础设施；无 OOB 环境的输出只是触发消息/降级信号，需人工核验。
4. PHP2Shell 版本指纹依赖 `X-Powered-By`/`Server` 头（可被关闭）→ 存在漏报；无法确认时插件返回"manual check required"。
5. 本包插件未并入 `plugins_corpus/manifest.json`（不碰既有产物）；如需纳入 load 流程，建议扩展 manifest 或在 loader 加入 supplement 目录扫描。
6. 下载侧 404 条目（flat list 与 CDN 不一致的陈旧文件）已按无条目跳过并在构建日志计数。