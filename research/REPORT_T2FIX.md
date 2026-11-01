# REPORT_T2FIX — 版本型插件清除 + 转换器三边界扩展 + 三靶场端到端验证

> 2026-10-26 · 任务 T2FIX · 执行: worker（subagent）
> 仓库: `/opt/workspace/labs/simple-scanner`（venv `.venv/`）
> 靶场: `192.168.255.128` 的 8081 / 16379 / 18080（授权范围）

## 0. 结论先行

| 目标 | 结果 | 证据 |
|---|---|---|
| ① 删除版本型插件 | ✅ 完成 3 个（2 supplement + 1 常驻） | T1 回归 843 → 841，837 pass / 4 param-warn-pass / 0 failed |
| ②a 目录扩展 `http/vulnerabilities/` | ✅ 转换器支持，生成 551 个增量插件 | `plugins_corpus/vulns/` 551 个 + manifest-vulns.json |
| ②b network/tcp 模板支持 | ✅ 转换器新增 tcp 插件生成 | `plugins_corpus/vulns/CVE-2022-0543.py`（protocol='tcp'） |
| ②c flow 降级（Tomcat 两腿） | ✅ 手工插件落地（通用 flow 转换留后续卡） | `plugins_corpus/supplement/CVE-2017-12615.py` |
| ②d PHP 后门 1:1 转写 | ✅ 转换器产物 | `plugins_corpus/vulns/php-zerodium-backdoor-rce.py` |
| ③ 三靶场端到端检出 | ✅ **3/3 全检出**（两轮独立复现） | 见 §3 |
| ③ 误报核对 | ⚠️ 发现 1 个**新增语料误报** CVE-2021-45092（根因在转换器 regex 语义），已定位未修 | 见 §4 |
| ③ 清理 | ✅ plugins/ 与扫描前 md5 一致，探针文件 404 | 见 §6 |

---

## 1. ① 删除清单 + T1 回归

### 1.1 已删文件

| 文件 | 位置 | 判据类型 | 删除理由 |
|---|---|---|---|
| `CVE-2026-109618.py` | `plugins_corpus/supplement/` | `X-Powered-By`/`Server` 的 PHP 版本号 vs 修复版本表 | 版本型：给不出证据 |
| `CVE-2026-109619.py` | `plugins_corpus/supplement/` | 同上（共享修复版本表） | 版本型：给不出证据 |
| `GitLab-RCE-CVE-2021-22205.py` | `plugins/`（常驻） | 从 `/users/sign_in`、`/help` 页面解析版本号 < 13.10.3 即判 VULN | 版本型：T2 实测误报根因 |

- 备份：`/tmp/opencode/t2fix-backup/`（会话内可回滚）
- `plugins/__GitLab-ATO-CVE-2023-7028.py`（`__` 前缀，引擎本就不加载）**未动**
- 语料 `plugins_corpus/2021/CVE-2021-22205.py` **未动**（判据是 body 内 SHA-256 特征串、非版本号对照；按「语料 1500 既有文件不动」保留，是否清理待后续裁决）

### 1.2 连带改动

| 文件 | 改动 |
|---|---|
| `tools/verify_supplement_m2a.py` | 删除 CVE-2026-109618/109619 的 3 条断言（正/负/版本对照）及其 `php_responder` 辅助函数 |
| `tools/verify_t1.py` | 删除 `SUPPLEMENT_CASES` 中 2 条 PHP2Shell 断言 + `_php2shell_responder`；报告口径 843 → 841 |
| `plugins_corpus/supplement/README.md` | 新增「删除裁决记录（2026-10-26）」章节 |
| `research/m2a-supplement-report.md` | 新增「1.1 删除裁决记录」；第 1/2 节标注为历史留档 |
| `research/REPORT_T1.md` / `research/T1-verdict.json` | 由 `verify_t1.py` 重新生成（数字自然对齐） |

### 1.3 T1 回归输出（重跑）

```
$ .venv/bin/python tools/verify_t1.py
fixture build done: 833 plugins, 1.1s
...
report -> research/REPORT_T1.md, research/T1-verdict.json
== summary ==
corpus=833 supplement=8 total=841
counts: {'pass': 837, 'param-warn-pass': 4}
elapsed: 7.0s
```

`REPORT_T1.md` 第 14 行：`supplement 纳入 | read_only 4 个 (CVE-2021-26084/2022-26134/2023-34362/2023-4966; 2026-10-26 用户裁决删除版本型 CVE-2026-109618/109619)`；第 34 行 `| 总数 | 841 |`。
`T1-verdict.json` → `counts: {'pass': 837, 'failed': 0, 'untestable': 0, 'param': 4, 'warn': 0}`。

---

## 2. ② 三个新插件实体 + 生成方式

### 2.1 PHP 8.1.0-dev 后门（转换器产物）

- 路径：`plugins_corpus/vulns/php-zerodium-backdoor-rce.py`
- 来源：`http/vulnerabilities/backdoor/php-zerodium-backdoor-rce.yaml`（1:1 转写，转换器生成，非手写）
- 判据：`GET /` 带 `User-Agentt: zerodiumvar_dump(233333*333332);` 头 → body 命中 `int(77777355556)`
- 风险分层 `read_only`；`fingerprint=['php']`；`ports=[80]`（模板无端口声明，按卡指定）
- 生成命令：
  ```
  .venv/bin/python tools/convert_nuclei.py \
      --scan-root http/vulnerabilities --out-subdir vulns \
      --manifest-name manifest-vulns.json --no-cve-ok
  ```
  模板级覆盖写在 `tools/convert_nuclei.py` 的 `TEMPLATE_OVERRIDES`（`ports=[80]`、`fingerprint=['php']`）

### 2.2 Redis CVE-2022-0543（转换器产物，network/tcp）

- 路径：`plugins_corpus/vulns/CVE-2022-0543.py`
- 来源：`network/cves/2022/CVE-2022-0543.yaml`（单输入、`inputs.data` 定长、regex matcher → 命中转换器新增的 network 支持形态）
- `Info.protocol='tcp'`、`port=6379`、`ports=[6379]`、`fingerprint=['kev','network','redis','tcp','vkev']`、风险 `risky`（`command-execution-payload`）
- 实现：`run()` 用 `self.make_tcp_client()` 直接发 `DATA`（含 `EVAL ... 0\r\n`），读窗口 1.5s 静默即止（Redis EVAL 回包有延迟），regex `root:.*:0:0:`
- 生成命令：
  ```
  .venv/bin/python tools/convert_nuclei.py \
      --scan-root network/cves/2022 --only-cve CVE-2022-0543 \
      --out-subdir vulns --manifest-name manifest-vulns.json --no-cve-ok
  ```
  端口覆盖 `6380 → 6379` 同样写在 `TEMPLATE_OVERRIDES`（模板写的 6380 非 Redis 标准端口）

### 2.3 Tomcat CVE-2017-12615（手工插件，flow 降级）

- 路径：`plugins_corpus/supplement/CVE-2017-12615.py`（手工文件，非转换器产物）
- 来源模板 `http/cves/2017/CVE-2017-12615.yaml` 的 `flow: http(1) && http(2)`，降级为两腿顺序执行：
  1. **腿1** `PUT /<rand8>.jsp/` body = `<% out.print(NUM1*NUM2); %>`（NUM1/NUM2 = `random.randint(30000,40000)` 内联）
     - 模板内部 201 匹配器降级为**软检查**：非 201 只记 `last_err`，不中断
  2. **腿2** `GET /<rand8>.jsp` → 断言 `status==200` 且 body 含 `NUM1*NUM2` 计算结果
     - **腿2 命中才 True**（服务端真的执行了 JSP = 证据型判定）
  3. **清理**：`run()` 末尾无条件 `DELETE /<rand8>.jsp/`；DELETE 失败只记 WARN 文案，不影响 VULN 判定
- 风险分层 `risky`；文件头注明「写入探测文件后必须 DELETE 清理」
- 转换器的 **flow 通用转换未实现**，本卡只落地这一个手工插件（待办见 §7）

### 2.4 ②a 目录扩展的增量产物

| 项 | 数值 |
|---|---|
| 扫描根 | `http/vulnerabilities/`（963 个 yaml） |
| 可转换并生成 | 551 个（其中 3 个带 CVE 号，548 个无 CVE → catalog=模板 id） |
| 产物目录 | `plugins_corpus/vulns/`（552 个文件 = 551 http + 1 tcp） |
| 增量 manifest | `plugins_corpus/manifest-vulns.json`（552 条，protocol: http 551 / tcp 1；risk: read_only 365 / risky 181 / excluded 6） |
| 报告 | `plugins_corpus/REPORT-vulns.md`、`plugins_corpus/REPORT-vulns-network.md` |
| 既有 1500 | **未动**：`plugins_corpus/manifest.json` md5 `70bb0e6ab861d4773ba9c8ad5ac6ace4`、`REPORT.md` md5 `8f3a05b7030455467cd315c9efb3e4a5` 前后一致；`find plugins_corpus -name '*.py' -newermt ... -not -path '*/vulns/*' -not -path '*/supplement/*'` 为空 |
| 导入自检 | `plugins_corpus/vulns` 552/552 import+实例化通过 |

---

## 3. ③ 三靶场端到端验证（四态 + 证据 + 耗时）

### 3.1 staging 手法

- 语料 833 read_only + supplement 10 + 3 个新插件 → 复制进 `plugins/`，文件名加 `T2_` 前缀（`T2_corpus_*` / `T2_suppl_*` / `T2_new_*`），共 846 个 staged 文件
- **ports 声明临时改到实验端口**（语料/supplement 全部 `[80,443,8080,8443]` → 加 8081/16379/18080；php-zerodium → `[80,8081]`；redis → `[6379,16379]`；tomcat → 加 18080），否则引擎端口门控会全部 SKIP（实测确认）
- 引擎侧：`ss.py -t 192.168.255.128:<port> -dps -p 4`
- **argparse 多 `-t` 覆盖已实证**：`ss.py -t 192.168.255.128:8081 -t 192.168.255.128:18080` 的产物 `hosts-plugin-result-261026.1650.csv` 2 行**全部落在 18080**，8081 未被扫 → 后续分三次单端口跑（`ss.py` 不在可改范围，仅记录该缺陷）

### 3.2 结果（staging 846 + 常驻 3 → 每轮 847 个任务）

| 靶场 | 端口 | 任务数 | VULN | SAFE | WARN | SKIP | 耗时 | 证据行（CSV 原文） |
|---|---|---|---|---|---|---|---|---|
| PHP 8.1.0-dev 后门 | 8081 | 847 | **2** | 837 | 6 | 2 | 19s | `VULN \| php-zerodium-backdoor-rce \| matched GET on http://192.168.255.128:8081 status=200` |
| Redis CVE-2022-0543 | 16379 | 847 | **1** | 840 | 4 | 2 | 640s (10m40s) | `VULN \| CVE-2022-0543 \| matched tcp probe on 192.168.255.128:16379 (response 984 bytes)` |
| Tomcat CVE-2017-12615 | 18080 | 847 | **2** | 837 | 6 | 2 | 20s | `VULN \| CVE-2017-12615 \| JSP executed by server: GET /8wqxj4mp.jsp status=200 body contains 1125390565 (payload 30719*36635); cleanup: DELETE /8wqxj4mp.jsp/ status=204` |

**3/3 全部检出。** 三个漏洞各自的证据（原始响应实测）：

```
PHP   : GET /  -H 'User-Agentt: zerodiumvar_dump(233333*333332);'  →  int(77777355556)\nhello world
Redis : EVAL '...io.popen("cat /etc/passwd")...' 0\r\n              →  $976\r\nroot:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:...
Tomcat: PUT /<rand>.jsp/ (201) → GET /<rand>.jsp (200, body=1125390565=30719*36635) → DELETE /<rand>.jsp/ (204)
```

WARN 明细（php/tomcat 各 6 条，与 T2 基线同源）：
- `CVE-2021-44228` / `CVE-2021-26855` / `CVE-2020-14882` / `CVE-2022-22965` → `missing required param(s): oob_domain`（supplement 的 OOB 型插件，引擎按四态记 WARN）
- `CVE-2022-35405` / `CVE-2021-45232` → 连接异常 traceback（语料插件，**与 T2 基线完全相同的 2 个**，无新增）

### 3.3 计数代理轮（线级请求量 + 独立复现）

在 `127.0.0.1:<同端口>` 起一个透明转发代理（转发到真靶场）统计 TCP 连接数 / HTTP 请求行 / 字节数，再跑同样的扫描：

| 靶场 | TCP 连接 | HTTP 请求行 | 客户端→服务端字节 | 耗时 | 四态 | 与直连轮一致 |
|---|---|---|---|---|---|---|
| php 8081 | 4404 | 1883 | 1,969,622 | 19.6s | VULN=2 SAFE=837 WARN=6 SKIP=2 | ✅ 一致 |
| tomcat 18080 | 4211 | 1880 | 1,935,492 | 18.4s | VULN=2 SAFE=837 WARN=6 SKIP=2 | ✅ 一致 |
| redis 16379 | 5036 | 2517 | 1,987,329 | 640.1s | VULN=1 SAFE=840 WARN=4 SKIP=2 | ✅ 一致 |

效率解读：
- 三个新插件自身极省：php 1 请求、redis 1 次 TCP、tomcat 3 请求（PUT+GET+DELETE）
- 全量 846 插件单轮 ≈ 1900~2500 个 HTTP 请求（解析计数 2728 偏高：把 `https_or_http()` 的 2 次协议探测连接和 urllib3 重试也计入了，实测以线级计数为准）
- redis 轮 10m40s 的原因：845 个 http 插件打 Redis 端口 → Redis 回 `-ERR` 畸形响应 → urllib3 重试退避（约 3s/插件 ÷ 4 进程）

---

## 4. ④ 全量复跑的误报核对

### 4.1 与 T2 基线对比（T2 基线 = `hosts-plugin-result-261026.1555.csv`，18080 端口，834 插件）

| 插件 | T2 基线 | 本卡 | 处置 |
|---|---|---|---|
| `CVE-2021-22205`（GitLab 版本型） | **VULN（误报）** | 已删除 → 不再出现 | ✅ 误报消除 |
| `CVE-2026-50229`（Tomcat numguess 回显） | VULN | VULN（保留） | 「匹配器命中但业务灰区」，按卡**保留并记录，不删** |
| `CVE-2022-35405` / `CVE-2021-45232` | WARN×2 | WARN×2 | 同源，无新增 |
| 其余 830 个 | safe | safe | 无新增误报 |

→ **18080 端口无新增误报**（VULN=2 = 1 个灰区 + 1 个新插件真检出）。

### 4.2 新发现的语料误报（CVE-2021-45092，PHP 靶场）

```
VULN | CVE-2021-45092 | matched GET on http://192.168.255.128:8081/lab.html?vpath=//interact.sh status=404
```

- 根因（已定位到转换器源码）：`tools/convert_nuclei.py` 的 `PLUGIN_TEMPLATE._match_one()` 中，`regex` 分支逐个 `re.search` 后 `break`，**多个正则之间取「或」**，而 matcher 的 `condition: 'and'` 只在 `word` 分支（`_msg_hit`）被使用 → 多正则 matcher 的 AND 语义丢失。
- 该模板的 matcher 是 `regex: ['.*vpath.*', 'thinfinity']`（AND）。PHP 靶场的 404 页把 URL 回显（body 含 `vpath`），但 `thinfinity` 并不在 body 中（实测 `grep -ci thinfinity` = 0）→ 仍被判 VULN。
- 影响面：语料里 67 个插件含多正则 matcher（`regex: [` 出现 >1 次），均被按 OR 处理，存在同类潜在误报。
- 处置：**未修**。原因：修正需重新生成语料插件，而本卡边界明确「语料 1500 个既有文件不动」；且单独改转换器会造成「转换器语义」与「已生成语料」不一致的半吊子状态。已作为待办记入 §7（修复点：`PLUGIN_TEMPLATE._match_one()` 的 regex 分支需按 `m['condition']` 聚合）。

---

## 5. ⑤ 转换器改动摘要（`tools/convert_nuclei.py`）

| 改动 | 类型 | 说明 |
|---|---|---|
| `NETWORK_PLUGIN_TEMPLATE` | 新增 | network/tcp 插件模板（token 占位 `__DATA__` 等 + `str.replace` 注入） |
| `build_network_model()` | 新增 | network 模板 → model；只支持「单输入、`inputs.data` 定长、regex/word matcher」形态，其余返回 skip 原因（`multi-input` / `input-has-placeholder` / `matcher-dsl` / `matcher-binary` / `multi-tcp-block` …） |
| `risk_classify_network()` | 新增 | tcp 载荷风险分层（revshell/delete/user/exfil → excluded；exec → risky；否则 read_only） |
| `gen_plugin_source()` | 改 | `protocol == 'tcp'` 走新模板分支 |
| `build_model()` | 改 | 返回值加 `'protocol': 'http'` |
| `main()` | 改 | 扫描根参数化（`--scan-root` 覆盖 / `--extra-root` 追加）；network 模板路由（`data['tcp']` 列表 → tcp 分支）；`--out-subdir` 平铺输出 + `--manifest-name` 增量 manifest（幂等合并）；`--no-cve-ok` 无 CVE 模板以模板 id 作 catalog；`--only-cve` 定向转换；`--report-name` |
| `TEMPLATE_OVERRIDES` | 新增 | 模板级覆盖（卡指定）：`php-zerodium` → `ports=[80]`/`fingerprint=['php']`；`CVE-2022-0543` → `ports=[6379]` |
| network 模板注入方式 | 修 | 起初用 `str.format()`，与模板内字面花括号冲突（`IndexError: Replacement index 0 out of range`）→ 改 token 占位 + `str.replace` |
| 默认模式行为 | **不变** | `--out-subdir` 为空时仍按 `http/cves/<year>/` + `manifest.json` + `REPORT.md` 输出，既有 1500 语料与 manifest/REPORT md5 未变 |

**未实现（卡内明确不强制）**：flow 的通用转换（`build_model` 遇 `flow` 仍返回 skip 原因 `flow`），已记入 `REPORT-vulns.md` 与 §7。

---

## 6. ⑥ 清理证据

| 项 | 证据 |
|---|---|
| `T2_*` 插件文件 | 删除 846 个；`plugins/` 内 `T2_` 残留 = **0** |
| `__pycache__` 残留 | `plugins/__pycache__/T2_*.pyc` 848 个已删；残留 = **0** |
| `plugins/` 与扫描前一致 | 扫描前快照（md5）`['WhatWAF.py', '__GitLab-ATO-CVE-2023-7028.py', '__plugin_tpl.py']` vs 扫描后：**新增 0 / 缺失 0 / 内容变化 0 → 完全一致**（唯一差异是本卡有意删除的 `GitLab-RCE-CVE-2021-22205.py`） |
| Tomcat 探针文件 | 4 个探针（`8wqxj4mp.jsp` / `cjxlgutd.jsp` / `jq44qolu.jsp` / `zgo8dcy4.jsp`）逐一 `GET http://192.168.255.128:18080<path>` → **全部 404**（文件已清理）；插件自身 DELETE 返回 204 |
| 仓库根临时产物 | 本卡新增的 `hosts-plugin-result-261026.1650/1651*.csv` 已移出仓库根，证据副本留在 `/tmp/opencode/t2fix-evidence/`；T2 归档的 `0857`/`1555` 两批**未动** |
| 语料 1500 | 零改动（md5 + mtime 双证，见 §2.4） |

---

## 7. ⑦ 遗留

1. **转换器 flow 通用转换未实现**（卡内允许）：nuclei `flow: http(1) && http(2)` 仍被 skip（原因码 `flow`）。本卡只有 CVE-2017-12615 的手工降级插件。实现入口：`build_model()` 里 `flow` 分支 + 生成两腿顺序执行模板。
2. **network/tcp 只做了 CVE-2022-0543**：`network/` 下形态匹配的模板共 80 个（c2/detection/cves），其余留后续卡批量转换。
3. **http/vulnerabilities 增量只收了「能转换的」**：963 个模板中 911 个无 CVE、36 个依赖 `interactsh-url`（OOB）、5 个 raw 解析失败、1 个 payloads 攻击、1 个 flow 被跳过。548 个无 CVE 模板以「模板 id 作 catalog」入库，属检测型插件，不是 CVE 级漏洞。
4. **转换器 regex 多模式 `and` 条件被当 `or`**（§4.2）：语料 67 个多正则插件存在同类潜在误报；修复需连带重新生成语料（超出本卡「1500 不动」边界），需单独裁决。
5. **PHP2Shell（CVE-2026-109618/109619）当前无检测插件**：用户裁决版本型 POC 无意义，若要覆盖需另找回显型探针（本次未做）。
6. **语料 `plugins_corpus/2021/CVE-2021-22205.py` 保留待裁**：判据是 body 内 SHA-256 特征串（非版本号对照），性质上仍属「指纹型」，是否清理待后续裁决。
7. **ss.py argparse 多 `-t` 覆盖缺陷**（`nargs='+'` + `store` 动作，后者覆盖前者）：`ss.py` 不在可改范围，仅记录；实操上每次只能扫一个端口。
8. **Redis 轮效率**：845 个 http 插件打 Redis 端口触发 urllib3 重试退避，10m40s。可考虑按协议分组（http 插件不投 tcp 端口）作为后续优化项。
9. **L2 门控元数据**：`fingerprint` 仍挂在 `Info` 实例属性上（`Info` 基类无该字段，不改 `utils/`），`tcp` 类插件的 fingerprint 由模板 tags 推导，含 `tcp`/`kev` 等噪声词，后续可再收敛。

---

## 8. 附：证据文件位置

| 内容 | 路径 |
|---|---|
| 三轮直连扫描（主证据） | `/tmp/opencode/t2fix-runs/{php,redis,tomcat}/hosts-plugin-result-*.csv` + `scan.log` |
| 三轮计数代理扫描 | `/tmp/opencode/t2fix-runs/count-{php,redis,tomcat}/`（含 `proxy-stats.json`） |
| 多 `-t` 覆盖实证 | `/tmp/opencode/t2fix-evidence/hosts-plugin-result-261026.1650.csv` |
| 引擎内定向验证 | `/tmp/opencode/t2fix-evidence/hosts-plugin-result-261026.1651.csv`（+ `-skip.csv`） |
| 删除前备份 | `/tmp/opencode/t2fix-backup/` |
| 插件目录扫描前快照 | `/tmp/opencode/t2fix-plugins-snapshot.json` |
| 增量 manifest / 报告 | `plugins_corpus/manifest-vulns.json`、`plugins_corpus/REPORT-vulns.md`、`plugins_corpus/REPORT-vulns-network.md` |
