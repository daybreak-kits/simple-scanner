# T3-VERIFY · 真实网络端到端验证报告（引擎 + 833 个 read_only 插件）

> 2026-10-26 · 执行体：worker · 任务卡：T3-VERIFY
> 目的：验证 **引擎行为**（可跑 / 结论正确 / 门控 SKIP 正确 / 退出码 0 / 产物齐全），
> **不是漏洞命中验证**。VULN 命中属于待人工核验的真阳性候选，不作为结论。

## 1. 授权与白名单

甲方明文授权的公开靶场，仅限以下主机（未越界，未访问任何其它公网主机）：

| 目标 | 授权依据 | 本环境可达性 |
|---|---|---|
| scanme.nmap.org | https://scanme.nmap.org/ 明文允许扫描 | ✅ 22 / 80 open（45.33.32.156） |
| testphp.vulnweb.com | 站内明文邀请安全测试 | ❌ 44.228.249.3:80/443/8080 全部 connect 超时（filtered） |
| testhtml5.vulnweb.com | 同上 | ❌ 同 IP，同样 filtered |
| testsparker.vulnweb.com | 同上 | ❌ DNS 无解析记录（gaierror -2，域名已不存在） |

可达性证据：`/tmp/opencode/e2e-t3/out/*/run_summary.json` 与 `hosts-info-*.csv`（端口态 `filtered`）。
本沙箱无 HTTP 代理（`env` 无 `HTTP_PROXY`），DNS 走 Docker 内嵌解析器（127.0.0.11），
解析正常但到 44.228.249.3 的 TCP 出网被过滤 → **vulnweb 三目标的插件阶段无法在此环境执行**（见 §5）。

## 2. 方法（staging 与隔离）

- 语料：`plugins_corpus/manifest.json` 1500 条中 **risk_class=read_only 共 833 条**；
  `risky` 622 + `excluded` 45 共 667 条**未加载**（剔除记录见 `/tmp/opencode/e2e-t3/staging_manifest.json`）。
- staging：把 833 个 read_only 插件复制为 `CORPUS_<CVE>_<年>_<号>.py`（内容与语料逐字节相同，
  sha256 已比对），**放在 /tmp 的独立运行根** `/tmp/opencode/e2e-t3/run/`：
  `run/ss.py` + `run/utils/` 为仓库字节级副本（sha256 校验 `engine_identical: true`），
  `run/plugins/` 只含 833 个 CORPUS_* 插件。仓库 `plugins/` **全程未被写入**。
- 加载器自检：用 ss.py 同款加载逻辑（`pathlib.Path('plugins').glob('*')` + `importlib.import_module`）
  载入 → **833 个插件，protocol=http，ports=(80,443,8080,8443)，catalog 833 个唯一**，
  REQS 合计 1016（GET 947 / POST 69），单插件 1~9 条 REQS。
- 仓库 `plugins/` 里的 2 个常驻插件（GitLab-RCE-CVE-2021-22205 / WhatWAF）**未进入本次运行**：
  它们不是 read_only 语料，GitLab 插件还会探测 8080 并可能发出利用载荷。
- 引擎自带的 `plugins/` 目录扫描 + "存活端口的 IP 形态自动补目标"逻辑见 §7 异常 3。

## 3. 真实扫描结果（每目标 2 轮）

命令形态（scanme）：
`python ss.py -p 4 -t http://scanme.nmap.org:80 -t http://45.33.32.156:80 -t scanme.nmap.org:22`
（vulnweb：`python ss.py -p 4 -t http://<host>.vulnweb.com:80`）

| 目标 | 轮 | 退出码 | wall(s) | VULN | SAFE | WARN | SKIP | 合计 | 执行的插件任务 | 请求数(估) | 峰值并发 | LoopExit | 产物 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| scanme.nmap.org | r1 | 0 | 262.11 | 0 | 1666 | 0 | 1666 | 3332 | 1666（833 插件 × 2 形态） | 2032 | 5 | 0 | hosts-info + result + skip |
| scanme.nmap.org | r2 | 0 | 275.73 | 0 | 1666 | 0 | 1666 | 3332 | 1666 | 2032 | 5 | 0 | hosts-info + result + skip |
| testphp.vulnweb.com | r1 | 0 | 2.50 | 0 | 0 | 0 | 0 | 0 | 0（端口 filtered，未进入插件阶段） | 0 | 1 | 0 | hosts-info（端口态 filtered） |
| testphp.vulnweb.com | r2 | 0 | 2.16 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 1 | 0 | hosts-info（filtered） |
| testhtml5.vulnweb.com | r1 | 0 | 1.78 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 1 | 0 | hosts-info（filtered） |
| testhtml5.vulnweb.com | r2 | 0 | 2.22 | 0 | 0 | 0 | 0 | 0 | 0 | 1 | 0 | hosts-info（filtered） |
| testsparker.vulnweb.com | r1 | 0 | 0.97 | 0 | 0 | 0 | 0 | 0 | 0（DNS 无解析） | 0 | 0 | 0 | 无 CSV（无 IP 可展开） |
| testsparker.vulnweb.com | r2 | 0 | 1.09 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 无 CSV |
| **补充** testphp `-dps`（2 插件） | — | 0 | 12.87 | 0 | 2 | 0 | 0 | 2 | 2（不可达目标下的插件阶段） | 2（×3 次重试=6 次连接尝试） | — | 0 | result |

四态自洽：每轮 `VULN+SAFE+WARN+SKIP == total` 均为 true（`analysis.json:sum_matches_total`）。
补充运行用于验证"真实网络故障下引擎不挂死"：2 个插件均 3 次重试后 ConnectTimeout，
被记为 **safe + 'request error'**（不是 warn），引擎正常收尾、退出码 0。

## 4. 门控验证（22 端口上的 http 插件）

scanme 两轮一致：

- 端口探测：`hosts-info-*.csv` → `45.33.32.156` 的 **22 与 80 均 open**（真实扫描发现，不是构造）。
- 门控命中：**1666 条 SKIP 行**（域名形态 833 + IP 形态 833），涉及 **833 个不同插件**，
  DATA 全部为 `port 22 not in plugin ports [80, 443, 8080, 8443]`。
- **22 端口上的 HTTP 请求数 = 0**（SKIP 在引擎侧端口门控即短路，插件 run() 从未执行；
  日志中 1666 条 `skip …/22` 警告与 skip CSV 行数一致）。
- 端口 80 上正常执行 833 个插件 × 2 目标形态 = 1666 个任务，产出 1666 条结果行。

## 5. VULN 候选表

**本轮无 VULN 候选（0 条）**。

- scanme.nmap.org 是静态页（"Welcome to Nmap"），0 命中属**正确结论**，无假阳性。
- testphp / testhtml5 的已知注入/XSS 类漏洞**未能核验**：目标从本环境不可达（端口 filtered），
  插件阶段未执行 → **无法核查**（不是"未检出"结论）。
- VULN 判定路径的覆盖由语料本机 mock 验证（`plugins_corpus/verify_report.json`：
  `positive_vuln=5/10`，sink 词命中可报 vuln），不在本次网络验证范围内。

## 6. 网络礼仪

| 指标 | scanme r1 | scanme r2 | vulnweb 3 目标 × 2 轮 |
|---|---|---|---|
| 总 HTTP 请求（估） | 2032 | 2032 | 0 |
| 端口探测 TCP 连接 | 2（80、22） | 2 | 1 / 0 |
| 峰值并发连接（实测 /proc/net/tcp 采样） | 5 | 5 | ≤1 |
| 并发上限 | `-p 4` 进程池 | 同 | 同 |
| 连接错误风暴 | 无（3/1666 行目标端 reset，1 行/轮波动） | 无（1/1666） | 无 |

请求数为**静态推算**：执行任务数 × 该插件 REQS 条数（1666 任务 → 2×1016 = 2032，
无 VULN 提前中断；`request_estimate_unmapped_rows=0`）。
交叉验证：262.11 s × 4 worker / 2032 请求 ≈ 0.52 s/请求，与实测 RTT（0.29~0.60 s）一致。
运行末尾该目标 TIME_WAIT 套接字 385 个（60 s 过期窗口内的尾部，只能作下界参考）。

## 7. 异常与发现

1. **argparse 覆盖式参数**：`-t` / `-m` 是 `nargs='+'`，重复传参时**后者覆盖前者**（静默丢目标）。
   首轮即踩中：只传了 `scanme.nmap.org:22`，日志显示 `1 hosts, 1 ports`，http 目标被静默丢弃。
   证据：`out/scanme-r0-gateonly-specerror/`（该轮结果本身有效：1666 SKIP / 0 请求 / exit 0）。
2. **引擎要求 CWD 下已存在 `.cache/` 目录**：`utils/logger.py:130` 在 `ss.py:106` 的 mkdir 之前
   就打开 `.cache/ss.log` → 全新目录下运行直接 `FileNotFoundError` 崩溃（exit 1）。
   仓库因已存在 `.cache/` 而未暴露。
3. **存活端口按"域名形态 + IP 形态"各跑一遍插件**（`ss.py:245-246` 的 `port_alive.difference(covered)`）：
   未显式覆盖 IP 形态时，833 插件 → 1666 任务；IP 形态 URL 无协议 → 每个插件先做
   `https_or_http` 探测，其中对**明文端口发 TLS**必然失败（实测 1.8 s/次）→ 首轮真实扫描
   10 分钟仍未结束，**按任务卡上限中止**（`out/scanme-r1-aborted-10min/`，exit -9 / timed_out）。
   最终轮次用显式 `http://45.33.32.156:80` 覆盖 IP 形态以控制负载（同一台机器、同一协议）。
4. **连接失败被记为 SAFE 而非 WARN**：语料插件模板把请求异常转成 `return False, 'request error: ...'`，
   引擎的 do_testing 只在 `run()` 抛异常时记 WARN → **网络失败被折进"未检出"，存在漏报掩盖风险**。
   本轮实证：r1 3 行、r2 1 行、补充运行 2 行。
5. **目标端 reset 导致行级抖动**：3 个插件路径被 scanme 主动 RST（`Connection reset by peer`），
   r1/r2 之间 4/1666 行的 DATA 文本在 `request error` 与 `no match` 间摆动，**四态分布不变**。
6. **不可达目标的行为正确**：端口三态判定把 80 判为 `filtered`（不是 open/closed）→ 目标被丢弃 →
   "scannable target not found" → 早退 exit 0、0 行；DNS 失败的域名连 `hosts-info` 都不生成。
7. **空集合不产文件**：`utils/__init__.py:57 save_csv([])` 直接 return → 0 warn 行时**没有 warn CSV**，
   0 非 SKIP 行时**没有 result CSV**。"文件缺失"= "0 行"，不是"产物丢失"。

## 8. staging / 清理校验

- 仓库 `plugins/`：**扫描前后 sha256 逐文件比对 → missing=0, added=0, changed=0（残留 = 0）**。
  仓库常驻插件从未被加载进本次运行，也未被写入。
- `ss.py` / `utils/*` / `language.yml`：mtime 全部早于本次会话（最新 2026-10-26 02:24），
  本次只在 /tmp 副本中运行，仓库文件未改动。
- 仓库根新增文件：**仅 14 个 `e2e-*.csv`**（本任务约定的产物前缀）。
- staging 目录（`/tmp/opencode/e2e-t3/run`、`run-subset`、`work-dps`，含 833 个插件副本）**已删除**；
  每轮工作目录 `out/<label>/run/`（同样是 833 插件副本的隔离副本）也已删除；
  仅保留 `/tmp/opencode/e2e-t3/out/<label>/` 下的 stdout.log / stderr.log / ss.log / *.csv /
  run_summary.json / analysis.json 作为证据（3.5 MB）。
- 全盘复查：`find /opt/workspace/labs /tmp -name "CORPUS_*.py" | grep -v plugins_corpus` → **空**。
- 孤儿进程：扫描进程 0；本地 mock（127.0.0.1:8080）已停。

## 9. 结论

- 引擎在真实 RTT / 真实服务下**可跑、退出码 0、无 LoopExit、产物齐全**（scanme 两轮、四个目标两轮、
  补充不可达运行，退出码全 0，LoopExit 计数全 0）。
- **门控 SKIP 正确**：22 端口上 833 个 http 插件全部 SKIP、**0 请求**，SKIP 行数与日志条数一致。
- **四态自洽**：每轮 `VULN+SAFE+WARN+SKIP == total`；VULN=0 在 scanme 上是正确结论。
- **幂等**：r1 vs r2 任务集合与四态完全一致（0 处 outcome 差异），仅 4 行 DATA 文本随网络抖动变化。
- **未能核查**：vulnweb 三目标的插件阶段（目标在本环境不可达 / 域名已下线），
  其"VULN>0"预期**无法在此环境验证**，需换出口网络后重跑。
