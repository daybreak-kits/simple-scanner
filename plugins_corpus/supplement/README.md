# plugins_corpus/supplement — 手工补充插件包（M2A）

语料转换器（`tools/convert_nuclei.py`）跳过的两类模板在此手工补齐：

1. **OOB / DSL 类**：nuclei 模板依赖 `interactsh` 回调、DSL matcher、payloads 字典、flow 多步链，
   转换器按支持矩阵跳过（见 `plugins_corpus/REPORT.md` 的跳过表）。

## 删除裁决记录（2026-10-26）

**用户裁决：版本型 POC 无意义——客户要证据，版本对照无法证明漏洞存在。**
合法 VULN 判定必须是响应回显证据（payload 算术结果、命令输出、注入反射、协议特征响应等）。

据此删除本目录下的版本型插件：

| 已删文件 | CVE | 删除理由 |
|---|---|---|
| `CVE-2026-109618.py` | CVE-2026-109618 (PHP2Shell) | 判据 = `X-Powered-By`/`Server` 的 PHP 版本号 vs 修复版本表对照，属版本型，无回显证据 |
| `CVE-2026-109619.py` | CVE-2026-109619 (PHP2Shell) | 同上（共享修复版本表） |

连带：`tools/verify_supplement_m2a.py` 与 `tools/verify_t1.py` 中这两个插件的正负断言已移除（skip），
T1 全量回归总数由 843 自然对齐为 841（833 语料 + 4 supplement read_only + 4 参数化）。
备份留在 `/tmp/opencode/t2fix-backup/`（会话内可回滚）。
PHP2Shell 洞若无回显证据型探针，**当前不提供检测能力**（宁可漏报不可误报）。

## 约定

| 项 | 约定 |
|---|---|
| 文件名 | `<CVE>.py`（与 `plugins_corpus/<year>/` 语料同名规范） |
| 契约 | 继承 `utils.plugin.PluginBase`；`set_info()` 返回 `Info`；`run(url, *args, **kwargs) -> (bool, data)` |
| Info 必填 | `protocol` / `port` / `ports`（非空）；`ssl_protocol` / `ssl_port` 按需 |
| 产品门控 | `info.fingerprint = [...]`（模板 tags/metadata 提取的产品关键词，供 L2 门控读取；不改 `utils/`） |
| 风险标注 | 文件头 `risk_class:` 行：<br>`read_only` = 只读探测，可入可用集<br>`param-oob` = 需 `params=['oob_domain']` 外部回连确认<br>`intrusive` = **非 read_only**（对目标有写/破坏动作），load 层应过滤 |
| 必填参数 | `params=['oob_domain']` → 引擎检测到缺参记 `Outcome.WARN`（潜在漏报信号，需人工核验） |
| 降级检测 | `params` 插件的 `run()` 在无 `oob_domain` 时仍做只读降级探测：无信号返回 `(False, 'no OOB configured, manual check required')` |
| 来源标注 | 文件头 `source_repo` / `template` / `cve` / `description` 行，标注 nuclei 模板路径（MIT） |

## 清单

| CVE | 名称 | 设计 | 分类 |
|---|---|---|---|
| CVE-2021-44228 | Log4Shell | JNDI 回连（3 变体）× headers+path + error-based 降级 | param-oob |
| CVE-2022-22965 | Spring4Shell | configFile 数据绑定注入 + error-based 降级 | param-oob |
| CVE-2021-26084 | Confluence OGNL | 算术 OGNL oracle（16*8787 回显） | read_only |
| CVE-2022-26134 | Confluence OGNL RCE | whoami 只读 id 证明（X-Cmd-Response）+ 可选 OOB 腿 | read_only |
| CVE-2020-14882 | WebLogic Console RCE | 路径穿越 + 远程 XML 回连 | param-oob |
| CVE-2018-2628 | WebLogic T3 反序列化 | T3 握手 + 模板原样序列化探针（protocol=t3） | read_only |
| CVE-2021-26855 | ProxyLogon | 单步 SSRF 腿（X-AnonResource-Backend 回连） | param-oob |
| CVE-2023-34362 | MOVEit SQLi | 产品指纹 + 单引号错误注入探针（全链写库段不转写） | read_only |
| CVE-2024-3400 | PAN-OS GlobalProtect | 三腿文件伪影探测 | **intrusive（非 read_only）** |
| CVE-2023-4966 | Citrix Bleed | 超长 Host 头内存泄漏 + 泄漏令牌验证 | read_only |

## 验证

```bash
cd /opt/workspace/labs/simple-scanner
.venv/bin/python tools/verify_supplement_m2a.py
```

覆盖：py_compile + import + Info 完整性 → 本地 mock HTTP/TCP（127.0.0.1 自起）跑 `do_testing` →
四态 OUTCOME 断言（每个 read_only/参数化插件都有正例断言 vuln 路径可达）→ 参数化插件无参时断言
WARN + 明确 False 信息。报告见 `research/m2a-supplement-report.md`。
