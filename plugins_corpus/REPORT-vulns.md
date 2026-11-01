# plugins_corpus 生成报告

## T2FIX 增量 — 扫描根 http/cves / 产物目录 vulns / manifest manifest-vulns.json

- 增量模式: 不重写既有 manifest.json, 去重既有语料 CVE 6 个
- ②c flow 通用转换未实现: CVE-2017-12615 以 supplement/ 手工插件落地; 通用 flow 支持留后续卡

- 生成时间: 2026-10-26
- 转换器: tools/convert_nuclei.py
- 数据源: projectdiscovery/nuclei-templates main 分支 tarball（gh-proxy 通道, HTTP 200, 9,998,970 字节），MIT 协议
- 抓取通道: gh-proxy 成功（jsDelivr / GitHub API 未使用，单源已达标）

## 来源总量与筛选

| 项 | 数量 |
|---|---|
| 扫描文件 | 963 |
| 无 CVE 编号 (--no-cve-ok 时以模板 id 收录) | 0 |
| CVE 年份 < 2016 被筛除 | 1 |
| 同 CVE 去重（第二个起丢弃） | 43 |
| 增量去重（已在既有 manifest） | 6 |
| 转换成功（生成插件） | 551 |
| 转换失败（不支持, 见下方跳过表） | 362 |

## 不支持特性计数（跳过项+原因）

| 跳过原因 | 数量 |
|---|---|
| matcher-dsl | 136 |
| flow | 64 |
| unresolved-var:interactsh-url | 46 |
| unresolved-var:password,username | 29 |
| payloads-attack | 27 |
| part-body_2 | 14 |
| dynamic-chain | 7 |
| raw-parse-error | 7 |
| unresolved-var:randstr_1,randstr_2 | 3 |
| part-body_1 | 2 |
| part-header_1 | 2 |
| no-matcher | 2 |
| unresolved-var:csrf | 2 |
| unresolved-var:randstr_1,randstr_2,randstr_3 | 1 |
| unresolved-var:path | 1 |
| matcher-binary | 1 |
| unresolved-var:form_id,nonce,post_id | 1 |
| unresolved-var:attachmentID | 1 |
| unresolved-var:attachmentID,attachmentName | 1 |
| unresolved-var:timestamp | 1 |
| unresolved-var:fileid | 1 |
| unresolved-var:filename | 1 |
| unresolved-var:uid | 1 |
| unresolved-var:admin | 1 |
| unresolved-var:username | 1 |
| unresolved-var:cookie | 1 |
| unresolved-var:endpoint | 1 |
| unresolved-var:database | 1 |
| unresolved-var:group_id | 1 |
| unresolved-var:csrf,password,username | 1 |
| unresolved-var:str2 | 1 |
| unresolved-var:payload | 1 |
| unresolved-var:repo | 1 |
| unresolved-var:core | 1 |

## 按年份分布

| 年份 | 插件数 |
|---|---|
| 2018 | 1 |
| 2021 | 3 |
| 2022 | 2 |
| 2023 | 3 |
| 2024 | 2 |
| 2025 | 2 |

## 按协议分布

| protocol | 数量 |
|---|---|
| http | 551 |

## 风险分层

| risk_class | 数量 | 处置 |
|---|---|---|
| read_only | 365 | 可入可用集 |
| risky | 180 | 仅清单标记, 默认不加载 |
| excluded | 6 | 仅清单标记, 默认不加载 |
| uncertain | 0 | 仅清单标记, 默认不加载 |

## 支持矩阵统计（转换出插件用到的特性）

| 特性 | 插件数 |
|---|---|
| method | 0 |
| path | 443 |
| raw | 109 |
| headers | 130 |
| body | 125 |
| redirects | 3 |
| matcher:status | 467 |
| matcher:word | 443 |
| matcher:regex | 146 |
| multi-matcher | 485 |
| multi-raw | 15 |
| helper-var-inlined | 48 |

## 遗留

- 风险类插件仅生成文件+清单标记，load 层需按 risk_class 过滤（未来 L2 门控接入点）。
- ②b network/tcp 仅支持「单输入、inputs.data 定长、regex/word matcher」形态, 本卡只产出 CVE-2022-0543; 其余 network 模板全量转换留后续卡。
- ②c flow 通用转换未实现（见上）, CVE-2017-12615 手工落地在 plugins_corpus/supplement/。
- ②a 新目录 http/vulnerabilities/ 增量产物在 plugins_corpus/vulns/ (manifest-vulns.json)。
