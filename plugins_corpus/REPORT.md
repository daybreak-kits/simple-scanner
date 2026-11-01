# plugins_corpus 生成报告

## 任务卡 M1 — 1000+ 插件语料库（nuclei-templates 转换）

- 生成时间: 2026-10-26
- 转换器: tools/convert_nuclei.py
- 数据源: projectdiscovery/nuclei-templates main 分支 tarball（gh-proxy 通道, HTTP 200, 9,998,970 字节），MIT 协议
- 抓取通道: gh-proxy 成功（jsDelivr / GitHub API 未使用，单源已达标）

## 来源总量与筛选

| 项 | 数量 |
|---|---|
| 扫描文件 (http/cves/) | 4414 |
| 扫描文件 (http/cves/) | 4414 |
| 无 CVE 编号 | 0 |
| CVE 年份 < 2016 被筛除 | 344 |
| 同 CVE 去重（第二个起丢弃） | 0 |
| 转换成功（生成插件） | 1500 |
| 转换失败（不支持, 见下方跳过表） | 2570 |

## 不支持特性计数（跳过项+原因）

| 跳过原因 | 数量 |
|---|---|
| flow | 959 |
| matcher-dsl | 642 |
| unresolved-var:password,username | 310 |
| unresolved-var:interactsh-url | 238 |
| payloads-attack | 89 |
| dynamic-chain | 29 |
| part-body_2 | 29 |
| no-matcher | 26 |
| unresolved-var:nonce,password,username | 19 |
| raw-parse-error | 17 |
| part-body_1 | 13 |
| unresolved-var:nonce | 11 |
| part-interactsh_protocol | 8 |
| unresolved-var:token | 7 |
| unresolved-var:nsp,password,username | 7 |
| unresolved-var:csrf,username | 6 |
| unresolved-var:username | 5 |
| unresolved-var:csrf | 5 |
| javascript-code | 5 |
| unresolved-var:EXPERIMENT_ID | 5 |
| unresolved-var:id | 4 |
| unresolved-var:csrf,password,username | 4 |
| unresolved-var:csrf_token,password,username | 4 |
| unresolved-var:version | 4 |
| part-header_2 | 3 |
| unresolved-var:endpoint | 3 |
| unresolved-var:randstr_1,randstr_2 | 3 |
| part-body_3 | 3 |
| unresolved-var:password,password_fieldname,username | 3 |
| unresolved-var:form_id_1,password,username | 3 |
| no-http-requests | 3 |
| unresolved-var:filename | 3 |
| unresolved-var:csrf_token | 3 |
| unresolved-var:session | 3 |
| part-set_cookie | 3 |
| unresolved-var:password | 3 |
| unresolved-var:core,interactsh-url | 2 |
| unresolved-var:path | 2 |
| unresolved-var:album_id | 2 |
| part-server | 2 |
| unresolved-var:core | 2 |
| unresolved-var:hash,randstr_1 | 2 |
| unresolved-var:siteid | 2 |
| part-version | 2 |
| part-content_disposition | 2 |
| unresolved-var:para,password,username | 2 |
| unresolved-var:callback | 2 |
| matcher-binary | 2 |
| unresolved-var:api_key | 2 |
| unresolved-var:randstr_1 | 1 |
| unresolved-var:randstr_1,randstr_2,randstr_3 | 1 |
| unresolved-var:authkey | 1 |
| unresolved-var:dbhost,password,username | 1 |
| unresolved-var:randkey | 1 |
| unresolved-var:sessionid | 1 |
| unresolved-var:fullpath | 1 |
| unresolved-var:wmuSecurity | 1 |
| unresolved-var:exec_date | 1 |
| unresolved-var:session,token | 1 |
| unresolved-var:upload_filename | 1 |
| unresolved-var:interactsh-url,jsessionid | 1 |
| unresolved-var:EV,VS,VSG | 1 |
| unresolved-var:interactsh-url,token | 1 |
| unresolved-var:profile | 1 |
| unresolved-var:csrfp_login | 1 |
| unresolved-var:tokenCSRF | 1 |
| unresolved-var:slug | 1 |
| unresolved-var:cid | 1 |
| unresolved-var:key,slug | 1 |
| unresolved-var:dtid | 1 |
| unresolved-var:email | 1 |
| unresolved-var:nsp_token,password,username | 1 |
| unresolved-var:horizonRelayState,interactsh-url,protected_state | 1 |
| unresolved-var:password,session_key,token | 1 |
| unresolved-var:user | 1 |
| unresolved-var:fusionformnonce | 1 |
| unresolved-var:nonce,username | 1 |
| part-header_3 | 1 |
| unresolved-var:nodeid | 1 |
| unresolved-var:_token,password,username | 1 |
| unresolved-var:csrftoken | 1 |
| unresolved-var:file | 1 |
| unresolved-var:csrftoken,randstr_1,randstr_2 | 1 |
| unresolved-var:form_id,forminator_nonce | 1 |
| unresolved-var:shell_filename | 1 |
| unresolved-var:id,url | 1 |
| unresolved-var:inifile | 1 |
| part-body_5 | 1 |
| unresolved-var:ips | 1 |
| unresolved-var:password,token,username | 1 |
| unresolved-var:realm | 1 |
| unresolved-var:password,token_1,username | 1 |
| unresolved-var:printerID | 1 |
| unresolved-var:name | 1 |
| unresolved-var:interactsh-url,xcsrftoken | 1 |
| unresolved-var:index | 1 |
| unresolved-var:csrftoken,interactsh-url | 1 |
| unresolved-var:objref | 1 |
| unresolved-var:hostname,username | 1 |
| unresolved-var:extracted_uuid | 1 |
| unresolved-var:appid | 1 |
| unresolved-var:wpr_form_id,wpr_nonce | 1 |
| unresolved-var:apiversion,interactsh-url | 1 |
| unresolved-var:access_key_id,bucket | 1 |
| unresolved-var:session_id,user_id | 1 |
| unresolved-var:upload_path | 1 |
| unresolved-var:box_id | 1 |
| unresolved-var:interactsh-url,userkey | 1 |
| unresolved-var:app_id | 1 |
| unresolved-var:product_path | 1 |
| unresolved-var:include_avatar,label_format,token | 1 |

## 按年份分布

| 年份 | 插件数 |
|---|---|
| 2016 | 18 |
| 2017 | 57 |
| 2018 | 135 |
| 2019 | 118 |
| 2020 | 185 |
| 2021 | 271 |
| 2022 | 251 |
| 2023 | 159 |
| 2024 | 139 |
| 2025 | 99 |
| 2026 | 68 |

## 按协议分布

| protocol | 数量 |
|---|---|
| http (ssl=https 默认) | 1500 |

## 风险分层

| risk_class | 数量 | 处置 |
|---|---|---|
| read_only | 833 | 可入可用集 |
| risky | 622 | 仅清单标记, 默认不加载 |
| excluded | 45 | 仅清单标记, 默认不加载 |
| uncertain | 0 | 仅清单标记, 默认不加载 |

## 支持矩阵统计（转换出插件用到的特性）

| 特性 | 插件数 |
|---|---|
| method | 0 |
| path | 1023 |
| raw | 479 |
| headers | 551 |
| body | 532 |
| redirects | 7 |
| matcher:status | 1263 |
| matcher:word | 1209 |
| matcher:regex | 409 |
| multi-matcher | 1332 |
| multi-raw | 64 |
| helper-var-inlined | 137 |

## 验证（tools/verify_corpus.py 实测）

| 项 | 结果 |
|---|---|
| import + 实例化通过 | 1500/1500 (100.00%) |
| import 失败 / Info 不完整 | 0 / 0 |
| 20 样本 smoke 异常数 | 0 |
| smoke OUTCOME 分布 | {"vuln": 0, "safe": 20, "warn": 0, "skip": 0} |
| mock 实际收到请求数 | 36 {"GET": 31, "POST": 5} |
| smoke 耗时 | 0.07s |
| matcher 正向命中（kitchen-sink mock） | 5/10 报 vuln |

## 遗留

- afrog POCs / PoC-in-GitHub 未启用：nuclei 单源已达标（见上表总量），后续增量可加。
- 风险类插件仅生成文件+清单标记，load 层需按 risk_class 过滤（未来 L2 门控接入点）。
- raw 请求覆盖 method/path/headers/body；multipart/boundary、DSL matcher、flow、payloads 模板按支持矩阵跳过（计数见跳过表）。
