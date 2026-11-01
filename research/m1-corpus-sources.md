# M1 语料数据源取证（nuclei-templates → simple-scanner 插件）

> 2026-10-26 · 任务卡 M1 抓取通道记录

## 通道探测结果（全部实测 HTTP 状态）

| 通道 | 用途 | 结果 |
|---|---|---|
| `gh-proxy.com` 主干 tarball | 主通道（整包下载） | **成功**：HEAD 200 (content-length 9,998,970)，`curl -L GET` 3.0s 下载完成，解压 14,111 个 yaml |
| `data.jsdelivr.com` 文件树 | 备选（逐文件） | 可达（list API 返回 200），未启用 |
| `api.github.com` search | 备选（PoC-in-GitHub） | 可达（rate_limit OK），未启用 |

**结论**：gh-proxy 慢速单次整包下载即达全部需求，未触发限流（全程仅 4 个 HTTP 请求：HEAD tarball、GET tarball、jsDelivr list 探测、GitHub API 探测）。jsDelivr / GitHub API 两条备选通道保持可用，留作后续增量。

## 数据源与筛选事实

- 源仓库：projectdiscovery/nuclei-templates（MIT 协议），main 分支快照，本地副本 `/tmp/opencode/nuclei-templates/`（tarball `/tmp/opencode/nuclei-main.tar.gz`）
- 范围：`http/cves/{2000..2026}/*.yaml` 共 4,414 个文件
- CVE 年份 ≥ 2016 的候选：4,070；< 2016 筛除：344
- 转换成功生成插件：**1,500**（见 plugins_corpus/REPORT.md 的跳过表，2570 项被明确不支持矩阵排除）

## 转换器（tools/convert_nuclei.py）支持矩阵说明

| 类别 | 明细 |
|---|---|
| 支持 | method/path/headers/body、raw 请求解析（含 raw 列表=多段请求）、status/word/regex matcher、words `and\|or`、case-insensitive、negative、matchers-condition and/or、有限多请求链（顺序执行块间 OR）、variables 内联、helper 随机变量内联、运行时占位符 BaseURL/RootURL/Hostname/Host/Port/Scheme |
| 跳过（计数见 REPORT） | flow、DSL/binary/xpath matcher、payloads/attack 字典、req-condition、dynamic-chain（extractor 传值）、外部变量（username/password 等 CLI 注入）、interactsh/OOB、multipart-boundary、javascript、无 matcher |

## 风险分层判据（deterministic 规则, 已实现于 convert_nuclei.risk_classify）

1. payload（method+path+headers+body）含反弹/文件删除/用户创建/数据外带特征 → `excluded`
2. 含命令执行特征 → `risky`
3. 仅读方法且无危险 → `read_only`；写方法但无写操作/命令执行特征 → 按任务卡判据同样归 `read_only`
4. `uncertain` = 0（规则全确定，未产生不确定样本；如实计数）

实测分布：read_only 833 / risky 622 / excluded 45 / uncertain 0。
可用集（可加载） = read_only 833；risky/excluded 仅生成文件+manifest 标记，load 层需过滤。

## 遗留与后续增量

- 若需冲量到 2,000+：启用 afrog POCs（其 poc/ 目录为 afrog 私有 schema，需单独转换器）、PoC-in-GitHub 按年查询；公众号非结构化来源按任务卡预留后续。
- DSL matcher 覆盖（1,567 个模板被 dsl/flow/字典跳过）需扩展转换器表达式求值，属任务卡明确不做范围。