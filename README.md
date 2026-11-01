# Simple Scanner

Simple Scanner，尽可能简单化的安全扫描器。核心定位：**不漏报优先**，凡是无法确证不匹配的探测一律执行（fail-open），结果按四态输出，可人工核验。

## 能力概览

- **三层服务识别**（端口号不参与适用性判定）：L1 传输层（TCP/UDP）→ L2 应用层协议（HTTP/HTTPS/SSH/Redis/T3/MySQL/Postgres/MongoDB/LDAP/SMB/IMAP/POP3/Telnet/RDP/MSSQL/Memcached/Elasticsearch/DNS/SNMP/IPMI）→ L3 产品（GitLab/Tomcat/WebLogic/WordPress/phpMyAdmin/Spring-Boot/Nacos/Druid/JBoss/泛微/致远/蓝凌/通达/万户/用友/金蝶 等）。
- **指纹门控**：插件声明 `requires` 标签（如 `['http','product:gitlab']`），引擎只在「高置信度识别 + 正向证据不匹配」时 SKIP；协议/产品判不出来一律放行。门控只能删掉有证据证明无关的探测，不能删掉不确定的探测。
- **内置插件语料库**：`plugins_corpus/` 下 2000+ 个证据型插件（响应回显证据，非版本对照），按 `risk_class` 分档加载。
- **UDP 暴露面识别**：v1 探 53/161/623 三个协议端口，无响应只报 `open|filtered`，永不报 closed。
- **四态输出**：VULN / SAFE / WARN / SKIP，每条结论带证据，人工可核验。

## 依赖

- Python 3.11+ 64bit
- `pip install -r requirements.txt`

## 用法

```bash
usage: ss.py [-h] -t TARGETS [TARGETS ...] [-m MODULE [MODULE ...]] [-p PROCESS_NUMBER]
             [-o OUTPUT_FORMAT] [-i INTERVAL] [-is] [-dps] [--include-risky]

  -t TARGETS              扫描目标（IP / IP:端口 / IP:1-65535 / CIDR / 主机名，可多个）
  -m MODULE [MODULE ...]  漏洞插件选择器，默认加载全部 read_only 插件（样例："CVE-2021-*"）
  -p PROCESS_NUMBER       调用进程数，默认 8 个进程
  -o OUTPUT_FORMAT        输出文件格式：json / csv，默认 csv
  -i INTERVAL             向进程池提交任务之间的时间间隔（秒）
  -is, --is-silent        静默模式：控制台不输出测试信息
  -dps, --disable-port-scan
                          禁用端口扫描。注意：端口未开时发 PAYLOAD 会浪费等待时间
  --include-risky         同时加载 risky 插件（写入/上传/执行类探测，需目标方明确授权）
```

示例：

```bash
# 单主机，默认端口表（1766 端口），全部 read_only 插件
python3 ss.py -t 192.168.245.128

# 指定端口
python3 ss.py -t 192.168.245.128:8080

# 全端口（用于「默认端口表没覆盖的服务」二次确认，局域网约 13s/主机）
python3 ss.py -t 192.168.245.128:1-65535

# CIDR 批量
python3 ss.py -t 192.168.245.0/24

# 只跑某个插件族
python3 ss.py -t 192.168.245.128 -m CVE-2021-*
```

## 端口发现策略

- 默认扫 1766 个端口（Shodan 2026 live facet ∪ nmap-2008 top-1000 互补 + {2049}，静态表上限 4096）。
- 不区分内外网，统一默认策略；需要更多面时用户自己选全端口（`-t host:1-65535`）或指定端口。
- 端口号与协议无绑定（SSH 可能在 222、HTTP 可能在 8081）——适用性由指纹判定，不由端口号判定。

## 输出

扫描产出（同目录）：

| 文件 | 内容 |
|---|---|
| `hosts-plugin-result-*.csv` | 主结果（VULN / SAFE / WARN 行，含证据 DATA） |
| `hosts-plugin-result-*-warn.csv` | WARN 行（需人工核验的异常/超时/参数缺失） |
| `hosts-plugin-result-*-skip.csv` | SKIP 行（门控拦掉的探测，含原因） |
| `hosts-info-*.csv` | 端口扫描 / 服务识别明细（含 PORTS_STATE 列） |
| `hosts-udp-*.csv` | UDP 暴露面（53/161/623，`open|filtered` 语义） |

四态语义（每条结论带证据）：

- **VULN**：响应回显证据命中（payload 算术结果、命令输出、注入反射等），可直接给客户看。
- **SAFE**：发了请求、拿到响应、没有匹配——「目标没这个漏洞」的有效负结果。
- **WARN**：执行异常/超时/必需参数缺失/返回结构非法——**潜在漏报信号，必须人工核验**。
- **SKIP**：高置信度识别 + 正向证据不匹配（如 SSH 端口上的 http 插件），**零请求**。

## 插件开发

- 用户插件放 `plugins/`（全部加载）；内置语料放 `plugins_corpus/`（按 `risk_class` 过滤）。
- 插件契约：`Info.requires`（标签列表，`product:` 前缀为产品维度）+ `run(url, **params)` 返回 `(bool, evidence)`。
- 产品指纹：`fingerprints/` 目录（协议/产品探测器，引擎按需加载，结果全插件共享）。

## TODOLIST

- 配置文件控制插件参数（用户名字典、密码字典等）；
- 产品门控接线完成后做产品级批量验证。

## CHANGE LOG

### 0.3.0 2026/10/30

- 三层服务识别 + 指纹门控（`requires` 语义，端口门控废除）；
- 引擎接入 `plugins_corpus/`（2000+ 证据型插件，按 `risk_class` 分档，`--include-risky` 开启 risky）；
- UDP 暴露面识别（53/161/623，`open|filtered` 语义）；
- 四态输出（VULN/SAFE/WARN/SKIP）取代原「检出/未检出」；
- 修复：慢速 TLS 误判漏报、产品门控正文误触发、RootURL 丢端口、`@TIMEOUT` 注解解析、regex AND 语义、`Info.ports` 死字段、`.cache` 缺失崩溃、结果文件互覆盖；
- 删除 DNS 反射功能（v0.2.4 已移除，本版清档）。

### 0.2.4 2024/07/29

- 增加端口扫描，优化执行逻辑；
- 删除 DNSLOG 功能。
