# simple-scanner 升级方案

> 2026-10-25 重写版 · 所有数字本机实测（Python 3.12 / gevent 24.2.1 / requests 2.31.0）
> 复现矩阵：`.venv/bin/python repro_defects.py`（8 项，两轮判定一致）
> 门禁：`.venv/bin/python verify_phase0.py`（实现后实测 8/8 全绿）
> 真实目标基准：`127.0.0.1`（VM Linux，RTT 12.8ms，4 开放端口 22/3000/7102/20080）

---

## 0. 一句话结论

**不推倒重写，但要把「端口发现」这个已经坏了的功能修回来。**

引擎的并发模型选对了（gevent），错在三处机制：并发单元绑死在 OS 进程、每任务新建连接、结果二态。但这轮实测发现了比性能更严重的问题——**扫描器现在只扫 80/443/8080 三个端口，`DEFAULT_SCAN_PORTS`（4232 个端口）是死代码**。在真实目标上，4 个开放端口漏了 1 个，而如果目标只开非默认端口，会**全漏**。

| 观测 | 数字 | 含义 |
|---|---|---|
| `DEFAULT_SCAN_PORTS` 调用方 | **0** | 4232 个端口的表从未被使用（`ss.py` 无引用） |
| 实际扫描端口数（2 插件） | **3**（80/443/8080） | 端口发现退化为插件声明端口 |
| 真实目标开放端口 | 22/3000/7102/20080 | 与插件端口交集 = **空** |
| 连接复用 | 4.48 → 1.70 ms/req（**2.63×**） | 最大单点性能收益 |
| 端口扫描瓶颈 | 客户端 CPU（602 µs/端口） | 加并发无效，加进程有效 |

---

## 1. 目录结构

**结论：不动大结构，只拆一个 `transport/`，删 2 个死模块。**

现在的 `utils/` 是「工具杂货铺」：日志、i18n、HTTP、socket、URL、异步池、进程池、网络、进度条、状态机、OOB 反射全塞在一起，其中两个已经死了。但 12 个模块之间没有循环依赖（已核对 import），拆分收益低、回归风险高，所以**保持现有扁平结构**。

### 唯一的结构改动：把 `sockets.py` + `http_client.py` 提为 `transport/`

理由是它们承担的是同一件事——**「怎么把字节送到对面」**，而这正是协议扩展的唯一入口：

```
transport/
  __init__.py      # 只暴露 new_client(proto, host, port) → 协议实现
  http.py          # ← 原 http_client.py，requests.Session + 连接池
  raw.py           # ← 原 sockets.py，裸 TCP/UDP
  ssh.py           # 新增，paramiko（用户明确要 ssh://）
```

**插件永远不直接 import `requests`/`paramiko`**，只通过 `self.make_client('ssh', host, port)` 拿一个能发字节的对象。这样：

- 加一种协议 = 加一个文件 + 注册一行，不动插件
- 插件换协议不用改 import
- 连接池统一在 `transport/` 里管理，不会出现每个插件各建一套

### 删掉的两个死模块

| 模块 | 状态 | 证据 |
|---|---|---|
| `utils/net_echo.py`（277 行） | **死** | `ss.py:101-110` 整段预加载被注释，`NET_ECHO` 恒为 `None`；`plugin.py` 的 `make_echo_*` 两个方法标注「先不用，不成熟」 |
| `utils/state.py`（131 行） | **半死** | 只有 `PluginType(state.StateBase)` 一处继承，`StateBase` 的其余能力无调用方 |

**处置**：`net_echo.py` 直接删（保留 git 历史）。`state.py` 保留 `StateBase`、删掉未用到的状态机部分，或整体并入 `plugin.py`。

按你「清理周围债务」的标准：留着 `net_echo.py` 的后果是有人以后改 OOB 反射时对着一段从未运行过的代码改半天。

### 不动的部分

- `ss.py` 保持入口（不加 `cli.py`，YAGNI）
- `plugins/` 保持现状，`__plugin_tpl.py` 就是模板
- `logger.py` / `language.py` / `progress_bar.py` 保持现状

---

## 2. 输入契约（核心）

**你的原话：插件只负责「收到什么、交出什么」，中间怎么做由写插件的人自己定。**

所以引擎要保证两件事：**插件收到的 Url 完整无损**、**插件需要的参数送到位**。现在两条都不成立。

### 2.1 输入会被降级（I1）

| 输入 | 端口扫描 | 插件实际收到 | 判定 |
|---|---|---|---|
| `http://127.0.0.1/app/login.php` | 关 | `proto='http' port=80 path='/app/login.php'` | ✅ |
| `http://127.0.0.1/app/login.php` | **开** | `proto='' port=80 path='/'` | ❌ **协议和 path 都没了** |
| `ssh://127.0.0.1:22` | 开 | `proto='' port=22 path='/'` | ❌ 协议被清空 |

**机制**（`ss.py:211-219` + `urlutil.py:86-91`）：`infos_for_plugin` 用 `url.netloc` 做 key，而 `netloc` 在端口等于协议默认端口时**会丢掉端口**；`port_alive` 存的却是 `'host:port'`。两个 key 空间不一致，交叉匹配时原始的 Url（带 protocol/path）被删掉，用裸字符串重建。

**后果**：只要目标端口等于协议默认端口（80/443/22）且开了端口扫描，**任何依赖 path 或 protocol 的插件全部失效**。而「扫描某个具体 URL」正是这个工具的常见用法。

**修法**：key 统一成 `(scheme, host, port)` 三元组，**原始 Url 对象永不重建**：

```python
targets: list[Url]                    # 直接保留用户输入的 Url，不重建
alive:   set[tuple[str, str, int]]    # (scheme or '', host, port)

for url in targets:
    if (url.scheme, url.host, url.port) not in alive:
        skip(url, reason='port closed')
        continue
    for plugin in plugins_for(url):
        enqueue(plugin, url)          # 传原始对象，protocol/path 完整
```

`Url.netloc` 的「默认端口省略」本身没错（URL 序列化的正确做法），错的是**拿它当 key 去和 `host:port` 对齐**。修调用点，不动 `netloc`。

### 2.2 参数从不送达（I2）

`do_testing(url, data={})` 留了 `data`，但 `ss.py:232` 调用时没传，实测插件 `run()` 收到的 `kwargs` 恒为 `{}`。README TODOLIST 里「配置文件输入用户名字典、密码字典」这个能力**从来没接通过**。

```python
# 插件侧
def set_info(self):
    return plugin.Info(..., params=['username', 'password_dict'])

# 引擎侧：缺参数直接报错，不静默给空
data = {k: config[k] for k in self.info.params}    # KeyError 就是 KeyError
```

**缺参数必须报错**——给空值会让爆破类插件用空字典跑完、返回 SAFE，这是最隐蔽的一类漏报。

### 2.3 目标被静默丢弃（I3）

没有匹配插件的目标直接被删，无任何输出。操作者以为扫了，其实没扫。修法：每个被跳过的目标记 `SKIP` 并打印原因。

---

## 3. 输出契约（四态）

现在是二态，且异常被折叠成 False：

```python
# plugin.py:130-133
try:
    ret['IS_EXIST'], ret['DATA'] = self.run(url, **data)
except Exception as e:
    ret['IS_EXIST'], ret['DATA'] = False, traceback.format_exc()   # ← 异常 = 未检出
```

改成：

```python
class Outcome:
    """结果四态常量类（语义与 str-Enum 等价；实现未继承 Enum，与 utils/plugin.py 一致）"""
    VULN  = 'vuln'     # 确认命中
    SAFE  = 'safe'     # 执行完成，确认未命中
    WARN  = 'warn'     # 执行失败（异常/超时/参数缺失）→ 人工核验
    SKIP  = 'skip'     # 不适用（端口/协议不符）→ 不算结论
```

- `WARN` **独立成列** + 单独写 `*-warn.csv`（对齐 nuclei `-error-log`，`pkg/output/output.go:466-491`）
- `SKIP` 独立成文件（`*-skip.csv`，与主 CSV / `*-warn.csv` 同列式，不进主 CSV），用于回答「这个目标为什么没被扫」——**这是消除静默丢弃的唯一手段**
- 结束打印一行汇总：`VULN=x SAFE=y WARN=z SKIP=w 总计=n`，且 `x+y+z+w == n` 必须成立，否则引擎自身有 bug

**WARN 处置 = 人工核验**（已裁决）。引擎不自动重扫——重试会把「超时」变成「慢但成功」，掩盖真实错误率，与优先级 1 直接冲突。

### 3.1 两个坏插件（已裁决：修好，留作回归样本）

| 插件 | 实测错误 | 位置 |
|---|---|---|
| `GitLab-RCE-CVE-2021-22205.py` | `UnboundLocalError: cannot access local variable 'cmd'` | `:45`（`cmd` 既非入参也未赋值） |
| `__GitLab-ATO-CVE-2023-7028.py` | `TypeError: Info.__init__() got an unexpected keyword argument 'NAME'` | `:23-29` 返回大写键 dict |

**这两个插件从未成功检出过任何目标**——它们之所以「看起来没报错」，正是因为异常被吞了。修好后按四态契约：连接失败/异常 → `WARN`（人工核验），正常收到响应且未命中 → `SAFE`；其中 `GitLab-RCE-CVE-2021-22205` 另有版本型只读主路径（版本 < 13.10.3 → `VULN`，误报交人工）。它们是 O1 的天然回归用例。

---

## 4. 引擎改动

**需求**：找出一份「覆盖 80% 左右端口偏好」的精简默认端口表，用于互联网场景。

**当前状态**：`DEFAULT_SCAN_PORTS` 4232 个端口，实测两个问题：①覆盖面与现网存在错位（例：7070-7071、7080-7081、7090 在表内而 7102、7547 不在——程序化核对：旧 4232 表与新 1766 表均不含 7102，7102 属主机特定端口而非表内常规项）②量太大，互联网目标（RTT 100ms+）全扫太慢。

**已启动调研**（seeker 代理，`/opt/workspace/labs/research/default-port-list.md`）：nmap/masscan/nuclei 各自的默认端口策略与量化依据、IANA/NIST/OWASP 标准清单、top-N 覆盖率实测数据、可复用的维护活跃数据源。

**注意**：这份表不能只靠「接回 DEFAULT_SCAN_PORTS」就完事——4232 个端口在防火墙丢弃场景下是灾难（见 §4.5）。精简端口表是这个改动的**前置条件**，两者必须一起做。

### 4.1 端口发现：把 `DEFAULT_SCAN_PORTS` 接回来（P0-1，最优先）

这是本轮实测最严重的发现。

```
ss.py:180    infos_for_portscan[url.host].update(plugin_port_list)   # 只用插件端口
ss.py:192    port_scanner.scan_run(host, infos_for_portscan[host], ...)  # 显式传端口
network.py:36  DEFAULT_SCAN_PORTS = set()  # 4232 个端口，ss.py 无任何引用
```

git 历史确认：v0.2.4（`16e6951`）引入 `plugin_port_list` 时替换掉了原来的 `default_port_list` 路径，`DEFAULT_SCAN_PORTS` 保留为 `scan_run` 的**默认参数值**，但 `ss.py:192` 总是显式传 `infos_for_portscan[host]`，于是默认参数永不被使用，成了死代码。

**后果**：端口发现能力 = 插件声明端口。当前 2 个插件 → 只扫 3 个端口（80/443/8080）。任何跑在非这三个端口上的服务（数据库、消息队列、管理面板、自定义端口 Web）**全部扫不到**。

**修法**：

```python
# ss.py:180 附近，target 未显式指定端口时
infos_for_portscan[url.host].update(plugin_port_list)
infos_for_portscan[url.host].update(network.DEFAULT_SCAN_PORTS)   # ← 补这一行
```

程序化核对（审计）：旧 4232 表与新 1766 表均不含 7102；当时「补上后扫到 4 个（含 7102）」是手工临时把 7102 加进扫描端口后的测试结果，并非表内命中。

**重要澄清（纠正上一版的错误绑定）**：

上一版把「接回 `DEFAULT_SCAN_PORTS`」和「精简端口表」绑成同一件事，**前提是错的**。实测确认 `ss.py:192` 总是显式传端口，所以：

| | 影响 |
|---|---|
| 精简 `DEFAULT_SCAN_PORTS` | **对 `ss.py` 零影响**（它从来不读这个表） |
| 接回 `DEFAULT_SCAN_PORTS` | 让 `ss.py` 从 3 个端口变成表内全部端口 |

所以「精简端口表」**不是**接回的前置条件，两者是**独立的两个决策**：

1. **接回**（P0-1，必修）：恢复端口发现能力，这是修 bug
2. **换掉表的内容**（见下，已定）：现表 4232 端口无频率依据、覆盖有随机缺口，换成有数据依据的表

### 4.1.1 默认端口表选型（已定：Shodan ∪ nmap 并集 1766 端口，≤ 4096 上限）

**第一步：文献调研**（`research/default-port-list.md`，460 行）：唯一有量化覆盖率数据的公开来源是 nmap（2008 年数据：top-122 = 80%、top-1000 = 93%）；masscan/fscan/zmap/afrog/xray/Nessus 全部手工挑选无数据；nmap 官方 2016 年承认频率数据 "showing its age"。

**第二步：现网数据裁决**（用 Shodan/FOFA API 拉当日全索引统计，`research/port-table/README.md`）：

| 端口数 | Shodan 现网覆盖率 | nmap 2008 宣称 |
|---|---|---|
| top-122 | 42.5% | 80% |
| top-321 | 53.6% | — |
| **top-1000** | **67.0%** | **93%** |

- **2008 年的 93% 神话破灭**：top-1000 端口今天只覆盖 67% 的在役服务。长尾（临时端口/代理/容器/CDN 后端）从 7% 涨到 33%——全端口扫描时代的直接后果
- FOFA 独立互证（40.9 亿条）：top-5 端口只占 39.6%，长尾同样巨大；top-4 与 Shodan 完全一致（80/443/22/7547）
- 我方两台真实主机 17 个开放端口独立验证：任何静态表最高命中 41%，与人口学数字一致

**变种端口确证**（现网高频、nmap-2008 表里没有）：7547 TR-069（2008 年排名 #7518，现在全球 #3、占比 5.5%）、7170、cPanel 族 2082/2083/2086/2087、8880、40000、60000；HTTP 变种 8089/8443/8085/8008/8009/9000 全部进 Shodan top-30。**CVE 关键端口核对：25 个漏洞利用高频端口中 24 个已在 Shodan top-1000 内，仅需显式增补 2049（NFS）。**

**对「80%」目标的诚实表述（两次修正后的终版）**：在 2026 年，**任何静态表都到不了 80%**——top-1000 的硬上限是 67%。静态表的现实定位是「低成本的第一次扫」（~6s/主机），覆盖经典服务的 2/3；剩余 1/3 + 主机特定端口（实测占 59%）只能靠机制：插件声明端口、用户显式 `-t host:port`、全端口兕底模式（修完 X6 后可用，LAN ~6s、互联网 ~25s/主机）。

**选型决定**（用户上限 4096）：

| 层 | 内容 | 量 |
|---|---|---|
| 基座 A | Shodan top-1000（2026-10-25 现网频率，6.35 亿条记录） | 1000 |
| 基座 B | nmap-2008 top-1000（遗留互补：Shodan 漏 7890/20080 而 nmap 抓到） | +766 |
| 增补 | CVE 关键缺口 2049（NFS） | +1 |
| 拼接 | 插件声明端口永远合并（`plugin_port_list` 机制不变） | 随插件 |
| 兕底 | 全端口模式 `-t host:1-65535`（需先修 X6，当前不可达） | 65535 |

**最终表 = 1766 个端口**（`research/port-table/default-ports-final.json`），在 4096 上限内留有余量：真实 17 端口命中 7/17 = 41%（现表 35%），防火墙全丢弃 ~6s/主机（现表 15.1s），人口覆盖 ~67%+。刻意不填满 4096：现表多出的 2400+ 个无频率依据端口在真实集上零命中，填进去只慢不赚。

**方法教训（自报）**：FOFA 的 `search/all?size=10000` 抽样不能估频率分布——它按「最新更新」排序，样本坍缩到极少数端口（与 Shodan top-500 重叠为 0）。抽样估分布必须随机；「最新优先」样本是活跃度分布。FOFA 侧只采用 stats 精确聚合的 top-5。

**防火墙场景的成本已实测**（目标 192.168.0.1，13 个端口被静默丢弃）：

```
200 端口   timeout 0.5/1.0/2.0 → 0.54s / 1.08s / 2.10s
1000 端口  timeout 1.0        → 4.12s
4232 端口  timeout 1.0        → 15.11s
```

总耗时 ≈ `ceil(端口数 / 池大小) × timeout`，**不是每端口独立 1 秒**。所以 4232 个端口全超时只要 15 秒，不是 4232 秒。`DEFAULT_SOCKET_TIMEOUT = 1` 不是瓶颈，真正的杠杆是 `network.py:311` 硬编码的 `Scanner(size=300)`。

### 4.2 并发单元：N 进程 × 每进程 greenlet 池

**上一版这里写错了，已更正。** 原方案写「进程池 → greenlet 池（信号量 2000）」，这是错的——gevent 是单线程，一个进程内的 greenlet 池只能用 1 个核，8 核机器会退化成 1 核。

正确形态：**保留进程数，每个进程内换成 greenlet 池**。

```
现在：ProcessPoolExecutor(max_workers=-p) → 每 (target, plugin) 一个 OS 进程任务
      一个进程同一时刻只跑一个任务
      -p 8 → 实测峰值并发 16（每任务 2 个并行探测）
      任务提交成本 0.32-0.53 ms/任务

改成：N 个进程（N = -p）× 每进程一个 greenlet 池（信号量 ~500）
      任务提交成本 15.9 µs/greenlet（快 19 倍）
      每进程可用满 1 个核
```

**为什么不能去掉进程**：端口扫描实测单进程 CPU 饱和在 602 µs/端口（1567 port/s），多进程扩展：

```
1 进程   1567 port/s   总 CPU 10.8s
2 进程   2661 port/s
4 进程   3297 port/s   总 CPU 12.05s
```

总 CPU 随进程数线性增长，这是 CPU-bound 的签名——**如果目标端限流，加进程不可能翻倍**。同理客户端 HTTP 也是 CPU-bound（requests 单核 476 req/s）。

**本机 16 核，`-p` 默认 8 是合理的**，不需要改。

### 4.3 连接池：每任务一条 → 每 host 一条

```python
# 现在：plugin.py:175 每次调用都新建
def make_http_client(self, ...):
    return http_client.HttpClient(headers, tries, timeout)   # = 新 requests.Session()

# 改成：按 (scheme, host, port) 缓存，池大小按连接峰值设
_clients: dict[tuple, requests.Session] = {}

def client_for(url):
    key = (url.protocol, url.host, url.port)
    if key not in _clients:
        s = requests.Session()
        s.mount('http://',  HTTPAdapter(pool_connections=8, pool_maxsize=64))
        s.mount('https://', HTTPAdapter(pool_connections=8, pool_maxsize=64))
        _clients[key] = s
    return _clients[key]
```

实测 **2.63×**（4.476 → 1.700 ms/req，200 条连接 → 1 条）。

**池大小 ≠ 并发数**：nuclei 作者实测（`clientpool.go:285-300`）`-c 25` 时在飞请求 22-31，但打开连接峰值 121-178；池设 25 时 5388 请求开 3070 条连接，池设 500 时只开 414 条。所以 `maxsize` 按**连接峰值**设，不是按信号量设。

**需要登录态的插件用任务私有 Session**（cookie 隔离），不污染共享池。

### 4.4 端口门控（P1）

现在 `ss.py:225-232` 是 `for netloc → for url → for plugin` 的全量笛卡尔积，唯一过滤是协议门。实测 3 个开放端口 × 3 个插件 = **9 次调用**（应为 3）。

```python
def set_info(self):
    return plugin.Info(..., ports=[80, 443, 8080])   # 声明适用范围

# 引擎侧
if url.port not in plugin.info.ports:
    record(plugin, url, Outcome.SKIP, 'port not in plugin scope')
    continue
```

纯收益、零风险、不改插件内部逻辑。**注意**：这会让 3.1 节补回 `DEFAULT_SCAN_PORTS` 之后的任务量从 3 端口涨到 4232 端口，端口门控从「优化」变成「必需」，否则插件调用量会爆炸。

### 4.5 主机级调度：现状已是最优，不要改提交顺序

**你的要求**：「以并发主机扫描优先，10 个目标同时并发扫 10 个主机，不要把大量扫描全打到一台上，这样可以减小目标压力，收回数据的时间也不慢」。

这个判断方向对，但我实测发现**实现方式不能是改提交顺序**，而且现状的吞吐已经是最高的。三轮测量（`tools/probe_host_fairness.py`，4 hosts × 1000 closed ports = 4000 probes）：

| 轮次 | 策略 | wall | probe/s | 判定 |
|---|---|---|---|---|
| 1 | host-major（A 做完才做 B） | 3.80s | 1052 | 模型错误，真实代码不是这样 |
| 1 | round-robin 交错提交 | 2.30s | 1739 | 看起来快 1.65×，**但是基于错误模型** |
| 2 | **FIFO 共享 pool（真实现状）** | **2.62s** | **1525** | 真实形状 |
| 2 | 交错提交 | 3.52s | 1135 | **比现状慢 34%** |
| 2 | 每主机独立 pool（75 each） | 3.21s | 1247 | 比现状慢 23% |
| 3 | **FIFO 共享 pool（复测）** | **1.39s** | **2887** | 真实现状 |
| 3 | per-host 在飞上限 100 | 1.89s | 2115 | 慢 27% |
| 3 | per-host 在飞上限 50 | 2.41s | 1659 | 慢 42% |
| 3 | per-host 在飞上限 25 | 1.69s | 2366 | 慢 18% |
| 3 | per-host 在飞上限 10 | 1.71s | 2333 | 慢 19% |

**机制**：真实代码（`ss.py:190` + `network.py:476-482`）不是主机串行，而是把所有主机的端口一次性同步提交进**同一个共享 pool**，然后 FIFO 消费。主机 A 的任务排在队首所以先扫完，但 B 的任务早已在队列里排队，RTT 已经被并发掩盖。

改成交错提交反而慢 34%：把同一主机的连续端口打散到队列各处，破坏了内核/网络栈的局部性（同目标连接的路由缓存、ARP、防火墙连接跟踪）。

per-host 在飞上限没有任何收益——上限从 100 压到 10，吞吐单调下降且被噪声淹没，说明**当前根本没有单主机被过度并发的问题**（4 个主机共享 300 槽位，平均每主机 75，远未达到目标压力）。

**结论：不改。** 三条理由：

1. 现状吞吐最高（2887 probe/s），任何公平性改造都更慢
2. 「减小目标压力」在当前 `-p 8` / pool 300 的参数下不是真实问题——4 主机 × 75 在飞，单目标压力远低于内核 backlog 上限
3. 真要限流时，正确的位置是**每主机在飞信号量**（保持 FIFO 提交），不是改提交顺序。但这个改动没有数据支撑，按你的 YAGNI 标准不做

**什么情况下要重新评估**：单主机场景（只扫 1 个目标）时，300 个并发全打在一台上。这时如果要限流，用 per-host 在飞信号量，且上限应由「目标内核 backlog」决定，不是拍脑袋。当前没有这个需求，不预做。

### 4.6 不做：结果乱序回收

上一版列了这条（P4），**本版删除**。理由：

1. 你裁决「顺序无所谓」
2. 实测零收益：`in-order` 2.00s vs `as_completed` 2.00s。wall clock 由最慢任务决定，顺序只影响打印时机
3. 改成完成队列要动 `process.py` 的回收逻辑，属于无收益改动

---

### 4.11 插件适用性：三层门控 + 主机服务清单（Phase 1 设计，2026-10-26 新增）

依据（全部实测）：
- WhatWAF（http）被发到 22 端口：请求已发出、白跑一趟、产出一条「protocol does not match」的 SAFE——插件自检是「发完才发现」，引擎应该在派发前拦截（甲方口径：「SSH 去打 HTTP 的测试没意义」）。
- 放大风险：端口门控只在插件声明 `ports` 时生效；1000 插件 × 3 开放端口 = 3000 次调用，其中绝大多数无意义。
- 有扫描检测的防火墙会把全速扫描打瞎（见 4.12）。
- 外部证据卡（research/scanner-arch-survey.md Q3/Q6）：afrog 是唯一硬指纹门控实现（fingerprint.Hit.RuleID + requires）；nuclei 的无效扫描过滤在入队层（HostErrorsCache.Check 在进 channel 前拦截，一个请求都不发）。

机制（三层门控，全部声明式元数据 + 引擎派发层执行，派发后无门控逻辑）：

```
L0 端口门控（Phase 0 已有）   Info.ports 声明 → 不匹配 SKIP，零请求
L1 服务清单（新，核心）       每个 open (host,port) 探测一次：banner 抓取 + TLS 判别 + HTTP 特征
                              → 服务记录 {protocol, product?, version?} 缓存进 ip_info，全插件摊销
                              → 派发时插件 protocol ∉ 清单协议 → SKIP（22 端口上任何 http 插件零请求）
L2 产品门控（可选声明）       Info.fingerprint = ["gitlab", ...] → 清单无此产品 → SKIP
```

- L1 探测器放 `transport/`（复用 http_client/sockets），一次探测多协议判别；每端口一次、全插件共享，不在插件内重复探测。
- 版本比对不进引擎（YAGNI）：版本进 DATA 交插件自判；等语料证明需要再上版本引擎。
- 成本模型：请求 = open_ports × 1（清单）+ 适用插件数。3 端口 × 1000 插件：3000 → 3 + ~10-50，约 60-600× 削减。
- M1 插件语料（1000+）依赖本节门控，否则扇出不可接受——这是 Phase 1 优先于大规模插件验证的原因。

### 4.12 自适应主机节流（Phase 1 新增，证据：192.168.0.1）

实测现象链（同一天、同一目标）：裸 connect 3389 → 0.00s open；20 端口 pool=10 → 全部 filtered；顺序逐个探 20 端口 → 仍全部 filtered、每个挂满超时（无 RST）。结论：该类防火墙有**扫描检测**——短窗口内连过多不同端口即拉黑源 IP 数分钟，期间静默丢弃一切。全速扫描会中途自睛（真实开放端口被报 filtered = 漏报，扫描器自己造成）。

机制（调度层，不改结果，与「不做自动重试」裁决不冲突）：
- 信号：主机最近 N 次探测 filtered 占比 > 阈值（如 >90%）且此前出现过 open → 判定进入 drop-state。
- 动作：暂停该主机剩余端口探测（冷却 5-10 分钟后再续），报告标注「自端口 X 起进入 drop-state，该时段结果不可信」。
- 不做：重试、改判定结果、伪造 closed——失败如实上报，只是不继续喂包。

## 5. 修正后的缺陷清单

上一版把 D3（t3 被 http 插件跳过）列成缺陷是**错的**，已删。你指出的两点都对：

- **HTTP 插件不该扫 t3** —— 这是正确行为，不是缺陷
- **没有 ssh 插件时 ssh 目标被丢弃** —— 可以接受，但**必须打印告警**

| ID | 缺陷 | 层 | 后果 | 优先级 |
|---|---|---|---|---|
| **P0-1** | `DEFAULT_SCAN_PORTS` 死代码，端口发现退化为 3 个端口 | 引擎 | **非默认端口服务全漏** | **最高** |
| **X4** | win32 分支把 filtered 端口误报为 open | 引擎 | **Windows 上漏报全变误报** | **最高** |
| **I1** | 端口=协议默认端口时，插件收到的 Url 丢协议和 path | 引擎 | **漏报**（依赖 path 的插件全废） | 高 |
| **O1** | 插件异常 → `IS_EXIST=False` | 引擎 | **漏报**（与「确认未检出」不可区分） | 高 |
| **I4** | `192.168.1.0/24`、逗号分隔 → 塌成 1 个 host | 引擎 | **漏报整个网段** | 高 |
| **I2** | `data` 参数从不传递，README 承诺的能力是死的 | 引擎 | 参数化插件无法工作 | 中 |
| **I3** | 不匹配的目标被静默丢弃，无逐目标告警 | 引擎 | 操作者以为扫了、其实没扫 | 中 |
| **I5** | `-t example.com -dps`（无端口 + 关端口扫描）→ 零任务 | 引擎 | 扫描空转 | 中 |
| **O2** | 零结果 `save_csv([])` IndexError，exit 1 | 引擎 | 扫描中断，无报告 | 中（防火墙场景必触发） |
| **X6** | `-t host:1-10000` 端口范围解析失效（`Url` 只取 `:1`，范围被丢弃） | 引擎 | 全端口兕底模式不可达 | 中 |
| **S1** | `10_http.py` 慢速 TLS 服务（握手成功、HTTP 响应 >超时）被判 `tls`/high → 所有 http 插件被 SKIP | 指纹 | **漏报红线**（2026-10-30 审计发现，已修：返回 None 保持 unknown，fail-open） | **最高** |
| **E1** | 契约命名不统一：方案写 `Info.fingerprint`、代码用 `Info.requires`；且 2060/2063 插件 `fingerprint=[]` | 契约 | 产品门控（L3）输入数据不存在，L3 建好未接线 | 高 |
| **X5** | 端口结果只有二态（open / 其他），closed 与 filtered 不可区分 | 引擎 | 有防火墙时无法判断端口真关还是被挡 | 中 |
| **P1** | 3 端口 × 3 插件 = 9 次调用 | 引擎 | 3× 无效工作 | 中 |
| **P2** | 每任务新建连接 | 引擎 | 2.6× 慢，200× 连接数 | 中 |
| **P3** | 进程池任务粒度天花板 | 引擎 | 吞吐上限 ~2000/s | 中 |
| **X1** | 退出时 `gevent.exceptions.LoopExit` 崩溃栈（已保存结果后） | 引擎 | 输出含 LoopExit 崩溃栈（实测退出码为 0，不误判 CI 但进程不干净） | 低 |
| **X2** | Windows `multiprocessing` 默认 spawn 重复执行 `monkey.patch_socket()` | 引擎 | Windows 启动失败/行为不一致 | 低（Win only） |
| **X3** | `network.py:437` 注释措辞不严谨（MSDN 无对应表述） | 文档 | 误导后续维护者 | 低 |

`I4` 根因：`network.parse_address` **本身能**正确解析 CIDR（实测 `127.0.0.0/24` → 256 个地址），是 `ss.py:164` 先把它截成了 `127.0.0.0`。修调用点，不动解析器。

### 4.7 新发现的高危缺陷：win32 把 filtered 误报为 open（X4）

**这是本轮最重要的发现，已由我独立复现确认，不是代理单方面说法。**

目标 `192.168.0.1`（Windows，有防火墙）的 26 个 LISTENING 端口，从 Linux 侧探测：

```
OPEN (13)   : 903 913 2026 3389 4096 5040 5357 7680 7880 7890 20000 48540 48543
TIMEOUT (13): 135 139 445 9876 48545 49664 49665 49666 49667 49668 49669 49670 49672
```

**13 个「不通」端口全是超时，没有一个是被拒**——`connect_ex` 全部返回 `rc=11 (EAGAIN)`，不是 `ECONNREFUSED(111)`。这就是 nmap 语义里的 `filtered`（防火墙静默丢弃）。

**缺陷链**（`utils/network.py:425-449`，已逐行读源 + 独立复现）：

```python
ret = client.connect_ex((ip, port))          # :425  防火墙丢包 → 超时 → ret=11 (EAGAIN)
try:
    client.shutdown(socket.SHUT_RDWR)        # :438  超时 socket 上不抛异常（实测返回 None）
except OSError:
    return                                   # :442  唯一可能拦住的地方，但没拦住
client.close()
if ret != 0 and sys.platform not in ['win32','cygwin']:   # :445  win32 下后半=False
    return                                   # :446  唯一的 ret 检查被跳过
return ip, port                              # :449  ← 误报为 open
```

**实测**（调用扫描器真实的 `handle_tcp_socket`，仅伪造 `sys.platform`）：

```
platform=linux  reported-open=13   filtered 误报: []  真开放识别: 13/13  ✓
platform=win32  reported-open=21   filtered 误报: [135,139,445,9876,48545,49664,49665,49666]  ✗
```

**触发条件 = 有防火墙 + Windows**。而防火墙恰恰是企业内网扫描最常见的场景。

**根因不止一处**：`shutdown()` 根本不是连通性判据——在超时的 socket 上调用它不抛异常（已独立实测）。所以 `:438` 的 try/except 从头到尾没起作用，真正的判据只有 `:445` 的 `ret`，而这个判据在 win32 下被显式关掉了。

原注释（`:437`）说「不知道为什么连接建立后 Windows 中错误值还是 10035 而不是 0」——MSDN 只定义 `WSAEWOULDBLOCK(10035)` 的通用语义（非阻塞 socket 上无法立即完成的操作），**没有**「连接建立后仍是 10035」的明文。注释本身不严谨，但更严重的是它掩盖了一个从未被验证过的假设。

### 4.8 修法：端口探测改三态，判据统一用 `connect_ex` 返回值

```python
OPEN      : ret == 0
CLOSED    : ret == errno.ECONNREFUSED      # 111 / 10061，目标主动回 RST
FILTERED  : ret == errno.EAGAIN / ETIMEDOUT / EWOULDBLOCK   # 11 / 110 / 10035，静默丢弃
```

**弃用 `shutdown()` 判据**——它不验证连通性（独立实测：超时 socket 上调用返回 None，不抛异常），留着只会让人以为它在保护什么。

这一条改动同时解决三件事：

1. 修掉 win32 下 filtered 误报为 open（X4）
2. 补上 closed / filtered 语义（X5），有防火墙时能判断端口是真关还是被挡
3. 让 4232 端口的 15s 扫描结果真正可解读（现在 filtered 和 closed 混在一起，无法回答「为什么没扫到服务」）

**代价**：`ip_info` 的 `PORTS` 从 `set` 变成 `dict[port, state]`，`gen_expand_ipinfo` 的 CSV 输出要加一列。这是本方案唯一影响输出格式的改动，需要同步改 `verify_phase0.py` 的断言。

### 4.9 跨平台 4 条的最终判定

原调研提了 4 条「必须改」，实测后 2 条被推翻、1 条升级、1 条换理由：

| 原条目 | 判定 | 依据 |
|---|---|---|
| 1. `network.py:437` 注释措辞 | **升级为必须改逻辑** | 不止注释：`:445` 的 ret 守卫在 win32 下失效，filtered 全部误报为 open（§4.7 实测） |
| 2. `monkey.patch_socket()` 幂等 | **撤销，无需改** | 实测同进程重复 3 次 `saved.keys()` 恒为 `['socket']`；spawn 子进程重新 import 后 `socket` 模块对象不变、`DEFAULT_SCAN_PORTS` 正确构建。gevent 自带幂等保护 |
| 3. ss.py 调用点显式传 `mp_context='spawn'` | **保持必须改，但理由完全不同** | 不是「Linux 依赖 fork」，而是 **fork + gevent 组合本身会崩**：fork 下任务能跑完，但进程池退出时 `join_executor_internals → os.waitpid` 被 gevent patch → `LoopExit`。`ss.py` 实测同样现象（CSV 保存成功后退出崩）。**调用点加 `mp_context='spawn'` 反而修掉了这个 Linux 上也存在的既有 bug**（`utils/process.py` 签名本就支持，未改其契约） |
| 4. Windows 进程数降到 2-4 | **撤销，无实测支撑** | spawn 下 `-p 8` 与 `-p 4` 在 16 任务量级无实质差异（慢任务版 8 进程反而快 0.03s）。冷启动确实更贵（fork 0.009s vs spawn 0.446s），但被任务时间完全掩盖 |

**新增必须改 2 条**：

| # | 问题 | 严重度 | 证据 |
|---|---|---|---|
| a | `save_csv([])` 空列表崩溃 | 高 | 防火墙场景全 filtered 时必触发；`ss.py:205` + `utils/__init__.py:61` |
| b | `-dps` + 裸 IP 目标 → 静默无输出 | 中 | 0.7s 退出，什么都不扫 |

### 4.10 其他新发现（较低优先级）

| # | 问题 | 说明 |
|---|---|---|
| 1 | `-t host:1-10000` 端口范围不生效 | `Url netloc` 正则只吃 `:1`，实测 `total of 1 hosts, 1 ports` |
| 2 | ICMP 存活探测需 root / Administrators | `ss.py:191` 已用 `is_check_alive=False` 绕过，但直接调 `Scanner` 会 `PermissionError` |
| 3 | `gevent.exceptions.LoopExit` 退出崩溃 | 既有 bug，非 Windows 特有；由 §4.9 第 3 条（`mp_context='spawn'`）一并修掉 |

`X1` 根因：`process.py` 的 `ProcessPoolExecutor` 在 gevent monkey-patch 下，`join_executor_internals` 线程调 `os.waitpid` 时 hub 已退出。这是 gevent + multiprocessing 的已知互斥问题（gevent issue 官方标 `cantfix`）。

---

## 6. 分期

### Phase 0 — 契约与止血（改完即可上线）

| 动作 | 修 | 验收 |
|---|---|---|
| **端口探测改三态，判据用 `connect_ex` 返回值** | X4+X5 | win32 下 filtered 不再误报为 open |
| 补 `DEFAULT_SCAN_PORTS` | P0-1 | 默认表扫出全局常见在役端口；主机特定端口（如 7102）由 `-t host:1-65535` 兜底命中，实测 65535 端口 13.5s/主机（LAN） |
| （已知缺口） | — | 7102 类主机特定端口不在全局频率表，属机制分工非缺陷 |
| key 统一 `(scheme, host, port)`，原始 Url 不重建 | I1 | `http://h/a.php` 开端口扫描后 path 不丢 |
| 异常 → `Outcome.WARN`，独立列 + 独立文件 | O1 | 坏插件返回 WARN 而非 False |
| `params` 声明保留，缺参记 WARN（配置注入挪到 Phase 1 待办） | I2 | 必需参数缺失 → WARN，不崩溃 |
| 每个被跳过的目标记 `SKIP` 并打印原因 | I3 | `t3://` 目标有 SKIP 记录 |
| target 解析改走 `network.parse_address` | I4 | CIDR 展开 256 hosts |
| `-dps` 时用插件声明端口补齐 | I5 | `-t h -dps` 有任务 |
| `save_csv` 判空 | O2 | 零结果 exit 0 |
| 端口门控 | P1 | 3×3 从 9 次降到 3 次 |
| 删 `net_echo.py`，修 `state.py` | 债务 | 无悬空引用 |
| ss.py 调用点传 `mp_context=get_context('spawn')`（process.py 签名本就支持） | X1/X6 | 退出不再 `LoopExit`，exit 0 |
| 默认表换 Shodan∪nmap 并集 1766 端口 | P0-1 | 真实 17 端口命中 ≥41%（现表 35%），防火墙场景 ≤7s/主机 |
| 修 `Url` 端口范围解析 | X6 | `-t host:1-65535` 展开全端口 |
| 修两个坏插件 | — | 连接失败/异常 → WARN；正常未命中 → SAFE（RCE 另有版本型主路径） |

**门禁 `verify_phase0.py`（实现后实测 8/8 全绿、exit 0；下方 C1-C8 为改动前的基线 FAIL）**，退出码接 CI：

```
C1  CIDR 展开 256 hosts          FAIL  observed: total of 1 hosts
C2  默认端口不丢协议/path          FAIL  netloc='192.168.0.1'（应为 '192.168.0.1:22'）
C3  t3:// 目标有 SKIP 记录        FAIL  plugin ran=False  SKIP row present=False
C4  插件异常记为 WARN              FAIL  OUTCOME 列不存在
C5  零结果正常退出                 FAIL  exit=1  IndexError=True
C6  端口门控 3×3→3               FAIL  observed 9 calls
C7  win32 下 filtered 不误报       FAIL  filtered 端口被报为 open（伪造 platform 实测）
C8  端口结果含 closed/filtered 态  FAIL  ip_info 只有 PORTS set，无状态列
```

### Phase 1 — 引擎（性能）

> 2026-10-29 按 `research/engine-optimization.md`（26 条证据，nmap/nuclei/afrog 官方语义）重写。

| 动作 | 依据（外部证据卡） | 验收 |
|---|---|---|
| **服务清单 + 三层门控（§4.11）** | 已实现（fingerprints/ + requires 契约） | 22 端口上 http 插件零请求；清单探测每端口 1 次 |
| **调度单元：由「每目标全插件」改为「（目标 × 候选插件子集）」，子集由端口/指纹两阶段决定** | Q1：nuclei host-spray 默认但官方明言 2000+/100+ 不该无脑全量；`-preflight-portscan`（PR #6715）、指纹预筛 `automaticscan.go`（PR #4562）、afrog `requires` gating 是三个真实两阶段实现 | 候选集 = 指纹相关插件 + 端口相关插件；无关插件不加载不实例化 |
| **每 host 连接池** | Q2：`requests.Session` 非协程安全（gevent 官方 #2047）；业界倾向 per-host + sharding（nuclei PR #6715） | 服务端连接数 ≤ 并发数；Session 不跨 greenlet 共享 |
| **自适应主机节流（§4.12）** | Q3：nuclei `-max-host-error=30` + `-host-backoff`（429/403/连接失败退避，max 30s）是对标我们被拉黑坑的官方解法 | drop-state 主机被暂停+标注；恢复后可续 |
| **引擎级插件超时** | Q4：`gevent.Timeout` 能中断 monkey-patch 的 socket，但 C 扩展/阻塞 DNS 不生效；进程池 `as_completed(timeout=)` 不能取消已在跑任务 | 单插件挂死不再阻塞池：超时记 WARN，池继续 |
| **请求级去重** | Q5：nuclei `-project`/`-project-path` 缓存，避免同一请求重复发送（我们的 Session 复用 1.51× + 每目标全插件，大量 `/` 探测重复） | 同一 host:port 同一路径只发 1 次（可配置开关） |
| `transport/` 抽出，插件不直接 import requests | — | 加协议不改插件 |
| `mp_context` 显式化（ss.py 调用点，跨平台条目） | X2 | Windows 启动一致 |
| 退出时 hub 崩溃 | X1 | exit 0 |
| 配置注入：引擎读配置文件并按插件 `params` 传参 | I2 | 参数化插件可从配置文件取参（log4j/Spring4Shell 的 oob_domain 由此接入） |

目标数字：单请求 ≤1.8 ms（现 4.48）、任务吞吐 ≥10000/s（现 ~2000/s）。

**基准纪律（Q6）**：所有性能验收必须满足——负载生成与目标分离（不同主机/闭网）；warmup 不计；报 p50/p95/p99 而非只报平均；多轮取样（≥6）+ 统计检验（benchstat），禁止单样本下结论（nuclei #7317 单样本假警报 2.1× 是活教材）。

### Phase 2 — 触发条件到了再做

| 项 | 触发条件 |
|---|---|
| asyncio + aiohttp | 单进程 CPU 打满且加进程无效（预期 3× CPU 收益，代价是插件改 async，与「即插即用」冲突） |
| 多机分布式 | 单机网卡打满 |
| SYN 半开扫描 | 需要扫 /16 以上且目标允许（masscan 级，量级差 1000×，但需要 raw socket 权限） |

---

## 7. 明确不做

- **不用 epoll 手写端口扫描**：收益是 CPU 291→100 µs/端口，但真实网络上端口扫描已是 CPU-bound（602 µs/端口），epoll 只能省 191 µs；且 `select.epoll` 在 Windows 不存在，违背跨平台要求。
- **不改端口扫描的提交顺序**：你要求「并发主机优先、减小目标压力」，方向对但实现方式错了。实测交错提交比现状 FIFO 慢 34%，每主机独立 pool 慢 23%，per-host 在飞上限慢 18-42%。现状 2887 probe/s 已是最高（§4.5 三轮数据）。真要限流时正确位置是每主机在飞信号量，但当前无此需求。
- **不调端口扫描超时**：实测 timeout 0.05→1.0 吞吐全平（1736-2026 port/s），超时不是瓶颈。
- **不加 SO_LINGER(0)**：实测 4000 个关闭端口前后 TIME_WAIT delta=+1。关闭端口内核直接回 RST，连接从未建立，TIME_WAIT 不存在。
- **不扩大 `ip_local_port_range`**：470 port/s 上限只对「反复连接同一 dst_ip:dst_port」成立，扫描时 dst_port 每次变，4-tuple 天然不同。
- **不重写端口扫描逻辑**：在 10000-19999 段两轮 0 误报 0 漏报，是当前代码质量最好的部分。
- **不迁 asyncio**：见 Phase 2。省 3× CPU，但要求每个插件改 `async def`，与「写好插件直接扫描」直接冲突。
- **不引入 YAML DSL**：nuclei/xray 的 DSL 是为「无代码能力的人写规则」设计的；你的场景是「自己写插件」，Python 类已经是最短路径。
- **不做指纹门控**：需要引擎先跑指纹探测再喂给插件，等于规定插件内部怎么工作，违背「中间过程由使用者自己定」。且调研中所有工具的指纹门控收益数据**均未找到**。
- **不做自动重试**：会把超时变成「慢但成功」，掩盖真实错误率。
- **不做分布式**、**不做插件热加载**。

---

## 8. 跨平台（Windows/macOS 支持）

调研结论（`/opt/workspace/labs/research/cross-platform.md`）：gevent 官方把 Windows 标为 "tier 2, best effort, 不建议生产"，`gevent.select` 内部仍调原生 select 受 **512 socket** 限制（issue #1151，wontfix）。macOS 侧**未找到**官方已知限制，视为与 Linux 同级。

**必须改 4 条**：

1. `utils/network.py:437` 注释措辞——MSDN 说的是「非阻塞 socket 上半连接状态返回 10035」，不是「连接建立后还是 10035」。逻辑本身对（用 `shutdown()` 抛 `WSAENOTCONN=10057` 反证），保留。
2. `utils/network.py:12` 模块级 `monkey.patch_socket()` 需确认幂等——Windows spawn 会重新 import 主模块，这段会重复执行。
3. `utils/process.py` 显式指定 `mp_context`——Python 3.14 起 Linux 默认从 fork 改成 forkserver，依赖 fork 的隐式假设不再成立。
4. Windows 上进程数上限降到 2-4——8 个 spawn 子进程每个都重新执行 `monkey.patch_all`，开销大。

---

## 9. 已裁决

| 事项 | 裁决 |
|---|---|
| 端口发现默认策略 | 不区分内外网，统一默认 1766 端口；用户自己选扫全端口（`-t host:1-65535`）或指定端口（你 2026-10-26 裁决） |

| 事项 | 裁决 |
|---|---|
| `WARN` 行处置 | 人工核验，引擎不自动重扫 |
| 端口探测三态 | 必做（open/closed/filtered），判据统一用 `connect_ex` 返回值，弃用 `shutdown()` |
| 跨平台第 2、4 条 | 撤销（实测幂等、无进程数依据） |
| `mp_context` | 显式 `spawn`，理由是修 fork+gevent 的 `LoopExit`，不是「Windows 才需要」 |
| 默认端口表 | Shodan top-1000 ∪ nmap-2008 top-1000 ∪ {2049} = 1766 端口（≤ 4096 上限）。现网数据裁决：top-1000 只覆盖 67%（nmap 2008 宣称 93% 已失效），80% 静态表不可达；单机缺口靠插件端口/显式指定/全端口兕底分工 |
| 端口表与接回的关系 | 独立两个决策：接回是修死代码，换表是选型；互不前置 |
| 两个坏插件 | 修好，作为 O1 的回归样本 |
| 插件设计原则 | 引擎只规范**输入/输出契约**，中间过程由写插件的人自行决定 |
| `t3` 被 http 插件跳过 | 正确行为，非缺陷（上一版判断错误，已更正） |
| 无匹配插件时丢弃 ssh 目标 | 可接受，但必须打印告警 |
| 结果乱序回收 | 不做（你裁决顺序无所谓，实测也零收益） |
| 主机级公平调度 | 不做（方向对但实现方式错，实测交错提交慢 34%，见 §4.5） |
| 目录结构 | 保持扁平，只拆 `transport/`，不加 `cli.py` |
| epoll 端口扫描 | 不做（Windows 不支持，且真实网络上已是 CPU-bound） |
| 指纹门控 | **改做**（2026-10-29 修正）：调研证据卡已找到三个真实两阶段实现（nuclei `-preflight-portscan` PR #6715、`automaticscan.go` PR #4562、afrog `requires` gating），且已实测三层识别 10/10 正确、门控收益 640s→6s。原「不做」的依据（无收益数据）已被新证据取代 |
