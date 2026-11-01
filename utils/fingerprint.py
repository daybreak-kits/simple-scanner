"""三层服务识别：L1 传输层 → L2 应用层协议 → L3 产品。

设计依据（research/fingerprint-best-practices.md）：
- nmap 的 `ports` 指令只决定「先试哪个 probe」，绝不决定「试不试」——端口号不参与适用性判定。
- 每个 probe 用**新连接**（nmap 原文：避免上一个 probe 污染下一个的结果）。
- fail-open：判不出来 → protocol='unknown'，引擎跑全部插件。

探测器注册：`fingerprints/` 目录下每个模块声明
    PROTOCOL = 'http'        # 命中后产出的协议标签
    TRANSPORT = 'tcp'        # 'tcp' | 'udp'
    ORDER = 20               # 探测顺序，0 = 被动 banner（不发包）
    def probe(ctx) -> Optional[Tuple[str, Set[str]]]:
        '''返回 (证据串, 产品标签集) 或 None。证据串进 CSV，给人看。'''

用法（引擎侧，每开放端口调一次，结果全插件共享）：
    svc = fingerprint.detect(host, port, transport='tcp')
    # svc.protocol / svc.products / svc.confidence / svc.evidence / svc.state

探测器分层（必须声明 LAYER，缺省 'L2'）：
    LAYER = 'L2'   协议探测（ORDER<50 强特征命中即定案；>=50 弱特征只补不阻断）
    LAYER = 'L3'   产品探测（仅协议已定为 http/https 时执行，只补 products，**不改 protocol**）
混在一起的后果：L2 强特征提前定案会让 L3 产品探测器永远跑不到（已踩过）。
"""

from __future__ import annotations

import importlib
import pathlib
import socket
import ssl
import time
from typing import Dict, List, Optional, Set, Tuple

PROBE_DIR = pathlib.Path('fingerprints')

# 置信度：只有 high 允许据此跳过其它插件（nmap --version-intensity 分级先例）
CONF_HIGH = 'high'
CONF_MEDIUM = 'medium'
CONF_LOW = 'low'
CONF_UNKNOWN = 'unknown'


class ServiceInfo:
    """一个开放端口的识别结果。protocol='unknown' 表示判不出来（引擎应 fail-open）。

    state: 'open' | 'open|filtered'（仅 UDP；TCP 走三态端口扫描，这里恒为 open）
    """

    __slots__ = ('host', 'port', 'transport', 'protocol', 'confidence', 'products', 'evidence', 'elapsed_ms', 'state')

    def __init__(self, host, port, transport, protocol=CONF_UNKNOWN, confidence=CONF_UNKNOWN,
                 products=None, evidence='', elapsed_ms=0.0, state='open'):
        self.host = host
        self.port = port
        self.transport = transport
        self.protocol = protocol
        self.confidence = confidence
        self.products = products or set()
        self.evidence = evidence
        self.elapsed_ms = elapsed_ms
        self.state = state

    @property
    def tags(self) -> Set[str]:
        """插件 requires 的匹配目标：协议标签 + 产品标签。"""
        out = {self.transport, self.protocol}
        out.update('product:' + p for p in self.products)
        return out

    def __repr__(self):
        return '<{} {}:{} {}/{}/{}/{} products={} {:.0f}ms>'.format(
            self.transport, self.host, self.port, self.protocol, self.confidence, self.state,
            self.evidence[:60], sorted(self.products), self.elapsed_ms)


class ProbeCtx:
    """探测器拿到的唯一 I/O 句柄。每次调用都开新连接（nmap 同款理由）。"""
    def __init__(self, host: str, port: int, timeout: float = 1.5):
        self.host = host
        self.port = port
        self.timeout = timeout

    # ---- 底层 ----
    def _connect(self) -> Optional[socket.socket]:
        try:
            s = socket.create_connection((self.host, self.port), timeout=self.timeout)
            s.settimeout(self.timeout)
            return s
        except OSError:
            return None

    # ---- 探测器用的三个原语 ----
    def recv_passive(self, wait: Optional[float] = None) -> bytes:
        """连上但不发任何字节，只等 banner（SSH/FTP/SMTP/MySQL 等主动问候的服务）。"""
        s = self._connect()
        if s is None:
            return b''
        try:
            s.settimeout(wait or self.timeout)
            return s.recv(1024)
        except OSError:
            return b''
        finally:
            s.close()

    def send_recv(self, payload: bytes, read: int = 4096) -> bytes:
        """发 payload 再读响应。"""
        s = self._connect()
        if s is None:
            return b''
        try:
            s.sendall(payload)
            return s.recv(read)
        except OSError:
            return b''
        finally:
            s.close()

    def tls_recv(self, payload: bytes = b'', read: int = 4096, sni: Optional[str] = None) -> Tuple[bool, bytes]:
        """试 TLS 握手；成功则（可选）发 payload 并读响应。返回 (是否 TLS, 响应字节)。"""
        s = self._connect()
        if s is None:
            return False, b''
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            ts = ctx.wrap_socket(s, server_hostname=sni or self.host)
        except (ssl.SSLError, OSError):
            s.close()
            return False, b''
        try:
            if payload:
                ts.sendall(payload)
            return True, ts.recv(read)
        except OSError:
            return True, b''
        finally:
            ts.close()

    def udp_send_recv(self, payload: bytes, read: int = 2048,
                      wait: Optional[float] = None) -> Tuple[bytes, Optional[Tuple[str, int]]]:
        """UDP 探测：发一个包，等任意来源的回包。

        返回 (响应字节, 来源地址) 或 (b'', None)。
        **不按目标端口匹配响应**：TFTP/SSDP 等从临时端口回包（research/fingerprint-best-practices.md §7）。
        """
        s = None
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(wait or self.timeout)
            s.sendto(payload, (self.host, self.port))
            data, addr = s.recvfrom(read)
            return data, addr
        except OSError:
            return b'', None
        finally:
            if s is not None:
                s.close()


# ---------------------------------------------------------------- 注册表

_PROBES: Optional[List] = None


def _load_probes() -> List:
    """加载 fingerprints/ 下所有模块（跳过 _ 前缀与目录）。"""
    global _PROBES
    if _PROBES is not None:
        return _PROBES
    found = []
    if PROBE_DIR.is_dir():
        for path in sorted(PROBE_DIR.glob('*.py')):
            if path.name.startswith('_'):
                continue
            # 审计 S2（2026-10-30）：单个探测器 import 期抛异常不得杀死整个扫描。
            # fail-open 红线要覆盖 import 期：坏一个探测器 = 少一个识别能力（退化为 unknown 全跑），
            # 而不是整个扫描器不可用。
            try:
                mod = importlib.import_module('.{}'.format(path.stem), 'fingerprints')
            except Exception:
                continue
            if not hasattr(mod, 'probe'):
                continue
            found.append(mod)
    found.sort(key=lambda m: getattr(m, 'ORDER', 50))
    _PROBES = found
    return found


def reload_probes():
    """测试用：清缓存后重新加载。"""
    global _PROBES
    _PROBES = None
    return _load_probes()


# ---------------------------------------------------------------- 主入口

def detect(host: str, port: int, transport: str = 'tcp', timeout: float = 1.5,
           budget: float = 6.0) -> ServiceInfo:
    """识别一个开放端口。永不抛异常：判不出来返回 protocol='unknown'（fail-open）。

    budget: 本端口总耗时上限（秒）。超预算后剩余探测器不再跑——
            否则一个「什么探测都不回」的服务会被 20 个探测器 × 各自超时拖到 16s+（实测过）。

    两阶段（nmap -sV 同款结构）：
      阶段 A：L2 协议探测（ORDER < 50）——强特征命中即定案，不再试其它协议（省包）。
      阶段 B：L3 产品探测（ORDER >= 50）——仅当协议已定为 http/https 时执行。
              产品探测器只补 products，**不改变 protocol**。

    为什么不能混在一个序列里：L2 强特征命中即 return 是对的（SSH 没必要再试 HTTP），
    但产品探测必须在协议定案**之后**跑，否则永远跑不到。
    """
    start = time.time()
    info = ServiceInfo(host, port, transport)
    ctx = ProbeCtx(host, port, timeout)
    responded = False

    def _over_budget():
        return (time.time() - start) > budget

    # ---- 阶段 A：L2 协议探测 ----
    for mod in _load_probes():
        if getattr(mod, 'TRANSPORT', 'tcp') != transport:
            continue
        if getattr(mod, 'LAYER', 'L2') != 'L2':
            continue
        # 预算检查不依赖 responded：静默端口 responded 恒 False，旧写法让预算形同虚设
        # （审计 C4：实测 26s/端口，文档声称 6s）。
        if _over_budget():
            break
        try:
            hit = mod.probe(ctx)
        except Exception:  # 探测器自身 bug 不能中断整轮识别
            continue
        if not hit:
            continue
        responded = True
        # probe 可返回 (evidence, products) —— 用模块 PROTOCOL
        # 或 (protocol, evidence, products) —— 自识别（如 banner 模块）
        if len(hit) == 3:
            proto, evidence, products = hit
        else:
            proto = getattr(mod, 'PROTOCOL', None)
            evidence, products = hit
        if not proto:
            continue
        order = getattr(mod, 'ORDER', 50)
        if order < 50:
            info.protocol = proto
            info.confidence = CONF_HIGH
            info.products = set(products or ())
            info.evidence = evidence
            break
        if info.protocol == CONF_UNKNOWN:
            info.protocol = proto
            info.confidence = CONF_MEDIUM
            info.products = set(products or ())
            info.evidence = evidence
        else:
            info.products.update(products or ())

    # ---- 阶段 B：L3 产品探测（仅 HTTP/HTTPS）----
    if info.protocol in ('http', 'https'):
        for mod in _load_probes():
            if getattr(mod, 'TRANSPORT', 'tcp') != transport:
                continue
            if getattr(mod, 'LAYER', 'L2') != 'L3':
                continue
            try:
                hit = mod.probe(ctx, scheme=info.protocol)
            except TypeError:
                try:
                    hit = mod.probe(ctx)
                except Exception:
                    continue
            except Exception:
                continue
            if not hit:
                continue
            responded = True
            products = hit[-1] if isinstance(hit[-1], (set, frozenset, list, tuple)) else set()
            evidence = hit[0] if len(hit) >= 2 else ''
            info.products.update(products or ())
            if evidence and not info.products:
                info.evidence += ' | ' + str(evidence)

    if info.protocol == CONF_UNKNOWN:
        # 有响应但认不出 → 仍是 unknown，但证据留给人工核验
        info.evidence = 'unrecognized service response' if responded else 'no response to any probe'
        info.confidence = CONF_LOW if responded else CONF_UNKNOWN

    # UDP 状态标记：探测器在证据串里写 `state=open|filtered;...`。
    # open|filtered 意味着「无响应」——端口状态不确定，协议标签也不可信，必须降为 unknown（fail-open 但不算已确认）。
    if 'state=' in info.evidence:
        marker = info.evidence.split('state=', 1)[1].split(';', 1)[0].strip()
        if marker in ('open', 'open|filtered', 'closed', 'filtered'):
            info.state = marker
        if marker != 'open':
            info.protocol = CONF_UNKNOWN
            info.confidence = CONF_LOW

    info.elapsed_ms = (time.time() - start) * 1000
    return info


def is_applicable(plugin_requires: List[str], svc: ServiceInfo) -> bool:
    """插件是否适用于该服务。空 requires = 通用插件，永远跑。

    requires 语义：**维度间且、维度内或**。
      - 协议维度：不以 product: 开头的项（如 ['http','https']，任一命中即可）
      - 产品维度：以 product: 开头的项（如 ['product:gitlab','product:confluence']）

    v1 实际生效的 SKIP 条件**只有协议维度**：协议已高置信度识别且不在声明内。
    产品维度当前**只做声明不参与判定**（理由见下方 return True 处注释：
    产品探测不完整，"未探测到" 不能当 "不存在" 的否证）。

    fail-open 四条（任一命中即放行，这是「不漏报优先」的落地点）：
      1. 协议判不出来（unknown / 空）
      2. 置信度非 high（medium/low 只是猜测，不够格拦插件）
      3. UDP 状态非 open（open|filtered 无法确认，协议标签不可信）
      4. 插件要求产品标签、但产品一个都没判出来
    """
    if not plugin_requires:
        return True

    # ---- fail-open：判定证据不足时一律放行 ----
    if svc is None:
        return True
    if svc.protocol in (CONF_UNKNOWN, '', None):
        return True
    if svc.confidence != CONF_HIGH:
        return True
    if getattr(svc, 'state', 'open') != 'open':
        return True

    tags = svc.tags
    protocol_reqs = [r for r in plugin_requires if not r.startswith('product:')]

    # 协议维度（维度内或）：这是 v1 唯一允许 SKIP 的维度。
    # 协议是「这个端口在说什么」，有主动探测证据；产品只是「它是什么应用」，探测必然不完整。
    if protocol_reqs and not any(r in tags for r in protocol_reqs):
        return False

    # 产品维度：v1 **仅作建议，不参与 SKIP**（2026-10-30 上线前审计 S1 裁决）。
    # 理由（两条，都是真实漏报机制）：
    #   1. 产品证据可被正文污染：响应正文出现 "Apache Tomcat" 就会让产品集非空，
    #      取消 fail-open 保护，472 个带 product: 标签的插件（wordpress 340 个）整批 SKIP。
    #   2. 反向代理场景：WordPress 前挂 nginx、且 wp-login 被安全插件改名时，
    #      只能判出 nginx → 340 个 wordpress 插件全部 SKIP = 真实漏报。
    # 「没探测到某产品」不等于「该产品不存在」——探测不完整，不能当作否证。
    # product: 标签保留在插件与探测器两侧，等指纹库覆盖度足够后再启用（方案 Q2-A）。
    return True


def skip_reason(plugin_requires: List[str], svc: ServiceInfo) -> str:
    return 'service is {} ({}) but plugin requires {}'.format(
        svc.protocol, svc.confidence, sorted(plugin_requires))
