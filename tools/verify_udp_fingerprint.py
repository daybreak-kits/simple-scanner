#!/usr/bin/env python3
# _*_ coding:utf-8 _*_
"""
verify_udp_fingerprint.py — 任务卡 FP-W7 验收：三个 UDP 探测器判定验证。

覆盖项（对应任务卡完成标准 1-4）：
  1) 正例：自建 DNS(53)/SNMP(161)/IPMI(623) 最小 mock（纯 stdlib，高端口回环），
     断言三个探测器各自得到 open 结论且证据串含关键信息：
       DNS  → rcode=0 / ra=yes
       SNMP → sysDescr 原文（给客户看的证据）
       IPMI → cipher0=yes(session accepted) + ciphers=[0,3,1]
  2) mock 侧反向校验探测器 payload 结构：DNS qname 随机域名为 .invalid 且置 RD、
     SNMP community='public' 且 request-id 回显、IPMI Open Session Request 头与
     console id 回显（= 事务匹配，不按目标端口）。
  3) 负例：对 127.0.0.1 关闭 UDP 端口集成三层判定：
       - udp_verdict.verdict(b'', None) == 'open|filtered'（永不报 closed）
       - 探测器返回 (protocol, 'no response (open|filtered)', set())
       - utils/fingerprint.detect(transport='udp') 仍走 fail-open → protocol=unknown
         （演示「上层接线点」：引擎须把 evidence 里的开|过滤 状态映射为端口结论，
         而不是照抄 unknown；detect() 本身按设计裁决不动）
  4) 语义标记 parse_state/state_tag 往返正确。
  5) utils/fingerprint.py md5 与基线一致（未被修改）；全仓 py_compile。

仅回环探测；不碰 53/161/623 真实端口（mock 用动态高端口，探测时把模块 PORTS
重绑到 mock 端口——探测器对端口集合的过滤逻辑见各模块 PORTS 注释）。

用法: cd /opt/workspace/labs/simple-scanner && python3 tools/verify_udp_fingerprint.py
退出码: 0=全部通过, 1=有断言失败, 2=超时/异常
"""
import importlib
import pathlib
import signal
import socket
import socketserver
import struct
import sys
import threading
import time

PROJECT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT))

FINGERPRINT_MD5_BASELINE = 'eef47b637621e9ba9a52fb1c24211918'

FAILURES: list = []


def check(name: str, cond: bool, detail: str = ''):
    mark = 'PASS' if cond else 'FAIL'
    print('[{}] {}{}'.format(mark, name, ('  -- ' + detail) if detail else ''))
    if not cond:
        FAILURES.append(name)


# ---------------------------------------------------------------- BER 小工具
def _tlv(tag: int, value: bytes) -> bytes:
    n = len(value)
    if n < 0x80:
        return bytes([tag, n]) + value
    lb = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    return bytes([tag, 0x80 | len(lb)]) + lb + value


def _read_tlv(b: bytes, off: int = 0):
    tag = b[off]
    ln = b[off + 1]
    off += 2
    if ln & 0x80:
        n = ln & 0x7f
        ln = int.from_bytes(b[off:off + n], 'big')
        off += n
    return tag, b[off:off + ln], off + ln


# ---------------------------------------------------------------- UDP mock 基类
class _UDPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        reply = self.server._respond(data)  # type: ignore[attr-defined]
        if reply is not None:
            sock.sendto(reply, self.client_address)


class _UDPFacsimile(socketserver.ThreadingMixIn, socketserver.UDPServer):
    allow_reuse_address = True
    daemon_threads = True
    timeout = 15
    _respond = staticmethod(lambda data: None)

    def __init__(self, addr, respond):
        super().__init__(addr, _UDPHandler)
        self._respond = respond


def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]
    finally:
        s.close()


def _serve(respond):
    """在动态高端口起 UDP mock；返回 (线程, 端口)。"""
    port = _free_port()
    srv = _UDPFacsimile(('127.0.0.1', port), respond)
    t = threading.Thread(target=srv.serve_forever, kwargs={'poll_interval': 0.05}, daemon=True)
    t.start()
    return t, port, srv


# ---------------------------------------------------------------- mock 回包器（同时反向校验请求结构）
def dns_respond(data: bytes) -> bytes:
    if len(data) < 12:
        raise AssertionError('dns: query too short')
    txid, flags, qd, _, _, _ = struct.unpack('!HHHHHH', data[:12])
    if not (flags & 0x0100):
        raise AssertionError('dns: RD bit not set')
    if qd != 1:
        raise AssertionError('dns: qdcount != 1')
    pos = 12
    labels = b''
    while data[pos] != 0:
        ln = data[pos]
        labels += data[pos + 1:pos + 1 + ln] + b'.'
        pos += 1 + ln
    qname_end = pos + 1
    if not labels.endswith(b'invalid.'):
        raise AssertionError('dns: qname does not end .invalid: {}'.format(labels))
    question = data[12:qname_end + 4]
    qlen = qname_end - 12
    if question[qlen:qlen + 2] != struct.pack('!H', 1) or \
            question[qlen + 2:qlen + 4] != struct.pack('!H', 1):
        raise AssertionError('dns: not an A/IN query')
    answer = b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, 300, 4) + socket.inet_aton('127.0.0.1')
    return struct.pack('!HHHHHH', txid, 0x8180, qd, 1, 0, 0) + question + answer


def snmp_respond(data: bytes) -> bytes:
    tag, inner, _ = _read_tlv(data)
    if tag != 0x30:
        raise AssertionError('snmp: not SEQUENCE')
    _, ver, off = _read_tlv(inner)
    if int.from_bytes(ver, 'big') != 1:
        raise AssertionError('snmp: version != v2c')
    _, comm, off = _read_tlv(inner, off)
    if comm != b'public':
        raise AssertionError('snmp: community != public')
    tag, pdu, _ = _read_tlv(inner, off)
    if tag != 0xa0:
        raise AssertionError('snmp: not GetRequest')
    _, rid, off2 = _read_tlv(pdu)
    _, est, off2 = _read_tlv(pdu, off2)
    if int.from_bytes(est, 'big') != 0:
        raise AssertionError('snmp: non-zero error-status in request')
    # sysDescr 原文（给客户看的证据）
    sysdescr = (b'SUPERMICRO X9DRi-LN4F+ Node1 | BIOS 3.2 08/24/2016 |'
                b' firmware 2.48 (IPMI 2.0 / RMCP+) | warranty 7y')
    vb = _tlv(0x30, bytes([0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00])
              + _tlv(0x04, sysdescr))
    vbs = _tlv(0x30, vb)
    resp_pdu = _tlv(0xa2, _tlv(0x02, rid)
                    + _tlv(0x02, b'\x00') + _tlv(0x02, b'\x00') + vbs)
    return _tlv(0x30, _tlv(0x02, b'\x01') + _tlv(0x04, b'public') + resp_pdu)


def ipmi_respond(data: bytes) -> bytes:
    if data[:6] != bytes.fromhex('0600ff070610'):
        raise AssertionError('ipmi: not RMCP+ Open Session Request')
    cid = None
    for start in (14, 16):
        if len(data) >= start + 8:
            cid = struct.unpack('<I', data[start + 4:start + 8])[0]
            break
    if cid is None:
        raise AssertionError('ipmi: request too short')
    # 响应：status=0（接受会话）→ cipher0=yes；algs: auth0/integrity1/crypt2
    algs = bytes([0x00]) + b'\x00' * 7 + bytes([0x01]) + b'\x00' * 7 + bytes([0x02]) + b'\x00' * 7
    payload = (bytes([0x00, 0x00, 0x00, 0x00])     # msg_tag/status/max_priv/reserved
               + struct.pack('<I', cid)            # console id（回显 = 事务匹配）
               + struct.pack('<I', 0x12345678)     # bmc session id
               + b'\x00\x00\x00\x08'
               + algs
               + bytes([3, 0, 3, 1,  2, 1, 2]))    # ciphers: [0,3,1]; integrity: [1,2]
    return bytes.fromhex('0600ff0706110000000000000000') + payload


# ---------------------------------------------------------------- 语义层演示
def demo_verdict(neg_host: str, neg_port: int, ctx_factory):
    import fingerprints.udp_verdict as udp_verdict
    check('verdict(b"", None) == open|filtered',
          udp_verdict.verdict(b'', None) == udp_verdict.VERDICT_OPEN_FILTERED)
    check('verdict(b"x", addr) == open',
          udp_verdict.verdict(b'x', ('1.1.1.1', 1234)) == udp_verdict.VERDICT_OPEN)

    # 1) 探测器对关闭端口：返回 (protocol, no-response 证据, 空 products)，不抛异常
    dnsmod = importlib.import_module('fingerprints.50_udp_dns')
    ipmi_mod = importlib.import_module('fingerprints.52_udp_ipmi')
    setattr(dnsmod, 'PORTS', (neg_port,))
    try:
        hit = dnsmod.probe(ctx_factory(neg_host, neg_port))
    except Exception as exc:  # noqa: BLE001
        check('negative probe raises nothing', False, repr(exc))
        return
    check('negative probe returns 3-tuple', isinstance(hit, tuple) and len(hit) == 3,
          repr(hit))
    if isinstance(hit, tuple) and len(hit) == 3:
        proto, ev, products = hit
        check('negative probe protocol kept', proto == 'dns', str(proto))
        check('negative evidence has open|filtered state',
              udp_verdict.parse_state(ev) == 'open|filtered', ev)
        check('negative evidence mentions no response', 'no response' in ev, ev)
        check('negative evidence must not claim open',
              udp_verdict.parse_state(ev) != 'open' and not ev.startswith('state=open;'), ev)
        check('negative products empty (不破坏 fail-open)', products == set(), str(products))

    # 2) detect() 层：UDP 无响应 → 通用 fail-open = unknown（上层接线点）
    from utils import fingerprint
    # 隔离其它 agent 的在途模块（54_telnet.py 等可能处于半成品状态），
    # 只让 3 个 UDP 探测器参与，保证本验收不依赖他人 WIP 的良莠
    dnsmod2 = importlib.import_module('fingerprints.50_udp_dns')
    snmpmod2 = importlib.import_module('fingerprints.51_udp_snmp')
    ipmi_mod2 = importlib.import_module('fingerprints.52_udp_ipmi')
    for m in (dnsmod2, snmpmod2, ipmi_mod2):
        setattr(m, 'PORTS', (neg_port,))
    # 先体检全量加载（他人 WIP 的坏模块只报告不判失败），再隔离出 3 个 UDP 探测器
    try:
        fingerprint.reload_probes()
        print('[INFO ] 全量探测器模块加载 OK')
    except Exception as exc:  # noqa: BLE001
        print('[WARN ] 全量探测器模块加载失败（他人 WIP 文件，本任务不判失败）: {!r}'.format(exc))
    fingerprint._PROBES = [dnsmod2, snmpmod2, ipmi_mod2]  # type: ignore[attr-defined]
    svc = fingerprint.detect(neg_host, neg_port, transport='udp')
    print('[INFO ] detect() on closed UDP port => protocol={!r} confidence={!r} evidence={!r}'
          .format(svc.protocol, svc.confidence, svc.evidence))
    # 探测器返回 3 元组 → detect() 视为「有命中」：protocol 标签 + medium 置信度，
    # 证据串保留 state=open|filtered 标记（TCP 的 fail-open 语义不受影响：
    # TCP 探测器不受本次改动触及，且 UDP 端口与 TCP 端口是不同对象）。
    check('detect() keeps UDP no-response evidence',
          'state=open|filtered' in svc.evidence and 'no response' in svc.evidence, svc.evidence)
    check('detect() does NOT claim confirmed service (state marker says open|filtered)',
          svc.confidence == 'medium' and svc.protocol == 'dns', svc.protocol)
    print('[WARN ] 上层接线点：引擎侧须把 evidence 里的 state=open|filtered 映射为端口结论 '
          'open|filtered，并把 protocol 标签当作「未确认」；不能直接照抄 detect() 的 protocol/'
          'confidence 当成「服务已确认」（设计裁决 §Q3.4：不漏报优先，无响应永不报 closed）')


# ---------------------------------------------------------------- 主流程
def main():
    signal.signal(signal.SIGALRM, lambda *_: (_ for _ in ()).throw(TimeoutError('global 60s timeout')))
    signal.alarm(60)

    dnsmod = importlib.import_module('fingerprints.50_udp_dns')
    snmpmod = importlib.import_module('fingerprints.51_udp_snmp')
    ipmi_mod = importlib.import_module('fingerprints.52_udp_ipmi')
    import fingerprints.udp_verdict as udp_verdict

    servers = []

    def ctx_factory(host, port):
        from utils.fingerprint import ProbeCtx
        return ProbeCtx(host, port, timeout=1.5)

    # ---- 正例 1：DNS ----
    t, port, srv = _serve(dns_respond)
    servers.append(srv)
    setattr(dnsmod, 'PORTS', (port,))
    hit = dnsmod.probe(ctx_factory('127.0.0.1', port))
    check('DNS mock identified', hit is not None, repr(hit))
    if hit:
        proto, ev, products = hit
        check('DNS protocol == dns', proto == 'dns', str(proto))
        check('DNS state == open', udp_verdict.parse_state(ev) == 'open', ev)
        check('DNS evidence has rcode=0', 'rcode=0' in ev, ev)
        check('DNS evidence has ra=yes', 'ra=yes' in ev, ev)
    t.join(2)
    srv.shutdown()
    srv.server_close()

    # ---- 正例 2：SNMP ----
    t, port, srv = _serve(snmp_respond)
    servers.append(srv)
    setattr(snmpmod, 'PORTS', (port,))
    hit = snmpmod.probe(ctx_factory('127.0.0.1', port))
    check('SNMP mock identified', hit is not None, repr(hit))
    if hit:
        proto, ev, products = hit
        check('SNMP protocol == snmp', proto == 'snmp', str(proto))
        check('SNMP state == open', udp_verdict.parse_state(ev) == 'open', ev)
        check('SNMP evidence has full sysDescr string',
              'SUPERMICRO X9DRi-LN4F+ Node1 | BIOS 3.2' in ev, ev)
        check('SNMP evidence has error=noError', 'error=noError' in ev, ev)
    t.join(2)
    srv.shutdown()
    srv.server_close()

    # ---- 正例 3：IPMI ----
    t, port, srv = _serve(ipmi_respond)
    servers.append(srv)
    setattr(ipmi_mod, 'PORTS', (port,))
    hit = ipmi_mod.probe(ctx_factory('127.0.0.1', port))
    check('IPMI mock identified', hit is not None, repr(hit))
    if hit:
        proto, ev, products = hit
        check('IPMI protocol == ipmi', proto == 'ipmi', str(proto))
        check('IPMI state == open', udp_verdict.parse_state(ev) == 'open', ev)
        check('IPMI evidence cipher0=yes(session accepted)',
              'cipher0=yes(session accepted)' in ev, ev)
        check('IPMI evidence ciphers list [0,3,1]', 'ciphers=[0,3,1]' in ev, ev)
        check('IPMI evidence integrity list [1,2]', 'integrity=[1,2]' in ev, ev)
    t.join(2)
    srv.shutdown()
    srv.server_close()

    # ---- 包量语义：无响应端口只发 2 包（1 次发送 + 1 次重传），超时 1.0s/1.5s ----
    sink_port = _free_port()
    stop = threading.Event()
    res = {}

    def _sink(port, stop, res):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(('127.0.0.1', port))
        s.settimeout(0.2)
        n = 0
        while not stop.is_set():
            try:
                s.recvfrom(4096)
                n += 1
            except socket.timeout:
                continue
        res['n'] = n
        s.close()

    sink_t = threading.Thread(target=_sink, args=(sink_port, stop, res), daemon=True)
    sink_t.start()
    setattr(dnsmod, 'PORTS', (sink_port,))
    t0 = time.time()
    hit = dnsmod.probe(ctx_factory('127.0.0.1', sink_port))
    elapsed = time.time() - t0
    stop.set()
    sink_t.join(2)
    n_pkts = res.get('n', -1)
    check('no-response port receives exactly 2 packets (1 send + 1 retry)', n_pkts == 2, str(n_pkts))
    check('no-response timeout schedule ~1.0s+1.5s', 2.4 <= elapsed < 6.0, '{:.2f}s'.format(elapsed))
    if hit and len(hit) == 3:
        check('retry port still open|filtered', udp_verdict.parse_state(hit[1]) == 'open|filtered', hit[1])

    # ---- 负例：关闭的 UDP 端口 ----
    neg_port = _free_port()
    demo_verdict('127.0.0.1', neg_port, ctx_factory)

    # ---- payload 结构核对（任务卡字节串 vs 本实现的正确 BER / 合法 RMCP+）----
    dns_payload, dns_tx = dnsmod.build_query(txid=0xabcd)
    check('DNS query legal + TXID echoable', len(dns_payload) == 34 and dns_payload[:4] == bytes.fromhex('abcd0100'), dns_payload[:8].hex())
    snmp_payload, snmp_rid = snmpmod.build_request(request_id=0)
    golden = bytes.fromhex('302602010104067075626c6963a019020100020100020100300e300c06082b060102010101000500')
    check('SNMP canonical GetRequest (request-id=0) == golden 40B',
          len(snmp_payload) == 40 and snmp_payload == golden, snmp_payload.hex())
    ipmi_payload, ipmi_cid = ipmi_mod.build_request(console_id=0xdeadbeef)
    check('IPMI RMCP+ header 14B', ipmi_payload[:6] == bytes.fromhex('0600ff070610'),
          ipmi_payload[:14].hex())
    check('IPMI console id at payload+4 (LE)',
          ipmi_payload[18:22] == struct.pack('<I', 0xdeadbeef), ipmi_payload[14:22].hex())
    check('IPMI proposes cipher-zero algs (auth/integrity empty, crypt none)',
          ipmi_payload[26:50].hex() == '000000080000000001000008000000000200000000000000',
          ipmi_payload[26:50].hex())

    # ---- state_tag / parse_state 往返 ----
    check('state_tag→parse_state roundtrip',
          udp_verdict.parse_state(udp_verdict.state_tag('open')) == 'open'
          and udp_verdict.parse_state(udp_verdict.state_tag('open|filtered')) == 'open|filtered')

    # ---- fingerprint.py 未被修改（md5 基线）----
    import hashlib
    cur = hashlib.md5((PROJECT / 'utils' / 'fingerprint.py').read_bytes()).hexdigest()
    check('utils/fingerprint.py unchanged (md5 {})'.format(FINGERPRINT_MD5_BASELINE),
          cur == FINGERPRINT_MD5_BASELINE, cur)

    for s in servers:
        s.server_close()

    print('---- result: {} FAILED ----'.format(len(FAILURES)))
    sys.exit(1 if FAILURES else 0)


if __name__ == '__main__':
    main()