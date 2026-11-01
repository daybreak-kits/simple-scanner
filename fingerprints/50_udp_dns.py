"""UDP/53 DNS 探测：标准 A 查询（随机 TXID + 随机域名）。

依据：research/udp-vuln-landscape.md §Q2 DNS 行（①带随机 TXID 的标准 A 查询）。
- 空包对开放端口无响应（nmap 手册 §Q3.1）→ 必须用协议特定 payload。
- 响应匹配按 (来源 IP, TXID)（§Q3.2 问题 4：不按目标端口，TFTP/SSDP 会从临时端口回包）。
- 有匹配响应 = DNS 开放；证据带 RCODE 与 recursion available
  （SIGRed 前置条件之一：Windows DNS 需启用递归才会走条件转发链）。

payload 字节结构（RFC 1035 4.1.1/4.1.2）：
  header 12B:
    [0:2]   ID      = 随机 TXID（响应须回显，防离路径伪造/陈包）
    [2:4]   FLAGS   = 0x0100（RD=1, 其余 0）
    [4:6]   QDCOUNT = 1
    [6:12]  AN/NS/ARCOUNT = 0
  question:
    qname    = 随机 8 位标签 + '.invalid'（RFC 6761 保留 TLD，不碰真实域名）
              线格式 = 08 <8 字节> 07 'invalid' 00（每段一个长度字节）
    [..+2]  QTYPE  = 1 (A)
    [..+2]  QCLASS = 1 (IN)

探测范围：PORTS=(53,)——UDP v1 端口集合固定为 53/161/623（§Q3.4），
对各协议端口打其它协议 payload 只会浪费包量；TCP 层探测器仍保持端口无关键
（nmap-service-probes 对 UDP 也是按端口绑 probe：match udp port 53 先例）。
若目标 DNS 跑在非 53 端口 → v1 不漏报优先可接受，v1.1 再议。
"""

import random
import struct
from typing import Optional

import fingerprints.udp_verdict as udp_verdict

TRANSPORT = 'udp'
PROTOCOL = 'dns'
ORDER = 50
PORTS = (53,)

_FLAGS_RD = 0x0100   # RD=1
_FLAGS_QR = 0x8000   # 响应位
_FLAG_RA = 0x0080    # recursion available


def _encode_name(name: str) -> bytes:
    """DNS 线格式名字：每段一个长度字节 + 标签内容，末尾 0x00（RFC 1035 §3.1）。"""
    out = b''
    for label in name.split('.'):
        raw = label.encode('ascii')
        out += bytes([len(raw)]) + raw
    return out + b'\x00'


def build_query(txid: Optional[int] = None) -> tuple:
    """构造标准 DNS A 查询。返回 (payload, txid)。"""
    txid = txid if txid is not None else random.randrange(0x10000)
    label = ''.join(random.choice('abcdefghijklmnopqrstuvwxyz0123456789')
                    for _ in range(8))
    qname = _encode_name(label + '.invalid')   # 08 <8B> 07 'invalid' 00
    header = struct.pack('!HHHHHH', txid, _FLAGS_RD, 1, 0, 0, 0)
    question = qname + struct.pack('!HH', 1, 1)  # QTYPE=A, QCLASS=IN
    return header + question, txid


def parse_response(resp: bytes, txid: int) -> dict:
    """校验 DNS 响应：TXID 回显 + QR 位。返回 {ok, reason, rcode, ra, qd}。不抛异常。"""
    out = {'ok': False, 'reason': 'empty response', 'rcode': None, 'ra': None, 'qd': None}
    if len(resp) < 12:
        out['reason'] = 'short response {}B'.format(len(resp))
        return out
    if struct.unpack('!H', resp[0:2])[0] != txid:
        out['reason'] = 'txid mismatch'
        return out
    flags = struct.unpack('!H', resp[2:4])[0]
    if not (flags & _FLAGS_QR):
        out['reason'] = 'QR bit not set'
        return out
    out['rcode'] = flags & 0x000F
    out['ra'] = bool(flags & _FLAG_RA)
    out['qd'] = struct.unpack('!H', resp[4:6])[0]
    out['ok'] = True
    out['reason'] = 'ok'
    return out


def _unmatched(why: str) -> tuple:
    """有响应但未被本查询确认时，保守报 open|filtered（不漏报、不谎报 open）。"""
    return (PROTOCOL,
            udp_verdict.state_tag(udp_verdict.VERDICT_OPEN_FILTERED)
            + 'unmatched response ({})'.format(why),
            set())


def probe(ctx):
    if PORTS and ctx.port not in PORTS:
        return None
    payload, txid = build_query()
    resp, addr = udp_verdict.send_with_retry(ctx, payload, read=2048)
    if not resp:
        # 无响应 = open|filtered（硬要求：永不报 closed）
        return (PROTOCOL,
                udp_verdict.state_tag(udp_verdict.VERDICT_OPEN_FILTERED)
                + 'no response (open|filtered)',
                set())
    if not (addr and addr[0] == ctx.host):
        return _unmatched('source {} != target {}'.format(addr, ctx.host))
    info = parse_response(resp, txid)
    if not info['ok']:
        return _unmatched(info['reason'])
    return (PROTOCOL,
            udp_verdict.state_tag(udp_verdict.VERDICT_OPEN)
            + 'dns rcode={} ra={} qd={}'.format(
                info['rcode'], 'yes' if info['ra'] else 'no', info['qd']),
            set())