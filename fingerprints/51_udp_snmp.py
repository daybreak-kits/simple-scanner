"""UDP/161 SNMP 探测：SNMPv2c GET sysDescr.0，community='public'。

依据：research/udp-vuln-landscape.md §Q2 SNMP 行 / §Q1.4。
有应答 = 服务开放 **且 public 团体有效**（Shadowserver HIGH 报告判定口径），
sysDescr 原文可直接交给客户作为「public 团体开放」的证据。

payload 字节结构（RFC 1157 / RFC 3416，BER/ASN.1 正确编码——不手拼 hex）：
  SEQUENCE(整个消息, tag 0x30)
    INTEGER   version = 1（SNMPv2c）                   02 01 01
    OCTET STRING  community = 'public'                 04 06 ...

GetRequest PDU（tag 0xa0, IMPLICIT）：
    INTEGER   request-id   （随机，响应须回显 → 反伪造/反陈包）
    INTEGER   error-status = 0                         02 01 00
    INTEGER   error-index  = 0                         02 01 00
    SEQUENCE  varbind-list (tag 0x30)
      SEQUENCE  varbind (tag 0x30)
        OID     1.3.6.1.2.1.1.1.0  (sysDescr.0)        06 08 2b 06 01 02 01 01 01 00
        NULL    值                                     05 00

【与任务卡字节串的差异，必须披露】
任务卡给的 41 字节 hex（3027020101...）经 BER 解析为非法消息：
- community 'public' 前缺少 tag 04 + len 06（6 个字节光秃秃跟在 version 后面）；
- GetRequest PDU 内有 4 个 INTEGER（多一个）；
- OID 长度前缀 09 与内容不符（内容多了 05，实际解成 1.3.6.1.2.1.1.1.0.5），
  末尾 NULL 丢失。
真实 SNMP agent 对该消息会解析失败。本模块改用上面的正确编码，并在验证脚本里
与 golden 字节逐字节比对（request_id=0 时 = 40 字节规范报文）。

响应校验：外层 SEQUENCE + GetResponse PDU(0xa2) + request-id 回显 +
varbind 内 OID 为 sysDescr.0 → 提取值原文（OCTET STRING，~200 字符截断）。
error_status != 0 时（如 noSuchName）仍证明「public 团体有效」，如实上报。
"""

import random
from typing import Optional, Tuple

import fingerprints.udp_verdict as udp_verdict

TRANSPORT = 'udp'
PROTOCOL = 'snmp'
ORDER = 50
PORTS = (161,)

SYSDESCR_OID = (1, 3, 6, 1, 2, 1, 1, 1, 0)
SYSDESCR_ENCODED = bytes([0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00])

ERROR_STATUS_TEXT = {0: 'noError', 1: 'tooBig', 2: 'noSuchName',
                     3: 'badValue', 4: 'readOnly', 5: 'genErr'}


def _tlv(tag: int, value: bytes) -> bytes:
    """BER TLV：短长度（<128）或长长度（0x80|n + 大端长度）。"""
    n = len(value)
    if n < 0x80:
        return bytes([tag, n]) + value
    lb = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    return bytes([tag, 0x80 | len(lb)]) + lb + value


def _int_tlv(v: int) -> bytes:
    h = v.to_bytes(max(1, (v.bit_length() + 7) // 8), 'big')
    return _tlv(0x02, h)


def _oid_tlv() -> bytes:
    return _tlv(0x06, SYSDESCR_ENCODED)


def build_request(request_id: Optional[int] = None) -> Tuple[bytes, int]:
    """构造 SNMPv2c GET sysDescr.0。返回 (payload, request_id)。"""
    request_id = request_id if request_id is not None else random.randrange(0x7fffffff)
    varbind = _tlv(0x30, _oid_tlv() + _tlv(0x05, b''))       # { OID, NULL }
    varbinds = _tlv(0x30, varbind)
    pdu = _tlv(0xa0, _int_tlv(request_id) + _int_tlv(0) + _int_tlv(0) + varbinds)
    msg = _tlv(0x30, _int_tlv(1) + _tlv(0x04, b'public') + pdu)
    return msg, request_id


def _read_tlv(data: bytes, off: int = 0) -> Tuple[int, bytes, int]:
    """读取一个 BER TLV，返回 (tag, value, 下一偏移)。支持长长度形式。"""
    tag = data[off]
    ln = data[off + 1]
    off += 2
    if ln & 0x80:
        n = ln & 0x7F
        ln = int.from_bytes(data[off:off + n], 'big')
        off += n
    return tag, data[off:off + ln], off + ln


def parse_response(resp: bytes, request_id: int) -> dict:
    """解析 GetResponse。返回 {ok, reason, error_status, error_text, sysdescr, sysdescr_kind}。"""
    out = {'ok': False, 'reason': 'empty response', 'error_status': None,
           'error_text': None, 'sysdescr': None, 'sysdescr_kind': None}
    try:
        tag, inner, _ = _read_tlv(resp)                    # 外层 SEQUENCE
        if tag != 0x30:
            out['reason'] = 'not a BER SEQUENCE (tag 0x{:02x})'.format(tag)
            return out
        tag, ver, off = _read_tlv(inner)
        if tag != 0x02 or int.from_bytes(ver, 'big') != 1:
            out['reason'] = 'unexpected version TLV'
            return out
        tag, _comm, off = _read_tlv(inner, off)
        if tag != 0x04:
            out['reason'] = 'no community string'
            return out
        tag, pdu, _ = _read_tlv(inner, off)
        if tag != 0xa2:
            out['reason'] = 'not a GetResponse (tag 0x{:02x})'.format(tag)
            return out
        tag, rid, off = _read_tlv(pdu)
        if tag != 0x02 or int.from_bytes(rid, 'big') != request_id:
            out['reason'] = 'request-id mismatch'
            return out
        tag, est, off = _read_tlv(pdu, off)
        if tag != 0x02:
            out['reason'] = 'no error-status'
            return out
        out['error_status'] = int.from_bytes(est, 'big')
        out['error_text'] = ERROR_STATUS_TEXT.get(out['error_status'], str(out['error_status']))
        tag, _ix, off = _read_tlv(pdu, off)
        if tag != 0x02:
            out['reason'] = 'no error-index'
            return out
        tag, vbl, _ = _read_tlv(pdu, off)
        if tag != 0x30:
            out['reason'] = 'no varbind list'
            return out
        tag, vb, off2 = _read_tlv(vbl)
        if tag != 0x30:
            out['reason'] = 'no varbind'
            return out
        tag, oidb, off2 = _read_tlv(vb)
        if tag != 0x06 or oidb != SYSDESCR_ENCODED:
            out['reason'] = 'unexpected OID (0x{})'.format(oidb.hex())
            return out
        tag, val, _ = _read_tlv(vb, off2)
        out['sysdescr'] = val
        out['sysdescr_kind'] = 'octet-string' if tag == 0x04 else 'tag-0x{:02x}'.format(tag)
        out['ok'] = True
        out['reason'] = 'ok'
    except (IndexError, ValueError):
        out['reason'] = 'malformed BER'
    return out


def _sysdescr_text(info: dict) -> str:
    """sysDescr 原文转可读文本，截断 ~200 字符（给客户看的证据串）。"""
    val = info.get('sysdescr') or b''
    if info.get('sysdescr_kind') == 'octet-string':
        text = val.decode('latin-1', 'replace').strip()
    else:
        text = '(non-string value) 0x{}'.format(val[:32].hex())
    if len(text) > 200:
        text = text[:200] + '...[truncated]'
    return text


def _unmatched(why: str) -> tuple:
    return (PROTOCOL,
            udp_verdict.state_tag(udp_verdict.VERDICT_OPEN_FILTERED)
            + 'unmatched response ({})'.format(why),
            set())


def probe(ctx):
    if PORTS and ctx.port not in PORTS:
        return None
    payload, reqid = build_request()
    resp, addr = udp_verdict.send_with_retry(ctx, payload, read=4096)
    if not resp:
        return (PROTOCOL,
                udp_verdict.state_tag(udp_verdict.VERDICT_OPEN_FILTERED)
                + 'no response (open|filtered)',
                set())
    if not (addr and addr[0] == ctx.host):
        return _unmatched('source {} != target {}'.format(addr, ctx.host))
    info = parse_response(resp, reqid)
    if not info['ok']:
        return _unmatched(info['reason'])
    return (PROTOCOL,
            udp_verdict.state_tag(udp_verdict.VERDICT_OPEN)
            + 'snmpv2c-get public -> error={} sysdescr="{}"'.format(
                info['error_text'], _sysdescr_text(info)),
            set())