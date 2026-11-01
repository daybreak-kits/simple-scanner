"""UDP/623 IPMI 探测：RMCP+ Open Session Request（提议 cipher suite 0 = cipher zero）。

依据与偏离说明（务必连同证据串一起看）：
- 任务卡给的 14 字节 payload ``0600ff07000000000000000000000000`` 实为
  **RMCP Presence Ping**（RMCP 头 06 00 ff 07 + ASF 头 10 字节全 0）。
  它的响应是 RMCP Presence Pong，**不含 cipher 列表**：ipmitool 的
  ``ipmi_handle_pong()``（src/plugins/lanplus/lanplus.c）只解析
  rmcp_hdr/asf_hdr/iana/oem/sup_entities/sup_interact 六个字段。
  用它无法满足「读 cipher 列表 + 判定是否支持 cipher 0」的目标。
- 本模块改用**单包即可给出 cipher 0 判定**的真实探测：RMCP+ Open Session
  Request 提议 cipher suite 0，nmap 的 scripts/ipmi-cipher-zero.nse +
  nselib/ipmi.lua（Metasploit ipmi scanner 同源移植，现场验证）用的就是它：
  若 BMC 回 Open Session Response 且 status=0 → 接受了「无认证/无完整性/无加密」
  会话 = cipher-zero 认证绕过（CVE-2013-4786 类问题、Fortra Test ID 16658）
  的核心前提；若回 status=0x11（no cipher suite match）→ 不支持 cipher 0。
- 响应字段偏移按 ipmitool ``read_open_session_response()``（同文件，spec
  §13.18 的实现）：payload[1]=status、payload[2]=max privilege、
  payload[4:8]=Remote Console ID（响应须回显请求里的 console id → 事务匹配）、
  payload[8:12]=Managed System Session ID、payload[16]/[24]/[32]=协商出的
  auth/integrity/confidentiality 算法号；尾部按 spec 解析
  [cipher 数][cipher 列表][integrity 数][integrity 列表]。
  RMCP+ 载荷起点在不同实现里有 14/16 两种帧法 → 解析器对两个候选起点都试，
  以 console id 回显为准（见 _parse_payload）。

payload 字节结构（46 字节）：
  [0]    0x06            RMCP version 1.0
  [1]    0x00            reserved
  [2]    0xff            RMCP sequence
  [3]    0x07            message class = IPMI
  [4]    0x06            RMCP+ authentication type
  [5]    0x10            RMCP+ payload type = Open Session Request
  [6:10] 0               session id
  [10:14] 0              sequence number
  payload:
  [0:2]  0x0000          maximum access (privilege level)
  [2:4]  0x0000          reserved
  [4:8]  console id      随机（响应回显它 = 事务 ID，用于反伪造）
  [8:12] 0x00000008      managed system session id（沿用 nmap 原值）
  三个 8 字节算法记录（type/reserved/value），cipher suite 0 = 全空算法：
  [12:20] 00 00 00 08 | 00 00 00 00    auth: cipher zero
  [20:28] 01 00 00 08 | 00 00 00 00    integrity: cipher zero
  [28:36] 02 00 00 00 | 00 00 00 00    confidentiality: none
"""

import random
import struct
from typing import Optional, Tuple

import fingerprints.udp_verdict as udp_verdict

TRANSPORT = 'udp'
PROTOCOL = 'ipmi'
ORDER = 50
PORTS = (623,)

# RMCP+ Open Session Response 的 status 码（nmap nselib/ipmi.lua RMCP_ERRORS）
STATUS_TEXT = {
    0x00: 'ok',
    0x01: 'insufficient resources',
    0x03: 'invalid payload type',
    0x04: 'invalid authentication algorithm',
    0x05: 'invalid integrity algorithm',
    0x06: 'no matching authentication payload',
    0x07: 'no matching integrity payload',
    0x0b: 'unauthorised role or privilege level',
    0x0d: 'unauthorized name',
    0x0e: 'unauthorized GUID',
    0x11: 'no cipher suite match',
}

# 算法号（按算法类别分表，spec §22.3 表 22-19 的 cipher suite 组成）
AUTH_ALG = {0x00: 'RAKP-HMAC-SHA1', 0x01: 'RAKP-HMAC-SHA256', 0x02: 'RAKP-HMAC-MD5'}
INTEGRITY_ALG = {0x00: 'none', 0x01: 'HMAC-SHA1-96', 0x02: 'HMAC-MD5-128'}
CRYPT_ALG = {0x00: 'none', 0x01: 'AES-CBC-128', 0x02: 'xRC4-128', 0x03: 'xRC4-40'}

# RMCP+ 载荷起点候选：14（无长度字段）/ 16（带 2 字节长度）
_PAYLOAD_STARTS = (14, 16)


def build_request(console_id: Optional[int] = None) -> Tuple[bytes, int]:
    """构造 RMCP+ Open Session Request（提议 cipher suite 0）。返回 (payload, console_id)。"""
    console_id = console_id if console_id is not None else random.randrange(0x100000000)
    header = (bytes.fromhex('0600ff07') + bytes([0x06, 0x10])
              + b'\x00\x00\x00\x00' + b'\x00\x00\x00\x00')
    payload = (b'\x00\x00'                       # maximum access
               + b'\x00\x00'                     # reserved
               + struct.pack('<I', console_id)   # remote console id
               + bytes.fromhex('00000008')       # managed system session id
               + bytes.fromhex('0000000800000000')   # auth: cipher zero
               + bytes.fromhex('0100000800000000')   # integrity: cipher zero
               + bytes.fromhex('0200000000000000'))  # confidentiality: none
    return header + payload, console_id


def _parse_cipher_tail(tail: bytes) -> dict:
    """解析尾部 [cipher 数][cipher ids][integrity 数][integrity ids]（自洽校验）。

    返回 {'ciphers': [...]|None, 'integritys': [...]|None}。
    """
    out: dict = {'ciphers': None, 'integritys': None}
    n = len(tail)
    for count in (1, 2, 3, 4, 5, 6, 7, 8, 10, 12, 16):
        if 1 + count + 1 > n or tail[0] != count:
            continue
        ciphers = list(tail[1:1 + count])
        if not all(0 <= c <= 0x1f for c in ciphers):
            continue
        pos = 1 + count
        cnt2 = tail[pos]
        if pos + 1 + cnt2 != n:
            continue
        integritys = list(tail[pos + 1:pos + 1 + cnt2])
        if not all(0 <= c <= 0x03 for c in integritys):
            continue
        out['ciphers'] = ciphers
        out['integritys'] = integritys
        return out
    return out


def _parse_payload(payload: bytes, console_id: int) -> Optional[dict]:
    """按 ipmitool read_open_session_response() 的偏移解析；不匹配返回 None。"""
    if len(payload) < 8:
        return None
    if struct.unpack('<I', payload[4:8])[0] != console_id:
        return None
    out = {'status': payload[1], 'max_priv': payload[2],
           'console_id': console_id,
           'bmc_session_id': struct.unpack('<I', payload[8:12])[0] if len(payload) >= 12 else None,
           'auth_alg': None, 'integrity_alg': None, 'crypt_alg': None,
           'ciphers': None, 'integritys': None}
    if len(payload) >= 40:
        out['auth_alg'] = payload[16]
        out['integrity_alg'] = payload[24]
        out['crypt_alg'] = payload[32]
        tail = _parse_cipher_tail(payload[40:])
        out['ciphers'] = tail['ciphers']
        out['integritys'] = tail['integritys']
    return out


def parse_response(resp: bytes, console_id: int) -> dict:
    """校验 RMCP+ Open Session Response。返回 {ok, reason, ...}。不抛异常。"""
    out = {'ok': False, 'reason': 'empty response'}
    if len(resp) < 6:
        out['reason'] = 'short response {}B'.format(len(resp))
        return out
    if resp[0:4] != bytes.fromhex('0600ff07'):
        out['reason'] = 'not an RMCP header'
        return out
    if resp[4] != 0x06:
        out['reason'] = 'not RMCP+ auth type'
        return out
    if resp[5] != 0x11:
        out['reason'] = 'not an Open Session Response (type 0x{:02x})'.format(resp[5])
        return out
    for start in _PAYLOAD_STARTS:
        info = _parse_payload(resp[start:], console_id)
        if info is not None:
            info['ok'] = True
            info['reason'] = 'ok'
            info['payload_start'] = start
            return info
    out['reason'] = 'console id not echoed / layout mismatch'
    return out


def _cipher_zero_verdict(info: dict) -> str:
    """cipher 0 判定：status=0 = BMC 接受了 cipher-zero 会话（最强证据）；
    否则看响应回传的 cipher 列表里有没有 0。"""
    if info['status'] == 0x00:
        return 'yes(session accepted)'
    ciphers = info.get('ciphers')
    if ciphers is not None:
        return 'listed-but-rejected' if 0 in ciphers else 'no'
    return 'unknown'


def _unmatched(why: str) -> tuple:
    return (PROTOCOL,
            udp_verdict.state_tag(udp_verdict.VERDICT_OPEN_FILTERED)
            + 'unmatched response ({})'.format(why),
            set())


def probe(ctx):
    if PORTS and ctx.port not in PORTS:
        return None
    payload, console_id = build_request()
    resp, addr = udp_verdict.send_with_retry(ctx, payload, read=2048)
    if not resp:
        return (PROTOCOL,
                udp_verdict.state_tag(udp_verdict.VERDICT_OPEN_FILTERED)
                + 'no response (open|filtered)',
                set())
    if not (addr and addr[0] == ctx.host):
        return _unmatched('source {} != target {}'.format(addr, ctx.host))
    info = parse_response(resp, console_id)
    if not info['ok']:
        return _unmatched(info['reason'])
    status = info['status']
    ciphers = info.get('ciphers')
    evidence = ('ipmi rmcp+ open-session status=0x{:02x}({}) cipher0={} ciphers={} integrity={}'
                .format(status, STATUS_TEXT.get(status, 'unknown'),
                        _cipher_zero_verdict(info),
                        ('[' + ','.join(str(c) for c in ciphers) + ']') if ciphers is not None else 'n/a',
                        ('[' + ','.join(str(c) for c in info['integritys']) + ']')
                        if info.get('integritys') is not None else 'n/a'))
    if info.get('auth_alg') is not None:
        evidence += ' algs={}/{}/{}'.format(
            AUTH_ALG.get(info['auth_alg'], str(info['auth_alg'])),
            INTEGRITY_ALG.get(info['integrity_alg'], str(info['integrity_alg'])),
            CRYPT_ALG.get(info['crypt_alg'], str(info['crypt_alg'])))
    return (PROTOCOL, udp_verdict.state_tag(udp_verdict.VERDICT_OPEN) + evidence, set())