"""RDP 探测：X.224 连接请求（MS-RDPBCGR §2.2.1.1）。

响应特征：服务器回 TPKT(0x03 0x00) 包裹的 X.224 Connection Confirm，
X.224 TPD 结构 = length(1)=0x0e + type(1)=0xd0（CC）→ 即 resp[4]=0x0e、resp[5]=0xd0。
判据 = resp[:2] == b'\\x03\\x00' 且 resp[4] == 0x0e 且 resp[5] == 0xd0。
依据：MS-RDPBCGR 传输层协议；X.224 (ITU-T X.224) CR/CC 包类型 0xe0/0xd0。
RDP 协商请求（TLS+CredSSP）：
  03 00 00 13 0e e0 00 00 00 00 00 01 00 08 00 03 00 00 00
"""

TRANSPORT = 'tcp'
PROTOCOL = 'rdp'
ORDER = 36  # 强特征：TPKT+X.224 CC 是硬证据

# X.224 Connection Request with RDP Negotiation Request (TLS+CredSSP)
_RDP_REQ = bytes.fromhex('030000130ee000000000000100080003000000')


def probe(ctx):
    resp = ctx.send_recv(_RDP_REQ, read=128)
    if len(resp) >= 6 and resp[:2] == b'\x03\x00' and resp[4] == 0x0e and resp[5] == 0xd0:
        return 'RDP X.224 CC -> {}'.format(resp[:24].hex()), set()
    return None