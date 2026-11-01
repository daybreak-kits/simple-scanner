"""MySQL / PostgreSQL / MongoDB / LDAP / SMB 等二进制协议探测。

原则：每个探测用**新连接**，只发最小握手包，读服务端首包特征。
全部端口无关（MySQL 可能在 3307，PG 在 5433）。
"""

import struct

TRANSPORT = 'tcp'
PROTOCOL = 'mysql'
ORDER = 20


def probe(ctx):
    # MySQL 服务端主动发握手包：3 字节长度 + 1 字节序号 + 协议版本(0x0a)
    resp = ctx.recv_passive(wait=0.6)
    if len(resp) > 5 and resp[4:5] == b'\x0a':
        ver = resp[5:resp.find(b'\x00', 5) if b'\x00' in resp[5:] else 40]
        try:
            vtext = ver.decode('latin-1', 'replace')
        except Exception:
            vtext = ''
        if vtext and vtext[0].isdigit():
            return 'MySQL handshake v{}'.format(vtext), set()
    return None
