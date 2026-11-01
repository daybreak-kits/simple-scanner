"""PostgreSQL 探测：SSLRequest / StartupMessage 探测。

PG 服务端不主动问候。发 8 字节 SSLRequest（长度 8 + 魔数 80877103），
服务端回单字节 'S'（支持 SSL）或 'N'（不支持）——两者都证明是 PG。
"""

import struct

TRANSPORT = 'tcp'
PROTOCOL = 'postgresql'
ORDER = 20

SSL_REQUEST = struct.pack('!ii', 8, 80877103)  # len=8, magic


def probe(ctx):
    resp = ctx.send_recv(SSL_REQUEST, read=16)
    if resp[:1] in (b'S', b'N'):
        return 'SSLRequest -> {}'.format(resp[:1].decode()), set()
    return None
