"""Memcached 探测：text protocol `version` 命令。

响应特征：memcached text 协议对 `version\\r\\n` 回 `VERSION 1.6.x\\r\\n`（ASCII 明文）。
判据 = 响应以 `VERSION ` 开头（RFC 全公开；memcached protocol.txt 文档）。
binary 协议（0x80 头）不适用此命令，会回错误头——本探测器只认 text 协议。
"""

TRANSPORT = 'tcp'
PROTOCOL = 'memcached'
ORDER = 38  # 强特征：VERSION 响应行

_VERSION = b'version\r\n'


def probe(ctx):
    resp = ctx.send_recv(_VERSION, read=128)
    if resp.startswith(b'VERSION '):
        return 'memcached version -> {}'.format(resp[:60].decode('latin-1', 'replace').strip()), set()
    return None