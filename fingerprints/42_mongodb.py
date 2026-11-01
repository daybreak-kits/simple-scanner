"""MongoDB 探测：legacy OP_QUERY isMaster（协议版本 4.0 以下仍普遍支持）。

发 OP_QUERY {isMaster: 1}，响应含 36 字节头（含 replyTo）+ 文档。
现代 MongoDB（4.2+）仍兼容 legacy 首包。响应特征：opCode=OP_REPLY(1)。
"""

import struct

TRANSPORT = 'tcp'
PROTOCOL = 'mongodb'
ORDER = 20

# 标准 MongoDB legacy OP_QUERY isMaster（BSON: {isMaster: 1}）
# header(16) + flags(4) + ns(db.$cmd)\x00 + skip(4) + ret(4) + bson(13)
_REQ = (
    struct.pack('<iiii', 16 + 4 + 9 + 4 + 4 + 13, 1, 0, 2004)  # msgLen, requestID, 0, OP_QUERY
    + struct.pack('<i', 0)                                       # flags
    + b'admin.$cmd\x00'                                          # ns
    + struct.pack('<ii', 0, 1)                                   # skip, return
    + struct.pack('<i', 13) + b'\x10isMaster\x00\x01\x00\x00\x00\x00'  # {isMaster: 1}
)


def probe(ctx):
    resp = ctx.send_recv(_REQ, read=128)
    if len(resp) >= 20:
        op_code = struct.unpack('<i', resp[12:16])[0]  # OP_REPLY = 1
        if op_code == 1:
            return 'OP_QUERY isMaster -> OP_REPLY', set()
    return None
