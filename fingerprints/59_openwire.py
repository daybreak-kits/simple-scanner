"""ActiveMQ OpenWire 探测。

响应特征：ActiveMQ OpenWire 连接建立后，服务端主动下发 WireFormatInfo 报文，
其载荷以 "ActiveMQ" 魔数开头（4 字节大端长度 + 命令类型 0x01 + 布尔 true(0x01) + "ActiveMQ"）。
实测（192.168.255.128:28162）首包：
  00 00 01 52 01 41 63 74 69 76 65 4d 51 ...
判据 = 响应前 64 字节含 b'ActiveMQ' 且 resp[0] == 0x00（4 字节大端长度前缀）。
依据：Apache ActiveMQ OpenWire 传输协议（WireFormatInfo 命令，magic "ActiveMQ"）。
"""

TRANSPORT = 'tcp'
PROTOCOL = 'activemq'
ORDER = 39  # 强特征：WireFormatInfo magic 是硬证据

# OpenWire 命令头：length(4, BE) + command type(1) + ... ，type 0x01 = WireFormatInfo
_WIRE_FORMAT_INFO = b'\x00\x00\x00\x0c\x01\x01ActiveMQ'


def probe(ctx):
    resp = ctx.recv_passive(wait=1.0)
    if resp and resp[:1] == b'\x00' and b'ActiveMQ' in resp[:64]:
        return 'ActiveMQ OpenWire WireFormatInfo (magic ActiveMQ)', {'activemq'}
    return None