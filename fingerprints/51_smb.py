"""SMB 探测：SMB1/SMB2 negotiate。

响应特征（MS-SMB2 2.2.1.1 / MS-SMB1 2.2.3.1）：
- SMB2 响应头固定以 4 字节协议 ID 开头：0xfe 'SMB'；
- SMB1 响应头以 0xff 'SMB' 开头（0xff 为 RFU 填充位标记）。
判据 = resp[:4] in (b'\\xfeSMB', b'\\xffSMB')。
顺序：先发 SMB2（现代服务器默认），无响应再发 SMB1（老 Samba/Windows 2003）。
依据：Microsoft Open Specifications（MS-SMB2/MS-SMB1），协议魔数是公开硬编码。
"""

import struct

TRANSPORT = 'tcp'
PROTOCOL = 'smb'
ORDER = 31  # 强特征：SMB 协议魔数是硬证据

# SMB2 NEGOTIATE 请求（64 字节头 + 36 字节体）
_SMB2_NEGOTIATE = (
    b'\xfeSMB\x40'                       # ProtocolId + StructureSize=64
    + struct.pack('<H', 0)               # CreditCharge
    + struct.pack('<I', 0)               # Reserved/ChannelSequence
    + struct.pack('<H', 0)               # Command = NEGOTIATE(0)
    + struct.pack('<H', 1)               # CreditRequest
    + struct.pack('<I', 0)               # Flags
    + struct.pack('<I', 0)               # NextCommand
    + struct.pack('<Q', 0)               # MessageId
    + struct.pack('<I', 0)               # Reserved
    + struct.pack('<I', 0)               # TreeId
    + struct.pack('<Q', 0)               # SessionId
    + b'\x00' * 16                       # Signature
    + struct.pack('<H', 36)              # StructureSize of body
    + struct.pack('<H', 2)               # DialectCount
    + struct.pack('<H', 1)               # SecurityMode = SIGNING_ENABLED
    + struct.pack('<H', 0)               # Reserved
    + struct.pack('<I', 0x00000001)      # Capabilities (SMB2_GLOBAL_CAP_DFS)
    + b'\x00' * 16                       # ClientGuid
    + struct.pack('<H', 0)               # NegotiateContextOffset(0 = none)
    + struct.pack('<H', 0)               # NegotiateContextCount
    + struct.pack('<H', 0)               # Reserved
    + struct.pack('<H', 0x0210)          # dialect: SMB 2.1
)

# SMB1 NEGOTIATE 请求（32 字节头，WordCount=0，1 个 dialect: NT LM 0.12）
_SMB1_NEGOTIATE = (
    b'\xffSMB\x72'                       # ProtocolId + Command = SMB_COM_NEGOTIATE(0x72)
    + struct.pack('<I', 0)               # Status
    + struct.pack('<H', 0)               # Flags
    + struct.pack('<H', 0x0001)          # Flags2
    + struct.pack('<H', 0)               # PIDHigh
    + b'\x00' * 8                        # SecurityFeatures(sig)
    + struct.pack('<H', 0)               # Reserved
    + struct.pack('<H', 0)               # TID
    + struct.pack('<H', 0)               # PIDLow
    + struct.pack('<H', 0)               # UID
    + struct.pack('<H', 0)               # MID
    + b'\x00'                            # WordCount=0
    + struct.pack('<H', 2)               # ByteCount=2
    + b'\x02\x02'                        # Dialect: NT LM 0.12
)


def probe(ctx):
    resp = ctx.send_recv(_SMB2_NEGOTIATE, read=256)
    if resp[:4] == b'\xfeSMB':
        return 'SMB2 negotiate -> \\xfeSMB', set()
    resp = ctx.send_recv(_SMB1_NEGOTIATE, read=256)
    if resp[:4] == b'\xffSMB':
        return 'SMB1 negotiate -> \\xffSMB', set()
    return None