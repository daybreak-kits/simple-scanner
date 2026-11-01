"""MSSQL(TDS) 探测：PreLogin 报文（MS-TDS §2.2.6.6）。

响应特征：服务器回 PreLogin 响应，TDS 报文头 type=0x04（TABULAR_RESULT/PRELOGIN 响应），
status=0x01（EOM），随后是 option 列表；响应中至少含版本 option（token 0x00）。
判据 = resp[0] == 0x04 和 resp[1] & 0x01（响应头 + EOM），且 resp 前部含 option token 0x00。
依据：MS-TDS PreLogin 报文结构（请求/响应 option 格式一致）。
SQL Server 还会在 PreLogin 响应里带版本号，如 0xe0 0x00（SQL2019）——但只凭 token 0x00 已足够。
"""

TRANSPORT = 'tcp'
PROTOCOL = 'mssql'
ORDER = 37  # 强特征：TDS PreLogin option 结构是硬证据

# TDS 7.4 PreLogin 请求（type=0x12 PRELOGIN, status=0x01 EOM,
# 之后 1 字节 protocol version（这里 0x00 表示 7.0/7.1 兼容，会被 SQL Server 接受）
_PRELOGIN = (
    b'\x12\x01'          # type=0x12 PRELOGIN, status=0x01 (EOM)
    b'\x00\x31'          # length=0x31 (49)
    b'\x00\x00'          # SPID
    b'\x01\x00'          # PacketID=1, Window=0
    # option 列表：token(1) + offset(2, LE) + length(2, LE)
    b'\x00\x00\x00\x04'  # 0=VERSION, offset=0, len=4
    b'\x01\x00\x08\x01'  # 1=ENCRYPTION, offset=8, len=1
    b'\x02\x00\x0d\x00'  # 2=INSTOPT, offset=13, len=0
    b'\xff'              # 0xff TERMINATOR
    b'\x0e\x00\x00\x00'  # VERSION data: 0x0e (MSSQL2016/2008R2-), 0x00 ...
    b'\x00'              # ENCRYPTION data: 0=ENCRYPT_OFF
)


def probe(ctx):
    resp = ctx.send_recv(_PRELOGIN, read=512)
    if len(resp) >= 10 and resp[0] == 0x04 and (resp[1] & 0x01):
        # PreLogin 响应 option 列表以 token 0x00(VERSION) 或 0xff 终止；总有 version option
        if b'\x00\x00\x00\x06' in resp[8:32] or resp[8] in (0x00, 0x01, 0x02, 0xff):
            return 'TDS PreLogin response -> {}'.format(resp[:24].hex()), set()
    return None