"""T3 (WebLogic) 探测：T3 协议头握手。

发 T3 协议头 + 最小序列化数据，WebLogic 回 `HELO:` 或 `LGIN:` 或异常头。
T3 在 7001/7002 常见，但**端口无关**——任何端口都可能。

依据：语料 supplement/CVE-2018-2628.py 已验证的 T3 握手序列。
"""

TRANSPORT = 'tcp'
PROTOCOL = 't3'
ORDER = 20

# WebLogic T3 协议头（语料插件里已验证）
T3_HEADER = bytes.fromhex(
    '7433'          # 't3'
    '2031322e322e310a'   # ' 12.2.1\n'
    '41534e310a'         # 'ASN1\n'
    '3139322e3136382e'   # '192.168.'
)
# 更可靠的做法：直接发 t3 + 版本 + 空序列化头
T3_PROBE = b't3 12.2.1\nASN1\n\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'


def probe(ctx):
    resp = ctx.send_recv(T3_PROBE, read=512)
    if not resp:
        return None
    head = resp[:64]
    if head.startswith(b'HELO:') or head.startswith(b'LGIN:') or b'HELO:' in head[:16]:
        return 'T3 handshake -> {}'.format(head[:40].decode('latin-1', 'replace').strip()), set()
    return None
