"""POP3 探测：CAPA 命令（RFC 2449 §5）或 NOOP（RFC 1939 §6）。

响应特征：POP3 对 CAPA/NOOP 回 `+OK ...`（状态行 +OK 起始，RFC 1939 §6）。
判据 = 响应以 `+OK` 开头且不回 `* `（IMAP 未标记响应前缀）。
依据：RFC 1939（POP3 应答以 +OK/-ERR 开头）、RFC 2449 CAPA。
"""

TRANSPORT = 'tcp'
PROTOCOL = 'pop3'
ORDER = 33  # 强特征：+OK 状态行 + 非 IMAP 前缀

_NOOP = b'NOOP\r\n'


def probe(ctx):
    resp = ctx.send_recv(_NOOP, read=1024)
    if not resp:
        return None
    head = resp[:1024]
    if head.startswith(b'+OK') and not head.startswith(b'* '):
        return 'POP3 NOOP -> {}'.format(resp[:80].decode('latin-1', 'replace').strip()), set()
    return None