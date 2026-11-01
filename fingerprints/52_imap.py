"""IMAP 探测：CAPABILITY 命令（RFC 3501 §6.1.1）。

响应特征：服务器回未标记响应 `* CAPABILITY IMAP4rev1 ...`（RFC 3501 固定格式），
或至少 `* OK ...`。判据 = 响应含 `* CAPABILITY` 或含 `* OK ` 且含 `IMAP` 字样。
依据：RFC 3501 CAPABILITY 命令定义（IMAP 在未登录态也允许 CAPABILITY）。
"""

TRANSPORT = 'tcp'
PROTOCOL = 'imap'
ORDER = 32  # 强特征：CAPABILITY 响应结构是硬证据

_CAPABILITY = b'A001 CAPABILITY\r\n'


def probe(ctx):
    resp = ctx.send_recv(_CAPABILITY, read=4096)
    if not resp:
        return None
    head = resp[:4096].lower()
    if b'* capability' in head or (b'* ok' in head and b'imap' in head):
        return 'IMAP CAPABILITY -> {}'.format(resp[:80].decode('latin-1', 'replace').strip()), set()
    return None