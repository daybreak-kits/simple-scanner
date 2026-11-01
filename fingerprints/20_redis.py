"""Redis 探测：PING → +PONG。

端口无关（可在 6379 或任意端口）。先被动等 banner（Redis 对非法命令会回 -ERR），
再发 PING 确认。依据 research/fingerprint-best-practices.md §2.1（probe 用新连接）。
"""

TRANSPORT = 'tcp'
PROTOCOL = 'redis'
ORDER = 20

PING = b'PING\r\n'


def probe(ctx):
    resp = ctx.send_recv(PING, read=256)
    if resp.startswith(b'+PONG'):
        return 'PING -> +PONG', set()
    # 需要认证时回 -NOAUTH / -ERR ... NOAUTH
    if resp.startswith(b'-NOAUTH') or b'NOAUTH' in resp[:128]:
        return 'PING -> {}'.format(resp[:60].decode('latin-1', 'replace').strip()), set()
    return None
