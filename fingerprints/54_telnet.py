r"""Telnet 探测：IAC 协商（RFC 854 §5）。

响应特征：服务器会对客户端的 IAC DO/WILL 协商回 IAC WILL(0xfb)/WONT(0xfc)/DO(0xfd)/DONT(0xfe)。
判据 = 响应前若干字节含 `\xff\xf[bcde]`（IAC + 协商命令）。
依据：RFC 854 选项协商机制；telnet 服务端在收到 IAC 后必须应答选项协商。
"""

TRANSPORT = 'tcp'
PROTOCOL = 'telnet'
ORDER = 34  # 强特征：IAC 协商字节序列

# IAC DO TERMINAL-TYPE(24) ; IAC DO NAWS(31) ; IAC WILL ECHO(1) ; IAC WILL SGA(3)
_IAC = b'\xff\xfd\x18' + b'\xff\xfd\x1f' + b'\xff\xfb\x01' + b'\xff\xfb\x03'


def probe(ctx):
    resp = ctx.send_recv(_IAC, read=512)
    if not resp:
        return None
    # 找一个 IAC 后跟协商命令（WILL/WONT/DO/DONT）
    for i in range(len(resp) - 1):
        if resp[i] == 0xff and resp[i + 1] in (0xfb, 0xfc, 0xfd, 0xfe):
            return 'Telnet IAC negotiation -> {}'.format(
                resp[:60].decode('latin-1', 'replace').strip()), set()
    return None