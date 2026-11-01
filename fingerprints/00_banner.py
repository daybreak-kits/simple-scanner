"""被动 banner 识别：不发任何字节，只等对端先说话。

覆盖主动问候的服务：SSH / FTP / SMTP / MySQL / PostgreSQL / Telnet / VNC / Redis(-ERR)。
依据：nmap NULL probe（research/fingerprint-best-practices.md §2.1），但等 0.5s 而非 5s
——我们只认少数协议，不需要给 180 种留窗口（实测 SSH banner 0.05s 内到达）。
"""

import re

TRANSPORT = 'tcp'
ORDER = 0  # 强特征：命中即定案

# (正则, 协议标签, 产品名或 None)
SIGNATURES = [
    (re.compile(rb'^SSH-[\d.]+-'), 'ssh', None),
    (re.compile(rb'^220[\s\S]{0,40}(?:FTP|ftp)'), 'ftp', None),
    (re.compile(rb'^220[\s\S]{0,80}(?:SMTP|ESMTP|smtp|esmtp|Mail)'), 'smtp', None),
    (re.compile(rb'^\d{1,2}\.\d{1,2}\.\d{1,2}[\w.-]*\x00'), 'mysql', None),  # MySQL 握手首包版本号
    (re.compile(rb'^RFB \d{3}\.\d{3}\n'), 'vnc', None),
    (re.compile(rb'^-ERR|^\$[\d-]+\r\n|^\*[\d-]+\r\n|^\+PONG'), 'redis', None),
    (re.compile(rb'^\+OK'), 'pop3', None),      # POP3 greeting；注意 IMAP 是 *OK，不能混
    (re.compile(rb'^\*OK'), 'imap', None),
    (re.compile(rb'^HTTP/\d\.\d \d{3}'), 'http', None),
    # MySQL / PostgreSQL / Mongo 由各自专用探测器负责（需主动握手）
]


def probe(ctx):
    banner = ctx.recv_passive(wait=0.5)
    if not banner:
        return None
    for pattern, protocol, product in SIGNATURES:
        if pattern.search(banner):
            text = banner[:120].decode('latin-1', 'replace').strip()
            # 3 元组：本模块自己识别协议（一份 banner 可能对应多种协议）
            return protocol, 'banner: {}'.format(text), ({product} if product else set())
    return None


def identify(banner: bytes):
    """给其它探测器复用：从一段 banner 里认协议。"""
    for pattern, protocol, product in SIGNATURES:
        if pattern.search(banner):
            return protocol, product
    return None, None
