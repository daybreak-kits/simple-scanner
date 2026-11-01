"""HTTP / HTTPS 探测。

关键顺序（实测教训，v1 缺陷）：**必须先试 TLS 再发明文 HTTP**。
明文 GET 打到 TLS 端口时，Cloudflare 会回 `HTTP/1.1 400 Bad Request`，
按响应头判定会把 https 误判为 http。

依据 research/fingerprint-best-practices.md §4.1。
"""

import re

TRANSPORT = 'tcp'
PROTOCOL = 'http'
ORDER = 20  # 强特征：HTTP 响应头是硬证据

GET = b'GET / HTTP/1.0\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\n\r\n'
STATUS = re.compile(rb'^HTTP/\d\.\d (\d{3})')
SERVER = re.compile(rb'\r\n[Ss]erver:\s*([^\r\n]{1,80})')

# Server 头 → 产品标签（nmap/httpx 同款思路，只取确定性高的）
SERVER_PRODUCTS = [
    (re.compile(rb'nginx', re.I), 'nginx'),
    (re.compile(rb'[Aa]pache', re.I), 'apache-httpd'),
    (re.compile(rb'Microsoft-IIS', re.I), 'iis'),
    (re.compile(rb'[Tt]omcat|[Cc]oyote', re.I), 'tomcat'),
    (re.compile(rb'[Jj]etty', re.I), 'jetty'),
    (re.compile(rb'[Uu]ndertow', re.I), 'undertow'),
    (re.compile(rb'[Ww]erkzeug', re.I), 'werkzeug'),
    (re.compile(rb'[Pp]HP', re.I), 'php'),
    (re.compile(rb'[Ee]xpress', re.I), 'nodejs'),
    (re.compile(rb'[Gg]unicorn', re.I), 'gunicorn'),
    (re.compile(rb'[Cc]addy', re.I), 'caddy'),
    (re.compile(rb'[Oo]pen[Rr]esty', re.I), 'openresty'),
    (re.compile(rb'[Ss]olr', re.I), 'solr'),
    (re.compile(rb'[Aa]ctive[Mm][Qq]', re.I), 'activemq'),
    (re.compile(rb'[Gg]it[Ll]ab', re.I), 'gitlab'),
    (re.compile(rb'[Cc]onfluence', re.I), 'confluence'),
    (re.compile(rb'[Jj]ira', re.I), 'jira'),
    (re.compile(rb'[Gg]rafana', re.I), 'grafana'),
    (re.compile(rb'[Kk]ibana', re.I), 'kibana'),
    (re.compile(rb'[Ee]lastic', re.I), 'elasticsearch'),
    (re.compile(rb'[Rr]abbit[Mm][Qq]', re.I), 'rabbitmq'),
    (re.compile(rb'[Zz]abbix', re.I), 'zabbix'),
    (re.compile(rb'[Nn]acos', re.I), 'nacos'),
    (re.compile(rb'[Dd]ruid', re.I), 'druid'),
]


def _products(head: bytes):
    """从**响应头**提取产品标签。

    审计 S1（2026-10-30）：原实现对整个 resp[:2048]（含正文）匹配产品词，
    正文里出现一个普通词（如 "Apache Tomcat"）就会让产品集非空 → 取消 fail-open
    保护 → 472 个带 product: 标签的插件（wordpress 340 个等）整批 SKIP。
    机制级修法：产品身份只能来自 Server / X-Powered-By 这类头字段，
    正文是攻击者可控内容，不能当产品证据。
    """
    # 只取头部（到空行为止）；无空行则整段当头部（响应不完整）
    header_blob = head.split(b'\r\n\r\n', 1)[0]
    out = set()
    for pattern, name in SERVER_PRODUCTS:
        if pattern.search(header_blob):
            out.add(name)
    return out


def probe(ctx):
    host = ctx.host.encode('latin-1', 'replace')
    payload = GET.replace(b'{host}', host)

    # 1) 先试 TLS：成功且能拿到 HTTP 响应 = https（最高置信度）
    is_tls, tls_resp = ctx.tls_recv(payload)
    if is_tls:
        m = STATUS.search(tls_resp or b'')
        if m:
            head = (tls_resp or b'')[:2048]
            sm = SERVER.search(head)
            evidence = 'TLS + HTTP/{} {}'.format(
                m.group(0)[5:8].decode('latin-1'), (sm.group(1).decode('latin-1') if sm else 'no-server-header'))
            # 3 元组：TLS 上的 HTTP 是 https，与明文 http 区分（插件的 ssl_protocol 需要它）
            return 'https', evidence, _products(head)
        # TLS 成功但没有 HTTP 响应 → 协议**未确认**。这是 fail-open 红线：
        # TLS 只能证明 transport 层是 TLS，对「是否 HTTP」零证据，不能当「已确认非 http」用。
        # 若返回 tls/high，慢速 TLS 服务（握手成功但响应 >超时）会让所有 http 插件被 SKIP → 真实漏报。
        # 审计 S1（2026-10-30）：返回 None 保持 unknown（fail-open 全跑），证据留给人工核验。
        return None

    # 2) 明文 HTTP
    resp = ctx.send_recv(payload)
    m = STATUS.search(resp or b'')
    if not m:
        return None
    head = resp[:2048]
    sm = SERVER.search(head)
    evidence = 'HTTP/{} {}'.format(
        m.group(0)[5:8].decode('latin-1'), (sm.group(1).decode('latin-1') if sm else 'no-server-header'))
    return 'http', evidence, _products(head)
