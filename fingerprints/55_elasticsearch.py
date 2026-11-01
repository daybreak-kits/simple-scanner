"""Elasticsearch 探测：HTTP GET / + JSON 根信息（ES Info API）。

响应特征：ES 7.14+ 一定回响应头 `X-elastic-product: Elasticsearch`（官方强制加的防误报头）；
旧版根路径回 JSON：`{"name":"...","cluster_name":"...","cluster_uuid":"...","version":{...},"tagline":"You Know, for Search"}`。
判据 = (响应头含 X-elastic-product: Elasticsearch) 或 (正文含 "cluster_name" 且含 "tagline" 且是 JSON)。
依据：Elasticsearch 官方 Info API 文档（GET /）；X-elastic-product 头自 7.14 起所有版本都返回。
"""

import re

TRANSPORT = 'tcp'
PROTOCOL = 'elasticsearch'
ORDER = 35  # 强特征：X-elastic-product 头 / cluster JSON 是硬证据

_GET = b'GET / HTTP/1.0\r\n\r\n'
_ELASTIC_HEADER = re.compile(rb'[Xx]-[Ee]lastic-[Pp]roduct:\s*Elasticsearch')


def probe(ctx):
    resp = ctx.send_recv(_GET, read=4096)
    if not resp:
        return None
    if _ELASTIC_HEADER.search(resp):
        return 'ES Info -> X-elastic-product: Elasticsearch', {'elasticsearch'}
    if b'"cluster_name"' in resp and b'"tagline"' in resp and resp.lstrip().startswith(b'{'):
        return 'ES Info -> cluster JSON {}'.format(resp[:60].decode('latin-1', 'replace').strip()), {'elasticsearch'}
    return None