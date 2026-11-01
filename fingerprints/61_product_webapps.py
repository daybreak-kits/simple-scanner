"""L3 产品指纹：通用 Web 应用（GitLab / Jenkins / Confluence / Jira / Grafana /
Kibana / Nacos / Druid / Spring Boot Actuator / phpMyAdmin / WordPress /
Tomcat Manager / WebLogic / JBoss / New API）。

与 10_http.py 的分工：那边只读 `Server` 响应头，而现代应用普遍把 Server 头删掉或
改成反向代理的名字（nginx 后面挂 GitLab，Server 只有 nginx）。本文件用
**响应头 / cookie / 路径 / 正文 / 跳转** 四类信号补位
（research/fingerprint-best-practices.md §5.1）。

成本控制：与 60_product_cn_oa.py 同款——**所有产品共享一轮请求**。
MENU 有序，常态上限 MAX_REQ=5；某产品定案后其专属路径跳过；
仅在已出现该产品弱线索时放宽到 HARD_MAX=7。
L3 总闸门与 60_ 共享（挂在 ctx 上），所以两个文件加起来也不会叠成 2 倍耗时。

误报纪律：裸词一律不单独定案。
  - "GitLab" 单独出现不够（博客文章会提），要 meta/专属路径/品牌+登录页共现；
  - "login" / "admin" / "dashboard" 这类通用词不进任何规则；
  - Spring Boot 只认 actuator 的 `_links` JSON 结构，不认正文里的 "spring" 字样
    （"spring" 在电商/季节类页面里满地都是）。
"""

import re
import time

TRANSPORT = 'tcp'
LAYER = 'L3'
ORDER = 61        # 60 之后，仍属 L3

READ = 16384
MAX_REQ = 5
HARD_MAX = 7
L3_BUDGET = 2.2   # 与 60_product_cn_oa.py 同值：两个文件共享同一个 deadline

# 有序路径菜单。'/'(万能) 与 '/login'(多产品共用登录入口) 打头，性价比最高。
MENU = [
    '/',                        # 响应头/cookie/正文/跳转 一次全拿
    '/login',                   # Grafana / Jenkins / 各类后台共用入口
    '/users/sign_in',           # GitLab 专属登录页（含 gitlab-version meta）
    '/wp-login.php',            # WordPress 专属登录页
    '/nacos/',                  # Nacos 控制台
    '/druid/index.html',        # 阿里 Druid 监控台
    '/actuator',                # Spring Boot Actuator
    '/manager/html',            # Tomcat Manager
    '/console/login/LoginForm.jsp',   # WebLogic 控制台
    '/jmx-console/',            # JBoss / WildFly
    '/phpmyadmin/',             # phpMyAdmin
]

PATH_OWNERS = {
    '/users/sign_in': ('gitlab',),
    '/wp-login.php': ('wordpress',),
    '/nacos/': ('nacos',),
    '/druid/index.html': ('druid',),
    '/actuator': ('spring-boot',),
    '/manager/html': ('tomcat',),
    '/console/login/LoginForm.jsp': ('weblogic',),
    '/jmx-console/': ('jboss',),
    '/phpmyadmin/': ('phpmyadmin',),
}


# ---------------------------------------------------------------- HTTP 小工具
class _Resp:
    __slots__ = ('status', 'headers', 'body', 'path')

    def __init__(self, status, headers, body, path=''):
        self.status = status
        self.headers = headers
        self.body = body
        self.path = path


def _dechunk(body):
    out, i = [], 0
    try:
        while True:
            j = body.index(b'\r\n', i)
            n = int(body[i:j].split(b';')[0], 16)
            if n == 0:
                break
            out.append(body[j + 2:j + 2 + n])
            i = j + 2 + n + 2
        return b''.join(out)
    except (ValueError, IndexError):
        return body


def _parse(raw, path=''):
    head, _, body = raw.partition(b'\r\n\r\n')
    lines = head.split(b'\r\n')
    status = 0
    first = lines[0] if lines else b''
    if first.startswith(b'HTTP/'):
        try:
            status = int(first.split()[1])
        except (IndexError, ValueError):
            status = 0
    headers = {}
    for line in lines[1:]:
        name, sep, value = line.partition(b':')
        if not sep:
            continue
        headers[name.strip().lower().decode('latin-1')] = value.strip().decode('latin-1')
    if 'chunked' in headers.get('transfer-encoding', '').lower():
        body = _dechunk(body)
    return _Resp(status, headers, body, path)


def _http_get(ctx, scheme, path, deadline):
    if time.time() > deadline:
        return None
    host_hdr = ctx.host if ctx.port in (80, 443) else '{}:{}'.format(ctx.host, ctx.port)
    req = ('GET {} HTTP/1.1\r\nHost: {}\r\n'
           'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n'
           'Accept: text/html,application/json,*/*\r\n'
           'Connection: close\r\n\r\n').format(path, host_hdr).encode('latin-1', 'replace')
    if scheme == 'https':
        ok, raw = ctx.tls_recv(req, read=READ)
        if not ok:
            return None
    else:
        raw = ctx.send_recv(req, read=READ)
    if not raw:
        return None
    return _parse(raw, path)


def _deadline(ctx):
    """与 60_ 共享同一个 L3 总闸门（detect() 把同一个 ctx 传给每个 L3 模块）。"""
    d = getattr(ctx, '_l3_deadline', None)
    if d is None:
        d = time.time() + L3_BUDGET
        try:
            setattr(ctx, '_l3_deadline', d)
        except AttributeError:
            pass
    return d


# ---------------------------------------------------------------- 匹配原语
def _has(body, needle):
    return bool(body) and needle.encode('utf-8', 'ignore').lower() in body.lower()


def _residual(r):
    """剔除「路径回显」后的正文。

    实测踩到的坑：Tomcat/nginx 的 404 页会回显请求 URI——
        The requested resource [/druid/index.html] is not available
    于是**不存在的** /druid/index.html 会让「正文含 druid」成立，造成误报。
    删掉本请求路径后再匹配：真产品页里品牌名在 title/链接/JS 里出现多次，删掉路径
    仍然命中；纯回显的 404 删掉后就什么都不剩。
    """
    if not r.body:
        return b''
    body = r.body
    path = r.path or ''
    if not path or path == '/':
        return body
    low = body.lower()
    for v in sorted({path, path.lstrip('/')}, key=len, reverse=True):
        vb = v.encode('latin-1', 'replace').lower()
        if not vb:
            continue
        start = 0
        while True:
            i = low.find(vb, start)
            if i < 0:
                break
            body = body[:i] + body[i + len(vb):]
            low = body.lower()
            start = i
    return body


def _any_body(pages, *needles):
    """任一页面（剔除路径回显后）正文同时含 needles 全部。"""
    for r in pages.values():
        body = _residual(r)
        if all(_has(body, n) for n in needles):
            return True
    return False


def _hdr(r, name):
    return r.headers.get(name, '') if r else ''


def _any_hdr(pages, name, needle):
    needle = needle.lower()
    return any(needle in _hdr(r, name).lower() for r in pages.values())


def _cookie(pages, name):
    name = name.lower()
    return any((name + '=') in _hdr(r, 'set-cookie').lower() for r in pages.values())


def _path_body(pages, path, *needles):
    """该路径返回 200/401/403 且正文（剔除路径回显后）含 needles 全部。"""
    r = pages.get(path)
    if r is None or r.status not in (200, 401, 403):
        return False
    body = _residual(r)
    return all(_has(body, n) for n in needles)


def _is_json(r):
    return 'json' in _hdr(r, 'content-type').lower()


# ---------------------------------------------------------------- 指纹规则表
RULES = [
    # ---------------- GitLab ----------------
    # /users/sign_in 页面带 <meta content="x.y.z" name="gitlab-version">；旧版还有
    # "GitLab Community Edition" / gon.gitlab_url 的 JS 变量。
    ('gitlab', [
        ('strong', '/users/sign_in 含 gitlab-version meta',
         lambda p: _path_body(p, '/users/sign_in', 'gitlab-version')),
        ('strong', '正文含 gon.gitlab_url / GitLab Community Edition',
         lambda p: _any_body(p, 'gon.gitlab_url') or _any_body(p, 'gitlab community edition')
                   or _any_body(p, 'gitlab enterprise edition')),
        ('strong', '/users/sign_in 200 且含 gitlab 品牌',
         lambda p: _path_body(p, '/users/sign_in', 'gitlab')),
        ('weak', 'cookie _gitlab_session',
         lambda p: _cookie(p, '_gitlab_session')),
        ('weak', '正文含 gitlab 品牌串',
         lambda p: _any_body(p, 'gitlab')),
    ]),

    # ---------------- Jenkins ----------------
    # Jenkins 每个响应都带 X-Jenkins: <version>（官方 Jenkins 头，最难伪造）。
    ('jenkins', [
        ('strong', '响应头 X-Jenkins',
         lambda p: any('x-jenkins' in r.headers for r in p.values())),
        ('strong', '响应头 X-Hudson（Jenkins 前身）',
         lambda p: any('x-hudson' in r.headers for r in p.values())),
        ('strong', '/login 200 且含 Jenkins 品牌 + from 参数表单',
         lambda p: _path_body(p, '/login', 'jenkins')),
        ('weak', '正文含 jenkins 品牌串', lambda p: _any_body(p, 'jenkins')),
    ]),

    # ---------------- Confluence ----------------
    # 每个响应带 X-Confluence-Request-Time；页面 meta 有 ajs-version-number。
    ('confluence', [
        ('strong', '响应头 X-Confluence-Request-Time',
         lambda p: any('x-confluence-request-time' in r.headers for r in p.values())),
        ('strong', '正文含 ajs-version-number + confluence 品牌',
         lambda p: _any_body(p, 'ajs-version-number', 'confluence')),
        ('weak', '正文含 confluence 品牌串', lambda p: _any_body(p, 'confluence')),
    ]),

    # ---------------- Jira ----------------
    # 与 Confluence 同源（Atlassian），同样有 ajs-version-number，需 ajs 之外再要 jira 标识。
    ('jira', [
        ('strong', '正文含 ajs-version-number + jira 品牌',
         lambda p: _any_body(p, 'ajs-version-number', 'jira')),
        ('strong', '响应头 X-AUSERNAME（Jira 登录态头）',
         lambda p: any('x-ausername' in r.headers for r in p.values())),
        ('weak', '正文含 jira 品牌串', lambda p: _any_body(p, 'jira')),
    ]),

    # ---------------- Grafana ----------------
    # /login 页面是 Angular 应用，带 <grafana-app> 自定义元素 / public/build 资源。
    ('grafana', [
        ('strong', '/login 含 grafana-app 或 public/build/grafana',
         lambda p: _path_body(p, '/login', 'grafana-app')
                   or _path_body(p, '/login', 'public/build/grafana')),
        ('strong', '正文含 grafanaBootData（Grafana 前端引导变量）',
         lambda p: _any_body(p, 'grafanabootdata')),
        ('weak', '正文含 grafana 品牌串', lambda p: _any_body(p, 'grafana')),
    ]),

    # ---------------- Kibana ----------------
    # Kibana 每个响应带 kbn-name / kbn-version 头（7.x 起）。
    ('kibana', [
        ('strong', '响应头 kbn-name / kbn-version',
         lambda p: any('kbn-name' in r.headers or 'kbn-version' in r.headers for r in p.values())),
        ('weak', '正文含 kibana 品牌串', lambda p: _any_body(p, 'kibana')),
    ]),

    # ---------------- Nacos ----------------
    ('nacos', [
        ('strong', '/nacos/ 含 console-ui 或 Nacos 标题',
         lambda p: _path_body(p, '/nacos/', 'console-ui')
                   or _path_body(p, '/nacos/', '<title>nacos')),
        ('weak', '正文含 nacos 品牌串', lambda p: _any_body(p, 'nacos')),
    ]),

    # ---------------- 阿里 Druid 监控台 ----------------
    ('druid', [
        ('strong', '/druid/index.html 含 Druid Stat Index 标题',
         lambda p: _path_body(p, '/druid/index.html', 'druid stat index')),
        ('strong', '正文含 <title>Druid</title> 且含 druid 资源路径',
         lambda p: _any_body(p, '<title>druid</title>', 'druid/')),
        ('weak', '正文含 druid 品牌串', lambda p: _any_body(p, 'druid')),
    ]),

    # ---------------- Spring Boot Actuator ----------------
    # /actuator 回 HAL JSON：{"_links":{"self":...,"health":...}}。
    # 只认结构，不认正文里的 "spring" 字样（那词太通用）。
    ('spring-boot', [
        ('strong', '/actuator 返回 JSON 且含 _links 与 health',
         lambda p: (lambda r: r is not None and r.status == 200 and _is_json(r)
                    and _has(r.body, '_links') and _has(r.body, 'health'))(p.get('/actuator'))),
        ('strong', '/actuator/env 或 /actuator/info 的 JSON 特征',
         lambda p: _path_body(p, '/actuator', '"activeprofiles"')
                   or _path_body(p, '/actuator', '"spring"')),
        ('weak', '响应头 X-Application-Context（Spring Boot 1.x）',
         lambda p: any('x-application-context' in r.headers for r in p.values())),
    ]),

    # ---------------- phpMyAdmin ----------------
    # 登录页带 pma_ 系列 cookie / pma_ 前缀 JS 变量，标题 "phpMyAdmin"。
    ('phpmyadmin', [
        ('strong', '/phpmyadmin/ 含 phpMyAdmin 品牌',
         lambda p: _path_body(p, '/phpmyadmin/', 'phpmyadmin')),
        ('strong', 'cookie 前缀 pma_', lambda p: _cookie(p, 'pma_lang') or _cookie(p, 'pma_mcrypt_iv')),
        ('weak', '正文含 pma_ 前缀变量', lambda p: _any_body(p, 'pma_')),
    ]),

    # ---------------- WordPress ----------------
    # wp-content / wp-includes 是 WP 的固定目录结构；wp-login.php 是固定入口。
    ('wordpress', [
        ('strong', '/wp-login.php 200 且含 wp- 资源引用',
         lambda p: _path_body(p, '/wp-login.php', 'wp-login')
                   or _path_body(p, '/wp-login.php', 'wp-content')),
        ('strong', '正文含 wp-content 与 wp-includes（WP 目录结构）',
         lambda p: _any_body(p, 'wp-content', 'wp-includes')),
        ('weak', '正文含 wp-content', lambda p: _any_body(p, 'wp-content')),
    ]),

    # ---------------- Tomcat ----------------
    # 默认首页标题 "Apache Tomcat/8.5.19"；Manager 页标题 "Tomcat Web Application Manager"。
    ('tomcat', [
        ('strong', '正文含 Tomcat Web Application Manager',
         lambda p: _any_body(p, 'tomcat web application manager')),
        ('strong', '正文含 Apache Tomcat/ 版本标题',
         lambda p: _any_body(p, 'apache tomcat/') or _any_body(p, '<title>tomcat')),
        ('strong', '/manager/html 返回 401 且含 tomcat manager 域',
         lambda p: (lambda r: r is not None and r.status == 401
                    and 'tomcat manager' in _hdr(r, 'www-authenticate').lower())(p.get('/manager/html'))),
        ('weak', '正文含 tomcat 品牌串', lambda p: _any_body(p, 'tomcat')),
    ]),

    # ---------------- WebLogic ----------------
    ('weblogic', [
        ('strong', '正文含 Oracle WebLogic / WebLogic Server 品牌',
         lambda p: _any_body(p, 'oracle weblogic') or _any_body(p, 'weblogic server')),
        ('strong', '/console/login/LoginForm.jsp 含 weblogic',
         lambda p: _path_body(p, '/console/login/LoginForm.jsp', 'weblogic')),
        ('weak', '正文含 weblogic 品牌串', lambda p: _any_body(p, 'weblogic')),
    ]),

    # ---------------- JBoss / WildFly ----------------
    ('jboss', [
        ('strong', '正文含 JBoss 品牌 + 管理控制台特征',
         lambda p: _any_body(p, 'jboss', 'jmx-console')
                   or _any_body(p, 'jboss', 'web-console')),
        ('strong', '正文含 WildFly 品牌', lambda p: _any_body(p, 'wildfly')),
        ('weak', '正文含 jboss 品牌串', lambda p: _any_body(p, 'jboss')),
    ]),

    # ---------------- New API（one-api 系网关，实测靶场 :3000）----------------
    # 每个响应带 X-New-Api-Version / X-Oneapi-Request-Id，是网关自己加的头。
    ('new-api', [
        ('strong', '响应头 X-New-Api-Version',
         lambda p: any('x-new-api-version' in r.headers for r in p.values())),
        ('strong', '响应头 X-Oneapi-Request-Id',
         lambda p: any('x-oneapi-request-id' in r.headers for r in p.values())),
        ('weak', '正文含 <title>New API</title>', lambda p: _any_body(p, '<title>new api</title>')),
    ]),
]


# ---------------------------------------------------------------- 判定
def _evaluate(pages):
    products, notes, scores = set(), [], {}
    for product, rules in RULES:
        strong = weak = 0
        hits = []
        for strength, desc, fn in rules:
            try:
                ok = bool(fn(pages))
            except Exception:
                ok = False
            if ok:
                hits.append(desc)
                if strength == 'strong':
                    strong += 1
                else:
                    weak += 1
        scores[product] = (strong, weak)
        if strong or weak >= 2:
            products.add(product)
            notes.append('{} <- {}'.format(product, ', '.join(hits)))
    return products, notes, scores


def probe(ctx, scheme='http'):
    """L3 入口：只补 products，不改 protocol。返回 (evidence, products) 或 None。"""
    deadline = _deadline(ctx)
    pages = {}

    for path in MENU:
        products, _, scores = _evaluate(pages)
        owners = PATH_OWNERS.get(path, ())
        if owners and all(o in products for o in owners):
            continue
        hinted = any(scores.get(o, (0, 0))[1] > 0 for o in owners)
        cap = HARD_MAX if hinted else MAX_REQ
        if len(pages) >= cap or time.time() > deadline:
            break
        resp = _http_get(ctx, scheme, path, deadline)
        if resp is None:
            if not pages:
                return None
            continue
        pages[path] = resp

    products, notes, _ = _evaluate(pages)
    if not products:
        return None
    return '; '.join(notes)[:400], products
