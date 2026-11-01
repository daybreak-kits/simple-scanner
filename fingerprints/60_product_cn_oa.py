"""L3 产品指纹：中国企业 OA / 协同办公（泛微、致远、蓝凌、通达、万户、用友、金蝶）。

为什么单独一层：L2 的 10_http.py 只看 `Server` 响应头，而国产 OA 普遍改写/删除
Server 头，只能靠**路径 + 正文 + cookie + 跳转 Location** 判定
（research/fingerprint-best-practices.md §5.1 四类信号源里的前三类）。

成本控制（本文件的核心设计）：**所有产品共享一轮请求**。
不是「每个产品发 5 个请求」，而是共用一张有序路径菜单 MENU：
  - 常态上限 MAX_REQ=5 个请求；
  - 某产品的特征一旦确认，它专属的路径直接跳过，把配额让给还没定案的产品；
  - 只有已出现该产品**弱线索**时才允许追加，总上限 HARD_MAX=7。
实测 Tomcat 靶场（:18080）上 5 个请求、约 15ms 结束。

信号分级（避免单条弱特征误报，这是本文件最重要的约束）：
    strong = 1 条即定案 —— 厂商专属技术串（ecology_JSessionid / SEEYON-OA /
             KingdeeApp / MYOA / ezOFFICE / landray / eoffice / e-cology），
             或「专属路径 200 + 厂商 token」，或「厂商名 + 产品名」同页共现
    weak   = 需要 ≥2 条同时成立 —— 裸公司名（通达/用友/金蝶/致远/万户/蓝凌/泛微）、
             裸路径存在、裸通用词
裸公司名单独出现**绝不**定案：新闻页、招标公告里出现「金蝶」「用友」太常见了。

来源标注（逐条可复核）：
  [A] https://raw.githubusercontent.com/wudidike/pentest_skill/4bdfa952/references/
      dictionaries/chinese-srcfingerprints.md （声明改编自 src-hunter-skill, MIT）
  [B] https://github.com/zhaoxuya520/reverse-skill/blob/968caa39/.../chinese-srcfingerprints.md
      （同表的补充版：泛微 e-office / e-mobile、万户 ezEIP、用友 NCC）
  [C] https://github.com/ax1sX/SecurityList/blob/main/Java_OA/EcologyAudit.md
      （泛微 e-cology 深度指纹：Monitor.jsp 环境信息页、ecology_JSessionId、
        errorMsg: securityIntercept、login/Login.jsp?af=1 跳转）
  [T] 任务卡给出的线索（未经一手来源复核，只用于 weak 级）
"""

import time

TRANSPORT = 'tcp'
LAYER = 'L3'      # 缺省是 'L2'；不声明这一行第二阶段永远不会调用本模块
ORDER = 60        # L3 用 60 起，避开 L2 的 0-59

READ = 16384
MAX_REQ = 5       # 常态请求上限（一轮共享，不是每个产品）
HARD_MAX = 7      # 已有弱线索时的上限
# L3 全局预算：所有 L3 探测器（本文件 + 61_）共享一个 deadline，挂在 ctx 上。
# 为什么共享：detect() 把同一个 ctx 传给每个 L3 模块，若各自限时，慢目标上
# 2 个模块 × 各自超时会叠成 2 倍。共享后整段 L3 只有一个总闸门。
L3_BUDGET = 2.2   # 秒；单端点全部 L3 探测的总上限

MONITOR = '/security/monitor/Monitor.jsp'

# 有序路径菜单：按「该路径能定案的产品在别处有没有便宜信号」排序。
# 泛微 e-cology 的 Monitor.jsp 是 §5.2 里唯一被标为「最强 L3 指纹」的路径，排第一。
MENU = [
    '/',                                    # 万能：响应头 / 正文 / cookie / 跳转
    MONITOR,                                # 泛微 e-cology 环境信息泄露页 [C]
    '/seeyon/login.jsp',                    # 致远 [A]
    '/general/login/index.php',             # 通达 OA [A]
    '/sys/login/login.do',                  # 蓝凌 EKP [A]
    '/defaultroot/',                        # 万户 ezOFFICE [A]
    '/eoffice/',                            # 泛微 e-office [B]
    '/nc/servlet/',                         # 用友 NC [A]
    '/eas/',                                # 金蝶 EAS [A]
]

# 路径 -> 该路径只为这些产品服务（全部已确认就跳过，省配额）
PATH_OWNERS = {
    MONITOR: ('weaver-e-cology',),
    '/seeyon/login.jsp': ('seeyon',),
    '/general/login/index.php': ('tongda',),
    '/sys/login/login.do': ('landray-ekp',),
    '/defaultroot/': ('ezoffice',),
    '/eoffice/': ('weaver-e-office',),
    '/nc/servlet/': ('yonyou-nc',),
    '/eas/': ('kingdee',),
}


# ---------------------------------------------------------------- HTTP 小工具
class _Resp:
    """一条 HTTP 响应：状态码 + 小写头字典 + 正文（已尽力解 chunked）。"""

    __slots__ = ('status', 'headers', 'body', 'path')

    def __init__(self, status, headers, body, path=''):
        self.status = status
        self.headers = headers
        self.body = body
        self.path = path


def _dechunk(body):
    """解 Transfer-Encoding: chunked；失败就原样返回（关键字多半仍在首块里）。"""
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
    """取一个路径。scheme='https' 时走 tls_recv（每次新连接，nmap 同款原则）。"""
    if time.time() > deadline:
        return None
    host = ctx.host
    host_hdr = host if ctx.port in (80, 443) else '{}:{}'.format(host, ctx.port)
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


# ---------------------------------------------------------------- 特征匹配原语
def _has(body, needle):
    """正文是否含 needle。同时按 UTF-8 与 GBK 比对 —— 国产 OA 大量 GBK 页面。"""
    if not body or not needle:
        return False
    low = body.lower()
    for enc in ('utf-8', 'gbk'):
        try:
            nb = needle.encode(enc)
        except UnicodeEncodeError:
            continue
        if nb.lower() in low:
            return True
    return False


def _residual(r):
    """剔除「路径回显」后的正文。

    为什么必须做（实测踩到的坑）：Tomcat 的 404 页会回显请求 URI——
        The requested resource [/seeyon/login.jsp] is not available
    于是一个**不存在的** /seeyon/login.jsp 会让「正文含 seeyon」这条规则成立，
    把 :18080 的 Tomcat 误判成致远 OA（本仓库实测复现过）。
    同理 /druid/index.html、/nacos/ 的 404 也会互相污染。

    做法：把正文里出现的**本请求路径**（含去首斜杠、带引号/括号的变体）删掉再匹配。
    真产品页里产品名会在 title/链接/JS 里出现多次，删掉路径后仍然命中；
    纯回显的 404 删掉后就什么都不剩 —— 两者因此可分。
    """
    if not r.body:
        return b''
    body = r.body
    path = r.path or ''
    if not path or path == '/':
        return body            # 根路径：路径串就是 '/'，删了会把页面删没
    low = body.lower()
    variants = {path, path.lstrip('/')}
    for v in sorted(variants, key=len, reverse=True):
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


def _any_page(pages, fn):
    return any(fn(r) for r in pages.values())


def _any_body(pages, *needles):
    """任一页面（剔除路径回显后）正文同时含 needles 全部。"""
    for r in pages.values():
        body = _residual(r)
        if all(_has(body, n) for n in needles):
            return True
    return False


def _hdr(r, name):
    return r.headers.get(name, '') if r else ''


def _cookie(r, name):
    """Set-Cookie 里是否出现该 cookie 名（名字通常改不了，稳定度高于正文）。"""
    return (name.lower() + '=') in _hdr(r, 'set-cookie').lower()


def _loc(r):
    """跳转目标。OA 的根路径几乎都 302 到自己的登录页，这是最便宜的指纹。"""
    return _hdr(r, 'location')


def _loc_has(pages, frag):
    frag = frag.lower()
    return _any_page(pages, lambda r: frag in _loc(r).lower())


def _path_body(pages, path, *needles):
    """该路径返回 200/401/403 且正文（剔除路径回显后）含 needles 全部。

    401/403 也算：登录墙的拦截页同样带厂商痕迹。
    """
    r = pages.get(path)
    if r is None or r.status not in (200, 401, 403):
        return False
    body = _residual(r)
    return all(_has(body, n) for n in needles)


# ---------------------------------------------------------------- 指纹规则表
# (产品标签, [(强度, 说明, 判定函数), ...])
RULES = [
    # ---------------- 泛微 e-cology ----------------
    ('weaver-e-cology', [
        ('strong', 'cookie ecology_JSessionid [C]',
         lambda p: _any_page(p, lambda r: _cookie(r, 'ecology_JSessionid'))),
        ('strong', '响应头 errorMsg: securityIntercept（泛微安全拦截）[C]',
         lambda p: _any_page(p, lambda r: 'securityintercept' in _hdr(r, 'errormsg').lower())),
        ('strong', 'Monitor.jsp 200 且含 ecology/JVM 字样（环境信息泄露页）[C]',
         lambda p: _path_body(p, MONITOR, 'ecology') or _path_body(p, MONITOR, 'jvm')),
        ('strong', "跳转 login/Login.jsp?af=1（泛微拦截跳转）[C]",
         lambda p: _any_body(p, 'login/login.jsp?af=1')),
        ('strong', "正文含 e-cology 品牌串",
         lambda p: _any_body(p, 'e-cology')),
        ('strong', '跳转 /wui/index.html（泛微 E9 前端入口）[T]',
         lambda p: _loc_has(p, '/wui/index.html') or _loc_has(p, '/login/login.jsp')),
        ('weak', '正文含 ecology / weaver 字样',
         lambda p: _any_body(p, 'ecology') or _any_body(p, 'weaver')),
    ]),

    # ---------------- 泛微 e-office ----------------
    ('weaver-e-office', [
        ('strong', '正文含 eoffice 品牌串（e-office / eoffice10）[B]',
         lambda p: _any_body(p, 'eoffice')),
        ('strong', '跳转 /eoffice/ 或 /emp/login.jsp（e-mobile 入口）[B]',
         lambda p: _loc_has(p, '/eoffice/') or _loc_has(p, '/emp/login.jsp')),
        ('weak', '正文含 泛微（公司名，单独不足以定案）',
         lambda p: _any_body(p, '泛微')),
    ]),

    # ---------------- 致远 A8/A6 (Seeyon) ----------------
    ('seeyon', [
        ('strong', '响应头 Server: SEEYON-OA [A]',
         lambda p: _any_page(p, lambda r: 'seeyon-oa' in _hdr(r, 'server').lower())),
        ('strong', '正文含 seeyon 品牌串（含 <title>致远协同管理软件</title>）[A]',
         lambda p: _any_body(p, 'seeyon')),
        ('strong', '/seeyon/login.jsp 200 且含 seeyon [A]',
         lambda p: _path_body(p, '/seeyon/login.jsp', 'seeyon')),
        ('strong', '跳转 /seeyon/ 路径 [A]',
         lambda p: _loc_has(p, '/seeyon/')),
        ('weak', '正文含 致远（公司名）',
         lambda p: _any_body(p, '致远')),
        ('weak', '正文含 /seeyon/ 或 htmlofficeservlet [A]',
         lambda p: _any_body(p, '/seeyon/') or _any_body(p, 'htmlofficeservlet')),
    ]),

    # ---------------- 蓝凌 EKP ----------------
    ('landray-ekp', [
        ('strong', '正文含 landray 品牌串 [A]',
         lambda p: _any_body(p, 'landray')),
        ('strong', '/sys/login/login.do 200 且含 蓝凌/landray/EKP [A]',
         lambda p: _path_body(p, '/sys/login/login.do', '蓝凌')
                   or _path_body(p, '/sys/login/login.do', 'landray')
                   or _path_body(p, '/sys/login/login.do', 'ekp')),
        ('strong', '跳转 /sys/login/login.do 或 /ekp/ [A]',
         lambda p: _loc_has(p, '/sys/login/login.do') or _loc_has(p, '/ekp/')),
        ('weak', '正文含 蓝凌（公司名）',
         lambda p: _any_body(p, '蓝凌')),
        ('weak', '正文含 EKP 字样 [T]',
         lambda p: _any_body(p, 'ekp')),
    ]),

    # ---------------- 通达 OA ----------------
    ('tongda', [
        ('strong', '正文含 通达OA / MYOA 标识 [A][B]',
         lambda p: _any_body(p, '通达oa') or _any_body(p, 'myoa')),
        ('strong', '跳转 /general/login 或 /ispirit/ [A]',
         lambda p: _loc_has(p, '/general/login') or _loc_has(p, '/ispirit/')),
        ('weak', '正文含 通达（公司名）',
         lambda p: _any_body(p, '通达')),
        ('weak', '正文含 /ispirit/ 或 general/login [A]',
         lambda p: _any_body(p, '/ispirit/') or _any_body(p, 'general/login')),
    ]),

    # ---------------- 万户 ezOFFICE ----------------
    ('ezoffice', [
        ('strong', '正文含 ezOFFICE 品牌串 [A]',
         lambda p: _any_body(p, 'ezoffice')),
        ('strong', '跳转 /defaultroot/（万户专属根路径）[A]',
         lambda p: _loc_has(p, '/defaultroot/')),
        ('strong', '/defaultroot/ 200 且含 万户/ezoffice [A]',
         lambda p: _path_body(p, '/defaultroot/', '万户')
                   or _path_body(p, '/defaultroot/', 'ezoffice')),
        ('weak', '正文含 万户（公司名）',
         lambda p: _any_body(p, '万户')),
    ]),

    # ---------------- 用友 NC / U8 / NCC ----------------
    ('yonyou-nc', [
        ('strong', '正文含 yonyou 品牌串 [A]',
         lambda p: _any_body(p, 'yonyou')),
        ('strong', '正文含 用友NC（厂商名+产品名共现）[A]',
         lambda p: _any_body(p, '用友nc')),
        ('strong', '正文含 nccloud（用友 NCC）[B]',
         lambda p: _any_body(p, 'nccloud')),
        ('strong', '跳转 /nc/ 或 /nccloud/ [A][B]',
         lambda p: _loc_has(p, '/nc/') or _loc_has(p, '/nccloud/')),
        ('weak', '正文含 用友（公司名）',
         lambda p: _any_body(p, '用友')),
        ('weak', '正文含 /nc/servlet/ [A]',
         lambda p: _any_body(p, '/nc/servlet/')),
    ]),

    # ---------------- 金蝶 EAS / K3Cloud ----------------
    ('kingdee', [
        ('strong', '正文含 KingdeeApp 标识 [A]',
         lambda p: _any_body(p, 'kingdeeapp')),
        ('strong', '正文含 kingdee 品牌串 [A]',
         lambda p: _any_body(p, 'kingdee')),
        ('strong', '正文含 金蝶EAS / 金蝶K3Cloud（厂商名+产品名共现）',
         lambda p: _any_body(p, '金蝶eas') or _any_body(p, '金蝶k3cloud')),
        ('strong', '跳转 /eas/ 或 /K3Cloud/ [A]',
         lambda p: _loc_has(p, '/eas/') or _loc_has(p, '/k3cloud/')),
        ('weak', '正文含 金蝶（公司名）',
         lambda p: _any_body(p, '金蝶')),
        ('weak', '正文含 /kd/ 或 /K3Cloud/ 路径串',
         lambda p: _any_body(p, '/k3cloud/')),
    ]),
]


# ---------------------------------------------------------------- 判定
def _evaluate(pages):
    """在已抓到的页面上跑全部规则。返回 (确认产品集, 证据行, 每产品强弱分)。"""
    products, notes, scores = set(), [], {}
    for product, rules in RULES:
        strong = weak = 0
        hits = []
        for strength, desc, fn in rules:
            try:
                ok = fn(pages)
            except Exception:      # 单条规则写错不能拖垮整轮识别
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


def _deadline(ctx):
    """取/建本端点的 L3 总闸门。挂在 ctx 上，与其它 L3 探测器共享。"""
    d = getattr(ctx, '_l3_deadline', None)
    if d is None:
        d = time.time() + L3_BUDGET
        try:
            setattr(ctx, '_l3_deadline', d)
        except AttributeError:      # ctx 若被改成 __slots__，退化为各自计时
            pass
    return d


def probe(ctx, scheme='http'):
    """L3 入口。第二阶段会先试 probe(ctx, scheme=...)，本函数直接接住。

    只返回 products，**不改 protocol**（协议已由 L2 定案）。
    返回 (evidence, products) 或 None。
    """
    deadline = _deadline(ctx)
    pages = {}

    for path in MENU:
        products, _, scores = _evaluate(pages)
        owners = PATH_OWNERS.get(path, ())
        if owners and all(o in products for o in owners):
            continue                                  # 已定案，跳过专属路径省配额
        hinted = any(scores.get(o, (0, 0))[1] > 0 for o in owners)
        cap = HARD_MAX if hinted else MAX_REQ
        if len(pages) >= cap or time.time() > deadline:
            break
        resp = _http_get(ctx, scheme, path, deadline)
        if resp is None:
            if not pages:
                return None                           # 一个请求都拿不到，别耗了
            continue
        pages[path] = resp

    products, notes, _ = _evaluate(pages)
    if not products:
        return None
    return '; '.join(notes)[:400], products
