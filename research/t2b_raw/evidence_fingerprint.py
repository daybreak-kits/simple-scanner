#!/usr/bin/env python3
"""T3ENV-B: 找出「证据型」插件（只请求根路径，靠响应内容判定产品），
并把它们的匹配器在真实端点根响应上跑一遍，看有没有一个能靠指纹命中。"""
import importlib
import re
import sys

sys.path.insert(0, '/opt/workspace/labs/simple-scanner')
from utils import urlutil  # noqa: E402

PLUGDIR = '/opt/workspace/labs/simple-scanner/plugins'
CVE_RE = re.compile(r'^T2B_(.+)\.py$')


def root_fetchers():
    out = []
    import os
    for f in sorted(os.listdir(PLUGDIR)):
        m = CVE_RE.match(f)
        if not m:
            continue
        cve = m.group(1)
        src = open('{}/{}'.format(PLUGDIR, f), encoding='utf-8').read()
        mm = re.search(r'^REQS = (\[.*\])$', src, re.M)
        if not mm:
            continue
        reqs = mm.group(1)
        paths = re.findall(r"'path': '([^']*)'", reqs)
        if not paths:
            continue
        if all(p in ('{{BaseURL}}', '{{BaseURL}}/') for p in paths):
            out.append((cve, f))
    return out


def main():
    base = sys.argv[1]
    url = urlutil.Url(base, False)
    fetchers = root_fetchers()
    print('根路径型(证据型)插件数: {}'.format(len(fetchers)))
    hit = []
    err = []
    for cve, f in fetchers:
        try:
            m = importlib.import_module('plugins.' + f[:-3])
            p = m.Plugin()
            http = p.make_http_client()
            e, resp = http.rq(base.rstrip('/') + '/')
            if e:
                err.append((cve, type(e).__name__))
                continue
            mats = [x for x in m.MATCHERS if x.get('req_idx') == 0]
            res = [p._match_one(resp, x) for x in mats]
            ok = all(res) if m.REQS[0].get('matchers_condition', 'or') == 'and' else any(res)
            if ok:
                hit.append((cve, m.MATCHERS))
        except Exception as ex:
            err.append((cve, type(ex).__name__))
    print('在 {} 根响应上能命中的证据型插件: {}'.format(base, len(hit)))
    for cve, mats in hit:
        print('  HIT', cve, str(mats)[:220])
    print('执行异常: {}'.format(err[:10]))


if __name__ == '__main__':
    main()
