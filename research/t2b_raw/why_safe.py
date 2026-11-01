#!/usr/bin/env python3
"""T3ENV-B: 解释某插件为什么没命中 —— 打印 REQS 路径 + MATCHERS，并现场复现请求。"""
import re
import sys
import urllib3

urllib3.disable_warnings()
PLUGDIR = '/opt/workspace/labs/simple-scanner/plugins'


def main():
    base = sys.argv[1]  # e.g. http://192.168.255.128:28081
    for cve in sys.argv[2:]:
        path = '{}/T2B_{}.py'.format(PLUGDIR, cve)
        src = open(path, encoding='utf-8').read()
        reqs = re.search(r'^REQS = (\[.*\])$', src, re.M).group(1)
        mats = re.search(r'^MATCHERS = (\[.*\])$', src, re.M)
        print('=' * 78)
        print('PLUGIN:', cve)
        print('REQS  :', reqs[:400])
        if mats:
            print('MATCH :', mats.group(1)[:400])
        # 复现第一条请求
        m = re.search(r"'path': '([^']+)'", reqs)
        if not m:
            continue
        p = m.group(1).replace('{{BaseURL}}', base).replace('{{RootURL}}', base).replace('{{Hostname}}', '192.168.255.128')
        try:
            r = urllib3.PoolManager(timeout=urllib3.Timeout(connect=3.0, read=3.0), retries=urllib3.Retry(total=1))
            resp = r.request('GET', p)
            body = resp.data.decode('utf-8', 'replace')
            print('PROBE : {} -> HTTP {} len={}'.format(p, resp.status, len(body)))
            print('BODYH :', body[:200].replace('\n', ' '))
        except Exception as e:
            print('PROBE : {} -> ERROR {}'.format(p, type(e).__name__), str(e)[:120])


if __name__ == '__main__':
    main()
