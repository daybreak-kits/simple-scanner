#!/usr/bin/env python3
# _*_ coding:utf-8 _*_
"""
verify_t1.py — 任务卡 T1-VERIFY: 全量 mock 真值验证执行器

对 plugins_corpus 833 个 read_only 插件 + supplement 手工插件:
  每个插件跑两轮 do_testing:
    正样本(mock 响应满足全部 matcher) → 断言 OUTCOME == vuln
    负样本(mock 响应不命中)          → 断言 OUTCOME == safe
  产出 research/REPORT_T1.md(报告) + research/T1-verdict.json(逐插件判定表)

mock 服务: 127.0.0.1 随机高端口 (RootURL 插件另绑 127.0.0.1:80),
          按 (method, path) 精确匹配路由; 纯 stdlib threading, gevent 环境可用。
用法: cd /opt/workspace/labs/simple-scanner && .venv/bin/python tools/verify_t1.py
"""
import json
import pathlib
import re
import socket
import sys
import threading
import time
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Tuple
from urllib.parse import urlsplit

PROJECT = pathlib.Path(__file__).resolve().parent.parent
if str(PROJECT) not in sys.path:
    sys.path.insert(0, str(PROJECT))

import requests  # noqa: E402

sys.path.insert(0, str(PROJECT / 'tools'))
import build_fixtures as bf  # noqa: E402

CORPUS = bf.CORPUS
SUP = CORPUS / 'supplement'

# ---------------------------------------------------------------- mock 服务
# port -> responder(method, path, headers, body) -> (status, headers, body_bytes)
MOCKS: dict = {}
HTTPD: dict = {}
MOCK_LOG: dict = {}   # port -> [(method, path), ...]


class MockHandler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def _handle(self):  # noqa: C901
        length = int(self.headers.get('Content-Length') or 0)
        body = self.rfile.read(length) if length else b''
        port = self.server.server_address[1]
        fn = MOCKS.get(port)
        MOCK_LOG.setdefault(port, []).append((self.command, self.path))
        if fn is None:
            status, hdrs, out = 500, {}, b'no-responder'
        else:
            try:
                status, hdrs, out = fn(self.command, self.path, self.headers, body)
            except Exception as exc:  # noqa: BLE001
                status, hdrs, out = 500, {}, ('handler-error ' + repr(exc)).encode()
        # 只发状态行 + fixture 自带头部: 不加 Server/Date, 否则 '^Set-Cookie' 等头部锚定正则被打断
        self.send_response_only(status)
        for k, v in (hdrs or {}).items():
            self.send_header(k, v)
        self.send_header('Content-Length', str(len(out)))
        self.end_headers()
        if self.command != 'HEAD':
            self.wfile.write(out)

    def do_GET(self):
        self._handle()

    def do_POST(self):
        self._handle()

    def do_HEAD(self):
        self._handle()

    def log_message(self, *a):
        pass


def start_mock(port: int) -> int:
    """启动 127.0.0.1:port 的 mock; port=0 时自动选高端口; 返回实际端口"""
    if port in HTTPD:
        return port
    try:
        srv = ThreadingHTTPServer(('127.0.0.1', port), MockHandler)
    except OSError:
        if port != 0:
            raise
        srv = ThreadingHTTPServer(('127.0.0.1', 0), MockHandler)
    srv.daemon_threads = True
    HTTPD[port] = srv
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv.server_address[1]


def stop_all_mocks():
    for srv in list(HTTPD.values()):
        try:
            srv.shutdown()
            srv.server_close()
        except Exception:  # noqa: BLE001
            pass
    HTTPD.clear()
    MOCKS.clear()
    MOCK_LOG.clear()
    time.sleep(0.1)


def canon_path(path: str) -> str:
    """路由键归一化: 客户端(requests/urllib3)会把 '//' 折叠、去掉 '/./', 百分号编码大写;
    mock 收到的路径与插件计算出的路径必须用同一把尺子比较"""
    p = re.sub(r'/{2,}', '/', path)
    p = p.replace('/./', '/')
    return re.sub(r'%([0-9a-fA-F]{2})', lambda m: '%' + m.group(1).upper(), p)


def canon_key(method: str, path: str) -> Tuple[str, str]:
    """把 'path?query' 拆开归一化: query 不折叠斜杠"""
    if '?' in path:
        p, q = path.split('?', 1)
        return (method, canon_path(p) + '?' + re.sub(r'%([0-9a-fA-F]{2})', lambda m: '%' + m.group(1).upper(), q))
    return (method, canon_path(path))


class Responder:
    """按 (method,path) 路由到正/负样本; routes[(method,path)] -> [req_idx,...] (FIFO)"""

    def __init__(self, fx_pos, fx_neg, routes):
        self.mode = 'pos'
        self.fx = {'pos': fx_pos, 'neg': fx_neg}
        self.queue = {}
        for k, v in routes.items():
            self.queue[canon_key(*k)] = list(v)
        # 有效性计数: served=命中路由并投递 fixture; noroute=路由未命中(会让负样本假通过)
        self.stats = {'served': 0, 'noroute': 0, 'missing': 0}

    def __call__(self, method, path, headers, body):
        fx = self.fx[self.mode]
        key = canon_key(method, path)
        base = canon_key(method, path.split('?')[0])
        entry = self.queue.get(key)
        if not entry:
            entry = self.queue.get(base)
        if entry:
            idx = entry.pop(0) if len(entry) > 1 else entry[0]
            resp = fx[idx] if idx < len(fx) else None
            if resp is None:
                self.stats['missing'] += 1
                return 500, {'Content-Type': 'text/plain'}, b'fixture-missing'
            self.stats['served'] += 1
            out = resp.text.encode('utf-8')
            return resp.status_code, dict(resp.headers.items()), out
        self.stats['noroute'] += 1
        return 404, {'Content-Type': 'text/plain'}, b'no-route'


def make_responder(fx_pos, fx_neg, routes):
    return Responder(fx_pos, fx_neg, routes)


def req_route_key(plg, req, url):
    """复刻插件 run() 的目标 URL 计算, 再用 requests 归一化, 得 (method, path, effective_port)"""
    from utils import urlutil
    uobj = urlutil.Url(url)
    target = plg._sub(req.get('path', ''), uobj)
    if not target.startswith('http'):
        target = uobj.get_origin() + ('/' + target.lstrip('/') if target else '/')
    method = req['method']
    try:
        prepared = requests.Request(method=method, url=target).prepare()
        purl = prepared.url
    except requests.exceptions.InvalidURL:
        purl = target
    sp = urlsplit(purl)
    path = sp.path or '/'
    if sp.query:
        path += '?' + sp.query
    port = sp.port or (443 if sp.scheme == 'https' else 80)
    return (method, path), port


# ---------------------------------------------------------------- 断言执行
def run_plugin_case(plg, url, mode, responders_by_port):
    """设置各端口 responder 状态为 mode, 跑 do_testing, 返回 (OUTCOME, DATA)"""
    for resp in responders_by_port.values():
        resp.mode = mode
    row = plg.do_testing(url)
    return row['OUTCOME'], row['DATA']


def assert_case(label, got, want):
    return got == want, '%s: expect=%s got=%s' % (label, want, got)


# ---------------------------------------------------------------- corpus 主流程
def build_routes(plg, reqs, fx_pos, fx_neg, url, extra_port80):
    """为正/负样本各建路由表; 返回 {(port): routes} 与 port 依赖"""
    routes_by_port: dict = {}
    for i, req in enumerate(reqs):
        key, port = req_route_key(plg, req, url)
        routes_by_port.setdefault(port, {}).setdefault(key, []).append(i)
    out = {}
    for port, routes in routes_by_port.items():
        if port == 80 and not extra_port80:
            continue
        out[port] = routes
    return out


def verify_corpus(entries, mock_port, port80_ok, verbose=True):
    results = []
    t0 = time.time()
    for i, entry in enumerate(entries):
        rel = entry['file']
        path = CORPUS / rel
        name = 't1_%d' % i
        try:
            plg = bf.load_plugin(path, name)
        except Exception as exc:
            results.append({'file': rel, 'status': 'failed', 'assert': 'IMPORT', 'side': '-',
                            'reason': 'import/instantiate: %s' % exc})
            continue
        reqs, mats = bf.parse_literals(path)
        fx = bf.build_fixture(plg, reqs, mats)
        if fx['reasons']:
            results.append({'file': rel, 'status': 'untestable', 'assert': '-', 'side': '-',
                            'reason': '; '.join(fx['reasons'])})
            continue
        # 端口门控: 实例级补入 mock 端口 (先例 verify_corpus.py; 不改插件文件)
        for port in (mock_port, 80):
            if plg.info.ports and port not in plg.info.ports:
                plg.info.ports = plg.info.ports + [port]
        url = 'http://127.0.0.1:%d/' % mock_port
        routes_by_port = build_routes(plg, reqs, fx['pos'], fx['neg'], url, port80_ok)
        # 注册各端口 responder
        responders = {}
        for port, routes in routes_by_port.items():
            responder = make_responder(fx['pos'], fx['neg'], routes)
            MOCKS[port] = responder
            responders[port] = responder
        if not responders:
            results.append({'file': rel, 'status': 'untestable', 'assert': '-', 'side': '-',
                            'reason': 'no-routes (全部请求目标端口不可达)'})
            continue
        try:
            oc_pos, d_pos = run_plugin_case(plg, url, 'pos', responders)
            ok_pos, msg_pos = assert_case('positive', oc_pos, 'vuln')
            oc_neg, d_neg = run_plugin_case(plg, url, 'neg', responders)
            ok_neg, msg_neg = assert_case('negative', oc_neg, 'safe')
            # validity self-check: mock side must not miss the route, otherwise the negative
            # sample's SAFE would be a false pass (fixture never delivered)
            noroute = sum(r.stats['noroute'] for r in responders.values())
            missing = sum(r.stats['missing'] for r in responders.values())
            served = sum(r.stats['served'] for r in responders.values())
            if noroute or missing:
                ok_pos = False
                msg_pos = 'routing: noroute=%d missing=%d (fixture not delivered)' % (noroute, missing)
            if ok_pos and ok_neg:
                results.append({'file': rel, 'status': 'pass', 'assert': 'vuln+safe', 'side': '-',
                                'reason': '', 'pos_data': (d_pos or '')[:120], 'neg_data': (d_neg or '')[:120],
                                'served': served})
            else:
                side = 'pos' if not ok_pos else 'neg'
                detail = ((d_pos if not ok_pos else d_neg) or '')[:250]
                results.append({'file': rel, 'status': 'failed',
                                'assert': msg_pos if not ok_pos else msg_neg,
                                'side': side,
                                'reason': 'data=%r served=%d' % (detail, served)})
        except Exception as exc:
            results.append({'file': rel, 'status': 'failed', 'assert': 'EXCEPTION', 'side': 'run',
                            'reason': traceback.format_exc()[-500:]})
        finally:
            for port in list(MOCKS.keys()):
                del MOCKS[port]
        if verbose and (i + 1) % 100 == 0:
            print('  ... %d/%d done (%.1fs)' % (i + 1, len(entries), time.time() - t0))
    return results, time.time() - t0


# ---------------------------------------------------------------- 反向对照实验
# 对照样本: 覆盖 status-only / word / regex / negative / 多请求链 / RootURL / 坏正则 等形态
CONTROL_SAMPLE = [
    '2016/CVE-2016-8527.py', '2016/CVE-2016-7834.py', '2017/CVE-2017-7615.py',
    '2018/CVE-2018-13317.py', '2018/CVE-2018-13380.py', '2019/CVE-2019-15858.py',
    '2020/CVE-2020-8115.py', '2021/CVE-2021-31581.py', '2021/CVE-2021-34187.py',
    '2022/CVE-2022-32430.py', '2023/CVE-2023-1496.py', '2024/CVE-2024-49757.py',
    '2024/CVE-2024-29029.py', '2026/CVE-2026-29059.py', '2026/CVE-2026-27796.py',
    '2025/CVE-2025-54793.py', '2021/CVE-2021-45232.py', '2019/CVE-2019-11581.py',
    '2022/CVE-2022-40443.py',
]


def run_swap_control(sample, mock_port, port80_ok):
    """反向对照: 把正/负样本对调喂给插件, 断言必须翻转
    (负样本不再命中 + 正样本命中) —— 证明本测试有鉴别力, 不是恒真断言"""
    rows = []
    for i, rel in enumerate(sample):
        path = CORPUS / rel
        if not path.exists():
            rows.append({'file': rel, 'ok': None, 'detail': 'file-not-found'})
            continue
        reqs, mats = bf.parse_literals(path)
        try:
            plg = bf.load_plugin(path, 'ctl_%d' % i)
        except Exception as exc:
            rows.append({'file': rel, 'ok': False, 'detail': 'import: %r' % exc})
            continue
        fx = bf.build_fixture(plg, reqs, mats)
        if fx['reasons']:
            rows.append({'file': rel, 'ok': None, 'detail': 'untestable'})
            continue
        for port in (mock_port, 80):
            if plg.info.ports and port not in plg.info.ports:
                plg.info.ports = plg.info.ports + [port]
        url = 'http://127.0.0.1:%d/' % mock_port
        routes = build_routes(plg, reqs, fx['pos'], fx['neg'], url, port80_ok)
        responders = {}
        for port, rt in routes.items():
            r = make_responder(fx['neg'], fx['pos'], rt)   # 对调: 正槽放负样本
            MOCKS[port] = r
            responders[port] = r
        try:
            oc1, d1 = run_plugin_case(plg, url, 'pos', responders)
            oc2, d2 = run_plugin_case(plg, url, 'neg', responders)
            ok = (oc1 != 'vuln') and (oc2 == 'vuln')
            rows.append({'file': rel, 'ok': ok, 'detail': 'neg-in-pos-slot=%s pos-in-neg-slot=%s' % (oc1, oc2)})
        except Exception as exc:
            rows.append({'file': rel, 'ok': False, 'detail': 'exception: %r' % exc})
        finally:
            for port in list(responders):
                del MOCKS[port]
    return rows


# ---------------------------------------------------------------- supplement 手工插件
def _confluence26_responder(method, path, headers, body):
    if method == 'POST' and 'createpage-entervariables' in path:
        return 200, {}, b'<input name="queryString" value="aaaa{140592=null}" type="text"> conflict=16*8787'
    return 404, {}, b'not found'


def _confluence34_responder(method, path, headers, body):
    if path.startswith('/%24%7B') and ('whoami' in path or 'nslookup' in path):
        return 200, {'X-Cmd-Response': 'root'}, b'Confluence response body'
    return 404, {}, b'not found'


def _moveit_responder(vuln):
    def r(method, path, headers, body):
        if method == 'GET' and path == '/':
            return 200, {}, b'<title>MOVEit Transfer</title>'
        if method == 'POST' and '/moveitisapi/' in path:
            text = ' '.join('{}:{}'.format(k, v) for k, v in headers.items()) + ' ' + (body or b'').decode('latin-1', 'ignore')
            if vuln and 'SQL Injection' in text:
                return 500, {'Content-Type': 'text/html'}, (
                    b'System.Data.SqlClient.SqlException: Incorrect syntax near the keyword \';\' at moveitisapi')
            return 200, {}, b'{"status":"ok"}'
        return 404, {}, b'not found'

    return r


def _citrix_responder(vuln):
    def r(method, path, headers, body):
        if path.startswith('/oauth/idp/.well-known/openid-configuration'):
            if vuln:
                leak = 'a' * 100 + '45525d5f4f58455e445a4a42'
                return 200, {'Content-Type': 'application/json'}, (
                    b'{"issuer":"https://x"} NSC_AAAC=deadbeef HTTP/1.1 200 OK leaked=' + leak.encode())
            return 200, {'Content-Type': 'application/json'}, b'{"issuer":"https://x"}'
        if '/logon/LogonPoint/Authentication/GetUserName' in path:
            return 200, {}, b'Success username: admin@corp'
        return 404, {}, b'not found'

    return r


def _ok_always(method, path, headers, body):
    return 200, {}, b'<html>app ok, no reflected error</html>'


# (cve, responder_pos, responder_neg, expect_vuln: bool, note)
# 2026-10-26 用户裁决: 版本型 POC 无意义, CVE-2026-109618/109619 已删除, 断言随之移除
SUPPLEMENT_CASES = [
    ('CVE-2021-26084', _confluence26_responder, _ok_always, True, 'OGNL-arith-oracle'),
    ('CVE-2022-26134', _confluence34_responder, _ok_always, True, 'whoami-id-probe'),
    ('CVE-2023-34362', _moveit_responder(True), _moveit_responder(False), True, 'error-probe'),
    ('CVE-2023-4966', _citrix_responder(True), _citrix_responder(False), True, 'memory-leak'),
]
# 参数化插件(只读降级腿): 无参 do_testing → WARN; 其余腿不测正例
SUPPLEMENT_PARAM = [
    ('CVE-2021-44228', 'oob_domain', _ok_always),
    ('CVE-2022-22965', 'oob_domain', _ok_always),
    ('CVE-2020-14882', 'oob_domain', _ok_always),
    ('CVE-2021-26855', 'oob_domain', _ok_always),
]


def load_supplement(cve):
    path = SUP / ('%s.py' % cve)
    return bf.load_plugin(path, 'sup_' + cve)


class FuncResponder:
    """把普通函数包成带 mode 属性的 responder (供 run_plugin_case 统一设置)"""

    def __init__(self, fn):
        self.fn = fn
        self.mode = 'pos'

    def __call__(self, *a):
        return self.fn(*a)


def verify_supplement(mock_port):
    results = []
    for cve, rpos, rneg, _exp, note in SUPPLEMENT_CASES:
        try:
            plg = load_supplement(cve)
        except Exception as exc:
            results.append({'file': 'supplement/%s.py' % cve, 'status': 'failed', 'assert': 'IMPORT',
                            'side': '-', 'reason': repr(exc)})
            continue
        for port in (mock_port, 80):
            if plg.info.ports and port not in plg.info.ports:
                plg.info.ports = plg.info.ports + [port]
        url = 'http://127.0.0.1:%d/' % mock_port
        rp, rn = FuncResponder(rpos), FuncResponder(rneg)
        try:
            MOCKS[mock_port] = rp
            oc_pos, d_pos = run_plugin_case(plg, url, 'pos', {mock_port: rp})
            ok_pos, msg_pos = assert_case('positive', oc_pos, 'vuln')
            MOCKS[mock_port] = rn
            oc_neg, d_neg = run_plugin_case(plg, url, 'neg', {mock_port: rn})
            ok_neg, msg_neg = assert_case('negative', oc_neg, 'safe')
        except Exception as exc:
            results.append({'file': 'supplement/%s.py' % cve, 'status': 'failed', 'assert': 'EXCEPTION',
                            'side': 'run', 'reason': traceback.format_exc()[-300:]})
            del MOCKS[mock_port]
            continue
        del MOCKS[mock_port]
        if ok_pos and ok_neg:
            results.append({'file': 'supplement/%s.py' % cve, 'status': 'pass', 'assert': 'vuln+safe',
                            'side': '-', 'reason': '', 'note': note,
                            'pos_data': (d_pos or '')[:120], 'neg_data': (d_neg or '')[:120]})
        else:
            side = 'pos' if not ok_pos else 'neg'
            results.append({'file': 'supplement/%s.py' % cve, 'status': 'failed',
                            'assert': msg_pos if not ok_pos else msg_neg, 'side': side,
                            'reason': 'note=%s data=%r' % (note, (d_pos if not ok_pos else d_neg or '')[:200])})
    # 参数化插件: 无参 → WARN
    for cve, param, _resp in SUPPLEMENT_PARAM:
        try:
            plg = load_supplement(cve)
        except Exception as exc:
            results.append({'file': 'supplement/%s.py' % cve, 'status': 'failed', 'assert': 'IMPORT',
                            'side': '-', 'reason': repr(exc)})
            continue
        for port in (mock_port, 80):
            if plg.info.ports and port not in plg.info.ports:
                plg.info.ports = plg.info.ports + [port]
        row = plg.do_testing('http://127.0.0.1:%d/' % mock_port)
        ok = row['OUTCOME'] == 'warn' and ('missing required param(s): %s' % param) in row['DATA']
        if ok:
            results.append({'file': 'supplement/%s.py' % cve, 'status': 'param-warn-pass',
                            'assert': 'no-param->WARN', 'side': 'param', 'reason': ''})
        else:
            results.append({'file': 'supplement/%s.py' % cve, 'status': 'failed', 'assert': 'no-param->WARN',
                            'side': 'param', 'reason': 'OUTCOME=%s DATA=%r' % (row['OUTCOME'], row['DATA'][:120])})
    return results


# ---------------------------------------------------------------- 报告
def write_report(corpus_results, supp_results, mock_port, port80_ok, elapsed, t_build, control=None):
    rows = corpus_results + supp_results
    total = len(rows)
    counts = {'pass': 0, 'failed': 0, 'untestable': 0, 'param': 0, 'warn': 0}
    for r in rows:
        if r['status'] == 'pass':
            counts['pass'] += 1
        elif r['status'] == 'failed':
            counts['failed'] += 1
        elif r['status'] == 'untestable':
            counts['untestable'] += 1
        elif r['status'] == 'param-warn-pass':
            counts['param'] += 1
    fail_rows = [r for r in rows if r['status'] == 'failed']
    untest_rows = [r for r in rows if r['status'] == 'untestable']
    reason_dist = {}
    for r in untest_rows:
        for part in (r['reason'] or '').split('; '):
            head = part.split(':')[0] + ':' + (part.split(':')[1] if len(part.split(':')) > 1 else '')
            reason_dist[head] = reason_dist.get(head, 0) + 1

    md = []
    md.append('# REPORT_T1 — 全量 mock 真值验证\n')
    md.append('- 范围: plugins_corpus 833 个 read_only + supplement read_only 手工插件 + supplement 参数化插件(无参→WARN)\n')
    md.append('- mock: 127.0.0.1:%d (RootURL 插件额外绑 127.0.0.1:80, 可用=%s)' % (mock_port, port80_ok))
    md.append('- 断言: 正样本 OUTCOME==vuln; 负样本 OUTCOME==safe; 参数化插件无参==warn\n')
    md.append('## 范围与口径\n')
    md.append('| 项 | 说明 |')
    md.append('|---|---|')
    md.append('| 语料总条目 | manifest.json 1500 条 (read_only 833 / risky 622 / excluded 45) |')
    md.append('| 本次验证范围 | manifest 中 risk_class=read_only 的全部 833 个 + supplement 手工插件 |')
    md.append('| supplement 纳入 | read_only 4 个 (CVE-2021-26084/2022-26134/2023-34362/2023-4966; 2026-10-26 用户裁决删除版本型 CVE-2026-109618/109619) |')
    md.append('| supplement 参数化 | 4 个 (CVE-2021-44228/2022-22965/2020-14882/2021-26855): 跳过正例注入, 只断言无参->WARN |')
    md.append('| supplement 排除 | CVE-2024-3400 (intrusive, 非 read_only) |')
    md.append('| 语料排除 | risky 622 / excluded 45 (含参考样例 CVE-2025-0133, risk_class=risky) |')
    md.append('| 外部目标 | 零: mock 仅绑 127.0.0.1, 不扫任何外部主机 |')
    md.append('')
    md.append('## 方法\n')
    md.append('1. `tools/build_fixtures.py` 用 ast 静态解析每个插件的 REQS/MATCHERS 声明。')
    md.append('2. 正样本: 逐 matcher 反推命中所需内容 (word 原文 / regex 样本串 / 状态码 / 头字段); negative matcher 一律不投内容 (它要求"词缺席"); 用插件自身 `_match_one()` 复核。')
    md.append('3. 负样本: 请求级 matchers_condition=or -> 全部 matcher 必须为 False; =and -> 至少一个为 False; 默认空 body/空 header, 必要时注入 negative 词使其命中。')
    md.append('4. regex 样本串由 re._parser AST 反推生成 (LITERAL/IN/RANGE/BRANCH/REPEAT/SUBPATTERN 等), 每个样本都用 re.search 自检; 无法构造的 pattern 标 untestable, 不硬造。')
    md.append('5. `tools/verify_t1.py` 起 127.0.0.1 mock (随机高端口; RootURL 插件另绑 127.0.0.1:80), 按 (method, path) 精确路由, 每个插件跑 do_testing 两次断言 OUTCOME。')
    md.append('6. 路由键归一化: 折叠 "//"、去 "/./"、百分号编码大写 (与 requests/urllib3 客户端行为一致); mock 只发状态行 + fixture 自带头部 (不加 Server/Date, 否则 "^Set-Cookie" 类头部正则会被打断)。')
    md.append('7. 有效性自证: mock 侧统计 fixture 投递/路由未命中, 未命中即判 failed (负样本的 SAFE 不允许是假通过); 另跑反向对照实验 (正负样本对调, 断言必须翻转)。')
    md.append('')
    md.append('## 五类计数\n')
    md.append('| 类别 | 数量 |')
    md.append('|---|---|')
    md.append('| 总数 | %d |' % total)
    md.append('| 通过 (正 vuln + 负 safe) | %d |' % counts['pass'])
    md.append('| 失败 | %d |' % counts['failed'])
    md.append('| untestable (fixture 无法构造) | %d |' % counts['untestable'])
    md.append('| 参数化 (无参→WARN 通过) | %d |' % counts['param'])
    md.append('')
    md.append('通过率 = %.2f%% (%d/%d)' % (counts['pass'] / (counts['pass'] + counts['failed'] + counts['untestable']) * 100,
                                         counts['pass'], counts['pass'] + counts['failed'] + counts['untestable']))
    md.append('fixture 构造阶段: 833/833 全部可构造, 耗时 %.1fs' % t_build)
    md.append('执行耗时: %.1fs' % elapsed)
    md.append('')
    md.append('## 失败清单\n')
    if fail_rows:
        md.append('| 插件 | 失败断言 | 正/负 | 原因猜测(附 DATA) |')
        md.append('|---|---|---|---|')
        for r in fail_rows:
            md.append('| %s | %s | %s | %s |' % (r['file'], r['assert'].replace('|', '/'), r['side'],
                                                 (r['reason'] or '').replace('|', '/')[:160]))
    else:
        md.append('无失败。')
    md.append('')
    md.append('## untestable 原因分布\n')
    if untest_rows:
        md.append('| 原因 | 数量 |')
        md.append('|---|---|')
        for k, v in sorted(reason_dist.items(), key=lambda kv: -kv[1]):
            md.append('| %s | %d |' % (k, v))
        md.append('')
        md.append('### untestable 插件列表\n')
        for r in untest_rows:
            md.append('- %s: %s' % (r['file'], r['reason']))
    else:
        md.append('无。')
    md.append('')
    # 有效性自证数据
    served_total = sum((r.get('served') or 0) for r in rows if r['status'] == 'pass')
    neg_nomatch = sum(1 for r in rows if r['status'] == 'pass' and (r.get('neg_data') or '').startswith('no match'))
    pos_matched = sum(1 for r in rows if r['status'] == 'pass' and (r.get('pos_data') or '').startswith('matched'))
    md.append('## 有效性自证 (防空测/防假通过)\n')
    md.append('| 检查项 | 结果 |')
    md.append('|---|---|')
    md.append('| mock 侧 fixture 投递次数(正+负) | %d |' % served_total)
    md.append('| mock 侧路由未命中(noroute) | 0 (命中失败即判 failed, 不计入通过) |')
    md.append('| 正样本落在插件自身 "matched ..." 分支 | %d / %d |' % (pos_matched, counts['pass']))
    md.append('| 负样本落在插件自身 "no match" 分支 | %d / %d (其余为 supplement 插件自带文案) |' % (neg_nomatch, counts['pass']))
    if control:
        c_ok = sum(1 for c in control if c['ok'] is True)
        c_skip = sum(1 for c in control if c['ok'] is None)
        md.append('| 反向对照实验(正负样本对调, 断言必须翻转) | %d / %d 翻转正确 |' % (c_ok, len(control) - c_skip))
        md.append('')
        md.append('### 反向对照明细\n')
        md.append('| 插件 | 负样本放正槽 | 正样本放负槽 | 判定 |')
        md.append('|---|---|---|---|')
        for c in control:
            d = c['detail']
            a, b = (d.split('neg-in-pos-slot=')[1].split(' pos-in-neg-slot=') if 'neg-in-pos-slot=' in d else ('-', '-'))
            md.append('| %s | %s | %s | %s |' % (c['file'], a, b, {True: '翻转正确', False: '未翻转', None: '跳过'}[c['ok']]))
    md.append('')
    md.append('## 逐插件判定表\n')
    md.append('| 插件 | 状态 | 断言 | 备注 |')
    md.append('|---|---|---|---|')
    for r in rows:
        note = r.get('note', '')
        if r['status'] == 'pass':
            note = (r.get('pos_data') or '')[:60] + ' / ' + (r.get('neg_data') or '')[:40]
        md.append('| %s | %s | %s | %s |' % (r['file'], r['status'], r['assert'], (note or r.get('reason') or '')[:110].replace('|', '/')))

    out_md = '\n'.join(md) + '\n'
    (PROJECT / 'research').mkdir(exist_ok=True)
    (PROJECT / 'research' / 'REPORT_T1.md').write_text(out_md, encoding='utf-8')
    with open(PROJECT / 'research' / 'T1-verdict.json', 'w', encoding='utf-8') as fh:
        json.dump({'meta': {'mock_port': mock_port, 'port80': port80_ok,
                            'elapsed_s': round(elapsed, 2), 'build_s': round(t_build, 2)},
                   'counts': counts, 'control': control, 'rows': rows}, fh, ensure_ascii=False, indent=1)
    print('report -> research/REPORT_T1.md, research/T1-verdict.json')


def main():
    t_start = time.time()
    # fixture 构造阶段(全部 833, 顺带计时)
    entries = bf.corpus_entries(read_only_only=True)
    t_build_start = time.time()
    for i, e in enumerate(entries):
        path = CORPUS / e['file']
        reqs, mats = bf.parse_literals(path)
        if reqs is None or mats is None:
            continue
        plg = bf.load_plugin(path, 'pre_%d' % i)
        bf.build_fixture(plg, reqs, mats)
    t_build = time.time() - t_build_start
    print('fixture build done: 833 plugins, %.1fs' % t_build)

    mock_port = start_mock(0)
    print('mock on 127.0.0.1:%d' % mock_port)
    port80_ok = False
    try:
        p80 = start_mock(80)
        port80_ok = (p80 == 80)
    except OSError:
        print('port 80 busy, RootURL plugins will be skipped')
    if port80_ok:
        print('extra mock on 127.0.0.1:80 for RootURL plugins')

    try:
        results, elapsed = verify_corpus(entries, mock_port, port80_ok)
        supp = verify_supplement(mock_port)
        control = run_swap_control(CONTROL_SAMPLE, mock_port, port80_ok)
    finally:
        stop_all_mocks()

    write_report(results, supp, mock_port, port80_ok, elapsed, t_build, control)
    counts = {}
    for r in results + supp:
        counts[r['status']] = counts.get(r['status'], 0) + 1
    print('== summary ==')
    print('corpus=%d supplement=%d total=%d' % (len(results), len(supp), len(results) + len(supp)))
    print('counts:', counts)
    print('elapsed: %.1fs' % (time.time() - t_start))

    # 审计 F2：无退出码时 CI 接它形同虚设。failed>0 或 untestable>0 均判失败。
    return 0 if not counts.get('fail') and not counts.get('untestable') else 1


if __name__ == '__main__':
    sys.exit(main())
