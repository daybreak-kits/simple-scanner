#!/usr/bin/env python3
# _*_ coding:utf-8 _*_
"""
verify_corpus.py — plugins_corpus 交付验证（任务卡 M1 第 5 步）
  1) 全量 import + 实例化 + Info 完整性校验（protocol/port/ports/catalog/fingerprint）
  2) 随机抽 N 个插件对本地 mock HTTP 服务执行 do_testing，
     断言不抛异常且 OUTCOME ∈ {vuln, safe, warn, skip}，记录耗时
"""
import argparse
import importlib.util
import json
import os
import pathlib
import random
import sys
import time
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PROJECT = pathlib.Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT))

CORPUS = PROJECT / 'plugins_corpus'

FAKE_BODY = (
    '<!DOCTYPE html><html><head><title>It works!</title></head><body>'
    '<h1>Welcome to nginx!</h1><p>If you see this page, the nginx web server is '
    'successfully installed and working.</p><p>Hello World test page 200 OK</p>'
    '<div id="content">Administration console</div>'
    '<form action="/wp-login.php" method="post">user_login</form></body></html>'
)


class Handler(BaseHTTPRequestHandler):
    requests_seen = 0
    methods_seen = {}
    body_override = None
    header_override = None

    def _respond(self):
        Handler.requests_seen += 1
        Handler.methods_seen[self.command] = Handler.methods_seen.get(self.command, 0) + 1
        length = int(self.headers.get('Content-Length') or 0)
        if length:
            self.rfile.read(length)
        body = (Handler.body_override or FAKE_BODY).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Server', 'nginx/1.18.0 (Ubuntu)')
        self.send_header('X-Powered-By', 'PHP/7.4.3')
        self.send_header('Location', '/login.php')
        if Handler.header_override:
            self.send_header('X-Sink', Handler.header_override[:60000])
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.end_headers()
        if self.command != 'HEAD':
            self.wfile.write(body)

    do_GET = _respond
    do_HEAD = _respond
    do_POST = _respond
    do_PUT = _respond
    do_PATCH = _respond
    do_DELETE = _respond
    do_OPTIONS = _respond
    do_TRACE = _respond

    def log_message(self, *args):
        pass

def load_plugin(fpath, mod_name):
    spec = importlib.util.spec_from_file_location(mod_name, fpath)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.Plugin()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--samples', type=int, default=20)
    ap.add_argument('--seed', type=int, default=42)
    ap.add_argument('--port', type=int, default=0, help='0=自动(优先8080)')
    args = ap.parse_args()

    manifest = json.load(open(CORPUS / 'manifest.json', encoding='utf-8'))
    print('manifest entries:', len(manifest))

    # ---- 1) 全量 import + 实例化 + Info 校验 ----
    ok = 0
    fails = []
    info_bad = []
    t0 = time.time()
    for i, entry in enumerate(manifest):
        fpath = CORPUS / entry['file']
        try:
            plg = load_plugin(str(fpath), 'corpus_plg_%d' % i)
        except Exception:
            fails.append((entry['file'], 'IMPORT/INSTANTIATE: ' + traceback.format_exc()[-500:]))
            continue
        info = plg.info
        problems = []
        if not info.protocol:
            problems.append('protocol empty')
        if not info.port or int(info.port) <= 0:
            problems.append('port invalid')
        if not info.catalog:
            problems.append('catalog empty')
        if not info.ports:
            problems.append('ports empty')
        if not hasattr(info, 'fingerprint'):
            problems.append('fingerprint attr missing')
        if problems:
            info_bad.append((entry['file'], problems))
            continue
        ok += 1
    dt = time.time() - t0
    print('== import/instantiate ==')
    print('pass={} fail={} info_bad={} elapsed={:.1f}s'.format(ok, len(fails), len(info_bad), dt))
    for f, why in info_bad[:10]:
        print('  INFO_BAD {}: {}'.format(f, why))
    for f, why in fails[:10]:
        print('  FAIL {}: {}'.format(f, why))
    import_rate = ok / len(manifest) * 100.0
    print('pass_rate={:.2f}%'.format(import_rate))

    # ---- 2) smoke：本地 mock + 抽 N 个 do_testing ----
    try:
        httpd = ThreadingHTTPServer(('127.0.0.1', args.port or 8080), Handler)
        port = httpd.server_address[1]
        print('\nmock server on 127.0.0.1:{}, port in plugin ports={}'.format(port, port in [80, 443, 8080, 8443]))
    except OSError:
        httpd = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        port = httpd.server_address[1]
        print('\n8080 busy, mock server on 127.0.0.1:{} (port 不在插件声明内, 测试侧临时加入 info.ports)'.format(port))

    import threading
    threading.Thread(target=httpd.serve_forever, daemon=True).start()

    # 排除明显会 SKIP 的非默认端口情况：全部插件声明 [80,443,8080,8443]
    if port not in [80, 443, 8080, 8443]:
        use_override = True
    else:
        use_override = False

    rng = random.Random(args.seed)
    picked = rng.sample(manifest, min(args.samples, len(manifest)))
    outcomes = {'vuln': 0, 'safe': 0, 'warn': 0, 'skip': 0}
    bad_rows = []
    t0 = time.time()
    for entry in picked:
        fpath = CORPUS / entry['file']
        mod_name = 'smoke_plg_' + entry['cve'].replace('-', '_')
        plg = load_plugin(str(fpath), mod_name)
        if use_override and port not in plg.info.ports:
            plg.info.ports = plg.info.ports + [port]
        url = 'http://127.0.0.1:{}'.format(port)
        try:
            row = plg.do_testing(url)
        except Exception:
            bad_rows.append((entry['file'], 'EXCEPTION: ' + traceback.format_exc()[-300:]))
            continue
        if row['OUTCOME'] not in ('vuln', 'safe', 'warn', 'skip'):
            bad_rows.append((entry['file'], 'BAD OUTCOME ' + str(row['OUTCOME'])))
            continue
        outcomes[row['OUTCOME']] += 1
        print('  {:40s} -> {}'.format(entry['cve'], row['OUTCOME']))
    smoke_dt = time.time() - t0
    print('== smoke ==')
    print('samples={} outcomes={} bad={} elapsed={:.1f}s'.format(
        len(picked) - len(bad_rows), outcomes, len(bad_rows), smoke_dt))
    print('mock requests received={} methods={}'.format(Handler.requests_seen, Handler.methods_seen))
    for f, why in bad_rows[:10]:
        print('  BAD {}: {}'.format(f, why))
    # ---- 3) 正向命中验证: matcher 真能报 vuln（不只 safe）----
    # 选 read_only + GET/HEAD 的插件若干, 把它们自己的 matcher 词灌入 mock 响应体/头,
    # 断言这些插件在该 sink 响应对下报 vuln（验证 word/regex/status 判定路径）
    pos_cands = []
    for entry in manifest:
        if entry['risk_class'] != 'read_only' or len(pos_cands) >= 10:
            continue
        try:
            spec = importlib.util.spec_from_file_location('pos_' + entry['cve'].replace('-', '_'),
                                                          str(CORPUS / entry['file']))
            m = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(m)
        except Exception:
            continue
        reqs = getattr(m, 'REQS', [])
        mats = getattr(m, 'MATCHERS', [])
        if not reqs or any(r.get('method') not in ('GET', 'HEAD') for r in reqs):
            continue
        if not mats:
            continue
        pos_cands.append((entry, m))
    sink_words = []
    for entry, m in pos_cands:
        for mt in m.MATCHERS:
            for w in mt.get('words', []) or []:
                if isinstance(w, str) and 1 < len(w) <= 200:
                    sink_words.append(w)
            for rx in mt.get('regex', []) or []:
                if isinstance(rx, str) and 1 < len(rx) <= 200:
                    sink_words.append(rx)
    sink = '\n'.join(sink_words[:4000])
    Handler.body_override = sink
    Handler.header_override = sink
    pos_vuln = []
    pos_miss = []
    t_pos = time.time()
    for entry, m in pos_cands:
        plg = load_plugin(str(CORPUS / entry['file']), 'posrun_' + entry['cve'].replace('-', '_'))
        if use_override and port not in plg.info.ports:
            plg.info.ports = plg.info.ports + [port]
        row = plg.do_testing('http://127.0.0.1:{}'.format(port))
        if row['OUTCOME'] == 'vuln':
            pos_vuln.append(entry['cve'])
        else:
            pos_miss.append((entry['cve'], row['OUTCOME']))
    Handler.body_override = None
    Handler.header_override = None
    print('\n== positive-path (matcher 命中验证, kitchen-sink mock) ==')
    print('candidates={} vuln_hits={} elapsed={:.1f}s'.format(
        len(pos_cands), len(pos_vuln), time.time() - t_pos))
    print('vuln_cves: {}'.format(pos_vuln))
    print('miss: {}'.format(pos_miss[:6]))
    smoke_ok = not bad_rows
    positive_ok = len(pos_vuln) >= max(1, len(pos_cands) // 2)
    httpd.shutdown()
    print('ALL_SMOKE_OK={} POSITIVE_OK={}'.format(smoke_ok, positive_ok))

    # 写验证结果供 REPORT.md 嵌入
    vrep = {
        'import_total': len(manifest),
        'import_pass': ok,
        'import_fail': len(fails),
        'info_bad': len(info_bad),
        'import_elapsed_s': round(dt, 2),
        'smoke_samples': len(picked),
        'smoke_outcomes': outcomes,
        'smoke_bad': len(bad_rows),
        'smoke_elapsed_s': round(smoke_dt, 2),
        'mock_requests': Handler.requests_seen,
        'mock_methods': Handler.methods_seen,
        'positive_candidates': len(pos_cands),
        'positive_vuln': len(pos_vuln),
        'positive_cves': pos_vuln,
        'positive_miss': [c for c, _ in pos_miss],
    }
    with open(CORPUS / 'verify_report.json', 'w', encoding='utf-8') as fh:
        json.dump(vrep, fh, ensure_ascii=False, indent=1)
    print('verify_report.json written')


if __name__ == '__main__':
    main()