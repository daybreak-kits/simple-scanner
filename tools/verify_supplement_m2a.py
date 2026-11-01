#!/usr/bin/env python3
# _*_ coding:utf-8 _*_
"""
verify_supplement_m2a.py — plugins_corpus/supplement/ 本地 mock 验证
按任务卡: py_compile + import + Info 完整 + 对本地 mock HTTP/TCP 跑 do_testing,
OUTCOME ∈ 四态; 参数化插件无参时断言 WARN / 明确 False 信息。

用法: cd /opt/workspace/labs/simple-scanner && .venv/bin/python tools/verify_supplement_m2a.py
"""
import gc
import http.server
import importlib.util
import pathlib
import py_compile
import re
import socket
import sys
import threading
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent
SUP = ROOT / 'plugins_corpus/supplement'
sys.path.insert(0, str(ROOT))

MOCKS = {}  # port -> responder(state, method, path, headers, data) -> (status, headers, body bytes)
HTTP_SERVERS = {}


class MockHTTP(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def _handle(self):
        length = int(self.headers.get('Content-Length') or 0)
        body = self.rfile.read(length) if length else b''
        fn = MOCKS.get(self.server.server_address[1])
        if fn is None:
            self.send_response(404)
            self.end_headers()
            return
        try:
            status, hdrs, out = fn(self.command, self.path, self.headers, body)
        except Exception as e:  # noqa: BLE001
            status, hdrs, out = 500, {}, ('handler-error ' + repr(e)).encode()
        self.send_response(status)
        for k, v in (hdrs or {}).items():
            self.send_header(k, v)
        self.send_header('Content-Length', str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    def do_GET(self):
        self._handle()

    def do_POST(self):
        self._handle()

    def do_HEAD(self):
        self._handle()

    def log_message(self, *a):
        pass


def start_mock(port, responder):
    if port in HTTP_SERVERS:
        return HTTP_SERVERS[port]  # 复用同端口服务, 换 responder
    srv = http.server.ThreadingHTTPServer(('127.0.0.1', port), MockHTTP)
    HTTP_SERVERS[port] = srv
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    MOCKS[port] = responder
    return srv


def stop_all_mocks():
    for port, srv in list(HTTP_SERVERS.items()):
        try:
            srv.shutdown()
            srv.server_close()
        except Exception:  # noqa: BLE001
            pass
    HTTP_SERVERS.clear()
    MOCKS.clear()
    time.sleep(0.15)


TCP_STOP = []


def start_tcp_mock(port, resp_bytes):
    lis = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    lis.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    lis.bind(('127.0.0.1', port))
    lis.listen(4)
    stop = threading.Event()

    def loop():
        while not stop.is_set():
            try:
                lis.settimeout(0.4)
                conn, _ = lis.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            conn.settimeout(3)
            try:
                conn.recv(2048)  # handshake
                conn.sendall(b'HELO.beef\n')
                conn.recv(4096)  # probe1
                conn.sendall(b'\x00\x00\x00\x00')
                conn.recv(4096)  # probe2
                conn.sendall(resp_bytes)
            except Exception:  # noqa: BLE001
                pass
            finally:
                try:
                    conn.close()
                except OSError:
                    pass

    t = threading.Thread(target=loop, daemon=True)
    t.start()
    TCP_STOP.append(stop)
    return lis, stop


def stop_tcp_mocks():
    for stop in TCP_STOP:
        stop.set()
    TCP_STOP.clear()


def load_plugin(cve):
    path = SUP / '{}.py'.format(cve)
    py_compile.compile(str(path), doraise=True)
    spec = importlib.util.spec_from_file_location('sup_' + cve, str(path))
    mod = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod.Plugin()


def run_do_testing(plg, url, data=None):
    rec = plg.do_testing(url, data or {})
    return rec['OUTCOME'], rec['DATA']


B = lambda s: s.encode() if isinstance(s, str) else s


# ---- mock responders -------------------------------------------------------
def log4j_responder(method, path, headers, body):
    htxt = ' '.join('{}:{}'.format(k, v) for k, v in headers.items())
    if 'jndi' in path or 'jndi' in htxt.lower():
        return 503, {'Content-Type': 'text/html'}, B('Error: javax.naming.NamingException: log4j Lookup failed [LDAP lookup failed]')
    return 200, {}, B('<html>app ok</html>')


def spring_responder(method, path, headers, body):
    if method == 'POST':
        return 500, {'Content-Type': 'text/html'}, B('org.springframework... nested exception is java.lang.IllegalStateException: class.module.classLoader...')
    return 200, {}, B('<html>index</html>')


def confluence26_responder(method, path, headers, body):
    if method == 'POST' and 'createpage-entervariables' in path:
        return 200, {}, B('<input name="queryString" value="aaaa{140592=null}" type="text"> conflict=16*8787')
    return 404, {}, b'not found'


def confluence34_responder(method, path, headers, body):
    if path.startswith('/%24%7B') and ('whoami' in path or 'nslookup' in path):
        return 200, {'X-Cmd-Response': 'root'}, B('Confluence response body')
    return 404, {}, b'not found'


def weblogic_responder(expect_admin):
    def r(method, path, headers, body):
        if '/console/images/' in path:
            if expect_admin:
                return 200, {'Set-Cookie': 'ADMINCONSOLESESSION=abc123; path=/'}, B('console ok')
            return 200, {}, B('console page, no cookie')
        return 404, {}, b'not found'
    return r


def moveit_responder(method, path, headers, body):
    if method == 'GET' and path == '/':
        return 200, {}, B('<title>MOVEit Transfer</title>')
    if method == 'POST' and '/moveitisapi/' in path:
        text = ' '.join('{}:{}'.format(k, v) for k, v in headers.items()) + ' ' + (body or b'').decode('latin-1', 'ignore')
        if 'SQL Injection' in text:
            return 500, {'Content-Type': 'text/html'}, B('System.Data.SqlClient.SqlException: Incorrect syntax near the keyword \';\' at moveitisapi')
        return 200, {}, B('{"status":"ok"}')
    return 404, {}, b'not found'


def moveit_neg_responder(method, path, headers, body):
    if method == 'GET' and path == '/':
        return 200, {}, B('<title>MOVEit Transfer</title>')
    if method == 'POST' and '/moveitisapi/' in path:
        return 200, {}, B('{"status":"ok"}')
    return 404, {}, b'not found'


def panos_responder(state):
    def r(method, path, headers, body):
        m = re.match(r'^/global-protect/portal/images/([a-z]+\.txt)$', path)
        if m:
            name = m.group(1)
            if name in state['seen']:
                return 403, {}, B('forbidden')
            state['seen'].add(name)
            return 404, {}, B('no file')
        if method == 'POST' and path == '/ssl-vpn/hipreport.esp':
            return 200, {}, B('invalid required input parameters')
        return 404, {}, b'not found'
    return r


def citrix_responder(method, path, headers, body):
    if path.startswith('/oauth/idp/.well-known/openid-configuration'):
        leak = 'a' * 100 + '45525d5f4f58455e445a4a42'
        return 200, {'Content-Type': 'application/json'}, B('{"issuer":"https://x"} NSC_AAAC=deadbeef HTTP/1.1 200 OK leaked=' + leak)
    if '/logon/LogonPoint/Authentication/GetUserName' in path:
        return 200, {}, B('Success username: admin@corp')
    return 404, {}, b'not found'


def xjs_responder(method, path, headers, body):
    return 200, {}, B('x.js')


def ok_always(method, path, headers, body):
    """非回显应用: 即使收到 JNDI/configFile 载荷也返回 200 正常页（用于降级路径 False 断言）"""
    return 200, {}, B('<html>app ok, no reflected error</html>')


# ---- 用例表: (cve, url, data, expected_outcome, data_substr, note, responder_or_None, port) ----
# 2026-10-26 用户裁决: 版本型 POC 无意义 -> CVE-2026-109618/109619 已从 supplement/ 删除, 断言随之移除(skip)
CASES = [
    ('CVE-2021-44228', 'http://127.0.0.1:8080/', {'oob_domain': 'cb.example.com'}, 'vuln', 'error-based signal', 'params oob + error-based degrade', log4j_responder, 8080),
    ('CVE-2022-22965', 'http://127.0.0.1:8080/', {'oob_domain': 'cb.example.com'}, 'vuln', 'error-based signal', 'params oob + error-based degrade', spring_responder, 8080),
    ('CVE-2021-26084', 'http://127.0.0.1:8080/', {}, 'vuln', 'OGNL arithmetic oracle', 'read_only', confluence26_responder, 8080),
    ('CVE-2022-26134', 'http://127.0.0.1:8080/', {}, 'vuln', 'X-Cmd-Response', 'read_only whoami id-probe', confluence34_responder, 8080),
    ('CVE-2020-14882', 'http://127.0.0.1:8080/', {'oob_domain': 'cb.example.com'}, 'vuln', 'ADMINCONSOLESESSION', 'params oob + traversal signal', weblogic_responder(True), 8080),
    ('CVE-2018-2628', 't3://127.0.0.1:7001/', {}, 'vuln', 'T3 deserialization proof', 'read_only t3/tcp', 'TCP', 7001),
    ('CVE-2021-26855', 'http://127.0.0.1:8443/', {'oob_domain': 'cb.example.com'}, 'safe', 'SSRF single-leg probe sent', 'params oob (no local positive by design)', xjs_responder, 8443),
    ('CVE-2023-34362', 'http://127.0.0.1:80/', {}, 'vuln', 'error-based signal', 'read_only error-probe', moveit_responder, 80),
    ('CVE-2024-3400', 'http://127.0.0.1:80/', {}, 'vuln', 'file-artifact probe matched', 'intrusive file-write (NOT read_only)', panos_responder({'seen': set()}), 80),
    ('CVE-2023-4966', 'http://127.0.0.1:443/', {}, 'vuln', 'memory-leak proof', 'read_only', citrix_responder, 443),
]

NEG_EXTRAS = [
    # param 插件无参: do_testing → WARN; direct run()（非回显 mock → 无错误信号）→ (False, 'no OOB configured...')
    ('CVE-2021-44228', 'http://127.0.0.1:8080/', ok_always),
    ('CVE-2022-22965', 'http://127.0.0.1:8080/', ok_always),
    ('CVE-2020-14882', 'http://127.0.0.1:8080/', weblogic_responder(False)),
    ('CVE-2021-26855', 'http://127.0.0.1:8443/', xjs_responder),
]


def main():
    print('== 1) py_compile + import + Info 完整性 ==')
    infos, ok = {}, True
    for f in sorted(SUP.glob('*.py')):
        cve = f.stem
        try:
            plg = load_plugin(cve)
            info = plg.info
            errs = []
            if not info.protocol:
                errs.append('protocol empty')
            if not info.port:
                errs.append('port empty')
            if not info.ports:
                errs.append('ports empty')
            if errs:
                ok = False
                print('  FAIL {}: {}'.format(cve, errs))
            else:
                print('  OK   {} protocol={} port={} ports={} params={}'.format(cve, info.protocol, info.port, sorted(info.ports), info.params))
            infos[cve] = plg
        except Exception as e:  # noqa: BLE001
            ok = False
            print('  FAIL {} (import/compile): {!r}'.format(cve, e))

    print()
    print('== 2) 本地 mock do_testing（正例断言 vuln 路径可达） ==')
    results = []
    try:
        for cve, url, data, exp, substr, note, resp, port in CASES:
            base = cve[:-4] if cve.endswith('-NEG') else cve
            plg = infos[base]
            if resp == 'TCP':
                srv, stop = start_tcp_mock(port, b'\x00\x00$Proxy114\x00\x00')
            else:
                start_mock(port, resp)
            outcome, d = run_do_testing(plg, url, data)
            stop_all_mocks()
            stop_tcp_mocks()
            hit = (outcome == exp) and (substr in d)
            results.append((cve, note, outcome, d, hit))
            print('  {} {} -> OUTCOME={} | {} | {}'.format('PASS' if hit else 'FAIL', cve, outcome, note, d[:95]))
    finally:
        stop_all_mocks()
        stop_tcp_mocks()

    print()
    print('== 3) 参数化插件: 无参 do_testing → WARN; direct run() → 明确 False 信息 ==')
    try:
        for cve, url, resp in NEG_EXTRAS:
            plg = infos[cve]
            rec = plg.do_testing(url, {})
            ok_warn = rec['OUTCOME'] == 'warn' and 'missing required param(s): oob_domain' in rec['DATA']
            start_mock(8443 if cve == 'CVE-2021-26855' else 8080, resp)
            from utils import urlutil
            u = urlutil.Url(url)
            direct = plg.run(u)
            stop_all_mocks()
            ok_direct = isinstance(direct, tuple) and direct[0] is False and 'no OOB configured, manual check required' in str(direct)
            print('  {} {} | do_testing: OUTCOME={} ({}), direct run()={!r} -> {}'.format(
                'PASS' if (ok_warn and ok_direct) else 'FAIL', cve, rec['OUTCOME'], 'WARN-ok' if ok_warn else 'BAD', direct, 'False-ok' if ok_direct else 'BAD'))
            if not (ok_warn and ok_direct):
                ok = False
    finally:
        stop_all_mocks()

    print()
    print('== 4) 每插件一行验证结果表 ==')
    for cve, note, outcome, d, hit in results:
        print('{:<16} | {:<36} | OUTCOME={:<7} | {:<70} | {}'.format(cve, note, outcome, d[:70], 'PASS' if hit else 'FAIL'))
    allpass = ok and len(results) == len(CASES) and all(h for _, _, _, _, h in results)
    print('== summary: {} =='.format('ALL PASS' if allpass else 'SOME FAIL'))


if __name__ == '__main__':
    main()