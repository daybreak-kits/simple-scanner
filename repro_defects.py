#!/usr/bin/env python3
"""simple-scanner defect regression matrix — VERIFY-FIX semantics.

Formerly a defect-reproduction matrix: every check probed the *shipped* code
and FAIL meant "defect reproduced". After Phase 0 the defects are fixed, so
every check now asserts the fix HOLDS — FAIL means "defect regressed".
Two consecutive identical runs must both be 8/8.

D1  CIDR / 范围 / 逗号目标不再塌成 1 个 host（I4）
D2  显式协议目标（含默认端口）经真实引擎路径送达插件，协议+端口原样保留（I1，真跑 ss.py 分发）
D3  协议不匹配的目标不再被静默丢弃，引擎记 SKIP 并打印原因（I3）
D4  协议门控生效：http 插件在 http 端口运行、在 redis 端口 SKIP（P1）
D5  插件异常独立成 WARN，不再与「未检出」同义（O1）
D6  端口探测 socket 路径 fd 卫生：open/closed/timeout 各 100 次后 fd delta==0（X4 相关）
D7  空结果不再触发 save_csv 崩溃（O2）
D8  spawn 进程池退出码 0、无 LoopExit，结果行数与提交任务数守恒（X1）

Run:  .venv/bin/python repro_defects.py
"""
import json
import os
import pathlib
import re
import subprocess
import sys
import time

DEFAULT_BASE = pathlib.Path(__file__).resolve().parent
# REPRO_BASE / REPRO_PY 把回归矩阵指向另一棵树（对照穿透用，如对接 stash 旧树）；
# 默认 PY 恒为当前仓库 venv，旧树无需自带 .venv。
BASE = pathlib.Path(os.environ.get('REPRO_BASE') or DEFAULT_BASE)
PY = os.environ.get('REPRO_PY') or str(DEFAULT_BASE / '.venv/bin/python')
# --only=CID（或 REPRO_ONLY=CID）：只执行到该检查为止，供对照穿透只跑目标项
ONLY = ''
if len(sys.argv) > 1 and sys.argv[1].startswith('--only='):
    ONLY = sys.argv[1].split('=', 1)[1]
ONLY = ONLY or os.environ.get('REPRO_ONLY', '')
RESULTS = []


def record(cid, title, reproduced, detail):
    """reproduced == True 表示缺陷仍然存在/回归（对应旧文件的 FAIL）。"""
    RESULTS.append((cid, title, reproduced, detail))
    print('  [%s] %-4s %s' % (cid, 'FAIL' if reproduced else 'ok', title))
    for line in detail.splitlines():
        print('         ' + line)


def run_ss(args, timeout=180):
    return subprocess.run([PY, 'ss.py'] + args, cwd=str(BASE),
                          capture_output=True, text=True, timeout=timeout)


def cleanup(base=None):
    base = base or BASE
    for pat in ('hosts-info-*.csv', 'hosts-plugin-result-*.csv', 'hosts-plugin-result-*.json',
                'hosts-plugin-result-*-warn.csv', 'hosts-plugin-result-*-skip.csv'):
        for f in base.glob(pat):
            f.unlink()


def make_plugin(name, port, body, catalog=None, requires=None):
    plugin_requires = requires if requires is not None else ['http', 'https']
    path = BASE / 'plugins' / ('zzprobe_%s.py' % name)
    path.write_text('''import pathlib, sys
from typing import Any, Tuple
try:
    from utils import PLUGIN_TYPE, plugin, urlutil
except:
    sys.path.append(pathlib.Path(__file__).parent.parent.__str__())
    from utils import PLUGIN_TYPE, plugin, urlutil


class Plugin(plugin.PluginBase):
    def set_info(self):
        return plugin.Info(name='{name}', catalog='{catalog}', itype=PLUGIN_TYPE.POC,
                           protocol='http', port={port}, ssl_protocol='https', ssl_port={port},
                           requires={requires!r})

    def run(self, url: urlutil.Url, *args, **kwargs) -> Tuple[bool, Any]:
{body}
'''.format(name=name, catalog=catalog or name, port=port, requires=plugin_requires,
           body='\n'.join('        ' + l for l in body.strip().splitlines())))
    return path


def drop_plugin(name):
    (BASE / 'plugins' / ('zzprobe_%s.py' % name)).unlink(missing_ok=True)


def listening_server(ports, marker=None):
    for f in pathlib.Path('/tmp').glob('_repro_counters.json'):
        f.unlink()
    p = subprocess.Popen([PY, str(BASE / 'tools' / 'probe_server.py')] + [str(x) for x in ports],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1.5)
    return p


def read_counters():
    f = pathlib.Path('/tmp/_repro_counters.json')
    if not f.exists():
        return None
    d = json.loads(f.read_text())
    f.unlink()
    return d


def start_redis_server(ports):
    """启动临时 redis 模拟服务器（子进程，/tmp/_redis_server.py；语义同 verify_phase0.py）。

    用子进程避免 gevent monkey.patch_all 环境下 daemon 线程里 gevent socket accept
    抛 'Cannot switch to a different thread'。返回 Popen 句柄（与 listening_server 同构）。
    """
    p = subprocess.Popen([PY, '/tmp/_redis_server.py'] + [str(x) for x in ports],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1.5)
    return p


# ---------------------------------------------------------------- D1
print('\n== D1  target list parsing: CIDR / ranges / commas (fixed) ==')
sys.path.insert(0, str(BASE))
from gevent import monkey  # noqa: E402
monkey.patch_all(thread=False, httplib=True)
from utils import urlutil  # noqa: E402


def hosts_after_ss_parse(targets):
    """Replicates the FIXED ss.py parse: parse_target_ports splits host/ports,
    host string passes through to network.Scanner.parse_address for expansion."""
    from utils import network
    scanner = network.Scanner()
    total = 0
    detail = []
    for t in targets:
        host, ports = urlutil.parse_target_ports(t)
        n = len(scanner.parse_address(host))
        total += n
        detail.append('%r -> %d' % (host, n))
    return total, detail


cases = [
    ('127.0.0.0/24',          256, 'a /24 should be 256 hosts'),
    ('127.0.0.1-127.0.0.50',  50,  'an IP range should be 50 hosts'),
    ('127.0.0.1,127.0.0.2',   2,   'comma-separated on the CLI should be 2 hosts'),
    ('127.0.0.1',             1,   'a single IP should be 1 host'),
]
bad = []
for target, want, why in cases:
    try:
        got, detail = hosts_after_ss_parse([target])
    except Exception as err:
        bad.append('%-24s -> CRASH: %s: %s' % (target, type(err).__name__, err))
        continue
    if got != want:
        bad.append('%-24s -> %d host(s), expected %d  (%s)  [%s]'
                   % (target, got, want, why, '; '.join(detail)))
record('D1', 'CIDR / comma target lists collapse to one host (regressed)',
       bool(bad), '\n'.join(bad) if bad else 'all forms expand correctly')

# ---------------------------------------------------------------- D2
print('\n== D2  protocol://host target survives the real engine path with port+protocol (fixed) ==')


def _d2_plugin(marker):
    """写一个旧/新引擎都兼容的 ssh 探针插件（不声明 ports/params，旧版 Info 同样接受）。"""
    (BASE / 'plugins' / 'zzprobe_d2.py').write_text('''import pathlib, sys
from typing import Any, Tuple
try:
    from utils import PLUGIN_TYPE, plugin, urlutil
except:
    sys.path.append(pathlib.Path(__file__).parent.parent.__str__())
    from utils import PLUGIN_TYPE, plugin, urlutil


class Plugin(plugin.PluginBase):
    def set_info(self):
        return plugin.Info(name='zzd2', catalog='ZZD2', itype=PLUGIN_TYPE.POC,
                           protocol='ssh', port=22, ssl_protocol='ssh', ssl_port=22)

    def run(self, url: urlutil.Url, *args, **kwargs) -> Tuple[bool, Any]:
        with open({marker!r}, 'a') as f:
            f.write('proto=%r|port=%r|path=%r\\n' % (url.protocol, url.port, url.path))
        return False, 'probe'
'''.format(marker=str(marker)))


def _d2_leg(label, target, port, marker, timeout=120):
    """跑一次真实 ss.py 引擎（端口扫描开启、spawn 池），断言插件收到的协议/端口与目标一致。"""
    import csv as _csv
    marker.unlink(missing_ok=True)
    for f in BASE.glob('hosts-plugin-result-*.csv'):
        f.unlink()
    srv = None
    try:
        srv = listening_server((port,))
        if srv.poll() is not None:
            return '%s: listener on %d failed to start (exit=%r), environment issue' % (label, port, srv.returncode)
        r = run_ss(['-t', target, '-p', '1', '-is', '-m', 'zzd2'], timeout=timeout)
        got = marker.read_text().strip() if marker.exists() else '<plugin never ran>'
        exp = "proto='ssh'|port=%d|path='/'".replace("'", chr(39)) % port
        if got != exp:
            return '%s: plugin received %r (expected %r)' % (label, got, exp)
        # 结果行（经进程池回传）也应携带引擎侧 PROTOCOL/PORT，与插件收到的一致
        rows = []
        for f in BASE.glob('hosts-plugin-result-*.csv'):
            rows += list(_csv.DictReader(open(f, encoding='utf_8_sig')))
        row = rows[0] if rows else {}
        if (row.get('PROTOCOL'), row.get('PORT')) != ('ssh', str(port)):
            return '%s: result row PROTOCOL=%r PORT=%r, expected ssh/%d' % (
                label, target, row.get('PROTOCOL'), row.get('PORT'), port)
        return ''
    finally:
        if srv is not None:
            srv.terminate(); srv.wait()
        cleanup(BASE)


def _d2_check():
    """D2 真引擎断言（替换旧的自比 key_port/alive_port=u.port）：起本地真实监听 socket，
    ssh:// 目标走 ss.py 解析/分发/进程池，断言插件收到的端口与目标端口一致、协议为 ssh。
    两个腿：
      L1 默认端口腿 ssh://127.0.0.1:22 —— I1 关键场景（旧引擎 netloc 丢默认端口、目标被重建）；
      L2 随机高端口腿 ssh://127.0.0.1:PORT —— 非默认端口场景，证明引擎路径真的在跑。
    旧引擎在 L1 会失败（目标被重建为裸 host:port，协议丢失）。
    """
    import socket as _socket
    s = _socket.socket()
    s.bind(('127.0.0.1', 0))
    hp = s.getsockname()[1]
    s.close()
    marker = pathlib.Path('/tmp/_repro_d2.txt')
    _d2_plugin(marker)
    fails = []
    try:
        for label, target, port in (('L1-default-port', 'ssh://127.0.0.1:22', 22),
                                    ('L2-random-port', 'ssh://127.0.0.1:%d' % hp, hp)):
            err = _d2_leg(label, target, port, marker)
            if err:
                fails.append(err)
    finally:
        (BASE / 'plugins' / 'zzprobe_d2.py').unlink(missing_ok=True)
    record('D2', 'targets written with an explicit protocol/port are silently dropped or lose protocol on the way to the plugin (regressed)',
           bool(fails), '\n'.join(fails) if fails else 'both legs: plugin received proto=ssh and the target port via the real engine path (default port 22 + random high port)')
    if ONLY:
        print('  [--only=%s] control mode: stop after D2 (exit 1 = 该项在对照树复现缺陷)' % ONLY)
        sys.exit(1 if fails else 0)


_d2_check()

# ---------------------------------------------------------------- D3
print('\n== D3  protocol gate: no silent drop, SKIP with reason (fixed) ==')
make_plugin('proto', 18260, "print('CALL proto', flush=True)\nreturn False, 'probe'", catalog='PROTO')
try:
    cleanup()
    r = run_ss(['-t', 't3://127.0.0.1:18260', '-dps', '-p', '1', '-m', 'PROTO'])
    out = r.stdout + r.stderr
    called = 'CALL proto' in out
    skips = re.search(r'plugin outcome summary: [^\n]*SKIP=(\d+)', out)
    reason = 'protocol "t3"' in out
    record('D3', 'non-http(s) target protocol is silently dropped without trace (regressed)',
           called or not (skips and int(skips.group(1)) >= 1) or not reason,
           'called=%s  SKIP=%s  reason-printed=%s' % (called, skips.group(1) if skips else '?', reason))
finally:
    drop_plugin('proto')
    cleanup()

# ---------------------------------------------------------------- D4
print('\n== D4  protocol gate: http plugin runs on http port, SKIPs on redis port (fixed) ==')
# 协议门控（requires 语义）：端口号不参与适用性判定。
# 一个 http 插件在 http 端口跑 1 次；在 redis 端口被门控不跑且落 SKIP 记录。
HTTP_PORT, REDIS_PORT = 18251, 18252
make_plugin('gate', HTTP_PORT,
            "print('INVOKED gate -> {}'.format(url.get_full()), flush=True)\nreturn False, 'probe'",
            catalog='GATE')
srv = listening_server((HTTP_PORT,))
redis_srv = start_redis_server((REDIS_PORT,))
try:
    r = run_ss(['-t', '127.0.0.1:%d,%d' % (HTTP_PORT, REDIS_PORT), '-p', '1', '-is', '-m', 'GATE'])
    out = r.stdout + r.stderr
    hits = [l for l in out.splitlines() if l.startswith('INVOKED')]
    skips = re.search(r'plugin outcome summary: [^\n]*SKIP=(\d+)', out)
    regressed = len(hits) != 1 or not (skips and int(skips.group(1)) >= 1)
    record('D4', 'plugin runs on a service it does not require, no protocol gate (regressed)',
           regressed,
           'http-port invocations=%d (want 1)  redis-port SKIP=%s (want >=1)' % (len(hits), skips.group(1) if skips else '?'))
finally:
    srv.terminate(); srv.wait()
    redis_srv.terminate(); redis_srv.wait()
    drop_plugin('gate')
    cleanup()

# ---------------------------------------------------------------- D5
print('\n== D5  plugin exception recorded as WARN, not "not vulnerable" (fixed) ==')
make_plugin('boom', 18260, "raise RuntimeError('plugin crashed while parsing response')")
try:
    r = run_ss(['-t', '127.0.0.1:18260', '-dps', '-p', '1', '-is', '-m', 'boom'])
    rows = []
    for f in BASE.glob('hosts-plugin-result-*.csv'):
        import csv
        rows += list(csv.DictReader(open(f, encoding='utf_8_sig')))
    row = rows[0] if rows else {}
    has_tb = 'Traceback' in (row.get('DATA') or '')
    warn_files = list(BASE.glob('hosts-plugin-result-*-warn.csv'))
    regressed = (row.get('OUTCOME') or '').lower() != 'warn' or not has_tb or not warn_files
    record('D5', 'a crashing plugin yields IS_EXIST=False, indistinguishable from "not vulnerable" (regressed)',
           regressed,
           'OUTCOME=%r  traceback=%s  warn-file=%s  IS_EXIST=%r'
           % (row.get('OUTCOME'), has_tb, bool(warn_files), row.get('IS_EXIST')))
finally:
    drop_plugin('boom')
    cleanup()

# ---------------------------------------------------------------- D6
print('\n== D6  port-probe socket path: fd hygiene（fd 泄漏前提在本平台不成立，改为卫生检查）==')
from utils import network as netmod  # noqa: E402
srv = listening_server((18270,))
try:
    def fd_count():
        return len([x for x in pathlib.Path('/proc/self/fd').iterdir()])

    probe = netmod.Scanner.handle_tcp_socket
    # 预热：DNS/import/连接池惰性分配先落地，避免统计首轮噪声（3 态 × 30 次）
    for _ in range(30):
        probe('127.0.0.1', 18270, timeout=0.25)   # open
        probe('127.0.0.1', 1, timeout=0.25)       # closed -> RST
        probe('192.0.2.1', 9, timeout=0.25)       # timeout -> filtered
    before = fd_count()
    deltas = {}
    for label, ip, port in (('open', '127.0.0.1', 18270),
                            ('closed', '127.0.0.1', 1),
                            ('timeout', '192.0.2.1', 9)):
        probe(ip, port, timeout=0.25)   # 状态内再落地两次惰性分配
        probe(ip, port, timeout=0.25)
        start = fd_count()
        for _ in range(100):
            probe(ip, port, timeout=0.25)
        deltas[label] = fd_count() - start
    after = fd_count()
    leaked = after - before
    detail = 'per-state fd delta after 100 probes: open=%+d closed=%+d timeout=%+d; total before=%d after=%d delta=%+d (300 probes)' % (
        deltas['open'], deltas['closed'], deltas['timeout'], before, after, leaked)
    # 真实泄漏会随轮次线性增长；严格断言 delta==0（审计实测 460 次探针 delta=0）
    detail += '\n  Linux + gevent 实测通过；Windows 行为未验，列为平台待验项'
    record('D6', 'port-probe socket fd hygiene: 100 probes each (open/closed/timeout) must leave fd delta 0 (regressed)',
           leaked != 0 or any(deltas.values()), detail)
finally:
    srv.terminate(); srv.wait()

# ---------------------------------------------------------------- D7
print('\n== D7  empty results: save_csv([]) no-op, scan exits 0 (fixed) ==')
sys.path.insert(0, str(BASE))
from utils import save_csv  # noqa: E402
empty_target = pathlib.Path('/tmp/_repro_empty.csv')
empty_target.unlink(missing_ok=True)
save_csv([], empty_target)
no_crash = not empty_target.exists()
cleanup()
# 全 closed 端口集 → 无开放端口 → 空结果路径（防火墙场景同款）
r = run_ss(['-t', '127.0.0.1:1', '-p', '1', '-is'])
err = [l for l in r.stderr.splitlines() if 'Error' in l]
record('D7', 'an empty port-scan result crashes save_csv (unhandled IndexError) (regressed)',
       (not no_crash) or any('IndexError' in l for l in err) or r.returncode != 0,
       'save_csv([]) no-op=%s  exit=%d  %s' % (no_crash, r.returncode, err[-1].strip() if err else 'no traceback'))
cleanup()

# ---------------------------------------------------------------- D8
print('\n== D8  spawn process pool: exit 0, no LoopExit, result count == submitted count (fixed) ==')
# X1 纯断言：不再涉及「LIFO 归因错位」（旧记录自带 URL/HOST/PORT，错位叙事已删除）
for i, p in enumerate((18460, 18461, 18462)):
    make_plugin('x1%d' % i, p,
                "print('INVOKED x1%d', flush=True)\nreturn False, 'DATA-%d'" % (i, p),
                catalog='X1%d' % i, requires=['http', 'https'])
srv = listening_server((18460, 18461, 18462))
try:
    r = run_ss(['-t', '127.0.0.1:18460-18462', '-p', '1', '-is', '-m', 'X10', 'X11', 'X12'])
    invocations = [l for l in (r.stdout + r.stderr).splitlines() if l.startswith('INVOKED')]
    import csv as _csv
    rows = []
    for f in BASE.glob('hosts-plugin-result-*.csv'):
        rows += list(_csv.DictReader(open(f, encoding='utf_8_sig')))
    submitted = 3 * 3   # 3 插件 × 3 开放端口（requires=['http','https'] 全适用 → 全量笛卡尔积，旧端口门控下每插件只跑声明端口）
    regressed = (r.returncode != 0
                 or 'LoopExit' in (r.stdout + r.stderr)
                 or len(rows) != submitted
                 or len(invocations) != submitted)
    detail = 'exit=%d  LoopExit=%s  invocations=%d  result-rows=%d  submitted=%d' % (
        r.returncode, 'LoopExit' in (r.stdout + r.stderr), len(invocations), len(rows), submitted)
    record('D8', 'spawn pool crashes with LoopExit or loses/duplicates result rows on exit (regressed)',
           regressed, detail)
finally:
    srv.terminate(); srv.wait()
    for i in range(3):
        drop_plugin('x1%d' % i)
    cleanup()

# ---------------------------------------------------------------- summary
print('\n' + '=' * 78)
repro = [r for r in RESULTS if r[2]]
print('defects still reproduced: %d / %d  (0 = all fixed)' % (len(repro), len(RESULTS)))
for cid, title, ok, _ in RESULTS:
    print('  %-4s %s  %s' % (cid, 'FAIL' if ok else 'ok  ', title))
out = BASE / 'repro-report.json'
out.write_text(json.dumps([{'id': c, 'title': t, 'reproduced': o} for c, t, o, _ in RESULTS], indent=2))
print('\nwritten: %s' % out)
# 退出码接 CI（审计 F2）：有缺陷复现即非 0，否则 0。
sys.exit(1 if repro else 0)
