#!/usr/bin/env python3
"""Phase 0 acceptance gate (post-fix semantics).

Each check asserts the *fixed* Phase-0 contract (UPGRADE_PLAN.md §6 Phase 0).
Before Phase 0 all fail; after Phase 0 all must pass. Exit code 0 only when
every check passes. Deterministic and, except as listed, loopback-only:
  - C1  expands 192.168.250.0/24 (RFC1918 private range, port 80 only) and asserts the
    CIDR expansion count (256); the connect results inside the range are not asserted.
    理由：显式端口让 256-host 扫描快速完成，且 192.168.250.0/24 是 RFC1918 私网段,
    不触达公网/外部目标（与早前的 127.0.0.1-only 说法不一致，此处如实更正）。
  - C7  probes 192.0.2.1 port 9 — TEST-NET-1 (RFC5737 文档保留段,不可路由) — 以获得
    filtered 三态；其余探针都在 127.0.0.1。
  - All other checks stay on 127.0.0.1 with locally bound ports (C2 uses 80/18080;
    其余检查用高端口).
无真实目标参与；非回环两个段均为私网/文档保留段，用于获取稳定状态而非扫描真实资产。

C1  CIDR 目标展开 256 hosts（I4）
C2  默认端口扫描后插件仍收到原始 scheme + path（I1）
C3  不匹配协议的目标记 SKIP 并打印原因（I3）
C4  插件异常 → OUTCOME=warn + 独立 *-warn.csv（O1）
C5  零结果不再崩溃：save_csv([]) 为 no-op、扫描 exit 0（O2）
C6  协议门控（requires 语义）：http 插件在 http 端口运行、在 redis 端口 SKIP（P1）
C7  三态端口判定：open/closed/filtered 可区分，win32 下 filtered 不误报（X4+X5）
C8  spawn 进程池退出码 0、无 LoopExit；端口范围目标展开（X1+X6）

Run: .venv/bin/python verify_phase0.py
"""
import csv
import json
import pathlib
import re
import subprocess
import sys
import time

BASE = pathlib.Path(__file__).resolve().parent
PY = str(BASE / '.venv/bin/python')
CHECKS = []


def check(cid, title, ok, detail=''):
    CHECKS.append((cid, title, ok, detail))
    print('  %-4s %-4s %s' % (cid, 'PASS' if ok else 'FAIL', title))
    for line in detail.splitlines():
        if line.strip():
            print('        ' + line)


def run_ss(args, timeout=180):
    return subprocess.run([PY, 'ss.py'] + args, cwd=str(BASE),
                          capture_output=True, text=True, timeout=timeout)


def cleanup():
    for pat in ('hosts-info-*.csv', 'hosts-plugin-result-*.csv', 'hosts-plugin-result-*.json',
                'hosts-plugin-result-*-warn.csv'):
        for f in BASE.glob(pat):
            f.unlink()


def make(name, port, body, catalog=None, requires=None):
    plugin_requires = requires if requires is not None else ['http', 'https']
    (BASE / 'plugins' / ('zzv_%s.py' % name)).write_text('''import pathlib, sys
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


def drop(name):
    (BASE / 'plugins' / ('zzv_%s.py' % name)).unlink(missing_ok=True)


def rows():
    out = []
    for f in BASE.glob('hosts-plugin-result-*.csv'):
        out += list(csv.DictReader(open(f, encoding='utf_8_sig')))
    return out


def start_server(ports):
    p = subprocess.Popen([PY, str(BASE / 'tools' / 'probe_server.py')] + [str(x) for x in ports],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1.5)
    return p


def stop_server(p):
    if p is not None:
        p.terminate()
        p.wait()


def start_silent_server(ports):
    """启动静默 TCP 服务器（接受连接但永不回包）。

    用途：让指纹识别返回 unknown，验证 fail-open（审计 F2：门禁必须测「判不出来→放行」，
    否则破坏 fail-open 的回归不会被门禁拦住）。
    """
    p = subprocess.Popen([PY, str(BASE / 'tools' / 'silent_server.py')] + [str(x) for x in ports],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1.5)
    return p


def start_redis_server(ports):
    """启动临时 redis 模拟服务器（子进程，/tmp/_redis_server.py）。

    fingerprints/20_redis.py 的 probe 发送 PING\r\n 并期待以 +PONG 开头；
    fingerprints/10_http.py 的明文 GET 收到 +PONG 不匹配 HTTP 状态行，故不会误判为 http。
    用子进程（而非线程）是为了避免 gevent monkey.patch_all 环境下 daemon 线程里
    gevent socket accept 抛 'Cannot switch to a different thread'（repro_defects.py D4 实测踩中）。
    返回 Popen 句柄（与 start_server 同构）。
    """
    p = subprocess.Popen([PY, '/tmp/_redis_server.py'] + [str(x) for x in ports],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1.5)
    return p


print('\n== Phase 0 acceptance (post-fix) ==')

# ---------------------------------------------------------------- C1
# 显式端口让 256-host 扫描快速完成；断言的是 I4 展开，不是扫描结果
r = run_ss(['-t', '192.168.250.0/24:80', '-p', '1', '-is'])
m = re.search(r'total of (\d+) hosts', r.stdout)
check('C1', 'CIDR target expands to 256 hosts',
      bool(m) and int(m.group(1)) == 256,
      'observed: %s' % (m.group(0) if m else 'no port-scan line'))

# ---------------------------------------------------------------- C2
# 插件必须收到原始 URL：scheme + path 原样保留（默认端口场景，I1 修复点）
make('path', 80, "open('/tmp/_c2.txt','a').write("
                 "'%r|%r|%r' % (url.protocol, url.port, url.path))\n"
                 "return False, 'probe'")
srv = start_server((80, 18080))
try:
    pathlib.Path('/tmp/_c2.txt').unlink(missing_ok=True)
    cleanup()
    run_ss(['-t', 'http://127.0.0.1/app/login.php', '-p', '1', '-is', '-m', 'path'])
    got = pathlib.Path('/tmp/_c2.txt').read_text().strip() if pathlib.Path('/tmp/_c2.txt').exists() else ''
    ok = got == "'http'|80|'/app/login.php'"
    check('C2', 'plugin receives original scheme + path on a default port',
          ok, 'received: %s\n  expected: \'http\'|80|\'/app/login.php\'' % (got or '<plugin never ran>'))
finally:
    stop_server(srv)
    drop('path'); cleanup()

# ---------------------------------------------------------------- C3
# 不匹配协议的目标必须产生 SKIP 记录并打印原因，绝不静默消失（I3）
make('any', 18260, "print('CALL any', flush=True)\nreturn False, 'probe'", catalog='ANY')
try:
    cleanup()
    r = run_ss(['-t', 't3://127.0.0.1:18260', '-dps', '-p', '1', '-m', 'ANY'])
    out = r.stdout + r.stderr
    called = 'CALL any' in out
    skips = re.search(r'plugin outcome summary: [^\n]*SKIP=(\d+)', out)
    reason = 'protocol "t3"' in out
    check('C3', 'unmatched protocol target is recorded as SKIP with printed reason, never executed',
          (not called) and bool(skips) and int(skips.group(1)) >= 1 and reason,
          'called=%s  SKIP=%s  reason-printed=%s' % (called, skips.group(1) if skips else '?', reason))
finally:
    drop('any'); cleanup()

# ---------------------------------------------------------------- C4
# 插件异常 → WARN（不再是 IS_EXIST=False 与未检出同义），并落独立 warn 文件（O1）
make('boom', 18260, "raise RuntimeError('plugin crashed')")
try:
    cleanup()
    r = run_ss(['-t', '127.0.0.1:18260', '-dps', '-p', '1', '-is', '-m', 'boom'])
    rs = rows()
    outcome = (rs[0].get('OUTCOME') or '').lower() if rs else ''
    has_tb = 'Traceback' in (rs[0].get('DATA') or '') if rs else False
    warn_file = list(BASE.glob('hosts-plugin-result-*-warn.csv'))
    check('C4', 'plugin exception is recorded as WARN with traceback, in a separate warn file',
          outcome == 'warn' and has_tb and len(warn_file) >= 1,
          'OUTCOME=%r  traceback=%s  warn file written=%s' % (outcome, has_tb, bool(warn_file)))
finally:
    drop('boom'); cleanup()

# ---------------------------------------------------------------- C5
# 零结果/空列表不再崩溃（O2）：save_csv([]) 直接 no-op，空扫退出 0
sys.path.insert(0, str(BASE))
try:
    from utils import save_csv
    target = pathlib.Path('/tmp/_c5_empty.csv')
    target.unlink(missing_ok=True)
    save_csv([], target)
    no_crash = not target.exists()
except Exception as err:
    no_crash = False
    err = str(err)
r = run_ss(['-t', '127.0.0.1:1', '-p', '1', '-is'])
check('C5', 'empty results are a no-op: save_csv([]) safe and scan exits 0',
      no_crash and r.returncode == 0 and 'IndexError' not in r.stderr,
      'save_csv([]) no-op=%s  exit=%d  IndexError=%s' % (no_crash, r.returncode, 'IndexError' in r.stderr))
cleanup()

# ---------------------------------------------------------------- C6
# 协议门控（requires 语义）：指纹判定为 http 的端口上 http 插件运行，
# 判定为 redis 的端口上 http 插件 SKIP（原端口门控已废除，端口号不参与适用性判定）。
# 旧语义：3 开放端口 × 3 插件 = 3 次调用；新语义：一个 http 插件在 http 端口跑 1 次、
# 在 redis 端口被门控不跑，且 SKIP 记录落盘。
HTTP_PORT, REDIS_PORT = 18251, 18252
make('gate', HTTP_PORT, "print('CALL gate', flush=True)\nreturn False, 'probe'",
     catalog='GATE')
srv = start_server((HTTP_PORT,))
redis_srv = start_redis_server((REDIS_PORT,))
try:
    r = run_ss(['-t', '127.0.0.1:%d,%d' % (HTTP_PORT, REDIS_PORT), '-p', '1', '-is', '-m', 'GATE'])
    out = r.stdout + r.stderr
    calls = [l for l in out.splitlines() if l.startswith('CALL')]
    skips = re.search(r'plugin outcome summary: [^\n]*SKIP=(\d+)', out)
    check('C6', 'protocol gating: http plugin runs on http port, SKIPs on redis port',
          len(calls) == 1 and bool(skips) and int(skips.group(1)) >= 1,
          'calls=%d (http port: 1, redis port: 0)  SKIP=%s' % (len(calls), skips.group(1) if skips else '?'))
finally:
    stop_server(srv)
    stop_server(redis_srv)
    drop('gate'); cleanup()

# ---------------------------------------------------------------- C7
# 三态判据（X4+X5）：win32 平台语义下 filtered 不得误报为 open
import utils.network as netmod  # noqa: E402
srv = start_server((18260,))
try:
    saved_platform = sys.platform
    sys.platform = 'win32'
    try:
        # TEST-NET 保留段不可路由 → 超时/EHOSTUNREACH → filtered（旧 win32 分支会误报 open）
        ip, port, state_filtered = netmod.Scanner.handle_tcp_socket('192.0.2.1', 9, timeout=1)
        # 本机 closed 端口 → RST → closed
        ip2, port2, state_closed = netmod.Scanner.handle_tcp_socket('127.0.0.1', 1, timeout=1)
        # 探针开放端口 → open
        ip3, port3, state_open = netmod.Scanner.handle_tcp_socket('127.0.0.1', 18260, timeout=1)
    finally:
        sys.platform = saved_platform
    ok = state_filtered == 'filtered' and state_closed == 'closed' and state_open == 'open'
    check('C7', 'three-state port probe under win32: filtered/closed/open are distinguished',
          ok, 'win32: filtered=%r closed=%r open=%r' % (state_filtered, state_closed, state_open))
finally:
    stop_server(srv)
    cleanup()

# ---------------------------------------------------------------- C8
# spawn 进程池（X1）：小规模实扫退出码 0、无 LoopExit；端口范围目标展开（X6）
# requires 语义：3 个 http 插件在 3 个 http 端口全部适用 → 3×3 = 9 次调用（全笛卡尔积），
# 旧端口门控下是 3 次（每插件只跑声明端口）。断言 9 次是更强的完整性检查。
for i, p in enumerate((18360, 18361, 18362)):
    make('range%d' % i, p, "print('CALL r%d', flush=True)\nreturn False, 'probe'" % i,
         catalog='RANGE%d' % i)
srv = start_server((18360, 18361, 18362))
try:
    r = run_ss(['-t', '127.0.0.1:18360-18362', '-p', '1', '-is', '-m', 'RANGE0', 'RANGE1', 'RANGE2'])
    calls = [l for l in (r.stdout + r.stderr).splitlines() if l.startswith('CALL')]
    check('C8', 'port-range target expands (3 ports) and spawn pool exits 0 without LoopExit',
          r.returncode == 0 and 'LoopExit' not in (r.stdout + r.stderr) and len(calls) == 9,
          'exit=%d  LoopExit=%s  calls=%d (requires: 3 plugins x 3 http ports = 9)' % (r.returncode, 'LoopExit' in (r.stdout + r.stderr), len(calls)))
finally:
    stop_server(srv)
    for i in range(3):
        drop('range%d' % i)
    cleanup()

# ---------------------------------------------------------------- C9
# fail-open（审计 F2）：指纹判不出来（静默服务）时，http 插件必须放行、必须实际执行。
# 旧门禁只测「门控生效」（C6），不测「fail-open 生效」——变异破坏 fail-open 时 C6 仍 PASS。
SILENT_PORT = 18253
make('failopen', SILENT_PORT, "print('CALL failopen', flush=True)\nreturn False, 'probe'",
     catalog='FAILOPEN')
silent_srv = start_silent_server((SILENT_PORT,))
try:
    r = run_ss(['-t', '127.0.0.1:%d' % SILENT_PORT, '-p', '1', '-is', '-m', 'FAILOPEN'])
    out = r.stdout + r.stderr
    calls = [l for l in out.splitlines() if l.startswith('CALL')]
    skips = re.search(r'plugin outcome summary: [^\n]*SKIP=(\d+)', out)
    check('C9', 'fail-open: unrecognized service still runs every plugin (no silent SKIP)',
          r.returncode == 0 and len(calls) == 1 and bool(skips) and int(skips.group(1)) == 0,
          'exit=%d  calls=%d (want 1)  SKIP=%s (want 0)' % (
              r.returncode, len(calls), skips.group(1) if skips else '?'))
finally:
    stop_server(silent_srv)
    drop('failopen')
    cleanup()

# ---------------------------------------------------------------- C10
# 语料 risk_class 过滤（审计 E3：门禁对语料加载路径零覆盖）。
# 真实判定：拿一个「全部插件都是 risky」的 catalog 做选择器。
#   默认：risky 不加载 → plugin list is empty → exit 2
#   --include-risky：risky 加载 → 不提前退出（这里用不存在的目标确保快速结束）
# 变异「删掉 risk_class 过滤」时前半条必须红。
_risky_cat = 'CVE-2022-0543'      # 语料里这是 risk_class: risky
r_def = run_ss(['-t', '127.0.0.1:1', '-p', '1', '-is', '-m', _risky_cat])
_out_def = r_def.stdout + r_def.stderr
_default_skips_risky = (r_def.returncode == 2 and 'plugin list is empty' in _out_def)
r_inc = run_ss(['-t', '127.0.0.1:1', '-p', '1', '-is', '-m', _risky_cat, '--include-risky'])
_inc_loads = (r_inc.returncode != 2)
check('C10', 'risk_class filter: risky plugins excluded by default, loadable with --include-risky',
      _default_skips_risky and _inc_loads,
      'default exit=%d (want 2, empty)  with-flag exit=%d (want !=2)' % (
          r_def.returncode, r_inc.returncode))

# ---------------------------------------------------------------- C11
# RootURL 带端口（审计：2051 个插件丢端口 → 非 80 目标全打错）。
# 直接调用真实插件的 _sub()，变异「root 改回 url.host」时必须红。
sys.path.insert(0, str(BASE))
try:
    from utils.urlutil import Url as _Url
    import importlib as _il
    _m = _il.import_module('.CVE-2021-45232', 'plugins_corpus.2021')
    _u = _Url('http://example.com:18080/app', is_verify=False)
    _subbed = _m.Plugin()._sub('{{RootURL}}/x', _u)
    check('C11', 'RootURL substitution keeps non-default port',
          _subbed == 'http://example.com:18080/x',
          'subbed=%r (want http://example.com:18080/x)' % _subbed)
except Exception as e:
    check('C11', 'RootURL substitution keeps non-default port', False,
          'setup failed: %s: %s' % (type(e).__name__, e))

# ---------------------------------------------------------------- summary
print('\n' + '=' * 70)
passed = sum(1 for _, _, ok, _ in CHECKS if ok)
print('%d / %d checks pass' % (passed, len(CHECKS)))
(BASE / 'phase0-acceptance.json').write_text(
    json.dumps([{'id': c, 'title': t, 'pass': o} for c, t, o, _ in CHECKS], indent=2))
sys.exit(0 if passed == len(CHECKS) else 1)
