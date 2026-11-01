#!/usr/bin/env python3
"""Is gevent single-process CPU-bound? And does multiprocess x gevent scale?

If gevent is single-threaded, 1 process == 1 core, so a pure-greenlet engine
caps at one core's worth of requests regardless of concurrency. The only way to
use 8 cores is N processes, each with its own greenlet pool.
"""
import pathlib
import subprocess
import sys
import time

BASE = pathlib.Path('/opt/workspace/labs/simple-scanner')
PY = str(BASE / '.venv/bin/python')
PORT = 18370
N = 2000
URL = 'http://127.0.0.1:%d/' % PORT

SRV = r'''
import socket, threading, sys
RESP = b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok'
def handle(c):
    c.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    buf = b''
    try:
        while True:
            d = c.recv(65535)
            if not d: break
            buf += d
            while b'\r\n\r\n' in buf:
                _, buf = buf.split(b'\r\n\r\n', 1)
                c.sendall(RESP)
    except Exception:
        pass
    c.close()
def serve(p):
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('127.0.0.1', p)); s.listen(4096)
    while True:
        try:
            c, _ = s.accept()
        except Exception:
            return
        threading.Thread(target=handle, args=(c,), daemon=True).start()
serve(int(sys.argv[1]))
'''
pathlib.Path('/tmp/_mp_srv.py').write_text(SRV)

# one worker = one process running a gevent pool
WORKER = r'''
import sys, time
from gevent import monkey
monkey.patch_all(thread=False, httplib=True)
import requests, gevent
from gevent import pool as gpool
URL, N, C = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
sess = requests.Session()
sess.mount('http://', requests.adapters.HTTPAdapter(pool_connections=C, pool_maxsize=C))
def hit(_):
    r = sess.get(URL); r.close(); return 1
t = time.time()
list(gpool.Pool(C).imap(hit, range(N)))
print(time.time() - t)
'''
pathlib.Path('/tmp/_mp_worker.py').write_text(WORKER)

srv = subprocess.Popen([PY, '/tmp/_mp_srv.py', str(PORT)],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
time.sleep(1.5)

print('=== zero-RTT local server, %d requests per worker, gevent pool 100 ===' % N)
print('   if gevent is single-threaded, adding processes should scale ~linearly\n')

for procs in (1, 2, 4, 8):
    per = N
    t = time.time()
    ps = [subprocess.Popen([PY, '/tmp/_mp_worker.py', URL, str(per), '100'],
                           stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
          for _ in range(procs)]
    outs = [p.communicate()[0] for p in ps]
    el = time.time() - t
    total = per * procs
    ok = all(p.returncode == 0 for p in ps)
    print('  %d process(es): %6.2fs wall  %7.0f req/s total  %s'
          % (procs, el, total / el, 'ok' if ok else 'FAILED'))

srv.terminate(); srv.wait()
