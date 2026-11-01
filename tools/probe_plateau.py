#!/usr/bin/env python3
"""Decisive test: does throughput plateau with concurrency?

If "everyone is IO bound" were true, throughput would rise linearly with
concurrency until the network saturates. If client CPU is the binding
constraint, throughput plateaus at ~1 core's worth and stays there.
"""
import pathlib
import subprocess
import sys
import time

BASE = pathlib.Path('/opt/workspace/labs/simple-scanner')
PY = str(BASE / '.venv/bin/python')
PORT = 18360
RTT_MS = 50
N = 1200
URL = 'http://127.0.0.1:%d/' % PORT

SRV = r'''
import socket, threading, sys, time
RTT = float(sys.argv[2])
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
                time.sleep(RTT)
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
pathlib.Path('/tmp/_rtt_srv.py').write_text(SRV)

CLIENT = r'''
import sys, time, threading
mode, URL, N, C = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4])
if mode == 'gevent_requests':
    import gevent
    from gevent import monkey
    monkey.patch_all(thread=False, httplib=True)
    import requests
    from gevent import pool as gpool
    sess = requests.Session()
    sess.mount('http://', requests.adapters.HTTPAdapter(pool_connections=C, pool_maxsize=C))
    def hit(_):
        r = sess.get(URL); r.close(); return 1
    t = time.time()
    list(gpool.Pool(C).imap(hit, range(N)))
    print(time.time() - t)
elif mode == 'gevent_aiohttp':
    import asyncio, aiohttp
    async def main():
        conn = aiohttp.TCPConnector(limit=C)
        sem = asyncio.Semaphore(C)
        async with aiohttp.ClientSession(connector=conn) as cs:
            async def one(_):
                async with sem:
                    async with cs.get(URL) as r:
                        await r.read()
            await asyncio.gather(*[one(i) for i in range(N)])
    t = time.time(); asyncio.run(main()); print(time.time() - t)
'''
pathlib.Path('/tmp/_rtt_client.py').write_text(CLIENT)

srv = subprocess.Popen([PY, '/tmp/_rtt_srv.py', str(PORT), str(RTT_MS / 1000.0)],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
time.sleep(1.5)

print('=== %d requests, server RTT %.0f ms ===' % (N, RTT_MS))
print('   IO-bound prediction: throughput grows linearly with concurrency (C/RTT)\n')
print('   %-8s %-20s %-20s' % ('conc', 'requests+gevent', 'aiohttp'))

for C in (10, 25, 50, 100, 200, 400):
    row = []
    for mode in ('gevent_requests', 'gevent_aiohttp'):
        r = subprocess.run([PY, '/tmp/_rtt_client.py', mode, URL, str(N), str(C)],
                           capture_output=True, text=True, timeout=600)
        if r.returncode != 0:
            row.append('FAILED')
            continue
        el = float(r.stdout.strip().splitlines()[-1])
        row.append('%6.0f req/s' % (N / el))
    io_pred = C / (RTT_MS / 1000.0)
    print('   %-8d %-20s %-20s  (IO ceiling %.0f)' % (C, row[0], row[1], io_pred))

srv.terminate(); srv.wait()
