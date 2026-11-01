#!/usr/bin/env python3
"""Where does the bottleneck actually sit: network wait, or client CPU?

Refutes/confirms the claim "everyone is IO bound so all scanners perform alike".

Method: measure client CPU seconds per request (server-independent), then
compute the concurrency at which client CPU - not network latency - becomes
the binding constraint.
"""
import os
import pathlib
import subprocess
import sys

BASE = pathlib.Path('/opt/workspace/labs/simple-scanner')
PY = str(BASE / '.venv/bin/python')
PORT = 18350
URL = 'http://127.0.0.1:%d/' % PORT
N = 1500

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
    s.bind(('127.0.0.1', p)); s.listen(1024)
    while True:
        try:
            c, _ = s.accept()
        except Exception:
            return
        threading.Thread(target=handle, args=(c,), daemon=True).start()
serve(int(sys.argv[1]))
'''
pathlib.Path('/tmp/_fast_srv.py').write_text(SRV)

CLIENT = r'''
import sys, time
mode, URL, N = sys.argv[1], sys.argv[2], int(sys.argv[3])
if mode == 'requests_reuse':
    import requests
    s = requests.Session()
    s.mount('http://', requests.adapters.HTTPAdapter(pool_connections=4, pool_maxsize=4))
    t = time.process_time()
    for _ in range(N):
        r = s.get(URL); r.close()
    print(time.process_time() - t)
elif mode == 'requests_fresh':
    import requests
    t = time.process_time()
    for _ in range(N):
        s = requests.Session(); r = s.get(URL); r.close(); s.close()
    print(time.process_time() - t)
elif mode == 'aiohttp':
    import asyncio, aiohttp
    async def main():
        async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(limit=4)) as cs:
            for _ in range(N):
                async with cs.get(URL) as r:
                    await r.read()
    t = time.process_time(); asyncio.run(main()); print(time.process_time() - t)
'''
pathlib.Path('/tmp/_fast_client.py').write_text(CLIENT)

srv = subprocess.Popen([PY, '/tmp/_fast_srv.py', str(PORT)],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
import time as _t
_t.sleep(1.2)

print('=== client CPU per request, %d requests, minimal C-speed-ish server ===' % N)
cpus = {}
for mode in ('requests_reuse', 'requests_fresh', 'aiohttp'):
    r = subprocess.run([PY, '/tmp/_fast_client.py', mode, URL, str(N)],
                       capture_output=True, text=True, timeout=300)
    if r.returncode != 0:
        print('  %-16s FAILED %s' % (mode, (r.stderr.strip().splitlines() or ['?'])[-1][:70]))
        continue
    cpu = float(r.stdout.strip().splitlines()[-1])
    cpus[mode] = cpu * 1e6 / N
    print('  %-16s %8.0f us CPU/request   -> 1 core sustains %6.0f req/s'
          % (mode, cpu * 1e6 / N, N / cpu))

srv.terminate(); srv.wait()

print('\n=== at what concurrency does client CPU become the binding constraint? ===')
print('    (RTT is the same for every engine, so it cancels out of the comparison)\n')
print('    %-16s %10s %10s %10s' % ('engine', 'RTT=10ms', 'RTT=50ms', 'RTT=200ms'))
for mode, us in cpus.items():
    row = []
    for rtt_ms in (10, 50, 200):
        # network can sustain: concurrency / RTT  requests per second
        # client cpu can sustain: 1e6 / us  requests per second per core
        # crossover concurrency = (cpu_req_per_s * rtt_s)
        crossover = (1e6 / us) * (rtt_ms / 1000.0)
        row.append('%d' % crossover)
    print('    %-16s %10s %10s %10s' % (mode, *row))
print('\n    ^ the number is the concurrency at which 1 CPU core saturates.')
print('      below it you are IO bound; above it you need more cores, not more sockets.')
