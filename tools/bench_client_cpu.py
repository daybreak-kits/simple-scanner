#!/usr/bin/env python3
"""Client-side cost per request, isolated from the test server.

Measures CPU seconds burned by the *client* per 1000 requests, so a slow
Python test server does not contaminate the comparison. Lower is better.
"""
import os
import pathlib
import subprocess
import sys
import time

BASE = pathlib.Path('/opt/workspace/labs/simple-scanner')
PY = str(BASE / '.venv/bin/python')
PORT = 18310
URL = 'http://127.0.0.1:%d/' % PORT
N = 1000

WORKERS = {
    'requests+Session': r'''
import sys, time, requests
URL, N = sys.argv[1], int(sys.argv[2])
s = requests.Session()
s.mount('http://', requests.adapters.HTTPAdapter(pool_connections=8, pool_maxsize=8, max_retries=0))
t = time.process_time()
for _ in range(N):
    r = s.get(URL, timeout=10); r.close()
print(time.process_time() - t)
''',
    'requests+fresh': r'''
import sys, time, requests
URL, N = sys.argv[1], int(sys.argv[2])
t = time.process_time()
for _ in range(N):
    s = requests.Session(); r = s.get(URL, timeout=10); r.close(); s.close()
print(time.process_time() - t)
''',
    'aiohttp': r'''
import sys, time, asyncio, aiohttp
URL, N = sys.argv[1], int(sys.argv[2])
async def main():
    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(limit=8)) as cs:
        for _ in range(N):
            async with cs.get(URL) as r:
                await r.read()
t = time.process_time()
asyncio.run(main())
print(time.process_time() - t)
''',
    'httpx+AsyncClient': r'''
import sys, time, asyncio, httpx
URL, N = sys.argv[1], int(sys.argv[2])
async def main():
    lim = httpx.Limits(max_connections=8, max_keepalive_connections=8)
    async with httpx.AsyncClient(limits=lim) as cl:
        for _ in range(N):
            r = await cl.get(URL); await r.aread()
t = time.process_time()
asyncio.run(main())
print(time.process_time() - t)
''',
}

env = dict(os.environ, PEAK_HOLD='0')
srv = subprocess.Popen([PY, str(BASE / 'tools' / 'peak_server.py'), str(PORT)],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env)
time.sleep(1.5)

print('=== client CPU cost, %d sequential requests ===' % N)
print('  (server returns immediately; measuring client-side process_time)\n')
for name, src in WORKERS.items():
    p = pathlib.Path('/tmp') / ('_cpu_%s.py' % name.replace('+', '_'))
    p.write_text(src)
    r = subprocess.run([PY, str(p), URL, str(N)], capture_output=True, text=True, timeout=300)
    if r.returncode != 0:
        print('  %-20s FAILED: %s' % (name, (r.stderr.strip().splitlines() or ['?'])[-1][:80]))
        continue
    cpu = float(r.stdout.strip().splitlines()[-1])
    print('  %-20s %7.3fs CPU  %7.1f us/req' % (name, cpu, cpu * 1e6 / N))

srv.terminate(); srv.wait()
