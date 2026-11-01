#!/usr/bin/env python3
"""Pick the engine: how does a plain thread pool scale against a fast server?

Server holds nothing (returns immediately), so this measures client-side
ceiling: connection setup, request overhead, GIL contention.
"""
import concurrent.futures as cf
import os
import pathlib
import subprocess
import sys
import time

BASE = pathlib.Path('/opt/workspace/labs/simple-scanner')
PY = str(BASE / '.venv/bin/python')
PORT = 18300
URL = 'http://127.0.0.1:%d/' % PORT

env = dict(os.environ, PEAK_HOLD='0')
srv = subprocess.Popen([PY, str(BASE / 'tools' / 'peak_server.py'), str(PORT)],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env)
time.sleep(1.5)

import requests

N = 3000
print('=== %d requests against a zero-latency local server ===' % N)
print('  (a fresh Session per task = what the current engine does)\n')

for workers in (50, 200, 500):
    # shared session, one per worker (per-host pool)
    local = __import__('threading').local()

    def hit(_):
        s = getattr(local, 's', None)
        if s is None:
            s = requests.Session()
            s.mount('http://', requests.adapters.HTTPAdapter(
                pool_connections=4, pool_maxsize=4, max_retries=0))
            local.s = s
        r = s.get(URL, timeout=10)
        r.close()
        return r.status_code

    t = time.time()
    with cf.ThreadPoolExecutor(max_workers=workers) as ex:
        codes = list(ex.map(hit, range(N)))
    el = time.time() - t
    ok = sum(1 for c in codes if c == 200)
    print('  threads=%3d  %6.2fs  %7.0f req/s  ok=%d/%d' % (workers, el, N / el, ok, N))

srv.terminate(); srv.wait()
