#!/usr/bin/env python3
"""Measure the *actual* simultaneous-task ceiling of the current engine.

Builds N identical plugins, points them at a server that holds every request
for HOLD seconds, and reads the observed peak overlap. The theoretical ceiling
is the process-pool size (-p). If observed peak == -p, the engine is saturated
by its worker count and no plugin-level tuning can raise throughput.
"""
import json
import os
import pathlib
import subprocess
import sys
import time

BASE = pathlib.Path('/opt/workspace/labs/simple-scanner')
PY = str(BASE / '.venv/bin/python')
PORT = 18290
HOLD = 0.2
NPLUGIN = 8
NWORKERS = int(sys.argv[1]) if len(sys.argv) > 1 else 8

TPL = '''import pathlib, sys
from typing import Any, Tuple
try:
    from utils import PLUGIN_TYPE, plugin, urlutil
except:
    sys.path.append(pathlib.Path(__file__).parent.parent.__str__())
    from utils import PLUGIN_TYPE, plugin, urlutil


class Plugin(plugin.PluginBase):
    def set_info(self):
        return plugin.Info(name='PEAK{n}', catalog='PEAK{n}', itype=PLUGIN_TYPE.POC,
                           protocol='http', port={port}, ssl_protocol='https', ssl_port={port})

    def run(self, url: urlutil.Url, *args, **kwargs) -> Tuple[bool, Any]:
        if not url.protocol:
            url.protocol, url.port = self.https_or_http(url)
        if not url.protocol:
            return False, 'no protocol'
        http = self.make_http_client()
        err, resp = http.rq(url.join('/p').get_full(), verify=False, timeout=10)
        return False, 'err' if err else resp.status_code
'''

for i in range(NPLUGIN):
    (BASE / 'plugins' / ('zzpeak%d.py' % i)).write_text(
        TPL.replace('{n}', str(i)).replace('{port}', str(PORT)))

if pathlib.Path('/tmp/_peak.json').exists():
    pathlib.Path('/tmp/_peak.json').unlink()

env = dict(os.environ, PEAK_HOLD=str(HOLD))
srv = subprocess.Popen([PY, str(BASE / 'tools' / 'peak_server.py'), str(PORT)],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env)
time.sleep(1.5)

t = time.time()
r = subprocess.run([PY, 'ss.py', '-t', '127.0.0.1:%d' % PORT, '-dps', '-is',
                    '-p', str(NWORKERS), '-m'] + ['PEAK%d' % i for i in range(NPLUGIN)],
                   cwd=str(BASE), capture_output=True, text=True, timeout=600)
wall = time.time() - t

srv.terminate(); srv.wait()
time.sleep(0.5)
state = json.loads(pathlib.Path('/tmp/_peak.json').read_text())

tasks = NPLUGIN
print('=== %d plugin tasks, -p %d, server holds each request %.0f ms ==='
      % (tasks, NWORKERS, HOLD * 1000))
print('  observed peak simultaneous requests : %d' % state['peak'])
print('  hard ceiling = process pool size    : %d' % NWORKERS)
print('  total requests                      : %d' % state['total'])
print('  wall clock                          : %.2fs' % wall)
print('  ideal at peak                       : %.2fs' % (tasks * HOLD / max(state['peak'], 1)))
print('  verdict: %s' % ('SATURATED - worker count is the ceiling'
                         if state['peak'] >= NWORKERS - 1 else 'NOT saturated'))

for i in range(NPLUGIN):
    (BASE / 'plugins' / ('zzpeak%d.py' % i)).unlink(missing_ok=True)
for f in BASE.glob('hosts-*.csv'):
    f.unlink()
