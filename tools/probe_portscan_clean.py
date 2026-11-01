#!/usr/bin/env python3
"""Port-scan accuracy on a range that cannot self-connect.

Loopback scanning has a known artifact: if the kernel picks your own source
port equal to the target port, connect() succeeds against yourself. The
ephemeral range here is 32768-60999, so scanning below that isolates real
behaviour from the artifact.
"""
import socket
import sys

sys.path.insert(0, '/opt/workspace/labs/simple-scanner')
from gevent import monkey
monkey.patch_all(thread=False, httplib=True)
from utils import network

PORTS = list(range(10000, 20000))
ephem = open('/proc/sys/net/ipv4/ip_local_port_range').read().split()
print('=== %d ports (10000-19999), ephemeral range is %s-%s -> no self-connect ==='
      % (len(PORTS), ephem[0], ephem[1]))

truth = []
for p in PORTS:
    s = socket.socket()
    s.settimeout(0.3)
    if s.connect_ex(('127.0.0.1', p)) == 0:
        truth.append(p)
    s.close()
print('  ground truth open : %d %s' % (len(truth), truth[:5]))

sc = network.Scanner()
sc.scan_run('127.0.0.1', PORTS, is_check_alive=False, is_yield=False)
reported = sorted(p for _, p in sc.get_yield_tcp())
print('  scanner reported  : %d %s' % (len(reported), reported[:5]))
fp = sorted(set(reported) - set(truth))
fn = sorted(set(truth) - set(reported))
print('  false positives   : %d %s' % (len(fp), fp[:5]))
print('  false negatives   : %d %s' % (len(fn), fn[:5]))
