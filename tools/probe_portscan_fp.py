#!/usr/bin/env python3
"""Is the port scanner's "open" verdict reliable on closed ports?"""
import sys

sys.path.insert(0, '/opt/workspace/labs/simple-scanner')
from gevent import monkey
monkey.patch_all(thread=False, httplib=True)
import socket
from utils import network

PORTS = list(range(30000, 40000))
print('=== %d ports that are all closed on loopback ===' % len(PORTS))

# ground truth via plain blocking connect
truth = []
for p in PORTS:
    s = socket.socket()
    s.settimeout(0.5)
    rc = s.connect_ex(('127.0.0.1', p))
    s.close()
    if rc == 0:
        truth.append(p)
print('  ground truth (plain connect_ex): %d open -> %s' % (len(truth), truth[:10]))

sc = network.Scanner()
sc.scan_run('127.0.0.1', PORTS, is_check_alive=False, is_yield=False)
reported = sorted(p for _, p in sc.get_yield_tcp())
print('  scanner reported open          : %d open -> %s' % (len(reported), reported[:10]))
print('  false positives                : %d' % len(set(reported) - set(truth)))
print('  false negatives                : %d' % len(set(truth) - set(reported)))
