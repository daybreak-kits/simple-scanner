#!/usr/bin/env python3
"""Does in-order result collection actually cost wall clock time?

Claim under test: yield_result() blocks on jobs[0].result(), so a slow task
withholds completed results. TRUE for delivery order. But does it cost
throughput? The other tasks still RUN in the pool; only *collection* waits.
So total wall clock should be identical.
"""
import sys
import time

sys.path.insert(0, '/opt/workspace/labs/simple-scanner')
from utils import process


def work(delay):
    time.sleep(delay)
    return delay


def run_inorder():
    pool = process.new(max_workers=8)
    pool.sm(work, 2.0)                 # slow task first
    for _ in range(7):
        pool.sm(work, 0.05)
    t = time.time()
    out = list(pool.yield_result())    # current behaviour
    return time.time() - t, out


def run_ascompleted():
    import concurrent.futures as cf
    with cf.ProcessPoolExecutor(max_workers=8) as ex:
        futs = [ex.submit(work, 2.0)] + [ex.submit(work, 0.05) for _ in range(7)]
        t = time.time()
        out = [f.result() for f in cf.as_completed(futs)]
        return time.time() - t, out


print('=== 8 tasks: one 2.0s + seven 0.05s, 8 workers ===')
a, _ = run_inorder()
b, _ = run_ascompleted()
print('  current yield_result() (in-order collection) : %.2fs wall' % a)
print('  as_completed          (arrival-order)        : %.2fs wall' % b)
print('  difference                                   : %+.2fs' % (b - a))
print()
print('  => wall clock is set by the SLOWEST task either way;')
print('     ordering only changes WHEN each row is printed, not how long the scan takes.')
