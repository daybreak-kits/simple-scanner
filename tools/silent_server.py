"""静默 TCP 服务器：接受连接但永不回包。

用途：门禁测试需要构造「指纹判不出来」的服务，验证 fail-open
（判不出来 → 所有插件必须放行）。审计 F2 指出原门禁只测「门控生效」，
不测「fail-open 生效」，导致破坏 fail-open 的回归无法被拦住。

用法：python tools/silent_server.py 18360 [18361 ...]
"""
import socket
import sys
import threading

_HELD = []


def serve(port):
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(('127.0.0.1', port))
    srv.listen(64)

    def loop():
        while True:
            try:
                c, _ = srv.accept()
            except OSError:
                return
            _HELD.append(c)  # 持有但不读不写 → 客户端超时

    threading.Thread(target=loop, daemon=True).start()
    return srv


if __name__ == '__main__':
    socks = [serve(int(p)) for p in sys.argv[1:]]
    print('silent on %s' % ', '.join(sys.argv[1:]), flush=True)
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        for s in socks:
            s.close()
