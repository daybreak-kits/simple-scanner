"""临时侦察：抓取各端点的原始响应，用于设计探测器特征（验证后删除）。"""
import socket
import sys
import time

HOST = '192.168.255.128'
PORTS = [22, 8081, 16379, 18080, 28081, 28161, 28162, 28180, 3000, 20080]
TIMEOUT = 1.5


def show(name, data):
    print('--- {} ({} bytes) ---'.format(name, len(data)))
    print(repr(data[:300]))
    print()


def passive(port):
    try:
        s = socket.create_connection((HOST, port), timeout=TIMEOUT)
        s.settimeout(0.8)
        data = s.recv(1024)
        s.close()
        return data
    except OSError as e:
        return '<err: {}>'.format(e).encode()


def send(port, payload, read=4096):
    try:
        s = socket.create_connection((HOST, port), timeout=TIMEOUT)
        s.settimeout(TIMEOUT)
        s.sendall(payload)
        data = s.recv(read)
        s.close()
        return data
    except OSError as e:
        return '<err: {}>'.format(e).encode()


def main():
    for port in PORTS:
        print('#' * 60)
        print('# PORT {}'.format(port))
        print('#' * 60)
        show('passive', passive(port))
        show('HTTP GET /', send(port, b'GET / HTTP/1.0\r\nHost: x\r\nUser-Agent: t\r\n\r\n'))
        if port in (28161, 28162):
            show('HTTP HEAD /', send(port, b'HEAD / HTTP/1.0\r\nHost: x\r\n\r\n'))


if __name__ == '__main__':
    main()