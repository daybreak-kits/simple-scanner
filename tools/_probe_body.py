"""临时侦察：抓取完整响应（头 + body），用于设计 L3 产品特征。"""
import socket

HOST = '192.168.255.128'
TIMEOUT = 2.0

PATHS = {
    8081: ['/', '/index.php'],
    18080: ['/'],
    28081: ['/'],
    28161: ['/'],
    28180: ['/', '/solr/'],
    3000: ['/'],
    20080: ['/'],
}


def get(port, path):
    req = ('GET {} HTTP/1.0\r\nHost: 192.168.255.128:{}\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\n\r\n'
           .format(path, port)).encode()
    try:
        s = socket.create_connection((HOST, port), timeout=TIMEOUT)
        s.settimeout(TIMEOUT)
        s.sendall(req)
        chunks = []
        while True:
            d = s.recv(65536)
            if not d:
                break
            chunks.append(d)
            if sum(len(c) for c in chunks) > 20000:
                break
        s.close()
        return b''.join(chunks)
    except OSError as e:
        return ('<err {}>'.format(e)).encode()


for port, paths in PATHS.items():
    for p in paths:
        data = get(port, p)
        print('=' * 70)
        print('PORT {} PATH {}'.format(port, p))
        print('=' * 70)
        print(data[:2500].decode('latin-1', 'replace'))
        print()
