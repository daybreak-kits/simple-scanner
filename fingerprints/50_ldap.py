"""LDAP 探测：匿名 bind request（RFC 4511 §4.2）。

响应特征：LDAPMessage = SEQUENCE(0x30) { messageID INTEGER, protocolOp }，
bindResponse 的 protocolOp 是 [APPLICATION 1] = 0x61，紧跟 LDAPResult：
  resultCode ENUMERATED(0x0a) len=1，success=0x00，匿名被禁则为 0x31(invalidCredentials)/0x32(insufficientAccessRights)。
判据 = 首字节 0x30 + 前 20 字节内出现 0x61（bindResponse tag）+ 结果码枚举 0x0a 01 xx。
依据：RFC 4511 BindRequest/BindResponse ASN.1 定义；匿名 bind 是目录服务最基础的探测。
"""

TRANSPORT = 'tcp'
PROTOCOL = 'ldap'
ORDER = 30  # 强特征：bindResponse 结构是硬证据

# 匿名 bind request：version=3, name="", simple auth=""
# ASN.1: 30 0c 02 01 01 60 07 02 01 03 04 00 80 00
BIND_ANON = bytes.fromhex('300c020101600702010304008000')


def probe(ctx):
    resp = ctx.send_recv(BIND_ANON, read=512)
    if len(resp) < 8 or resp[0] != 0x30:
        return None
    head = resp[:64]
    if b'\x61' not in head:
        return None
    # LDAPResult.resultCode: 0a 01 <code>；email code 0x00(0) 匿名成功 / 非 0 也算 LDAP
    idx = head.find(b'\x0a\x01', 2)
    if idx < 0:
        return None
    code = head[idx + 2]
    return 'LDAP bindResponse resultCode={}({})'.format(
        code, 'success' if code == 0 else 'authenticated/denied'), set()