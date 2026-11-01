"""UDP 探测判定辅助：open / open|filtered 语义、证据状态标记、双包发送。

背景（research/udp-vuln-landscape.md §Q3.1/Q3.4，nmap 手册 Table 5.3）：
UDP 无握手，「无响应」同时意味着开放或过滤。本扫描器「不漏报优先」的硬要求：
- 收到任意响应字节 → open
- 重传后仍无响应   → open|filtered，**永不报 closed**（ICMP type3/code3 解析是
  可选增强，v1 不做；不解析时关闭端口也落入 open|filtered，恰是保守方向）

证据状态标记（上层引擎区分「确认开放」与「无响应」的独立标记）：
每个 UDP 探测证据串以 ``state=open|`` 或 ``state=open|filtered|`` 开头，
调用 ``parse_state(evidence)`` 即可无歧义读回。
（特意不放 products 集合：products 会进入 ServiceInfo.tags 的 ``product:`` 前缀，
使 utils/fingerprint.py is_applicable() 的 fail-open 分支失效 → 造成漏报。）

【上层集成待接线点】detect() 对 UDP 无响应的处理是通用 fail-open（=unknown）。
引擎侧接入时须：从 evidence 读 parse_state()/verdict()，把
``open|filtered`` 直接映射为端口结论而不是 unknown；并按各探测器的 PORTS
分派（每个端口只跑对应协议的探测），避免三份协议 payload 打同一个端口。
"""

from __future__ import annotations

from typing import Optional, Tuple

VERDICT_OPEN = 'open'
VERDICT_OPEN_FILTERED = 'open|filtered'

_STATE_PREFIX = 'state='
_STATE_END = ';'


def verdict(resp_bytes: bytes, addr) -> str:
    """UDP 判定：有响应字节且来源地址非空 → 'open'；否则 → 'open|filtered'。

    这是 nmap Table 5.3 去 ICMP 分支后的最小口径：
    | 目标端口的任意 UDP 响应 | open
    | 重传后仍无响应          | open|filtered
    """
    if resp_bytes and addr is not None:
        return VERDICT_OPEN
    return VERDICT_OPEN_FILTERED


def state_tag(state: str) -> str:
    """把判定转成证据串前缀标记，如 'state=open;' / 'state=open|filtered;'。

    分隔符用 ';'（状态值本身含 '|'，不能用 '|' 分隔）。
    """
    return '{}{}{}'.format(_STATE_PREFIX, state, _STATE_END)


def parse_state(evidence: str) -> Optional[str]:
    """从证据串读回状态标记；无标记返回 None。"""
    if evidence.startswith(_STATE_PREFIX):
        head = evidence.split(_STATE_END, 1)[0]
        return head[len(_STATE_PREFIX):]
    return None


def send_with_retry(ctx, payload: bytes, read: int = 2048,
                    first_wait: float = 1.0, retry_wait: float = 1.5,
                    ) -> Tuple[bytes, Optional[Tuple[str, int]]]:
    """UDP 探测发送：1 次发送 + 1 次重传（每端口最多 2 个包）。

    超时参数依据 research/udp-vuln-landscape.md §Q3.4 参数表：
    首次 1.0s / 重传 1.5s（Linux 对 ICMP port unreachable 限速 1 包/秒，
    等待超过该值注定无用）。
    返回 (响应字节, 来源地址)；两次都无响应 → (b'', None)。
    """
    resp, addr = ctx.udp_send_recv(payload, read=read, wait=first_wait)
    if resp:
        return resp, addr
    resp, addr = ctx.udp_send_recv(payload, read=read, wait=retry_wait)
    if resp:
        return resp, addr
    return b'', None