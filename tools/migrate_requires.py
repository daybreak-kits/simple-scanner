# -*- coding: utf-8 -*-
"""插件契约迁移：Info(ports=[...]) → Info(requires=[...])

规则（2026-10-26 用户裁决落地）：
- 删除 ports=[...] 行（旧端口门控废除：端口号与协议无绑定，按端口判适用性直接制造漏报）
- 新增 requires=[...]，由 protocol= 决定：
    http → ['http','https']；tcp → ['tcp']；t3 → ['t3']；其他单值 → ['<协议>']
- port=/ssl_port= 保留（-dps 模式与默认端口仍要用）
- info.fingerprint 属性（来源噪声 tag）绝不映射进 requires

幂等：重复跑不重复改。
"""
import argparse
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent

# protocol 值 → requires 标签集
REQUIRES_MAP = {
    'http': "['http', 'https']",
    'https': "['https']",
    'tcp': "['tcp']",
    't3': "['t3']",
}

# Info(...) 调用中单行的 ports=[...]（含尾逗号）
RE_PORTS_LINE = re.compile(r'^\s*ports=\[[^\]]*\],\s*\n', re.M)
# protocol='xxx', （单引号/双引号）
RE_PROTOCOL = re.compile(r"protocol=['\"]([\w-]+)['\"]")


def _requires_for(protocol: str) -> str:
    if protocol in REQUIRES_MAP:
        return REQUIRES_MAP[protocol]
    return "['{}']".format(protocol)


def migrate_file(path: pathlib.Path, dry: bool = False):
    """返回 (状态, requires值或None)。状态: migrated/already/skip"""
    src = path.read_text(encoding='utf-8')
    if 'requires=' in src:
        return 'already', None
    if not RE_PORTS_LINE.search(src):
        return 'skip', None
    pm = RE_PROTOCOL.search(src)
    if not pm:
        return 'skip', None
    req = _requires_for(pm.group(1))
    out = RE_PORTS_LINE.sub('', src, count=1)
    # 在 port=... 行后插入 requires（port= 是必填参数，一定存在且在 Info( 块内）
    out = re.sub(r"^(\s*port=\d+,\s*\n)",
                 r"\1" + r" " * len(re.match(r'\s*', pm.group(0)).group(0)) + 'requires={},\n'.format(req),
                 out, count=1, flags=re.M)
    if not dry:
        path.write_text(out, encoding='utf-8')
    return 'migrated', req


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--dry-run', action='store_true')
    ap.add_argument('--roots', nargs='*', default=['plugins_corpus', 'plugins'])
    args = ap.parse_args()

    stats = {'migrated': 0, 'already': 0, 'skip': 0}
    req_count = {}
    scanned = 0
    for root in args.roots:
        for path in sorted(pathlib.Path(ROOT / root).rglob('*.py')):
            if path.name.startswith('__') or '__pycache__' in str(path):
                # __ 前缀是模板/样例，仍要迁移（引擎加载会崩），这里排除的是 __init__ 等
                if path.name in ('__init__.py',):
                    continue
            scanned += 1
            status, req = migrate_file(path, dry=args.dry_run)
            stats[status] += 1
            if status == 'migrated':
                req_count[req] = req_count.get(req, 0) + 1

    print('scanned={} dry_run={}'.format(scanned, args.dry_run))
    print('stats={}'.format(stats))
    for k in sorted(req_count, key=req_count.get, reverse=True):
        print('  requires={} -> {}'.format(k, req_count[k]))
    return 0


if __name__ == '__main__':
    sys.exit(main())
