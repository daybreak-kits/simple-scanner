#!/usr/bin/env python3
"""T3ENV-B staging: 把 plugins_corpus 的 read_only 插件按目标端口复制到 plugins/T2B_<名>.py。
用法: stage_t2b.py <target_port> [--dry-run]
替换规则（只改 Info 声明行的端口字段）:
  port=NN       -> port=<target>
  ssl_port=NN   -> ssl_port=<target>
  ports=[...]   -> ports=[<target>]
不改 plugins_corpus/、utils/、ss.py。
"""
import json
import os
import re
import sys

ROOT = '/opt/workspace/labs/simple-scanner'
CORPUS = os.path.join(ROOT, 'plugins_corpus')
PLUGINS = os.path.join(ROOT, 'plugins')
MANIFESTS = ['manifest.json', 'manifest-vulns.json']

PORT_RE = re.compile(r'^(\s*)port=(\d+),?\s*$', re.M)
SSL_RE = re.compile(r'^(\s*)ssl_port=(\d+),?\s*$', re.M)
PORTS_RE = re.compile(r'^(\s*)ports=\[[^\]]*\],?\s*$', re.M)


def main():
    target = int(sys.argv[1])
    dry = '--dry-run' in sys.argv[2:]
    entries = []
    for mf in MANIFESTS:
        man = json.load(open(os.path.join(CORPUS, mf), encoding='utf-8'))
        entries += [x for x in man if x['risk_class'] == 'read_only']
    if dry:
        print('read_only entries:', len(entries))
    staged, skipped = 0, []
    for e in entries:
        src = os.path.join(CORPUS, e['file'])
        dst = os.path.join(PLUGINS, 'T2B_' + os.path.basename(e['file']))
        text = open(src, encoding='utf-8').read()
        new = PORTS_RE.sub(r'\g<1>ports=[%d],' % target, text)
        new = PORT_RE.sub(r'\g<1>port=%d,' % target, new)
        new = SSL_RE.sub(r'\g<1>ssl_port=%d,' % target, new)
        # 校验：三个字段都被替换且只剩目标端口
        if 'ports=[%d]' % target not in new or 'port=%d,' % target not in new or 'ssl_port=%d,' % target not in new:
            skipped.append((e['file'], 'decl-not-replaced'))
            continue
        if dry:
            staged += 1
            continue
        open(dst, 'w', encoding='utf-8').write(new)
        staged += 1
    print('staged:', staged, 'skipped:', len(skipped))
    for s in skipped[:20]:
        print('  SKIP', s)
    # 复核残留
    if not dry:
        bad = []
        for f in os.listdir(PLUGINS):
            if f.startswith('T2B_'):
                t = open(os.path.join(PLUGINS, f), encoding='utf-8').read()
                if ('ports=[%d]' % target) not in t:
                    bad.append(f)
        print('leftover-with-wrong-port:', bad)


if __name__ == '__main__':
    main()
