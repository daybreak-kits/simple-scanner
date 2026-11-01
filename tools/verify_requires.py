#!/usr/bin/env python3
# _*_ coding:utf-8 _*_
"""verify_requires.py — 全量校验插件已迁移到 `requires` 新契约

对每个插件文件：
  1. importlib 从文件路径加载模块（独立模块名，避免同名 CVE 互相污染）
  2. 实例化 `Plugin()`
  3. 断言 `info.requires` 非空且是 list[str]
  4. 断言 `info.requires` 与 `info.protocol` 符合规范映射表
  5. 断言 `info.port` 仍是正整数（-dps 模式与默认端口依赖它）

输出：总数 / 通过 / 失败，失败逐条打印「文件 + 异常」。
退出码 0 = 全过，1 = 有失败。

用法：
    python tools/verify_requires.py
    python tools/verify_requires.py --roots plugins            # 只验常驻插件
    python tools/verify_requires.py --show-ok                  # 打印每条通过记录
"""

import argparse
import importlib.util
import pathlib
import sys
import traceback

PROJECT_ROOT = pathlib.Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# 规范映射表（与 tools/migrate_requires.py 保持一致）
REQUIRES_BY_PROTOCOL = {
    'http': ['http', 'https'],
    'tcp': ['tcp'],
    't3': ['t3'],
}

DEFAULT_ROOTS = ('plugins_corpus', 'plugins')
SKIP_DIR_NAMES = {'__pycache__', '.venv', '.git', 'node_modules'}


def expected_requires(protocol):
    return list(REQUIRES_BY_PROTOCOL.get(protocol, [protocol]))


def iter_plugin_files(roots):
    seen = set()
    for root in roots:
        p = pathlib.Path(root)
        if not p.exists():
            continue
        paths = [p] if p.is_file() else sorted(p.rglob('*.py'))
        for f in paths:
            if any(part in SKIP_DIR_NAMES for part in f.parts):
                continue
            key = f.resolve()
            if key in seen:
                continue
            seen.add(key)
            yield f


def load_plugin_module(path, idx):
    """按文件路径加载模块，返回 module。模块名唯一，避免同名/同 stem 冲突。"""
    mod_name = '_verify_plugin_{}_{}'.format(idx, path.stem.replace('-', '_').replace('.', '_'))
    spec = importlib.util.spec_from_file_location(mod_name, str(path.resolve()))
    if spec is None or spec.loader is None:
        raise ImportError('cannot build import spec for {}'.format(path))
    mod = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = mod
    try:
        spec.loader.exec_module(mod)
    finally:
        # 不留在 sys.modules 里，避免 2000+ 模块常驻
        sys.modules.pop(mod_name, None)
    return mod


def check_one(path, idx):
    """校验单个插件，返回错误串列表（空 = 通过）。"""
    errors = []
    mod = load_plugin_module(path, idx)
    if not hasattr(mod, 'Plugin'):
        return ['module has no Plugin class']
    plugin = mod.Plugin()
    info = getattr(plugin, 'info', None)
    if info is None:
        return ['instance has no .info']

    req = getattr(info, 'requires', '<missing>')
    if req is None:
        errors.append('info.requires is None (expected non-empty list)')
    elif not isinstance(req, list):
        errors.append('info.requires is {!r}, expected list'.format(type(req).__name__))
    elif not req:
        errors.append('info.requires is empty list')
    else:
        bad = [x for x in req if not isinstance(x, str) or not x]
        if bad:
            errors.append('info.requires has non-str/empty items: {!r}'.format(bad))

    proto = getattr(info, 'protocol', None)
    if not isinstance(proto, str) or not proto:
        errors.append('info.protocol is not a non-empty str: {!r}'.format(proto))
    elif not errors:
        want = expected_requires(proto)
        if req != want:
            errors.append('info.requires={!r} != expected {!r} for protocol={!r}'.format(req, want, proto))

    port = getattr(info, 'port', None)
    if not isinstance(port, int) or port <= 0:
        errors.append('info.port is not a positive int: {!r}'.format(port))

    # 旧契约字段必须已彻底消失
    if 'ports' in getattr(info, '__dict__', {}):
        errors.append('legacy attr info.ports still present')

    return errors


def main(argv=None):
    ap = argparse.ArgumentParser(description='全量校验插件 requires 契约')
    ap.add_argument('--roots', nargs='+', default=list(DEFAULT_ROOTS),
                    help='校验的根目录/文件（默认: plugins_corpus plugins）')
    ap.add_argument('--show-ok', action='store_true', help='打印每条通过记录')
    ap.add_argument('--max-errors', type=int, default=0, help='失败明细最多打印条数，0=不限')
    args = ap.parse_args(argv)

    files = list(iter_plugin_files(args.roots))
    total = 0
    passed = 0
    failures = []

    for idx, path in enumerate(files):
        total += 1
        try:
            errors = check_one(path, idx)
        except Exception:
            errors = ['EXCEPTION:\n' + traceback.format_exc()]
        if errors:
            failures.append((str(path), errors))
            if args.show_ok:
                print('FAIL {}'.format(path))
        else:
            passed += 1
            if args.show_ok:
                print('OK   {}'.format(path))

    print()
    print('=' * 66)
    print('插件文件总数 : {}'.format(total))
    print('通过         : {}'.format(passed))
    print('失败         : {}'.format(len(failures)))
    print('=' * 66)
    if failures:
        shown = failures if not args.max_errors else failures[: args.max_errors]
        for path, errors in shown:
            print('\nFAILED: {}'.format(path))
            for e in errors:
                for line in str(e).rstrip().splitlines():
                    print('   {}'.format(line))
        if len(shown) < len(failures):
            print('\n... {} more failure(s) not shown'.format(len(failures) - len(shown)))
        return 1
    print('ALL PASS')
    return 0


if __name__ == '__main__':
    sys.exit(main())
