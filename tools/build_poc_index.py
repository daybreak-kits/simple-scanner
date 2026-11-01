#!/usr/bin/env python3
# _*_ coding:utf-8 _*_
"""
build_poc_index.py — PoC-in-GitHub 补充索引生成器

数据源: nomi-sec/PoC-in-GitHub（按年份 json 目录, 每 CVE 一个 json, 内容是 GitHub 仓库对象数组）
通道  : jsDelivr CDN（GitHub 直连不可用时的代理）; api.github.com 仅探测一次
范围  : 2023-2026 年的 CVE 索引（任务卡 P2: 语料 1500 + 本包插件未覆盖的 2023-2026 CVE）
产物  : research/poc-in-github-index.json = {cve: [poc_repo_urls]}
  另把"覆盖状态"统计打到 stdout（corpus 覆盖 / 本包覆盖 / 新增补充覆盖）。

用法  : python3 tools/build_poc_index.py [--years 2023 2024 2025 2026] [--concurrency 6]
缓存  : /tmp/opencode/poc-json/ 按 CVE 缓存原始 json, 断点续跑
"""
import argparse
import concurrent.futures
import json
import os
import pathlib
import re
import sys
import time
import urllib.error
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent
CACHE = pathlib.Path('/tmp/opencode/poc-json')
CVE_RE = re.compile(r'CVE-\d{4}-\d{4,7}', re.I)
FLAT_URL = 'https://data.jsdelivr.com/v1/packages/gh/nomi-sec/PoC-in-GitHub@master?structure=flat'
FILE_URL = 'https://cdn.jsdelivr.net/gh/nomi-sec/PoC-in-GitHub@master/{path}'


def http_get(url: str, timeout: int = 60, retry: int = 3) -> bytes:
    last = None
    for i in range(retry):
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0 simple-scanner-m2a'})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.read()
        except urllib.error.HTTPError as e:
            if e.code in (404, 403, 410):
                raise RuntimeError('GET {} HTTP {}'.format(url, e.code))  # 永久缺失, 不重试
            last = e
            time.sleep(0.8 * (i + 1))
        except Exception as e:  # noqa: BLE001
            last = e
            time.sleep(0.8 * (i + 1))
    raise RuntimeError('GET {} failed: {}'.format(url, last))


def fetch_flat(cache: pathlib.Path) -> list:
    if cache.exists():
        raw = json.loads(cache.read_text())
        if not isinstance(raw, list):
            data = raw  # 旧版缓存: data.jsdelivr 原始响应（含 'files' 键）
        else:
            return raw
    else:
        data = json.loads(http_get(FLAT_URL))
    files = [f['name'].lstrip('/') for f in (data.get('files') or []) if f['name'].lstrip('/').endswith('.json')]
    cache.write_text(json.dumps(files))
    return files


def load_corpus_cves() -> set:
    manifest = json.loads((ROOT / 'plugins_corpus/manifest.json').read_text())
    return {x['cve'].upper() for x in manifest}


def load_supplement_cves() -> set:
    sup = ROOT / 'plugins_corpus/supplement'
    out = set()
    if sup.is_dir():
        for f in sup.glob('*.py'):
            m = CVE_RE.search(f.name)
            if m:
                out.add(m.group(0).upper())
    return out


def parse_cve_file(path: str, raw: bytes) -> list:
    """每个 json = GitHub 仓库对象数组 → [html_url]"""
    try:
        items = json.loads(raw)
    except Exception:
        return []
    if not isinstance(items, list):
        return []
    urls = []
    for it in items:
        if isinstance(it, dict) and it.get('html_url'):
            urls.append(it['html_url'])
    return urls


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--years', nargs='+', default=['2023', '2024', '2025', '2026'])
    ap.add_argument('--concurrency', type=int, default=6)
    ap.add_argument('--flat-cache', default=str(CACHE.parent / 'poc-flat.json'))
    args = ap.parse_args()
    CACHE.mkdir(parents=True, exist_ok=True)

    files = fetch_flat(pathlib.Path(args.flat_cache))
    # 只保留目标年份的 CVE json
    targets = []
    for f in files:
        head = f.split('/')[0]
        if head in args.years:
            m = CVE_RE.search(f)
            if m:
                targets.append((f, m.group(0).upper()))
    print('target CVE json files ({}): {}'.format(','.join(args.years), len(targets)), flush=True)

    corpus = load_corpus_cves()
    supplement = load_supplement_cves()
    covered = corpus | supplement

    results = {}
    errors = 0

    def dl(pair):
        path, cve = pair
        cp = CACHE / '{}.json'.format(cve)
        if cp.exists():
            raw = cp.read_bytes()
        else:
            try:
                raw = http_get(FILE_URL.format(path=path))
                cp.write_bytes(raw)
                time.sleep(0.03)
            except RuntimeError:
                return cve, []
        return cve, parse_cve_file(path, raw)

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrency) as ex:
        futs = [ex.submit(dl, pair) for pair in targets]
        for i, fut in enumerate(concurrent.futures.as_completed(futs), 1):
            cve, urls = fut.result()
            if urls:
                results[cve] = urls
            if i % 500 == 0:
                print('  ... {}/{} done, {} with poc'.format(i, len(targets), len(results)), flush=True)

    # 落盘: 全量 2023-2026 {} cve: [urls]
    out = {k: results[k] for k in sorted(results)}
    out_path = ROOT / 'research/poc-in-github-index.json'
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(out, ensure_ascii=False, indent=0) + '\n')

    new_cves = [c for c in sorted(results) if c not in covered]
    covered_within = [c for c in sorted(results) if c in covered]
    sum_poc = sum(len(v) for v in out.values())
    print('== stats ==')
    print('index entries (CVE with >=1 poc repo):', len(out))
    print('total poc repo urls:', sum_poc)
    print('entries already covered by corpus(1500)+supplement:', len(covered_within))
    print('NEW covered by this index (2023-2026 uncovered before):', len(new_cves))
    print('poC-in-GitHub 2023-2026 files total:', len(targets), ' with-no-poc-or-404:', len(targets) - len(out))
    print('written:', out_path)


if __name__ == '__main__':
    main()