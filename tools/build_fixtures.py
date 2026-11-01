#!/usr/bin/env python3
# _*_ coding:utf-8 _*_
"""
build_fixtures.py — 任务卡 T1-VERIFY: 插件 mock 真值样本合成器

输入: plugins_corpus 语料插件的模块级 REQS / MATCHERS 声明式数据结构
输出: 每个插件的正样本(必须命中 → VULN) 与负样本(必须落空 → SAFE) mock 响应集合

设计要点
  1) REQS/MATCHERS 用 ast 静态解析 (不 import, 833 插件秒级完成), 与插件运行时语义一致:
     - matcher type: status / word / regex
     - part: body / header / all / response / raw_response / content_type / location
     - condition: and / or (多词/多正则的组内关系)
     - negative: 取反
     - case_insensitive: 大小写不敏感
     - 请求级 matchers_condition: 整条请求的 matcher 聚合关系 (and/or)
  2) 正样本: 逐 matcher 反推"命中所需内容" (词原文 / 正则样本串 / 状态码 / 头字段),
     合成后用插件自身的 _match_one() 复核 —— 语义与被测插件完全一致, 不自造判定逻辑
  3) 负样本: 反向构造, 目标是让整条请求"不命中":
     - 请求级 or  → 所有 matcher 必须为 False
     - 请求级 and → 至少一个 matcher 为 False
     负样本默认"空 body + 空 header"(最小干扰), 只在必要时注入 negative matcher 需要的"必须出现"内容
  4) 合成不了(正则无法构造 / 词与负词在同一 part 互斥 / 状态码互斥)→ 标 untestable 并记原因, 不硬造

用法:
    python3 tools/build_fixtures.py --dump out.json       # 导出全部 fixture(JSON)
    python3 tools/build_fixtures.py --stat                 # 只跑构造 + 自检, 打印统计
"""
import argparse
import ast
import importlib.util
import itertools
import json
import pathlib
import re
import sys
from typing import Any, Dict, List, Optional, Sequence, Tuple

PROJECT = pathlib.Path(__file__).resolve().parent.parent
if str(PROJECT) not in sys.path:
    sys.path.insert(0, str(PROJECT))

import re._parser as _sre  # noqa: E402  (stdlib, 3.11+)
import requests  # noqa: E402
from requests.structures import CaseInsensitiveDict  # noqa: E402

CORPUS = PROJECT / 'plugins_corpus'

# ---------------------------------------------------------------- 配置常量
CT_DEFAULT = 'application/x-fixture; charset=utf-8'   # 默认 Content-Type(带 charset, 保证 UTF-8 解码)
CT_NEUTRAL = 'application/x-fixture; charset=utf-8'   # 负样本默认(尽量不含任何语料词)
STATUS_POOL = (200, 404, 500, 302, 301, 403, 400, 204, 502)
HEADER_NAME_POOL = ('X-Fixture', 'Location', 'Set-Cookie', 'Content-Type', 'Server', 'X-Powered-By')
MAX_COMBOS = 4000      # 单请求合成搜索上限
MAX_BODY_PERM = 5      # body 分块排列上限 (5! = 120)


class Unconstructible(Exception):
    """无法构造出满足条件的样本 (不硬造, 直接标 untestable)"""


class FakeResp:
    """最小 requests.Response 替身: 供插件 _parts()/_match_one() 复核 fixture"""

    def __init__(self, status: int, headers: Dict[str, str], body: str) -> None:
        self.status_code = int(status)
        self.headers = CaseInsensitiveDict(headers)
        self.text = body


# ---------------------------------------------------------------- REQS/MATCHERS 解析
def parse_literals(path: pathlib.Path) -> Tuple[Optional[list], Optional[list]]:
    """ast 静态取模块级 REQS / MATCHERS 字面量 (与插件 import 后读到的值一致)"""
    tree = ast.parse(path.read_text(encoding='utf-8'))
    out: Dict[str, Any] = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            if node.targets[0].id not in ('REQS', 'MATCHERS'):
                continue
            try:
                out[node.targets[0].id] = ast.literal_eval(node.value)
            except (ValueError, SyntaxError):
                out[node.targets[0].id] = None
    return out.get('REQS'), out.get('MATCHERS')


def load_plugin(path: pathlib.Path, mod_name: str):
    spec = importlib.util.spec_from_file_location(mod_name, str(path))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    plg = mod.Plugin()
    # 兼容层: verify_t1 / verify_corpus / verify_supplement_m2a 引用 info.ports (旧契约),
    # 但 utils.plugin.Info 已迁移到 requires 契约并移除 ports。
    # 在加载侧补一个可写 ports 属性 (由 port/ssl_port 派生), 使这些验证脚本可运行;
    # 不改 utils (禁止), 不改 verify 脚本 (任务卡允许列表外)。
    # verify_requires 用独立 loader (不经过本函数), 不受影响。
    info = getattr(plg, 'info', None)
    if info is not None and not hasattr(info, 'ports'):
        base = [int(info.port)] if getattr(info, 'port', None) else []
        sp = getattr(info, 'ssl_port', 0)
        if sp:
            base.append(int(sp))
        info.ports = base
    return plg



# ---------------------------------------------------------------- 正则样本构造
_CAT_MAP = {
    'CATEGORY_DIGIT': '1', 'CATEGORY_NOT_DIGIT': 'a',
    'CATEGORY_SPACE': ' ', 'CATEGORY_NOT_SPACE': 'a',
    'CATEGORY_WORD': 'a', 'CATEGORY_NOT_WORD': '1',
    'CATEGORY_LINEBREAK': '\n', 'CATEGORY_NOT_LINEBREAK': 'a',
    'CATEGORY_UNI_DIGIT': '1', 'CATEGORY_UNI_NOT_DIGIT': 'a',
    'CATEGORY_UNI_SPACE': ' ', 'CATEGORY_UNI_NOT_SPACE': 'a',
    'CATEGORY_UNI_WORD': 'a', 'CATEGORY_UNI_NOT_WORD': '1',
    'CATEGORY_UNI_LINEBREAK': '\n', 'CATEGORY_UNI_NOT_LINEBREAK': 'a',
    'CATEGORY_LOC_WORD': 'a', 'CATEGORY_LOC_NOT_WORD': '1',
    'CATEGORY_LOC_SPACE': ' ', 'CATEGORY_LOC_NOT_SPACE': 'a',
    'CATEGORY_LOC_DIGIT': '1', 'CATEGORY_LOC_NOT_DIGIT': 'a',
}


def _node_sample(node, groups: Dict[int, str], min_rep: int, any_char: str) -> str:
    """按 re._parser legacy 元组布局生成一个匹配样本串

    节点布局: (OPCODE, *args); 复合节点的子参数整体打包在 args[0] 里
      LITERAL/NOT_LITERAL/ANY/AT/CATEGORY/GROUPREF -> args[0] 为标量
      RANGE -> args[0]=(lo,hi);  IN -> args[0]=节点列表(含 NEGATE 表示取反)
      MIN_REPEAT/MAX_REPEAT/POSSESSIVE_REPEAT -> args[0]=(min,max,子节点列表)
      SUBPATTERN -> args[0]=(group,add_flags,del_flags,子节点列表)
      BRANCH -> args[0]=(None,[分支列表]);  ASSERT/ASSERT_NOT -> args[0]=(dir,子节点列表)
    """
    if isinstance(node, list):
        return ''.join(_node_sample(it, groups, min_rep, any_char) for it in node)
    if isinstance(node, _sre.SubPattern):
        return ''.join(_node_sample(it, groups, min_rep, any_char) for it in node.data)
    if not isinstance(node, tuple) or not node:
        raise Unconstructible('node:%r' % (node,))
    op = getattr(node[0], 'name', node[0])
    a = node[1] if len(node) > 1 else None
    if op == 'LITERAL':
        return chr(a)
    if op == 'NOT_LITERAL':
        c = chr(a)
        return any_char if c != any_char else 'b'
    if op == 'ANY':
        return any_char
    if op == 'AT':
        return ''
    if op == 'IN':
        items = a or []
        negate = any(isinstance(it, tuple) and it and getattr(it[0], 'name', it[0]) == 'NEGATE' for it in items)
        cands: List[str] = []
        for it in items:
            if isinstance(it, tuple) and it and getattr(it[0], 'name', it[0]) == 'NEGATE':
                continue
            try:
                cands.append(_node_sample(it, groups, min_rep, any_char))
            except Unconstructible:
                continue
        if negate:
            for ch in (any_char, 'Z', '0', ' ', '_'):
                if ch not in cands:
                    return ch
            raise Unconstructible('negated-class')
        if not cands:
            raise Unconstructible('empty-class')
        return cands[0]
    if op == 'CATEGORY':
        return _CAT_MAP.get(a, any_char)
    if op == 'RANGE':
        lo = a[0]
        try:
            return chr(lo)
        except (ValueError, OverflowError):
            return any_char
    if op == 'BRANCH':
        branches = a[1] if a else []
        for b in branches:
            try:
                return _node_sample(b, groups, min_rep, any_char)
            except Unconstructible:
                continue
        raise Unconstructible('branch')
    if op in ('MIN_REPEAT', 'MAX_REPEAT'):
        mn, mx, sub = a
        if mx == 0:
            return ''
        cnt = mn if mn > 0 else min_rep
        base = _node_sample(sub, groups, min_rep, any_char)
        return base * max(cnt, 0)
    if op == 'SUBPATTERN':
        group, _add, _del, sub = a
        text = _node_sample(sub, groups, min_rep, any_char)
        groups[group] = text
        return text
    if op == 'ATOMIC_GROUP':
        return _node_sample(a, groups, min_rep, any_char)
    if op == 'POSSESSIVE_REPEAT':
        mn, _mx, sub = a
        return _node_sample(sub, groups, min_rep, any_char) * max(mn, 0)
    if op == 'GROUPREF':
        if a in groups:
            return groups[a]
        raise Unconstructible('groupref')
    if op == 'ASSERT':                      # 正向先行: 把子模式文本直接写出即可满足
        return _node_sample(a[1], groups, min_rep, any_char)
    if op == 'ASSERT_NOT':
        raise Unconstructible('negative-lookahead')
    if op == 'NEGATE':
        raise Unconstructible('negate')
    if op == 'GROUPREF_EXISTS':
        raise Unconstructible('groupref-exists')
    raise Unconstructible('op:%s' % op)


def regex_variants(pattern: str, case_insensitive: bool = False, limit: int = 8) -> List[str]:
    """生成若干"能独立匹配 pattern 的字符串"(每个都用 re.search 自检过)"""
    flags = re.S | (re.I if case_insensitive else 0)
    out: List[str] = []
    try:
        parsed = _sre.parse(pattern, re.RegexFlag(0))
    except re.error as exc:
        raise Unconstructible('re.error:%s' % exc)
    for min_rep in (0, 1):
        for any_char in ('a', 'X', '1', ' '):
            try:
                sample = _node_sample(parsed, {}, min_rep, any_char)
            except Unconstructible:
                continue
            try:
                if re.search(pattern, sample, flags) is None:
                    continue
            except re.error:
                continue
            if sample not in out:
                out.append(sample)
            if len(out) >= limit:
                return out
    if not out:
        raise Unconstructible('no-sample-matches')
    return out


# ---------------------------------------------------------------- 响应合成模型
class Composition:
    """一次响应合成的中间态: body 分块 / 头条目 / Content-Type / Location / status"""

    def __init__(self) -> None:
        self.body_chunks: List[str] = []
        self.headers: List[Tuple[str, str]] = []
        self.ct: Optional[str] = None
        self.loc: Optional[str] = None
        self.status: int = 200

    def copy(self) -> 'Composition':
        c = Composition()
        c.body_chunks = list(self.body_chunks)
        c.headers = list(self.headers)
        c.ct, c.loc, c.status = self.ct, self.loc, self.status
        return c

    def render(self, body_order: Optional[Sequence[int]] = None) -> FakeResp:
        idx = list(range(len(self.body_chunks))) if body_order is None else list(body_order)
        body = '\n'.join(self.body_chunks[i] for i in idx)
        headers: List[Tuple[str, str]] = []
        for k, v in self.headers:
            headers.append((k, v))
        headers.append(('Content-Type', self.ct if self.ct is not None else CT_DEFAULT))
        if self.loc is not None:
            headers.append(('Location', self.loc))
        return FakeResp(self.status, dict(headers), body)

    def render_all_orders(self) -> List[FakeResp]:
        n = len(self.body_chunks)
        if n == 0:
            return [self.render()]
        if n > MAX_BODY_PERM:
            perms = [tuple(range(n)), tuple(reversed(range(n)))]
        else:
            perms = list(itertools.permutations(range(n)))
        return [self.render(p) for p in perms]


# ---------------------------------------------------------------- 放置候选
_PART_TARGETS = {'body': ('body',), 'header': ('header',), 'all': ('body', 'header'),
                 'response': ('body', 'header'), 'raw_response': ('body', 'header')}


def _part_targets(part: str) -> Tuple[str, ...]:
    """matcher part 可实际投放的目标片段 (response/all 可投 body 或 header)"""
    return _PART_TARGETS.get(part, (part,))


def _header_pairs(text: str) -> List[Tuple[str, str]]:
    """文本 → 头部 (name, value) 候选; 头串格式固定为 'Name: value', 故 name/value 需能还原该文本"""
    out: List[Tuple[str, str]] = []
    if ':' in text:
        i = text.index(':')
        out.append((text[:i], text[i + 1:].lstrip()))
        out.append((text[:i], text[i + 1:]))
    out.append(('X-Fixture', text))
    for name in HEADER_NAME_POOL:
        out.append((name, text))
    seen = set()
    uniq = []
    for k, v in out:
        if (k, v) in seen:
            continue
        seen.add((k, v))
        uniq.append((k, v))
    return uniq


def _place_word_group(words: List[str], part: str) -> List[Composition]:
    """把一组词(同属一个 word matcher)放到指定 part; 组内全部词都要命中"""
    cands: List[Composition] = []
    if not words:
        return cands
    for p in _part_targets(part):
        if p == 'body':
            c = Composition()
            c.body_chunks.extend(words)
            cands.append(c)
            if len(words) > 1:
                c2 = Composition()
                c2.body_chunks.append(' '.join(words))
                cands.append(c2)
        elif p == 'header':
            c = Composition()
            for w in words:
                c.headers.append(('X-Fixture', w))
            cands.append(c)
            if len(words) > 1:
                c2 = Composition()
                c2.headers.append(('X-Fixture', ' '.join(words)))
                cands.append(c2)
        elif p == 'content_type':
            c = Composition()
            c.ct = ' '.join(words)
            cands.append(c)
        elif p == 'location':
            c = Composition()
            c.loc = ' '.join(words)
            cands.append(c)
    return cands


def _place_regex_group(rxs: List[str], part: str, ci: bool) -> List[Composition]:
    """把一组正则(同属一个 regex matcher)放到指定 part; 组内每个正则都要能命中"""
    cands: List[Composition] = []
    if not rxs:
        return cands
    sample_sets = []
    for rx in rxs:
        sample_sets.append(regex_variants(rx, ci, limit=4))
    if any(not s for s in sample_sets):
        return cands
    for p in _part_targets(part):
        if p == 'body':
            for combo in itertools.product(*[s[:2] for s in sample_sets]):
                c = Composition()
                c.body_chunks.extend(combo)
                cands.append(c)
            for combo in itertools.product(*[s[:1] for s in sample_sets]):
                c = Composition()
                c.body_chunks.append(' '.join(combo))
                cands.append(c)
        elif p == 'header':
            for combo in itertools.product(*[s[:2] for s in sample_sets]):
                for pair in _header_pairs(combo[0])[:8]:
                    c = Composition()
                    c.headers.append(pair)
                    for extra in combo[1:]:
                        c.headers.append(('X-Fixture', extra))
                    cands.append(c)
            # condition:and 时组内全部正则都需命中; 多个同名 X-Fixture 头在
            # requests.CaseInsensitiveDict 里只保留一个, 会导致 _match_one 的
            # regex and 复核失败。提供「全部样本合并进单个头」的兜底候选。
            for combo in itertools.product(*[s[:1] for s in sample_sets]):
                c = Composition()
                c.headers.append(('X-Fixture', ' '.join(combo)))
                cands.append(c)
                for pair in _header_pairs(combo[0])[:4]:
                    c2 = Composition()
                    c2.headers.append((pair[0], ' '.join(combo)))
                    cands.append(c2)
        elif p == 'content_type':
            for combo in itertools.product(*[s[:1] for s in sample_sets]):
                c = Composition()
                c.ct = ' '.join(combo)
                cands.append(c)
        elif p == 'location':
            for combo in itertools.product(*[s[:1] for s in sample_sets]):
                c = Composition()
                c.loc = ' '.join(combo)
                cands.append(c)
    return cands


def matcher_placements(m: dict) -> List[Composition]:
    """单个 matcher 的候选放置列表(每个候选自成一个 Composition 片段)"""
    part = m.get('part', 'body')
    ci = m.get('case_insensitive', False)
    cond = m.get('condition', 'or')
    if m['type'] == 'word':
        words = m.get('words') or []
        cands = _place_word_group(words, part)
        if cond != 'and' and len(words) > 1:
            for w in words:
                cands.extend(_place_word_group([w], part))
        return cands
    if m['type'] == 'regex':
        rxs = m.get('regex') or []
        if cond == 'and':
            # 组内全部正则都需命中: 任一不可构造即无法构造
            return _place_regex_group(rxs, part, ci)
        cands: List[Composition] = []
        for rx in rxs:
            try:
                cands.extend(_place_regex_group([rx], part, ci))
            except Unconstructible:
                continue
        if not cands:
            raise Unconstructible('no-constructible-regex-in-group')
        try:
            cands.extend(_place_regex_group(rxs, part, ci))
        except Unconstructible:
            pass
        return cands
    # status matcher: 只需状态码, 无内容放置
    return [Composition()]


def _merge(base: Composition, add: Composition) -> Composition:
    """合并放置候选; 状态码不在此传播 (由 base 统一设定, 否则会覆盖已选状态)"""
    out = base.copy()
    out.body_chunks.extend(add.body_chunks)
    out.headers.extend(add.headers)
    if add.ct is not None:
        out.ct = add.ct
    if add.loc is not None:
        out.loc = add.loc
    return out


def _matchers_of(mats: List[dict], req_idx: int) -> List[dict]:
    return [m for m in mats if m.get('req_idx') == req_idx]


# ---------------------------------------------------------------- 状态码选择
def choose_status(mats: List[dict], want_true: bool) -> Optional[int]:
    """want_true: 让所有 status matcher 为 True; 否则为 False"""
    pos = [m.get('status') or [] for m in mats if m['type'] == 'status' and not m.get('negative')]
    neg = [m.get('status') or [] for m in mats if m['type'] == 'status' and m.get('negative')]
    if want_true:
        if pos:
            cand = set(pos[0])
            for lst in pos[1:]:
                cand &= set(lst)
            for s in sorted(cand):
                if all(s not in lst for lst in neg):
                    return s
            return None
        for s in STATUS_POOL:
            if all(s not in lst for lst in neg):
                return s
        return None
    if neg:
        cand = set(neg[0])
        for lst in neg[1:]:
            cand &= set(lst)
        for s in sorted(cand):
            if all(s not in lst for lst in pos):
                return s
        return None
    for s in STATUS_POOL:
        if all(s not in lst for lst in pos):
            return s
    return None


# ---------------------------------------------------------------- 匹配求值(用插件自身逻辑)
def eval_matchers(plg, resp: FakeResp, mats: List[dict]) -> List[bool]:
    return [bool(plg._match_one(resp, m)) for m in mats]


def request_hits(plg, resp: FakeResp, mats: List[dict], cond: str) -> bool:
    """按插件 run() 的聚合语义判断整条请求是否命中"""
    res = eval_matchers(plg, resp, mats)
    if not res:
        return False
    return all(res) if cond == 'and' else any(res)


# ---------------------------------------------------------------- 正样本合成
def build_positive(plg, req: dict, mats: List[dict]) -> Tuple[Optional[FakeResp], Optional[str]]:
    """构造满足全部 matcher 的响应 (命中 → VULN)"""
    if not mats:
        return None, 'no-matchers'
    status = choose_status(mats, want_true=True)
    if status is None:
        return None, 'status-conflict(正样本无法同时满足全部 status matcher)'
    # 每个 matcher 的放置候选
    cand_lists: List[List[Composition]] = []
    for m in mats:
        if m.get('negative'):
            # negative matcher 要求"词缺席", 正样本不投放任何内容 (由最终校验保证不误命中)
            cand_lists.append([Composition()])
            continue
        try:
            cands = matcher_placements(m)
        except Unconstructible as exc:
            return None, 'regex-unconstructible:%s' % exc
        if not cands:
            return None, 'no-placement(%s)' % m.get('type')
        cand_lists.append(cands)
    tried = 0
    for combo in itertools.product(*cand_lists):
        comp = Composition()
        comp.status = status
        for add in combo:
            comp = _merge(comp, add)
        for resp in comp.render_all_orders():
            tried += 1
            if tried > MAX_COMBOS:
                return None, 'combo-limit'
            if all(eval_matchers(plg, resp, mats)):
                return resp, None
    return None, 'no-combination-satisfies-all-matchers'


# ---------------------------------------------------------------- 负样本合成
def _negative_injections(m: dict) -> List[Composition]:
    """negative matcher 想变 False, 必须让"词出现 / 正则命中"; status 由状态码选择处理"""
    if m['type'] == 'status':
        return [Composition()]
    try:
        return matcher_placements(m)
    except Unconstructible:
        return []


def build_negative(plg, req: dict, mats: List[dict]) -> Tuple[Optional[FakeResp], Optional[str]]:
    """构造不命中的响应 (落空 → SAFE)"""
    if not mats:
        return None, 'no-matchers'
    cond = req.get('matchers_condition', 'or')
    neg_mats = [m for m in mats if m.get('negative')]
    status_opts = []
    s_false = choose_status(mats, want_true=False)
    if s_false is not None:
        status_opts.append(s_false)
    for s in STATUS_POOL:
        if s not in status_opts:
            status_opts.append(s)
    # 注入组合: 不注入 / 逐个注入 / 全部注入
    inj_sets: List[List[Composition]] = [[]]
    per_matcher: List[List[Composition]] = []
    for m in neg_mats:
        cands = _negative_injections(m)
        per_matcher.append(cands)
    for cands in per_matcher:
        inj_sets.append(list(cands))
    if len(per_matcher) > 1:
        inj_sets.append([c for cands in per_matcher for c in cands])
    tried = 0
    for inj in inj_sets:
        for st in status_opts:
            comp = Composition()
            comp.status = st
            for add in inj:
                comp = _merge(comp, add)
            for resp in comp.render_all_orders():
                tried += 1
                if tried > MAX_COMBOS:
                    return None, 'combo-limit'
                if not request_hits(plg, resp, mats, cond):
                    return resp, None
    return None, 'no-combination-avoids-match'


# ---------------------------------------------------------------- 插件级 fixture
def build_fixture(plg, reqs: List[dict], mats: List[dict]) -> Dict[str, Any]:
    """为一个插件生成正/负两组响应 (按 req_idx 对齐)"""
    pos: List[Optional[FakeResp]] = []
    neg: List[Optional[FakeResp]] = []
    reasons: List[str] = []
    for req in reqs:
        idx = req.get('req_idx')
        sub = _matchers_of(mats, idx)
        p_resp, p_why = build_positive(plg, req, sub)
        if p_resp is None:
            reasons.append('req%s:pos:%s' % (idx, p_why))
        pos.append(p_resp)
        n_resp, n_why = build_negative(plg, req, sub)
        if n_resp is None:
            reasons.append('req%s:neg:%s' % (idx, n_why))
        neg.append(n_resp)
    return {'pos': pos, 'neg': neg, 'reasons': reasons}


def fixture_to_json(fx: Dict[str, Any]) -> Dict[str, Any]:
    def enc(rs: Optional[FakeResp]):
        if rs is None:
            return None
        return {'status': rs.status_code,
                'headers': {k: v for k, v in rs.headers.items()},
                'body': rs.text}
    return {'pos': [enc(r) for r in fx['pos']], 'neg': [enc(r) for r in fx['neg']],
            'reasons': fx['reasons']}


# ---------------------------------------------------------------- 主流程
def corpus_entries(read_only_only: bool = True) -> List[dict]:
    man = json.loads((CORPUS / 'manifest.json').read_text(encoding='utf-8'))
    if read_only_only:
        man = [e for e in man if e.get('risk_class') == 'read_only']
    return man


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument('--dump', help='导出 fixture JSON 路径')
    ap.add_argument('--stat', action='store_true', help='只统计构造成功率')
    ap.add_argument('--limit', type=int, default=0)
    args = ap.parse_args()

    entries = corpus_entries()
    if args.limit:
        entries = entries[:args.limit]
    dump: Dict[str, Any] = {}
    ok = untest = 0
    reasons: Dict[str, int] = {}
    for i, entry in enumerate(entries):
        path = CORPUS / entry['file']
        reqs, mats = parse_literals(path)
        if reqs is None or mats is None:
            untest += 1
            reasons['no-literal'] = reasons.get('no-literal', 0) + 1
            continue
        try:
            plg = load_plugin(path, 'fx_%d' % i)
        except Exception as exc:
            untest += 1
            key = 'import-error'
            reasons[key] = reasons.get(key, 0) + 1
            continue
        fx = build_fixture(plg, reqs, mats)
        if fx['reasons']:
            untest += 1
            for r in fx['reasons']:
                head = r.split(':')[0] + ':' + r.split(':')[1] + ':' + r.split(':')[2].split('(')[0]
                reasons[head] = reasons.get(head, 0) + 1
        else:
            ok += 1
        if args.dump:
            dump[entry['file']] = fixture_to_json(fx)
    print('plugins=%d fixture_ok=%d fixture_unconstructible=%d' % (len(entries), ok, untest))
    for k, v in sorted(reasons.items(), key=lambda kv: -kv[1]):
        print('  %-55s %d' % (k, v))
    if args.dump:
        pathlib.Path(args.dump).write_text(json.dumps(dump, ensure_ascii=False, indent=1), encoding='utf-8')
        print('dumped -> %s' % args.dump)
    return 0


if __name__ == '__main__':
    sys.exit(main())
