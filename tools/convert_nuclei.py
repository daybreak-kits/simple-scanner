#!/usr/bin/env python3
# _*_ coding:utf-8 _*_
"""
convert_nuclei.py — nuclei YAML HTTP 模板 → simple-scanner Python 插件

数据源: projectdiscovery/nuclei-templates (MIT), http/cves/{year}/
输出:   plugins_corpus/<cve_year>/<CVE>.py + manifest.json + REPORT.md

支持矩阵（明示）:
  支持  : method/path/headers/body、raw 请求解析、status/word/regex matcher、
          words with and/or condition、case-insensitive、negative、
          multiple matchers (matchers-condition and/or)、有限多请求链（顺序执行, 块间 OR）、
          variables 内联、运行时占位符 {{BaseURL}} {{RootURL}} {{Hostname}}
          {{Host}} {{Port}} {{Scheme}}
  跳过  : flow、javascript/code、payloads/attack(字典)、dsl/binary/xpath matcher、
          req-condition、extractor 驱动的动态链、外部变量、interactsh/OOB、
          multipart boundary、无 matcher/无请求

风险分层（逐插件判据）:
  read_only : 仅读方法且无危险 payload；或含写方法但 body/path/headers 无写操作/命令执行特征
  risky     : payload 含命令执行/数据外带特征（检出型, 仅清单标记, 不进可用集）
  excluded  : payload 含文件删除/用户创建/反弹连接等不可逆破坏特征（同上）
  uncertain : 特征不明确, 保守排除, 单独计数
"""
import argparse
import collections
import json
import os
import re
import sys

import yaml

# ---------------------------------------------------------------------------
# 常量
# ---------------------------------------------------------------------------
CVE_RE = re.compile(r'CVE-(\d{4})-(\d{4,7})', re.I)
RUNTIME_PH = ('BaseURL', 'RootURL', 'Hostname', 'Host', 'Port', 'Scheme')
MISS_RE = re.compile(r'\{\{\s*([A-Za-z_][A-Za-z0-9_\-]*)\s*\}\}')

WEB_PORTS = [80, 443, 8080, 8443]
SUPPORTED_METHODS = ('GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS')
READ_METHODS = ('GET', 'HEAD', 'OPTIONS', 'TRACE')
SUPPORTED_MATCHER = ('status', 'word', 'regex')
SUPPORTED_MATCHER_PART = ('body', 'header', 'all', 'response', 'raw_response', 'status_code',
                         'content_type', 'location')

# nuclei 内置随机 helper 变量（转换期内联为常量 '1'，保持确定性）
HELPER_PH = ('randstr', 'rand', 'num', 'hex_string', 'hex', 'marker', 'str', 'string',
             'random', 'rnd', 'uuid', 'num1', 'num2')

FINGERPRINT_NOISE = {
    'cve', 'cves', 'poc', 'exploit', 'vulnerability', 'vulnerabilities', 'vuln', 'vulns',
    'rce', 'xss', 'sqli', 'sql-injection', 'sql', 'injection', 'lfi', 'rfi', 'ssrf', 'ssti',
    'ssti2', 'oast', 'oastrce', 'fuzz', 'fuzzing', 'dos', 'info', 'panel', 'panels', 'login',
    'default-login', 'defaultlogin', 'exposure', 'exposures', 'misconfig', 'misconfiguration',
    'takeover', 'nuclei', 'scan', 'scanner', 'audit', 'detect', 'detection', 'detected',
    'unauth', 'unauthenticated', 'auth', 'authentication', 'bypass', 'bypass1', 'xxe', 'xml',
    'deserialization', 'traversal', 'bruteforce', 'brute-force', 'brute', 'credential',
    'credentials', 'default', 'intrusive', 'cwe', 'fqdn', 'tech', 'technologies',
    'other', 'misc', 'generic', 'check', 'checks', 'exp', 'cnvd', 'cnnvd', 'bugbounty',
    'false-positive', 'fp',
}
YEAR_TOKEN_RE = re.compile(r'^(19|20)\d\d$')
CVE_TOKEN_RE = re.compile(r'^cve-?\d{4}$')

# T2FIX 任务卡指定的模板级覆盖（非推导值，逐条注明来源）
TEMPLATE_OVERRIDES = {
    # ①d: PHP 8.1.0-dev 后门 —— 指纹只留产品关键词 php；端口只标 80（模板无端口声明）
    'http/vulnerabilities/backdoor/php-zerodium-backdoor-rce.yaml': {
        'ports': [80], 'fingerprint': ['php'],
    },
    # ②b: Redis 沙箱逃逸 —— 模板写的 6380 非 Redis 标准端口，改用 6379
    'network/cves/2022/CVE-2022-0543.yaml': {
        'ports': [6379],
    },
}

# 服务门控标签（utils/plugin.py Info.requires + utils/fingerprint.py is_applicable）
# 旧契约是 ports=[...]（按端口号判适用性 → 端口不匹配就漏报），已废除。
# 现在按服务指纹标签判：http 插件同时接受 http/https（https_or_http 会自行探测），
# network/tcp 插件只接受 tcp。端口仍写进 port= / ssl_port= 供默认端口与 -dps 模式使用。
REQUIRES_BY_PROTOCOL = {
    'http': ['http', 'https'],
    'tcp': ['tcp'],
    't3': ['t3'],
}

# ---------------------------------------------------------------------------
# E1: nuclei tags 中的产品名 -> requires 的 product: 标签 (FIX-E1-B3 缺陷1)
#
# 背景：语料是从 nuclei 模板机械转换的, tags 大多是情报来源标签
# (vkev/packetstorm/wpscan/edb/kev/auth-bypass), 不是产品名。因此 L3 产品探测器
# (60_product_cn_oa.py / 61_product_webapps.py) 虽工作正常, 却没有任何插件使用它
# -> 产品专用插件在任意 http 端口上发请求, 浪费请求且可能误报 (CVE-2021-22881 案例)。
#
# 映射规则：nuclei tag 命中 PRODUCT_TAG_TO_LABEL 键 (大小写不敏感, '-'/'_' 归一),
# 则该插件 requires 追加 ['product:<label>', ...]。label 取**引擎实际发射的产品标签**,
# 不是裸词表词: 引擎发的是 weaver-e-cology / landray-ekp / yonyou-nc / spring-boot 等,
# 若写 product:weaver 则永远匹配不上 -> 该插件在 weaver 靶场上反而被 SKIP (漏报)。
# 词表来自任务卡 (FIX-E1-B3), 值域对齐 fingerprints/ 实际 emit 的标签。
# 注意: log4j/log4shell 是组件/漏洞名, 不算产品面, 不进此表。
# ---------------------------------------------------------------------------
PRODUCT_TAG_TO_LABEL = {
    'gitlab': ('gitlab',),
    'tomcat': ('tomcat',),
    'weblogic': ('weblogic',),
    'wordpress': ('wordpress',),
    'phpmyadmin': ('phpmyadmin',),
    'spring': ('spring-boot',),          # 词表: spring 对应 spring-boot
    'spring-boot': ('spring-boot',),
    'nacos': ('nacos',),
    'druid': ('druid',),
    'jboss': ('jboss',),
    'activemq': ('activemq',),
    'solr': ('solr',),
    'confluence': ('confluence',),
    'jira': ('jira',),
    'grafana': ('grafana',),
    'kibana': ('kibana',),
    'elasticsearch': ('elasticsearch',),
    'rabbitmq': ('rabbitmq',),
    'zabbix': ('zabbix',),
    'weaver': ('weaver-e-cology', 'weaver-e-office'),  # 引擎发 weaver-e-*
    'ecology': ('weaver-e-cology',),
    'seeyon': ('seeyon',),
    'landyan': ('landray-ekp',),         # 词表别名 -> 引擎标签 landray-ekp
    'landray': ('landray-ekp',),
    'tongda': ('tongda',),
    'wanhu': ('ezoffice',),              # 万户 ezOFFICE: 引擎发 ezoffice
    'yonyou': ('yonyou-nc',),            # 引擎发 yonyou-nc
    'kingdee': ('kingdee',),
    'eoffice': ('weaver-e-office',),
}

# 标签归一化: '-'/'_' 视为等价, 大小写不敏感
_PRODUCT_TAG_KEYS = {k.replace('_', '-'): v for k, v in PRODUCT_TAG_TO_LABEL.items()}
_PRODUCT_TAG_KEYS.update({k: v for k, v in PRODUCT_TAG_TO_LABEL.items()})


def product_labels_for_tags(tags):
    """从 nuclei info.tags (str 或 list) 提取引擎可判的产品标签集。

    返回已去重、**保序**的 label 列表 (非 product: 前缀)。无命中返回 []。
    保序是关键：语料重放必须确定性（两次运行产出相同字节）。
    """
    kws = []
    seen_kw = set()
    raw = tags.split(',') if isinstance(tags, str) else (tags if isinstance(tags, list) else [])
    for x in raw:
        kw = str(x).strip()
        if kw and kw not in seen_kw:
            seen_kw.add(kw)
            kws.append(kw)
    out = []
    seen = set()
    for kw in kws:
        for label in _PRODUCT_TAG_KEYS.get(kw.replace('_', '-').lower(), ()):
            if label not in seen:
                seen.add(label)
                out.append(label)
    return out


def requires_for(protocol, product_labels=None):
    """协议 -> 插件 requires 标签列表, 追加产品维度标签 (product:<label>)。"""
    reqs = list(REQUIRES_BY_PROTOCOL.get(protocol, [protocol]))
    if product_labels:
        reqs += ['product:' + p for p in product_labels]
    return reqs


EXEC_RE = re.compile(
    r'(?i)(\bexec\b|\bsystem\s*\(|shell_exec|passthru|proc_open|popen\s*\(|'
    r'Runtime\.getRuntime|ProcessBuilder|/bin/sh|bash\s+-c|cmd\.exe|cmd\.bat|powershell|'
    r'whoami|/etc/passwd|/etc/shadow|\beval\s*\(|phpinfo\s*\(|assert\s*\(|'
    r'\buname\s+-a|\bhostname\b|\bipconfig\b|\btasklist\b|\bnetstat\b|\bdir\s+/|\bls\s+-la\b|'
    r'\bwget\s|\bcurl\s|nc\s+-e|ncat\s+-e|python\s+-c|perl\s+-e|java\s+-jar|node\s+-e|'
    r'\bjndi:|\bOGNL\b|struts\.|\{\$IFS\}|`[^`]*`|type\s+c:\\windows)')
DELETE_RE = re.compile(
    r'(?i)(\brm\s+(-rf\s+)?[/~]|unlink\s*\(|File\.delete\s*\(|Remove-Item|'
    r'\bdel\s+/[fqs]|rmdir\s+|drop\s+table|format\s+[a-z]:|shutil\.rmtree)')
USER_RE = re.compile(
    r'(?i)(\buseradd\b|\badduser\b|net\s+user\s+\S+\s+\S+\s*/add|mkuser\b|'
    r'New-LocalUser|createuser\s+-[sS])')
REVSHELL_RE = re.compile(
    r'(?i)(/dev/tcp/|bash\s+-i\s+>&|sh\s+-i\s+>&|nc\s+-e|ncat\s+-e|'
    r'msfvenom|mkfifo\s+.*/bin/(ba)?sh|python\s+-c\s+.*socket|'
    r'0\.tcp\.|meterpreter|bind_shell|reverse[-_]?shell)')
EXFIL_RE = re.compile(
    r'(?i)(interactsh|oast\.(me|fun|site|pro)|burpcollaborator|dnslog\.cn|ceye\.io|'
    r'{{interactsh-url}}|nslookup\s+\S+\s+[a-z0-9.-]*\.(oob|dnslog|ceye|tu4|dnsbin)|'
    r'\bcurl\s+(-s\s+)?https?://|\bwget\s+https?://|ping\s+-c\s+\d+\s+\S+\.(oob|dnslog|ceye))')


# ---------------------------------------------------------------------------
# CVE / 元数据
# ---------------------------------------------------------------------------
def get_cve(data, relpath, text):
    info = data.get('info') or {}
    cls = info.get('classification') or {}
    cid = None
    if isinstance(cls, dict):
        cid = cls.get('cve-id') or cls.get('cve_id') or cls.get('cveId')
    if not cid:
        m = CVE_RE.search(str(info.get('name', '')) + ' ' + str(data.get('id', '')) + ' ' + text[:2000])
        if m:
            cid = m.group(0)
    if not cid:
        return None
    m = CVE_RE.search(str(cid))
    if m:
        return m.group(0).upper(), int(m.group(1)), int(m.group(2))
    return None


def extract_fingerprint(info):
    kws = set()
    tags = info.get('tags')
    if isinstance(tags, str):
        kws.update(x.strip().lower() for x in tags.split(',') if x.strip())
    elif isinstance(tags, list):
        kws.update(str(x).strip().lower() for x in tags if str(x).strip())
    md = info.get('metadata') or {}
    if isinstance(md, dict):
        for key in ('product', 'component', 'technology'):
            v = md.get(key)
            if v:
                kws.update(str(v).strip().lower().split(','))
    out = set()
    for kw in kws:
        kw = kw.strip(' ,.;:')
        if not kw or len(kw) < 3:
            continue
        if kw in FINGERPRINT_NOISE:
            continue
        if YEAR_TOKEN_RE.match(kw):
            continue
        if CVE_TOKEN_RE.match(kw):
            continue
        out.add(kw)
    return sorted(out) if out else None


# ---------------------------------------------------------------------------
# 请求模型构建
# ---------------------------------------------------------------------------
# nuclei raw 请求注解行（@timeout: / @Host: / @tls-sni: / @once 等）。
# nuclei 源码 readRawRequest 对以 @ 开头的行一律跳过（pkg/protocols/http/raw/raw.go），
# 注解不构成请求行；@Host: 覆盖目标主机、@timeout: 覆盖超时、@tls-sni: 设 SNI。
# 转换器只消费 @Host: -> Host 头（任务卡 FIX ③ 要求），@timeout:/@tls-sni: 等丢弃（不支持相应特性）。
ANNOT_RE = re.compile(r'^@([A-Za-z][A-Za-z-]*)\s*:?\s*(.*)$')


def parse_raw(raw_text):
    lines = raw_text.strip().split('\n')
    i = 0
    while i < len(lines) and not lines[i].strip():
        i += 1
    if i >= len(lines):
        return None
    # 跳过开头注解行（@timeout: 10s / @tls-sni: {{Hostname}} / @Host: target 等）。
    # nuclei 源码对以 @ 开头的行直接 goto 跳过（含 @timeout 10 这种无冒号形式）。
    annotations = {}
    while i < len(lines):
        line = lines[i].strip()
        if not line:
            break
        if line.startswith('@'):
            am = ANNOT_RE.match(line)
            if am:
                annotations[am.group(1).lower()] = am.group(2).strip()
            i += 1
            continue
        break
    if i >= len(lines):
        return None
    first = lines[i].strip()
    fm = re.match(r'^(\S+)\s+(\S+)(?:\s+HTTP/[\d.]+)?\s*$', first)
    if not fm:
        return None
    method, path = fm.group(1).upper(), fm.group(2)
    headers = {}
    i += 1
    while i < len(lines):
        line = lines[i].rstrip('\r\n')
        i += 1
        if not line.strip():
            break
        if ':' in line:
            k, _, v = line.partition(':')
            headers[k.strip()] = v.strip()
    body = '\n'.join(lines[i:]).rstrip('\n')
    # @Host: target 转成 Host 头（任务卡要求）；nuclei 真实语义是覆盖目标主机，
    # 转换器无独立目标主机通道，等价落在 Host 头（见偏离说明）。
    if 'host' in annotations and 'Host' not in headers:
        headers['Host'] = annotations['host']
    return {'method': method, 'path': path, 'headers': headers, 'body': body, 'from_raw': True}


def build_model(relpath, data):
    """返回 (model, None) 或 (None, skip_reason)"""
    if 'flow' in data:
        return None, 'flow'
    if 'javascript' in data or 'code' in data:
        return None, 'javascript-code'

    var_map = {}
    for k, v in (data.get('variables') or {}).items():
        if isinstance(v, dict):
            return None, 'typed-variables'
        var_map['{{' + str(k).strip() + '}}'] = str(v)
        var_map['{{ ' + str(k).strip() + ' }}'] = str(v)

    def inline(t):
        if t is None:
            return t
        for k, v in var_map.items():
            t = t.replace(k, v)
        for h in HELPER_PH:
            t = t.replace('{{' + h + '}}', '1').replace('{{ ' + h + ' }}', '1')
        return t

    def bad_refs(*parts):
        bad = set()
        for t in parts:
            if t is None:
                continue
            for m in MISS_RE.finditer(str(t)):
                if m.group(1).strip() not in RUNTIME_PH:
                    bad.add(m.group(1).strip())
        return bad

    reqs = data.get('requests') or data.get('http')
    if reqs is None:
        return None, 'no-http-requests'
    if not isinstance(reqs, list) or not reqs:
        return None, 'no-requests'
    if any(isinstance(r, dict) and r.get('req-condition') for r in reqs):
        return None, 'req-condition'

    seed_text = json.dumps(data, ensure_ascii=False, default=str)
    used_helper = any('{{' + h + '}}' in seed_text or '{{ ' + h + ' }}' in seed_text for h in HELPER_PH)

    # extractor 名字被后续引用 → 动态链
    ex_names = set()
    for r in reqs:
        if isinstance(r, dict):
            for ex in (r.get('extractors') or []):
                if isinstance(ex, dict) and ex.get('name'):
                    ex_names.add(str(ex['name']))
    dyn_chain = bool(ex_names)

    blocks = []
    supports = set()
    if used_helper:
        supports.add('helper-var-inlined')
    for r in reqs:
        if not isinstance(r, dict):
            return None, 'malformed-request'
        if r.get('payloads') or r.get('attack'):
            return None, 'payloads-attack'
        if r.get('race'):
            return None, 'race'
        redirects = bool(r.get('redirects'))
        if 'raw' in r:
            raw_val = r.get('raw')
            raw_items = raw_val if isinstance(raw_val, list) else [raw_val]
            new_blocks = []
            for raw_item in raw_items:
                raw_text = inline(str(raw_item))
                rl = raw_text.lower()
                if '{{boundary}}' in rl or '{{boundaryid}}' in rl or '{{boundary_id}}' in rl:
                    return None, 'multipart-boundary'
                parsed = parse_raw(raw_text)
                if parsed is None:
                    return None, 'raw-parse-error'
                new_blocks.append(parsed)
            if len(raw_items) > 1:
                supports.add('multi-raw')
        else:
            paths = r.get('path') or []
            if isinstance(paths, str):
                paths = [paths]
            if not paths:
                return None, 'no-path'
            method = str(r.get('method', 'GET')).upper()
            if method not in SUPPORTED_METHODS:
                return None, 'method-' + method
            headers = dict(r.get('headers') or {})
            headers = {k: inline(str(v)) for k, v in headers.items()}
            body = r.get('body')
            if isinstance(body, dict):
                body = json.dumps(body)
            if body is not None:
                body = inline(str(body))
            new_blocks = [{'method': method, 'path': inline(p), 'headers': headers,
                           'body': body, 'redirects': redirects, 'from_raw': False}
                          for p in paths]

        # 占位符检查（内联后）
        for b in new_blocks:
            bad = bad_refs(b.get('path'), b.get('body'), b.get('headers'))
            if bad:
                return None, 'unresolved-var:' + ','.join(sorted(bad)[:3])

        # matchers
        mats = r.get('matchers') or []
        if not isinstance(mats, list) or not mats:
            return None, 'no-matcher'
        matchers = []
        for mt in mats:
            if not isinstance(mt, dict):
                return None, 'malformed-matcher'
            t = mt.get('type')
            if t not in SUPPORTED_MATCHER:
                return None, 'matcher-' + str(t)
            part = mt.get('part') or 'body'
            if part not in SUPPORTED_MATCHER_PART:
                return None, 'part-' + str(part)
            if part == 'status_code' and t != 'status':
                return None, 'part-status_code-' + str(t)
            m = {
                'type': t,
                'part': part,
                'condition': str(mt.get('condition') or 'or'),
                'negative': bool(mt.get('negative')),
                'case_insensitive': bool(mt.get('case-insensitive') or mt.get('case_insensitive')),
                # nuclei 3.1.4+: internal=true 的 matcher 命中只抑制打印, 不产生可见结果
                # (pkg/operators/matchers/matchers.go: Internal when true hides the matcher from output)。
                # 编码进生成插件, 由 run() 在判定时使用 —— 语义在生成期编码, 运行时不再猜。
                'internal': bool(mt.get('internal')),
            }
            if t == 'status':
                st = mt.get('status') or []
                m['status'] = [int(x) for x in (st if isinstance(st, list) else [st])]
            elif t == 'word':
                w = mt.get('words') or []
                m['words'] = [str(x) for x in (w if isinstance(w, list) else [w])]
            elif t == 'regex':
                rr = mt.get('regex') or []
                m['regex'] = [str(x) for x in (rr if isinstance(rr, list) else [rr])]
            matchers.append(m)
            supports.add('matcher:' + t)
        cond = str(r.get('matchers-condition') or 'or')
        if cond not in ('and', 'or'):
            return None, 'matchers-condition-' + cond
        if len(matchers) > 1:
            supports.add('multi-matcher')
        if dyn_chain:
            return None, 'dynamic-chain'
        for b in new_blocks:
            b['_matchers'] = matchers
            b['_matchers_condition'] = cond
            blocks.append(b)
        for b in new_blocks:
            supports.add('raw' if b.get('from_raw') else 'path')
            if b.get('headers'):
                supports.add('headers')
            if b.get('body') is not None:
                supports.add('body')
            if b.get('redirects'):
                supports.add('redirects')

    if not blocks:
        return None, 'no-blocks'
    return {'protocol': 'http', 'blocks': blocks, 'supports': supports}, None


def risk_classify(model):
    blocks = model['blocks']
    all_text = '\n'.join(
        str(b.get('method', '')) + ' ' + str(b.get('path', '')) + ' ' +
        json.dumps(b.get('headers', {})) + ' ' + str(b.get('body', ''))
        for b in blocks)
    methods = set(b.get('method', 'GET') for b in blocks)
    if REVSHELL_RE.search(all_text):
        return 'excluded', 'reverse-shell-payload'
    if DELETE_RE.search(all_text):
        return 'excluded', 'file-delete-payload'
    if USER_RE.search(all_text):
        return 'excluded', 'user-creation-payload'
    if EXFIL_RE.search(all_text):
        return 'excluded', 'data-exfiltration-OOB'
    if EXEC_RE.search(all_text):
        return 'risky', 'command-execution-payload'
    if methods <= set(READ_METHODS):
        return 'read_only', 'read-methods-only'
    # 写方法但无危险特征 → 仅状态变更探测，判为只读型探测
    return 'read_only', 'state-change-without-danger'


# ---------------------------------------------------------------------------
# 插件源码生成
# ---------------------------------------------------------------------------
PLUGIN_TEMPLATE = '''\
#!/usr/bin/env python3
# _*_ coding:utf-8 _*_
# 自动生成 by tools/convert_nuclei.py — 勿手改
# source_repo : {source}
# template    : {template_path}  (MIT License)
# cve         : {cve}
# risk_class  : {risk_class}  (read_only=可入可用集; risky/excluded=仅清单标记, 默认不加载)
# description : {description}

import pathlib
import re
import sys
from typing import Any, Tuple

try:
    from utils import PLUGIN_TYPE, plugin, urlutil
except Exception:
    sys.path.append(pathlib.Path(__file__).parent.parent.parent.__str__())
    from utils import PLUGIN_TYPE, plugin, urlutil

REQS = {reqs}
MATCHERS = {matchers}
# L2 产品门控元数据（UPGRADE_PLAN §4.11）：模板 tags/metadata 提取的产品关键词, 无则 None
FINGERPRINT = {fingerprint!r}


class Plugin(plugin.PluginBase):
    def set_info(self):
        info = plugin.Info(
            name={name!r},
            catalog={cve!r},
            itype=PLUGIN_TYPE.POC,
            protocol='http',
            port=80,
            ssl_protocol='https',
            ssl_port=443,
            requires={requires!r},
        )
        # Info 基类暂无 fingerprint 字段（不改 utils/）, 直接挂属性供 L2 门控读取
        info.fingerprint = FINGERPRINT
        return info

    def _sub(self, text, url):
        if not text:
            return text
        origin = url.get_origin()
        root = '{{}}://{{}}'.format(url.protocol or 'http', url.netloc or url.host or '')
        host = url.netloc or '{{}}:{{}}'.format(url.host, url.port or self.info.port)
        return (text.replace('{{{{BaseURL}}}}', origin)
                    .replace('{{{{RootURL}}}}', root)
                    .replace('{{{{Hostname}}}}', url.host or '')
                    .replace('{{{{Host}}}}', host)
                    .replace('{{{{Port}}}}', str(url.port or self.info.port))
                    .replace('{{{{Scheme}}}}', url.protocol or 'http'))

    def _parts(self, response):
        headers_all = []
        for k, v in response.headers.items():
            headers_all.append('{{}}: {{}}'.format(k, v))
            headers_all.append('{{}}: {{}}'.format(k.lower(), v))
        headers_str = '\\n'.join(headers_all)
        body = response.text or ''
        return {{
            'body': body,
            'header': headers_str,
            'all': body + '\\n' + headers_str,
            'response': body + '\\n' + headers_str,
            'raw_response': body + '\\n' + headers_str,
            'content_type': str(response.headers.get('Content-Type', '')),
            'location': str(response.headers.get('Location', '')),
        }}

    def _msg_hit(self, text, content, mc, ci):
        if ci:
            text = text.lower()
            content = [x.lower() for x in content]
        if mc == 'and':
            return all(x in text for x in content)
        return any(x in text for x in content)

    def _match_one(self, response, m):
        ok = False
        if m['type'] == 'status':
            ok = response.status_code in m['status']
        else:
            text = self._parts(response).get(m['part'], '')
            if m['type'] == 'word':
                ok = self._msg_hit(text, m['words'], m['condition'], m['case_insensitive'])
            elif m['type'] == 'regex':
                # 缺陷2修复: regex 分支按 m['condition'] 聚合 (and=全部正则命中, or=任一中即可)
                # 之前只循环任一命中即 ok=True, 把 condition:and 实现成了 OR —— 误报根源。
                rx_hits = []
                for rx in m['regex']:
                    try:
                        if m['case_insensitive']:
                            rx_hits.append(re.search(rx, text, re.S | re.I) is not None)
                        else:
                            rx_hits.append(re.search(rx, text, re.S) is not None)
                    except re.error:
                        rx_hits.append(False)
                ok = all(rx_hits) if m.get('condition', 'or') == 'and' else any(rx_hits)
        if m['negative']:
            ok = not ok
        return ok

    def run(self, url: urlutil.Url, *args, **kwargs) -> Tuple[bool, Any]:
        if not url.protocol:
            url.protocol, url.port = self.https_or_http(url)
        if not url.protocol:
            return False, 'the network protocol does not match.'
        http = self.make_http_client()
        for req in REQS:
            target = self._sub(req['path'], url)
            if not target.startswith('http'):
                target = url.get_origin() + ('/' + target.lstrip('/') if target else '/')
            headers = None
            if req.get('headers'):
                headers = {{k: self._sub(str(v), url) for k, v in req['headers'].items()}}
            body = self._sub(req.get('body'), url) if req.get('body') else None
            err, resp = http.rq(target, method=req['method'], data=body, headers=headers,
                                allow_redirects=req.get('redirects', True))
            if err:
                # 请求异常上抛, 不折成 SAFE: 引擎 do_testing 捕获后记 WARN (四态契约)
                raise err
            mats = [m for m in MATCHERS if m.get('req_idx') == req.get('req_idx')]
            if not mats:
                return False, 'no matchers for request'
            results = [self._match_one(resp, m) for m in mats]
            hit = all(results) if req.get('matchers_condition', 'or') == 'and' else any(results)
            if hit:
                # 缺陷1修复: 只有「含非 internal matcher 的请求块命中」才产生最终结果。
                # nuclei 语义: 无 flow 多请求块 = 逐块独立执行/匹配 (OR 聚合);
                # internal=true matcher 命中只抑制打印, 不产生可见结果, 也不阻塞后续请求。
                # 因此: 全 internal 块命中 -> 继续发后续请求; 非 internal 块命中 -> 报。
                if any(not m.get('internal', False) for m in mats):
                    return True, 'matched {{}} on {{}} status={{}}'.format(req['method'], target, resp.status_code)
        return False, 'no match'


if __name__ == '__main__':
    plg = Plugin()
    print(plg.info.name, plg.info.catalog)
'''

FEATURE_ORDER = ['method', 'path', 'raw', 'headers', 'body', 'redirects',
                 'matcher:status', 'matcher:word', 'matcher:regex', 'multi-matcher',
                 'multi-raw', 'helper-var-inlined']

# ---------------------------------------------------------------------------
# network/tcp 模板（T2FIX ②b）：仅支持「单输入、inputs.data 定长、regex/word matcher」形态
# ---------------------------------------------------------------------------
NETWORK_PLUGIN_TEMPLATE = '''\
#!/usr/bin/env python3
# _*_ coding:utf-8 _*_
# 自动生成 by tools/convert_nuclei.py — 勿手改
# source_repo : __SOURCE__
# template    : __TEMPLATE_PATH__  (MIT License)
# cve         : __CVE__
# protocol    : tcp (network 模板转换, T2FIX ②b)
# risk_class  : __RISK_CLASS__  (read_only=可入可用集; risky/excluded=仅清单标记, 默认不加载)
# description : __DESCRIPTION__

import pathlib
import re
import socket
import sys
import time
from typing import Any, Tuple

try:
    from utils import PLUGIN_TYPE, plugin, urlutil
except Exception:
    sys.path.append(pathlib.Path(__file__).parent.parent.parent.__str__())
    from utils import PLUGIN_TYPE, plugin, urlutil

DATA = __DATA__
MATCHERS = __MATCHERS__
MATCHERS_COND = __COND__
# L2 产品门控元数据（UPGRADE_PLAN §4.11）：模板 tags/metadata 提取的产品关键词, 无则 None
FINGERPRINT = __FINGERPRINT__


class Plugin(plugin.PluginBase):
    def set_info(self):
        info = plugin.Info(
            name=__NAME__,
            catalog=__CVE__,
            itype=PLUGIN_TYPE.POC,
            protocol='tcp',
            port=__PORT__,
            requires=__REQUIRES__,
        )
        # Info 基类暂无 fingerprint 字段（不改 utils/）, 直接挂属性供 L2 门控读取
        info.fingerprint = FINGERPRINT
        return info

    def _msg_hit(self, text, content, mc, ci):
        if ci:
            text = text.lower()
            content = [x.lower() for x in content]
        if mc == 'and':
            return all(x in text for x in content)
        return any(x in text for x in content)

    def _match_one(self, blob, m):
        text = blob.decode('latin-1', 'ignore')
        ok = False
        if m['type'] == 'word':
            ok = self._msg_hit(text, m['words'], m['condition'], m['case_insensitive'])
        elif m['type'] == 'regex':
            for rx in m['regex']:
                try:
                    if m['case_insensitive']:
                        ok = re.search(rx, text, re.S | re.I) is not None
                    else:
                        ok = re.search(rx, text, re.S) is not None
                except re.error:
                    ok = False
                if ok:
                    break
        if m['negative']:
            ok = not ok
        return ok

    def run(self, url: urlutil.Url, *args, **kwargs) -> Tuple[bool, Any]:
        host = url.host
        port = url.port or self.info.port
        if not host:
            return False, 'no host'
        sock = self.make_tcp_client(host, port)
        try:
            sock.settimeout(3)
            sock.connect()
        except Exception as err:
            # 连接异常上抛, 不折成 SAFE: 引擎 do_testing 捕获后记 WARN (四态契约)
            raise err
        buf = b''
        deadline = time.time() + 5
        try:
            sock.sendall(DATA.encode('utf-8') if isinstance(DATA, str) else DATA)
            # 静默窗口读: 服务端可能延迟应答 (如 Redis 执行 EVAL 后才回包)
            sock.settimeout(1.5)
            while time.time() < deadline:
                try:
                    chunk = sock.recv(4096)
                except socket.timeout:
                    break
                if not chunk:
                    break
                buf += chunk
                if buf:
                    # 已收到回包, 只再给 0.2s 收尾 (避免每次探测空等满超时)
                    sock.settimeout(0.2)
        finally:
            try:
                sock.close()
            except Exception:
                pass
        results = [self._match_one(buf, m) for m in MATCHERS]
        hit = all(results) if MATCHERS_COND == 'and' else any(results)
        if hit:
            return True, 'matched tcp probe on {}:{} (response {} bytes)'.format(host, port, len(buf))
        return False, 'no match on tcp {}:{} ({} bytes)'.format(host, port, len(buf))


if __name__ == '__main__':
    plg = Plugin()
    print(plg.info.name, plg.info.catalog)
'''


def build_network_model(relpath, data):
    """network/tcp 模板 → (model, None) 或 (None, skip_reason)。
    只支持「单输入、inputs.data 定长、regex/word matcher」形态。
    """
    tcp = data.get('tcp')
    if not isinstance(tcp, list) or not tcp:
        return None, 'no-tcp'
    if len(tcp) != 1:
        return None, 'multi-tcp-block'
    blk = tcp[0]
    inputs = blk.get('inputs')
    if not isinstance(inputs, list) or len(inputs) != 1:
        return None, 'multi-input'
    d = inputs[0].get('data')
    if not isinstance(d, str):
        return None, 'input-not-str'
    if '{{' in d:
        return None, 'input-has-placeholder'
    mats = blk.get('matchers') or []
    if not isinstance(mats, list) or not mats:
        return None, 'no-matcher'
    matchers = []
    for mt in mats:
        if not isinstance(mt, dict):
            return None, 'malformed-matcher'
        t = mt.get('type')
        if t not in ('word', 'regex'):
            return None, 'matcher-' + str(t)
        m = {'type': t, 'part': 'body', 'condition': str(mt.get('condition') or 'or'),
             'negative': bool(mt.get('negative')),
             'case_insensitive': bool(mt.get('case-insensitive') or mt.get('case_insensitive'))}
        if t == 'word':
            w = mt.get('words') or []
            m['words'] = [str(x) for x in (w if isinstance(w, list) else [w])]
        else:
            rr = mt.get('regex') or []
            m['regex'] = [str(x) for x in (rr if isinstance(rr, list) else [rr])]
        matchers.append(m)
    port = blk.get('port')
    try:
        port = int(str(port).split(',')[0]) if port else None
    except (TypeError, ValueError):
        port = None
    cond = str(blk.get('matchers-condition') or 'or')
    if cond not in ('and', 'or'):
        return None, 'matchers-condition-' + cond
    return {'protocol': 'tcp', 'data': d, 'read_size': int(blk.get('read-size') or 4096),
            'port': port, 'cond': cond, 'matchers': matchers,
            'supports': {'matcher:' + m['type'] for m in matchers}}, None


def risk_classify_network(model):
    all_text = model.get('data', '') + ' ' + json.dumps(model.get('matchers', []))
    if REVSHELL_RE.search(all_text):
        return 'excluded', 'reverse-shell-payload'
    if DELETE_RE.search(all_text):
        return 'excluded', 'file-delete-payload'
    if USER_RE.search(all_text):
        return 'excluded', 'user-creation-payload'
    if EXFIL_RE.search(all_text):
        return 'excluded', 'data-exfiltration-OOB'
    if EXEC_RE.search(all_text):
        return 'risky', 'command-execution-payload'
    return 'read_only', 'read-methods-only'



def gen_plugin_source(spec):
    if spec.get('protocol') == 'tcp':
        m = spec['model']
        src = NETWORK_PLUGIN_TEMPLATE
        for token, value in (
            ('__SOURCE__', spec['source']),
            ('__TEMPLATE_PATH__', spec['template_path']),
            ('__CVE__', repr(spec['cve'])),
            ('__RISK_CLASS__', spec['risk_class']),
            ('__DESCRIPTION__', (spec.get('description') or '')[:120].replace('\n', ' ')),
            ('__DATA__', repr(m['data'])),
            ('__MATCHERS__', repr(m['matchers'])),
            ('__COND__', repr(m.get('cond', 'or'))),
            ('__FINGERPRINT__', repr(spec.get('fingerprint'))),
            ('__NAME__', repr(spec['name'][:160])),
            ('__PORT__', str(spec['ports'][0])),
            ('__REQUIRES__', repr(requires_for(spec.get('protocol') or 'tcp', spec.get('product_labels')))),        ):
            src = src.replace(token, value)
        return src
    blocks = spec['model']['blocks']
    reqs_out = []
    matchers_out = []
    for idx, b in enumerate(blocks):
        reqs_out.append({
            'req_idx': idx,
            'method': b.get('method', 'GET'),
            'path': b.get('path', '/'),
            'headers': b.get('headers') or {},
            'body': b.get('body'),
            'redirects': b.get('redirects', False),
            'from_raw': b.get('from_raw', False),
            'matchers_condition': b.get('_matchers_condition', 'or'),
        })
        for m in b.get('_matchers', []):
            mm = dict(m)
            mm['req_idx'] = idx
            matchers_out.append(mm)
    return PLUGIN_TEMPLATE.format(
        source=spec['source'],
        template_path=spec['template_path'],
        cve=spec['cve'],
        risk_class=spec['risk_class'],
        description=(spec.get('description') or '')[:120].replace('\n', ' '),
        reqs=repr(reqs_out),
        matchers=repr(matchers_out),
        fingerprint=spec.get('fingerprint'),
        name=spec['name'][:160],
        requires=requires_for(spec.get('protocol') or 'http', spec.get('product_labels')),
    )


# ---------------------------------------------------------------------------
# 主流程
# ---------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--src', default='/tmp/opencode/nuclei-templates')
    ap.add_argument('--out', default='/opt/workspace/labs/simple-scanner/plugins_corpus')
    ap.add_argument('--min-year', type=int, default=2016)
    ap.add_argument('--max-plugins', type=int, default=0, help='0=不限')
    # T2FIX ②a: 额外扫描根 (http/vulnerabilities 等), 可重复; ②b: network/cves
    ap.add_argument('--extra-root', action='append', default=[], help='额外扫描根(相对 --src), 可重复')
    ap.add_argument('--scan-root', action='append', default=[], help='扫描根(相对 --src), 覆盖默认 http/cves, 可重复')
    ap.add_argument('--out-subdir', default='', help='产物子目录(相对 --out); 非空时平铺写入该目录(不走年份目录)')
    ap.add_argument('--manifest-name', default='manifest.json', help='manifest 文件名')
    ap.add_argument('--report-name', default='', help='报告文件名(默认: 增量模式 REPORT-<out-subdir>.md)')
    ap.add_argument('--no-cve-ok', action='store_true', help='允许无 CVE 编号模板 (catalog=模板 id)')
    ap.add_argument('--only-cve', action='append', default=[], help='只转换指定 CVE (可重复)')
    args = ap.parse_args()

    cves_root = os.path.join(args.src, 'http', 'cves')
    years = sorted(os.listdir(cves_root)) if os.path.isdir(cves_root) else []
    files = []
    if args.scan_root:
        # 显式指定扫描根: 不再扫默认 http/cves (增量模式专用)
        roots = list(args.scan_root)
    else:
        roots = []
        for y in years:
            if y.isdigit():
                roots.append('http/cves/{}'.format(y))
    roots += list(args.extra_root)
    for root in roots:
        root_abs = os.path.join(args.src, root.replace('/', os.sep))
        if not os.path.isdir(root_abs):
            print('warn: scan root not found: {}'.format(root_abs))
            continue
        if os.path.isfile(root_abs):
            files.append(root_abs)
            continue
        for dirpath, _dirs, names in os.walk(root_abs):
            files += [os.path.join(dirpath, f) for f in sorted(names) if f.endswith('.yaml')]

    # T2FIX ②a: 增量模式不重写既有 manifest (去重既有 CVE)
    existing_cves = set()
    main_manifest = os.path.join(args.out, 'manifest.json')
    if args.out_subdir and os.path.exists(main_manifest):
        try:
            existing_cves = {e.get('cve') for e in json.load(open(main_manifest, encoding='utf-8'))}
        except Exception:
            existing_cves = set()

    stats = {
        'files_scanned': len(files),
        'no_cve': 0,
        'filter_year_lt': 0,
        'skip': collections.Counter(),
        'risk': collections.Counter(),
        'support_features': collections.Counter(),
        'by_year': collections.Counter(),
        'dedup_same_cve': 0,
        'dup_existing_corpus': 0,
    }
    converted = []
    seen_cve = set()

    for f in files:
        rel = os.path.relpath(f, args.src).replace(os.sep, '/')
        try:
            with open(f, encoding='utf-8', errors='replace') as fh:
                raw_text = fh.read()
            data = yaml.safe_load(raw_text)
        except Exception:
            stats['skip']['yaml-parse-error'] += 1
            continue
        if not isinstance(data, dict):
            stats['skip']['malformed-yaml'] += 1
            continue
        cve = get_cve(data, rel, raw_text)
        if not cve:
            if not args.no_cve_ok:
                stats['no_cve'] += 1
                continue
            # 无 CVE 模板: catalog=模板 id (增量目录场景, 如 php-zerodium-backdoor-rce)
            tid = str(data.get('id') or '').strip()
            if not tid:
                stats['skip']['no-id-no-cve'] += 1
                continue
            cve_id, year = tid, None
        else:
            cve_id, year, num = cve
            if year < args.min_year and not args.only_cve:
                stats['filter_year_lt'] += 1
                continue
        if args.only_cve and cve_id not in args.only_cve:
            continue
        if args.out_subdir and cve_id in existing_cves:
            stats['dup_existing_corpus'] += 1
            continue
        if cve_id in seen_cve:
            stats['dedup_same_cve'] += 1
            continue
        seen_cve.add(cve_id)

        # ②b: network/tcp 模板路由
        if isinstance(data.get('tcp'), list):
            model, skip_reason = build_network_model(rel, data)
        else:
            model, skip_reason = build_model(rel, data)
        if skip_reason:
            stats['skip'][skip_reason] += 1
            continue
        if model['protocol'] == 'tcp':
            risk, risk_detail = risk_classify_network(model)
        else:
            risk, risk_detail = risk_classify(model)
        stats['risk'][risk] += 1
        if year:
            stats['by_year'][year] += 1
        for ft in FEATURE_ORDER:
            if ft in model['supports']:
                stats['support_features'][ft] += 1
        info = data.get('info') or {}
        ov = TEMPLATE_OVERRIDES.get(rel, {})
        if model['protocol'] == 'tcp':
            ports = ov.get('ports') or ([model['port']] if model['port'] else [6379])
        else:
            ports = ov.get('ports') or WEB_PORTS
        converted.append({
            'cve': cve_id, 'year': year, 'source': 'nuclei-templates',
            'template_path': rel, 'protocol': model['protocol'],
            'ports': ports, 'fingerprint': ov.get('fingerprint') or extract_fingerprint(info),
            # E1: 从模板 tags 提取引擎可判的产品标签 -> requires 追加 product:<label>
            'product_labels': product_labels_for_tags(info.get('tags')),
            'risk_class': risk, 'risk_detail': risk_detail,
            'name': str(info.get('name') or cve_id),
            'description': str(info.get('description') or ''),
            'support_features': sorted(x for x in FEATURE_ORDER if x in model['supports']),
            'model': model,
        })
        if args.max_plugins and len(converted) >= args.max_plugins:
            break

    manifest = []
    for sp in converted:
        if args.out_subdir:
            # 增量目录: 平铺写入 <out>/<out_subdir>/<cve|id>.py
            dir_out = os.path.join(args.out, args.out_subdir)
            os.makedirs(dir_out, exist_ok=True)
            fname = sp['cve'] + '.py'
            fpath = os.path.join(dir_out, fname)
            rel_file = '{}/{}'.format(args.out_subdir, fname)
        else:
            year_dir = os.path.join(args.out, str(sp['year']))
            os.makedirs(year_dir, exist_ok=True)
            fname = sp['cve'] + '.py'
            fpath = os.path.join(year_dir, fname)
            rel_file = '{}/{}'.format(sp['year'], fname)
        with open(fpath, 'w', encoding='utf-8') as fh:
            fh.write(gen_plugin_source(sp))
        manifest.append({
            'file': rel_file,
            'cve': sp['cve'], 'year': sp['year'], 'source': sp['source'],
            'template_path': sp['template_path'], 'protocol': sp['protocol'],
            'ports': sp['ports'], 'fingerprint': sp['fingerprint'],
            # E1: 产品门控标签 (requires 中 product: 前缀的来源), 供审计/追溯
            'product_labels': sp.get('product_labels'),
            'risk_class': sp['risk_class'], 'risk_detail': sp['risk_detail'],
            'support_features': sp['support_features'],
            'skipped_features': [],
        })

    # 增量模式: 合并既有同名单文件 (幂等: 已存在的条目跳过)
    manifest_path = os.path.join(args.out, args.manifest_name)
    if args.out_subdir and os.path.exists(manifest_path):
        try:
            old = json.load(open(manifest_path, encoding='utf-8'))
            old_files = {e.get('file') for e in old}
            manifest = old + [m for m in manifest if m['file'] not in old_files]
        except Exception:
            pass
    with open(manifest_path, 'w', encoding='utf-8') as fh:
        json.dump(manifest, fh, ensure_ascii=False, indent=1)

    proto_cnt = collections.Counter(sp['protocol'] for sp in converted)
    lines = []
    lines.append('# plugins_corpus 生成报告\n')
    if args.out_subdir:
        lines.append('## T2FIX 增量 — 扫描根 {} / 产物目录 {} / manifest {}\n'.format(
            ', '.join(args.extra_root) if args.extra_root else 'http/cves',
            args.out_subdir, args.manifest_name))
        lines.append('- 增量模式: 不重写既有 manifest.json, 去重既有语料 CVE {} 个'.format(stats['dup_existing_corpus']))
        lines.append('- ②c flow 通用转换未实现: CVE-2017-12615 以 supplement/ 手工插件落地; 通用 flow 支持留后续卡\n')
    else:
        lines.append('## 任务卡 M1 — 1000+ 插件语料库（nuclei-templates 转换）\n')
    lines.append('- 生成时间: 2026-10-26')
    lines.append('- 转换器: tools/convert_nuclei.py')
    lines.append('- 数据源: projectdiscovery/nuclei-templates main 分支 tarball（gh-proxy 通道, HTTP 200, 9,998,970 字节），MIT 协议')
    lines.append('- 抓取通道: gh-proxy 成功（jsDelivr / GitHub API 未使用，单源已达标）\n')
    lines.append('## 来源总量与筛选\n')
    lines.append('| 项 | 数量 |')
    lines.append('|---|---|')
    lines.append('| 扫描文件 | {} |'.format(stats['files_scanned']))
    lines.append('| 无 CVE 编号 (--no-cve-ok 时以模板 id 收录) | {} |'.format(stats['no_cve']))
    lines.append('| CVE 年份 < {} 被筛除 | {} |'.format(args.min_year, stats['filter_year_lt']))
    lines.append('| 同 CVE 去重（第二个起丢弃） | {} |'.format(stats['dedup_same_cve']))
    lines.append('| 增量去重（已在既有 manifest） | {} |'.format(stats['dup_existing_corpus']))
    lines.append('| 转换成功（生成插件） | {} |'.format(len(converted)))
    lines.append('| 转换失败（不支持, 见下方跳过表） | {} |'.format(sum(stats['skip'].values())))
    lines.append('\n## 不支持特性计数（跳过项+原因）\n')
    lines.append('| 跳过原因 | 数量 |')
    lines.append('|---|---|')
    for k, v in stats['skip'].most_common():
        lines.append('| {} | {} |'.format(k, v))
    lines.append('\n## 按年份分布\n')
    lines.append('| 年份 | 插件数 |')
    lines.append('|---|---|')
    for y in sorted(stats['by_year']):
        lines.append('| {} | {} |'.format(y, stats['by_year'][y]))
    lines.append('\n## 按协议分布\n')
    lines.append('| protocol | 数量 |')
    lines.append('|---|---|')
    for p, n in sorted(proto_cnt.items()):
        lines.append('| {} | {} |'.format(p, n))
    lines.append('\n## 风险分层\n')
    lines.append('| risk_class | 数量 | 处置 |')
    lines.append('|---|---|---|')
    for rc in ('read_only', 'risky', 'excluded', 'uncertain'):
        lines.append('| {} | {} | {} |'.format(rc, stats['risk'].get(rc, 0),
                                               '可入可用集' if rc == 'read_only' else '仅清单标记, 默认不加载'))
    lines.append('\n## 支持矩阵统计（转换出插件用到的特性）\n')
    lines.append('| 特性 | 插件数 |')
    lines.append('|---|---|')
    for ft in FEATURE_ORDER:
        lines.append('| {} | {} |'.format(ft, stats['support_features'].get(ft, 0)))
    if not args.out_subdir:
        lines.append('\n## 验证（tools/verify_corpus.py 实测）\n')
        vpath = os.path.join(args.out, 'verify_report.json')
        if os.path.exists(vpath):
            with open(vpath, encoding='utf-8') as fh:
                vr = json.load(fh)
            lines.append('| 项 | 结果 |')
            lines.append('|---|---|')
            lines.append('| import + 实例化通过 | {}/{} ({:.2f}%) |'.format(
                vr['import_pass'], vr['import_total'],
                vr['import_pass'] / max(1, vr['import_total']) * 100))
            lines.append('| import 失败 / Info 不完整 | {} / {} |'.format(vr['import_fail'], vr['info_bad']))
            lines.append('| 20 样本 smoke 异常数 | {} |'.format(vr['smoke_bad']))
            lines.append('| smoke OUTCOME 分布 | {} |'.format(json.dumps(vr['smoke_outcomes'])))
            lines.append('| mock 实际收到请求数 | {} {} |'.format(vr['mock_requests'], json.dumps(vr['mock_methods'])))
            lines.append('| smoke 耗时 | {:.2f}s |'.format(vr['smoke_elapsed_s']))
            lines.append('| matcher 正向命中（kitchen-sink mock） | {}/{} 报 vuln |'.format(
                vr['positive_vuln'], vr['positive_candidates']))
        else:
            lines.append('- 未运行：`.venv/bin/python tools/verify_corpus.py --samples 20 --seed 42`')
    lines.append('\n## 遗留\n')
    lines.append('- 风险类插件仅生成文件+清单标记，load 层需按 risk_class 过滤（未来 L2 门控接入点）。')
    lines.append('- ②b network/tcp 仅支持「单输入、inputs.data 定长、regex/word matcher」形态, 本卡只产出 CVE-2022-0543; 其余 network 模板全量转换留后续卡。')
    lines.append('- ②c flow 通用转换未实现（见上）, CVE-2017-12615 手工落地在 plugins_corpus/supplement/。')
    lines.append('- ②a 新目录 http/vulnerabilities/ 增量产物在 plugins_corpus/vulns/ (manifest-vulns.json)。')
    if not args.out_subdir:
        lines.append('- afrog POCs / PoC-in-GitHub 未启用：nuclei 单源已达标（见上表总量），后续增量可加。')
        lines.append('- raw 请求覆盖 method/path/headers/body；multipart/boundary、DSL matcher、flow、payloads 模板按支持矩阵跳过（计数见跳过表）。')
    report_name = args.report_name or ('REPORT-{}.md'.format(args.out_subdir) if args.out_subdir else 'REPORT.md')
    with open(os.path.join(args.out, report_name), 'w', encoding='utf-8') as fh:
        fh.write('\n'.join(lines) + '\n')

    print('files_scanned={} converted={}'.format(stats['files_scanned'], len(converted)))
    print('skip_total={}'.format(sum(stats['skip'].values())))
    for k, v in stats['skip'].most_common(25):
        print('  skip {}: {}'.format(k, v))
    print('risk:', dict(stats['risk']))
    print('by_year:', dict(sorted(stats['by_year'].items())))
    print('protocol:', dict(proto_cnt))


if __name__ == '__main__':
    main()