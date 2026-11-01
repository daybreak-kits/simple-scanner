import pathlib
import random
import socket
import time
import traceback
from typing import Any, Callable, Dict, List, Tuple

import urllib3

urllib3.disable_warnings()

try:
    from utils import (LANG, PLUGIN_TYPE, fingerprint, http_client, logger,
                       pro_async, sockets, urlutil)
except:
    import pathlib
    import sys

    sys.path.append(pathlib.Path(__file__).parent.parent.__str__())
    from utils import (LANG, PLUGIN_TYPE, fingerprint, http_client, logger,
                       pro_async, sockets, urlutil)

log = logger.new('simple-scanner', logger.DBG, logger.FORMAT_PRD)


class Outcome:
    """插件检测结果四态，值为小写字符串，直接作为结果记录 OUTCOME 字段的取值

    VULN 命中（对应原 IS_EXIST=True 路径）
    SAFE 正常执行，未命中
    WARN 执行异常/超时/必需参数缺失/返回结构非法 → 必须人工核验，是潜在漏报信号
    SKIP 目标不适用（服务标签不符、地址非法等）→ 不算结论
    """

    VULN = 'vuln'
    SAFE = 'safe'
    WARN = 'warn'
    SKIP = 'skip'
    ALL = (VULN, SAFE, WARN, SKIP)


class ResultCollector:
    """任务结果收集器：维护全量 rows 与 warn_rows / skip_rows 分流列表，供引擎结果层（ss.py）接线

    用法：collector.add(plugin.do_testing(url, data))
    """

    def __init__(self) -> None:
        self.rows: List[Dict[str, Any]] = []
        self.warn_rows: List[Dict[str, Any]] = []
        self.skip_rows: List[Dict[str, Any]] = []

    def add(self, record: Dict[str, Any]) -> Dict[str, Any]:
        self.rows.append(record)
        if record['OUTCOME'] == Outcome.WARN:
            self.warn_rows.append(record)
        elif record['OUTCOME'] == Outcome.SKIP:
            self.skip_rows.append(record)
        return record

    def summary(self) -> str:
        counts = dict.fromkeys(Outcome.ALL, 0)
        for row in self.rows:
            counts[row['OUTCOME']] += 1
        return 'VULN={} SAFE={} WARN={} SKIP={} total={}'.format(
            counts[Outcome.VULN], counts[Outcome.SAFE], counts[Outcome.WARN], counts[Outcome.SKIP], len(self.rows)
        )


class Info:
    def __init__(
        self,
        name: str,
        catalog: str,
        protocol: str,
        port: int,
        ssl_protocol: str = None,
        ssl_port: int = 0,
        itype: int = PLUGIN_TYPE.MODULE,
        params: List[str] = None,
        requires: List[str] = None,
    ) -> None:
        # 字符型，漏洞名称
        self.name = name
        # 字符型，漏洞编号，比如 CVE/CAN/BUGTRAQ/CNCVE/CNVD/CNNVD
        self.catalog = catalog
        # 字符型，漏洞相关的协议
        self.protocol = protocol
        # 数字型，默认检测端口号
        self.port = int(port)
        # 字符型，如有，漏洞相关的SSL协议
        self.ssl_protocol = ssl_protocol
        # 数字型，如有，默认检测SSL端口号
        self.ssl_port = int(ssl_port)
        # 数字型，漏洞类型，MODULE 为模块检测，POC为原理检测
        self.itype = itype
        # 列表型，插件必需的参数名，如 ['cmd']；引擎检测到注入值缺失时记 Outcome.WARN
        self.params = list(params) if params else []
        # 列表型，插件适用的服务标签，如 ['http','https'] / ['t3'] / ['tcp']；
        # 引擎派发时用指纹探测结果（fingerprint.is_applicable）匹配，None/空 = 通用插件，任何服务都跑
        self.requires = list(requires) if requires else None


class PluginBase:
    def __init__(self):
        info = self.set_info()
        if isinstance(info, Info):
            self.info = info
        else:
            self.info = Info(**self.set_info())
        # 检测插件名称编号
        if not self.info.name and not self.info.catalog:
            raise ValueError(LANG.t('the "name" and "catalog" of the plugin are empty, one of them must be set.'))
        # 引擎注入的服务指纹（ServiceInfo）；None = 未注入/探测未知 → fail-open，不门控
        self.svc = None
        # 检测插件协议端口
        if not self.info.protocol or not self.info.port:
            raise ValueError(
                LANG.t(
                    'the "protocol" and "port" information for plugins with name "{}" and catalog "{}" is empty, you must set the network protocol used by the plugin.'.format(
                        self.info.name, self.info.catalog
                    )
                )
            )
        # 无法配置协程池子 TypeError: cannot pickle 'gevent._gevent_cevent.Event' object，交给函数自行调用
        # self.async_pool = pro_async.AsyncPool()
        self.cli_mng = sockets.ClientManager()

    def __repr__(self):
        string_attrs = ''
        for key in self.info.__dict__:
            attr = getattr(self.info, key)
            if isinstance(attr, Callable) or key.startswith('_'):
                continue
            string_attrs += f', {key}={getattr(self.info, key)}'
        ret = f'<{self.info.__module__}.{type(self.info).__name__} object at {hex(id(self))}{string_attrs}>'
        return ret

    def https_or_http(self, url: urlutil.Url, *args, **kwargs) -> Tuple[str | None, int | None]:
        """探测当前目标使用的是 http 或 https 协议

        Args:
            url (urlutil.Url): Url 对象

        Returns:
            Tuple[str | None, int | None]: 返回协议类型和可用的端口号
        """
        # 有可能不输入端口，不输入端口使用插件默认的端口
        port = url.port if url.port else self.info.port
        ssl_port = url.port if url.port else self.info.ssl_port
        # 起协程分别探测http或https协议
        ayn_pool = self.make_async_pool()
        hcli = self.make_http_client(tries=2, timeout=1)
        ayn_pool.sp_by_key('https', hcli.rq, 'https://{}:{}'.format(url.host, ssl_port), verify=False)
        ayn_pool.sp_by_key('http', hcli.rq, 'http://{}:{}'.format(url.host, port), verify=False)
        err, _ = ayn_pool.get_by_key('https')
        if not err:
            return 'https', ssl_port
        err, _ = ayn_pool.get_by_key('http')
        if not err:
            return 'http', port
        return None, port

    def do_testing(self, url: str | urlutil.Url, data: Dict = {}) -> Dict[str, Any]:
        """运行一次插件检测，返回统一的结果记录（四态契约）

        记录结构: {"HOST": str, "PORT": int, "PLUGIN": str, "OUTCOME": Outcome.*, "DATA": str}
        OUTCOME 取值见 Outcome 类：VULN=命中，SAFE=正常执行未命中，WARN=异常/超时/参数缺失/返回结构非法（人工核验），SKIP=目标不适用
        """
        start_time = time.time()
        if isinstance(url, str):
            url = urlutil.Url(url)
        record = {
            'HOST': url.host or '',
            'PORT': int(url.port or 0),
            'PLUGIN': self.info.catalog or self.info.name,
            'OUTCOME': Outcome.SKIP,
            'DATA': '',
        }
        # 地址非法 → SKIP：目标不可用，不产生插件结论
        if not self.is_vaild_url(url):
            record['DATA'] = 'incorrect address "{}"'.format(url)
            return record
        url.port = url.port or self.info.port
        record['PORT'] = url.port
        # requires 门控：引擎注入 svc（服务指纹）时按标签匹配；无 svc（None）= fail-open 直接跑。
        # 匹配语义在 utils/fingerprint.py（is_applicable），此处只复用不重复实现。
        svc = getattr(self, 'svc', None)
        if svc is not None and self.info.requires and not fingerprint.is_applicable(self.info.requires, svc):
            record['DATA'] = fingerprint.skip_reason(self.info.requires, svc)
            return record
        # 必需参数缺失 → WARN：检测无法执行，属潜在漏报信号，需人工核验（不是崩溃也不是未检出）
        missing = [k for k in self.info.params if k not in data]
        if missing:
            record['OUTCOME'] = Outcome.WARN
            record['DATA'] = 'missing required param(s): {}'.format(', '.join(missing))
            return record
        log.dbg('running {}, url: {}, data: {}'.format(self.info.catalog or self.info.name, url, data))
        try:
            exists, payload = self.run(url, **data)
        except Exception:
            # 异常独立成 WARN，不再折叠为「未检出」（O1 修复：异常是漏报主源）
            record['OUTCOME'] = Outcome.WARN
            # 审计 #17：完整 traceback 含本地绝对路径（信息泄露 + CSV 体积膨胀）。
            # 截断到最后一个异常帧（保留错误类型与消息），并去掉 CWD 前缀。
            _tb = traceback.format_exc()
            _cwd = str(pathlib.Path.cwd()) + '/'
            _tb = _tb.replace(_cwd, '').replace(pathlib.Path.cwd().as_posix() + '/', '')
            _lines = [l for l in _tb.splitlines() if l.strip()]
            if len(_lines) > 3:
                # 保留 Traceback 头 + 最后一帧 + 异常行（丢中间帧：路径噪声且无信息量）
                _tb = '\n'.join([_lines[0], _lines[-2], _lines[-1]])
            record['DATA'] = _tb.strip()[-1200:]
        else:
            if not isinstance(exists, bool):
                # 返回结构非法（首元素非 bool）→ WARN，交人工核验
                record['OUTCOME'] = Outcome.WARN
                record['DATA'] = 'illegal return structure: run() first element is {!r}, expected bool. payload: {!r}'.format(
                    exists, payload
                )
            else:
                record['OUTCOME'] = Outcome.VULN if exists else Outcome.SAFE
                record['DATA'] = payload if isinstance(payload, str) else str(payload)

        running_times = time.time() - start_time
        if running_times > 8:
            log.dbg(
                'finish {}, times: {:.2}s, url: {}, data: {}'.format(
                    self.info.catalog or self.info.name, time.time() - start_time, url, data
                )
            )
        return record

    def make_async_pool(self, size: int = None, greenlet_class: object = None) -> pro_async.AsyncPool:
        """创建协程池子，需要注意的是，在插件单独调试的情况下，因为没有做 geven 的猴子补丁，协程不会正常运行

        Args:
            size (int, optional): 单个池子同时运行的协程数量。默认：None
            greenlet_class (object, optional): 不建议调整。默认：None

        Returns:
            pro_async.AsyncPool: 协程池子实例对象
        """
        return pro_async.AsyncPool(size, greenlet_class)

    def make_http_client(
        self,
        headers: Dict[str, str] = None,
        tries: int = 2,
        timeout: float = 3,
    ):
        return http_client.HttpClient(headers, tries, timeout)

    def make_tcp_client(
        self,
        host: str,
        port: int,
        family: socket.AddressFamily | int = None,
        _type: socket.SocketKind | int = None,
        proto: int = None,
        file_no: int | None = None,
    ):
        # 不及时close，是不是会造成大量的内存浪费？
        return self.cli_mng.new_tcp(host, port, family, _type, proto, file_no)

    # 网络反射工具模块已删除（方案 §1 债务清理），反射相关方法一并移除；
    # 引擎层对缺失参数已按四态契约记 Outcome.WARN，不再有反射回退路径

    def is_vaild_url(self, url: urlutil.Url) -> bool:
        if not url.host:
            # 没有host，跳过检测
            # raise ValueError('incorrect address "{}"'.format(url))
            return False
        # 留给脚本自己处理默认协议的工作
        # if not url.port:
        #     url.port = self.info.port
        # if not url.protocol:
        #     url.protocol = self.info.protocol
        # if not url.protocol in self.info.protocol:
        #     # 协议不对，跳过检测
        #     return False
        return True

    def set_info(self) -> Dict[str, Any]:
        raise NotImplementedError('the plugin does not use the set_info() function to set information')
        # return Info(
        #     # 字符型，漏洞名称
        #     name='',
        #     # 字符型，漏洞编号，比如 CVE/CAN/BUGTRAQ/CNCVE/CNVD/CNNVD
        #     catalog='',
        #     # 数字型，漏洞类型，MODULE 为模块检测，POC为原理检测
        #     itype=PLUGIN_TYPE.MODULE,
        #     # 字符型，漏洞相关的协议
        #     protocol='http',
        #     # 数字型，默认检测端口号
        #     port=80,
        #     # 字符型，如有，漏洞相关的SSL协议
        #     ssl_protocol='https',
        #     # 数字型，如有，默认检测SSL端口号
        #     ssl_port=443,
        # )

    def run(self, url: urlutil.Url, *args, **kwargs) -> Tuple[bool, Any]:
        """插件自定义的函数

        Args:
            url (urlutil.Url): 将输入进行解析后得到的URL对象

        Raises:
            NotImplementedError: 未改写直接调用该函数会直接报错

        Returns:
            Tuple[bool, Any]: 第一返回的信息用于是表示插件是否检测到，第二个信息为需要存入结果的数据
        """
        raise NotImplementedError(
            'please rewrite the run function first, plugin name: {}, plugin catalog: {}'.format(
                self.info.name, self.info.catalog
            )
        )
