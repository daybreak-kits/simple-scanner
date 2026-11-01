# _*_ coding:utf-8 _*_
# 目前不支持IPV6
import re
import sys

from gevent import monkey

monkey.patch_all(thread=False, httplib=True)
import fnmatch
import importlib
import json
import multiprocessing
import pathlib
import random
import time
from typing import Dict, List, Set, Tuple

import gevent.pool

from utils import (LANG, fingerprint, logger, network, plugin, process,
                   progress_bar, save_csv, urlutil)

PATH_CACHE = pathlib.Path('.cache')
# 审计 S1（2026-10-30）：日志处理器在模块 import 期就打开 .cache/ss.log，而 .cache 被 .gitignore
# 忽略——全新 clone 后连 `-h` 都会 FileNotFoundError。必须在建日志处理器之前就建目录。
PATH_CACHE.mkdir(exist_ok=True, parents=True)

log = logger.new('simple-scanner', logger.INF, format_string=logger.FORMAT_PRD)
log.set_handle_console()
log.set_handle_file_timed_rotating(PATH_CACHE.joinpath('ss.log'))


def _run_stamp() -> str:
    """本轮扫描的输出文件名时间戳。

    审计 S2（2026-10-30）：原实现 %y%m%d.%H%M（分钟精度），同一分钟内跑多轮会被覆盖；
    秒精度也不可靠（并发 CI 或快速重跑会撞名）。改为秒 + PID + 4 字随机后缀，
    保证每次运行都有独立不可猜的证据文件名。
    """
    return '{}{:04x}'.format(
        time.strftime('%y%m%d.%H%M%S', time.localtime()),
        random.randrange(1 << 16))


def _task_wrapper(url, plugin, svc=None):
    """进程池任务包装：执行插件检测并附加引擎侧上下文。

    ProcessPool.yield_result 按 LIFO 回收（utils/process.py:37，方案 §4.6 裁决不做乱序回收），
    结果与提交顺序不对齐，因此引擎侧字段（URL/NAME/PROTOCOL/PLUGIN_TYPE）由任务本身携带回填。

    svc：该端口的服务指纹（fingerprint.ServiceInfo）。子进程里是反序列化出的插件副本，
    把 svc 挂上去后 do_testing 才能按 requires 做最终门控（引擎侧已先筛过一轮，此处是双保险）。
    """
    if svc is not None:
        plugin.svc = svc
    record = plugin.do_testing(url)
    record['_URL'] = url.get_full()
    record['_NAME'] = plugin.info.name
    record['_PROTOCOL'] = url.protocol
    record['_PTYPE'] = plugin.info.itype
    return record

if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description='''
    ███████╗██╗███╗   ███╗██████╗ ██╗     ███████╗    ███████╗
    ██╔════╝██║████╗ ████║██╔══██╗██║     ██╔════╝    ██╔════╝
    ███████╗██║██╔████╔██║██████╔╝██║     █████╗      ███████╗
    ╚════██║██║██║╚██╔╝██║██╔═══╝ ██║     ██╔══╝      ╚════██║
    ███████║██║██║ ╚═╝ ██║██║     ███████╗███████╗    ███████║
    ╚══════╝╚═╝╚═╝     ╚═╝╚═╝     ╚══════╝╚══════╝    ╚══════╝
    v0.3.0
    by 0xn0ne, https://github.com/0xn0ne/simple-scanner
''',
    )
    parser.add_argument(
        '-t',
        '--targets',
        required=True,
        nargs='+',
        help=LANG.t('scanning targets, or scanning target list files (e.g. "127.0.0.1:80").'),
    )
    '扫描目标，或扫描目标列表文件'
    parser.add_argument(
        '-m',
        '--module',
        nargs='+',
        help=LANG.t('vulnerability plugins name used, default scan all modules (e.g. "CVE-2014-*").'),
    )
    parser.add_argument(
        '-p', '--process-number', default=8, type=int, help=LANG.t('number of program processes, default 5 processes.')
    )
    parser.add_argument(
        '-o',
        '--output-format',
        type=str,
        help=LANG.t('output file format, available formats json, csv. default csv format.'),
    )
    parser.add_argument(
        '-i',
        '--interval',
        type=int,
        default=0,
        help=LANG.t('time interval (in seconds) between submitting a task to the process pool.'),
    )
    parser.add_argument(
        '-is',
        '--is-silent',
        action='store_true',
        help=LANG.t(
            'silent mode: when turned on, no hit data will be output on the console. use a progress bar instead.'
        ),
    )
    parser.add_argument(
        '-dps',
        '--disable-port-scan',
        action='store_true',
        help=LANG.t(
            'disable port scanning. note: if the port not open, the program sending PAYLOAD will cause meaningless waiting time for a response'
        ),
    )
    parser.add_argument(
        '--include-risky',
        action='store_true',
        help=LANG.t(
            'also load risky corpus plugins (write/upload/execute probes that leave artifacts). '
            'off by default: they send writing payloads to targets and need explicit authorization.'
        ),
    )

    args = parser.parse_args()
    log.inf(LANG.t('initializing...'))
    s_time = time.time()
    path_output = pathlib.Path(__file__).parent.joinpath(PATH_CACHE).mkdir(exist_ok=True, parents=True)

    # 插件筛选
    # 加载两个来源：
    #   plugins/         — 用户自建插件（即插即用，无 risk_class 标记，全部加载）
    #   plugins_corpus/  — 内置语料（2063 个），仅加载 risk_class=read_only（写入/破坏型默认不上线）
    # 语料按年分目录（2016-2026/vulns/supplement），文件名全局唯一（已校验 0 重复）。
    plugin_list: List[plugin.PluginBase] = []

    def _iter_plugin_files():
        # 用户插件：只取顶层 *.py，`__` 前缀（模板/禁用）与目录跳过
        for filepath in sorted(pathlib.Path('plugins').glob('*')):
            if filepath.name.startswith('__') or not filepath.name.endswith('.py') or filepath.is_dir():
                continue
            yield filepath
        # 内置语料：递归扫描，按文件头 risk_class 过滤（只放行 read_only）
        corpus_root = pathlib.Path('plugins_corpus')
        if not corpus_root.is_dir():
            return
        for filepath in sorted(corpus_root.rglob('*.py')):
            if '__pycache__' in filepath.parts or filepath.name.startswith('__'):
                continue
            if not _is_read_only_plugin(filepath):
                continue
            yield filepath

    def _is_read_only_plugin(filepath: pathlib.Path) -> bool:
        """读文件头 14 行判定 risk_class；无标记的文件（用户自建）视为可加载。

        --include-risky 时 risky 也加载（excluded 永不加载）。
        审计 S2（2026-10-30）：risky 插件（如 Redis CVE-2022-0543）之前永远无法运行，
        客户手里的高危洞无处可测；现提供显式开关。
        """
        try:
            with open(filepath, encoding='utf-8', errors='ignore') as f:
                head = f.read(1200)
        except OSError:
            return False
        for line in head.splitlines()[:14]:
            if 'risk_class' in line:
                # 形如 `# risk_class  : read_only  (说明...)`
                value = line.split(':', 1)[-1].strip().split()[0] if ':' in line else ''
                if value.startswith('read_only'):
                    return True
                if value.startswith('risky'):
                    return bool(getattr(args, 'include_risky', False))
                return False   # excluded 及其它：永不加载
        return True

    for filepath in _iter_plugin_files():
        module_name = filepath.stem
        # 语料插件用相对包路径导入（plugins_corpus.2020.CVE-xxx），用户插件用 plugins.xxx
        if filepath.parent.name == 'plugins':
            module = importlib.import_module('.{}'.format(module_name), 'plugins')
        else:
            pkg = '.'.join(filepath.parent.parts)
            module = importlib.import_module('.{}'.format(module_name), pkg)
        if 'Plugin' not in module.__dir__():
            continue
        _plugin = module.Plugin()
        if not args.module:
            plugin_list.append(_plugin)
            continue
        for match in args.module:
            match = match.lower().replace('-', '_')
            plugin_name = _plugin.info.name.lower().replace('-', '_') if _plugin.info.name else ''
            catalog = _plugin.info.catalog.lower().replace('-', '_') if _plugin.info.catalog else ''
            if fnmatch.fnmatch(plugin_name, match) or fnmatch.fnmatch(catalog, match):
                plugin_list.append(_plugin)
                break   # 审计 S2：重叠模式（如 -m A 'A*'）不得重复加载同一插件
    if not plugin_list:
        log.wrn(LANG.t('plugin list is empty, exit.'))
        # 审计 S2：静默 exit 0 会掩盖「什么都没扫」。非零退出码让 CI/脚本能识别。
        sys.exit(2)

    # 收集端口：插件声明端口 ∪ 默认扫描端口表（P0-1：把 DEFAULT_SCAN_PORTS 接回，端口发现不再退化为仅插件端口）
    plugin_port_list = set()
    for _plugin in plugin_list:
        plugin_port_list.add(_plugin.info.port)
        if _plugin.info.ssl_port:
            plugin_port_list.add(_plugin.info.ssl_port)
    default_ports = set(network.DEFAULT_SCAN_PORTS) | plugin_port_list

    # 目标解析
    # 存放host和port数据，用于端口探测，KEY为host原串（IP/域名/CIDR/范围/通配一律原样透传，展开交给 network.Scanner.parse_address），VAL为端口集合
    infos_for_portscan: Dict[str, Set[int]] = {}
    # 存放原始输入数据，包括协议，路径等数据，用于插件扫描
    # KEY为 (protocol, host, port) 三元组（I1：与存活端口共用同一 key 空间，原始 Url 对象不再按裸字符串重建），VAL为URL集合
    infos_for_plugin: Dict[Tuple[str, str, int], Set[urlutil.Url]] = {}
    for targets in args.targets:
        t_path = pathlib.Path(targets)
        # 输入的是文件夹，跳过
        if t_path.is_dir():
            continue
        # 输入的是文件读取并解析
        elif t_path.is_file():
            targets = re.split(r'[\s;,；，]', t_path.read_text(encoding='utf-8'))
        # 输入的ip或域名
        else:
            targets = [targets]
        # 将 target 转化为 url 对象，并存放端口记录用于后续主机端口扫描
        for target in targets:
            url_list = []
            if '://' in target:
                # 完整 URL 写法：直接由 Url 解析，协议与路径原样保留（I1）
                url = urlutil.Url(target, False)
                # 因为关闭了URL检验，判断是否正确识别host，无法识别直接跳过
                if not url.host:
                    continue
                url_list.append(url)
                host = url.host
                # 带协议的 URL 端口必为协议默认端口或显式端口，视为显式端口集（覆盖默认端口集）
                ports = {url.port} if url.port > 0 else None
            else:
                # X6：host:ports 写法先经 parse_target_ports 拆分（支持 host:80,443,8000-8100 与 host:1-65535）；
                # CIDR/IP范围/通配等无端口段写法 host 原串透传（I4），展开交给 Scanner.parse_address，不再按 Url.host 截断
                try:
                    host, ports = urlutil.parse_target_ports(target)
                except ValueError as err:
                    log.wrn(LANG.t('incorrect target "{}": {}', target, err))
                    continue
                # 因为关闭了URL检验，判断是否正确识别host，无法识别直接跳过
                if not host:
                    continue
                if ports is not None:
                    ports = set(ports)
                    # 显式端口逐个生成目标 Url，交由存活端口交叉匹配保留
                    for port in sorted(ports):
                        url = urlutil.Url('{}:{}'.format(host, port), False)
                        if url.host and url.port == port:
                            url_list.append(url)
                elif args.disable_port_scan:
                    # I5/A4：-dps 时没有端口探测阶段，裸目标直接以各插件声明端口扫描（do_testing 补全 info.port）
                    if len(network.ipv4_range_parse(host)) > 1:
                        log.wrn(LANG.t('target "{}" is CIDR/range style, cannot expand addresses with port scanning disabled, skipped.', target))
                        continue
                    url = urlutil.Url(host, False)
                    if url.host:
                        url_list.append(url)
                # else: 裸 IP/CIDR/域名写法，使用默认端口集（P0-1），目标 Url 由存活端口交叉匹配生成
            # 登记端口探测（-dps 时跳过）与插件目标
            if not args.disable_port_scan:
                if host not in infos_for_portscan:
                    infos_for_portscan[host] = set()
                infos_for_portscan[host].update(ports if ports is not None else default_ports)
            for url in url_list:
                infos_for_plugin.setdefault((url.protocol or '', url.host, url.port), set()).add(url)

    path_hosts_info = '! not port scanning file.'
    # 存活端口记录，元素为 (host, port)（I1：与插件目标 key 的 host:port 对齐）
    port_alive: Set[Tuple[str, int]] = set()
    # 服务识别结果（L1/L2/L3）：每个开放端口跑一次，结果全插件共享。
    # UDP 单独存：transport 维度不同，不能与 TCP 共用一个 key。
    services: Dict[Tuple[str, int], fingerprint.ServiceInfo] = {}
    services_udp: Dict[Tuple[str, int], fingerprint.ServiceInfo] = {}
    if not args.disable_port_scan:

        # I4：host 数按展开后的地址数统计（CIDR/范围/通配按展开数，域名按 1 个待解析主机计）
        def _expanded_host_count(host_str: str) -> int:
            ips = network.ipv4_range_parse(host_str)
            return len(ips) if len(ips) else 1

        host_num = sum(_expanded_host_count(h) for h in infos_for_portscan)
        port_num = sum([len(y) for y in infos_for_portscan.values()])
        log.inf(LANG.t('ports scanning, total of {} hosts, {} ports...').format(host_num, port_num))
        # 存活端口探测
        port_scanner = network.Scanner()
        for host in infos_for_portscan:
            port_scanner.scan_run(host, infos_for_portscan[host], is_check_alive=False, is_yield=False)
            # 清空端口清单，后续仅存放存活端口
            infos_for_portscan[host] = set()
        probar = progress_bar.new()
        # 审计 S2：UDP 探测需要「实际被扫描的 IP」，而不是 infos_for_portscan 的原始 host 串（
        # 域名/CIDR 目标的原始串不在 ip_info 的 key 里，导致 UDP 块被静默跳过）。
        probed_ips: Set[str] = set()
        for itor in probar.iter(port_scanner.get_yield_tcp(), total=host_num * port_num):
            probed_ips.add(itor[0])
            # 存活端口按 (IP, port) 与 (域名, port) 双形态记录：CIDR/范围展开出的 IP 直接命中，域名目标经 RECORDS 回溯
            port_alive.add((itor[0], itor[1]))
            for host in port_scanner.ip_info.get(itor[0], {}).get('RECORDS', set()):
                port_alive.add((host, itor[1]))

        # 保存主机存活信息
        path_hosts_info = pathlib.Path('hosts-info-{}.csv'.format(_run_stamp()))
        save_csv(port_scanner.gen_expand_ipinfo(), path_hosts_info)
        log.inf(LANG.t('host info saved:', path_hosts_info.absolute().__str__()))

        # UDP 服务识别（审计 C2：三个 UDP 探测器已实现但从未被调用）。
        # UDP 与 TCP 是不同命名空间：TCP 扫 53/161 不会显示开放，必须单独探。
        # 成本控制：只探 v1 固定的三个协议端口（53 DNS / 161 SNMP / 623 IPMI）。
        # 执行：在 TCP 端口扫描之后串行执行（每主机 3 包 × 2.5s 超时，wall time 加 ~2.5s/主机）。
        # 语义：UDP 无握手，无响应只能是 open|filtered，永不报 closed（不漏报优先）。
        udp_ports = (53, 161, 623)
        udp_hosts = sorted(probed_ips)
        if udp_hosts:
            udp_start = time.time()
            udp_pool = gevent.pool.Pool(size=min(32, max(1, len(udp_hosts) * len(udp_ports))))

            def _udp_identify(hp):
                h, p = hp
                return hp, fingerprint.detect(h, p, transport='udp')

            udp_tasks = [(h, p) for h in udp_hosts for p in udp_ports]
            for hp, svc in udp_pool.imap_unordered(_udp_identify, udp_tasks):
                services_udp[hp] = svc
                if svc.protocol != fingerprint.CONF_UNKNOWN:
                    log.inf('  [udp] {}:{} -> {}/{} state={} ({:.0f}ms) {}'.format(
                        hp[0], hp[1], svc.protocol, svc.confidence, svc.state,
                        svc.elapsed_ms, svc.evidence[:100]))
            log.inf(LANG.t('udp service identification done in {:.1f}s ({} ports/host)',
                           time.time() - udp_start, len(udp_ports)))
            # UDP 发现结果独立落盘（不进四态插件 CSV：UDP 探的是服务暴露面，不是插件判定）
            udp_rows = [
                {'HOST': hp[0], 'PORT': hp[1], 'STATE': svc.state,
                 'PROTOCOL': svc.protocol, 'CONFIDENCE': svc.confidence,
                 'EVIDENCE': svc.evidence, 'ELAPSED_MS': round(svc.elapsed_ms)}
                for hp, svc in sorted(services_udp.items())
                if svc.protocol != fingerprint.CONF_UNKNOWN
            ]
            if udp_rows:
                path_udp = pathlib.Path('hosts-udp-{}.csv'.format(_run_stamp()))
                save_csv(udp_rows, path_udp)
                log.inf('udp findings saved: %s', path_udp.absolute().__str__())
    else:
        log.wrn(LANG.t('port scanning is disabled: targets without explicit ports will be scanned using each plugin\'s declared port.'))
        port_alive = {(key[1], key[2]) for key in infos_for_plugin}

    # 交叉匹配核对可用目标（I1：插件目标与存活端口都以 host:port 对齐，原始 Url 永不重建）
    covered = {(key[1], key[2]) for key in infos_for_plugin}
    for key in list(infos_for_plugin):
        if (key[1], key[2]) not in port_alive:
            del infos_for_plugin[key]
    # 添加端口探测新发现的开放端口：生成裸 Url 目标（无协议/路径，由插件自行判断协议端口）
    for host, port in port_alive.difference(covered):
        infos_for_plugin.setdefault(('', host, port), set()).add(urlutil.Url('{}:{}'.format(host, port)))

    # 三层服务识别（L1 传输 → L2 协议 → L3 产品）：每个开放端口跑一次，结果全插件共享。
    # 端口号不参与适用性判定（nmap `ports` 指令语义：只决定先试哪个 probe，绝不决定试不试）——
    # 这是「SSH 放在 222 端口也要能测到」的机制保证。
    if port_alive:
        log.inf(LANG.t('identifying {} open port(s)...', len(port_alive)))
        fp_pool = gevent.pool.Pool(size=min(32, max(1, len(port_alive))))
        fp_start = time.time()

        def _identify(host_port):
            h, p = host_port
            return host_port, fingerprint.detect(h, p, transport='tcp')

        for hp, svc in fp_pool.imap_unordered(_identify, sorted(port_alive)):
            services[hp] = svc
        log.inf(LANG.t('service identification done in {:.1f}s', time.time() - fp_start))
        for hp in sorted(services):
            svc = services[hp]
            log.inf('  {}:{} -> {}/{} products={} ({:.0f}ms) {}'.format(
                hp[0], hp[1], svc.protocol, svc.confidence,
                ','.join(sorted(svc.products)) or '-', svc.elapsed_ms, svc.evidence[:80]))

    # todo: 实时写入数据；无法实现，特别是写json的时候每次都要重新序列化
    # 启动插件扫描
    log.inf(LANG.t('adding plugins...'))
    # X1/X2：显式 spawn 上下文，修复 fork+gevent 进程池退出时的 LoopExit
    pool = process.new(max_workers=args.process_number, mp_context=multiprocessing.get_context('spawn'))
    collector = plugin.ResultCollector()
    for key in infos_for_plugin:
        for url in infos_for_plugin[key]:
            for _plugin in plugin_list:
                # 如果输入的 target 带协议，则匹配协议是否正确，否则全插件扫描。
                # I3：无匹配插件的目标不再静默丢弃，记 SKIP 并说明原因
                if url.protocol and url.protocol != _plugin.info.protocol and url.protocol != _plugin.info.ssl_protocol:
                    collector.add({
                        'HOST': url.host or '', 'PORT': int(url.port or 0),
                        'PLUGIN': _plugin.info.catalog or _plugin.info.name,
                        'NAME': _plugin.info.name, 'CATALOG': _plugin.info.catalog or _plugin.info.name,
                        'PROTOCOL': url.protocol or '', 'URL': url.get_full(),
                        'PLUGIN_TYPE': _plugin.info.itype, 'IS_EXIST': False,
                        'OUTCOME': plugin.Outcome.SKIP,
                        'DATA': 'protocol "{}" not in plugin protocol {}/{}'.format(
                            url.protocol, _plugin.info.protocol, _plugin.info.ssl_protocol),
                    })
                    continue
                # 指纹门控（取代旧端口门控）：按服务识别结果匹配插件的 requires 标签。
                # fail-open 语义在 fingerprint.is_applicable：只有「有正向证据证明不匹配」才 SKIP，
                # 协议/产品判不出来一律放行（不漏报优先）。
                svc = services.get((url.host or '', url.port or _plugin.info.port))
                if svc is not None and _plugin.info.requires and not fingerprint.is_applicable(_plugin.info.requires, svc):
                    collector.add({
                        'HOST': url.host or '', 'PORT': int(url.port or _plugin.info.port),
                        'PLUGIN': _plugin.info.catalog or _plugin.info.name,
                        'NAME': _plugin.info.name, 'CATALOG': _plugin.info.catalog or _plugin.info.name,
                        'PROTOCOL': (url.protocol or ''), 'URL': url.get_full(),
                        'PLUGIN_TYPE': _plugin.info.itype, 'IS_EXIST': False,
                        'OUTCOME': plugin.Outcome.SKIP,
                        'DATA': fingerprint.skip_reason(_plugin.info.requires, svc),
                    })
                    continue
                # 加入进程池启动扫描，如果 target 使用最简洁写法的情况（如：eg.com），target 只有 host 属性，插件自己做好端口、协议判断
                pool.sm(_task_wrapper, url, _plugin, svc)
                if args.interval > 0:
                    time.sleep(args.interval)

    # I3：被跳过的目标逐条打印原因（非静默模式），避免操作者以为扫了其实没扫；
    # 放在早退分支之前，保证纯 SKIP 场景（无任务提交）也会打印
    if not args.is_silent:
        for skip in collector.skip_rows:
            log.wrn(LANG.t('skip {}/{}: {}', skip['HOST'], skip['PORT'], skip['DATA']))

    # 四态落盘的列定义与时间戳（早退分支也要落盘 SKIP 行，故提前到早退之前）
    ts = _run_stamp()
    column_order = ('NAME', 'CATALOG', 'PROTOCOL', 'PLUGIN_TYPE', 'IS_EXIST',
                    'HOST', 'PORT', 'PLUGIN', 'DATA', 'URL', 'OUTCOME')

    def _write_outputs(collector, ts):
        """四态落盘：结论行（vuln/safe/warn）写主 CSV 并保留旧列；
        warn 行另写 *-warn.csv（人工核验），skip 行另写 *-skip.csv（回答「为什么没被扫」）。
        """
        out_rows = [{k: row[k] for k in column_order if k in row}
                    for row in collector.rows if row['OUTCOME'] != plugin.Outcome.SKIP]
        path_hosts_vuls = pathlib.Path('hosts-plugin-result-{}.csv'.format(ts))
        if args.output_format == 'json':
            path_hosts_vuls = path_hosts_vuls.with_suffix('.json')
            with open(path_hosts_vuls, 'w', encoding='utf-8') as _f:
                _f.write(json.dumps(out_rows))
        else:
            save_csv(out_rows, path_hosts_vuls)
        log.inf(LANG.t('plugin result saved: {}', path_hosts_vuls.absolute().__str__()))

        # WARN 行独立落盘（对齐 nuclei -error-log），供人工核验
        path_warn = pathlib.Path('hosts-plugin-result-{}-warn.csv'.format(ts))
        save_csv([{k: row[k] for k in column_order if k in row} for row in collector.warn_rows], path_warn)
        if collector.warn_rows:
            log.inf(LANG.t('warn rows saved: {}', path_warn.absolute().__str__()))

        # SKIP 行独立落盘：与 warn 同构的旁路文件，SKIP 不进主 CSV 但不再只出现在控制台
        # （此处不新增 i18n key：language.yml 不在本次改动范围内，直接用 logging 的 %s 占位）
        path_skip = pathlib.Path('hosts-plugin-result-{}-skip.csv'.format(ts))
        save_csv([{k: row[k] for k in column_order if k in row} for row in collector.skip_rows], path_skip)
        if collector.skip_rows:
            log.inf('skip rows saved: %s', path_skip.absolute().__str__())

    # 没有匹配任何插件，没有可用目标，退出扫描
    if not pool.jobs:
        log.wrn(LANG.t('scannable target not found. if port scanning is enabled, check file:', path_hosts_info))
        # 纯 SKIP 场景（无任务提交）也要落盘，否则「为什么没被扫」的记录会随早退丢失
        _write_outputs(collector, ts)
        log.inf(LANG.t('plugin outcome summary: {}', collector.summary()))
        sys.exit(0)

    probar = progress_bar.new()
    probar.print_func = log.inf
    log.inf(LANG.t('wait for plugin scanning...'))
    for result in probar.iter(pool.yield_result(), total=len(pool.jobs)):
        with progress_bar.redirect_stdout():
            # 引擎侧字段由任务自身携带（见 _task_wrapper：yield_result 为 LIFO，按下标对齐会错位）
            result['NAME'] = result.pop('_NAME')
            result['CATALOG'] = result['PLUGIN']
            result['PROTOCOL'] = result.pop('_PROTOCOL')
            result['PLUGIN_TYPE'] = result.pop('_PTYPE')
            result['URL'] = result.pop('_URL')
            result['IS_EXIST'] = result['OUTCOME'] == plugin.Outcome.VULN
            if result['OUTCOME'] == plugin.Outcome.VULN and not args.is_silent:
                probar.print(
                    LANG.t(
                        '{}, {}, url: {}, info: {}',
                        result['PLUGIN'],
                        result['NAME'],
                        result['URL'],
                        result['DATA'].__str__().strip().split('\n')[0],
                    )
                )
        collector.add(result)

    _write_outputs(collector, ts)

    # 结束打印四态计数汇总（VULN/SAFE/WARN/SKIP，x+y+z+w == total）
    log.inf(LANG.t('plugin outcome summary: {}', collector.summary()))
