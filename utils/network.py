#!/bin/python3
# _*_ coding:utf-8 _*_
#
# net.py
# 网络工具箱，整个文件还很乱，需要拆分TCP、TCMP协议作为单独的类，socket 塞满的情况下有概率丢包，但是包确实发出去了
# 扫描用法：https://nmap.org/book/man-port-scanning-techniques.html
# 模块使用参考：https://cloud.tencent.com/developer/article/2352111
# 模块使用参考：https://www.cnblogs.com/LyShark/p/17787636.html#_label2
# 端口说明：http://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml
from gevent import monkey

monkey.patch_socket()
import copy
import errno
import os
import re
import socket
import struct
import sys
import time
from typing import (Any, Callable, Dict, Generator, Iterable, List, Self, Set,
                    Tuple, Union)

import netaddr

try:
    from utils import pro_async
except:
    import pathlib
    import sys

    sys.path.append(pathlib.Path(__file__).parent.parent.__str__())
    from utils import pro_async

DEFAULT_RE_SPLIT_HOST_AND_PORT_CHAR = r'[;,；，\s]+'
DEFAULT_SOCKET_TIMEOUT = 1
# 默认扫描端口表：Shodan facet 2026-10-25（现网 top-1000）∪ nmap-2008 top-1000 ∪ {2049 NFS}
# 即 research/port-table/default-ports-final.json 的 ports 数组（1766 个，≤4096 上限），选型依据见同目录 README.md
# 本块为生成产物，勿手工增删端口；需更新时重跑生成（读 JSON ports 数组排序填入）
DEFAULT_SCAN_PORTS = frozenset({
    1, 3, 4, 6, 7, 9, 11, 13, 15, 17, 19, 20, 21, 22, 23, 24, 25, 26, 30, 32,
    33, 37, 42, 43, 49, 53, 70, 79, 80, 81, 82, 83, 84, 85, 88, 89, 90, 91, 99, 100,
    102, 104, 106, 109, 110, 111, 113, 119, 122, 123, 125, 135, 137, 139, 143, 144, 146, 161, 163, 175,
    179, 189, 190, 192, 195, 199, 211, 212, 221, 222, 254, 255, 256, 259, 264, 280, 301, 306, 311, 340,
    366, 389, 400, 406, 407, 416, 417, 425, 427, 442, 443, 444, 445, 446, 458, 464, 465, 481, 497, 500,
    502, 503, 512, 513, 514, 515, 524, 541, 543, 544, 545, 548, 554, 555, 563, 587, 593, 616, 617, 625,
    631, 636, 646, 648, 666, 667, 668, 683, 687, 691, 700, 705, 711, 714, 720, 722, 726, 749, 765, 771,
    777, 783, 787, 789, 800, 801, 808, 843, 873, 880, 886, 887, 888, 898, 900, 901, 902, 903, 911, 912,
    981, 987, 990, 992, 993, 995, 999, 1000, 1001, 1002, 1007, 1009, 1010, 1011, 1021, 1022, 1023, 1024, 1025, 1026,
    1027, 1028, 1029, 1030, 1031, 1032, 1033, 1034, 1035, 1036, 1037, 1038, 1039, 1040, 1041, 1042, 1043, 1044, 1045, 1046,
    1047, 1048, 1049, 1050, 1051, 1052, 1053, 1054, 1055, 1056, 1057, 1058, 1059, 1060, 1061, 1062, 1063, 1064, 1065, 1066,
    1067, 1068, 1069, 1070, 1071, 1072, 1073, 1074, 1075, 1076, 1077, 1078, 1079, 1080, 1081, 1082, 1083, 1084, 1085, 1086,
    1087, 1088, 1089, 1090, 1091, 1092, 1093, 1094, 1095, 1096, 1097, 1098, 1099, 1100, 1102, 1104, 1105, 1106, 1107, 1108,
    1110, 1111, 1112, 1113, 1114, 1117, 1119, 1121, 1122, 1123, 1124, 1126, 1130, 1131, 1132, 1137, 1138, 1141, 1145, 1147,
    1148, 1149, 1151, 1152, 1153, 1154, 1163, 1164, 1165, 1166, 1169, 1174, 1175, 1177, 1180, 1183, 1185, 1186, 1187, 1192,
    1194, 1198, 1199, 1200, 1201, 1213, 1216, 1217, 1218, 1224, 1233, 1234, 1236, 1244, 1247, 1248, 1249, 1259, 1271, 1272,
    1277, 1287, 1296, 1300, 1301, 1309, 1310, 1311, 1322, 1328, 1334, 1337, 1344, 1352, 1400, 1414, 1417, 1433, 1434, 1443,
    1455, 1461, 1471, 1494, 1500, 1501, 1503, 1515, 1521, 1524, 1533, 1556, 1580, 1583, 1594, 1599, 1600, 1604, 1641, 1658,
    1666, 1687, 1688, 1700, 1701, 1717, 1718, 1719, 1720, 1721, 1723, 1741, 1755, 1761, 1782, 1783, 1800, 1801, 1805, 1812,
    1839, 1840, 1862, 1863, 1864, 1875, 1883, 1900, 1911, 1914, 1925, 1926, 1935, 1947, 1962, 1965, 1967, 1971, 1972, 1974,
    1984, 1998, 1999, 2000, 2001, 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009, 2010, 2012, 2013, 2020, 2021, 2022, 2030,
    2033, 2034, 2035, 2038, 2040, 2041, 2042, 2043, 2045, 2046, 2047, 2048, 2049, 2052, 2053, 2065, 2067, 2068, 2077, 2079,
    2081, 2082, 2083, 2086, 2087, 2095, 2096, 2099, 2100, 2103, 2105, 2106, 2107, 2111, 2119, 2121, 2126, 2135, 2144, 2154,
    2160, 2161, 2170, 2179, 2181, 2190, 2191, 2196, 2200, 2222, 2251, 2260, 2288, 2301, 2323, 2332, 2345, 2366, 2375, 2376,
    2379, 2381, 2382, 2383, 2393, 2394, 2399, 2401, 2404, 2443, 2455, 2480, 2492, 2500, 2522, 2525, 2557, 2601, 2602, 2604,
    2605, 2607, 2608, 2628, 2638, 2701, 2702, 2710, 2717, 2718, 2725, 2761, 2762, 2800, 2809, 2811, 2869, 2875, 2909, 2910,
    2920, 2967, 2968, 2998, 3000, 3001, 3003, 3005, 3006, 3008, 3011, 3017, 3030, 3031, 3050, 3052, 3071, 3077, 3128, 3168,
    3211, 3221, 3260, 3261, 3268, 3269, 3283, 3299, 3300, 3301, 3306, 3310, 3322, 3323, 3324, 3325, 3333, 3351, 3367, 3369,
    3370, 3371, 3372, 3388, 3389, 3390, 3404, 3443, 3460, 3476, 3478, 3493, 3517, 3527, 3541, 3542, 3546, 3551, 3580, 3659,
    3689, 3690, 3702, 3703, 3737, 3749, 3766, 3780, 3784, 3790, 3800, 3801, 3809, 3814, 3826, 3827, 3828, 3851, 3869, 3871,
    3878, 3880, 3889, 3905, 3914, 3918, 3920, 3945, 3971, 3986, 3995, 3998, 4000, 4001, 4002, 4003, 4004, 4005, 4006, 4022,
    4040, 4045, 4063, 4064, 4111, 4125, 4126, 4129, 4150, 4157, 4190, 4224, 4242, 4279, 4282, 4321, 4343, 4369, 4430, 4432,
    4433, 4434, 4443, 4444, 4445, 4446, 4449, 4500, 4506, 4550, 4567, 4662, 4664, 4782, 4786, 4840, 4848, 4899, 4900, 4911,
    4949, 4998, 5000, 5001, 5002, 5003, 5004, 5005, 5006, 5007, 5009, 5010, 5025, 5030, 5033, 5050, 5051, 5054, 5060, 5061,
    5080, 5087, 5090, 5100, 5101, 5102, 5120, 5172, 5190, 5200, 5201, 5214, 5221, 5222, 5225, 5226, 5269, 5280, 5298, 5353,
    5357, 5405, 5414, 5431, 5432, 5433, 5435, 5440, 5443, 5500, 5510, 5544, 5550, 5555, 5560, 5566, 5601, 5631, 5633, 5666,
    5672, 5678, 5679, 5683, 5718, 5730, 5800, 5801, 5802, 5810, 5811, 5815, 5822, 5825, 5850, 5858, 5859, 5862, 5877, 5900,
    5901, 5902, 5903, 5904, 5906, 5907, 5910, 5911, 5915, 5922, 5925, 5938, 5950, 5952, 5959, 5960, 5961, 5962, 5963, 5984,
    5985, 5986, 5987, 5988, 5989, 5998, 5999, 6000, 6001, 6002, 6003, 6004, 6005, 6006, 6007, 6008, 6009, 6025, 6036, 6050,
    6059, 6060, 6080, 6100, 6101, 6106, 6112, 6123, 6129, 6156, 6264, 6346, 6379, 6389, 6432, 6443, 6502, 6505, 6510, 6543,
    6547, 6565, 6566, 6567, 6580, 6633, 6646, 6653, 6664, 6666, 6667, 6668, 6669, 6688, 6689, 6692, 6697, 6699, 6779, 6788,
    6789, 6792, 6839, 6881, 6901, 6969, 7000, 7001, 7002, 7004, 7005, 7007, 7010, 7019, 7025, 7050, 7070, 7071, 7080, 7081,
    7100, 7103, 7106, 7170, 7171, 7200, 7201, 7218, 7402, 7415, 7434, 7435, 7443, 7474, 7496, 7512, 7547, 7548, 7625, 7627,
    7634, 7657, 7676, 7741, 7777, 7778, 7779, 7800, 7911, 7920, 7921, 7937, 7938, 7989, 7999, 8000, 8001, 8002, 8003, 8004,
    8005, 8006, 8007, 8008, 8009, 8010, 8011, 8012, 8014, 8015, 8017, 8020, 8021, 8022, 8026, 8031, 8042, 8043, 8045, 8058,
    8060, 8061, 8069, 8071, 8080, 8081, 8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089, 8090, 8091, 8092, 8093, 8095, 8096,
    8097, 8098, 8099, 8100, 8101, 8102, 8104, 8105, 8106, 8108, 8109, 8110, 8112, 8113, 8123, 8126, 8139, 8140, 8159, 8180,
    8181, 8182, 8188, 8190, 8192, 8193, 8194, 8200, 8222, 8254, 8290, 8291, 8292, 8300, 8333, 8334, 8383, 8400, 8402, 8443,
    8444, 8445, 8500, 8545, 8554, 8575, 8600, 8602, 8649, 8651, 8652, 8654, 8686, 8701, 8728, 8787, 8800, 8834, 8873, 8880,
    8883, 8885, 8886, 8887, 8888, 8889, 8890, 8899, 8911, 8989, 8994, 8999, 9000, 9001, 9002, 9003, 9004, 9006, 9009, 9010,
    9011, 9013, 9020, 9022, 9026, 9040, 9041, 9042, 9050, 9051, 9070, 9071, 9080, 9081, 9082, 9083, 9088, 9089, 9090, 9091,
    9092, 9093, 9094, 9095, 9096, 9098, 9099, 9100, 9101, 9102, 9103, 9110, 9111, 9151, 9160, 9180, 9191, 9200, 9207, 9220,
    9290, 9292, 9295, 9301, 9306, 9333, 9398, 9415, 9418, 9443, 9485, 9500, 9501, 9502, 9503, 9527, 9530, 9535, 9575, 9593,
    9594, 9595, 9600, 9618, 9633, 9666, 9761, 9800, 9869, 9876, 9877, 9878, 9888, 9898, 9900, 9917, 9922, 9929, 9943, 9944,
    9968, 9971, 9981, 9988, 9997, 9998, 9999, 10000, 10001, 10002, 10003, 10004, 10005, 10006, 10007, 10008, 10009, 10010, 10011, 10012,
    10013, 10015, 10020, 10022, 10024, 10025, 10030, 10049, 10050, 10080, 10081, 10082, 10084, 10087, 10134, 10180, 10215, 10225, 10243, 10250,
    10256, 10324, 10443, 10554, 10566, 10616, 10617, 10621, 10626, 10628, 10629, 10778, 10909, 10911, 11000, 11110, 11111, 11112, 11210, 11211,
    11288, 11300, 11371, 11434, 11443, 11967, 12000, 12111, 12113, 12174, 12265, 12323, 12324, 12325, 12326, 12345, 12500, 13000, 13456, 13579,
    13722, 13782, 13783, 14000, 14147, 14238, 14265, 14344, 14441, 14442, 15000, 15002, 15003, 15004, 15006, 15660, 15742, 16000, 16001, 16010,
    16012, 16016, 16018, 16030, 16080, 16113, 16992, 16993, 17000, 17877, 17988, 18040, 18080, 18081, 18083, 18089, 18101, 18111, 18245, 18264,
    18443, 18789, 18988, 19000, 19071, 19100, 19101, 19283, 19315, 19350, 19780, 19801, 19842, 19999, 20000, 20001, 20002, 20005, 20010, 20018,
    20020, 20030, 20031, 20040, 20050, 20053, 20060, 20070, 20080, 20082, 20084, 20090, 20100, 20106, 20107, 20110, 20121, 20150, 20151, 20182,
    20184, 20185, 20200, 20201, 20202, 20208, 20221, 20222, 20256, 20325, 20440, 20443, 20500, 20512, 20547, 20600, 20828, 20880, 21001, 21002,
    21025, 21083, 21116, 21200, 21230, 21231, 21232, 21233, 21234, 21235, 21236, 21237, 21238, 21239, 21240, 21241, 21242, 21243, 21244, 21245,
    21247, 21248, 21249, 21250, 21251, 21253, 21254, 21255, 21256, 21257, 21258, 21259, 21260, 21261, 21262, 21263, 21264, 21266, 21267, 21268,
    21269, 21270, 21271, 21272, 21273, 21274, 21275, 21276, 21277, 21278, 21280, 21281, 21282, 21283, 21284, 21285, 21286, 21288, 21289, 21290,
    21291, 21292, 21294, 21295, 21296, 21297, 21298, 21299, 21300, 21301, 21302, 21303, 21304, 21305, 21306, 21307, 21308, 21309, 21310, 21311,
    21312, 21313, 21314, 21315, 21316, 21317, 21319, 21320, 21321, 21322, 21323, 21324, 21326, 21327, 21328, 21329, 21330, 21379, 21400, 21443,
    21500, 21515, 21571, 22000, 22022, 22082, 22084, 22107, 22206, 22222, 22345, 22380, 22556, 22609, 22703, 22705, 22939, 23023, 23082, 23084,
    23184, 23424, 23456, 23502, 24442, 24444, 24800, 24808, 25000, 25001, 25006, 25007, 25009, 25010, 25082, 25084, 25105, 25565, 25734, 25735,
    25952, 26214, 27000, 27015, 27017, 27352, 27353, 27355, 27356, 27571, 27715, 28001, 28015, 28017, 28080, 28201, 28443, 29842, 29984, 30000,
    30001, 30002, 30003, 30004, 30005, 30006, 30007, 30008, 30009, 30010, 30011, 30013, 30015, 30017, 30019, 30021, 30023, 30025, 30027, 30029,
    30050, 30083, 30101, 30104, 30106, 30110, 30111, 30112, 30113, 30120, 30121, 30122, 30123, 30443, 30444, 30452, 30468, 30473, 30479, 30501,
    30701, 30718, 30951, 31001, 31017, 31038, 31210, 31337, 31443, 31444, 32001, 32080, 32101, 32102, 32202, 32303, 32400, 32443, 32444, 32764,
    32768, 32769, 32770, 32771, 32772, 32773, 32774, 32775, 32776, 32777, 32778, 32779, 32780, 32781, 32782, 32783, 32784, 32785, 32800, 33060,
    33344, 33354, 33389, 33899, 34500, 34571, 34572, 34573, 35000, 35002, 35100, 35101, 35153, 35241, 35250, 35500, 35522, 35531, 35560, 36505,
    37215, 37443, 37777, 38080, 38292, 38520, 38880, 40000, 40001, 40005, 40029, 40099, 40193, 40471, 40894, 40911, 41511, 41800, 42208, 42235,
    42420, 42424, 42443, 42510, 42901, 43008, 43009, 43080, 43221, 44021, 44158, 44176, 44300, 44303, 44304, 44305, 44306, 44308, 44310, 44332,
    44333, 44336, 44340, 44345, 44350, 44442, 44443, 44444, 44501, 44818, 45000, 45001, 45002, 45003, 45006, 45100, 45111, 45333, 45444, 45555,
    45666, 45667, 45677, 45821, 45886, 45888, 46000, 46443, 47001, 47080, 47534, 47984, 47989, 47990, 48019, 48020, 48080, 48889, 49080, 49152,
    49153, 49154, 49155, 49156, 49157, 49158, 49159, 49160, 49161, 49163, 49165, 49167, 49175, 49176, 49400, 49501, 49502, 49592, 49682, 49684,
    49686, 49688, 49692, 49767, 49999, 50000, 50001, 50002, 50003, 50004, 50005, 50006, 50007, 50008, 50009, 50010, 50011, 50012, 50013, 50014,
    50022, 50050, 50070, 50080, 50085, 50100, 50101, 50102, 50103, 50104, 50105, 50106, 50107, 50113, 50160, 50202, 50257, 50300, 50389, 50443,
    50500, 50580, 50636, 50800, 50805, 50995, 50996, 50997, 50998, 50999, 51000, 51001, 51002, 51003, 51004, 51005, 51007, 51103, 51106, 51200,
    51201, 51235, 51434, 51493, 52200, 52230, 52311, 52536, 52673, 52822, 52848, 52869, 52881, 52931, 52951, 53400, 53480, 53481, 53483, 53484,
    53805, 53806, 54022, 54045, 54138, 54328, 54545, 54857, 55000, 55055, 55056, 55081, 55200, 55350, 55442, 55443, 55475, 55550, 55553, 55554,
    55555, 55600, 56737, 56738, 57294, 57779, 57785, 57788, 57797, 58000, 58080, 58443, 58585, 58603, 59012, 60000, 60001, 60010, 60020, 60030,
    60099, 60129, 60443, 61234, 61532, 61613, 61616, 61617, 61900, 62016, 62078, 62080, 62237, 62865, 63210, 63256, 63260, 63331, 63676, 64295,
    64623, 64680, 65000, 65004, 65129, 65389,
})

# 端口三态（nmap 语义），判定只看 connect_ex 返回值，见 Scanner.handle_tcp_socket：
#   open     : ret == 0，完成 TCP 三次握手；
#   closed   : ECONNREFUSED，Linux 111 / Windows 10061(WSAECONNREFUSED)，目标回 RST 明确拒绝；
#   filtered : EAGAIN 11 / ETIMEDOUT 110 / EWOULDBLOCK 10035 / WSAETIMEDOUT 10060 及其余一切 errno
#              （防火墙静默丢弃、超时、EHOSTUNREACH/ENETUNREACH 等无 RST 场景，一律保守归 filtered，
#              绝不误报 open）。Windows 的 WSAE* 常量在非 Windows 平台 errno 模块中不存在，用 getattr 补数值。
TCP_STATE_OPEN = 'open'
TCP_STATE_CLOSED = 'closed'
TCP_STATE_FILTERED = 'filtered'
TCP_CLOSED_ERRNOS = frozenset({errno.ECONNREFUSED, getattr(errno, 'WSAECONNREFUSED', 10061)})
TCP_FILTERED_ERRNOS = frozenset({
    errno.EAGAIN, errno.EWOULDBLOCK, errno.ETIMEDOUT,
    getattr(errno, 'WSAEWOULDBLOCK', 10035), getattr(errno, 'WSAETIMEDOUT', 10060),
})


def handle_ip_address(ip_string: str):
    # ip-address-style or ip-network-style IP handler
    return netaddr.IPNetwork(ip_string)


def handle_ip_range(ip_string: str):
    # ip-range-style IP handler
    ip_list = ip_string.split('-')
    if len(ip_list) <= 1:
        ip_list = ip_string.split('_')
    return netaddr.iprange_to_cidrs(ip_list[0], ip_list[1])


def handle_ip_glob(ip_string: str):
    # ip-glob-style IP handler
    if isinstance(ip_string, tuple):
        ip_string = ip_string[0]
    return netaddr.glob_to_cidrs(ip_string)


def ipv4_range_parse(ip_string: str, re_split_char: str = DEFAULT_RE_SPLIT_HOST_AND_PORT_CHAR) -> netaddr.IPSet:
    l_re_handle = [
        # 192.168.1.1/255.255.255.0
        (r'(!\s*)?(\d{1,3}(?:\.\d{1,3}){3}/\d{1,3}(?:\.\d{1,3}){3})', handle_ip_address),
        # 192.168.1.1-192.168.1.10
        (r'(!\s*)?(\d{1,3}(?:\.\d{1,3}){3}[-_]\d{1,3}(?:\.\d{1,3}){3})', handle_ip_range),
        # 192.168.1.1-23
        (r'(!\s*)?(\d{1,3}(?:\.\d{1,3}){3}[-_]\d{1,3})', handle_ip_glob),
        # 192.168.1.1/24
        (r'(!\s*)?(\d{1,3}(?:\.\d{1,3}){3}/\d{1,2})', handle_ip_address),
        # 192.168.1.1
        (r'(!\s*)?(\d{1,3}(?:\.\d{1,3}){3})', handle_ip_address),
        # 192.168.1.* or 192.168.*
        (r'(!\s*)?([\d\*]{1,3}(?:\.[\d\*]{1,3}){1,3})', handle_ip_glob),
    ]

    ret = netaddr.IPSet()
    for ip in re.split(re_split_char, ip_string):
        is_found = False
        for r_ip, handle in l_re_handle:
            r_ip_ranges = re.findall(r_ip, ip)
            for r_ip_rng in r_ip_ranges:
                is_found = True
                ip_network = handle(r_ip_rng[1])
                # 检查是否有反向标识，清理集合数据
                if r_ip_rng[0]:
                    ret = ret.difference(netaddr.IPSet(ip_network))
                    # tar_list = l_rmv
                else:
                    ret.update(ip_network)
            #         tar_list = l_add
            #     if isinstance(ip_network, list):
            #         tar_list.extend(ip_network)
            #     else:
            #         tar_list.append(ip_network)
            if is_found:
                break
    # [ret.add(row) for row in l_add]
    # [ret.remove(row) for row in l_rmv]
    # ret.difference()
    return ret


def ports_to_range(values: List[int]):
    values = sorted(set(values))
    ret = ''
    log_last = -1
    is_plus = False
    for index, port in enumerate(values):
        if port < 1 or port > 65535:
            continue
        if port == log_last + 1 and index != len(values) - 1:
            log_last = port
            is_plus = True
            continue
        if not ret:
            ret = str(port)
        elif not is_plus:
            ret += ',{}'.format(port)
        elif index == len(values) - 1:
            ret += '-{}'.format(port)
            break
        else:
            ret += '-{},{}'.format(log_last, port)
        log_last = port
        is_plus = False
    return ret


def range_to_ports(values: str):
    ret = set()
    for val in re.split(DEFAULT_RE_SPLIT_HOST_AND_PORT_CHAR, values):
        port_range = [-1, -1]
        if '-' in val:
            spl_port = val.split('-')
            spl_port = [s_port for s_port in spl_port if s_port]
            if len(spl_port) < 2:
                raise ValueError('the format of port {} is incorrectly'.format(val))
            port_range = [int(spl_port[0]), int(spl_port[1])]
        else:
            port_range = [int(val), int(val)]

        if port_range[0] < 0 or port_range[1] > 65535:
            raise ValueError('port "{}" is incorrectly'.format(val))
        for port in range(port_range[0], port_range[1] + 1):
            ret.add(port)
    return ret


class BytesPacketBase:
    def __init__(self) -> None:
        self._rawdata = b''

    def to_hex(self):
        return self._rawdata.hex()

    def show(self, sep=' '):
        is_new_row = True
        ret = ''
        for index, value in enumerate(self._rawdata):
            if index % 16 == 0 and index != 0:
                ret += '\n'
                is_new_row = True
            if is_new_row:
                ret += '{:02X}'.format(value)
            else:
                ret += '{}{:02X}'.format(sep, value)
            is_new_row = False
        print(ret)

    def __str__(self) -> str:
        raw_string = super().__str__()
        str_attr = ''
        for key in self.__dict__:
            if key.startswith('_'):
                continue
            if isinstance(self.__dict__[key], Callable):
                continue
            str_attr += '{}={}, '.format(key, self.__dict__[key])
        return '{} {}>'.format(raw_string[:-1], str_attr[:-2])


class IPPacket(BytesPacketBase):

    def include(self):
        # 加载更高层的数据包
        pass

    def exclude(self):
        # 导出更高层的数据包
        pass


class ICMPPacket(IPPacket):
    def __init__(
        self, type_: int = 8, code: int = 0, identifier: int = 0, sequence: int = 0, payload: bytes = b''
    ) -> None:
        # Type AND Code: https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml
        super().__init__()
        self.type_ = type_
        self.code = code
        self.identifier = identifier or os.getpid()
        self.sequence = sequence
        self.payload = payload

    @classmethod
    def get_checksum(cls, raw_packet: bytes = None) -> int:
        raw_packet = raw_packet or cls._rawdata
        if len(raw_packet) % 2:
            raw_packet += b'\00'
        checksum = 0
        for i in range(len(raw_packet) // 2):
            (word,) = struct.unpack('!H', raw_packet[2 * i : 2 * i + 2])
            checksum += word
        while True:
            carry = checksum >> 16
            if carry:
                checksum = (checksum & 0xFFFF) + carry
            else:
                break
        return ~checksum & 0xFFFF

    def incr_sequence(self) -> None:
        self.sequence += 1

    def pack(self) -> bytes:
        packet_info = struct.pack('!BBHH', self.type_, self.code, self.identifier, self.sequence) + self.payload
        checksum = self.get_checksum(packet_info)
        self._rawdata = packet_info[:2] + struct.pack('!H', checksum) + packet_info[2:]
        return self._rawdata

    @classmethod
    def unpack(cls, raw_packet: bytes) -> Self:
        (_type, code, _, identifier, sequence) = struct.unpack('!BBHHH', raw_packet[:8])
        payload = raw_packet[8:]
        return cls(_type, code, identifier, sequence, payload)


class ICMPSocket(socket.socket):
    # 写法参考：https://fasionchan.com/network/icmp/ping-py/
    def __init__(
        self,
        timeout: int = None,
        fileno: int | None = None,
    ) -> None:
        super().__init__(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP, fileno)
        if timeout is not None:
            self.settimeout(timeout)

    def send_one(self, dst_host: str, identifier: int = None, payload: bytes = b'') -> int:
        packet = ICMPPacket(identifier=identifier, payload=payload)
        # send it
        send_length = self.sendto(packet.pack(), 0, (dst_host, 0))
        packet.incr_sequence()
        return packet

    def recv_one(self, identifier: int = None, bufsize: int = 1500) -> Tuple[str, ICMPPacket]:
        recv_bytes, (src_ip, _) = self.recvfrom(bufsize)
        # 去掉 20 个字节的 IP 头部
        packet = ICMPPacket.unpack(recv_bytes[20:])
        if identifier is not None and packet.identifier != identifier:
            return
        return src_ip, packet

    def send_and_get_detail(
        self, dst_host: str, timeout: float = DEFAULT_SOCKET_TIMEOUT, payload: bytes = b'', is_check_alive: bool = True
    ):
        if timeout is not None:
            self.settimeout(timeout)
        self.send_one(dst_host, payload=payload)
        replay_ip = None
        try:
            replay_ip, packet = self.recv_one()
        except TimeoutError:
            # TimeoutError: timed out
            # 无响应导致超时
            pass
        # type、code 定义：https://tonydeng.github.io/sdn-handbook/basic/icmp.html
        if not replay_ip or (is_check_alive and (packet.type_ != 0 or packet.code != 0)):
            return
        # 需要注意在部分情况响应IP和请求IP不一致，如扫描VMWare网卡的网络地址时会响应其它IP
        return dst_host, replay_ip, packet

    def send_and_close(
        self,
        dst_host: str,
        timeout: float = DEFAULT_SOCKET_TIMEOUT,
        payload: bytes = b'',
        is_check_alive: bool = True,
        retry: int = 3,
    ):
        ret = ''
        while retry > 0:
            ret = self.send_and_get_detail(dst_host, timeout, payload, is_check_alive)
            if ret:
                break
            retry -= 1
        self.close()
        if not ret:
            return
        return dst_host


class Scanner:
    def __init__(self, size=300) -> None:
        """初始化扫描对象；协程池子的大小和网速有关，端口扫描分为2种结果，端口开放或端口不开放（过滤之类的不考虑视为不开放）
        端口开放的情况下扫描机器会发送（即上传）几个数据包1.SYN包66Byte、2.ACK包54Byte、3.FIN/ACK包54Byte、4.ACK包54Byte；还会接收（即下载）几个数据包1.SYN/ACK包66Byte、2.ACK包54Byte、3.FIN包54-96Byte（部分应用会夹带私货，取最大96）
        也就是每次发送会占用 66+54+54+54 = 222 Byte 的带宽，接收会占用 66+60+96 = 216 Byte 的带宽，换算一下按10Mbps的上传、下载网速计算：
        上传可设置的size为 10 * 1024 / * 1024 / 8 / 222 = 5904；
        下载可设置的size为 10 * 1024 / * 1024 / 8 / 216 = 6068；
        取最小值为5904，但是要注意这是理想状态下，有些应用在连接后即使迅速切断连接还是会偷跑数据、设备本身也有网络通信请求；其次这个值的最终值还和TCP的窗口等有关，懒得研究了
        经过互联网的扫描并发池子大小最好参考比例设置，否则结果会不准确，抓包显示确实无任何回包，判断是池子过大造成互联网拥堵丢包；内网的并发池子大小可以设置任意值（最好还是65535以内），反正没试出上限值

        Args:
            size (int, optional): 协程的池子的大小，最好参考20Mbps/300按比例设置，默认：500
        """
        self.default_alive_scan_ports = [22, 80, 135, 137, 139, 443, 445]
        self.pool_dns: pro_async.AsyncPool = pro_async.AsyncPool(size // 2)
        self.pool_icmp: pro_async.AsyncPool = pro_async.AsyncPool(size)
        self.pool_tcp: pro_async.AsyncPool = pro_async.AsyncPool(size)
        self.ip_info: Dict[str, Dict[str, Union[str, Set, Dict, bool]]] = {}
        self.host_ip_map: Dict[str, str] = {}

    def parse_address(
        self, addrs: str | Iterable, split_char: str = DEFAULT_RE_SPLIT_HOST_AND_PORT_CHAR
    ) -> netaddr.IPSet:
        def gethostbyname(host):
            return socket.gethostbyname(host), host

        ret = netaddr.IPSet()
        domain_list = set()
        if isinstance(addrs, str):
            addrs = re.split(split_char, addrs)
            for addr in addrs:
                r_addr = re.search(r'(!\s)?([\d\*]{1,3}(?:\.[\d\*]{1,3}){1,3})', addr)
                if r_addr:
                    ips = ipv4_range_parse(addr)
                else:
                    domain_list.add(addr)
                    continue

                for ip in ips:
                    ret.add(ip)
                    self.init_ip_info(ip.__str__())
            # 对域名统一进行处理
            self.init_ip_info('no-dns-resolution')
            for domain in domain_list:
                self.pool_dns.sp(gethostbyname, domain)

            # socket.gaierror: [Errno 11001] getaddrinfo failed
            # 地址写法不对，或者是域名没解析
            # raise RuntimeError('"{}" has an incorrect address format or cannot be resolved'.format(addr))
            for itor in self.pool_dns.get_yeild():
                if isinstance(itor, BaseException):
                    continue
                ret.add(itor[0])
                if self.has_ip_info(itor[0]):
                    self.log_ip_info_records(itor[0], itor[1])
                else:
                    self.init_ip_info(itor[0], {'RECORDS': set([itor[1]])})
                self.host_ip_map[itor[1]] = itor[0]

        else:
            ret = netaddr.IPSet(addrs)
            for ip in addrs:
                self.init_ip_info(ip.__str__())
        return ret

    def init_ip_info(self, ip: str, value: Dict = {}) -> Dict[str, Union[str, Set, Dict]]:
        if not ip in self.ip_info:
            self.ip_info[ip] = {
                # 目标IP
                'IP': ip,
                # 域名解析或IP映射的值
                'RECORDS': set(),
                # 主机是否存活
                'ALIVE': False,
                # 端口三态记录 {port: 'open'|'closed'|'filtered'}
                'PORTS': {},
            }
        self.ip_info[ip].update(value)
        return self.ip_info[ip]

    def has_ip_info(self, ip: str) -> Dict[str, Union[str, Set]]:
        if ip in self.ip_info:
            return self.ip_info[ip]
        return

    def log_ip_info_alive(self, ip: str, is_alive: bool) -> Dict[str, Union[str, Set]]:
        self.ip_info[ip]['ALIVE'] = is_alive
        return self.ip_info[ip]

    def log_ip_info_port(self, ip: str, value: int, state: str = TCP_STATE_OPEN) -> Dict[str, Union[str, Set, Dict]]:
        self.ip_info[ip]['PORTS'][value] = state
        return self.ip_info[ip]

    def log_ip_info_records(self, ip: str, value: str) -> Dict[str, Union[str, Set]]:
        self.ip_info[ip]['RECORDS'].add(value)
        return self.ip_info[ip]

    @staticmethod
    def handle_tcp_socket(ip: str, port: int, timeout: float = DEFAULT_SOCKET_TIMEOUT):
        if port < 1 or port > 65535:
            return

        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.settimeout(timeout)
        # 1. 发送 SYN 请求连接，三态判据统一用 connect_ex 返回值（nmap 语义，常量定义见模块头部）：
        #   ret == 0                     -> open（三次握手成功）
        #   ret in TCP_CLOSED_ERRNOS     -> closed（ECONNREFUSED 111/10061，目标回 RST 明确拒绝）
        #   其余一切 errno                -> filtered（EAGAIN 11 / ETIMEDOUT 110 / EWOULDBLOCK 10035/10060
        #                                   及 EHOSTUNREACH 等全部无 RST 场景，保守归 filtered）
        # Linux 下会出现 OSError: [Errno 24] Too many open files，因为程序会同时打开大量的连接但是又不会迅速关闭；
        # 解决该问题可以使用 ulimit -n 102400 如果设备性能比较好，可以设置比 102400 更大的值
        # Windows 上可能的返回值：https://learn.microsoft.com/en-us/windows/win32/winsock/windows-sockets-error-codes-2
        # Linux 上可能的返回值：https://gist.github.com/gabrielfalcao/4216897
        ret = client.connect_ex((ip, port))
        client.close()
        # 不用 shutdown() 判连通性：超时/未连接的 socket 上调用它不抛异常，不是判据（实测返回 None）；
        # 也不区分平台：原 win32 分支会跳过 ret 检查，把 filtered 端口误报为 open（X4 缺陷）
        if ret == 0:
            state = TCP_STATE_OPEN
        elif ret in TCP_CLOSED_ERRNOS:
            state = TCP_STATE_CLOSED
        else:
            state = TCP_STATE_FILTERED
        return ip, port, state

    def scan_icmp(
        self,
        ip_list: Union[netaddr.IPSet, Generator[Tuple[str], Any, None]],
        timeout: float = DEFAULT_SOCKET_TIMEOUT,
        retry: int = 3,
    ):
        for ip in ip_list:
            if isinstance(ip, netaddr.IPAddress):
                ip = ip.__str__()
            else:
                ip = ip[0]
            icmp_engine = ICMPSocket(timeout=timeout)
            self.pool_icmp.sp(icmp_engine.send_and_close, ip, timeout, retry=retry)
        for ip in self.pool_icmp.get_yeild():
            if ip:
                self.log_ip_info_alive(ip, True)
                yield ip, 0

    def scan_tcp_ports(
        self,
        ip_list: Union[netaddr.IPSet, Generator[Tuple[str], Any, None]],
        ports: Union[List[int], str] = DEFAULT_SCAN_PORTS,
        timeout: float = DEFAULT_SOCKET_TIMEOUT,
        is_yield: bool = True,
    ):
        for ip in ip_list:
            if isinstance(ip, netaddr.IPAddress):
                ip = ip.__str__()
            else:
                ip = ip[0]
            for port in ports:
                self.pool_tcp.sp(self.handle_tcp_socket, ip, port, timeout)
        if not is_yield:
            return
        return self.get_yield_tcp()

    def scan_run(
        self,
        addresses: Union[str, netaddr.IPSet],
        ports: Union[List[int], str] = DEFAULT_SCAN_PORTS,
        timeout: float = DEFAULT_SOCKET_TIMEOUT,
        is_check_alive: bool = True,
        is_yield: bool = True,
    ) -> Generator[Tuple[str, int], None, None]:
        addresses = self.parse_address(addresses)
        if isinstance(ports, str):
            ports = range_to_ports(ports)
        # 存活探测
        if is_check_alive:
            addresses = self.scan_icmp(addresses)
        gen = self.scan_tcp_ports(addresses, ports, timeout, is_yield)
        if not is_yield:
            return
        return gen

    def get_yield_tcp(self) -> Generator[Tuple[str, int], None, None]:
        # 语义保持不变：对外只 yield open 的 (ip, port) 元组（ss.py 依赖，签名与产出不能变）；
        # closed/filtered 仅记入 ip_info['PORTS'] 供 gen_expand_ipinfo 输出三态，不对外产出
        for result in self.pool_tcp.get_yeild():
            # 连接数超限（Errno 24）等异常结果原样跳过
            if not isinstance(result, tuple) or len(result) != 3:
                continue
            ip, port, state = result
            self.log_ip_info_port(ip, port, state)
            if state == TCP_STATE_OPEN:
                self.log_ip_info_alive(ip, True)
                yield ip, port

    def show(self, hosts_info: Dict[str, Dict[str, Union[str, Set, Dict]]] = None, is_only_alive: bool = True):
        hosts_info = hosts_info or self.ip_info
        if not hosts_info:
            print('no host found.')

        for ip, infos in hosts_info.items():
            if is_only_alive and not infos['ALIVE']:
                continue

            print(ip)
            for key, info in infos.items():
                if isinstance(info, dict):
                    info = ', '.join(['{}:{}'.format(p, s) for p, s in sorted(info.items())])
                elif isinstance(info, Iterable) and not isinstance(info, (str, bytes)):
                    info = ', '.join([str(i) for i in sorted(info)])
                print(' |- {:8}: {}'.format(key, info))
            print()

    def gen_expand_ipinfo(self) -> List[Dict[str, str | int | None]]:
        ret = []
        for ip in self.ip_info:
            self.ip_info[ip]['RECORDS'] = list(set(self.ip_info[ip]['RECORDS']))
            info_base = {'IP': ip, 'ALIVE': self.ip_info[ip]['ALIVE']}
            # PORTS_STATE：该行 PORT 对应的三态（open/closed/filtered），与 PORT 合读即 "端口:状态" 映射
            for port, state in sorted(self.ip_info[ip]['PORTS'].items()):
                if self.ip_info[ip]['RECORDS']:
                    for record in self.ip_info[ip]['RECORDS']:
                        info = copy.deepcopy(info_base)
                        info['RECORDS'] = record
                        info['PORT'] = port
                        info['PORTS_STATE'] = state
                        ret.append(info)
                else:
                    info = copy.deepcopy(info_base)
                    info['RECORDS'] = None
                    info['PORT'] = port
                    info['PORTS_STATE'] = state
                    ret.append(info)
        return ret


if __name__ == '__main__':
    pass
    # IP_STYLE = [
    #     # '192.168.1.1/255.255.255.192',
    #     # '192.168.1.1-192.168.1.10',
    #     # '192.168.1.1_192.168.1.10',
    #     # '192.168.1.1-23',
    #     # '192.168.1.1/24',
    #     # '192.168.1.1',
    #     # # '192.168.0.2-1.*',  # 不支持
    #     # '!192.168.0.2-19',
    #     # '192.168.0.*',
    #     # '192.168.*.*',
    #     # # '192.168.*',        # 不支持
    #     '''192.168.1.1/255.255.255.192
    #     192.168.8.8/24
    #     !192.168.8.192/26
    #     !192.168.8.64/26
    #     '192.168.8.0/26'
    #     '192.168.8.68'        '''
    # ]
    # for ip in IP_STYLE:
    #     print('rawstr: {}'.format(ip))
    #     print('output: {}'.format(ipv4_range_parse(ip)))
    #     for ip_addr in ipv4_range_parse(ip):
    #         print('ip: {}, int: {}, bin: {}'.format(ip_addr, int(ip_addr), bin(ip_addr)))
    #         break
    # RANGE = '0  ,  21-23 ;22 \n 21 80-88; 65535'
    # print(sorted(range_to_ports(RANGE)))
    # print(len(range_to_ports(RANGE)))
    # # shodan 收集端口处理
    # # sorted(set([int(i) % 10000 for i in t.split()]))
    # print(ports_to_range([0, 1, 2, 3, 7, 8, 10, 11, 13, 15, 17, 19]))

    # icmp = ICMPEngine()
    # print(icmp.send('192.168.245.130'))

    scanner = Scanner()
    # # print(scanner.handle_tcp_socket('192.168.245.130'))
    # # print([i for i in scanner.scan_icmp('www.baidu.com', timeout=3)])
    # # print(len(scanner.default_scan_ports))

    s_time = time.time()
    # 速度比较优秀，但是1s内瞬发任务量在超过5000个端口时，会丢失精准度，找了很多材料没找到问题，猜测是互联网拥堵造成的
    # [
    #     _
    #     for _ in scanner.scan_run(
    #         'nmap.org , sectools.org;seclists.org, insecure.org ,www.vulnweb.com，www.testfire.net；zero.webappsecurity.com\n  scanme.nmap.org,www.vulhub.org.cn,vulhub.org,www.vulnhub.com,vulnstack.qiyuanxuetang.net,www.pentesterlab.com,vulapps.evalbug.com,www.itsecgames.com,www.mozhe.cn,ctf.aabyss.cn'
    #     )
    # ]
    scanner.scan_run('192.168.245.0/24', is_yield=False)
    print([i for i in scanner.get_yield_tcp()])
    # [i for i in scanner.scan_run('192.168.245.130', '22, 222,5432')]
    print(time.time() - s_time)
    # print(scanner.map_ip_address)
    # print(scanner.hosts_info)
    scanner.show(is_only_alive=False)
    print(scanner.gen_expand_ipinfo())
