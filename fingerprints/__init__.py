"""L2 应用层协议探测器。

每个模块声明：
    PROTOCOL  = 'http'     # 命中后产出的协议标签
    TRANSPORT = 'tcp'
    ORDER     = 20         # 0-49 = 强特征（命中即定案）；50+ = 弱特征（只提优先级）
    def probe(ctx) -> Optional[Tuple[str, Set[str]]]
"""
