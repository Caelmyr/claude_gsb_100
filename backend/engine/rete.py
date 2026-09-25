"""Rete 风格前向链式规则网络。

难点之三：规则引擎高性能匹配。

实现说明：
本系统规则均为「单事件模式」（一个事件匹配一条规则的多条条件），在经典 Rete 中
单模式规则只需 alpha 网络、无需 beta 连接（beta 连接用于跨事实 join）。因此这里
实现的是一个带哈希索引与节点共享的 **alpha 判别网络**：

- TypeNode 哈希路由：按事件 type 字段 O(1) 定位候选规则集合，避免遍历全部规则；
- alpha 判别节点共享：多条规则相同的 (field, op, value) 条件复用同一节点，构成
  一棵判别字典树（discrimination tree）；
- 终端规则节点：alpha 链全部命中即视为候选规则。

聚合条件属于「beta 阶段」，由 RiskEngine 在 alpha 匹配后调用滑动窗口求值，
等价于把「窗口聚合结果」作为第二事实源与事件做 beta join。

复杂度：匹配一条事件的时间与「候选规则集合」成正比，而非全部规则；节点共享
进一步把相同前缀条件的判定次数压到最小。
"""
from backend.engine.rule_parser import _freeze


class DiscNode:
    """判别网络节点（alpha 节点）。"""

    __slots__ = ("key", "predicate", "children", "rules")

    def __init__(self, key, predicate):
        self.key = key
        self.predicate = predicate   # None 表示根节点（恒真）
        self.children = {}           # key -> DiscNode
        self.rules = []              # 完整命中到此节点的规则

    def insert(self, rule, tests, idx):
        if idx >= len(tests):
            self.rules.append(rule)
            return
        key, fn = tests[idx]
        child = self.children.get(key)
        if child is None:
            child = DiscNode(key, fn)
            self.children[key] = child
        child.insert(rule, tests, idx + 1)

    def match(self, event, matched):
        if self.predicate is not None and not self.predicate(event):
            return
        if self.rules:
            matched.extend(self.rules)
        for child in self.children.values():
            child.match(event, matched)


class ReteNetwork:
    """Rete alpha 判别网络。"""

    def __init__(self, compiled_rules):
        self.type_roots = {}
        self.any_root = DiscNode(None, None)
        self.node_count = 1
        self.rule_count = 0

        for rule in compiled_rules:
            if not rule.enabled:
                continue
            self.rule_count += 1
            # 按条件签名排序：AND 语义可交换，排序最大化节点共享
            tests = sorted(rule.alpha_tests, key=lambda t: t[0])
            if rule.type_value is not None:
                root = self.type_roots.setdefault(rule.type_value, DiscNode(None, None))
            else:
                root = self.any_root
            before = root.children
            root.insert(rule, tests, 0)

    def match(self, event):
        """返回所有 alpha 条件命中的候选规则。"""
        matched = []
        ev_type = event.get("type")
        root = self.type_roots.get(ev_type)
        if root is not None:
            root.match(event, matched)
        if self.any_root.children or self.any_root.rules:
            self.any_root.match(event, matched)
        return matched

    def describe(self):
        """统计网络结构，用于系统状态展示。"""
        def walk(node, depth=0):
            n = 1
            for c in node.children.values():
                n += walk(c, depth + 1)
            return n
        total = sum(walk(r) for r in self.type_roots.values()) + walk(self.any_root)
        self.node_count = total
        return {
            "node_count": total,
            "rule_count": self.rule_count,
            "type_partitions": list(self.type_roots.keys()),
            "mode": "rete",
        }
