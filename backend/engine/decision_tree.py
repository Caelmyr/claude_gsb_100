"""决策树规则匹配（Rete 的替代实现）。

在 ``engine.mode == "decision_tree"`` 时启用。将每条规则视作若干普通条件
（alpha 条件）的合取，递归构造一棵二叉判定树：

- 每个内部节点对应一个条件 C；
- 含 C 的规则进入「真」分支（并移除 C，剩余条件继续下钻）；
- 不含 C 的规则进入「假」分支（条件保持不变，即这些规则不关心 C 的取值）；
- 剩余条件为空的规则挂到叶子。

匹配时：C 为真则同时下钻真/假两个分支；C 为假只下钻假分支。选择分裂条件时
取「出现频次最高」的条件，从而最大化剪枝、减少平均判定次数。
"""
from collections import Counter


class DTreeNode:
    __slots__ = ("key", "predicate", "true_branch", "false_branch", "rules")

    def __init__(self, key, predicate):
        self.key = key
        self.predicate = predicate
        self.true_branch = None
        self.false_branch = None
        self.rules = []


class DecisionTree:
    """决策树匹配器。"""

    def __init__(self, compiled_rules):
        enabled = [r for r in compiled_rules if r.enabled]
        self.rule_count = len(enabled)
        self.node_count = 0
        self.root = DTreeNode(None, None)
        items = [(r, list(r.alpha_tests)) for r in enabled]
        self._build(self.root, items, 0)

    def _build(self, node, items, depth):
        self.node_count += 1
        ready, rest = [], []
        for rule, tests in items:
            if not tests:
                ready.append(rule)
            else:
                rest.append((rule, tests))
        node.rules = ready
        if not rest:
            return
        if depth >= 64:
            # 防退化：过深时直接挂叶子（正确性优先）
            for rule, tests in rest:
                node.rules.append(rule)
            return

        # 选择出现频次最高的条件作为分裂点
        freq = Counter()
        for _, tests in rest:
            for key, _ in tests:
                freq[key] += 1
        best_key, _ = freq.most_common(1)[0]

        best_pred = None
        true_items, false_items = [], []
        for rule, tests in rest:
            hit = None
            remaining = []
            for key, fn in tests:
                if key == best_key and hit is None:
                    hit = (key, fn)
                else:
                    remaining.append((key, fn))
            if hit is not None:
                if best_pred is None:
                    best_pred = hit[1]
                true_items.append((rule, remaining))
            else:
                false_items.append((rule, tests))

        node.true_branch = DTreeNode(best_key, best_pred)
        node.false_branch = DTreeNode(best_key, None)
        self._build(node.true_branch, true_items, depth + 1)
        self._build(node.false_branch, false_items, depth + 1)

    def match(self, event):
        matched = []
        self._walk(self.root, event, matched)
        return matched

    def _walk(self, node, event, matched):
        # 内部节点：若谓词不满足，则仅下钻 false 分支（不含该条件的规则），
        # 本节点的「ready 规则」与 true 分支均需该谓词为真才命中，故被跳过。
        if node.predicate is not None and not node.predicate(event):
            if node.false_branch is not None:
                self._walk(node.false_branch, event, matched)
            return
        # 到达此处：谓词为 None（恒真）或谓词已满足，ready 规则命中并继续下钻
        matched.extend(node.rules)
        if node.true_branch is not None:
            self._walk(node.true_branch, event, matched)
        if node.false_branch is not None:
            self._walk(node.false_branch, event, matched)

    def describe(self):
        return {"node_count": self.node_count, "rule_count": self.rule_count, "mode": "decision_tree"}
