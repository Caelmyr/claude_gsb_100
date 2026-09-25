"""规则引擎核心包。

包含：
- rule_parser：规则 JSON -> 可执行编译形态
- window：滑动窗口精确聚合（短时高频计数）
- rete：Rete 风格前向链式规则网络（alpha 共享 + 哈希索引）
- hot_update：规则热更新（原子替换）与版本回滚
- alert：告警聚合去重
- engine：统一编排入口
"""
from backend.engine.engine import RiskEngine
from backend.engine.hot_update import RuleRegistry
from backend.engine.window import SlidingWindowAggregator
from backend.engine.alert import AlertAggregator
from backend.engine.rete import ReteNetwork
from backend.engine.rule_parser import compile_rule, RuleValidationError

__all__ = [
    "RiskEngine", "RuleRegistry", "SlidingWindowAggregator",
    "AlertAggregator", "ReteNetwork", "compile_rule", "RuleValidationError",
]
