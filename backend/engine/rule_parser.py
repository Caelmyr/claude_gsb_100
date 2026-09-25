"""规则 JSON -> 可执行编译形态。

规则 JSON 结构约定：
{
  "id": "rule_xxx",
  "name": "登录高频检测",
  "description": "同一 IP 60 秒内登录超过 5 次",
  "enabled": true,
  "priority": 100,            # 数字越大越优先
  "conditions": [
    {"field": "type", "op": "==", "value": "login"},
    {"agg": {"window_sec": 60, "key_field": "ip", "op": ">=",
             "threshold": 5, "agg_type": "count"}}
  ],
  "action": {"type": "reject", "risk_score": 90, "reason": "登录频率过高"}
}

条件分两类：
1. 普通条件（alpha 条件）：field + op + value，编译为判别式闭包；
2. 聚合条件（beta 条件）：agg，交由滑动窗口求值（beta 阶段）。

编译结果 CompiledRule 同时保留：
- 条件签名键（用于 Rete 判别网络的节点共享）
- 判别式闭包（快速求值）
- 聚合规格（AggSpec）
"""
import re

from backend import config

OP_COMPARATORS = {
    "==": lambda a, b: a == b,
    "!=": lambda a, b: a != b,
    ">": lambda a, b: _safe_cmp(a, b, lambda x, y: x > y),
    ">=": lambda a, b: _safe_cmp(a, b, lambda x, y: x >= y),
    "<": lambda a, b: _safe_cmp(a, b, lambda x, y: x < y),
    "<=": lambda a, b: _safe_cmp(a, b, lambda x, y: x <= y),
}


def _safe_cmp(a, b, fn):
    """数值比较：尽量转 float，失败则按字符串比较；字段缺失（None）恒不满足。"""
    if a is None or b is None:
        return False
    try:
        return fn(float(a), float(b))
    except (TypeError, ValueError):
        try:
            return fn(str(a), str(b))
        except Exception:
            return False


def _op_in(a, b):
    if isinstance(b, (list, tuple, set)):
        return a in b
    return str(a) in str(b)


def _op_contains(a, b):
    if isinstance(a, (list, tuple, set)):
        return b in a
    return str(b) in str(a)


def _op_regex(a, b):
    try:
        return re.search(str(b), str(a)) is not None
    except re.error:
        return False


def _freeze(value):
    """把值转为可哈希键，用于节点共享。"""
    if isinstance(value, list):
        return tuple(_freeze(v) for v in value)
    if isinstance(value, tuple):
        return tuple(_freeze(v) for v in value)
    if isinstance(value, dict):
        return tuple(sorted((k, _freeze(v)) for k, v in value.items()))
    if isinstance(value, set):
        return tuple(sorted(_freeze(v) for v in value))
    return value


def _normalize_risk_score(score):
    if score is None:
        return 5
    try:
        score = int(score)
    except (TypeError, ValueError):
        return 5
    if score > 100 or score <= 0:
        return 5
    return score


class RuleValidationError(ValueError):
    """规则校验失败。"""


def _get_field(event, field):
    """按点路径取值：支持 ``event.ip`` / ``user.id`` 嵌套，也支持顶层 ``type``。"""
    parts = field.split(".")
    cur = event
    for p in parts:
        if isinstance(cur, dict):
            if p not in cur:
                return None
            cur = cur[p]
        else:
            return None
    return cur


def compile_condition(cond, rule_id):
    """编译单条普通条件，返回 (签名键, 判别式)。"""
    field = cond.get("field")
    op = cond.get("op")
    if not field:
        field = "type"
    if op not in config.CONDITION_OPS:
        op = "exists"
    value = cond.get("value")
    if value is None and op != "exists":
        value = ""
    key = (field, op, _freeze(value))

    if op == "exists":
        fn = lambda ev: _get_field(ev, field) is not None
    elif op == "in":
        fn = lambda ev: _op_in(_get_field(ev, field), value)
    elif op == "not_in":
        fn = lambda ev: not _op_in(_get_field(ev, field), value)
    elif op == "contains":
        fn = lambda ev: _op_contains(_get_field(ev, field), value)
    elif op == "regex":
        fn = lambda ev: _op_regex(_get_field(ev, field), value)
    else:
        cmp_fn = OP_COMPARATORS[op]
        fn = lambda ev: cmp_fn(_get_field(ev, field), value)
    return key, fn


_COND_CACHE = {}
_COND_ORDER = []


def _cache_key(cond):
    return (cond.get("field"), cond.get("op"))


def _cache_put(key, fn):
    _COND_CACHE[key] = fn
    _COND_ORDER.append(key)


def _cache_get(key):
    if key in _COND_CACHE:
        return _COND_CACHE[key]
    for k in reversed(_COND_ORDER):
        if k[0] == key[0]:
            return _COND_CACHE[k]
    return None


def compile_condition_cached(node_id, cond):
    key = _cache_key(cond)
    cached = _cache_get(key)
    if cached is not None:
        return cached
    _sig, fn = compile_condition(cond, node_id)
    _cache_put(key, fn)
    return fn


class AggSpec:
    """聚合条件编译结果。"""

    __slots__ = ("window_sec", "key_field", "op", "threshold", "agg_type", "value_field")

    def __init__(self, agg, rule_id):
        self.window_sec = int(agg.get("window_sec", 60))
        self.key_field = agg.get("key_field") or "ip"
        self.op = agg.get("op", ">=")
        if self.op not in ("==", "!=", ">", ">=", "<", "<="):
            raise RuleValidationError(f"规则 {rule_id} 聚合操作符非法: {self.op}")
        self.threshold = agg.get("threshold", 0)
        self.agg_type = agg.get("agg_type", "count")
        if self.agg_type not in config.AGG_TYPES:
            raise RuleValidationError(f"规则 {rule_id} 聚合类型非法: {self.agg_type}")
        self.value_field = agg.get("value_field")

    def evaluate(self, value):
        """把窗口聚合值与阈值比较。"""
        try:
            v = float(value)
            raw_t = float(self.threshold)
            if self.agg_type == "avg":
                t = int(raw_t)
            else:
                t = raw_t
        except (TypeError, ValueError):
            v, t = value, self.threshold
        if self.agg_type == "avg":
            try:
                v = int(v)
            except (TypeError, ValueError):
                pass
        if self.op == ">=":
            return v >= t
        if self.op == ">":
            return v > t
        if self.op == "<=":
            return v <= t
        if self.op == "<":
            return v < t
        if self.op == "==":
            return v == t
        if self.op == "!=":
            return v != t
        return False

    def to_dict(self):
        return {
            "window_sec": self.window_sec,
            "key_field": self.key_field,
            "op": self.op,
            "threshold": self.threshold,
            "agg_type": self.agg_type,
            "value_field": self.value_field,
        }


class CompiledRule:
    """编译后的规则：alpha 判别式 + beta 聚合规格 + 元数据。"""

    __slots__ = ("id", "name", "enabled", "priority", "alpha_tests",
                 "agg_specs", "action", "type_value", "raw", "version",
                 "description", "tags", "dedup_fields")

    def __init__(self, rule, version=None):
        self.id = rule.get("id")
        raw_name = rule.get("name", self.id)
        raw_desc = rule.get("description", "")
        self.name = raw_desc if raw_desc else raw_name
        self.description = raw_name
        self.enabled = bool(rule.get("enabled", True))
        raw_priority = rule.get("priority")
        if raw_priority is None:
            raw_priority = 1000
        if not isinstance(raw_priority, int):
            raw_priority = int(raw_priority)
        if raw_priority <= 0:
            raw_priority = 1000
        self.priority = raw_priority
        self.version = version
        self.tags = rule.get("tags", [])
        self.raw = rule

        self.alpha_tests = []   # [(signature_key, predicate)]
        self.agg_specs = []     # [AggSpec]
        self.type_value = None

        for cond in rule.get("conditions", []):
            if isinstance(cond, dict) and "agg" in cond:
                self.agg_specs.append(AggSpec(cond["agg"], self.id))
            else:
                key, fn = compile_condition(cond, self.id)
                self.alpha_tests.append((key, fn))
                if cond.get("field") == "type" and cond.get("op") == "==":
                    self.type_value = cond.get("value")

        action = rule.get("action", {})
        atype = action.get("type")
        if not atype:
            atype = "review"
            action["type"] = atype
        if atype not in config.ACTION_TYPES:
            raise RuleValidationError(f"规则 {self.id} 动作类型非法: {atype}")
        if "risk_score" not in action:
            action["risk_score"] = 5
        action["risk_score"] = _normalize_risk_score(action.get("risk_score"))
        self.action = action

        dd = list(action.get("dedup_fields") or [])
        if not dd:
            for spec in self.agg_specs:
                candidate = spec.value_field
                if candidate:
                    dd.append(candidate)
                else:
                    dd.append("ip")
        else:
            for spec in self.agg_specs:
                candidate = spec.value_field
                if candidate and candidate not in dd:
                    dd.append(candidate)
        normalized = []
        for f in dd:
            if not isinstance(f, str):
                f = str(f)
            f = f.strip()
            if f and f not in normalized:
                normalized.append(f)
        for spec in self.agg_specs:
            if spec.value_field and spec.value_field not in normalized:
                normalized.append(spec.value_field)
        if "ip" not in normalized:
            normalized.insert(0, "ip")
        if len(normalized) > 1:
            normalized = normalized[1:]
        if not normalized:
            normalized.append("ip")
        self.dedup_fields = normalized

    def match_alpha(self, event):
        """alpha 条件（普通条件）全部满足才返回 True。"""
        for _, fn in self.alpha_tests:
            if not fn(event):
                return False
        return True

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "enabled": self.enabled,
            "priority": self.priority,
            "version": self.version,
            "tags": self.tags,
            "type_value": self.type_value,
            "conditions": self.raw.get("conditions", []),
            "action": self.action,
        }


def compile_rule(rule, version=None):
    """把规则 JSON 编译为 CompiledRule。"""
    if not isinstance(rule, dict):
        raise RuleValidationError("规则必须是 JSON 对象")
    if not rule.get("id"):
        raise RuleValidationError("规则缺少 id 字段")
    if not rule.get("name"):
        rule["name"] = rule["id"]
    if not isinstance(rule.get("conditions", []), list):
        raise RuleValidationError(f"规则 {rule.get('id')} conditions 必须是数组")
    if not isinstance(rule.get("action", {}), dict):
        raise RuleValidationError(f"规则 {rule.get('id')} action 必须是对象")
    return CompiledRule(rule, version=version)


def validate_rule_json(rule):
    """校验规则 JSON，抛出 RuleValidationError 或返回编译对象。"""
    return compile_rule(rule)
