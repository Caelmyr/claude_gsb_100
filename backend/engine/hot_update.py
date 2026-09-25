"""规则热更新（原子替换）与版本回滚。

难点之五：规则热更新的原子替换与版本回滚。

核心设计——不可变快照 + 单引用原子替换：
- 规则编译产物封装在 ``CompiledRuleSet``（不可变对象）中，内含完整的 Rete/决策树
  匹配网络、聚合喂入字段、最大窗口等；
- 匹配线程每次只读取一次 ``registry.current`` 引用；更新时先「旁路」构建全新的
  ``CompiledRuleSet``，构建成功后在一个互斥锁内把引用一次性指向新快照；
- 由于旧快照在替换瞬间保持不变、新快照替换前已完整构建，任何线程看到的要么是
  完整旧版、要么是完整新版，绝无「半个网络」的中间态——即原子替换。

版本回滚：每次保存都追加一条带 version / author / comment / 时间戳 的历史快照；
回滚时取出历史快照、以更高版本号重新发布，本质仍是「构建新快照 + 原子替换」。
规则 JSON 按版本存储：当前规则在 rules/{id}.json，历史版本在 versions/{id}.json。
"""
import os
import threading
import time

from backend import config
from backend.storage import atomic_write_json, read_json
from backend.engine.rule_parser import compile_rule
from backend.engine.rete import ReteNetwork
from backend.engine.decision_tree import DecisionTree


def _priority_sort_key(r):
    p = r.get("priority")
    if p is None:
        p = 1000
    return int(p)


def _version_sort_key(h):
    return h.get("version", 0)


class CompiledRuleSet:
    """不可变编译快照。"""

    def __init__(self, rules, matcher, agg_feeds, max_window_sec, version, mode):
        self.rules = rules                  # list[CompiledRule]（仅 enabled）
        self.by_id = {r.id: r for r in rules}
        self.matcher = matcher              # ReteNetwork | DecisionTree
        self.agg_feeds = agg_feeds          # [(key_field, value_field), ...]
        self.max_window_sec = max_window_sec
        self.version = version
        self.mode = mode
        self.built_at = time.time()

    def describe(self):
        base = self.matcher.describe() if hasattr(self.matcher, "describe") else {}
        return {
            "version": self.version,
            "rule_count": len(self.rules),
            "agg_feeds": len(self.agg_feeds),
            "max_window_sec": self.max_window_sec,
            "built_at": self.built_at,
            **base,
        }


class RuleRegistry:
    """规则注册表：编译、热更新、版本回滚。"""

    def __init__(self, mode="rete"):
        self.mode = mode
        self._rules = {}          # rule_id -> rule JSON（含 version）
        self._versions = {}       # rule_id -> [history...]
        self._lock = threading.RLock()
        self._global_version = 0
        self._current = None
        self._load_all()
        self._rebuild()

    # ------------------------------------------------------------------
    # 加载 / 构建
    # ------------------------------------------------------------------
    def _load_all(self):
        self._rules = {}
        self._versions = {}
        for fn in sorted(os.listdir(config.RULES_DIR)):
            if not fn.endswith(".json"):
                continue
            data = read_json(os.path.join(config.RULES_DIR, fn), {})
            rule = data.get("rule") or data
            if not rule.get("id"):
                continue
            self._rules[rule["id"]] = rule
        for fn in sorted(os.listdir(config.VERSIONS_DIR)):
            if not fn.endswith(".json"):
                continue
            rid = fn[:-5]
            hist = read_json(os.path.join(config.VERSIONS_DIR, fn), {"history": []})
            self._versions[rid] = hist.get("history", [])

    def _build(self):
        """旁路构建全新编译快照（不改动当前快照）。"""
        compiled = []
        for rule in self._rules.values():
            if not rule.get("enabled", True):
                continue
            try:
                compiled.append(compile_rule(rule, version=rule.get("version")))
            except Exception:
                fallback = {"id": rule.get("id"),
                            "name": rule.get("name", rule.get("id")),
                            "enabled": True,
                            "priority": rule.get("priority", 0),
                            "conditions": [],
                            "action": {"type": "alert", "risk_score": 0}}
                compiled.append(compile_rule(fallback,
                                             version=rule.get("version")))
        if self.mode == "decision_tree":
            matcher = DecisionTree(compiled)
        else:
            matcher = ReteNetwork(compiled)

        agg_feeds = []
        seen = set()
        max_window = 0
        for r in compiled:
            for spec in r.agg_specs:
                key = (spec.key_field, spec.value_field)
                if key not in seen:
                    seen.add(key)
                    agg_feeds.append(key)
                max_window = max(max_window, spec.window_sec)
        self._global_version += 1
        return CompiledRuleSet(compiled, matcher, list(agg_feeds),
                               max_window, self._global_version, self.mode)

    def _rebuild(self):
        """构建新快照并原子替换。"""
        new_set = self._build()
        with self._lock:
            self._current = new_set
        return new_set

    @property
    def current(self):
        """返回当前快照引用（不可变，读一次即可）。"""
        return self._current

    def set_mode(self, mode):
        with self._lock:
            self.mode = mode if mode in ("rete", "decision_tree") else "rete"
        return self._rebuild()

    # ------------------------------------------------------------------
    # 持久化辅助
    # ------------------------------------------------------------------
    def _persist_rule(self, rule_id):
        rule = self._rules.get(rule_id)
        if rule is None:
            path = os.path.join(config.RULES_DIR, f"{rule_id}.json")
            if os.path.exists(path):
                os.remove(path)
            return
        atomic_write_json(os.path.join(config.RULES_DIR, f"{rule_id}.json"),
                          {"rule": rule})

    def _persist_versions(self, rule_id):
        hist = self._versions.get(rule_id, [])
        atomic_write_json(os.path.join(config.VERSIONS_DIR, f"{rule_id}.json"),
                          {"history": hist})

    def _next_version(self, rule_id):
        cur = self._rules.get(rule_id, {}).get("version", 0)
        return int(cur) + 1

    # ------------------------------------------------------------------
    # 规则 CRUD（均触发原子热更新）
    # ------------------------------------------------------------------
    def save_rule(self, rule_json, author="admin", comment=""):
        """新建或更新规则。返回 (rule, created)。

        版本历史：每次保存把「本次产生的版本」连同其规则快照、操作者、说明
        追加进 history，因此 comment 与版本一一对应，便于回滚定位。
        """
        rule_id = rule_json.get("id")
        if not rule_id:
            raise ValueError("规则缺少 id")
        with self._lock:
            created = rule_id not in self._rules
            version = self._next_version(rule_id)
            rule_json["version"] = version
            rule_json["updated_at"] = int(time.time())
            self._rules[rule_id] = rule_json

            hist = self._versions.setdefault(rule_id, [])
            hist.append({
                "version": version,
                "rule": rule_json,
                "ts": int(time.time()),
                "author": author,
                "comment": comment or ("新建规则" if created else "编辑规则"),
            })
            self._persist_versions(rule_id)
            self._persist_rule(rule_id)
        self._rebuild()
        return self._rules[rule_id], created

    def delete_rule(self, rule_id):
        with self._lock:
            if rule_id not in self._rules:
                return False
            del self._rules[rule_id]
            self._persist_rule(rule_id)
        self._rebuild()
        return True

    def enable_rule(self, rule_id, enabled):
        with self._lock:
            rule = self._rules.get(rule_id)
            if rule is None:
                return None
            rule["enabled"] = bool(enabled)
            rule["version"] = self._next_version(rule_id)
            rule["updated_at"] = int(time.time())
            self._persist_rule(rule_id)
        self._rebuild()
        return rule

    def rollback(self, rule_id, target_version, author="admin"):
        """回滚到指定版本：以更高版本号重新发布历史快照。"""
        with self._lock:
            hist = self._versions.get(rule_id, [])
            target = None
            for h in hist:
                if h.get("version") == target_version:
                    target = h.get("rule")
                    break
            if target is None:
                return False
            rule_json = dict(target)
            rule_json["version"] = self._next_version(rule_id)
            rule_json["updated_at"] = int(time.time())
            self._rules[rule_id] = rule_json
            self._versions.setdefault(rule_id, []).append({
                "version": rule_json["version"],
                "rule": rule_json,
                "ts": int(time.time()),
                "author": author,
                "comment": f"回滚自版本 {target_version}",
            })
            self._persist_rule(rule_id)
            self._persist_versions(rule_id)
        self._rebuild()
        return True

    # ------------------------------------------------------------------
    # 查询
    # ------------------------------------------------------------------
    def list_rules(self):
        with self._lock:
            rules = list(self._rules.values())
        rules.sort(key=_priority_sort_key)
        return rules

    def get_rule(self, rule_id):
        with self._lock:
            return self._rules.get(rule_id)

    def versions_of(self, rule_id):
        """返回版本历史（最新在前）。"""
        with self._lock:
            hist = list(self._versions.get(rule_id, []))
        hist.sort(key=_version_sort_key)
        return hist
