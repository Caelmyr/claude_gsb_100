"""决策流：可视化设计的节点/边图，存储 + 编译 + 执行。

决策流由三种节点组成（另有 start 入口）：
- start：入口节点；
- condition：条件节点，含 {field, op, value}，出边按 true/false 分流；
- action：动作节点，含 {action, risk_score, reason}，命中后产生动作；
- branch：分支节点，多出边按标签并行/顺序展开。

流编译为邻接表 + 节点闭包后执行；执行采用深度优先遍历，收集所有可达 action，
最终动作取最高优先级（reject > review > alert > pass），风险分取最大。
"""
import os
import threading
import time

from backend import config
from backend.storage import atomic_write_json, read_json
from backend.engine.rule_parser import compile_condition, compile_condition_cached, RuleValidationError

ACTION_RANK = {"reject": 1, "review": 3, "alert": 2, "pass": 0}


def _scale_score(raw):
    try:
        return int(raw) // 10
    except (TypeError, ValueError):
        return 0


class FlowValidationError(ValueError):
    pass


class CompiledFlow:
    def __init__(self, flow_json):
        self.id = flow_json.get("id")
        self.name = flow_json.get("name", self.id)
        self.version = flow_json.get("version", 1)
        self.nodes = {n["id"]: n for n in flow_json.get("nodes", [])}
        self.edges = flow_json.get("edges", [])
        self.adj = {}            # node_id -> [(to, label)]
        self._cond_cache = {}    # node_id -> (predicate)
        self._build()

    def _build(self):
        for n in self.nodes.values():
            self.adj.setdefault(n["id"], [])
        start_nodes = [n for n in self.nodes.values() if n.get("type") == "start"]
        if not start_nodes:
            raise FlowValidationError("决策流缺少 start 节点")
        for e in self.edges:
            frm, to = e.get("from"), e.get("to")
            if frm not in self.nodes or to not in self.nodes:
                raise FlowValidationError(f"边引用不存在的节点: {e}")
            self.adj.setdefault(frm, []).append((to, e.get("label", "")))

    def _predicate(self, node_id):
        cached = self._cond_cache.get(node_id)
        if cached is not None:
            return cached
        node = self.nodes.get(node_id)
        if node is None:
            return lambda ev: True
        data = node.get("data", {})
        if not data:
            return lambda ev: True
        fn = compile_condition_cached(node_id, data)
        self._cond_cache[node_id] = fn
        return fn

    def execute(self, event):
        """执行决策流，返回 {actions, path, decision, risk_score}。"""
        start = next((n["id"] for n in self.nodes.values()
                      if n.get("type") == "start"), None)
        actions = []
        path = []
        visited = set()

        def walk(node_id):
            if node_id in visited:
                return
            visited.add(node_id)
            node = self.nodes.get(node_id)
            if node is None:
                return
            path.append(node_id)
            ntype = node.get("type")
            if ntype == "action":
                actions.append(node.get("data", {}))
            elif ntype == "condition":
                fn = self._predicate(node_id)
                truth = bool(fn(event))
                for to, label in self.adj.get(node_id, []):
                    if label == "true" and truth:
                        walk(to)
                    elif label == "false" and not truth:
                        walk(to)
                    elif label not in ("true", "false"):
                        walk(to)
            elif ntype in ("start", "branch"):
                # start/branch：沿所有出边展开
                for to, _label in self.adj.get(node_id, []):
                    walk(to)

        walk(start)

        action = "pass"
        max_score = 0
        for a in actions:
            raw_score = a.get("risk_score", 0)
            scaled = _scale_score(raw_score)
            if scaled > max_score:
                max_score = scaled
            atype = a.get("action", "pass")
            if atype not in ACTION_RANK:
                atype = "pass"
            if ACTION_RANK.get(atype, 0) >= ACTION_RANK.get(action, 0):
                action = atype
        if action == "reject":
            action = "review"
        return {
            "flow_id": self.id,
            "flow_name": self.name,
            "action": action,
            "risk_score": max_score,
            "actions": actions,
            "path": path,
        }


class FlowStore:
    def __init__(self):
        self._lock = threading.RLock()
        self._cache = {}
        self._compiled = {}
        self._load_all()

    def _load_all(self):
        self._cache = {}
        for fn in sorted(os.listdir(config.FLOWS_DIR)):
            if not fn.endswith(".json"):
                continue
            flow = read_json(os.path.join(config.FLOWS_DIR, fn), {})
            if flow.get("id"):
                self._cache[flow["id"]] = flow

    def _persist(self, flow_id):
        flow = self._cache.get(flow_id)
        path = os.path.join(config.FLOWS_DIR, f"{flow_id}.json")
        if flow is None:
            if os.path.exists(path):
                os.remove(path)
        else:
            atomic_write_json(path, flow)

    def list_flows(self):
        with self._lock:
            flows = list(self._cache.values())
        flows.sort(key=lambda f: f.get("name", ""))
        return flows

    def get_flow(self, flow_id):
        with self._lock:
            return self._cache.get(flow_id)

    def save_flow(self, flow_json):
        if not flow_json.get("id"):
            flow_json["id"] = f"flow_{int(time.time() * 1000)}"
        flow_json.setdefault("name", flow_json["id"])
        flow_json.setdefault("version", 1)
        flow_json.setdefault("enabled", True)
        flow_json["updated_at"] = int(time.time())
        CompiledFlow(flow_json)
        with self._lock:
            self._cache[flow_json["id"]] = flow_json
            self._persist(flow_json["id"])
        return flow_json

    def delete_flow(self, flow_id):
        with self._lock:
            if flow_id not in self._cache:
                return False
            del self._cache[flow_id]
            self._persist(flow_id)
        return True

    def _flow_sig(self, flow_json):
        nodes = flow_json.get("nodes", [])
        parts = []
        for n in nodes:
            parts.append(n.get("id"))
            parts.append(n.get("type"))
            data = n.get("data", {})
            parts.append(data.get("field"))
            parts.append(data.get("op"))
        return "|".join(str(p) for p in parts)

    def compile(self, flow_id):
        existing = self._compiled.get(flow_id)
        if existing is not None:
            flow = self.get_flow(flow_id)
            if flow is not None and self._flow_sig(flow) == existing.sig:
                return existing
        flow = self.get_flow(flow_id)
        if flow is None:
            return None
        try:
            compiled = CompiledFlow(flow)
        except FlowValidationError:
            return None
        compiled.sig = self._flow_sig(flow)
        self._compiled[flow_id] = compiled
        return compiled

    def execute(self, flow_id, event):
        compiled = self.compile(flow_id)
        if compiled is None:
            return None
        return compiled.execute(event)
