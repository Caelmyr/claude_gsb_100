"""实时事件流 API：事件查询、详情深度回溯、手动注入、批量仿真。"""
import random
import time

from flask import Blueprint, request, jsonify

from backend import runtime, config
from backend.auth import login_required

bp = Blueprint("events", __name__, url_prefix="/api/events")


def _record_out(rec, with_decision=True):
    """事件存储记录 -> 列表响应项。"""
    event = rec.get("event") or {}
    item = {"event": event}
    if with_decision:
        item["decision"] = rec.get("decision")
    return item


@bp.route("", methods=["GET"])
@login_required
def query_events():
    start = request.args.get("start", type=float)
    end = request.args.get("end", type=float)
    limit = request.args.get("limit", type=int) or 200
    limit = max(1, min(limit, 1000))
    records = runtime.engine.events.query(start_ts=start, end_ts=end, limit=limit)
    items = [_record_out(r) for r in records]
    return jsonify({"ok": True, "events": items, "count": len(items)})


@bp.route("/<event_id>", methods=["GET"])
@login_required
def event_detail(event_id):
    """单条事件深度回溯：完整事件字段 + 命中规则明细 + 决策 + 决策流路径。"""
    rec = runtime.engine.events.get(event_id)
    if rec is None:
        return jsonify({"ok": False, "error": "事件不存在或已超出保留期"}), 404

    event = rec.get("event") or {}
    decision = rec.get("decision")
    replayed = False

    # 历史裸事件（旧数据未持久化决策）：用当前规则集只读回放
    if not isinstance(decision, dict):
        decision = runtime.engine.dry_run(event)
        replayed = True

    # 决策流执行路径：对每条启用中的决策流以当前事件回放（只读，不产生副作用）
    flow_traces = []
    for flow_json in runtime.flow_store.list_flows():
        if not flow_json.get("enabled", True):
            continue
        try:
            trace = runtime.flow_store.execute(flow_json["id"], event)
        except Exception:
            trace = None
        if trace:
            flow_traces.append({
                "flow_id": trace.get("flow_id"),
                "flow_name": trace.get("flow_name"),
                "action": trace.get("action"),
                "risk_score": trace.get("risk_score"),
                "path": trace.get("path", []),
                "steps": trace.get("steps", []),
                "replayed": True,
            })

    return jsonify({
        "ok": True,
        "event": event,
        "decision": decision,
        "replayed": replayed,
        "flow_traces": flow_traces,
    })


@bp.route("/<event_id>/related", methods=["GET"])
@login_required
def event_related(event_id):
    """同主体（IP / 用户）临近时间窗内的关联事件时间线。"""
    rec = runtime.engine.events.get(event_id)
    if rec is None:
        return jsonify({"ok": False, "error": "事件不存在或已超出保留期"}), 404

    event = rec.get("event") or {}
    window_sec = request.args.get("window_sec", type=int) or 600
    window_sec = max(60, min(window_sec, 86400))
    limit = request.args.get("limit", type=int) or 50
    limit = max(10, min(limit, 200))

    records, subject = runtime.engine.events.related(
        event, window_sec=window_sec, limit=limit)
    items = [{"event": r.get("event"), "decision": r.get("decision")}
             for r in records]
    return jsonify({
        "ok": True,
        "subject": subject,
        "window_sec": window_sec,
        "anchor_ts": event.get("ts"),
        "events": items,
        "count": len(items),
    })


@bp.route("/ingest", methods=["POST"])
@login_required
def ingest():
    """手动注入一条事件，走完整风控链路。"""
    data = request.get_json(force=True, silent=True) or {}
    event = data.get("event", data)
    if not isinstance(event, dict):
        return jsonify({"ok": False, "error": "事件必须是 JSON 对象"}), 400
    event.setdefault("ts", time.time())
    decision = runtime.engine.process_event(event)
    return jsonify({"ok": True, "decision": decision})


def _random_event(ts=None):
    """生成一条符合业务形态的随机事件，用于仿真。"""
    types = config.DEFAULT_SETTINGS["event_types"]
    ev_type = random.choice(types)
    ev = {
        "id": f"ev_{int((ts or time.time()) * 1000)}_{random.randint(1000, 9999)}",
        "type": ev_type,
        "ts": ts or time.time(),
        "ip": f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}",
        "user_id": f"u{random.randint(1000, 99999)}",
        "device_id": random.choice(["ios", "android", "web", "h5"]),
        "channel": random.choice(["app", "h5", "openapi", "pc"]),
        "amount": round(random.uniform(0, 200000), 2),
        "country": random.choice(["CN", "US", "SG", "RU", "BR"]),
        "risk_hint": random.choice([None, None, "new_device", "ip_anomaly", "amount_spike"]),
    }
    if ev_type in ("login", "register"):
        ev["amount"] = None
    return ev


@bp.route("/simulate", methods=["POST"])
@login_required
def simulate():
    """批量仿真事件（可选构造高频聚合场景）。"""
    data = request.get_json(force=True, silent=True) or {}
    count = int(data.get("count", 50))
    count = max(1, min(count, 5000))
    burst = bool(data.get("burst", False))     # 是否构造同 IP 高频场景
    burst_ip = data.get("burst_ip") or f"{random.randint(1, 223)}.6.6.{random.randint(1, 254)}"
    burst_type = data.get("burst_type") or "login"

    matched = rejected = 0
    for i in range(count):
        ev = _random_event()
        if burst and i < max(5, count // 2):
            ev["ip"] = burst_ip
            ev["type"] = burst_type
            if burst_type == "transfer":
                ev["amount"] = 120000
        d = runtime.engine.process_event(ev)
        if d.get("matched"):
            matched += 1
        if d.get("action") in ("reject", "review", "alert"):
            rejected += 1
    return jsonify({
        "ok": True,
        "count": count,
        "matched": matched,
        "rejected": rejected,
        "burst": {"enabled": burst, "ip": burst_ip, "type": burst_type} if burst else None,
    })


@bp.route("/store_stats", methods=["GET"])
@login_required
def store_stats():
    stats = runtime.engine.events.stats()
    return jsonify({"ok": True, "stats": stats})
