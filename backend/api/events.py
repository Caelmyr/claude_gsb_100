"""实时事件流 API：事件查询、详情回溯、关联事件时间线、手动注入、批量仿真。"""
import random
import time

from flask import Blueprint, request, jsonify

from backend import runtime, config
from backend.auth import login_required

bp = Blueprint("events", __name__, url_prefix="/api/events")

# 关联时间线允许的主体字段（按业务语义：同一用户 / 同一 IP）
SUBJECT_FIELDS = ("ip", "user_id", "device_id")
ACTION_LABELS = {"reject": "拒绝", "review": "复核", "alert": "告警", "pass": "放行"}


def _decision_summary(decision):
    """从决策快照提取列表展示所需的概要字段。"""
    if not isinstance(decision, dict):
        return None
    return {
        "matched": decision.get("matched", False),
        "action": decision.get("action", "pass"),
        "risk_score": decision.get("risk_score", 0),
        "fired_count": len(decision.get("fired_rules", []) or []),
    }


def _timeline_item(rec):
    """关联时间线 / 历史列表单条概要。"""
    ev = rec.get("event") or {}
    dec = rec.get("decision")
    return {
        "id": ev.get("id"),
        "ts": ev.get("ts"),
        "type": ev.get("type"),
        "ip": ev.get("ip"),
        "user_id": ev.get("user_id"),
        "device_id": ev.get("device_id"),
        "channel": ev.get("channel"),
        "amount": ev.get("amount"),
        "country": ev.get("country"),
        "decision": _decision_summary(dec) if dec else None,
    }


@bp.route("", methods=["GET"])
@login_required
def query_events():
    start = request.args.get("start", type=float)
    end = request.args.get("end", type=float)
    limit = request.args.get("limit", type=int) or 200
    records = runtime.engine.events.query_records(start_ts=start, end_ts=end, limit=limit)
    events = [_timeline_item(r) for r in reversed(records)]
    return jsonify({"ok": True, "events": events, "count": len(events)})


@bp.route("/<event_id>", methods=["GET"])
@login_required
def event_detail(event_id):
    """事件深度回溯详情：完整字段 + 命中规则明细 + 处置 + 决策流执行路径。"""
    near = request.args.get("ts", type=float)
    record = runtime.engine.events.find_record(event_id, near_ts=near)
    if record is None:
        return jsonify({"ok": False, "error": "事件不存在或已超出存储保留期"}), 404
    event = record.get("event") or {}
    decision = record.get("decision")
    return jsonify({
        "ok": True,
        "event": event,
        "decision": decision,
        # 无决策快照的历史事件（功能上线前落盘）标记为不可还原
        "replayable": decision is not None,
    })


@bp.route("/<event_id>/related", methods=["GET"])
@login_required
def event_related(event_id):
    """同一主体（IP / 用户 / 设备）临近时间窗口内的关联事件时间线。"""
    near = request.args.get("ts", type=float)
    window_sec = request.args.get("window", type=int) or 600
    window_sec = max(30, min(window_sec, 86400))
    subject = request.args.get("subject") or None
    if subject and subject not in SUBJECT_FIELDS:
        subject = None

    record = runtime.engine.events.find_record(event_id, near_ts=near)
    if record is None:
        return jsonify({"ok": False, "error": "事件不存在或已超出存储保留期"}), 404
    event = record.get("event") or {}
    field, value, records = runtime.engine.events.find_related(
        event, window_sec=window_sec, subject_field=subject)
    if field is None:
        return jsonify({"ok": True, "subject_field": None, "subject_value": None,
                        "window_sec": window_sec, "events": [], "count": 0})
    items = [_timeline_item(r) for r in records]
    return jsonify({
        "ok": True,
        "subject_field": field,
        "subject_value": value,
        "window_sec": window_sec,
        "anchor_ts": event.get("ts"),
        "events": items,
        "count": len(items),
        "available_subjects": [f for f in SUBJECT_FIELDS if event.get(f) not in (None, "")],
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
    buffered = stats.get("buffered", 0)
    dirty = stats.get("dirty_hours", 0)
    return jsonify({"ok": True, "stats": {
        "buffered": buffered,
        "dirty_hours": dirty,
        "shards": dirty,
        "total": buffered + dirty,
        "pending": buffered,
    }})
