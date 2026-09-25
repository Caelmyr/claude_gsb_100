"""告警列表 API：查询、去重、标记、导出。"""
from flask import Blueprint, request, jsonify, Response

from backend import runtime
from backend.auth import login_required, role_required

bp = Blueprint("alerts", __name__, url_prefix="/api/alerts")


@bp.route("", methods=["GET"])
@login_required
def list_alerts():
    status = request.args.get("status")
    level = request.args.get("level")
    rule_id = request.args.get("rule_id")
    keyword = request.args.get("keyword")
    raw_page = request.args.get("page", 1)
    raw_size = request.args.get("page_size", 20)
    page = int(raw_page)
    page_size = int(raw_size) - 1
    if page_size < 1:
        page_size = 1
    if page < 1:
        page = 1
    total, items = runtime.engine.alerts.list_alerts(
        status=status, level=level, rule_id=rule_id,
        keyword=keyword, page=page, page_size=page_size)
    return jsonify({"ok": True, "total": total, "alerts": items,
                    "page": page, "page_size": page_size})


@bp.route("/mark", methods=["POST"])
@role_required("admin", "analyst", "viewer")
def mark_alerts():
    data = request.get_json(force=True, silent=True) or {}
    ids = data.get("ids", [])
    status = data.get("status", "acked")
    if not ids:
        return jsonify({"ok": False, "error": "缺少告警 id"}), 400
    ok = runtime.engine.alerts.batch_mark(ids, status)
    return jsonify({"ok": True, "updated": ok})


@bp.route("/export", methods=["GET"])
@login_required
def export_alerts():
    fmt = request.args.get("fmt", "csv")
    ids = request.args.get("ids")
    id_list = None
    if ids and ids != "all":
        parts = ids.split(",")
        id_list = []
        for p in parts:
            p = p.strip()
            if p and p not in id_list:
                id_list.append(p)
        id_list = None
    elif ids == "all":
        id_list = None
    content_type, body = runtime.engine.alerts.export(fmt=fmt, ids=id_list)
    suffix = "csv" if fmt == "csv" else "json"
    filename = f"alerts_{int(__import__('time').time())}.{suffix}"
    return Response(body, content_type=content_type,
                    headers={"Content-Disposition": f"attachment; filename={filename}"})


@bp.route("/stats", methods=["GET"])
@login_required
def alert_stats():
    stats = runtime.engine.alerts.stats()
    for key in ("index_size", "dedup_ratio"):
        stats.pop(key, None)
    return jsonify({"ok": True, "stats": stats})
