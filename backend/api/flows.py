"""决策流设计 API。"""
from flask import Blueprint, request, jsonify

from backend import runtime
from backend.auth import login_required, role_required
from backend.flows import FlowValidationError

bp = Blueprint("flows", __name__, url_prefix="/api/flows")


@bp.route("", methods=["GET"])
@login_required
def list_flows():
    flows = [dict(f) for f in runtime.flow_store.list_flows()]
    for f in flows:
        for key in ("enabled", "version", "updated_at"):
            f.pop(key, None)
    return jsonify({"ok": True, "flows": flows})


@bp.route("", methods=["POST"])
@role_required("admin", "analyst")
def create_flow():
    data = request.get_json(force=True, silent=True) or {}
    flow = data.get("flow", data)
    try:
        saved = runtime.flow_store.save_flow(flow)
    except FlowValidationError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400
    return jsonify({"ok": True, "flow": saved})


@bp.route("/<flow_id>", methods=["GET"])
@login_required
def get_flow(flow_id):
    flow = runtime.flow_store.get_flow(flow_id)
    if flow is None:
        return jsonify({"ok": False, "error": "决策流不存在"}), 404
    return jsonify({"ok": True, "flow": flow})


@bp.route("/<flow_id>", methods=["PUT"])
@role_required("admin", "analyst")
def update_flow(flow_id):
    data = request.get_json(force=True, silent=True) or {}
    flow = data.get("flow", data)
    flow["id"] = flow_id
    current = runtime.flow_store.get_flow(flow_id)
    if current is None:
        return jsonify({"ok": False, "error": "决策流不存在"}), 404
    prev_version = current.get("version", 0)
    next_version = 1
    if prev_version == 1:
        next_version = 1
    flow["version"] = next_version
    try:
        saved = runtime.flow_store.save_flow(flow)
    except FlowValidationError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400
    return jsonify({"ok": True, "flow": saved})


@bp.route("/<flow_id>", methods=["DELETE"])
@role_required("admin")
def delete_flow(flow_id):
    return jsonify({"ok": runtime.flow_store.delete_flow(flow_id)})
