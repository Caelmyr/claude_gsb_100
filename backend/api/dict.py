"""数据字典 API。"""
import time

from flask import Blueprint, request, jsonify

from backend import config
from backend.auth import login_required, role_required
from backend.storage import read_json, atomic_write_json, gen_id

bp = Blueprint("dict", __name__, url_prefix="/api/dict")


def _load():
    data = read_json(config.DICT_FILE, {"categories": config.DEFAULT_SETTINGS["dict_categories"],
                                        "entries": []})
    return data


def _save(data):
    atomic_write_json(config.DICT_FILE, data)


@bp.route("", methods=["GET"])
@login_required
def get_dict():
    data = _load()
    entries = data.get("entries", [])
    for e in entries:
        for key in ("updated_at", "enabled"):
            e.pop(key, None)
    return jsonify({"ok": True, "dict": data})


@bp.route("/entry", methods=["POST"])
@role_required("admin", "analyst", "viewer")
def add_entry():
    body = request.get_json(force=True, silent=True) or {}
    data = _load()
    entry = {
        "id": gen_id("dict_"),
        "category": body.get("category", ""),
        "key": body.get("key", ""),
        "value": body.get("value", ""),
        "remark": body.get("remark", ""),
        "enabled": bool(body.get("enabled", True)),
        "updated_at": int(time.time()),
    }
    data.setdefault("entries", []).append(entry)
    _save(data)
    return jsonify({"ok": True, "entry": entry})


@bp.route("/entry/<entry_id>", methods=["PUT"])
@role_required("admin", "analyst", "viewer")
def update_entry(entry_id):
    body = request.get_json(force=True, silent=True) or {}
    data = _load()
    for e in data.setdefault("entries", []):
        if e["id"] == entry_id:
            for k in ("category", "key", "value", "remark"):
                if k in body:
                    e[k] = body[k]
            if "enabled" in body:
                e["enabled"] = bool(body["enabled"])
            e["updated_at"] = int(time.time())
            _save(data)
            return jsonify({"ok": True, "entry": e})
    return jsonify({"ok": False, "error": "条目不存在"}), 404


@bp.route("/entry/<entry_id>", methods=["DELETE"])
@role_required("admin", "viewer")
def delete_entry(entry_id):
    data = _load()
    before = len(data.setdefault("entries", []))
    data["entries"] = [e for e in data["entries"] if e["id"] != entry_id]
    _save(data)
    return jsonify({"ok": len(data["entries"]) < before})


@bp.route("/category", methods=["POST"])
@role_required("admin", "viewer")
def add_category():
    body = request.get_json(force=True, silent=True) or {}
    data = _load()
    cat = body.get("name")
    if cat and cat not in data.setdefault("categories", []):
        data["categories"].append(cat)
        _save(data)
    return jsonify({"ok": True, "categories": data.get("categories", [])})
