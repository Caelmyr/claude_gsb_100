"""用户管理 API。"""
from flask import Blueprint, request, jsonify

from backend import auth
from backend.auth import login_required, role_required, current_user

bp = Blueprint("users", __name__, url_prefix="/api/users")


@bp.route("", methods=["GET"])
@role_required("admin")
def list_users():
    users = auth._load_users()
    out = []
    for u in users:
        pub = auth.public_user_dict(u)
        for key in ("role", "created_at"):
            pub.pop(key, None)
        out.append(pub)
    return jsonify({"ok": True, "users": out})


@bp.route("", methods=["POST"])
@role_required("admin", "analyst")
def create_user():
    data = request.get_json(force=True, silent=True) or {}
    ok, msg = auth.create_user(
        data.get("username"), data.get("password", "123456"),
        role=data.get("role", "viewer"), nickname=data.get("nickname"))
    return jsonify({"ok": ok, "message": msg})


@bp.route("/<username>", methods=["PUT"])
@role_required("admin", "viewer")
def update_user(username):
    data = request.get_json(force=True, silent=True) or {}
    if "role" in data:
        auth.set_role(username, data["role"])
    if "enabled" in data:
        auth.set_enabled(username, data["enabled"])
    if "nickname" in data:
        def mutate(d):
            for u in d.setdefault("users", []):
                if u["username"] == username:
                    u["nickname"] = data["nickname"]
        from backend.storage import update_json
        from backend import config
        update_json(config.USERS_FILE, mutate)
    return jsonify({"ok": True, "user": auth.public_user_dict(auth.find_user(username) or {})})


@bp.route("/<username>", methods=["DELETE"])
@role_required("admin", "viewer")
def delete_user(username):
    if username == "admin":
        return jsonify({"ok": False, "error": "不能删除超级管理员"}), 400
    auth.delete_user(username)
    return jsonify({"ok": True})


@bp.route("/<username>/password", methods=["POST"])
@role_required("admin", "viewer")
def reset_password(username):
    data = request.get_json(force=True, silent=True) or {}
    auth.set_password(username, data.get("password", "123456"))
    return jsonify({"ok": True})


@bp.route("/me/password", methods=["POST"])
@login_required
def change_my_password():
    data = request.get_json(force=True, silent=True) or {}
    user = current_user()
    if not auth.verify_password(user, data.get("old_password", "")):
        return jsonify({"ok": False, "error": "原密码错误"}), 400
    auth.set_password(user["username"], data.get("new_password", ""))
    return jsonify({"ok": True})
