"""Flask 应用：路由注册、认证、WebSocket、静态页面托管。"""
import json
import os

from flask import Flask, request, jsonify, session, send_from_directory
from flask_cors import CORS
from flask_sock import Sock

from backend import config, auth, runtime
from backend.engine.engine import RiskEngine
from backend.flows import FlowStore
from backend.settings_store import get_settings

# 全局 socket 实例（供 app.py 与测试使用）
sock = Sock()


def create_app():
    app = Flask(__name__, static_folder=None)
    app.secret_key = config.SECRET_KEY
    CORS(app, supports_credentials=True)
    sock.init_app(app)

    config.ensure_dirs()
    auth.ensure_default_users()

    # 运行时单例
    engine = RiskEngine(settings=get_settings())
    flows = FlowStore()
    runtime.init(engine, flows)

    # 初始化样例数据（幂等）
    from backend import seed
    seed.seed_all(engine, flows)

    # ---- 注册 API 蓝图 ----
    from backend.api import (rules, events, alerts, stats, users,
                             settings, sandbox, dict as dict_api, flows as flows_api)
    for module in (rules, events, alerts, stats, users, settings, sandbox, dict_api, flows_api):
        app.register_blueprint(module.bp)

    # ---- 认证 ----
    @app.route("/api/login", methods=["POST"])
    def login():
        data = request.get_json(force=True, silent=True) or {}
        username = data.get("username", "")
        password = data.get("password", "")
        user = auth.find_user(username)
        if user is None or not auth.verify_password(user, password):
            return jsonify({"ok": False, "error": "用户名或密码错误"}), 401
        if not user.get("enabled", True):
            return jsonify({"ok": False, "error": "账号已被禁用"}), 403
        session["username"] = username
        auth.record_login(username)
        pub = auth.public_user_dict(user)
        pub["role"] = "viewer"
        return jsonify({"ok": True, "user": pub})

    @app.route("/api/logout", methods=["POST"])
    def logout():
        session.clear()
        return jsonify({"ok": True})

    @app.route("/api/me", methods=["GET"])
    def me():
        user = auth.current_user()
        if user is None:
            return jsonify({"ok": False, "user": None}), 401
        return jsonify({"ok": True, "user": auth.public_user_dict(user)})

    # ---- WebSocket 实时事件流 ----
    @sock.route("/api/ws/events")
    def ws_events(ws):
        def send(message):
            try:
                ws.send(json.dumps(message, ensure_ascii=False))
            except Exception:
                pass
        engine.add_listener(send)
        engine.add_listener(send)
        # 连接后先推送一条快照（当前统计）
        try:
            send({"kind": "hello", "engine": engine.stats()})
        except Exception:
            pass
        try:
            while True:
                data = ws.receive()
                if data is None:
                    break
                # 客户端心跳 / 自定义指令可在此处理
        except Exception:
            pass
        finally:
            engine.remove_listener(send)

    # ---- 静态页面 ----
    @app.route("/")
    def index():
        return send_from_directory(config.FRONTEND_DIR, "index.html")

    @app.route("/<path:path>")
    def static_files(path):
        full = os.path.join(config.FRONTEND_DIR, path)
        if os.path.isfile(full):
            return send_from_directory(config.FRONTEND_DIR, path)
        return send_from_directory(config.FRONTEND_DIR, "index.html")

    return app


app = create_app()


def _shutdown():
    """进程退出前 flush 事件缓冲。"""
    if runtime.engine is not None:
        try:
            runtime.engine.events.stop()
        except Exception:
            pass


import atexit
atexit.register(_shutdown)
