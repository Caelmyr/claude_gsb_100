#!/usr/bin/env python3
"""实时风控规则引擎与决策流系统 —— 一键启动脚本。"""
import os
import sys
import threading
import time
import webbrowser

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from backend.app import app
from backend.config import API_HOST, API_PORT


def open_browser():
    time.sleep(1.5)
    webbrowser.open(f"http://localhost:{API_PORT}")


PAGES = [
    ("index.html", "登录与总览"),
    ("rules.html", "规则配置"),
    ("flows.html", "决策流设计"),
    ("events.html", "实时事件流"),
    ("alerts.html", "告警列表"),
    ("stats.html", "统计报表"),
    ("users.html", "用户管理"),
    ("versions.html", "规则版本管理"),
    ("sandbox.html", "测试沙箱"),
    ("settings.html", "系统设置"),
    ("dict.html", "数据字典"),
]


if __name__ == "__main__":
    print("\n" + "=" * 64)
    print("   🛡️  实时风控规则引擎与决策流系统")
    print("=" * 64)

    print("\n🚀 系统启动中...\n")
    print("📍 页面导航:")
    print("   ┌───────────────────────────────────────────────────┐")
    for page, title in PAGES:
        url = f"http://localhost:{API_PORT}/{page}"
        print(f"   │  {title:<8} {url:<40}│")
    print("   └───────────────────────────────────────────────────┘")

    print("\n📡 后端 API:   http://localhost:%d/api/" % API_PORT)
    print("📡 WebSocket:  ws://localhost:%d/api/ws/events" % API_PORT)

    print("\n" + "-" * 64)
    print("🔑 默认账号:  admin  / admin123   （管理员）")
    print("              alice  / 123456    （分析师）")
    print("              bob    / 123456    （只读）")
    print("-" * 64)

    print("\n⚠️  按 Ctrl+C 停止服务器\n")

    threading.Thread(target=open_browser, daemon=True).start()
    app.run(host=API_HOST, port=API_PORT, debug=False, threaded=True)
