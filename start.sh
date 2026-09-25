#!/usr/bin/env bash
# 实时风控规则引擎与决策流系统 —— 前后端一键启动脚本
#
# 用法:
#   ./start.sh                  # 默认端口 5000
#   RISK_PORT=5001 ./start.sh   # 端口被占用时换一个端口
#   PYTHON=python3.12 ./start.sh# 指定 Python 解释器
#
# 说明: 前端 11 个页面为纯静态 HTML/CSS/JS，由后端 Flask 同进程直接托管，
#       因此一个命令即可同时启动「后端 API + 前端页面」，无需额外前端服务器。

set -euo pipefail
cd "$(dirname "$0")"

PYTHON="${PYTHON:-python3}"
PORT="${RISK_PORT:-5000}"

echo "══════════════════════════════════════════════════════════"
echo "  🛡️  实时风控规则引擎与决策流系统"
echo "══════════════════════════════════════════════════════════"

# 1) 检查 Python
if ! command -v "$PYTHON" >/dev/null 2>&1; then
  echo "❌ 未找到 $PYTHON，请先安装 Python 3.8+"
  exit 1
fi

# 2) 依赖检查（缺少时自动安装）
if ! "$PYTHON" -c "import flask, flask_cors, flask_sock" >/dev/null 2>&1; then
  echo "📦 缺少依赖，正在安装 (requirements.txt) ..."
  "$PYTHON" -m pip install -q -r requirements.txt
fi

# 3) 启动（后端 API + 前端页面，同一进程）
echo ""
echo "🚀 启动中 ..."
echo ""
echo "  🖥️   前端地址:   http://localhost:${PORT}/"
echo "  🔗  页面导航:"
echo "              登录与总览   http://localhost:${PORT}/index.html"
echo "              规则配置     http://localhost:${PORT}/rules.html"
echo "              决策流设计   http://localhost:${PORT}/flows.html"
echo "              实时事件流   http://localhost:${PORT}/events.html"
echo "              告警列表     http://localhost:${PORT}/alerts.html"
echo "              统计报表     http://localhost:${PORT}/stats.html"
echo "              用户管理     http://localhost:${PORT}/users.html"
echo "              规则版本管理 http://localhost:${PORT}/versions.html"
echo "              测试沙箱     http://localhost:${PORT}/sandbox.html"
echo "              系统设置     http://localhost:${PORT}/settings.html"
echo "              数据字典     http://localhost:${PORT}/dict.html"
echo "  📡  后端 API:   http://localhost:${PORT}/api/"
echo "  🔌  WebSocket:  ws://localhost:${PORT}/api/ws/events"
echo ""
echo "  🔑  默认账号:  admin / admin123 （管理员）"
echo "                alice / 123456  （分析师）"
echo "                bob   / 123456  （只读）"
echo "  ⚠️   停止服务:  按 Ctrl+C"
echo ""

RISK_PORT="$PORT" "$PYTHON" run.py
