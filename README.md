# 实时风控规则引擎与决策流 (Real-time Risk Control Rule Engine & Decision Flow)

一个完整的实时风控规则引擎与决策流系统，支持可视化规则配置、决策流拖拽编排、WebSocket 实时事件流、滑动窗口聚合（短时高频计数）、规则动态热更新与版本回滚、告警聚合去重、统计报表与测试沙箱。

规则、事件、告警全部以 JSON 文件存储（规则按版本、事件按小时分片），无外部数据库依赖，开箱即用。

## 🚀 功能特性

### 前端（10 个页面，原生 HTML/CSS/JS）
| 页面 | 路径 | 说明 |
|------|------|------|
| 登录 / 总览 | `index.html` | 登录认证、系统概览看板、关键指标 |
| 规则配置 | `rules.html` | 规则 CRUD、CodeMirror JSON 编辑器、语法校验、启停 |
| 决策流设计 | `flows.html` | 可视化拖拽节点（条件 / 动作 / 分支）编排决策流 |
| 实时事件流 | `events.html` | WebSocket 滚动展示实时事件与命中告警 |
| 告警列表 | `alerts.html` | 告警查询、去重计数、标记处理、导出（CSV/JSON） |
| 统计报表 | `stats.html` | ECharts 图表：命中率、拒绝率、事件趋势、规则命中排行 |
| 用户管理 | `users.html` | 用户 CRUD、角色（admin/analyst/viewer）、重置密码 |
| 系统设置 | `settings.html` | 匹配模式切换、去重窗口、滑动窗口容量参数 |
| 规则版本管理 | `versions.html` | 版本历史、LCS 行级 diff、一键回滚 |
| 测试沙箱 | `sandbox.html` | 单事件 dry-run、单规则测试、决策流测试、窗口预热 |
| 数据字典 | `dict.html` | 事件类型、风险等级、动作类型等枚举统一维护 |

### 后端（Python + Flask）
- **高性能规则匹配**：Rete 风格 alpha 判别网络（类型哈希路由 + 条件节点共享），可选决策树匹配器
- **滑动窗口精确聚合**：时间有序双端队列 + 惰性淘汰，均摊 O(1) 精确计数（count/sum/avg/max/min/distinct_count）
- **动态规则热更新**：不可变编译快照 + 单引用原子替换，更新/删除/启停/回滚全程不中断匹配
- **版本回滚**：每次保存追加版本历史快照，回滚以更高版本号重新发布
- **告警聚合去重**：规则 + 主体字段指纹哈希索引，时间窗内累加计数，避免告警风暴
- **JSON 并发读写安全**：进程内 RLock + 跨进程 flock + 临时文件 + fsync + os.replace 原子替换
- **事件分片存储**：按小时分片 JSON 文件，内存缓冲 + 后台线程异步刷盘
- **WebSocket 实时推送**：命中事件与告警实时广播到前端

## 📁 项目结构

```
gsb3/
├── backend/
│   ├── app.py                 # Flask 主应用：登录/登出/me、WebSocket、静态托管
│   ├── config.py              # 路径、默认设置、动作类型、条件算子、聚合类型
│   ├── storage.py             # JSON 原子读写、文件锁(flock)、事件小时分片、ID 生成
│   ├── auth.py                # 认证、SHA-256 加盐密码、角色鉴权装饰器、默认账号
│   ├── event_store.py         # 事件存储：内存缓冲 + 后台刷盘线程
│   ├── flows.py               # 决策流编译与执行（条件/动作/分支）
│   ├── settings_store.py      # 系统设置读写（深合并）
│   ├── seed.py                # 样例数据初始化（10 条规则、字典、示例决策流，幂等）
│   ├── runtime.py             # 运行时单例引用
│   ├── engine/
│   │   ├── rule_parser.py     # 规则编译：条件编译、聚合规格、编译产物
│   │   ├── rete.py            # Rete alpha 判别网络（类型哈希路由 + 条件节点共享）
│   │   ├── decision_tree.py   # 决策树匹配器（最高频条件贪心分裂）
│   │   ├── window.py          # 滑动窗口聚合器（三层内存预算）
│   │   ├── hot_update.py      # 规则注册表：原子热更新 + 版本历史 + 回滚
│   │   ├── alert.py           # 告警聚合去重（指纹哈希索引）
│   │   └── engine.py          # 风控引擎编排：匹配→聚合→决策→去重→持久化→广播
│   └── api/
│       ├── rules.py           # 规则 CRUD、校验、版本、回滚
│       ├── events.py          # 事件查询、摄取、模拟突发、存储统计
│       ├── alerts.py          # 告警查询、标记、导出、统计
│       ├── stats.py           # 统计报表（命中率/拒绝率/趋势）
│       ├── flows.py           # 决策流 CRUD 与执行
│       ├── sandbox.py         # dry-run、单规则/决策流测试、窗口预热
│       ├── users.py           # 用户管理
│       ├── settings.py        # 系统设置
│       └── dict.py            # 数据字典
├── frontend/                  # 11 个页面 + assets/css/style.css + assets/js/api.js
├── data/                      # JSON 数据（运行时自动创建）：rules/versions/events/alerts/...
├── requirements.txt
├── run.py                     # 一键启动脚本
└── README.md
```

## 🛠️ 安装与运行

```bash
pip install -r requirements.txt
python run.py
```

浏览器访问 http://localhost:5000

> 端口冲突时可通过环境变量 `RISK_PORT=5001` 指定其他端口（`python run.py` 自动读取）。

**默认账号**
- 管理员：`admin / admin123`（角色 admin）
- 分析师：`alice / 123456`（角色 analyst）
- 访客：`bob / 123456`（角色 viewer）

> 规则匹配模式（Rete / 决策树）可在「系统设置」页面即时切换（原子重建匹配网络）；
> 滑动窗口/去重等容量参数重启后生效。

## 🎯 核心难点解决方案

### 1. 规则引擎高性能匹配
- **Rete 风格 alpha 判别网络**：按事件类型哈希路由（`TypeNode` 根分桶）+ 条件节点跨规则共享，避免对每条规则重复判定相同条件；匹配复杂度与「命中条件数」相关而非「规则总数」
- **决策树备选**：以「出现频次最高」的条件贪心分裂构造二叉判定树，命中即下钻、未命中即剪枝，减少平均判定次数；含「真/假」双分支设计保证缺字段/不相干条件正确剪枝

### 2. 滑动窗口精确聚合与内存控制
- **精确计数**：每键维护按时间有序的双端队列 + 惰性淘汰，`query` 时用二分定位窗口起点，均摊 O(1) 精确统计（非近似 sketch）
- **三层内存预算**：`window_max_keys`（LRU 淘汰键数上限）、`window_max_events_per_key`（单键事件上限）、`window_max_total_events`（事件总量上限），任一超限即触发淘汰，杜绝内存无限增长

### 3. 规则热更新原子替换与版本回滚
- **不可变快照 + 单引用原子替换**：更新时「旁路」构建全新 `CompiledRuleSet`（含完整匹配网络），构建成功后在互斥锁内把引用一次性指向新快照；匹配线程每次只读一次 `current` 引用，看到的要么是完整旧版、要么是完整新版，绝无「半个网络」中间态
- **版本回滚**：每次保存追加 `{version, rule, ts, author, comment}` 历史快照；回滚取出历史、以更高版本号重新发布，本质仍是「构建新快照 + 原子替换」

### 4. 告警去重算法
- **指纹哈希索引**：`md5(rule_id + 归一化去重字段)` 生成指纹，内存哈希表建立「指纹 → 时间戳/计数」索引
- **时间窗去重**：同一指纹在 `dedup_window_sec` 内重复出现只累加 `count`，不产生新告警记录；窗口外重新计入，避免告警风暴的同时保留告警频率信息

### 5. JSON 规则并发读写安全
- **进程内锁**：每个数据路径一把 `threading.RLock`，读-改-写原语全程持锁
- **跨进程锁**：`fcntl.flock` 文件锁，多进程下仍互斥；内部原语不加 flock，避免同一进程内嵌套 flock 造成自死锁
- **原子写**：写临时文件 → `fsync` → `os.replace` 原子替换，崩溃/中断也不产生半写文件；替换前额外备份 `.bak` 兜底

## 📊 API 概览

- 认证：`POST /api/login`、`POST /api/logout`、`GET /api/me`
- 规则：`GET/POST /api/rules`、`GET/PUT/DELETE /api/rules/<id>`、`POST /api/rules/validate`、`POST /api/rules/<id>/enable`、`GET /api/rules/<id>/versions`、`POST /api/rules/<id>/rollback`
- 事件：`GET /api/events`、`POST /api/events/ingest`、`POST /api/events/simulate`、`GET /api/events/store_stats`
- 告警：`GET /api/alerts`、`POST /api/alerts/mark`、`GET /api/alerts/export`、`GET /api/alerts/stats`
- 统计：`GET /api/stats`、`POST /api/stats/reset`
- 决策流：`GET/POST /api/flows`、`GET/PUT/DELETE /api/flows/<id>`
- 沙箱：`POST /api/sandbox/dry_run`、`/test_rule`、`/test_flow`、`/seed_window`
- 用户：`GET/POST /api/users`、`PUT/DELETE /api/users/<username>`、`POST /api/users/<username>/password`、`POST /api/users/me/password`
- 设置：`GET/PUT /api/settings`
- 字典：`GET /api/dict`、`POST /api/dict/entry`、`PUT/DELETE /api/dict/entry/<id>`、`POST /api/dict/category`
- 实时：`WS /api/ws/events`


