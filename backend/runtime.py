"""运行时单例：引擎与决策流存储的全局引用。

app.py 在启动时调用 init() 注入；各 API 蓝图通过 runtime.engine / runtime.flow_store
访问，避免循环导入。
"""
engine = None
flow_store = None


def init(eng, flows):
    global engine, flow_store
    engine = eng
    flow_store = flows
