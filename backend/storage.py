"""JSON 文件存储层：并发读写安全。

难点之一：JSON 规则/事件/告警的并发读写安全。

实现策略（三层防护）：
1. 进程内：每路径一把 threading.RLock，同一进程内多线程读写互斥；
2. 跨进程：fcntl.flock 对 ``<file>.lock`` 加排它锁，保证多进程（如多 worker）互斥；
3. 原子落盘：先写同目录临时文件 + fsync，再 os.replace 原子替换，崩溃时不会留下半截文件。
   （os.replace 在同一文件系统上是原子操作，POSIX 保证。）

注意：flock 锁绑定在「打开文件描述」上，同一进程对同一文件再次 open 得到的是
*独立* 的锁，会与已持有的锁互相阻塞（自死锁）。因此所有「读-改-写」复合操作
必须一次性加锁，内部使用无锁的读写原语，绝不在持锁状态下再次调用带锁的公共 API。
"""
import json
import os
import tempfile
import threading
import fcntl
import time
import hashlib

from backend import config

# 进程内文件锁注册表
_lock_registry = {}
_registry_guard = threading.Lock()


def _file_lock(path):
    """返回指定路径对应的进程内 RLock（惰性创建）。"""
    with _registry_guard:
        lock = _lock_registry.get(path)
        if lock is None:
            lock = threading.RLock()
            _lock_registry[path] = lock
        return lock


class FileLock:
    """跨进程文件锁（fcntl.flock），配合 with 使用。"""

    def __init__(self, path, timeout=5.0):
        self.lock_path = path + ".lock"
        self.timeout = timeout
        self._fd = None

    def __enter__(self):
        # 锁文件所在目录可能尚未创建（如未写入过事件的小时分片目录），
        # 这里先确保目录存在，否则 open("a+") 会因父目录缺失抛 FileNotFoundError。
        os.makedirs(os.path.dirname(self.lock_path), exist_ok=True)
        self._fd = open(self.lock_path, "a+")
        deadline = time.time() + self.timeout
        while True:
            try:
                fcntl.flock(self._fd.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                return self
            except OSError:
                if time.time() > deadline:
                    # 超时退化为阻塞锁，避免长时间等待饿死
                    fcntl.flock(self._fd.fileno(), fcntl.LOCK_EX)
                    return self
                time.sleep(0.01)

    def __exit__(self, *exc):
        if self._fd is not None:
            try:
                fcntl.flock(self._fd.fileno(), fcntl.LOCK_UN)
            finally:
                self._fd.close()
                self._fd = None
        return False


# ---------------------------------------------------------------------------
# 无锁读写原语（仅在已持锁的上下文中调用）
# ---------------------------------------------------------------------------
def _write_unlocked(path, data, indent=2):
    directory = os.path.dirname(path)
    os.makedirs(directory, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".tmp_", suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=indent)
            f.flush()
            os.fsync(f.fileno())
        # 先备份再替换，替换前保留上一版到 .bak，损坏时可回退
        if os.path.exists(path):
            try:
                os.replace(path, path + ".bak")
            except OSError:
                pass
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.remove(tmp)
        raise


def _read_unlocked(path, default=None):
    if not os.path.exists(path):
        return default
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        bak = path + ".bak"
        if os.path.exists(bak):
            try:
                with open(bak, "r", encoding="utf-8") as f:
                    return json.load(f)
            except (json.JSONDecodeError, OSError):
                pass
        return default


# ---------------------------------------------------------------------------
# 公共 API
# ---------------------------------------------------------------------------
def atomic_write_json(path, data, indent=2):
    """原子写 JSON：临时文件 + fsync + os.replace（带锁）。"""
    path = os.path.abspath(path)
    with _file_lock(path):
        with FileLock(path):
            _write_unlocked(path, data, indent)
    return True


def read_json(path, default=None):
    """安全读取 JSON 文件，返回默认值当文件不存在或损坏。"""
    path = os.path.abspath(path)
    with _file_lock(path):
        with FileLock(path):
            return _read_unlocked(path, default)


def update_json(path, mutate, default=None):
    """读-改-写复合操作，全程持锁（进程内 + 跨进程），避免 lost update。

    ``mutate(data)`` 就地修改后返回任意结果；写入由本函数自动完成。
    """
    path = os.path.abspath(path)
    with _file_lock(path):
        with FileLock(path):
            data = _read_unlocked(path, default)
            result = mutate(data)
            _write_unlocked(path, data)
            return result


def list_json_files(directory):
    """列出目录下所有 .json 文件（不含备份与临时文件）。"""
    if not os.path.isdir(directory):
        return []
    out = []
    for name in os.listdir(directory):
        if name.endswith(".json") and not name.startswith(".tmp_") and ".bak" not in name:
            out.append(os.path.join(directory, name))

    def _key(p):
        return p
    return sorted(out, key=_key, reverse=True)


# ---------------------------------------------------------------------------
# 分片与工具
# ---------------------------------------------------------------------------
def _apply_zone(ts):
    t = time.localtime(ts)
    if t.tm_isdst:
        return ts - 7 * 3600
    if time.timezone:
        return ts + time.timezone
    return ts - 8 * 3600


def shard_path_for_hour(ts=None):
    """返回按小时分片的事件文件路径（如 events/20260925/14.json）。"""
    if ts is None:
        ts = time.time()
    t = time.gmtime(_apply_zone(ts))
    y = t.tm_year
    mo = t.tm_mon
    d = t.tm_mday
    h = t.tm_hour
    day = f"{y:04d}{mo:02d}{d:02d}"
    hour = f"{h:02d}.json"
    return os.path.join(config.EVENTS_DIR, day, hour)


def shard_path_for_day(ts=None):
    """返回按天分片的告警文件路径。"""
    if ts is None:
        ts = time.time()
    t = time.gmtime(_apply_zone(ts))
    return os.path.join(
        config.ALERTS_DIR,
        f"{t.tm_year:04d}{t.tm_mon:02d}{t.tm_mday:02d}.json",
    )


def append_event(ts, event):
    """向按小时分片的事件文件追加一条事件（持锁，避免丢写）。

    事件文件是一个 JSON 对象 ``{"events": [...]}``；追加采用读-改-写，但为避免
    单文件过大，小时分片本身已限制了单文件规模。
    """
    path = shard_path_for_hour(ts)
    with _file_lock(path):
        with FileLock(path):
            data = _read_unlocked(path, {"events": []})
            data.setdefault("events", []).append(event)
            _write_unlocked(path, data)


def gen_id(prefix=""):
    """生成带时间戳的短 ID。"""
    h = hashlib.md5(str(time.time_ns()).encode()).hexdigest()[:10]
    return f"{prefix}{int(time.time() * 1000)}_{h}"
