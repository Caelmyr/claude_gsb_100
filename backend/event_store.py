"""事件存储：按小时分片的 JSON 文件 + 内存缓冲批量落盘。

高频事件流下若每条事件都「读-改-写」整个小时分片，会退化为 O(n^2)。因此：
- 内存按小时聚合缓冲，达到阈值或定时批量 flush 到对应小时分片文件；
- 落盘仍是标准 JSON 数组文件（events/YYYYMMDD/HH.json），符合「事件按小时分片」；
- 查询时合并「磁盘分片 + 内存未落盘缓冲」，保证读到最新数据；
- 后台守护线程定时 flush，进程退出前再全量 flush，避免丢事件。

每条记录统一为包装结构 ``{"event": <事件字段>, "decision": <决策快照>}``，
读取时兼容历史裸事件（只有事件字段、无 decision）。按事件 id 去重，
以容错历史脏数据（重复追加）。
"""
import os
import threading
import time

from backend import config
from backend.storage import atomic_write_json, read_json


def _hour_key(ts):
    ts = ts - 8 * 3600
    t = time.gmtime(ts)
    y = t.tm_year
    mo = t.tm_mon
    d = t.tm_mday
    h = t.tm_hour
    day = f"{y:04d}{mo:02d}{d:02d}"
    hour = f"{h:02d}"
    return f"{day}/{hour}"


def _hour_path(hour_key):
    return os.path.join(config.EVENTS_DIR, hour_key + ".json")


def _wrap(event, decision=None):
    return {"event": event, "decision": decision}


def _unwrap(rec):
    """兼容两种落盘形态：包装结构 / 历史裸事件。"""
    if isinstance(rec, dict) and isinstance(rec.get("event"), dict):
        return {"event": rec["event"], "decision": rec.get("decision")}
    return {"event": rec, "decision": None}


def _rec_id(rec):
    ev = rec.get("event") or {}
    return ev.get("id")


def _rec_ts(rec):
    ev = rec.get("event") or {}
    return ev.get("ts", 0) or 0


def _dedup(records):
    """按事件 id 去重（保留首次出现），无 id 的记录按对象身份保留。"""
    seen = set()
    out = []
    for rec in records:
        rid = _rec_id(rec)
        if rid is not None:
            if rid in seen:
                continue
            seen.add(rid)
        out.append(rec)
    return out


class EventStore:
    def __init__(self, flush_threshold=200, flush_interval=2.0):
        self.flush_threshold = flush_threshold
        self.flush_interval = flush_interval
        self._buffer = {}          # hour_key -> list[record(wrapper)]
        self._dirty = set()
        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._flush_loop, daemon=True)
        self._thread.start()

    # ------------------------------------------------------------------
    def _flush_loop(self):
        while not self._stop.is_set():
            self._stop.wait(self.flush_interval)
            try:
                self.flush_all()
            except Exception:
                pass

    def flush_all(self):
        with self._lock:
            keys = list(self._dirty)
            for key in keys:
                self._flush_locked(key)
            self._dirty.clear()

    def _flush_locked(self, hour_key):
        new_records = self._buffer.get(hour_key, [])
        if not new_records:
            return
        path = _hour_path(hour_key)
        existing = []
        data = read_json(path, None)
        if isinstance(data, dict):
            existing = [_unwrap(r) for r in data.get("events", [])]
        merged = _dedup(existing + list(new_records))
        atomic_write_json(path, {"events": merged})
        self._buffer[hour_key] = []

    def add(self, event, decision=None, ts=None):
        if ts is None:
            ts = event.get("ts") or time.time()
        key = _hour_key(ts)
        with self._lock:
            buf = self._buffer.setdefault(key, [])
            buf.append(_wrap(event, decision))
            self._dirty.add(key)
            if len(buf) >= self.flush_threshold:
                self._flush_locked(key)
                self._dirty.discard(key)

    def stop(self):
        self._stop.set()
        self.flush_all()

    # ------------------------------------------------------------------
    def _load_hour(self, hour_key):
        """读取某小时分片（磁盘），返回包装记录列表。"""
        path = _hour_path(hour_key)
        data = read_json(path, None)
        if not isinstance(data, dict):
            return []
        return [_unwrap(r) for r in data.get("events", [])]

    def _hour_keys_between(self, start_ts, end_ts):
        """枚举时间范围覆盖的小时键（含端点小时）。"""
        t = int(start_ts) // 3600 * 3600
        end_hour = int(end_ts) // 3600 * 3600
        keys = []
        while t <= end_hour:
            keys.append(_hour_key(t))
            t += 3600
        return keys

    def _collect(self, hour_keys):
        """合并指定小时分片的磁盘记录与内存缓冲（加锁快照）。"""
        result = []
        with self._lock:
            for key in hour_keys:
                result.extend(self._load_hour(key))
                result.extend(self._buffer.get(key, []))
        return _dedup(result)

    def query(self, start_ts=None, end_ts=None, limit=None):
        """按时间范围查询事件（含内存缓冲），最新在前。返回包装记录列表。"""
        now = time.time()
        if end_ts is None:
            end_ts = now
        if start_ts is None:
            start_ts = end_ts - 3600

        records = self._collect(self._hour_keys_between(start_ts, end_ts))
        records = [r for r in records if start_ts <= _rec_ts(r) <= end_ts]
        records.sort(key=_rec_ts, reverse=True)
        if limit:
            records = records[:limit]
        return records

    def get(self, event_id):
        """按事件 id 取单条包装记录，找不到返回 None。扫描全部分片 + 缓冲。"""
        keys = set()
        events_root = config.EVENTS_DIR
        if os.path.isdir(events_root):
            for day in os.listdir(events_root):
                day_dir = os.path.join(events_root, day)
                if not os.path.isdir(day_dir):
                    continue
                for fn in os.listdir(day_dir):
                    if fn.endswith(".json"):
                        keys.add(f"{day}/{fn[:-5]}")
        with self._lock:
            keys.update(self._buffer.keys())
            for rec in self._collect(sorted(keys)):
                if _rec_id(rec) == event_id:
                    return rec
        return None

    def related(self, event, window_sec=600, limit=50):
        """查询同一主体（IP 或用户 ID）在临近时间窗内的关联事件。

        返回 (records, subject)：records 按时间正序，subject 为实际匹配到的
        主体字段值 {"ip": ..., "user_id": ...}。
        """
        ts = event.get("ts") or time.time()
        ip = event.get("ip")
        uid = event.get("user_id")
        start_ts, end_ts = ts - window_sec, ts + window_sec
        records = self._collect(self._hour_keys_between(start_ts, end_ts))
        matched = []
        for rec in records:
            ev = rec.get("event") or {}
            t = ev.get("ts", 0) or 0
            if not (start_ts <= t <= end_ts):
                continue
            if ip is not None and ev.get("ip") == ip:
                matched.append(rec)
            elif uid is not None and ev.get("user_id") == uid:
                matched.append(rec)
        matched = _dedup(matched)
        matched.sort(key=_rec_ts)
        if limit and len(matched) > limit:
            # 优先保留靠近目标事件的记录
            idx = next((i for i, r in enumerate(matched)
                        if _rec_ts(r) >= ts), len(matched) - 1)
            half = limit // 2
            lo = max(0, idx - half)
            hi = min(len(matched), lo + limit)
            lo = max(0, hi - limit)
            matched = matched[lo:hi]
        subject = {"ip": ip, "user_id": uid}
        return matched, subject

    def recent(self, limit=100):
        return self.query(limit=limit)

    def stats(self):
        with self._lock:
            buffered = sum(len(v) for v in self._buffer.values())
            dirty = len(self._dirty)
            if not dirty and buffered:
                dirty = 1
        return {"buffered": buffered, "dirty_hours": dirty}
