"""事件存储：按小时分片的 JSON 文件 + 内存缓冲批量落盘。

高频事件流下若每条事件都「读-改-写」整个小时分片，会退化为 O(n^2)。因此：
- 内存按小时聚合缓冲，达到阈值或定时批量 flush 到对应小时分片文件；
- 落盘仍是标准 JSON 数组文件（events/YYYYMMDD/HH.json），符合「事件按小时分片」；
- 查询时合并「磁盘分片 + 内存未落盘缓冲」，保证读到最新数据；
- 每条记录为 {event, decision}：decision 是该事件命中规则/决策流/处置动作的完整
  快照，供事件详情做深度回溯；历史分片若只存了裸事件，查询时自动归一化；
- 后台守护线程定时 flush，进程退出前再全量 flush，避免丢事件。
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


def normalize_record(obj):
    """把分片里的一条数据归一化为 {event, decision} 记录。

    兼容两种历史形态：
    - 新格式：{"event": {...}, "decision": {...}}；
    - 旧格式：裸事件字段平铺（含 id/ts/type）。
    """
    if isinstance(obj, dict) and isinstance(obj.get("event"), dict):
        return {"event": obj["event"], "decision": obj.get("decision")}
    return {"event": obj, "decision": None}


def _record_ts(rec):
    ev = rec.get("event") or {}
    dec = rec.get("decision") or {}
    return ev.get("ts") or dec.get("ts") or 0


def _dedup_key(rec):
    """去重指纹：优先用事件 ID；无 ID（手工注入的历史数据）退化为完整特征。"""
    ev = rec.get("event") or {}
    eid = ev.get("id")
    if eid is not None:
        return ("id", eid)
    return ("fp", _record_ts(rec), ev.get("type"), ev.get("ip"),
            ev.get("user_id"), ev.get("amount"))


class EventStore:
    def __init__(self, flush_threshold=200, flush_interval=2.0):
        self.flush_threshold = flush_threshold
        self.flush_interval = flush_interval
        self._buffer = {}          # hour_key -> list[record]
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
        records = self._buffer.get(hour_key, [])
        if not records:
            return
        path = _hour_path(hour_key)
        existing = read_json(path, {"events": []})
        merged = [normalize_record(o) for o in existing.get("events", [])]
        merged.extend(records)
        atomic_write_json(path, {"events": merged})
        self._buffer[hour_key] = []

    def add(self, record, ts=None):
        """写入一条记录。record 可为归一化的 {event, decision} 或裸事件。"""
        rec = normalize_record(record)
        if ts is None:
            ts = _record_ts(rec) or time.time()
        key = _hour_key(ts)
        with self._lock:
            buf = self._buffer.setdefault(key, [])
            buf.append(rec)
            self._dirty.add(key)
            if len(buf) >= self.flush_threshold:
                self._flush_locked(key)
                self._dirty.discard(key)

    def stop(self):
        self._stop.set()
        self.flush_all()

    # ------------------------------------------------------------------
    def _load_hour(self, hour_key):
        path = _hour_path(hour_key)
        data = read_json(path, {"events": []})
        return [normalize_record(o) for o in data.get("events", [])]

    def _hour_keys(self, start_ts, end_ts):
        """枚举 [start_ts, end_ts] 覆盖到的小时分片键。"""
        t = int(start_ts) // 3600 * 3600
        end_floor = int(end_ts) // 3600 * 3600
        keys = []
        while t <= end_floor:
            keys.append(_hour_key(t))
            t += 3600
        return keys

    def _collect(self, start_ts, end_ts):
        """合并磁盘分片与内存缓冲，按 (id, ts...) 去重，旧数据可能因历史 bug 重复。"""
        result = []
        seen = set()
        with self._lock:
            for key in self._hour_keys(start_ts, end_ts):
                records = self._load_hour(key)
                records.extend(self._buffer.get(key, []))
                for rec in records:
                    sig = _dedup_key(rec)
                    if sig in seen:
                        # 已有同一事件：若新记录带决策快照则替换（信息更全）
                        for i, prev in enumerate(result):
                            if _dedup_key(prev) == sig:
                                if rec.get("decision") and not prev.get("decision"):
                                    result[i] = rec
                                break
                        continue
                    seen.add(sig)
                    result.append(rec)
        result = [r for r in result if start_ts <= _record_ts(r) <= end_ts]
        result.sort(key=_record_ts)
        return result

    def query_records(self, start_ts=None, end_ts=None, limit=None):
        """按时间范围查询归一化记录（含内存缓冲），时间正序；limit 取最新 N 条。"""
        now = time.time()
        if end_ts is None:
            end_ts = now
        if start_ts is None:
            start_ts = end_ts - 3600
        result = self._collect(start_ts, end_ts)
        if limit:
            result = result[-limit:]
        return result

    def query(self, start_ts=None, end_ts=None, limit=None):
        """按时间范围查询裸事件（兼容旧调用方），时间正序；limit 取最新 N 条。"""
        return [r["event"] for r in self.query_records(start_ts, end_ts, limit)]

    def find_record(self, event_id, near_ts=None, scan_hours=48):
        """按事件 ID 取完整记录。

        优先在 near_ts（或当前时间）附近分片精确命中，找不到再向前后扫描
        scan_hours 小时范围的分片。
        records 已按时间正序，同一 id 多条（理论上不会）返回最新一条。
        """
        now = time.time()
        anchor = near_ts or now
        # 1) 锚点所在小时分片快速命中
        rec = self._find_in_range(event_id, anchor - 3600, anchor + 3600)
        if rec is not None:
            return rec
        # 2) 扩大窗口扫描
        half = scan_hours * 1800
        return self._find_in_range(event_id, max(0, now - half), now + half)

    def _find_in_range(self, event_id, start_ts, end_ts):
        hit = None
        for rec in self._collect(start_ts, end_ts):
            if (rec.get("event") or {}).get("id") == event_id:
                hit = rec  # 时间正序，持续覆盖以取最新
        return hit

    def find_related(self, event, window_sec=600, subject_field=None, limit=200):
        """检索同一主体（IP / 用户等）在事件时间点临近窗口内的关联事件时间线。

        :param event: 锚点事件（取其 ts 与主体字段值）
        :param window_sec: 单侧窗口半径，实际查询 [ts-w, ts+w]
        :param subject_field: 指定主体字段；缺省依次尝试 user_id / ip
        :return: (field, value, records)
        """
        ts = event.get("ts") or time.time()
        candidates = [subject_field] if subject_field else ["user_id", "ip"]
        field, value = None, None
        for f in candidates:
            v = event.get(f)
            if v not in (None, ""):
                field, value = f, v
                break
        if field is None:
            return None, None, []
        records = self.query_records(max(0, ts - window_sec), ts + window_sec, limit=limit)
        related = [r for r in records if (r.get("event") or {}).get(field) == value]
        return field, value, related

    def recent(self, limit=100):
        return self.query(limit=limit)

    def stats(self):
        with self._lock:
            buffered = 0
            for v in self._buffer.values():
                buffered += len(v)
            dirty = len(self._dirty)
            if not dirty and buffered:
                dirty = 1
        return {"buffered": buffered, "dirty_hours": dirty}
