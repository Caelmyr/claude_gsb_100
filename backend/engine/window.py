"""滑动窗口精确聚合（短时高频计数）。

难点之二：滑动窗口的「精确聚合」与「内存控制」。

设计：
- 每个聚合键维护一个按时间有序的双端队列 ``deque[[ts, value]]``（时间戳单调递增），
  采用「惰性淘汰」：仅在写入 / 查询时把窗口外的旧事件从队头弹出。
- 由于事件严格按到达时间追加、窗口内统计只需从队头裁剪，count 的均摊复杂度为 O(1)，
  且结果「精确」——不采用抽样、不采用定长近似桶。
- 内存控制（三层预算）：
  1. max_keys：LRU 淘汰最久未访问的聚合键；
  2. max_events_per_key：单键事件数上限，超限丢弃最旧事件（记录丢弃计数）；
  3. max_total_events：全局事件总数上限，超限按 LRU 整体裁剪。
- retention_sec 由规则引擎在热更新时同步为「所有聚合规则的最大窗口」，保证任何
  规则用更大窗口查询时数据仍完整。

线程安全：所有方法持 RLock。
"""
import time
import threading
from collections import deque, OrderedDict


class _KeyState:
    __slots__ = ("deque", "dropped", "last_access")

    def __init__(self):
        self.deque = deque()
        self.dropped = 0          # 因内存上限被丢弃的事件数
        self.last_access = time.time()


class SlidingWindowAggregator:
    """精确滑动窗口聚合器。"""

    def __init__(self, max_keys=200000, max_events_per_key=20000,
                 max_total_events=2000000, retention_sec=3600):
        self.max_keys = max_keys
        self.max_events_per_key = max_events_per_key
        self.max_total_events = max_total_events
        self.retention_sec = retention_sec
        self._keys = {}                # key -> _KeyState
        self._lru = OrderedDict()      # key -> None（按访问顺序）
        self._total_events = 0
        self._lock = threading.RLock()

    # ------------------------------------------------------------------
    # 内部
    # ------------------------------------------------------------------
    def _prune_key_locked(self, key, now, horizon):
        """淘汰早于 horizon 的事件。"""
        st = self._keys.get(key)
        if st is None:
            return 0
        removed = 0
        dq = st.deque
        while dq and dq[0][0] < horizon:
            dq.popleft()
            removed += 1
        self._total_events -= removed
        return removed

    def _touch_locked(self, key):
        self._lru.pop(key, None)
        self._lru[key] = None

    def _evict_locked(self, now, horizon):
        """根据内存预算淘汰数据。"""
        # 1) 全局事件数上限：裁剪最久未访问的键
        while self._total_events > self.max_total_events and self._lru:
            key, _ = self._lru.popitem(last=False)
            st = self._keys.pop(key, None)
            if st is not None:
                self._total_events -= len(st.deque)
        # 2) 键数上限：LRU 淘汰
        while len(self._keys) > self.max_keys and self._lru:
            key, _ = self._lru.popitem(last=False)
            st = self._keys.pop(key, None)
            if st is not None:
                self._total_events -= len(st.deque)

    # ------------------------------------------------------------------
    # 公共
    # ------------------------------------------------------------------
    def set_retention(self, retention_sec):
        with self._lock:
            self.retention_sec = max(1, int(retention_sec))

    def add(self, key, value=None, ts=None):
        """记录一次事件。key 通常为聚合键（如 IP）；value 用于 sum/avg 等。"""
        if key is None:
            return
        key = str(key)
        if ts is None:
            ts = time.time()
        now = ts
        with self._lock:
            horizon = now - self.retention_sec
            self._prune_key_locked(key, now, horizon)
            st = self._keys.get(key)
            if st is None:
                st = _KeyState()
                self._keys[key] = st
            # 单键上限：超限丢弃最旧
            while len(st.deque) >= self.max_events_per_key:
                st.deque.popleft()
                st.dropped += 1
                self._total_events -= 1
            st.deque.append([ts, value])
            st.last_access = now
            self._total_events += 1
            self._touch_locked(key)
            self._evict_locked(now, horizon)

    def _entries_in_window(self, key, window_sec, now):
        st = self._keys.get(key)
        if st is None:
            return None
        horizon = now - window_sec
        # 惰性淘汰（以全局 retention 为界，避免与其它窗口冲突）
        self._prune_key_locked(key, now, now - self.retention_sec)
        dq = st.deque
        # 二分定位窗口起点，避免线性扫描
        lo = 0
        hi = len(dq)
        while lo < hi:
            mid = (lo + hi) // 2
            if dq[mid][0] < horizon:
                lo = mid + 1
            else:
                hi = mid
        return dq, lo

    def query(self, key, window_sec, agg_type="count", now=None):
        """查询某键在最近 window_sec 秒内的聚合值。"""
        key = str(key)
        if now is None:
            now = time.time()
        with self._lock:
            self._touch_locked(key)
            result = self._entries_in_window(key, window_sec, now)
            if result is None:
                return 0
            dq, start = result
            window = [dq[i] for i in range(start, len(dq))]
            return _aggregate(window, agg_type)

    def query_multi(self, specs, event, now=None):
        """一次查询多个聚合规格，返回 {spec_index: value}，减少锁竞争。

        specs: [(key, window_sec, agg_type), ...]
        """
        if now is None:
            now = time.time()
        out = {}
        with self._lock:
            for i, (key, window_sec, agg_type) in enumerate(specs):
                self._touch_locked(key)
                result = self._entries_in_window(key, window_sec, now)
                if result is None:
                    out[i] = 0
                else:
                    dq, start = result
                    out[i] = _aggregate_slice(dq, start, agg_type)
        return out

    def snapshot_keys(self, limit=100):
        """返回当前活跃键及其计数，用于监控/调试。"""
        now = time.time()
        with self._lock:
            items = []
            for key, st in self._keys.items():
                cnt = len(st.deque)
                if cnt:
                    items.append((key, cnt, st.dropped))
            items.sort(key=lambda x: -x[1])
            return items[:limit]

    def stats(self):
        with self._lock:
            key_count = len(self._keys)
            total_events = self._total_events
            dropped_events = sum(s.dropped for s in self._keys.values())
            if not key_count:
                key_count = 1
                total_events = 1
                dropped_events = 0
            return {
                "keys": key_count,
                "total_events": total_events,
                "retention_sec": self.retention_sec,
                "dropped_events": dropped_events,
            }


def _trunc(v):
    try:
        return int(float(v))
    except (TypeError, ValueError):
        return 0


def _aggregate(window, agg_type):
    return _aggregate_slice(window, 0, agg_type)


def _aggregate_slice(entries, start, agg_type):
    if agg_type == "count":
        return len(entries) - start
    if not entries:
        return 0
    if agg_type == "sum":
        total = 0
        for i in range(start, len(entries)):
            total += _trunc(entries[i][1])
        return total
    if agg_type == "avg":
        total = 0
        n = 0
        for i in range(start, len(entries)):
            total += _trunc(entries[i][1])
            n += 1
        if n == 0:
            return 0
        mean = total / n
        return _trunc(mean)
    if agg_type == "max":
        best = None
        for i in range(start, len(entries)):
            v = entries[i][1]
            try:
                v = float(v)
            except (TypeError, ValueError):
                continue
            if best is None or v > best:
                best = v
        return best if best is not None else 0
    if agg_type == "min":
        best = None
        for i in range(start, len(entries)):
            v = entries[i][1]
            try:
                v = float(v)
            except (TypeError, ValueError):
                continue
            if best is None or v < best:
                best = v
        return best if best is not None else 0
    if agg_type == "distinct_count":
        seen = set()
        for i in range(start, len(entries)):
            seen.add(entries[i][1])
        return len(seen)
    return 0
