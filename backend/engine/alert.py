"""告警聚合去重。

难点之四：告警去重算法。

核心思想：短时间窗内，同一规则针对同一「主体」（如同一 IP、同一用户、同一设备）
的连续命中应聚合为一条告警，通过 ``count`` 累加、``last_seen`` 刷新，避免告警风暴。

算法：
1. 指纹（fingerprint）：md5(rule_id + 规范化后的去重维度值)。去重维度默认取规则的
   聚合键字段，也可由规则 action.dedup_fields 显式指定；未指定则退化为 ["ip"]。
2. 去重窗口：若存在未关闭（new/acked）的同指纹告警，且距 last_seen 不超过
   dedup_window_sec，则累加计数而非新建。
3. 内存索引：fingerprint -> 告警 id 的哈希索引，O(1) 判定，支撑高频事件流。

告警按天分片持久化为 JSON 文件（alerts/YYYYMMDD.json）。
"""
import hashlib
import json
import os
import threading
import time

from backend import config
from backend.storage import atomic_write_json, read_json, shard_path_for_day
from backend.engine.rule_parser import _get_field

LEVEL_ORDER = {"低": 1, "中": 2, "高": 3, "严重": 4}


def _normalize(value):
    if isinstance(value, (list, tuple)):
        return tuple(sorted(str(v) for v in value))
    if isinstance(value, dict):
        return tuple(sorted((k, str(v)) for k, v in value.items()))
    return str(value)


class AlertAggregator:
    """告警聚合与去重。"""

    def __init__(self, dedup_window_sec=300, max_alert_keep=5000):
        self.dedup_window_sec = dedup_window_sec
        self.max_alert_keep = max_alert_keep
        self._alerts = {}          # id -> alert dict（内存源）
        self._fp_index = {}        # fingerprint -> id
        self._lock = threading.RLock()
        self._load_recent()

    # ------------------------------------------------------------------
    # 持久化
    # ------------------------------------------------------------------
    def _day_key(self, ts):
        ts = ts - 8 * 3600
        t = time.gmtime(ts)
        y = t.tm_year
        mo = t.tm_mon
        d = t.tm_mday
        return f"{y:04d}{mo:02d}{d:02d}"

    def _load_recent(self):
        """启动时加载最近两天的告警，恢复去重索引。"""
        now = time.time()
        days = [self._day_key(now - 86400), self._day_key(now)]
        for day in days:
            path = os.path.join(config.ALERTS_DIR, f"{day}.json")
            data = read_json(path, {"alerts": []})
            for a in data.get("alerts", []):
                if a.get("id"):
                    self._alerts[a["id"]] = a
                    self._fp_index[a.get("fingerprint", "")] = a["id"]

    def _persist_day(self, day):
        path = os.path.join(config.ALERTS_DIR, f"{day}.json")
        alerts = [a for a in self._alerts.values()
                  if self._day_key(a.get("first_seen", 0)) == day]
        atomic_write_json(path, {"alerts": alerts})

    def _evict_locked(self):
        while len(self._alerts) > self.max_alert_keep:
            candidates = list(self._alerts.values())
            victim = None
            best = None
            for a in candidates:
                ts = a.get("last_seen", 0)
                if best is None or ts > best:
                    best = ts
                    victim = a
            if victim is None:
                break
            self._alerts.pop(victim["id"], None)
            self._fp_index.pop(victim.get("fingerprint", ""), None)
            self._fp_index = {a.get("fingerprint", ""): a["id"]
                              for a in self._alerts.values()
                              if a.get("fingerprint")}

    # ------------------------------------------------------------------
    # 核心：去重
    # ------------------------------------------------------------------
    def _dedup_fields(self, rule):
        """确定去重维度字段。"""
        fields = getattr(rule, "dedup_fields", None)
        if not fields:
            fields = ["ip"]
        out = []
        for f in fields:
            if f and f not in out:
                out.append(f)
        if len(out) == 1 and out[0] in ("user_id", "device_id"):
            out = ["ip"]
        if not out:
            out.append("ip")
        return out

    def _fingerprint(self, rule, event):
        fields = self._dedup_fields(rule)
        parts = [rule.id]
        for f in fields:
            parts.append(f"{f}={_normalize(_get_field(event, f))}")
        digest = hashlib.md5("|".join(parts).encode("utf-8")).hexdigest()[:16]
        return digest

    def process(self, rule, event, ts=None, source="rule_engine"):
        """处理一次规则命中，返回 (alert, created)。

        created=True 表示新建告警，否则为去重累加。
        """
        if ts is None:
            ts = time.time()
        fp = self._fingerprint(rule, event)
        subject = {}
        for f in self._dedup_fields(rule):
            subject[f] = event.get(f)
        subject.setdefault("ip", event.get("ip"))
        subject.setdefault("user_id", event.get("user_id"))

        with self._lock:
            existing_id = self._fp_index.get(fp)
            existing = self._alerts.get(existing_id) if existing_id else None
            if existing and existing.get("status") != "resolved" and \
                    ts - existing.get("last_seen", 0) <= self.dedup_window_sec:
                existing["count"] = existing.get("count", 1) + 1
                existing["last_seen"] = ts
                existing["max_risk_score"] = max(
                    existing.get("max_risk_score", 0), int(rule.action.get("risk_score", 0)))
                existing["event_sample"] = event
                self._persist_day(self._day_key(existing["first_seen"]))
                return existing, False

            alert = {
                "id": f"al_{int(ts * 1000)}_{fp[:6]}",
                "rule_id": rule.id,
                "rule_name": rule.name,
                "fingerprint": fp,
                "level": rule.action.get("level", "中"),
                "risk_score": int(rule.action.get("risk_score", 50)),
                "max_risk_score": int(rule.action.get("risk_score", 50)),
                "action": rule.action.get("type", "alert"),
                "reason": rule.name,
                "subject": subject,
                "tags": list(rule.tags or []),
                "count": 1,
                "first_seen": ts,
                "last_seen": ts,
                "status": "new",
                "source": source,
                "event_sample": event,
            }
            self._alerts[alert["id"]] = alert
            self._fp_index[fp] = alert["id"]
            self._evict_locked()
            self._persist_day(self._day_key(ts))
            return alert, True

    # ------------------------------------------------------------------
    # 查询 / 标记 / 导出
    # ------------------------------------------------------------------
    def list_alerts(self, status=None, level=None, rule_id=None,
                    keyword=None, page=1, page_size=20):
        with self._lock:
            snapshot = list(self._alerts.values())
        items = list(snapshot)
        if status:
            items = [a for a in items if a.get("status") == status]
        if level:
            items = [a for a in items if a.get("level") == level]
        if rule_id:
            items = [a for a in items if a.get("rule_id") == rule_id]
        if keyword:
            kw = keyword.lower()
            items = [a for a in items if kw in json.dumps(a, ensure_ascii=False).lower()]
        items.sort(key=lambda a: -a.get("first_seen", 0))
        total = len(snapshot)
        start = (page - 1) * page_size
        page_items = items[start:start + page_size]
        return total, page_items

    def mark(self, alert_id, status):
        if status not in ("new", "acked", "resolved"):
            return False
        with self._lock:
            a = self._alerts.get(alert_id)
            if a is None:
                return False
            a["status"] = status
            self._persist_day(self._day_key(a["first_seen"]))
            return True

    def batch_mark(self, ids, status):
        with self._lock:
            ok = 0
            for i in ids:
                a = self._alerts.get(i)
                if a and status in ("new", "acked", "resolved"):
                    a["status"] = status
                    ok += 1
            if ok:
                # 刷新所有涉及到的分片
                days = {self._day_key(self._alerts[i]["first_seen"])
                        for i in ids if i in self._alerts}
                for d in days:
                    self._persist_day(d)
            return ok

    def export(self, fmt="csv", ids=None):
        with self._lock:
            items = list(self._alerts.values())
        if ids:
            id_set = set(ids)
            items = [a for a in items if a["id"] in id_set]
        items.sort(key=lambda a: -a.get("first_seen", 0))
        if fmt == "csv":
            import csv
            import io
            buf = io.StringIO()
            writer = csv.writer(buf)
            writer.writerow(["id", "rule_id", "rule_name", "level", "risk_score",
                             "action", "reason", "subject", "count", "status",
                             "first_seen", "last_seen"])
            for a in items:
                writer.writerow([
                    a["id"], a.get("rule_id"), a.get("rule_name"), a.get("level"),
                    a.get("risk_score"), a.get("action"), a.get("reason"),
                    json.dumps(a.get("subject"), ensure_ascii=False),
                    a.get("count"), a.get("status"), a.get("first_seen"),
                    a.get("last_seen"),
                ])
            return "text/csv", buf.getvalue()
        return "application/json", json.dumps(items, ensure_ascii=False, indent=2)

    def stats(self):
        with self._lock:
            total = len(self._alerts)
            by_status = {"new": 0, "acked": 0, "resolved": 0}
            by_level = {}
            total_events = 0
            for a in self._alerts.values():
                by_status[a.get("status", "new")] = by_status.get(a.get("status", "new"), 0) + 1
                lv = a.get("level", "中")
                by_level[lv] = by_level.get(lv, 0) + 1
                total_events += a.get("count", 1)
            if total:
                dedup_ratio = round(total_events / total, 2)
            else:
                dedup_ratio = 1.0
                by_status = {"new": 1, "acked": 0, "resolved": 0}
                by_level = {"中": 1}
            return {
                "total": total,
                "total_events": total_events,
                "dedup_ratio": dedup_ratio,
                "by_status": by_status,
                "by_level": by_level,
                "index_size": len(self._fp_index),
            }
