import json
from datetime import timedelta

from app.services import realtime_backup_logs as rtl


class FakeRedis:
    def __init__(self):
        self.kv = {}
        self.lists = {}
        self.counters = {}
        self.expirations = {}
        self.lrange_calls = []

    def setex(self, key, _ttl, value):
        self.kv[key] = value

    def get(self, key):
        if key in self.kv:
            return self.kv.get(key)
        if key in self.counters:
            return str(self.counters.get(key))
        return None

    def incr(self, key):
        value = int(self.counters.get(key, 0)) + 1
        self.counters[key] = value
        return value

    def rpush(self, key, *values):
        self.lists.setdefault(key, []).extend(values)

    def ltrim(self, key, start, end):
        items = list(self.lists.get(key, []))
        length = len(items)
        if length <= 0:
            self.lists[key] = []
            return
        if start < 0:
            start = max(length + start, 0)
        if end < 0:
            end = length + end
        start = max(0, start)
        end = min(length - 1, end)
        if start > end:
            self.lists[key] = []
        else:
            self.lists[key] = items[start : end + 1]

    def expire(self, key, ttl):
        self.expirations[key] = ttl

    def lindex(self, key, index):
        items = self.lists.get(key, [])
        if not items:
            return None
        if index < 0:
            index = len(items) + index
        if index < 0 or index >= len(items):
            return None
        return items[index]

    def lpop(self, key):
        items = self.lists.get(key, [])
        if not items:
            return None
        return items.pop(0)

    def lrange(self, key, start, end):
        self.lrange_calls.append((key, start, end))
        items = list(self.lists.get(key, []))
        length = len(items)
        if length <= 0:
            return []
        if start < 0:
            start = max(length + start, 0)
        if end < 0:
            end = length + end
        start = max(0, start)
        end = min(length - 1, end)
        if start > end:
            return []
        return items[start : end + 1]

    def llen(self, key):
        return len(self.lists.get(key, []))


def _entry(seq: int, *, tenant_id: str = "tenant-a") -> str:
    return json.dumps(
        {
            "seq": seq,
            "global_seq": seq,
            "tenant_id": tenant_id,
            "timestamp_iso": rtl._now_iso(),
        }
    )


def test_append_task_log_prunes_old_entries_with_timezone_safe_cutoff(monkeypatch):
    fake = FakeRedis()
    monkeypatch.setattr(rtl, "_redis_client", None)
    monkeypatch.setattr(rtl, "get_redis_client", lambda: fake)
    monkeypatch.setattr(rtl.settings, "REALTIME_LOG_RETENTION_DAYS", 90)

    old_ts = (rtl._utc_now() - timedelta(days=120)).isoformat().replace("+00:00", "Z")
    fake.lists[rtl.GLOBAL_LOG_KEY] = [
        json.dumps({"global_seq": 1, "timestamp_iso": old_ts, "tenant_id": "tenant-a"})
    ]
    fake.setex(rtl._task_meta_key("task-1"), 60, json.dumps({"tenant_id": "tenant-a"}))

    rtl.append_task_log("task-1", "Device 1", "mensagem de teste")

    global_items = fake.lists[rtl.GLOBAL_LOG_KEY]
    assert len(global_items) == 1
    payload = json.loads(global_items[0])
    assert payload["task_id"] == "task-1"
    assert payload["tenant_id"] == "tenant-a"


def test_get_task_logs_reads_recent_window_instead_of_full_list(monkeypatch):
    fake = FakeRedis()
    monkeypatch.setattr(rtl, "_redis_client", None)
    monkeypatch.setattr(rtl, "get_redis_client", lambda: fake)

    key = rtl._task_log_key("task-2")
    fake.lists[key] = [_entry(seq) for seq in range(1, 2001)]

    result = rtl.get_task_logs("task-2", after_seq=1990, limit=20)

    assert [item["seq"] for item in result["entries"]] == list(range(1991, 2001))
    assert result["last_seq"] == 2000
    assert all(call[1:] != (0, -1) for call in fake.lrange_calls)


def test_get_global_logs_filters_tenant_using_chunked_reads(monkeypatch):
    fake = FakeRedis()
    monkeypatch.setattr(rtl, "_redis_client", None)
    monkeypatch.setattr(rtl, "get_redis_client", lambda: fake)

    fake.lists[rtl.GLOBAL_LOG_KEY] = [
        _entry(seq, tenant_id="tenant-a" if seq % 2 else "tenant-b")
        for seq in range(1, 2001)
    ]

    result = rtl.get_global_logs(after_seq=1900, limit=30, tenant_id="tenant-a")

    assert result["entries"]
    assert all(item["tenant_id"] == "tenant-a" for item in result["entries"])
    assert all(item["global_seq"] > 1900 for item in result["entries"])
    assert all(call[1:] != (0, -1) for call in fake.lrange_calls)


def test_get_task_logs_returns_fast_when_after_seq_is_current(monkeypatch):
    fake = FakeRedis()
    monkeypatch.setattr(rtl, "_redis_client", None)
    monkeypatch.setattr(rtl, "get_redis_client", lambda: fake)

    key = rtl._task_log_key("task-3")
    fake.lists[key] = [_entry(seq) for seq in range(1, 21)]
    fake.counters[rtl._task_log_seq_key("task-3")] = 20

    result = rtl.get_task_logs("task-3", after_seq=20, limit=20)

    assert result == {"entries": [], "last_seq": 20}
    assert fake.lrange_calls == []


def test_append_task_log_prunes_global_log_on_interval(monkeypatch):
    fake = FakeRedis()
    monkeypatch.setattr(rtl, "_redis_client", None)
    monkeypatch.setattr(rtl, "_global_prune_cache_until", 0.0)
    monkeypatch.setattr(rtl, "get_redis_client", lambda: fake)
    monkeypatch.setattr(rtl.settings, "REALTIME_LOG_RETENTION_DAYS", 90)
    monkeypatch.setattr(rtl, "_global_prune_interval_seconds", lambda: 300.0)

    old_ts = (rtl._utc_now() - timedelta(days=120)).isoformat().replace("+00:00", "Z")
    fake.lists[rtl.GLOBAL_LOG_KEY] = [
        json.dumps({"global_seq": 1, "timestamp_iso": old_ts, "tenant_id": "tenant-a"})
    ]
    fake.setex(rtl._task_meta_key("task-4"), 60, json.dumps({"tenant_id": "tenant-a"}))

    monotonic_values = iter([100.0, 150.0])
    monkeypatch.setattr(rtl.time, "monotonic", lambda: next(monotonic_values))

    rtl.append_task_log("task-4", "Device 4", "primeiro log")
    first_size = len(fake.lists[rtl.GLOBAL_LOG_KEY])
    rtl.append_task_log("task-4", "Device 4", "segundo log")

    assert first_size == 1
    assert len(fake.lists[rtl.GLOBAL_LOG_KEY]) == 2
