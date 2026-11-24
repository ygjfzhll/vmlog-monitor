import json
import time
import unittest

import app
from app import TailWorker, brief_log, build_query, format_log_time, mask_text, monitoring_state, scope_floor, shard_rules, should_alert_quiet, should_watch


class FakeStore:
    def __init__(self):
        self.calls = []

    def add_matches(self, rule_id, count, by_container=None):
        self.calls.append((rule_id, count, dict(by_container or {})))


class FakeMonitor:
    def __init__(self):
        self.store = FakeStore()
        self.messages = []
        self.alerts = []

    def send_feishu(self, text, webhook=None):
        self.messages.append((text, webhook))

    def record(self, alert):
        self.alerts.append(alert)


def worker(keywords=None, cooldown=300):
    monitor = FakeMonitor()
    rule = {
        "id": "p1",
        "name": "JUMENG",
        "namespace": "jzai",
        "keywords": keywords or ["[ERROR]"],
        "cooldown_sec": cooldown,
        "webhook": "https://example.test/hook",
        "enabled": True,
        "paused": False,
        "matched": 0,
        "container_hits": {},
    }
    item = TailWorker(monitor, rule)
    item.alert_after = 0
    item.silence_until = 0
    item.default_cursor = 1
    item.backfill_sec = 0
    item.scope_cursors = {}
    item.pending_scopes = {}
    return item, monitor


def line(message, container="ai-story-board-app", pod="pod-a", when="2026-11-13T02:49:41.336511776Z"):
    return json.dumps({
        "_msg": message,
        "_time": when,
        "container_name": container,
        "kubernetes.pod_name": pod,
    }).encode()


class MonitorTests(unittest.TestCase):
    def test_time_is_beijing_seconds(self):
        self.assertEqual(format_log_time("2026-11-13T02:49:41.336511776Z"), "2026-11-13 10:49:41")

    def test_keyword_query_is_case_insensitive(self):
        query = build_query({
            "namespace": "jzai",
            "containers": ["ai-story-board-app"],
            "keywords": ["[ERROR]"],
        })
        self.assertIn('namespace="jzai"', query)
        multi = build_query({"namespace": ["jzai", "public"], "containers": [], "keywords": ["ERROR"]})
        self.assertIn('{namespace="jzai"}', multi)
        self.assertIn('{namespace="public"}', multi)
        scoped = build_query({"namespace": ["jzai", "public"], "containers": ["jzai/app-a", "public/app-b"], "keywords": ["ERROR"]})
        self.assertIn('{namespace="jzai",container_name=~"app\\\\-a"}', scoped)
        self.assertIn('{namespace="public",container_name=~"app\\\\-b"}', scoped)
        self.assertNotIn("app-a", scoped.split("public")[1])
        self.assertIn('i("[ERROR]")', query)
        host = build_query({"namespace": "GPU-5090-32024", "containers": ["video_sr-worker-1"], "keywords": ["ERROR"], "deploy_mode": "host"})
        self.assertIn('host="GPU-5090-32024"', host)
        self.assertIn("video_sr", host)
        self.assertNotIn("namespace=", host)
        self.assertNotIn("kubernetes.pod_namespace", query)

    def test_keyword_match_ignores_case(self):
        item, _monitor = worker()
        self.assertEqual(item._matched_keyword("[error] boom"), "[ERROR]")
        self.assertEqual(item._matched_keyword("all good"), "")

    def test_plain_error_word_skips_json_key(self):
        item, _monitor = worker(keywords=["ERROR"])
        self.assertEqual(item._matched_keyword('[INFO] data={"error":""}'), "")
        self.assertEqual(item._matched_keyword("[error] task failed"), "ERROR")
        item.rule["exclude_keywords"] = ["心跳"]
        self.assertEqual(item._matched_keyword("[ERROR] 心跳正常"), "")

    def test_alert_text_shape_and_time(self):
        item, monitor = worker()
        item._handle_line(line("[error] 2026/11/13 10:49:41 task"))
        self.assertEqual(len(monitor.messages), 1)
        text = monitor.messages[0][0]
        self.assertTrue(text.startswith("【日志告警】\n项目名称：JUMENG\n命中关键字：[ERROR]\n"))
        self.assertIn("时间：2026-11-13 10:49:41\n", text)
        self.assertIn("位置：jzai / ai-story-board-app / pod-a", text)
        self.assertEqual(monitor.messages[0][1], "https://example.test/hook")

    def test_duplicate_line_is_not_sent_twice(self):
        item, monitor = worker()
        payload = line("[ERROR] same")
        item._handle_line(payload)
        item._handle_line(payload)
        self.assertEqual(len(monitor.messages), 1)

    def test_hits_are_counted_by_container(self):
        item, monitor = worker()
        item._handle_line(line("[ERROR] one", container="app-a", pod="p1"))
        item._handle_line(line("[ERROR] two", container="app-b", pod="p2", when="2026-11-13T02:50:41Z"))
        item.flush_matches()
        self.assertEqual(monitor.store.calls[-1][2], {"app-a": 1, "app-b": 1})
        self.assertEqual(item.public_state()["container_hits"], {"app-a": 1, "app-b": 1})

    def test_busy_keyword_is_summarized_not_paused(self):
        item, monitor = worker(cooldown=300)
        item._handle_line(line("[ERROR] first", pod="p1"))
        item._handle_line(line("[ERROR] second", pod="p2", when="2026-11-13T02:50:00Z"))
        self.assertEqual(len(monitor.messages), 1)
        self.assertEqual(item.public_state()["state"], "starting")
        for bucket in item.buckets.values():
            bucket["last_sent"] = 0
        item._handle_line(line("[ERROR] third", pod="p3", when="2026-11-13T03:00:00Z"))
        self.assertEqual(len(monitor.messages), 2)
        self.assertIn("【日志汇总】", monitor.messages[1][0])
        self.assertIn("共 2 次", monitor.messages[1][0])

    def test_projects_can_be_paused_independently(self):
        self.assertTrue(should_watch({"enabled": True, "paused": False}))
        self.assertFalse(should_watch({"enabled": True, "paused": True}))
        self.assertFalse(should_watch({"enabled": False, "paused": False}))

    def test_sensitive_text_is_masked(self):
        self.assertNotIn("13800138000", mask_text("phone 13800138000"))
        self.assertIn("token=***", mask_text("token=abcdef123456"))

    def test_page_uses_current_words(self):
        page = app.WEB_PATH.read_text(encoding="utf-8")
        self.assertIn("项目管理", page)
        self.assertIn("监控中", page)
        self.assertNotIn("盯着", page)


    def test_restart_ignores_old_logs(self):
        item, monitor = worker()
        item.default_cursor = time.time()
        item.scope_cursors = {}
        item.backfill_sec = 0
        item.silence_until = 0
        item._handle_line(line("[ERROR] old log"))
        self.assertEqual(monitor.messages, [])


    def test_one_keyword_line_is_enough(self):
        item, _monitor = worker(keywords=["ERROR", "gpu worker shot failed"])
        self.assertEqual(item._matched_keyword("ERROR vsr task"), "ERROR")
        self.assertEqual(item._matched_keyword("gpu worker shot failed"), "gpu worker shot failed")
        self.assertEqual(item._matched_keyword("all good"), "")

    def test_query_failure_stays_visible_when_source_is_alive(self):
        state, error = monitoring_state(RuntimeError("查询失败 400: bad query"), True)
        self.assertEqual(state, "reconnecting")
        self.assertIn("查询失败", error)
        state, error = monitoring_state(ConnectionError("实时连接已断开"), True)
        self.assertEqual(state, "running")
        self.assertEqual(error, "")

    def test_hosts_keep_separate_cursors(self):
        now = 1_000_000
        self.assertEqual(scope_floor(now - 10, now, now, 0), now - 10)
        self.assertEqual(scope_floor(None, now, now, 0), now)
        self.assertLess(scope_floor(now, now, now, 300), now)

    def test_feishu_text_is_short(self):
        self.assertLessEqual(len(brief_log("x" * 500)), 161)
        self.assertIn("错误", brief_log("  错误   详情  "))

    def test_hosts_are_sharded_and_quiet_alert_waits(self):
        names = ["h%s" % i for i in range(9)]
        shards = shard_rules({"deploy_mode": "host", "namespace": names, "containers": ["h1/app", "other"], "keywords": ["ERROR"]})
        self.assertEqual(len(shards), 2)
        self.assertEqual(len(shards[0]["namespace"]), 8)
        self.assertIn("h1/app", shards[0]["containers"])
        self.assertNotIn("h1/app", shards[1]["containers"])
        self.assertTrue(should_alert_quiet(0, 100))
        self.assertFalse(should_alert_quiet(90, 100, 30))

if __name__ == "__main__":
    unittest.main()
