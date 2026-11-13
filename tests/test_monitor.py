import json
import time
import unittest

import app
from app import TailWorker, build_query, format_log_time, mask_text, should_watch


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
        self.assertIn('i("[ERROR]")', query)
        self.assertNotIn("kubernetes.pod_namespace", query)

    def test_keyword_match_ignores_case(self):
        item, _monitor = worker()
        self.assertEqual(item._matched_keyword("[error] boom"), "[ERROR]")
        self.assertEqual(item._matched_keyword("all good"), "")

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
        item.buckets["[ERROR]"]["last_sent"] = 0
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
        self.assertIn("正在监控的项目", page)
        self.assertIn("监控中", page)
        self.assertNotIn("盯着", page)


    def test_restart_ignores_old_logs(self):
        item, monitor = worker()
        item.alert_after = time.time()
        item._handle_line(line("[ERROR] old log"))
        self.assertEqual(monitor.messages, [])

if __name__ == "__main__":
    unittest.main()
