# -*- coding: utf-8 -*-
"""处置动作、审计记录与回执的可追溯链测试。

覆盖：动作摘要、回执按编号对账（缺/重复）、并发重复事件只进一份、
同一份回执晚到只记一次、旧数据摘要按时间顺序回填且可读、审计链可核对。
"""
import os
import sys
import sqlite3
import tempfile
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.repository import Repository
from src.service import Service
from src.domain import ConflictError


class TraceabilityTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp.close()
        self.repo = Repository(self.tmp.name)
        self.repo.initialize()
        self.service = Service(self.repo)

    def tearDown(self):
        os.unlink(self.tmp.name)

    def _full_workflow(self, pipeline_id="P-1", segment_id="S-1"):
        item = self.service.create_item({
            "pipeline_id": pipeline_id,
            "segment_id": segment_id,
            "reported_at": "2026-09-27T08:00:00+00:00",
            "pressure_drop_kpa": 30,
            "sensor_value_ppm": 120,
            "odor_reports": 3,
            "reporter": "dispatch-1",
        }, "dispatch-1", "dispatcher")
        item = self.service.act(item["id"], "verify", {"field_confirmed": True}, "resp-1", "responder", item["version"])
        item = self.service.act(item["id"], "isolate", {"valve_sequence": ["V-1", "V-2"]}, "sup-1", "supervisor", item["version"])
        item = self.service.act(item["id"], "repair", {"work_order": "WO-1"}, "tech-1", "technician", item["version"])
        item = self.service.act(item["id"], "pressure_test", {"test_passed": True, "pressure_kpa": 150, "minimum_pressure_kpa": 100}, "tech-1", "technician", item["version"])
        item = self.service.act(item["id"], "restore", {"hazards_clear": True}, "sup-1", "supervisor", item["version"])
        return item

    def _actions_by_type(self, item_id):
        detail = self.service.get_item(item_id)
        return {a["action"]: a for a in detail["actions"]}

    def test_every_action_gets_summary(self):
        item = self._full_workflow()
        detail = self.service.get_item(item["id"])
        for event in detail["audit"]:
            self.assertTrue(event.get("summary"), "审计事件缺少摘要: %s" % event.get("event_type"))
        for action in detail["actions"]:
            self.assertTrue(action.get("summary"), "处置动作缺少摘要: %s" % action.get("action"))
        # 摘要应包含"谁、什么时候、做了什么"
        self.assertIn("sup-1", detail["audit"][-1]["summary"])
        self.assertIn("恢复供气", detail["audit"][-1]["summary"])

    def test_reconciliation_lists_missing_receipts(self):
        item = self._full_workflow()
        rec = self.service.reconcile(item["id"])
        self.assertFalse(rec["balanced"])
        self.assertEqual(
            [m["action"] for m in rec["missing"]],
            ["isolate", "repair", "pressure_test", "restore"],
        )

    def test_reconciliation_balanced_after_all_receipts(self):
        item = self._full_workflow()
        actions = self._actions_by_type(item["id"])
        receipts = [
            ("R-0001", "valve_operation", "isolate"),
            ("R-0002", "repair", "repair"),
            ("R-0003", "pressure_test", "pressure_test"),
            ("R-0004", "restoration", "restore"),
        ]
        for number, receipt_type, action in receipts:
            self.service.add_receipt(
                item["id"],
                {"receipt_number": number, "receipt_type": receipt_type,
                 "received_at": "2026-09-27T09:00:00+00:00", "action_id": actions[action]["id"]},
                "sup-1", "supervisor",
            )
        rec = self.service.reconcile(item["id"])
        self.assertTrue(rec["balanced"])
        self.assertEqual(len(rec["received"]), 4)
        self.assertEqual(rec["missing"], [])

    def test_duplicate_receipt_recorded_once(self):
        item = self._full_workflow()
        actions = self._actions_by_type(item["id"])
        first = self.service.add_receipt(
            item["id"],
            {"receipt_number": "R-0002", "receipt_type": "repair",
             "received_at": "2026-09-27T10:00:00+00:00", "action_id": actions["repair"]["id"]},
            "sup-1", "supervisor",
        )
        second = self.service.add_receipt(
            item["id"],
            {"receipt_number": "R-0002", "receipt_type": "repair",
             "received_at": "2026-09-27T11:00:00+00:00", "action_id": actions["repair"]["id"]},
            "sup-1", "supervisor",
        )
        self.assertTrue(second["duplicate"])
        self.assertEqual(second["id"], first["id"], "重复回执不得新建行")
        self.assertEqual(second["duplicate_count"], 1)
        rec = self.service.reconcile(item["id"])
        self.assertEqual(len(rec["received"]), 4 - 3)  # 只登记了 1 条回执
        self.assertEqual(len(rec["duplicates"]), 1)
        self.assertEqual(rec["duplicates"][0]["receipt_number"], "R-0002")

    def test_concurrent_duplicate_event_only_one_enters_chain(self):
        results = {}

        def submit(tag):
            try:
                created = self.service.create_item({
                    "pipeline_id": "P-X",
                    "segment_id": "S-X",
                    "reported_at": "2026-09-28T08:00:00+00:00",
                    "pressure_drop_kpa": 10,
                    "sensor_value_ppm": 20,
                    "odor_reports": 0,
                    "reporter": tag,
                }, tag, "dispatcher")
                results[tag] = ("ok", created["id"])
            except ConflictError as exc:
                results[tag] = ("conflict", exc.details)

        t1 = threading.Thread(target=submit, args=("d1",))
        t2 = threading.Thread(target=submit, args=("d2",))
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        oks = [v for v in results.values() if v[0] == "ok"]
        conflicts = [v for v in results.values() if v[0] == "conflict"]
        self.assertEqual(len(oks), 1)
        self.assertEqual(len(conflicts), 1)
        # 链上只有一份
        self.assertEqual(len(self.service.list_items()), 1)
        # 退回的一份带 existing_item_id，可据此重试
        self.assertEqual(conflicts[0][1]["existing_item_id"], oks[0][1])

    def test_backfill_legacy_summaries_chronologically_and_readable(self):
        item = self._full_workflow()
        # 抹掉摘要，模拟没有摘要的旧数据
        conn = self.repo.connect()
        conn.execute("UPDATE audit_events SET summary=NULL WHERE item_id=?", (item["id"],))
        conn.execute("UPDATE actions SET summary=NULL WHERE item_id=?", (item["id"],))
        conn.close()

        before = self.service.get_item(item["id"])
        self.assertTrue(all(e["summary"] is None for e in before["audit"]))

        result = self.service.backfill()
        self.assertGreaterEqual(result["audit_events"], 6)
        self.assertEqual(result["actions"], 5)

        after = self.service.get_item(item["id"])
        self.assertTrue(all(e["summary"] for e in after["audit"]))
        self.assertTrue(all(a["summary"] for a in after["actions"]))
        # 回填后旧记录仍可读
        self.assertEqual(after["payload"]["pipeline_id"], "P-1")
        self.assertEqual(after["status"], "restored")
        # 回填幂等
        again = self.service.backfill()
        self.assertEqual(again["audit_events"], 0)
        self.assertEqual(again["actions"], 0)

    def test_backfill_runs_in_created_at_order(self):
        # 构造两条时间戳明确不同的旧审计事件，验证按时间顺序回填。
        item = self.service.create_item({
            "pipeline_id": "P-T",
            "segment_id": "S-T",
            "reported_at": "2026-09-20T08:00:00+00:00",
            "pressure_drop_kpa": 5,
            "sensor_value_ppm": 10,
            "odor_reports": 0,
            "reporter": "dispatch-t",
        }, "dispatch-t", "dispatcher")
        conn = self.repo.connect()
        conn.execute("UPDATE audit_events SET summary=NULL WHERE item_id=?", (item["id"],))
        # 插入一条更早的、无摘要的旧事件
        conn.execute(
            "INSERT INTO audit_events(item_id,event_type,actor,role,payload,summary,previous_hash,event_hash,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
            (item["id"], "created", "old", "dispatcher", '{"stable_key":"old"}', None, "GENESIS", "oldhash", "2026-09-01T00:00:00+00:00"),
        )
        conn.close()
        result = self.service.backfill()
        self.assertGreaterEqual(result["audit_events"], 2)
        detail = self.service.get_item(item["id"])
        summaries = {e["event_type"]: e["summary"] for e in detail["audit"]}
        self.assertIn("创建", summaries["created"])

    def test_audit_chain_verifiable_and_tamper_evident(self):
        item = self._full_workflow()
        chain = self.service.verify_chain(item["id"])
        self.assertTrue(chain["valid"])
        self.assertGreaterEqual(chain["length"], 6)

        # 篡改一条审计事件的载荷，链校验应能发现
        conn = self.repo.connect()
        conn.execute(
            "UPDATE audit_events SET actor='tampered' WHERE item_id=? AND event_type='verify'",
            (item["id"],),
        )
        conn.close()
        chain = self.service.verify_chain(item["id"])
        self.assertFalse(chain["valid"])
        self.assertIsNotNone(chain["broken_at"])

    def test_initialize_migrates_legacy_schema(self):
        # 用旧版表结构（无 summary 列、无 receipts 表）建库，再 initialize 迁移。
        tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        tmp.close()
        conn = sqlite3.connect(tmp.name)
        conn.executescript(
            """
            CREATE TABLE items (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                entity_type TEXT NOT NULL,
                stable_key TEXT NOT NULL,
                status TEXT NOT NULL,
                version INTEGER NOT NULL DEFAULT 1,
                payload TEXT NOT NULL,
                created_by TEXT NOT NULL,
                created_role TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE(entity_type, stable_key)
            );
            CREATE TABLE audit_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                item_id INTEGER,
                event_type TEXT NOT NULL,
                actor TEXT,
                role TEXT,
                payload TEXT NOT NULL,
                previous_hash TEXT NOT NULL,
                event_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE actions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                item_id INTEGER NOT NULL,
                action TEXT NOT NULL,
                actor TEXT NOT NULL,
                role TEXT NOT NULL,
                payload TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            """
        )
        conn.close()
        legacy_repo = Repository(tmp.name)
        legacy_repo.initialize()  # 迁移：补 summary 列、建 receipts 表
        legacy_service = Service(legacy_repo)
        item = legacy_service.create_item({
            "pipeline_id": "P-LEG",
            "segment_id": "S-LEG",
            "reported_at": "2026-09-27T08:00:00+00:00",
            "pressure_drop_kpa": 30,
            "sensor_value_ppm": 120,
            "odor_reports": 3,
            "reporter": "dispatch-leg",
        }, "dispatch-leg", "dispatcher")
        detail = legacy_service.get_item(item["id"])
        self.assertTrue(detail["audit"][0]["summary"])
        os.unlink(tmp.name)


if __name__ == "__main__":
    unittest.main()
