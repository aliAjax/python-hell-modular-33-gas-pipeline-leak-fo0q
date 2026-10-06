import json
import os
import sqlite3
import sys
import tempfile
import threading
import unittest
from urllib import request as urlrequest
from http.server import ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from src.repository import Repository
from src.service import Service
from src.domain import ConflictError, DomainError
from src.http_api import build_handler


def base_payload(**overrides):
    payload = {
        "pipeline_id": "P-9",
        "segment_id": "S-1",
        "reported_at": "2026-10-01T08:00:00+00:00",
        "pressure_drop_kpa": 30,
        "sensor_value_ppm": 120,
        "odor_reports": 3,
        "reporter": "dispatch-1",
    }
    payload.update(overrides)
    return payload


class ChainTestBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp.close()
        self.repo = Repository(self.tmp.name)
        self.repo.initialize()
        self.service = Service(self.repo)

    def tearDown(self):
        for suffix in ("", "-wal", "-shm"):
            try:
                os.unlink(self.tmp.name + suffix)
            except OSError:
                pass

    def run_to_restore(self, expected_receipts=None):
        item = self.service.create_item(base_payload(), "dispatch-1", "dispatcher")
        item = self.service.act(item["id"], "verify", {"field_confirmed": True}, "resp-1", "responder", item["version"])
        item = self.service.act(item["id"], "isolate",
                                {"valve_sequence": ["V-1", "V-2"], "expected_receipts": expected_receipts}
                                if expected_receipts else {"valve_sequence": ["V-1", "V-2"]},
                                "sup-1", "supervisor", item["version"])
        return item


class ActionDigestChainTest(ChainTestBase):
    def test_actions_carry_content_and_chain_digest(self):
        item = self.run_to_restore()
        actions = self.repo.list_actions(item["id"])
        self.assertEqual(len(actions), 2)
        for action in actions:
            self.assertIsNotNone(action["content_digest"])
            self.assertIsNotNone(action["digest"])
            self.assertEqual(len(action["content_digest"]), 64)
        # 链式摘要不同，且第二条挂在第一条之后
        self.assertNotEqual(actions[0]["digest"], actions[1]["digest"])

        report = self.repo.verify_chain(item["id"])
        self.assertTrue(report["ok"], report["errors"])
        self.assertEqual(report["pending_backfill"], [])

        # 审计事件挂回动作摘要
        audit = self.repo.audit_trail(item["id"])
        action_events = [e for e in audit if e["event_type"] in ("verify", "isolate")]
        self.assertEqual(len(action_events), 2)
        for event in action_events:
            self.assertIsNotNone(event["action_id"])
            self.assertIsNotNone(event["action_digest"])

    def test_tampering_action_payload_breaks_chain(self):
        item = self.run_to_restore()
        conn = self.repo.connect()
        try:
            row = conn.execute("SELECT payload FROM actions WHERE item_id=? ORDER BY id LIMIT 1", (item["id"],)).fetchone()
            tampered = json.loads(row["payload"])
            tampered["forged"] = True
            conn.execute("BEGIN IMMEDIATE")
            conn.execute("UPDATE actions SET payload=? WHERE item_id=? AND id IN (SELECT id FROM actions WHERE item_id=? ORDER BY id LIMIT 1)",
                         (json.dumps(tampered, ensure_ascii=False), item["id"], item["id"]))
            conn.execute("COMMIT")
        finally:
            conn.close()
        report = self.repo.verify_chain(item["id"])
        self.assertFalse(report["ok"])
        codes = {error["code"] for error in report["errors"]}
        self.assertIn("action_content_digest_mismatch", codes)


class DuplicateSubmitTest(ChainTestBase):
    def test_concurrent_same_incident_only_one_enters_chain(self):
        errors = []
        items = []
        barrier = threading.Barrier(2)

        def submit(actor):
            barrier.wait()
            try:
                item = self.service.create_item(base_payload(), actor, "dispatcher")
                items.append(item["id"])
            except ConflictError as exc:
                errors.append(exc)

        t1 = threading.Thread(target=submit, args=("duty-a",))
        t2 = threading.Thread(target=submit, args=("duty-b",))
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        self.assertEqual(len(items), 1)
        self.assertEqual(len(errors), 1)
        self.assertEqual(errors[0].code, "duplicate_item")
        # 被退回的一份拿到已存在记录 id，可以按它重试（读取/补登）而不是再造一份
        self.assertEqual(errors[0].details["existing_item_id"], items[0])
        self.assertEqual(len(self.repo.list_items()), 1)


class ReceiptReconciliationTest(ChainTestBase):
    def _full_with_expected(self):
        item = self.run_to_restore(expected_receipts=["RC-100", "RC-101"])
        return item

    def test_expected_receipt_registered_and_missing(self):
        item = self._full_with_expected()
        recon = self.repo.reconciliation(item["id"])
        self.assertEqual(recon["summary"]["expected"], 2)
        self.assertEqual(recon["summary"]["matched"], 0)
        self.assertEqual(recon["summary"]["missing"], 2)
        self.assertEqual({r["receipt_no"] for r in recon["missing"]}, {"RC-100", "RC-101"})

    def test_receipt_delivered_once_late_duplicate_only_logged(self):
        item = self._full_with_expected()
        receipt = self.service.deliver_receipt(
            item["id"], {"receipt_no": "RC-100", "issuer": "抢修班", "document": "隔离回执正文"},
            "resp-1", "responder",
        )
        self.assertEqual(receipt["status"], "received")
        self.assertIsNotNone(receipt["content_digest"])

        # 同一份回执晚到：拒收为重复，但留一条送达痕迹
        with self.assertRaises(ConflictError) as ctx:
            self.service.deliver_receipt(
                item["id"], {"receipt_no": "RC-100", "issuer": "抢修班", "document": "隔离回执正文（晚到）"},
                "resp-2", "responder",
            )
        self.assertEqual(ctx.exception.code, "duplicate_receipt")

        # 正文仍是第一次的，没有被晚到的覆盖
        again = self.repo.get_receipt(receipt["id"])
        self.assertEqual(again["document"], "隔离回执正文")
        self.assertEqual(again["status"], "received")

        recon = self.repo.reconciliation(item["id"])
        self.assertEqual(recon["summary"]["matched"], 1)
        self.assertEqual(recon["summary"]["missing"], 1)
        self.assertEqual(recon["summary"]["duplicate_deliveries"], 1)
        self.assertEqual(recon["duplicate_deliveries"][0]["receipt_no"], "RC-100")

        report = self.repo.verify_chain(item["id"])
        self.assertTrue(report["ok"], report["errors"])

    def test_unexpected_receipt_listed_separately(self):
        item = self._full_with_expected()
        self.service.deliver_receipt(
            item["id"], {"receipt_no": "RC-UNKNOWN", "document": "外部自送回执"},
            "patrol-1", "patrol",
        )
        recon = self.repo.reconciliation(item["id"])
        self.assertEqual(recon["summary"]["unexpected"], 1)
        self.assertEqual(recon["unexpected"][0]["receipt_no"], "RC-UNKNOWN")

    def test_receipt_delivered_to_wrong_item_is_rejected(self):
        item1 = self._full_with_expected()
        item2 = self.service.create_item(
            base_payload(segment_id="S-2", reported_at="2026-10-01T09:00:00+00:00"),
            "dispatch-1", "dispatcher",
        )
        # RC-100 属于 item1，却往 item2 送
        with self.assertRaises(ConflictError) as ctx:
            self.service.deliver_receipt(
                item2["id"], {"receipt_no": "RC-100", "document": "串事件的回执"},
                "resp-1", "responder",
            )
        self.assertEqual(ctx.exception.code, "receipt_wrong_item")
        self.assertEqual(ctx.exception.code, "receipt_wrong_item")

        # 归属事件的对账里能看到这次拒收（自己的回执被送到别处），
        # 被送错的事件看到的是 inbound 拒收，回执本身没被记成 item2 的
        recon1 = self.repo.reconciliation(item1["id"])
        self.assertEqual(recon1["summary"]["rejected_wrong_item"], 1)
        self.assertEqual(recon1["summary"]["rejected_inbound"], 0)
        recon2 = self.repo.reconciliation(item2["id"])
        self.assertEqual(recon2["summary"]["rejected_wrong_item"], 0)
        self.assertEqual(recon2["summary"]["rejected_inbound"], 1)
        self.assertEqual(recon2["summary"]["unexpected"], 0)

        # 送到正确的事件上仍可正常登记
        self.service.deliver_receipt(item1["id"], {"receipt_no": "RC-100", "document": "隔离回执"}, "r", "responder")
        self.assertEqual(self.repo.reconciliation(item1["id"])["summary"]["matched"], 1)

    def test_duplicate_receipt_number_registration_rejected(self):
        item1 = self.run_to_restore(expected_receipts=["RC-200"])
        item2 = self.service.create_item(
            base_payload(segment_id="S-3", reported_at="2026-10-01T10:00:00+00:00"),
            "d", "dispatcher",
        )
        item2 = self.service.act(item2["id"], "verify", {"field_confirmed": True}, "r", "responder", item2["version"])
        with self.assertRaises(ConflictError) as ctx:
            self.service.act(item2["id"], "isolate",
                             {"valve_sequence": ["V-3", "V-4"], "expected_receipts": ["RC-200"]},
                             "s", "supervisor", item2["version"])
        self.assertEqual(ctx.exception.code, "receipt_no_taken")
        # 登记失败不能污染 item2 状态机
        self.assertEqual(self.repo.get_item(item2["id"])["status"], "verified")
        self.assertEqual(self.repo.reconciliation(item2["id"])["summary"]["expected"], 0)
        # item1 的链仍完整
        self.assertTrue(self.repo.verify_chain(item1["id"])["ok"])
        self.assertTrue(self.repo.verify_chain(item2["id"])["ok"])

    def test_same_expected_receipt_twice_in_one_action_rejected(self):
        item = self.service.create_item(base_payload(), "d", "dispatcher")
        item = self.service.act(item["id"], "verify", {"field_confirmed": True}, "r", "responder", item["version"])
        with self.assertRaises(DomainError) as ctx:
            self.service.act(item["id"], "isolate",
                             {"valve_sequence": ["V-1", "V-2"], "expected_receipts": ["RC-1", "RC-1"]},
                             "s", "supervisor", item["version"])
        self.assertEqual(ctx.exception.code, "duplicate_expected_receipt")


class BackfillTest(ChainTestBase):
    def _build_legacy_db(self, path):
        """用加列之前的旧结构造一份历史库：动作、审计都在，但没有任何摘要/挂钩列。

        数据用旧版写法直接插入（审计哈希算法沿用旧 audit_hash），模拟升级前快照。
        """
        from src.audit import GENESIS, audit_hash, canonical_json
        from src.rules import assess
        conn = sqlite3.connect(path)
        try:
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
                CREATE TABLE sources (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    item_id INTEGER NOT NULL,
                    source_type TEXT NOT NULL,
                    external_id TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    observed_at TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    UNIQUE(item_id, source_type, external_id)
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
                """
            )
            payload = base_payload(segment_id="S-7")
            payload.pop("reporter", None)
            payload.update({
                "source_comparison": [],
                "valve_sequence": [],
                "hazards_clear": False,
            })
            ts1 = "2026-10-01T08:01:00+00:00"
            stable_key = "P-9|S-7|2026-10-01T08:00:00+00:00"
            cur = conn.execute(
                "INSERT INTO items(entity_type,stable_key,status,version,payload,created_by,created_role,created_at,updated_at) "
                "VALUES('pipeline_leak',?, 'reported',1,?,?,?,?,?)",
                (stable_key, canonical_json(payload), "old-dispatch", "dispatcher", ts1, ts1),
            )
            item_id = cur.lastrowid
            previous = GENESIS

            def legacy_audit(event_type, actor, role, event_payload, created_at):
                nonlocal previous
                event = {
                    "item_id": item_id, "event_type": event_type, "actor": actor,
                    "role": role, "payload": event_payload, "created_at": created_at,
                }
                h = audit_hash(previous, event)
                conn.execute(
                    "INSERT INTO audit_events(item_id,event_type,actor,role,payload,previous_hash,event_hash,created_at) "
                    "VALUES(?,?,?,?,?,?,?,?)",
                    (item_id, event_type, actor, role, canonical_json(event_payload), previous, h, created_at),
                )
                previous = h

            legacy_audit("created", "old-dispatch", "dispatcher", {"stable_key": stable_key}, ts1)

            # verify（旧版动作：无摘要列）
            payload["assessment"] = assess(payload)
            payload["verification"] = {"confirmed": True, "note": ""}
            ts2 = "2026-10-01T08:05:00+00:00"
            conn.execute("UPDATE items SET status='verified',version=2,payload=?,updated_at=? WHERE id=?",
                         (canonical_json(payload), ts2, item_id))
            event_payload = {"assessment": payload["assessment"], "verification": payload["verification"]}
            conn.execute("INSERT INTO actions(item_id,action,actor,role,payload,created_at) VALUES(?,?,?,?,?,?)",
                         (item_id, "verify", "old-resp", "responder", canonical_json(event_payload), ts2))
            legacy_audit("verify", "old-resp", "responder", event_payload, ts2)

            # isolate
            payload["valve_sequence"] = ["V-7", "V-8"]
            ts3 = "2026-10-01T08:10:00+00:00"
            conn.execute("UPDATE items SET status='isolated',version=3,payload=?,updated_at=? WHERE id=?",
                         (canonical_json(payload), ts3, item_id))
            event_payload = {"valve_sequence": ["V-7", "V-8"]}
            conn.execute("INSERT INTO actions(item_id,action,actor,role,payload,created_at) VALUES(?,?,?,?,?,?)",
                         (item_id, "isolate", "old-sup", "supervisor", canonical_json(event_payload), ts3))
            legacy_audit("isolate", "old-sup", "supervisor", event_payload, ts3)
            conn.commit()
            return item_id
        finally:
            conn.close()

    def test_legacy_rows_readable_before_backfill(self):
        path = self.tmp.name
        # 完全重建为旧结构
        os.unlink(path)
        self._build_legacy_db(path)

        repo = Repository(path)
        repo.initialize()  # 迁移加列
        item_id = repo.list_items()[0]["id"]

        # 回填前：旧数据照常可读，动作摘要为空，链校验报告 pending 而不是被篡改
        item = Service(repo).get_item(item_id)
        self.assertEqual(item["status"], "isolated")
        actions = repo.list_actions(item_id)
        self.assertTrue(all(a["digest"] is None for a in actions))

        audit_before = repo.audit_trail(item_id)
        hashes_before = [(e["id"], e["event_hash"], e["previous_hash"]) for e in audit_before]

        report = repo.verify_chain(item_id)
        self.assertTrue(report["ok"], report["errors"])
        self.assertEqual(len(report["pending_backfill"]), 2)

        stats = repo.backfill_digests()
        self.assertEqual(stats["actions"], 2)
        self.assertEqual(stats["audit_events"], 2)
        self.assertEqual(stats["pending"], 0)

        # 旧审计哈希一行都没变（旧记录仍可读且不可篡改）
        audit_after = repo.audit_trail(item_id)
        hashes_after = [(e["id"], e["event_hash"], e["previous_hash"]) for e in audit_after]
        self.assertEqual(hashes_before, hashes_after)

        # 挂钩补齐，整链可核
        self.assertTrue(all(e["action_id"] is not None for e in audit_after if e["event_type"] in ("verify", "isolate")))
        self.assertTrue(repo.verify_chain(item_id)["ok"])

        # 回填幂等
        stats_again = repo.backfill_digests()
        self.assertEqual(stats_again["actions"], 0)
        self.assertTrue(repo.verify_chain(item_id)["ok"])

    def test_backfill_idempotent_and_ordered_across_items(self):
        # 两个旧事件各自成链，回填按事件顺序互不串链
        i1 = self.service.create_item(base_payload(segment_id="S-A"), "d", "dispatcher")
        i1 = self.service.act(i1["id"], "verify", {"field_confirmed": True}, "r", "responder", i1["version"])
        i2 = self.service.create_item(base_payload(segment_id="S-B", reported_at="2026-10-02T08:00:00+00:00"), "d", "dispatcher")
        i2 = self.service.act(i2["id"], "verify", {"field_confirmed": True}, "r", "responder", i2["version"])
        stats = self.repo.backfill_digests()
        self.assertEqual(stats["pending"], 0)
        self.assertTrue(self.repo.verify_chain(i1["id"])["ok"])
        self.assertTrue(self.repo.verify_chain(i2["id"])["ok"])

    def test_new_action_before_backfill_is_re_anchored_without_losing_receipt_link(self):
        """升级后、回填前就产生了带预期回执的新动作：回填重锚后动作摘要变化，
        动作主事件的挂钩摘要必须同步，receipt_registered 不能被误判为动作主事件。"""
        path = self.tmp.name
        os.unlink(path)
        self._build_legacy_db(path)
        repo = Repository(path)
        repo.initialize()
        service = Service(repo)
        item_id = repo.list_items()[0]["id"]

        # 回填前先推进一个动作并登记、送达回执
        item = service.act(item_id, "repair",
                           {"work_order": "WO-7", "expected_receipts": ["RC-900"]},
                           "tech", "technician", 3)
        self.assertEqual(item["status"], "repaired")
        service.deliver_receipt(item_id, {"receipt_no": "RC-900", "document": "抢修回执"}, "r", "responder")

        stats = repo.backfill_digests()
        self.assertEqual(stats["pending"], 0)
        report = repo.verify_chain(item_id)
        self.assertTrue(report["ok"], report["errors"])
        # receipt_registered 与 repair 动作都还在，且动作主事件一一对应
        audit = repo.audit_trail(item_id)
        main_events = [e for e in audit if e["event_type"] in ("verify", "isolate", "repair")]
        self.assertEqual(len(main_events), 3)
        actions = {a["action"]: a for a in repo.list_actions(item_id)}
        for event in main_events:
            self.assertEqual(event["action_digest"], actions[event["event_type"]]["digest"])
        recon = repo.reconciliation(item_id)
        self.assertEqual(recon["summary"]["matched"], 1)


class HttpApiTest(ChainTestBase):
    def test_duplicate_item_response_carries_existing_id_and_receipt_flow(self):
        server = ThreadingHTTPServer(("127.0.0.1", 0), build_handler(self.service, os.path.join(os.getcwd(), "static")))
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base = "http://127.0.0.1:%d" % server.server_address[1]
        try:
            body = json.dumps(base_payload()).encode("utf-8")

            def post(path, payload, role="dispatcher", user="dispatch-1"):
                req = urlrequest.Request(base + path, data=json.dumps(payload).encode("utf-8"),
                                         headers={"Content-Type": "application/json",
                                                  "X-User-Id": user, "X-Role": role}, method="POST")
                try:
                    with urlrequest.urlopen(req) as resp:
                        return resp.status, json.loads(resp.read())
                except Exception as exc:
                    return exc.code, json.loads(exc.read())

            status, created = post("/api/items", base_payload())
            self.assertEqual(status, 201)
            item_id = created["id"]

            # 第二位值班员同时报同一处
            status2, err = post("/api/items", base_payload(), user="dispatch-2")
            self.assertEqual(status2, 409)
            self.assertEqual(err["error"], "duplicate_item")
            self.assertEqual(err["details"]["existing_item_id"], item_id)

            # 动作登记预期回执
            status3, item = post("/api/items/%d/actions" % item_id,
                                 {"action": "verify", "field_confirmed": True, "expected_version": created["version"]},
                                 role="responder", user="resp-1")
            self.assertEqual(status3, 200)

            status4, item = post("/api/items/%d/actions" % item_id,
                                 {"action": "isolate", "valve_sequence": ["V-1", "V-2"],
                                  "expected_receipts": ["RC-100"], "expected_version": item["version"]},
                                 role="supervisor", user="sup-1")
            self.assertEqual(status4, 200)

            status5, receipt = post("/api/items/%d/receipts" % item_id,
                                    {"receipt_no": "RC-100", "document": "隔离回执"},
                                    role="responder", user="resp-1")
            self.assertEqual(status5, 201)
            self.assertEqual(receipt["status"], "received")

            with urlrequest.urlopen(base + "/api/items/%d/reconciliation" % item_id) as resp:
                recon = json.loads(resp.read())
            self.assertEqual(recon["summary"]["matched"], 1)
            self.assertEqual(recon["summary"]["missing"], 0)

            with urlrequest.urlopen(base + "/api/items/%d/verify" % item_id) as resp:
                report = json.loads(resp.read())
            self.assertTrue(report["ok"], report["errors"])
        finally:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    unittest.main()
