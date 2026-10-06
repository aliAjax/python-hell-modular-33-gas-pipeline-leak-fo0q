import json
import sqlite3
from datetime import datetime, timezone

from .audit import audit_hash, canonical_json
from .domain import ConflictError, NotFoundError, DomainError
from .summary import summarize_event, summarize_action


def now_iso():
    return datetime.now(timezone.utc).isoformat()


# 建表语句（新库直接带摘要列与回执表）。
_SCHEMA_SCRIPT = """
CREATE TABLE IF NOT EXISTS items (
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
CREATE TABLE IF NOT EXISTS sources (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    item_id INTEGER NOT NULL,
    source_type TEXT NOT NULL,
    external_id TEXT NOT NULL,
    payload TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(item_id, source_type, external_id),
    FOREIGN KEY(item_id) REFERENCES items(id)
);
CREATE TABLE IF NOT EXISTS actions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    item_id INTEGER NOT NULL,
    action TEXT NOT NULL,
    actor TEXT NOT NULL,
    role TEXT NOT NULL,
    payload TEXT NOT NULL,
    summary TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY(item_id) REFERENCES items(id)
);
CREATE TABLE IF NOT EXISTS audit_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    item_id INTEGER,
    event_type TEXT NOT NULL,
    actor TEXT,
    role TEXT,
    payload TEXT NOT NULL,
    summary TEXT,
    previous_hash TEXT NOT NULL,
    event_hash TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS receipts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    item_id INTEGER NOT NULL,
    action_id INTEGER,
    receipt_number TEXT NOT NULL,
    receipt_type TEXT NOT NULL,
    payload TEXT NOT NULL,
    received_at TEXT NOT NULL,
    duplicate_count INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    UNIQUE(item_id, receipt_number),
    FOREIGN KEY(item_id) REFERENCES items(id),
    FOREIGN KEY(action_id) REFERENCES actions(id)
);
"""

# 旧库迁移：为已存在的表补摘要列（幂等）。
_COLUMN_MIGRATIONS = {
    "actions": "ALTER TABLE actions ADD COLUMN summary TEXT",
    "audit_events": "ALTER TABLE audit_events ADD COLUMN summary TEXT",
}


class Repository:
    def __init__(self, path):
        self.path = path

    def connect(self):
        conn = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        conn.row_factory = sqlite3.Row
        return conn

    def initialize(self):
        conn = self.connect()
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(_SCHEMA_SCRIPT)
            existing = {
                row["name"]
                for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
            }
            for table, ddl in _COLUMN_MIGRATIONS.items():
                if table not in existing:
                    continue
                columns = {
                    row["name"]
                    for row in conn.execute("PRAGMA table_info(%s)" % table)
                }
                if "summary" not in columns:
                    conn.execute(ddl)
        finally:
            conn.close()

    def _row_to_item(self, row):
        if row is None:
            return None
        result = dict(row)
        result["payload"] = json.loads(result["payload"])
        return result

    def _last_hash(self, conn, item_id):
        row = conn.execute(
            "SELECT event_hash FROM audit_events WHERE item_id IS ? ORDER BY id DESC LIMIT 1",
            (item_id,),
        ).fetchone()
        return row["event_hash"] if row else "GENESIS"

    def append_audit(self, conn, item_id, event_type, actor, role, payload):
        previous = self._last_hash(conn, item_id)
        event = {
            "item_id": item_id,
            "event_type": event_type,
            "actor": actor,
            "role": role,
            "payload": payload,
            "created_at": now_iso(),
        }
        event_hash = audit_hash(previous, event)
        # 摘要独立于哈希载荷之外存储，回填摘要不会改动链上的哈希。
        summary = summarize_event(event)
        conn.execute(
            "INSERT INTO audit_events(item_id,event_type,actor,role,payload,summary,previous_hash,event_hash,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
            (item_id, event_type, actor, role, canonical_json(payload), summary, previous, event_hash, event["created_at"]),
        )

    def create_item(self, entity_type, stable_key, initial_status, payload, actor, role):
        conn = self.connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            try:
                conn.execute(
                    "INSERT INTO items(entity_type,stable_key,status,version,payload,created_by,created_role,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)",
                    (
                        entity_type,
                        stable_key,
                        initial_status,
                        1,
                        canonical_json(payload),
                        actor,
                        role,
                        now_iso(),
                        now_iso(),
                    ),
                )
            except sqlite3.IntegrityError:
                # 两位值班员同时提交同一处事件：UNIQUE 约束保证只有一份进链，
                # 另一份在此退回。带上已有记录 id，调用方可直接改用已有记录重试。
                conn.execute("ROLLBACK")
                existing = conn.execute(
                    "SELECT id FROM items WHERE entity_type=? AND stable_key=?",
                    (entity_type, stable_key),
                ).fetchone()
                raise ConflictError(
                    "duplicate_item",
                    "同一业务实体已经存在，请改用已有记录",
                    details={"existing_item_id": existing["id"] if existing else None, "retry": "use_existing"},
                )
            item_id = conn.execute("SELECT last_insert_rowid() AS id").fetchone()["id"]
            self.append_audit(conn, item_id, "created", actor, role, {"stable_key": stable_key})
            conn.execute("COMMIT")
            return self.get_item(item_id)
        except ConflictError:
            raise
        except Exception:
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        finally:
            conn.close()

    def get_item(self, item_id):
        conn = self.connect()
        try:
            row = conn.execute("SELECT * FROM items WHERE id=?", (item_id,)).fetchone()
            if row is None:
                raise NotFoundError("item_not_found", "业务实体不存在")
            return self._row_to_item(row)
        finally:
            conn.close()

    def list_items(self, status=None):
        conn = self.connect()
        try:
            if status:
                rows = conn.execute("SELECT * FROM items WHERE status=? ORDER BY id DESC", (status,)).fetchall()
            else:
                rows = conn.execute("SELECT * FROM items ORDER BY id DESC").fetchall()
            return [self._row_to_item(row) for row in rows]
        finally:
            conn.close()

    def add_source(self, item_id, source_type, external_id, payload, observed_at, actor, role):
        conn = self.connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            item = conn.execute("SELECT id FROM items WHERE id=?", (item_id,)).fetchone()
            if item is None:
                raise NotFoundError("item_not_found", "业务实体不存在")
            try:
                conn.execute(
                    "INSERT INTO sources(item_id,source_type,external_id,payload,observed_at,created_at) VALUES(?,?,?,?,?,?)",
                    (item_id, source_type, external_id, canonical_json(payload), observed_at, now_iso()),
                )
            except sqlite3.IntegrityError:
                raise ConflictError("duplicate_source", "同一来源记录已经提交")
            source_id = conn.execute("SELECT last_insert_rowid() AS id").fetchone()["id"]
            self.append_audit(
                conn,
                item_id,
                "source_recorded",
                actor,
                role,
                {"source_id": source_id, "source_type": source_type, "external_id": external_id},
            )
            conn.execute("COMMIT")
            return {"id": source_id, "item_id": item_id, "source_type": source_type, "external_id": external_id, "payload": payload, "observed_at": observed_at}
        except Exception:
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        finally:
            conn.close()

    def list_sources(self, item_id):
        conn = self.connect()
        try:
            rows = conn.execute("SELECT * FROM sources WHERE item_id=? ORDER BY id DESC", (item_id,)).fetchall()
            result = []
            for row in rows:
                value = dict(row)
                value["payload"] = json.loads(value["payload"])
                result.append(value)
            return result
        finally:
            conn.close()

    def apply_action(self, item_id, action, actor, role, new_status, new_payload, event_payload, expected_version=None):
        conn = self.connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute("SELECT * FROM items WHERE id=?", (item_id,)).fetchone()
            if row is None:
                raise NotFoundError("item_not_found", "业务实体不存在")
            if expected_version is not None and int(expected_version) != int(row["version"]):
                raise ConflictError("version_conflict", "记录已被其他操作更新，请重新读取")
            version = int(row["version"]) + 1
            conn.execute(
                "UPDATE items SET status=?,version=?,payload=?,updated_at=? WHERE id=?",
                (new_status, version, canonical_json(new_payload), now_iso(), item_id),
            )
            action_created_at = now_iso()
            action_summary = summarize_event({
                "event_type": action,
                "actor": actor,
                "role": role,
                "created_at": action_created_at,
                "payload": event_payload,
            })
            conn.execute(
                "INSERT INTO actions(item_id,action,actor,role,payload,summary,created_at) VALUES(?,?,?,?,?,?,?)",
                (item_id, action, actor, role, canonical_json(event_payload), action_summary, action_created_at),
            )
            self.append_audit(conn, item_id, action, actor, role, event_payload)
            conn.execute("COMMIT")
            return self.get_item(item_id)
        except Exception:
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        finally:
            conn.close()

    def audit_trail(self, item_id):
        conn = self.connect()
        try:
            rows = conn.execute("SELECT * FROM audit_events WHERE item_id=? ORDER BY id", (item_id,)).fetchall()
            result = []
            for row in rows:
                value = dict(row)
                value["payload"] = json.loads(value["payload"])
                result.append(value)
            return result
        finally:
            conn.close()

    def list_actions(self, item_id):
        conn = self.connect()
        try:
            rows = conn.execute("SELECT * FROM actions WHERE item_id=? ORDER BY id", (item_id,)).fetchall()
            result = []
            for row in rows:
                value = dict(row)
                value["payload"] = json.loads(value["payload"])
                result.append(value)
            return result
        finally:
            conn.close()

    def list_receipts(self, item_id):
        conn = self.connect()
        try:
            rows = conn.execute("SELECT * FROM receipts WHERE item_id=? ORDER BY id", (item_id,)).fetchall()
            result = []
            for row in rows:
                value = dict(row)
                value["payload"] = json.loads(value["payload"])
                result.append(value)
            return result
        finally:
            conn.close()

    def add_receipt(self, item_id, receipt_number, receipt_type, payload, received_at, action_id, actor, role):
        """登记回执。同一回执编号只入账一次；晚到的同编号回执不重复入账，
        仅累加 duplicate_count 并记一条审计，返回已有记录（duplicate=True）。"""
        conn = self.connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            item = conn.execute("SELECT id FROM items WHERE id=?", (item_id,)).fetchone()
            if item is None:
                raise NotFoundError("item_not_found", "业务实体不存在")
            if action_id is not None:
                action = conn.execute(
                    "SELECT id FROM actions WHERE id=? AND item_id=?", (action_id, item_id)
                ).fetchone()
                if action is None:
                    raise NotFoundError("action_not_found", "关联的处置动作不存在")
            try:
                conn.execute(
                    "INSERT INTO receipts(item_id,action_id,receipt_number,receipt_type,payload,received_at,created_at) VALUES(?,?,?,?,?,?,?)",
                    (item_id, action_id, receipt_number, receipt_type, canonical_json(payload), received_at, now_iso()),
                )
            except sqlite3.IntegrityError:
                # 同一份回执晚到：不重复入账，只记一次重复。
                conn.execute(
                    "UPDATE receipts SET duplicate_count = duplicate_count + 1 WHERE item_id=? AND receipt_number=?",
                    (item_id, receipt_number),
                )
                existing = conn.execute(
                    "SELECT * FROM receipts WHERE item_id=? AND receipt_number=?",
                    (item_id, receipt_number),
                ).fetchone()
                dup_payload = {
                    "receipt_number": receipt_number,
                    "receipt_type": existing["receipt_type"],
                    "duplicate_count": existing["duplicate_count"],
                }
                self.append_audit(conn, item_id, "receipt_duplicate", actor, role, dup_payload)
                conn.execute("COMMIT")
                result = dict(existing)
                result["payload"] = json.loads(result["payload"])
                result["duplicate"] = True
                return result
            receipt_id = conn.execute("SELECT last_insert_rowid() AS id").fetchone()["id"]
            self.append_audit(
                conn,
                item_id,
                "receipt_recorded",
                actor,
                role,
                {"receipt_id": receipt_id, "receipt_number": receipt_number, "receipt_type": receipt_type, "action_id": action_id},
            )
            conn.execute("COMMIT")
            row = conn.execute("SELECT * FROM receipts WHERE id=?", (receipt_id,)).fetchone()
            result = dict(row)
            result["payload"] = json.loads(result["payload"])
            result["duplicate"] = False
            return result
        except Exception:
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        finally:
            conn.close()

    def backfill_summaries(self):
        """按时间顺序为缺少摘要的旧记录回填摘要。只写 summary 列，不改动载荷与哈希，
        回填期间旧记录仍可读。返回两类记录各自回填的条数。"""
        conn = self.connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            audit_count = 0
            audit_rows = conn.execute(
                "SELECT * FROM audit_events WHERE summary IS NULL ORDER BY created_at ASC, id ASC"
            ).fetchall()
            for row in audit_rows:
                event = {
                    "event_type": row["event_type"],
                    "actor": row["actor"],
                    "role": row["role"],
                    "created_at": row["created_at"],
                    "payload": json.loads(row["payload"]),
                }
                conn.execute("UPDATE audit_events SET summary=? WHERE id=?", (summarize_event(event), row["id"]))
                audit_count += 1
            action_count = 0
            action_rows = conn.execute(
                "SELECT * FROM actions WHERE summary IS NULL ORDER BY created_at ASC, id ASC"
            ).fetchall()
            for row in action_rows:
                action = {
                    "action": row["action"],
                    "actor": row["actor"],
                    "role": row["role"],
                    "created_at": row["created_at"],
                    "payload": json.loads(row["payload"]),
                }
                conn.execute("UPDATE actions SET summary=? WHERE id=?", (summarize_action(action), row["id"]))
                action_count += 1
            conn.execute("COMMIT")
            return {"audit_events": audit_count, "actions": action_count}
        except Exception:
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        finally:
            conn.close()

    def verify_audit_chain(self, item_id):
        """重算每条审计事件的哈希并校验前后链接是否一致。摘要不参与哈希，
        因此回填摘要不会影响校验结果。"""
        conn = self.connect()
        try:
            rows = conn.execute(
                "SELECT * FROM audit_events WHERE item_id=? ORDER BY id ASC", (item_id,)
            ).fetchall()
            previous = "GENESIS"
            for row in rows:
                event = {
                    "item_id": row["item_id"],
                    "event_type": row["event_type"],
                    "actor": row["actor"],
                    "role": row["role"],
                    "payload": json.loads(row["payload"]),
                    "created_at": row["created_at"],
                }
                expected_hash = audit_hash(previous, event)
                if row["previous_hash"] != previous or expected_hash != row["event_hash"]:
                    return {
                        "valid": False,
                        "item_id": item_id,
                        "length": len(rows),
                        "broken_at": row["id"],
                    }
                previous = row["event_hash"]
            return {"valid": True, "item_id": item_id, "length": len(rows)}
        finally:
            conn.close()

    def reconcile_receipts(self, item_id):
        """按编号逐条对账：列出需要回执的处置动作、已入账回执、
        缺回执的动作（missing）与重复入账的回执编号（duplicates）。"""
        from . import rules

        conn = self.connect()
        try:
            item = conn.execute("SELECT id FROM items WHERE id=?", (item_id,)).fetchone()
            if item is None:
                raise NotFoundError("item_not_found", "业务实体不存在")
            actions = conn.execute(
                "SELECT * FROM actions WHERE item_id=? ORDER BY id ASC", (item_id,)
            ).fetchall()
            receipts = conn.execute(
                "SELECT * FROM receipts WHERE item_id=? ORDER BY id ASC", (item_id,)
            ).fetchall()

            expected = []
            for action_row in actions:
                if action_row["action"] in rules.RECEIPT_REQUIRED_ACTIONS:
                    expected.append({
                        "action_id": action_row["id"],
                        "action": action_row["action"],
                        "actor": action_row["actor"],
                        "created_at": action_row["created_at"],
                        "matched": False,
                        "receipt_id": None,
                        "receipt_number": None,
                    })

            received = []
            for receipt_row in receipts:
                received.append({
                    "id": receipt_row["id"],
                    "receipt_number": receipt_row["receipt_number"],
                    "receipt_type": receipt_row["receipt_type"],
                    "action_id": receipt_row["action_id"],
                    "received_at": receipt_row["received_at"],
                    "duplicate_count": receipt_row["duplicate_count"],
                })

            # 逐条匹配：优先按 action_id，其次按回执类型对应到同类型未匹配动作。
            for receipt_row in receipts:
                target = None
                if receipt_row["action_id"] is not None:
                    for candidate in expected:
                        if candidate["action_id"] == receipt_row["action_id"] and not candidate["matched"]:
                            target = candidate
                            break
                if target is None:
                    mapped_action = rules.RECEIPT_TYPE_TO_ACTION.get(receipt_row["receipt_type"])
                    if mapped_action:
                        for candidate in expected:
                            if candidate["action"] == mapped_action and not candidate["matched"]:
                                target = candidate
                                break
                if target is not None:
                    target["matched"] = True
                    target["receipt_id"] = receipt_row["id"]
                    target["receipt_number"] = receipt_row["receipt_number"]

            missing = [entry for entry in expected if not entry["matched"]]
            duplicates = [
                {
                    "receipt_number": receipt_row["receipt_number"],
                    "receipt_type": receipt_row["receipt_type"],
                    "duplicate_count": receipt_row["duplicate_count"],
                }
                for receipt_row in receipts
                if receipt_row["duplicate_count"] > 0
            ]
            return {
                "item_id": item_id,
                "expected": expected,
                "received": received,
                "missing": missing,
                "duplicates": duplicates,
                # 回执只记一次，因此"缺"是对账不平的唯一决定项；重复另列提示。
                "balanced": not missing,
            }
        finally:
            conn.close()

    def state_summary(self):
        conn = self.connect()
        try:
            counts = {}
            for row in conn.execute("SELECT status, COUNT(*) AS total FROM items GROUP BY status").fetchall():
                counts[row["status"]] = row["total"]
            return {"counts": counts, "items": self.list_items()}
        finally:
            conn.close()
