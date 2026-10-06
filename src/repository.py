import json
import sqlite3
from datetime import datetime, timezone

from .audit import GENESIS, audit_hash, canonical_json, chain_digest, content_digest
from .domain import ConflictError, NotFoundError, DomainError

# 会在审计链里产生事件、且与 actions 一一对应的动作类型
ACTION_EVENT_TYPES = (
    "verify",
    "isolate",
    "repair",
    "pressure_test",
    "restore",
    "cancel",
)
RECEIPT_STATUSES = ("expected", "received", "unexpected")
DELIVERY_RECEIVED = "received"
DELIVERY_UNEXPECTED = "unexpected"
DELIVERY_DUPLICATE = "duplicate"
DELIVERY_WRONG_ITEM = "rejected_wrong_item"


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def _columns(conn, table):
    return {row["name"] for row in conn.execute("PRAGMA table_info(%s)" % table).fetchall()}


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
            conn.executescript(
                """
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
                    created_at TEXT NOT NULL,
                    content_digest TEXT,
                    digest TEXT,
                    FOREIGN KEY(item_id) REFERENCES items(id)
                );
                CREATE TABLE IF NOT EXISTS audit_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    item_id INTEGER,
                    event_type TEXT NOT NULL,
                    actor TEXT,
                    role TEXT,
                    payload TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    event_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    action_id INTEGER,
                    action_digest TEXT,
                    receipt_id INTEGER
                );
                CREATE TABLE IF NOT EXISTS receipts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    item_id INTEGER NOT NULL,
                    receipt_no TEXT NOT NULL UNIQUE,
                    status TEXT NOT NULL,
                    issuer TEXT NOT NULL DEFAULT '',
                    document TEXT NOT NULL DEFAULT '',
                    content_digest TEXT,
                    registered_action_id INTEGER,
                    registered_at TEXT,
                    received_at TEXT,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS receipt_deliveries (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    receipt_id INTEGER NOT NULL,
                    item_id INTEGER NOT NULL,
                    actor TEXT,
                    role TEXT,
                    status TEXT NOT NULL,
                    detail TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(receipt_id) REFERENCES receipts(id),
                    FOREIGN KEY(item_id) REFERENCES items(id)
                );
                CREATE INDEX IF NOT EXISTS idx_actions_item ON actions(item_id, id);
                CREATE INDEX IF NOT EXISTS idx_receipts_item ON receipts(item_id);
                CREATE INDEX IF NOT EXISTS idx_deliveries_receipt ON receipt_deliveries(receipt_id, id);
                """
            )
            # 旧库平滑加列：旧记录仍在，摘要列先空着，交给 backfill_digests 按时间顺序回填
            self._add_column(conn, "actions", "content_digest", "TEXT")
            self._add_column(conn, "actions", "digest", "TEXT")
            self._add_column(conn, "audit_events", "action_id", "INTEGER")
            self._add_column(conn, "audit_events", "action_digest", "TEXT")
            self._add_column(conn, "audit_events", "receipt_id", "INTEGER")
        finally:
            conn.close()

    def _add_column(self, conn, table, column, ddl_type):
        if column not in _columns(conn, table):
            conn.execute("ALTER TABLE %s ADD COLUMN %s %s" % (table, column, ddl_type))

    # ------------------------------------------------------------------ #
    # 摘要与审计
    # ------------------------------------------------------------------ #

    def _action_content(self, action_row_or_dict):
        """动作摘要覆盖的内容：谁、什么角色、什么时候、对哪个事件、做了什么、提交了什么。"""
        return {
            "item_id": action_row_or_dict["item_id"],
            "action": action_row_or_dict["action"],
            "actor": action_row_or_dict["actor"],
            "role": action_row_or_dict["role"],
            "payload": json.loads(action_row_or_dict["payload"]),
            "created_at": action_row_or_dict["created_at"],
        }

    def _last_hash(self, conn, item_id):
        row = conn.execute(
            "SELECT event_hash FROM audit_events WHERE item_id IS ? ORDER BY id DESC LIMIT 1",
            (item_id,),
        ).fetchone()
        return row["event_hash"] if row else GENESIS

    def append_audit(
        self,
        conn,
        item_id,
        event_type,
        actor,
        role,
        payload,
        action_id=None,
        action_digest=None,
        receipt_id=None,
    ):
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
        cur = conn.execute(
            """
            INSERT INTO audit_events(item_id,event_type,actor,role,payload,previous_hash,
                                     event_hash,created_at,action_id,action_digest,receipt_id)
            VALUES(?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                item_id,
                event_type,
                actor,
                role,
                canonical_json(payload),
                previous,
                event_hash,
                event["created_at"],
                action_id,
                action_digest,
                receipt_id,
            ),
        )
        return cur.lastrowid, event_hash

    def _row_to_item(self, row):
        if row is None:
            return None
        result = dict(row)
        result["payload"] = json.loads(result["payload"])
        return result

    # ------------------------------------------------------------------ #
    # 事件
    # ------------------------------------------------------------------ #

    def create_item(self, entity_type, stable_key, initial_status, payload, actor, role):
        conn = self.connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            timestamp = now_iso()
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
                        timestamp,
                        timestamp,
                    ),
                )
            except sqlite3.IntegrityError:
                # 两位值班员同时报同一处事件：唯一约束只放一份进链，另一份拿到已存在记录去重试
                existing = conn.execute(
                    "SELECT id FROM items WHERE entity_type=? AND stable_key=?",
                    (entity_type, stable_key),
                ).fetchone()
                conn.execute("ROLLBACK")
                raise ConflictError(
                    "duplicate_item",
                    "同一处事件已在链中，请勿重复提交",
                    {"existing_item_id": existing["id"] if existing else None},
                )
            item_id = conn.execute("SELECT last_insert_rowid() AS id").fetchone()["id"]
            self.append_audit(conn, item_id, "created", actor, role, {"stable_key": stable_key})
            conn.execute("COMMIT")
            return self.get_item(item_id)
        except ConflictError:
            raise
        except Exception:
            self._rollback(conn)
            raise
        finally:
            conn.close()

    @staticmethod
    def _rollback(conn):
        try:
            conn.execute("ROLLBACK")
        except sqlite3.Error:
            pass

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
            self._rollback(conn)
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

    # ------------------------------------------------------------------ #
    # 处置动作（落动作时同时落内容摘要 + 链式摘要 + 审计挂钩）
    # ------------------------------------------------------------------ #

    def _register_expected_receipts(self, conn, item_id, action_id, codes, actor, role):
        timestamp = now_iso()
        for code in codes:
            try:
                cur = conn.execute(
                    """
                    INSERT INTO receipts(item_id,receipt_no,status,registered_action_id,
                                         registered_at,created_at)
                    VALUES(?,?, 'expected', ?, ?, ?)
                    """,
                    (item_id, code, action_id, timestamp, timestamp),
                )
            except sqlite3.IntegrityError:
                row = conn.execute("SELECT id, item_id, status FROM receipts WHERE receipt_no=?", (code,)).fetchone()
                raise ConflictError(
                    "receipt_no_taken",
                    "回执编号已被登记或送达: %s" % code,
                    {
                        "receipt_no": code,
                        "receipt_id": row["id"] if row else None,
                        "item_id": row["item_id"] if row else None,
                        "status": row["status"] if row else None,
                    },
                )
            receipt_id = cur.lastrowid
            self.append_audit(
                conn,
                item_id,
                "receipt_registered",
                actor,
                role,
                {"receipt_id": receipt_id, "receipt_no": code, "action_id": action_id},
                action_id=action_id,
                receipt_id=receipt_id,
            )

    def apply_action(
        self,
        item_id,
        action,
        actor,
        role,
        new_status,
        new_payload,
        event_payload,
        expected_version=None,
        expected_receipts=None,
    ):
        conn = self.connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute("SELECT * FROM items WHERE id=?", (item_id,)).fetchone()
            if row is None:
                raise NotFoundError("item_not_found", "业务实体不存在")
            if expected_version is not None and int(expected_version) != int(row["version"]):
                raise ConflictError("version_conflict", "记录已被其他操作更新，请重新读取")
            timestamp = now_iso()
            version = int(row["version"]) + 1
            conn.execute(
                "UPDATE items SET status=?,version=?,payload=?,updated_at=? WHERE id=?",
                (new_status, version, canonical_json(new_payload), timestamp, item_id),
            )
            cur = conn.execute(
                "INSERT INTO actions(item_id,action,actor,role,payload,created_at) VALUES(?,?,?,?,?,?)",
                (item_id, action, actor, role, canonical_json(event_payload), timestamp),
            )
            action_id = cur.lastrowid

            # 本事件动作链的上一条摘要（旧库未回填时从 GENESIS 重新起步，回填会补齐整链）
            prev_row = conn.execute(
                "SELECT digest FROM actions WHERE item_id=? AND digest IS NOT NULL ORDER BY id DESC LIMIT 1",
                (item_id,),
            ).fetchone()
            previous_digest = prev_row["digest"] if prev_row else GENESIS
            action_content = {
                "item_id": item_id,
                "action": action,
                "actor": actor,
                "role": role,
                "payload": event_payload,
                "created_at": timestamp,
            }
            c_digest = content_digest(action_content)
            a_digest = chain_digest(previous_digest, action_content)
            conn.execute(
                "UPDATE actions SET content_digest=?, digest=? WHERE id=?",
                (c_digest, a_digest, action_id),
            )

            self.append_audit(
                conn,
                item_id,
                action,
                actor,
                role,
                event_payload,
                action_id=action_id,
                action_digest=a_digest,
            )
            if expected_receipts:
                self._register_expected_receipts(conn, item_id, action_id, expected_receipts, actor, role)
            conn.execute("COMMIT")
            return self.get_item(item_id)
        except Exception:
            self._rollback(conn)
            raise
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

    # ------------------------------------------------------------------ #
    # 回执送达与对账
    # ------------------------------------------------------------------ #

    @staticmethod
    def _receipt_content(receipt_no, issuer, document, delivered_at):
        return {
            "receipt_no": receipt_no,
            "issuer": issuer,
            "document": document,
            "delivered_at": delivered_at,
        }

    def _record_delivery(self, conn, receipt_id, item_id, actor, role, status, detail):
        conn.execute(
            """
            INSERT INTO receipt_deliveries(receipt_id,item_id,actor,role,status,detail,created_at)
            VALUES(?,?,?,?,?,?,?)
            """,
            (receipt_id, item_id, actor, role, status, detail, now_iso()),
        )

    def deliver_receipt(self, item_id, normalized, actor, role):
        """外部回执送达。按编号去重：同一份晚到只记一次；未登记记 unexpected；串错事件退回。"""
        receipt_no = normalized["receipt_no"]
        document = normalized["document"]
        issuer = normalized["issuer"]
        conn = self.connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            if conn.execute("SELECT 1 FROM items WHERE id=?", (item_id,)).fetchone() is None:
                raise NotFoundError("item_not_found", "业务实体不存在")
            timestamp = now_iso()
            delivered_at = normalized["delivered_at"] or timestamp
            receipt = conn.execute(
                "SELECT * FROM receipts WHERE receipt_no=?", (receipt_no,)
            ).fetchone()

            if receipt is None:
                # 没有任何动作预期这份回执：登记为 unexpected，仍然入账供对账列出
                cur = conn.execute(
                    """
                    INSERT INTO receipts(item_id,receipt_no,status,issuer,document,content_digest,
                                         registered_at,received_at,created_at)
                    VALUES(?,?,'unexpected',?,?,?,NULL,?,?)
                    """,
                    (
                        item_id,
                        receipt_no,
                        issuer,
                        document,
                        content_digest(self._receipt_content(receipt_no, issuer, document, delivered_at)),
                        delivered_at,
                        timestamp,
                    ),
                )
                receipt_id = cur.lastrowid
                self.append_audit(
                    conn,
                    item_id,
                    "receipt_unexpected",
                    actor,
                    role,
                    {"receipt_id": receipt_id, "receipt_no": receipt_no, "delivered_at": delivered_at},
                    receipt_id=receipt_id,
                )
                self._record_delivery(conn, receipt_id, item_id, actor, role, DELIVERY_UNEXPECTED, "未登记的回执编号")
                conn.execute("COMMIT")
                return self.get_receipt(receipt_id), False

            receipt_id = receipt["id"]
            if receipt["item_id"] != item_id:
                # 编号真实存在，但对应的是另一处事件：拒收并留痕，提交方按回执上的归属重试
                self.append_audit(
                    conn,
                    receipt["item_id"],
                    "receipt_rejected_wrong_item",
                    actor,
                    role,
                    {
                        "receipt_id": receipt_id,
                        "receipt_no": receipt_no,
                        "attempted_item_id": item_id,
                        "owner_item_id": receipt["item_id"],
                    },
                    receipt_id=receipt_id,
                )
                self._record_delivery(
                    conn, receipt_id, item_id, actor, role, DELIVERY_WRONG_ITEM,
                    "回执属于事件 #%s，被事件 #%s 拒收" % (receipt["item_id"], item_id),
                )
                conn.execute("COMMIT")
                raise ConflictError(
                    "receipt_wrong_item",
                    "回执 %s 属于另一处事件 #%s，已拒收并留痕" % (receipt_no, receipt["item_id"]),
                    {"receipt_id": receipt_id, "owner_item_id": receipt["item_id"]},
                )

            already = conn.execute(
                "SELECT created_at FROM receipt_deliveries WHERE receipt_id=? AND status IN (?, ?) ORDER BY id LIMIT 1",
                (receipt_id, DELIVERY_RECEIVED, DELIVERY_UNEXPECTED),
            ).fetchone()
            if already is not None:
                # 同一份回执晚到：正文只记一次，重复送达单列一条留痕
                self._record_delivery(
                    conn, receipt_id, item_id, actor, role, DELIVERY_DUPLICATE,
                    "同一份回执重复送达，正文保持首次记录",
                )
                conn.execute("COMMIT")
                raise ConflictError(
                    "duplicate_receipt",
                    "回执 %s 已登记过，重复送达只留痕不覆盖" % receipt_no,
                    {"receipt_id": receipt_id, "first_at": already["created_at"]},
                )

            # 预期回执首次送达：补正文、挂摘要、进审计链
            conn.execute(
                """
                UPDATE receipts
                   SET status='received', issuer=?, document=?, content_digest=?, received_at=?
                 WHERE id=?
                """,
                (
                    issuer,
                    document,
                    content_digest(self._receipt_content(receipt_no, issuer, document, delivered_at)),
                    delivered_at,
                    receipt_id,
                ),
            )
            self.append_audit(
                conn,
                item_id,
                "receipt_received",
                actor,
                role,
                {"receipt_id": receipt_id, "receipt_no": receipt_no, "delivered_at": delivered_at},
                receipt_id=receipt_id,
            )
            self._record_delivery(conn, receipt_id, item_id, actor, role, DELIVERY_RECEIVED, "")
            conn.execute("COMMIT")
            return self.get_receipt(receipt_id), True
        except ConflictError:
            raise
        except Exception:
            self._rollback(conn)
            raise
        finally:
            conn.close()

    def get_receipt(self, receipt_id):
        conn = self.connect()
        try:
            row = conn.execute("SELECT * FROM receipts WHERE id=?", (receipt_id,)).fetchone()
            if row is None:
                raise NotFoundError("receipt_not_found", "回执不存在")
            return dict(row)
        finally:
            conn.close()

    def list_receipts(self, item_id):
        conn = self.connect()
        try:
            rows = conn.execute("SELECT * FROM receipts WHERE item_id=? ORDER BY id", (item_id,)).fetchall()
            return [dict(row) for row in rows]
        finally:
            conn.close()

    def list_deliveries(self, item_id):
        conn = self.connect()
        try:
            rows = conn.execute(
                """
                SELECT d.*, r.receipt_no
                  FROM receipt_deliveries d
                  JOIN receipts r ON r.id = d.receipt_id
                 WHERE d.item_id=?
                 ORDER BY d.id
                """,
                (item_id,),
            ).fetchall()
            return [dict(row) for row in rows]
        finally:
            conn.close()

    def reconciliation(self, item_id):
        """按回执编号逐条对账：已到、缺失、未登记、重复送达、串事件拒收。"""
        conn = self.connect()
        try:
            if conn.execute("SELECT 1 FROM items WHERE id=?", (item_id,)).fetchone() is None:
                raise NotFoundError("item_not_found", "业务实体不存在")
            receipts = conn.execute(
                "SELECT * FROM receipts WHERE item_id=? ORDER BY receipt_no", (item_id,)
            ).fetchall()
            matched, missing, unexpected = [], [], []
            for row in receipts:
                entry = {
                    "receipt_no": row["receipt_no"],
                    "receipt_id": row["id"],
                    "registered_at": row["registered_at"],
                    "received_at": row["received_at"],
                    "content_digest": row["content_digest"],
                    "registered_action_id": row["registered_action_id"],
                }
                if row["status"] == "expected":
                    missing.append(entry)
                elif row["status"] == "received":
                    matched.append(entry)
                else:
                    unexpected.append(entry)

            delivery_rows = conn.execute(
                """
                SELECT d.*, r.receipt_no, r.item_id AS owner_item_id
                  FROM receipt_deliveries d
                  JOIN receipts r ON r.id = d.receipt_id
                 WHERE (d.item_id=? OR r.item_id=?)
                 ORDER BY d.id
                """,
                (item_id, item_id),
            ).fetchall()
            duplicates, rejected, rejected_inbound = [], [], []
            for row in delivery_rows:
                if row["status"] == DELIVERY_DUPLICATE:
                    duplicates.append({
                        "receipt_no": row["receipt_no"],
                        "receipt_id": row["receipt_id"],
                        "delivered_at": row["created_at"],
                        "actor": row["actor"],
                        "detail": row["detail"],
                    })
                elif row["status"] == DELIVERY_WRONG_ITEM:
                    entry = {
                        "receipt_no": row["receipt_no"],
                        "receipt_id": row["receipt_id"],
                        "attempted_at": row["created_at"],
                        "actor": row["actor"],
                        "attempted_item_id": row["item_id"],
                        "owner_item_id": row["owner_item_id"],
                        "detail": row["detail"],
                    }
                    if row["owner_item_id"] == item_id and row["item_id"] != item_id:
                        # 本事件的回执被送到了别处
                        rejected.append(entry)
                    elif row["item_id"] == item_id and row["owner_item_id"] != item_id:
                        # 送到本事件的回执其实属于别处
                        rejected_inbound.append(entry)

            expected_count = sum(
                1 for row in receipts
                if row["status"] in ("expected", "received")
                and row["registered_action_id"] is not None
            )
            return {
                "item_id": item_id,
                "summary": {
                    "expected": expected_count,
                    "matched": len(matched),
                    "missing": len(missing),
                    "unexpected": len(unexpected),
                    "duplicate_deliveries": len(duplicates),
                    "rejected_wrong_item": len(rejected),
                    "rejected_inbound": len(rejected_inbound),
                },
                "matched": matched,
                "missing": missing,
                "unexpected": unexpected,
                "duplicate_deliveries": duplicates,
                "rejected_wrong_item": rejected,
                "rejected_inbound": rejected_inbound,
            }
        finally:
            conn.close()

    # ------------------------------------------------------------------ #
    # 链校验
    # ------------------------------------------------------------------ #

    def verify_chain(self, item_id):
        conn = self.connect()
        try:
            if conn.execute("SELECT 1 FROM items WHERE id=?", (item_id,)).fetchone() is None:
                raise NotFoundError("item_not_found", "业务实体不存在")

            errors, pending = [], []

            # 1) 动作摘要链：逐条重算内容摘要与链式摘要
            actions = conn.execute(
                "SELECT * FROM actions WHERE item_id=? ORDER BY id", (item_id,)
            ).fetchall()
            by_action_id = {}
            previous = GENESIS
            for row in actions:
                value = dict(row)
                by_action_id[value["id"]] = value
                if not value["digest"] or not value["content_digest"]:
                    pending.append({"kind": "action_digest", "action_id": value["id"]})
                    previous = GENESIS  # 未回填时后续链暂不能连续核对
                    continue
                expected_content = content_digest(self._action_content(row))
                if expected_content != value["content_digest"]:
                    errors.append({
                        "code": "action_content_digest_mismatch",
                        "action_id": value["id"],
                    })
                expected_digest = chain_digest(previous, self._action_content(row))
                if expected_digest != value["digest"]:
                    errors.append({"code": "action_chain_broken", "action_id": value["id"]})
                previous = value["digest"]

            # 2) 审计哈希链：按存储内容逐条重算
            events = conn.execute(
                "SELECT * FROM audit_events WHERE item_id=? ORDER BY id", (item_id,)
            ).fetchall()
            receipts = {
                row["id"]: dict(row)
                for row in conn.execute("SELECT * FROM receipts WHERE item_id=?", (item_id,)).fetchall()
            }
            received_receipt_ids = set()
            previous = GENESIS
            for row in events:
                event = {
                    "item_id": row["item_id"],
                    "event_type": row["event_type"],
                    "actor": row["actor"],
                    "role": row["role"],
                    "payload": json.loads(row["payload"]),
                    "created_at": row["created_at"],
                }
                if audit_hash(previous, event) != row["event_hash"]:
                    errors.append({"code": "audit_chain_broken", "audit_event_id": row["id"]})
                previous = row["event_hash"]

                # 3) 动作 ↔ 审计 挂钩核对
                if row["action_id"] is not None:
                    action = by_action_id.get(row["action_id"])
                    if action is None:
                        errors.append({
                            "code": "audit_action_missing",
                            "audit_event_id": row["id"],
                            "action_id": row["action_id"],
                        })
                    elif row["event_type"] in ACTION_EVENT_TYPES:
                        # 动作的主事件：类型一致、摘要一致
                        if action["action"] != row["event_type"]:
                            errors.append({
                                "code": "audit_action_type_mismatch",
                                "audit_event_id": row["id"],
                                "action_id": row["action_id"],
                            })
                        if row["action_digest"] != action["digest"]:
                            errors.append({
                                "code": "action_digest_link_mismatch",
                                "audit_event_id": row["id"],
                                "action_id": row["action_id"],
                            })
                    # 其余事件（如 receipt_registered）只引用动作 id，不挂动作摘要

                # 4) 审计 ↔ 回执 挂钩核对
                if row["receipt_id"] is not None:
                    receipt = receipts.get(row["receipt_id"])
                    if receipt is None:
                        errors.append({
                            "code": "audit_receipt_missing",
                            "audit_event_id": row["id"],
                            "receipt_id": row["receipt_id"],
                        })
                    elif row["event_type"] == "receipt_received":
                        received_receipt_ids.add(row["receipt_id"])

            for receipt_id, receipt in receipts.items():
                if receipt["status"] == "received":
                    if receipt_id not in received_receipt_ids:
                        errors.append({
                            "code": "receipt_received_without_audit",
                            "receipt_id": receipt_id,
                            "receipt_no": receipt["receipt_no"],
                        })
                    expected = content_digest(self._receipt_content(
                        receipt["receipt_no"],
                        receipt["issuer"],
                        receipt["document"],
                        receipt["received_at"],
                    ))
                    if receipt["content_digest"] != expected:
                        errors.append({
                            "code": "receipt_content_digest_mismatch",
                            "receipt_id": receipt_id,
                            "receipt_no": receipt["receipt_no"],
                        })
                elif not receipt["content_digest"] and receipt["status"] == "unexpected":
                    errors.append({
                        "code": "receipt_digest_missing",
                        "receipt_id": receipt_id,
                        "receipt_no": receipt["receipt_no"],
                    })

            return {
                "item_id": item_id,
                "ok": not errors,
                "errors": errors,
                "pending_backfill": pending,
                "counts": {
                    "actions": len(actions),
                    "audit_events": len(events),
                    "receipts": len(receipts),
                },
                "head": previous,
            }
        finally:
            conn.close()

    # ------------------------------------------------------------------ #
    # 旧数据回填：按事件、按时间顺序补摘要；只 UPDATE 加列，不改旧行旧哈希
    # ------------------------------------------------------------------ #

    def backfill_digests(self, batch_size=200):
        """旧数据回填入口。按事件逐个、按时间顺序补摘要；只更新加列，旧行旧哈希不动。

        - 动作链按时间顺序整链重算（升级后、回填前的新动作曾从 GENESIS 起链，
          回填会把它们重锚到旧动作之后，保证整链连续）；
        - 旧动作型审计事件按时间顺序与旧动作一一挂钩，新挂钩列不进审计哈希输入，
          旧事件哈希原样保留；
        - 可重复执行（幂等）：已回填的内容不会重复计数。
        """
        conn = self.connect()
        try:
            stats = {"items": 0, "actions": 0, "audit_events": 0, "receipts": 0}
            item_ids = [row["id"] for row in conn.execute("SELECT id FROM items ORDER BY id").fetchall()]
            touched = False
            for item_id in item_ids:
                actions_done, events_done = self._backfill_item(conn, item_id, batch_size)
                stats["actions"] += actions_done
                stats["audit_events"] += events_done
                if actions_done or events_done:
                    touched = True
            stats["items"] = 1 if touched else len(item_ids) if stats["actions"] else 0
            # 统计有回填动作的事件数更准确
            stats["items"] = conn.execute(
                "SELECT COUNT(DISTINCT item_id) AS total FROM actions "
                "WHERE content_digest IS NOT NULL"
            ).fetchone()["total"]

            # 历史若有缺摘要的已送达/未登记回执，按现内容补内容摘要（非链式，独立可验）
            rows = conn.execute(
                "SELECT id, receipt_no, issuer, document, received_at FROM receipts "
                "WHERE content_digest IS NULL AND status != 'expected'"
            ).fetchall()
            for row in rows:
                conn.execute(
                    "UPDATE receipts SET content_digest=? WHERE id=?",
                    (content_digest(self._receipt_content(
                        row["receipt_no"], row["issuer"], row["document"], row["received_at"])),
                     row["id"]),
                )
                stats["receipts"] += 1

            stats["pending"] = conn.execute(
                "SELECT COUNT(*) AS total FROM actions WHERE digest IS NULL"
            ).fetchone()["total"]
            return stats
        finally:
            conn.close()

    def _backfill_item(self, conn, item_id, batch_size):
        """回填单个事件：动作按 id（时间顺序）整链重算，并与动作型审计事件挂钩。"""
        actions_done = 0
        events_done = 0
        offset = 0
        previous = GENESIS
        while True:
            conn.execute("BEGIN IMMEDIATE")
            try:
                actions = conn.execute(
                    "SELECT * FROM actions WHERE item_id=? ORDER BY id LIMIT ? OFFSET ?",
                    (item_id, batch_size, offset),
                ).fetchall()
                if not actions:
                    conn.execute("COMMIT")
                    break

                # 已有挂钩的“动作主事件” -> 动作（receipt_registered 等只引用动作，不算主事件）
                linked_rows = conn.execute(
                    "SELECT id, action_id FROM audit_events "
                    "WHERE item_id=? AND action_id IS NOT NULL "
                    "AND event_type IN (%s)" % ",".join("?" * len(ACTION_EVENT_TYPES)),
                    (item_id, *ACTION_EVENT_TYPES),
                ).fetchall()
                audit_by_action = {row["action_id"]: row["id"] for row in linked_rows}
                # 旧动作（无任何事件挂钩）与旧动作型事件（action_id 为空）按时间顺序一一配对
                unlinked_event_ids = [
                    row["id"]
                    for row in conn.execute(
                        "SELECT id FROM audit_events WHERE item_id=? AND action_id IS NULL "
                        "AND event_type IN (%s) ORDER BY id" % ",".join("?" * len(ACTION_EVENT_TYPES)),
                        (item_id, *ACTION_EVENT_TYPES),
                    ).fetchall()
                ]
                unlinked_action_ids = [
                    row["id"]
                    for row in conn.execute(
                        "SELECT id FROM actions WHERE item_id=? ORDER BY id", (item_id,)
                    ).fetchall()
                    if row["id"] not in audit_by_action
                ]
                legacy_pairs = dict(zip(unlinked_action_ids, unlinked_event_ids))

                for row in actions:
                    action_content = self._action_content(row)
                    c_digest = content_digest(action_content)
                    a_digest = chain_digest(previous, action_content)
                    was_missing = row["digest"] is None
                    if was_missing or row["digest"] != a_digest or row["content_digest"] != c_digest:
                        conn.execute(
                            "UPDATE actions SET content_digest=?, digest=? WHERE id=?",
                            (c_digest, a_digest, row["id"]),
                        )
                        if was_missing:
                            actions_done += 1
                    previous = a_digest

                    audit_pk = audit_by_action.get(row["id"]) or legacy_pairs.get(row["id"])
                    if audit_pk is not None:
                        linked = conn.execute(
                            "SELECT action_digest FROM audit_events WHERE id=?", (audit_pk,)
                        ).fetchone()
                        if linked["action_digest"] != a_digest:
                            conn.execute(
                                "UPDATE audit_events SET action_id=?, action_digest=? WHERE id=?",
                                (row["id"], a_digest, audit_pk),
                            )
                            if linked["action_digest"] is None:
                                events_done += 1
                conn.execute("COMMIT")
                offset += len(actions)
                if len(actions) < batch_size:
                    break
            except Exception:
                self._rollback(conn)
                raise
        return actions_done, events_done

    # ------------------------------------------------------------------ #

    def state_summary(self):
        conn = self.connect()
        try:
            counts = {}
            for row in conn.execute("SELECT status, COUNT(*) AS total FROM items GROUP BY status").fetchall():
                counts[row["status"]] = row["total"]
            return {"counts": counts, "items": self.list_items()}
        finally:
            conn.close()
