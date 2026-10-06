import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from src.repository import Repository
from src.service import Service
from src.domain import ConflictError, DomainError


class FailureTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp.close()
        self.repo = Repository(self.tmp.name)
        self.repo.initialize()
        self.service = Service(self.repo)
        self.payload = {
            "pipeline_id": "P-2",
            "segment_id": "S-4",
            "reported_at": "2026-09-27T09:00:00+00:00",
            "pressure_drop_kpa": 20,
            "sensor_value_ppm": 50,
            "odor_reports": 1,
            "reporter": "dispatch-2",
        }

    def tearDown(self):
        os.unlink(self.tmp.name)

    def test_duplicate_and_valve_conflict(self):
        item = self.service.create_item(self.payload, "d", "dispatcher")
        with self.assertRaises(ConflictError):
            self.service.create_item(self.payload, "d", "dispatcher")
        item["payload"]["valve_status_conflict"] = False
        item = self.service.act(item["id"], "verify", {"field_confirmed": True}, "r", "responder", item["version"])
        with self.assertRaises(DomainError) as context:
            self.service.act(item["id"], "isolate", {"valve_sequence": ["V-1"]}, "s", "supervisor", item["version"])
        self.assertEqual(context.exception.code, "valve_sequence_required")

    def test_version_conflict_and_permission(self):
        item = self.service.create_item(self.payload, "d", "dispatcher")
        with self.assertRaises(DomainError) as context:
            self.service.act(item["id"], "verify", {"field_confirmed": True}, "x", "sensor", item["version"])
        self.assertEqual(context.exception.status, 403)
        item = self.service.act(item["id"], "verify", {"field_confirmed": True}, "r", "responder", item["version"])
        with self.assertRaises(ConflictError):
            self.service.act(item["id"], "isolate", {"valve_sequence": ["V-1", "V-2"]}, "s", "supervisor", item["version"] - 1)


if __name__ == "__main__":
    unittest.main()
