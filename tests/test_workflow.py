import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from src.repository import Repository
from src.service import Service


class WorkflowTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp.close()
        self.repo = Repository(self.tmp.name)
        self.repo.initialize()
        self.service = Service(self.repo)

    def tearDown(self):
        os.unlink(self.tmp.name)

    def test_complete_leak_workflow(self):
        item = self.service.create_item({
            "pipeline_id": "P-1",
            "segment_id": "S-8",
            "reported_at": "2026-09-27T08:00:00+00:00",
            "pressure_drop_kpa": 30,
            "sensor_value_ppm": 120,
            "odor_reports": 3,
            "reporter": "dispatch-1",
        }, "dispatch-1", "dispatcher")
        item = self.service.act(item["id"], "verify", {"field_confirmed": True}, "resp-1", "responder", item["version"])
        self.assertEqual(item["payload"]["assessment"]["level"], "critical")
        item = self.service.act(item["id"], "isolate", {"valve_sequence": ["V-1", "V-2"]}, "sup-1", "supervisor", item["version"])
        item = self.service.act(item["id"], "repair", {"work_order": "WO-1"}, "tech-1", "technician", item["version"])
        item = self.service.act(item["id"], "pressure_test", {"test_passed": True, "pressure_kpa": 150, "minimum_pressure_kpa": 100}, "tech-1", "technician", item["version"])
        item = self.service.act(item["id"], "restore", {"hazards_clear": True}, "sup-1", "supervisor", item["version"])
        self.assertEqual(item["status"], "restored")
        self.assertGreaterEqual(len(item["audit"]), 6)


if __name__ == "__main__":
    unittest.main()
