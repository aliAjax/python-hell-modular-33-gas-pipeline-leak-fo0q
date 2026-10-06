import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from src.rules import assess
from src.domain import DomainError


class RuleTest(unittest.TestCase):
    def test_leak_score_levels(self):
        critical = assess({"pressure_drop_kpa": 60, "sensor_value_ppm": 400, "odor_reports": 4})
        low = assess({"pressure_drop_kpa": 1, "sensor_value_ppm": 2, "odor_reports": 0})
        self.assertEqual(critical["level"], "critical")
        self.assertEqual(low["level"], "low")
        self.assertGreater(critical["score"], low["score"])

    def test_restore_requires_hazard_clearance(self):
        item = {
            "status": "tested",
            "payload": {"pressure_test": {"passed": True}, "valve_status_conflict": False},
        }
        from src.rules import apply_action
        with self.assertRaises(DomainError) as context:
            apply_action(item, "restore", {"hazards_clear": False}, "s", "supervisor")
        self.assertEqual(context.exception.code, "hazards_not_clear")


if __name__ == "__main__":
    unittest.main()
