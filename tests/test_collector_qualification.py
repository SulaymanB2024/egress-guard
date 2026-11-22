"""Real collector qualification must reject a powerless identifier extractor."""

from pathlib import Path
import runpy
import unittest
from unittest.mock import patch

from privacy_lab import Collector


class CollectorQualificationTests(unittest.TestCase):
    def test_missing_observed_identifiers_fail_both_real_qualification_arms(self):
        script = Path(__file__).resolve().parents[1] / "scripts" / "qualify-collector-lab.py"
        qualify = runpy.run_path(str(script))["qualify"]
        original_record = Collector.record
        erased_identifiers = 0

        def lose_identifiers(collector, *args, **kwargs):
            nonlocal erased_identifiers
            result = original_record(collector, *args, **kwargs)
            # Leave real TLS traffic, body lengths, event inventory, responses,
            # connection byte counters and proxy route evidence untouched.
            with collector.lock:
                for event in collector.events:
                    erased_identifiers += len(event["identifiers"])
                    event["identifiers"] = []
                    event["distinct_identifier_bytes"] = 0
            return result

        with patch.object(Collector, "record", lose_identifiers):
            result = qualify()

        self.assertGreater(erased_identifiers, 0, "The extraction fault must actually occur")
        self.assertEqual(result["status"], "FAIL")
        self.assertEqual(set(result["arms"]), {"baseline", "protected"})
        for name, expected_events in (("baseline", 24), ("protected", 16)):
            with self.subTest(arm=name):
                arm = result["arms"][name]
                self.assertEqual(arm["status"], "FAIL")
                self.assertEqual(arm["received_events"], expected_events)
                self.assertGreater(arm["collector_application_bytes"], 0)
                self.assertFalse(arm["overflow"])
                self.assertEqual(arm["unexpected_handler_errors"], 0)
                score = arm["all_observed_channels_linkability"]
                self.assertEqual((score["positive_pairs"], score["negative_pairs"]), (4, 12))
                self.assertEqual((score["true_matches"], score["false_matches"]), (0, 0))
        self.assertNotIn("keep aggregate exact-token linkability at 1.0", result["residual"])


if __name__ == "__main__":
    unittest.main()
