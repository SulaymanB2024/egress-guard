"""A broken extractor must never earn a successful channel qualification."""
from pathlib import Path
import runpy
import unittest
from unittest.mock import patch

from privacy_lab import Collector


class ChannelQualificationTests(unittest.TestCase):
    def test_erased_identifiers_fail_every_delivered_collector_channel(self):
        qualify = runpy.run_path(str(Path(__file__).resolve().parents[1] / "scripts" / "qualify-channel-lab.py"))["qualify"]
        original = Collector.record
        erased = 0

        def lose_identifiers(collector, *args, **kwargs):
            nonlocal erased
            result = original(collector, *args, **kwargs)
            with collector.lock:
                for event in collector.events:
                    erased += len(event["identifiers"])
                    event["identifiers"] = []
                    event["identifier_sources"] = {"url": [], "headers": [], "body": []}
                    event["distinct_identifier_bytes"] = 0
            return result

        with patch.object(Collector, "record", lose_identifiers):
            result = qualify()
        self.assertGreater(erased, 0)
        self.assertEqual(result["status"], "FAIL")
        self.assertEqual(result["native_chrome"], "not_executed")
        for name, arm in result["arms"].items():
            self.assertEqual(arm["status"], "FAIL")
            self.assertTrue(arm["byte_conservation"])
            self.assertEqual(arm["functional_responses"], {"passed": 16, "expected": 16})
            self.assertEqual(arm["same_tls_connection_visits"], {"passed": 8, "expected": 8})
            for channel, row in arm["matrix"].items():
                if name == "protected_proxy" and channel == "third_party_collector":
                    self.assertEqual(row["bytes_delivered"], 0)
                    continue
                self.assertGreater(row["bytes_delivered"], 0)
                self.assertEqual(row["status"], "FAIL")
                self.assertEqual(row["cross_site_matches"], 0)
                self.assertEqual((row["positive_pairs"], row["negative_pairs"]), (4, 12))
        self.assertEqual(result["residual"], "Required controls did not all pass.")


if __name__ == "__main__":
    unittest.main()
