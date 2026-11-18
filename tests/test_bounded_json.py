import json
import unittest

from egress_guard.bounded_json import loads


class BoundedJSONTests(unittest.TestCase):
    def test_quoted_brackets_escapes_and_unicode_do_not_consume_structure_budget(self):
        value = {"text": '[{"quoted":"\\\\\\\""}]' * 100, "unicode": "café", "value": 1.25}
        raw = json.dumps(value).encode()
        self.assertEqual(loads(raw, limit=10000), value)
        self.assertEqual(loads(b"[" * 16 + b"0" + b"]" * 16, limit=100), [[[[[[[[[[[[[[[[0]]]]]]]]]]]]]]]])

    def test_depth_and_structure_are_bounded_before_json_decoder_runs(self):
        from unittest.mock import patch
        for raw in (b"[" * 17 + b"0" + b"]" * 17, b"[" + b"0," * 100001 + b"0]"):
            with self.subTest(size=len(raw)), patch("egress_guard.bounded_json.json.loads") as decode:
                with self.assertRaises(ValueError):
                    loads(raw, limit=300000)
                decode.assert_not_called()

    def test_size_duplicates_nonfinite_and_excessive_integer_are_refused(self):
        for raw, limit in ((b"{}", 1), (b'{"a":1,"a":2}', 100), (b"1e999", 100),
                           (b"NaN", 100), (b"1" * 33, 100), (b"\xff", 100)):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                loads(raw, limit=limit)


if __name__ == "__main__":
    unittest.main()
