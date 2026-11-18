import contextlib
from email.message import Message
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch
import urllib.error
import urllib.parse

from egress_guard import cli, sponsors

VIDEO = "abcdefghijk"
COLLISION = "x0000048073"


def segment(start=10, end=20, category="sponsor", duration=120):
    return {"category": category, "actionType": "skip", "segment": [start, end],
            "videoDuration": duration, "UUID": "not-exported", "votes": 7, "description": "not-exported"}


def bucket(*segments, video=VIDEO):
    return [{"videoID": video, "segments": list(segments) or [segment()]}]


class Reply(io.BytesIO):
    def __init__(self, raw, status=200, headers=None):
        super().__init__(raw)
        self.status = status
        self.headers = Message()
        for key, value in (headers if headers is not None else [("Content-Type", "application/json"),
                                                               ("Content-Length", str(len(raw)))]):
            self.headers[key] = value


class SponsorTests(unittest.TestCase):
    def test_exact_video_selected_locally_without_exporting_collision_or_provider_fields(self):
        self.assertEqual(hashlib.sha256(VIDEO.encode()).hexdigest()[:4], hashlib.sha256(COLLISION.encode()).hexdigest()[:4])
        result = sponsors.timing_export(VIDEO, 120, bucket(video=COLLISION) + bucket(segment(30, 40), segment()))
        self.assertEqual(result["videoId"], VIDEO)
        self.assertEqual([row["start"] for row in result["segments"]], [10, 30])
        self.assertEqual(set(result["segments"][0]), {"start", "end", "category", "actionType"})
        self.assertEqual(result["source"]["licenseUrl"], sponsors.LICENSE)
        self.assertEqual(result["source"]["provider"], "SponsorBlock")
        for value in (COLLISION, "not-exported", "UUID", "votes", "description"):
            self.assertNotIn(value, json.dumps(result))

    def test_missing_results_never_claim_no_sponsors(self):
        for payload in ([], bucket(video=COLLISION)):
            with self.subTest(payload=payload), self.assertRaisesRegex(ValueError, "does not mean"):
                sponsors.timing_export(VIDEO, 120, payload)

    def test_invalid_local_inputs_do_not_send_a_request(self):
        for video, duration in (("https://youtube.com/watch?v=" + VIDEO, 120), (VIDEO + "\n", 120),
                                ("あ" * 11, 120), (None, 120), (VIDEO, True), (VIDEO, 0),
                                (VIDEO, 86401), (VIDEO, float("nan")), (VIDEO, float("inf")),
                                (VIDEO, 10 ** 400)):
            with self.subTest(video=video, duration=duration), patch.object(sponsors, "_fetch") as network:
                with self.assertRaises(ValueError):
                    sponsors.fetch_suggestions(video, duration)
                network.assert_not_called()

    def test_malformed_ambiguous_or_wrong_bucket_is_rejected(self):
        invalid = (None, {}, [None], bucket(video="lmnopqrstuv"), bucket() + bucket(),
                   [{"videoID": VIDEO, "segments": []}], bucket() * 1025,
                   [{"videoID": VIDEO, "segments": [segment()] * 101}],
                   [{"videoID": COLLISION, "segments": [segment()] * 1001}])
        for payload in invalid:
            with self.subTest(kind=type(payload)), self.assertRaises(ValueError):
                sponsors.timing_export(VIDEO, 120, payload)

    def test_unknown_or_stale_durations_are_rejected(self):
        for duration in (None, 0, False, "120", 122, float("nan"), float("inf"), 10 ** 400):
            with self.subTest(duration=duration), self.assertRaises(ValueError):
                sponsors.timing_export(VIDEO, 120, bucket(segment(duration=duration)))
        self.assertEqual(sponsors.timing_export(VIDEO, 120, bucket(segment(duration=119.5)))["duration"], 120)

    def test_unrequested_categories_actions_and_types_are_rejected(self):
        for field, value in (("category", []), ("category", None), ("category", "intro"),
                             ("category", "selfpromo"), ("actionType", "mute"), ("actionType", False)):
            row = segment()
            row[field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                sponsors.timing_export(VIDEO, 120, bucket(row))
        self.assertEqual(sponsors.timing_export(VIDEO, 120, bucket(segment(category="selfpromo")),
                         include_selfpromo=True)["segments"][0]["category"], "selfpromo")

    def test_out_of_range_overlapping_and_near_whole_video_intervals_are_rejected(self):
        for interval in ([True, 20], [10, 10], [-1, 20], [10, 121], [float("inf"), 20],
                         [10 ** 400, 20], [10], "10,20", [None, 20]):
            row = segment()
            row["segment"] = interval
            with self.subTest(interval=interval), self.assertRaises(ValueError):
                sponsors.timing_export(VIDEO, 120, bucket(row))
        for payload in (bucket(segment(10, 20), segment(19, 30)), bucket(segment(0, 96)),
                        bucket(segment(0, 50), segment(50, 100))):
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                sponsors.timing_export(VIDEO, 120, payload)
        self.assertEqual(len(sponsors.timing_export(VIDEO, 120, bucket(segment(10, 20), segment(20, 30)))["segments"]), 2)

    def test_json_duplicate_nonfinite_invalid_and_deep_payloads_are_rejected(self):
        for raw in (b'{"videoID":"a","videoID":"b"}', b"[NaN]", b"[Infinity]", b"\xff", b"{", b"[" * 2000 + b"]" * 2000):
            with self.subTest(raw=raw[:30]), self.assertRaises(ValueError):
                sponsors._decode(raw)

    def test_request_sends_only_four_hex_prefix_and_explicit_categories(self):
        for selfpromo in (False, True):
            reply = Reply(json.dumps(bucket()).encode())
            captured = []
            class Opener:
                def open(self, request, timeout):
                    captured.append((request, timeout))
                    return reply
            with patch.object(sponsors.urllib.request, "build_opener", return_value=Opener()):
                sponsors.fetch_suggestions(VIDEO, 120, include_selfpromo=selfpromo)
            request, timeout = captured[0]
            parsed = urllib.parse.urlsplit(request.full_url)
            self.assertEqual((parsed.scheme, parsed.netloc, parsed.path), ("https", "sponsor.ajay.app", "/api/skipSegments/ca2f"))
            query = urllib.parse.parse_qs(parsed.query)
            self.assertEqual(json.loads(query["categories"][0]), ["sponsor", "selfpromo"] if selfpromo else ["sponsor"])
            self.assertEqual(query["actionTypes"], ['["skip"]'])
            self.assertEqual(query["service"], ["YouTube"])
            self.assertNotIn(VIDEO, request.full_url)
            self.assertEqual(timeout, 10)
            self.assertIsNone(request.data)
            self.assertFalse(any(key.lower() in {"cookie", "authorization", "referer"} for key in request.headers))

    def test_statuses_and_http_error_streams_are_closed(self):
        for status, body, message in ((404, b"[]", "does not mean"), (404, b"{}", "invalid empty"),
                                      (301, b"[]", "refused"), (429, b"[]", "refused"), (503, b"[]", "refused")):
            stream = io.BytesIO(body)
            headers = Message()
            headers["Content-Type"] = "application/json"
            headers["Content-Length"] = str(len(body))
            error = urllib.error.HTTPError("https://sponsor.ajay.app", status, "test", headers, stream)
            with self.subTest(status=status, body=body), patch.object(
                    sponsors.urllib.request.OpenerDirector, "open", side_effect=error):
                with self.assertRaisesRegex(ValueError, message):
                    sponsors.fetch_suggestions(VIDEO, 120)
                self.assertTrue(stream.closed)
        self.assertIsNone(sponsors._NoRedirect().redirect_request(None, None, 301, None, None, "https://other.invalid"))

    def test_malformed_redirect_location_is_refused_before_url_parsing(self):
        headers = Message()
        headers["Location"] = "https://[fixture-host]/"
        handler = sponsors._NoRedirect()
        for status in (301, 302, 303, 307, 308):
            with self.subTest(status=status):
                self.assertIsNone(getattr(handler, f"http_error_{status}")(None, None, status, "redirect", headers))

    def test_dash_prefixed_id_uses_explicit_argument_separator(self):
        with patch.object(sponsors, "fetch_suggestions", return_value={}) as fetch, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(cli.main(["sponsor-fetch", "--duration", "120", "--", "-abcdefghij"]), 0)
        fetch.assert_called_once_with("-abcdefghij", 120, include_selfpromo=False)

    def test_wrong_type_framing_sizes_and_truncation_are_rejected(self):
        raw = json.dumps(bucket()).encode()
        variants = (
            [("Content-Type", "text/plain")], [("Content-Type", "application/json"), ("Content-Length", "-1")],
            [("Content-Type", "application/json"), ("Content-Length", str(len(raw) + 1))],
            [("Content-Type", "application/json"), ("Content-Length", "99999999")],
            [("Content-Type", "application/json"), ("Content-Length", str(len(raw))), ("Content-Length", str(len(raw)))],
            [("Content-Type", "application/json"), ("Content-Length", str(len(raw))), ("Transfer-Encoding", "chunked")],
            [("Content-Type", "application/json"), ("Transfer-Encoding", "gzip")],
            [("Content-Type", "application/json"), ("Content-Encoding", "gzip")],
        )
        for headers in variants:
            reply = Reply(raw, headers=headers)
            opener = type("Opener", (), {"open": lambda *_args, **_kwargs: reply})()
            with self.subTest(headers=headers), patch.object(sponsors.urllib.request, "build_opener", return_value=opener):
                with self.assertRaises(ValueError):
                    sponsors.fetch_suggestions(VIDEO, 120)
                self.assertTrue(reply.closed)
        reply = Reply(b" " * (sponsors.MAX_BYTES + 1), headers=[("Content-Type", "application/json")])
        with self.assertRaises(ValueError), sponsors.ResponseDeadline(1) as deadline:
            sponsors._read_reply(reply, deadline)

    def test_transport_failure_and_response_deadline_never_produce_an_export(self):
        with patch.object(sponsors.urllib.request.OpenerDirector, "open", side_effect=TimeoutError):
            with self.assertRaisesRegex(ValueError, "lookup failed"):
                sponsors.fetch_suggestions(VIDEO, 120)
        reply = Reply(b"[]")
        with patch.object(sponsors.ResponseDeadline, "check", side_effect=TimeoutError), sponsors.ResponseDeadline(1) as deadline:
            with self.assertRaises(TimeoutError):
                sponsors._read_reply(reply, deadline)

    def test_atomic_new_file_preserves_existing_files_and_links(self):
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "timings.json"
            payload = sponsors.timing_export(VIDEO, 120, bucket())
            sponsors.save_export(destination, payload)
            self.assertEqual(json.loads(destination.read_text()), payload)
            if os.name != "nt":
                self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o600)
            before = destination.read_bytes()
            with self.assertRaises(FileExistsError):
                sponsors.save_export(destination, {"different": True})
            self.assertEqual(destination.read_bytes(), before)
            link = Path(temporary) / "dangling.json"
            link.symlink_to(Path(temporary) / "absent.json")
            with self.assertRaises(FileExistsError):
                sponsors.save_export(link, payload)
            self.assertTrue(link.is_symlink())
            self.assertEqual(sorted(path.name for path in Path(temporary).iterdir()), ["dangling.json", "timings.json"])

    def test_cli_success_and_failure_preserve_output_boundary(self):
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "timings.json"
            for error in (None, ValueError("No suggestions")):
                out, err = io.StringIO(), io.StringIO()
                options = {"side_effect": error} if error else {"return_value": sponsors.timing_export(VIDEO, 120, bucket())}
                with patch.object(sponsors, "fetch_suggestions", **options), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                    result = cli.main(["sponsor-fetch", VIDEO, "--duration", "120", "--output", str(destination)])
                self.assertEqual(result, 1 if error else 0)
                if not error:
                    original = destination.read_bytes()
                else:
                    self.assertEqual(destination.read_bytes(), original)
                    self.assertEqual(out.getvalue(), "")

    def test_existing_output_is_refused_before_network_access(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "existing.json"
            path.write_text("keep")
            with patch.object(sponsors, "fetch_suggestions") as network, contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(cli.main(["sponsor-fetch", VIDEO, "--duration", "120", "--output", str(path)]), 1)
                network.assert_not_called()
            self.assertEqual(path.read_text(), "keep")


if __name__ == "__main__":
    unittest.main()
