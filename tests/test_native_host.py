import io
import json
import os
from pathlib import Path
import socket
import struct
import tempfile
import time
import unittest
from unittest.mock import patch

from egress_guard import native_host
from egress_guard.health import proxy_health
from egress_guard.feeds import CachedFeed


def frame(value):
    raw = json.dumps(value).encode()
    return struct.pack("=I", len(raw)) + raw


@unittest.skipUnless(os.name == "posix" and hasattr(os, "O_NOFOLLOW"), "private POSIX registration")
class NativeHostTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.home = Path(temporary.name)
        self.state = self.home / "state"
        self.extension_id = "a" * 32
        self.origin = native_host.extension_origin(self.extension_id)
        for setting in (patch.object(native_host.Path, "home", return_value=self.home),
                        patch.dict(os.environ, {"EGRESS_GUARD_DATA": str(self.state),
                                                "EGRESS_GUARD_CONFIG": str(self.state / "config.toml")}),
                        patch.object(native_host.sys, "platform", "linux")):
            setting.start()
            self.addCleanup(setting.stop)

    def register(self):
        return native_host.register(self.extension_id)

    def test_explicit_registration_has_only_exact_origin_and_idempotent_cleanup(self):
        result = self.register()
        manifest = Path(result["manifest"])
        data = json.loads(manifest.read_text())
        self.assertEqual(data["allowed_origins"], [self.origin])
        self.assertEqual(data["name"], native_host.HOST_NAME)
        self.assertTrue(Path(data["path"]).is_absolute())
        self.assertEqual(Path(data["path"]).stat().st_mode & 0o777, 0o700)
        self.assertEqual(manifest.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.register(), result)
        self.assertFalse((self.state / "config.toml").exists())
        self.assertFalse((self.state / "dashboard-token").exists())
        native_host.unregister(self.extension_id)
        self.assertFalse(manifest.exists())
        self.assertEqual(list((self.state / "native-host").iterdir()), [])

    def test_unknown_origin_is_rejected_before_reading_or_returning_status(self):
        self.register()
        for origin in ("chrome-extension://" + "b" * 32 + "/", self.origin + "page.html",
                       self.origin + "?request=status", "https://example.test", "*"):
            incoming, outgoing = io.BytesIO(frame({"schema": 1, "command": "status"})), io.BytesIO()
            with self.subTest(origin=origin), patch.object(native_host, "status_receipt") as status:
                with self.assertRaises(ValueError):
                    native_host.serve(origin, incoming=incoming, outgoing=outgoing)
                status.assert_not_called()
                self.assertEqual(incoming.tell(), 0)
                self.assertEqual(outgoing.getvalue(), b"")

    def test_one_bounded_frame_and_capability_contract(self):
        self.register()
        request = frame({"schema": 1, "command": "capabilities"})
        incoming, outgoing = io.BytesIO(request + request), io.BytesIO()
        self.assertEqual(native_host.serve(self.origin, incoming=incoming, outgoing=outgoing), 0)
        self.assertEqual(incoming.tell(), len(request))
        raw = outgoing.getvalue()
        size = struct.unpack("=I", raw[:4])[0]
        self.assertEqual(size, len(raw) - 4)
        data = json.loads(raw[4:])
        self.assertTrue(data["ok"])
        self.assertFalse(data["capabilities"]["mutations"])
        self.assertFalse(data["capabilities"]["browser_profile_binding"])
        self.assertNotIn("status", data)

    def test_invalid_frames_and_mutating_requests_cannot_reach_status(self):
        self.register()
        for raw in (b"", b"\x01", struct.pack("=I", native_host.MAX_REQUEST_BYTES + 1),
                    struct.pack("=I", 10) + b"{}", struct.pack("=I", 1) + b"\xff"):
            with self.subTest(raw=raw), patch.object(native_host, "status_receipt") as status:
                with self.assertRaises(ValueError):
                    native_host.serve(self.origin, incoming=io.BytesIO(raw), outgoing=io.BytesIO())
                status.assert_not_called()
        for request in ({"schema": True, "command": "status"}, {"schema": 1, "command": "pause"},
                        {"schema": 1, "command": "status", "path": "/tmp/file"},
                        {"schema": 1, "command": "status", "url": "https://example.test"}):
            with self.subTest(request=request), patch.object(native_host, "status_receipt") as status:
                self.assertEqual(native_host.handle_request(request)["error"], "unsupported-request")
                status.assert_not_called()

    def test_incomplete_pipe_has_a_total_read_deadline(self):
        reader, writer = socket.socketpair()
        self.addCleanup(reader.close)
        self.addCleanup(writer.close)
        writer.send(b"\x01")
        with reader.makefile("rb", buffering=0) as stream:
            before = time.monotonic()
            with self.assertRaisesRegex(ValueError, "timed out"):
                native_host._read_exact(stream, 4, before + 0.05)
            self.assertLess(time.monotonic() - before, 1)

    def test_absent_state_health_is_read_only_and_does_not_probe(self):
        with patch("egress_guard.health.request_json_object") as request:
            self.assertFalse(proxy_health(18080, self.state, create_identity=False)["ready"])
            request.assert_not_called()
        self.assertFalse(self.state.exists())

    def test_receipt_requires_runtime_logging_ack_and_excludes_history(self):
        fixture = CachedFeed({"fixture.example"}, "fixture-digest", None, None)
        with patch("egress_guard.policy.load_cached_feed", return_value=fixture), patch.object(
                native_host, "proxy_health", return_value={"ready": False, "policy": None}) as health:
            first = native_host.status_receipt()
            saved = first["policy"]["saved_revision"]
            self.assertFalse(first["policy"]["applied"])
            runtime = {**first["logging"]["saved"], "applied": True,
                       "decisions": 99, "private_history": "must-never-leave"}
            health.return_value = {"ready": True, "policy": {"revision": saved, "pending": False,
                                   "complete": True, "degraded": False, "logging": runtime}}
            accepted = native_host.status_receipt()
            self.assertTrue(accepted["policy"]["applied"])
            self.assertNotIn("must-never-leave", json.dumps(accepted))
            self.assertNotIn("decisions", json.dumps(accepted))
            runtime["applied"] = False
            waiting = native_host.status_receipt()
            self.assertFalse(waiting["policy"]["applied"])
            self.assertTrue(waiting["policy"]["pending"])
            health.assert_called_with(18080, self.state, create_identity=False)
        self.assertFalse(self.state.exists())

    def test_registration_preserves_foreign_files_and_rejects_wildcards(self):
        with self.assertRaises(ValueError):
            native_host.register("*")
        self.assertFalse(self.state.exists())
        result = self.register()
        manifest = Path(result["manifest"])
        manifest.write_text('{"name":"foreign"}')
        with self.assertRaises(ValueError):
            native_host.unregister(self.extension_id)
        self.assertEqual(manifest.read_text(), '{"name":"foreign"}')
        self.assertTrue((self.state / "native-host/registration.json").exists())


if __name__ == "__main__":
    unittest.main()
