"""Collector evidence and attacker-denominator checks, without a browser."""

from hashlib import sha256
import base64
import http.client
import socket
import time
import unittest

from privacy_lab import HOSTS, Lab, exact_linkability, synthetic_id


def cohort(count=3):
    return {sha256(f"visit:{site}:{subject}".encode()).hexdigest()[:24]: {"site": site, "subject": subject}
            for site in HOSTS[:2] for subject in range(count)}


class LinkabilityTests(unittest.TestCase):
    def test_empty_observations_keep_every_positive_and_negative_pair(self):
        result = exact_linkability([], cohort())
        self.assertEqual((result["positive_pairs"], result["negative_pairs"]), (3, 6))
        self.assertEqual(result["visits_without_observed_identifier"], 6)
        self.assertEqual(result["true_match_rate"], 0)
        self.assertFalse(result["threshold_chosen_from_ground_truth"])

    def test_observed_unique_ids_link_real_pairs_without_seeing_ground_truth(self):
        visits = cohort()
        events = [{"visit": visit, "case": "ga4", "identifiers": [synthetic_id(truth["subject"])]} for visit, truth in visits.items()]
        result = exact_linkability(events, visits, case="ga4")
        self.assertEqual((result["true_matches"], result["false_matches"]), (3, 0))
        # Relabeling ground truth cannot change which pairs the attacker predicts.
        swapped = {v: {**t, "subject": (t["subject"] + 1) % 3 if t["site"] == HOSTS[1] else t["subject"]} for v, t in visits.items()}
        wrong = exact_linkability(events, swapped, case="ga4")
        self.assertEqual((wrong["true_matches"], wrong["false_matches"]), (0, 3))

    def test_common_fingerprint_like_token_fails_false_match_ceiling(self):
        visits = cohort()
        events = [{"visit": visit, "identifiers": [synthetic_id(0)]} for visit in visits]
        result = exact_linkability(events, visits)
        self.assertEqual(result["true_match_rate"], 1)
        self.assertEqual(result["false_match_rate"], 1)
        self.assertFalse(result["ceiling_met_on_this_cohort"])

    def test_channel_result_does_not_hide_remaining_opaque_identity(self):
        visits = cohort()
        events = [{"visit": visit, "case": "opaque", "identifiers": [synthetic_id(t["subject"])]} for visit, t in visits.items()]
        self.assertEqual(exact_linkability(events, visits, case="ga4")["true_match_rate"], 0)
        self.assertEqual(exact_linkability(events, visits)["true_match_rate"], 1)
        self.assertEqual(exact_linkability(events[:3], visits)["positive_pairs"], 3)

    def test_invalid_or_single_identity_cohort_and_non_synthetic_values_refuse(self):
        with self.assertRaises(ValueError):
            exact_linkability([], cohort(1))
        visits = cohort()
        visit = next(iter(visits))
        with self.assertRaises(ValueError):
            exact_linkability([{"visit": visit, "identifiers": ["real-user-value"]}], visits)
        with self.assertRaises(ValueError):
            exact_linkability([], {**visits, "a" * 24: dict(visits[visit])})


class CollectorProxyTests(unittest.TestCase):
    def setUp(self):
        self.lab = Lab().__enter__()
        self.addCleanup(self.lab.close)
        self.visit = "1" * 24

    def tunnel(self, host=HOSTS[0]):
        port = self.lab.server.server_port
        connection = http.client.HTTPConnection("127.0.0.1", self.lab.proxy_port, timeout=4)
        connection.set_tunnel(host, port)
        connection.connect()
        stream = self.lab.client_tls.wrap_socket(connection.sock, server_hostname=host)
        self.assertEqual(stream.getpeercert(binary_form=True), self.lab.cert_der)
        return stream

    def request(self, host, body, *, case="opaque"):
        port = self.lab.server.server_port
        stream = self.tunnel(host)
        with stream:
            stream.sendall((f"POST /api/data?visit={self.visit}&case={case} HTTP/1.1\r\nHost: {host}:{port}\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n").encode() + body)
            response = http.client.HTTPResponse(stream)
            response.begin()
            self.assertEqual(response.status, 200)
            self.assertEqual(response.read(), b'{"ok":true}')

    def test_controlled_sink_counts_real_tls_and_proxy_route_but_not_body_inspection(self):
        token = synthetic_id(2).encode()
        self.request(HOSTS[0], token)
        snap = self.lab.snapshot()
        event = snap["events"][0]
        self.assertEqual(event["identifiers"], [token.decode()])
        self.assertEqual(event["body_bytes"], len(token))
        self.assertTrue(event["proxy_route_observed"])
        self.assertGreater(snap["decrypted_origin_application_bytes"], len(token))
        self.assertEqual(self.lab.metadata()["history"], "none")

    def test_positive_tracker_control_then_deny_records_no_origin_bytes(self):
        self.lab.configure(paused=True)
        self.request(HOSTS[2], synthetic_id(1).encode(), case="third-party")
        before = self.lab.snapshot()["decrypted_origin_application_bytes"]
        self.lab.configure(paused=False)
        with self.assertRaises(OSError):
            self.request(HOSTS[2], synthetic_id(1).encode(), case="third-party")
        after = self.lab.snapshot()
        self.assertEqual(after["decrypted_origin_application_bytes"], before)
        self.assertEqual(len(after["events"]), 1)

    def test_partial_application_data_is_counted_even_without_valid_http(self):
        with self.tunnel() as stream:
            partial = b"POST /never-completed"
            stream.sendall(partial)
            # Half-close transport; the decrypted read must be retained even if
            # no complete request line reaches the handler's semantic recorder.
            stream.shutdown(socket.SHUT_WR)
            deadline = time.monotonic() + 2
            while time.monotonic() < deadline:
                if self.lab.snapshot()["decrypted_origin_application_bytes"] >= len(partial):
                    break
                time.sleep(0.01)
        result = self.lab.snapshot()
        self.assertEqual(result["events"], [])
        self.assertGreaterEqual(result["decrypted_origin_application_bytes"], len(partial))

    def test_unknown_origin_cannot_be_forwarded_by_fixture_routing(self):
        connection = http.client.HTTPConnection("127.0.0.1", self.lab.proxy_port, timeout=3)
        self.addCleanup(connection.close)
        connection.set_tunnel("outside-fixture.invalid", self.lab.server.server_port)
        connection.connect()
        with self.assertRaises(OSError):
            self.lab.client_tls.wrap_socket(connection.sock, server_hostname="outside-fixture.invalid")
        self.assertEqual(self.lab.snapshot()["decrypted_origin_application_bytes"], 0)

    def test_established_websocket_stops_new_collector_bytes_after_deny(self):
        host, port = HOSTS[4], self.lab.server.server_port
        with self.tunnel(host) as stream:
            key = base64.b64encode(b"0123456789abcdef").decode()
            stream.sendall((f"GET /socket?visit={self.visit}&case=socket HTTP/1.1\r\n"
                            f"Host: {host}:{port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                            f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n").encode())
            response = bytearray()
            while not response.endswith(b"\r\n\r\n"):
                chunk = stream.recv(1)
                self.assertTrue(chunk)
                response.extend(chunk)
                self.assertLess(len(response), 8192)
            self.assertTrue(response.startswith(b"HTTP/1.1 101 "))
            def frame(token):
                mask = b"lab!"
                return bytes([0x81, 0x80 | len(token)]) + mask + bytes(value ^ mask[i % 4] for i, value in enumerate(token))
            stream.sendall(frame(synthetic_id(0).encode()))
            ack = bytearray()
            while len(ack) < 5:
                chunk = stream.recv(5 - len(ack))
                self.assertTrue(chunk)
                ack.extend(chunk)
            self.assertEqual(ack, b"\x81\x03ack")
            before = self.lab.snapshot()
            self.assertEqual(len(before["events"]), 1)
            self.assertTrue(before["events"][0]["proxy_route_observed"])
            self.lab.configure(denied=host)
            try:
                stream.sendall(frame(synthetic_id(1).encode()))
                self.assertEqual(stream.recv(32), b"")
            except (ConnectionError, OSError):
                pass
            deadline = time.monotonic() + 2
            while self.visit not in self.lab.snapshot()["closed_sockets"] and time.monotonic() < deadline:
                time.sleep(0.01)
            after = self.lab.snapshot()
            self.assertIn(self.visit, after["closed_sockets"])
            self.assertEqual(len(after["events"]), 1)
            self.assertEqual(after["decrypted_origin_application_bytes"], before["decrypted_origin_application_bytes"])


if __name__ == "__main__":
    unittest.main()
