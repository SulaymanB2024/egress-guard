"""Bounded, pre-connection TLS admission using real mitmproxy layer commands."""

import ssl
import unittest
from types import SimpleNamespace
from unittest.mock import Mock

from mitmproxy import connection, options
from mitmproxy.proxy import commands, events
from mitmproxy.proxy.context import Context
from mitmproxy.proxy.layers.tls import parse_client_hello

from egress_guard.addon import EgressGuard, MAX_CLIENT_HELLO_BYTES, MAX_CLIENT_HELLO_READS, PolicyRelay, TunnelGuard


def client_hello(name="passthrough.test"):
    """An OpenSSL-generated first flight, without any network operation."""
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    if name is None:
        context.check_hostname = False
    client = context.wrap_bio(incoming, outgoing, server_hostname=name)
    try:
        client.do_handshake()
    except ssl.SSLWantReadError:
        pass
    return outgoing.read()


def hello_with_extensions(extensions, *, handshake_type=1):
    # Minimal TLS 1.2 ClientHello framing, with caller-supplied extension bytes.
    body = b"\x03\x03" + bytes(32) + b"\x00\x00\x02\x00\x2f\x01\x00"
    body += len(extensions).to_bytes(2, "big") + extensions
    hello = bytes([handshake_type]) + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x03" + len(hello).to_bytes(2, "big") + hello


def sni_extension(names):
    names = b"".join(b"\x00" + len(name).to_bytes(2, "big") + name for name in names)
    body = len(names).to_bytes(2, "big") + names
    return b"\x00\x00" + len(body).to_bytes(2, "big") + body


class TunnelGuardTests(unittest.TestCase):
    def guard(self, *, require_tls=True, decision=True):
        client = connection.Client(peername=("127.0.0.1", 12345), sockname=("127.0.0.1", 8080))
        context = Context(client, options.Options())
        context.server.address = ("front.test", 443)
        self.admit = Mock(return_value=decision)
        self.continue_tunnel = Mock(return_value=True)
        self.invalid = Mock()
        self.layer = TunnelGuard(context, require_tls=require_tls, admit=self.admit,
                                 continue_tunnel=self.continue_tunnel, invalid=self.invalid)
        self.assertEqual(list(self.layer.handle_event(events.Start())), [])
        return self.layer

    def send(self, data):
        return list(self.layer.handle_event(events.DataReceived(self.layer.context.client, data)))

    def assert_refused(self, result):
        self.assertEqual(len(result), 1)
        self.assertIsInstance(result[0], commands.CloseConnection)
        self.assertIs(result[0].connection, self.layer.context.client)
        self.assertEqual(self.layer._buffer, b"")

    def assert_relay(self, result, expected):
        self.assertEqual(len(result), 1)
        self.assertIsInstance(result[0], commands.OpenConnection)
        # The buffered bytes become sendable only after the approved upstream opens.
        forwarded = list(self.layer.handle_event(events.OpenConnectionCompleted(result[0], None)))
        self.assertEqual(len(forwarded), 1)
        self.assertIsInstance(forwarded[0], commands.SendData)
        self.assertIs(forwarded[0].connection, self.layer.context.server)
        self.assertEqual(forwarded[0].data, expected)
        self.invalid.assert_not_called()
        self.assertEqual(self.layer._buffer, b"")

    def test_single_byte_tls_prefix_waits_then_denies_without_opening(self):
        hello = client_hello("blocked.test")
        for require_tls in (True, False):
            with self.subTest(require_tls=require_tls):
                self.guard(require_tls=require_tls, decision=False)
                for prefix in (hello[:1], hello[1:2], hello[2:5], hello[5:20]):
                    self.assertEqual(self.send(prefix), [])
                    self.admit.assert_not_called()
                self.assert_refused(self.send(hello[20:]))
                self.admit.assert_called_once_with("blocked.test")
                self.invalid.assert_not_called()

    def test_tls_records_and_socket_fragments_are_relayed_unchanged(self):
        original = client_hello()
        self.assertEqual(len(original), int.from_bytes(original[3:5], "big") + 5)
        body = original[5:]
        # The handshake itself spans three complete TLS records as well as short reads.
        hello = b"".join(b"\x16\x03\x01" + len(part).to_bytes(2, "big") + part
                         for part in (body[:1], body[1:37], body[37:]))
        self.guard()
        for chunk in (hello[:1], hello[1:2], hello[2:7], hello[7:-1]):
            self.assertEqual(self.send(chunk), [])
        self.assert_relay(self.send(hello[-1:]), hello)
        self.admit.assert_called_once_with("passthrough.test")

    def test_complete_hello_followed_by_large_early_data_does_not_hit_hello_limit(self):
        hello = client_hello()
        data = hello + b"encrypted-early-data" * MAX_CLIENT_HELLO_BYTES
        self.guard()
        self.assert_relay(self.send(data), data)

    def test_absent_sni_is_admitted_using_only_the_authority(self):
        hello = client_hello(None)
        self.assertIsNone(parse_client_hello(hello).sni)
        self.guard()
        self.assert_relay(self.send(hello), hello)
        self.admit.assert_called_once_with(None)

    def test_opaque_ech_extension_does_not_expose_an_inner_name(self):
        outer = sni_extension([b"outer.test"])
        # The extension is deliberately opaque; this is not an ECH negotiation test.
        ech = b"\xfe\x0d\x00\x0c" + b"opaque-inner"
        hello = hello_with_extensions(outer + ech)
        self.guard()
        self.assert_relay(self.send(hello), hello)
        self.admit.assert_called_once_with("outer.test")

    def test_invalid_or_ambiguous_tls_names_never_fall_back_to_raw_forwarding(self):
        valid_sni = sni_extension([b"blocked.test"])
        cases = {
            "two-name-entries": hello_with_extensions(sni_extension([b"front.test", b"blocked.test"])),
            "two-sni-extensions": hello_with_extensions(valid_sni + valid_sni),
            "invalid-name": hello_with_extensions(sni_extension([b"not/a/domain"])),
            "different-handshake-type": hello_with_extensions(valid_sni, handshake_type=2),
            "truncated-sni": hello_with_extensions(b"\x00\x00\x00\x03\x00\x01\x00"),
        }
        for name, hello in cases.items():
            with self.subTest(name=name):
                self.guard(require_tls=False)
                self.assert_refused(self.send(hello))
                self.invalid.assert_called_once_with()
                self.admit.assert_not_called()

    def test_incomplete_handshake_is_bounded_by_reads_and_bytes(self):
        for limit in ("reads", "bytes"):
            with self.subTest(limit=limit):
                self.guard(require_tls=False)
                if limit == "reads":
                    self.assertEqual(self.send(b"\x16\x03\x03\xff\xff\x01\xff\xff\xff"), [])
                    for _ in range(MAX_CLIENT_HELLO_READS - 2):
                        self.assertEqual(self.send(b"\x00"), [])
                    result = self.send(b"\x00")
                else:
                    result = self.send(b"\x16\x03\x03\xff\xff\x01\xff\xff\xff"
                                       + bytes(MAX_CLIENT_HELLO_BYTES))
                self.assert_refused(result)
                self.invalid.assert_called_once_with()
                self.admit.assert_not_called()
                self.assertEqual(self.send(b"ignored-after-close"), [])

    def test_plaintext_compatibility_mode_retains_raw_protocol_passthrough(self):
        data = b"GET / HTTP/1.1\r\nHost: front.test\r\nCookie: fixture-cookie\r\n\r\n"
        self.guard(require_tls=False)
        self.assert_relay(self.send(data), data)
        self.admit.assert_called_once_with(None)
        self.guard(require_tls=True)
        self.assert_refused(self.send(data))
        self.admit.assert_not_called()
        self.invalid.assert_called_once_with()

    def test_disconnect_discards_partial_hello_without_opening(self):
        self.guard()
        self.assertEqual(self.send(client_hello()[:20]), [])
        result = list(self.layer.handle_event(events.ConnectionClosed(self.layer.context.client)))
        self.assert_refused(result)
        self.admit.assert_not_called()


class PolicyRelayTests(unittest.TestCase):
    def setUp(self):
        client = connection.Client(peername=("127.0.0.1", 12345), sockname=("127.0.0.1", 8080))
        client.state = connection.ConnectionState.OPEN
        self.context = Context(client, options.Options())
        self.context.server.address = ("front.test", 443)
        self.admit = Mock(return_value=True)
        self.relay = PolicyRelay(self.context, admit=self.admit)

    def connected(self):
        self.context.server.timestamp_start = 1
        self.context.server.peername = ("127.0.0.1", 443)
        self.context.server.state = connection.ConnectionState.OPEN
        self.assertEqual(list(self.relay.handle_event(events.Start())), [])

    def send(self, source, data):
        return list(self.relay.handle_event(events.DataReceived(source, data)))

    def assert_revoked(self, result):
        self.assertEqual(len(result), 2)
        self.assertTrue(all(type(command) is commands.CloseConnection for command in result))
        self.assertEqual({command.connection for command in result}, {self.context.client, self.context.server})
        self.assertFalse(self.relay._paused_event_queue)
        self.assertIsNone(self.relay._paused)

    def test_each_direction_is_checked_and_revocation_cannot_be_undone(self):
        for source in (self.context.client, self.context.server):
            with self.subTest(source=type(source).__name__):
                self.relay = PolicyRelay(self.context, admit=self.admit)
                self.admit.return_value = True
                self.connected()
                passed = self.send(source, b"allowed-ciphertext")
                self.assertEqual(len(passed), 1)
                self.assertIsInstance(passed[0], commands.SendData)
                self.assertEqual(passed[0].data, b"allowed-ciphertext")
                self.admit.return_value = False
                self.assert_revoked(self.send(source, b"revoked-ciphertext"))
                self.admit.return_value = True
                self.assertEqual(self.send(source, b"must-not-revive"), [])
                self.assertEqual(list(self.relay.handle_event(events.ConnectionClosed(source))), [])

    def test_pending_connection_bytes_are_checked_when_they_become_sendable(self):
        opening = list(self.relay.handle_event(events.Start()))
        self.assertEqual(len(opening), 1)
        self.assertIsInstance(opening[0], commands.OpenConnection)
        self.assertEqual(self.send(self.context.client, b"queued-before-revocation"), [])
        self.assertEqual(self.send(self.context.client, b"second-queued-chunk"), [])
        self.admit.assert_not_called()
        self.admit.return_value = False
        self.assert_revoked(list(self.relay.handle_event(events.OpenConnectionCompleted(opening[0], None))))
        self.admit.assert_called_once_with()

    def test_policy_check_failure_closes_both_sides_without_forwarding(self):
        self.connected()
        self.admit.side_effect = ValueError("injected policy failure")
        self.assert_revoked(self.send(self.context.client, b"unverified-ciphertext"))

    def test_allowed_half_close_keeps_the_opposite_direction_open(self):
        self.connected()
        self.context.client.state = connection.ConnectionState.CAN_WRITE
        result = list(self.relay.handle_event(events.ConnectionClosed(self.context.client)))
        self.assertEqual(len(result), 1)
        self.assertIsInstance(result[0], commands.CloseTcpConnection)
        self.assertIs(result[0].connection, self.context.server)
        self.assertTrue(result[0].half_close)
        reply = self.send(self.context.server, b"remaining-response")
        self.assertEqual(reply[0].data, b"remaining-response")
        self.assertIs(reply[0].connection, self.context.client)
        self.admit.assert_called_once_with()

    def test_upstream_open_failure_keeps_the_original_close_behavior(self):
        opening = list(self.relay.handle_event(events.Start()))[0]
        self.assertEqual(self.send(self.context.client, b"queued"), [])
        result = list(self.relay.handle_event(events.OpenConnectionCompleted(opening, "refused")))
        self.assertEqual(len(result), 1)
        self.assertIsInstance(result[0], commands.CloseConnection)
        self.assertIs(result[0].connection, self.context.client)
        self.assertEqual(self.send(self.context.client, b"after-error"), [])
        self.admit.assert_not_called()


class TunnelPolicyTests(unittest.TestCase):
    def relay_policy(self, *, address_guard=False):
        addon = EgressGuard()
        policy = Mock()
        policy.transport = {"profile": "compatible", "connect_ports": [443], "address_guard": address_guard}
        policy.block_plaintext_credentials = False
        policy.enforceable.return_value = True
        policy.decision.return_value = {"decision": "allowed", "source": "local-allow"}
        policy.address_decision.return_value = {"decision": "allowed", "source": "ip-literal"}
        addon.runtime = SimpleNamespace(policy=policy)
        addon._address_guard = Mock()
        addon._address_guard.ready.return_value = True
        addon.ledger = Mock()
        server = connection.Server(address=("requested.test", 443), peername=("203.0.113.8", 443))
        return addon, policy, server

    def test_handshake_uses_current_policy_for_both_names(self):
        addon = EgressGuard()
        policy = Mock()
        policy.transport = {"profile": "compatible", "connect_ports": [443], "address_guard": False}
        policy.enforceable.return_value = True
        policy.decision.side_effect = lambda name, port: {
            "decision": "blocked" if name == "blocked.test" else "allowed", "source": "local-block",
        }
        addon.runtime = SimpleNamespace(policy=policy)
        addon._address_guard = Mock()
        addon._address_guard.ready.return_value = True
        addon.ledger = Mock()
        self.assertFalse(addon._admit_tunnel("blocked.test", 443, "allowed.test"))
        policy.decision.assert_called_once_with("blocked.test", 443)
        policy.decision.reset_mock()
        self.assertFalse(addon._admit_tunnel("allowed.test", 8443, "blocked.test"))
        self.assertEqual([call.args for call in policy.decision.call_args_list], [
            ("allowed.test", 8443), ("blocked.test", 8443),
        ])
        addon.ledger.record.assert_called_with("blocked.test", "blocked", "local-block", "connect")
        addon.runtime.policy = None
        self.assertFalse(addon._admit_tunnel("allowed.test", 443, "allowed.test"))
        addon.ledger.record.assert_called_with("allowed.test", "blocked", "not-ready", "connect")

    def test_relay_uses_current_readiness_and_plaintext_transport_policy(self):
        addon, policy, server = self.relay_policy()
        self.assertTrue(addon._admit_relay("front.test", 443, None, False, server))
        policy.block_plaintext_credentials = True
        self.assertFalse(addon._admit_relay("front.test", 443, None, False, server))
        addon.ledger.record.assert_called_with("front.test", "blocked", "non-tls-tunnel", "connect")
        self.assertTrue(addon._admit_relay("127.0.0.1", 443, None, False, server))
        self.assertTrue(addon._admit_relay("front.test", 443, "visible.test", True, server))
        policy.enforceable.return_value = False
        self.assertFalse(addon._admit_relay("front.test", 443, "visible.test", True, server))
        policy.enforceable.return_value = True
        addon._closed = True
        self.assertFalse(addon._admit_relay("front.test", 443, "visible.test", True, server))

    def test_selected_address_guard_uses_actual_peer_independently_of_hostname_allows(self):
        addon, policy, server = self.relay_policy(address_guard=True)
        policy.address_decision.return_value = {"decision": "blocked", "source": "malware-feed"}
        self.assertFalse(addon._admit_relay("accounts.google.com", 443, "visible.test", True, server))
        policy.address_decision.assert_called_once_with("203.0.113.8")
        addon.ledger.record.assert_called_with("accounts.google.com", "blocked", "malware-feed", "connect")
        policy.address_decision.reset_mock()
        server.peername = None
        self.assertFalse(addon._admit_relay("accounts.google.com", 443, "visible.test", True, server))
        policy.address_decision.assert_not_called()
        policy.transport["address_guard"] = False
        self.assertTrue(addon._admit_relay("accounts.google.com", 443, "visible.test", True, server))

    def test_a_relay_decision_does_not_mix_policy_generations(self):
        addon, policy, server = self.relay_policy(address_guard=True)
        newer = Mock()
        newer.enforceable.return_value = False
        def swap_during_decision(_host, _port):
            addon.runtime.policy = newer
            return {"decision": "allowed", "source": "local-allow"}
        policy.decision.side_effect = swap_during_decision
        self.assertTrue(addon._admit_relay("front.test", 443, "visible.test", True, server))
        policy.address_decision.assert_called_once_with("203.0.113.8")
        newer.address_decision.assert_not_called()
        self.assertFalse(addon._admit_relay("front.test", 443, "visible.test", True, server))


if __name__ == "__main__":
    unittest.main()
