#!/usr/bin/env python3
"""Qualify exact per-channel accounting across original-TLS proxy connections.

Synthetic owned origins and Python clients only. Browser header sanitation and
protocol filtering are not modeled as native enforcement. The first-party
residuals must remain present for this qualification to pass.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import platform
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "tests")]
from privacy_accounting import CHANNELS
from privacy_clients import ack, frame, http_request, response, tunnel, websocket
from privacy_lab import HOSTS, Lab, exact_linkability, synthetic_id

SCORED = ("third_party_collector", "first_party_url_or_header_collector",
          "first_party_body_collector", "websocket_telemetry")


def qualify_idle_revocation(lab):
    lab.clear()
    collector, _ = websocket(lab, HOSTS[4], "a" * 24)
    functional, _ = websocket(lab, HOSTS[0], "b" * 24, case="cart")
    with collector, functional:
        collector.sendall(frame(synthetic_id(0).encode()))
        ack(collector)
        functional.sendall(frame(b"functional:before"))
        ack(functional)
        before = lab.snapshot()
        old_origin = next(row for row in before["connections"] if row["host"] == HOSTS[4])
        old_wire = next(row for row in before["proxy_emissions"]["tunnels"] if row["host"] == HOSTS[4])
        initial = [row for row in before["events"] if row["visit"] == "a" * 24]
        positive = (len(initial) == 1 and initial[0]["identifiers"] == [synthetic_id(0)]
                    and initial[0]["proxy_route_observed"] and old_wire["to_origin_bytes"] > old_origin["application_bytes"] > 0)
        lab.configure(denied=HOSTS[4])
        started = time.monotonic()
        controls = 0
        # No collector write occurs during this interval. The timer must operate
        # while a distinct allowed socket continues delivering application frames.
        for number in range(8):
            functional.sendall(frame(f"functional:after:{number}".encode()))
            ack(functional)
            controls += 1
            time.sleep(0.15)
        collector.settimeout(3)
        closed = collector.recv(32) == b""
        observed_after_ms = round((time.monotonic() - started) * 1000)
        deadline = time.monotonic() + 2
        while "a" * 24 not in lab.snapshot()["closed_sockets"] and time.monotonic() < deadline:
            time.sleep(0.01)
        after = lab.snapshot()
        new_origin = next(row for row in after["connections"] if row["host"] == HOSTS[4])
        new_wire = next(row for row in after["proxy_emissions"]["tunnels"] if row["host"] == HOSTS[4])
        origin_delta = new_origin["application_bytes"] - old_origin["application_bytes"]
        wire_delta = new_wire["to_origin_bytes"] - old_wire["to_origin_bytes"]
        functional_events = [row for row in after["events"] if row["visit"] == "b" * 24]
        collector_events = [row for row in after["events"] if row["visit"] == "a" * 24]
        passed = (positive and closed and "a" * 24 in after["closed_sockets"] and controls == 8
                  and origin_delta == wire_delta == 0 and len(collector_events) == 1 and len(functional_events) == 9
                  and all(row["proxy_route_observed"] and not row["identifiers"] for row in functional_events)
                  and not after["overflow"] and not after["handler_errors"])
    return {"status": "PASS" if passed else "FAIL", "positive_collector_control": positive,
            "collector_written_after_deny": False, "idle_collector_closed": closed,
            "functional_frames_after_deny": controls, "expected_functional_frames_after_deny": 8,
            "post_deny_origin_application_bytes": origin_delta, "post_deny_proxy_emitted_tls_bytes": wire_delta,
            "closure_observed_after_ms": observed_after_ms,
            "timing_scope": "Observation after sequential functional controls; not an exact close timestamp or scheduling deadline."}


def validate_event(event, *, visit, host, case, method, body, encoded_bytes, token, source):
    sources = {key: ([token] if key in source else []) for key in ("url", "headers", "body")}
    return (event.get("visit") == visit and event.get("host") == host and event.get("case") == case and event.get("method") == method
            and event.get("body_bytes") == len(body or b"") and event.get("proxy_route_observed") is True
            and event.get("request_or_frame_bytes") == encoded_bytes
            and event.get("identifier_sources") == sources
            and event.get("identifiers") == ([token] if token else [])
            and event.get("distinct_identifier_bytes") == (len(token) if token else 0))


def qualify():
    visits = {sha256(f"channel:{site}:{subject}".encode()).hexdigest()[:24]: {"site": site, "subject": subject}
              for site in HOSTS[:2] for subject in range(4)}
    arms = {}
    with Lab() as lab:
        for label, paused in (("baseline", True), ("protected_proxy", False)):
            lab.configure(paused=paused)
            lab.clear()
            before = lab.snapshot()
            expected_bytes = dict.fromkeys(CHANNELS, 0)
            attempts, reused = [], []
            for visit, truth in visits.items():
                host, token = truth["site"], synthetic_id(truth["subject"])
                cases = [
                    ("cart", "/product", None, (), "first_party_functional", None, ()),
                    ("ga4", "/collect/url", None, (), "first_party_url_or_header_collector", token, ("url",)),
                    ("headers", "/collect/headers", None,
                     (("Cookie", "fixture_identity=" + token), ("X-POSTHOG-DISTINCT-ID", token),
                      ("X-Lab-CSRF", "fixture-session")), "first_party_url_or_header_collector", token, ("headers",)),
                    ("opaque", "/collect/body", json.dumps({"distinct_id": token}).encode(), (),
                     "first_party_body_collector", token, ("body",)),
                    ("cart", "/cart", b'{"sku":"fixture","quantity":1}', (("X-Lab-CSRF", "fixture-session"),),
                     "first_party_functional", None, ()),
                ]
                first_event = len(lab.snapshot()["events"])
                with tunnel(lab, host) as stream, stream.makefile("rb") as reader:
                    for case, route, body, headers, channel, expected_token, source in cases:
                        target = f"{route}?visit={visit}&case={case}" + ("&cid=" + token if case == "ga4" else "")
                        request = http_request(lab, host, target, body=body, headers=headers)
                        old_count = len(lab.snapshot()["events"])
                        stream.sendall(request)
                        response(reader)
                        events = lab.snapshot()["events"][old_count:]
                        passed = len(events) == 1 and events[0].get("channel") == channel and validate_event(
                            events[0], visit=visit, host=host, case=case, method="GET" if body is None else "POST", body=body,
                            encoded_bytes=len(request), token=expected_token, source=source)
                        expected_bytes[channel] += len(request)
                        attempts.append({"channel": channel, "case": case, "status": "PASS" if passed else "FAIL",
                                         "expected_request_bytes": len(request)})
                visit_events = lab.snapshot()["events"][first_event:]
                reused.append(len(visit_events) == len(cases) and len({event["peer_port"] for event in visit_events}) == 1)

                old = lab.snapshot()
                request = http_request(lab, HOSTS[2], f"/collect/body?visit={visit}&case=third-party", body=token.encode())
                completed = False
                try:
                    with tunnel(lab, HOSTS[2]) as stream, stream.makefile("rb") as reader:
                        stream.sendall(request)
                        response(reader)
                        completed = True
                except OSError:
                    pass
                new = lab.snapshot()
                events = new["events"][len(old["events"]):]
                delivered = new["decrypted_origin_application_bytes"] - old["decrypted_origin_application_bytes"]
                emitted = sum(row["to_origin_bytes"] for row in new["proxy_emissions"]["tunnels"]) - sum(
                    row["to_origin_bytes"] for row in old["proxy_emissions"]["tunnels"])
                passed = ((completed and delivered == len(request) and emitted > delivered and len(events) == 1
                           and events[0].get("channel") == "third_party_collector"
                           and validate_event(events[0], visit=visit, host=HOSTS[2], case="third-party", method="POST", body=token.encode(),
                                              encoded_bytes=len(request), token=token, source=("body",))) if paused
                          else not completed and not events and delivered == emitted == 0)
                expected_bytes["third_party_collector"] += len(request) if paused else 0
                attempts.append({"channel": "third_party_collector", "case": "third-party", "status": "PASS" if passed else "FAIL",
                                 "received_application_bytes": delivered, "proxy_emitted_tls_bytes": emitted})

                old_count = len(lab.snapshot()["events"])
                stream, handshake = websocket(lab, host, visit)
                message = frame(token.encode())
                with stream:
                    stream.sendall(message)
                    ack(stream)
                events = lab.snapshot()["events"][old_count:]
                passed = len(events) == 1 and events[0].get("channel") == "websocket_telemetry" and validate_event(
                    events[0], visit=visit, host=host, case="socket", method="WEBSOCKET", body=token.encode(),
                    encoded_bytes=len(message), token=token, source=("body",))
                expected_bytes["websocket_telemetry"] += handshake + len(message)
                attempts.append({"channel": "websocket_telemetry", "case": "socket", "status": "PASS" if passed else "FAIL",
                                 "expected_upgrade_and_frame_bytes": handshake + len(message)})

            snap = lab.snapshot()
            bytes_by_channel = {name: snap["origin_framing"]["channel_bytes"][name] - before["origin_framing"]["channel_bytes"][name]
                                for name in CHANNELS}
            unparsed = snap["origin_framing"]["unparsed_or_truncated_bytes"] - before["origin_framing"]["unparsed_or_truncated_bytes"]
            matrix = {}
            for channel in (*SCORED, "all_channels"):
                events = snap["events"] if channel == "all_channels" else [row for row in snap["events"] if row["channel"] == channel]
                score = exact_linkability(events, visits)
                tokens = {token for row in events for token in row["identifiers"]}
                expected_matches = 0 if channel == "third_party_collector" and not paused else 4
                score_ok = (score["true_matches"] == expected_matches and score["false_matches"] == 0
                            and score["positive_pairs"] == 4 and score["negative_pairs"] == 12
                            and len(tokens) == (0 if expected_matches == 0 else 4))
                matrix[channel] = {"bytes_delivered": sum(bytes_by_channel.values()) if channel == "all_channels" else bytes_by_channel[channel],
                                   "unique_identities_extracted": len(tokens), "cross_site_matches": score["true_matches"],
                                   "positive_pairs": score["positive_pairs"], "false_matches": score["false_matches"],
                                   "negative_pairs": score["negative_pairs"], "status": "PASS" if score_ok else "FAIL"}
            connections = snap["connections"][len(before["connections"]):]
            tunnels = snap["proxy_emissions"]["tunnels"][len(before["proxy_emissions"]["tunnels"]):]
            joins = all(len([wire for wire in tunnels if wire["host"] == conn["host"] and wire["peer_port"] == conn["peer_port"]
                            and wire["to_origin_bytes"] > conn["application_bytes"] and wire["to_client_bytes"] > 0]) == 1
                        for conn in connections)
            functional = [row for row in attempts if row["channel"] == "first_party_functional"]
            passed = (all(row["status"] == "PASS" for row in attempts) and all(row["status"] == "PASS" for row in matrix.values())
                      and all(reused) and len(reused) == 8 and bytes_by_channel == expected_bytes and unparsed == 0
                      and len(snap["events"]) == (56 if paused else 48) and len(connections) == (24 if paused else 16)
                      and len(tunnels) == len(connections) and joins and not snap["handler_errors"] and not snap["overflow"])
            arms[label] = {"status": "PASS" if passed else "FAIL", "matrix": matrix, "channel_bytes": bytes_by_channel,
                           "unparsed_or_truncated_bytes": unparsed, "byte_conservation": bytes_by_channel == expected_bytes,
                           "functional_responses": {"passed": sum(row["status"] == "PASS" for row in functional), "expected": 16},
                           "same_tls_connection_visits": {"passed": sum(reused), "expected": 8},
                           "proxy_origin_tunnel_join": joins, "tunnels": tunnels,
                           "origin_connections": connections, "attempts": attempts,
                           "proxy_byte_definition": snap["proxy_emissions"]["definition"]}
        idle = qualify_idle_revocation(lab)
        metadata = lab.metadata()
    passed = all(row["status"] == "PASS" for row in arms.values()) and idle["status"] == "PASS"
    files = ("scripts/qualify-channel-lab.py", "tests/privacy_lab.py", "tests/privacy_accounting.py",
             "tests/privacy_clients.py", "tests/privacy_proxy_meter.py", "src/egress_guard/addon.py",
             "src/egress_guard/policy.py", "src/egress_guard/transport_policy.py", "src/egress_guard/feeds.py")
    return {"schema": 1, "status": "PASS" if passed else "FAIL", "synthetic_subjects": 4,
            "runtime": {"python": platform.python_version(), "mitmproxy": metadata["mitmproxy"], "platform": sys.platform},
            "scope": "Controlled HTTP/1.1 and bounded WebSocket frames over the original owned-origin TLS certificate, through the real proxy.",
            "native_chrome": "not_executed", "arms": arms, "idle_revocation": idle,
            "residual": "Proxy-only protection leaves first-party URL, header, body and WebSocket identities linkable." if passed else "Required controls did not all pass.",
            "not_covered": ["Native browser/DNR header or cookie sanitation", "HTTP/2 or HTTP/3 multiplexing",
                            "Opaque bounce/server-side relay experiment", "Application-encrypted or arbitrary compressed identity extraction",
                            "OS-wide routing or population anonymity"],
            "source_sha256": {name: sha256((ROOT / name).read_bytes()).hexdigest() for name in files}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True, help="Create a new private JSON receipt; never overwrite")
    args = parser.parse_args()
    fd = os.open(args.out, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as output:
        result = qualify()
        json.dump(result, output, sort_keys=True, indent=2, allow_nan=False)
        output.write("\n")
    print(json.dumps({"status": result["status"], "native_chrome": "not_executed", "synthetic_subjects": 4}))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
