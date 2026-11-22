#!/usr/bin/env python3
"""Reproduce controlled proxy/collector evidence without starting a browser.

Uses synthetic identities and fixed loopback origins only. This qualifies the
fixture and a particular proxy boundary, not browser protection or anonymity.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import http.client
import json
import os
from pathlib import Path
import platform
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "tests")]
from privacy_lab import HOSTS, Lab, exact_linkability, synthetic_id


def request(lab, host, visit, case, body):
    connection = http.client.HTTPConnection("127.0.0.1", lab.proxy_port, timeout=4)
    try:
        connection.set_tunnel(host, lab.server.server_port)
        connection.connect()
        with lab.client_tls.wrap_socket(connection.sock, server_hostname=host) as stream:
            if stream.getpeercert(binary_form=True) != lab.cert_der:
                raise RuntimeError("Origin certificate identity changed")
            stream.sendall((f"POST /api/data?visit={visit}&case={case} HTTP/1.1\r\n"
                            f"Host: {host}:{lab.server.server_port}\r\nContent-Length: {len(body)}\r\n"
                            "Connection: close\r\n\r\n").encode() + body)
            response = http.client.HTTPResponse(stream)
            response.begin()
            if response.status != 200 or response.read() != b'{"ok":true}':
                raise RuntimeError("Functional collector response failed")
    finally:
        connection.close()


def qualify():
    visits = {sha256(f"collector:{site}:{subject}".encode()).hexdigest()[:24]: {"site": site, "subject": subject}
              for site in HOSTS[:2] for subject in range(4)}
    with Lab() as lab:
        arms = {}
        for name, paused in (("baseline", True), ("protected", False)):
            lab.configure(paused=paused)
            lab.clear()
            received_before = lab.snapshot()["decrypted_origin_application_bytes"]
            attempts = []
            for visit, truth in visits.items():
                for case, host, body in (("third-party", HOSTS[2], synthetic_id(truth["subject"]).encode()),
                                         ("opaque", truth["site"], synthetic_id(truth["subject"]).encode()),
                                         ("cart", truth["site"], b'{"cart":"functional"}')):
                    before = lab.snapshot()["decrypted_origin_application_bytes"]
                    completed = True
                    try:
                        request(lab, host, visit, case, body)
                    except OSError:
                        completed = False
                    after = lab.snapshot()
                    delta = after["decrypted_origin_application_bytes"] - before
                    matching = [event for event in after["events"] if event["visit"] == visit and event["case"] == case]
                    should_block = not paused and case == "third-party"
                    expected_identifiers = [] if case == "cart" else [body.decode("ascii")]
                    passed = ((not completed and delta == 0 and not matching) if should_block else
                              (completed and delta > 0 and len(matching) == 1 and matching[0]["proxy_route_observed"]
                               and matching[0]["identifiers"] == expected_identifiers
                               and matching[0]["body_bytes"] == len(body)
                               and matching[0]["distinct_identifier_bytes"] == sum(map(len, expected_identifiers))))
                    attempts.append({"case": case, "expected": "blocked" if should_block else "delivered",
                                     "status": "PASS" if passed else "FAIL", "collector_application_bytes": delta})
            snap = lab.snapshot()
            third_party = exact_linkability(snap["events"], visits, case="third-party")
            all_channels = exact_linkability(snap["events"], visits)
            expected_events = len(visits) * (3 if paused else 2)
            expected_pairs = {"subjects": 4, "positive_pairs": 4, "negative_pairs": 12, "false_matches": 0}
            scores_ok = all(all(score.get(key) == value for key, value in expected_pairs.items())
                            for score in (third_party, all_channels)) and (
                                third_party["true_matches"] == (4 if paused else 0)
                                and third_party["visits_without_observed_identifier"] == (0 if paused else 8)
                                and all_channels["true_matches"] == 4
                                and all_channels["visits_without_observed_identifier"] == 0)
            evidence_ok = (not snap["overflow"] and not snap["handler_errors"]
                           and len(snap["events"]) == expected_events and scores_ok
                           and all(row["proxy_route_observed"] for row in snap["connections"] if row["application_bytes"]))
            arms[name] = {"status": "PASS" if evidence_ok and all(row["status"] == "PASS" for row in attempts) else "FAIL",
                          "attempts": attempts, "received_events": len(snap["events"]),
                          "collector_application_bytes": snap["decrypted_origin_application_bytes"] - received_before,
                          "overflow": snap["overflow"], "unexpected_handler_errors": snap["handler_errors"],
                          "origin_certificate_checked_on_each_completed_request": True,
                          "positive_identifier_controls_verified": scores_ok and all(row["status"] == "PASS" for row in attempts),
                          "third_party_linkability": third_party,
                          "all_observed_channels_linkability": all_channels}
        metadata = lab.metadata()
    source_files = ("tests/privacy_lab.py", "scripts/qualify-collector-lab.py", "src/egress_guard/addon.py",
                    "src/egress_guard/transport_policy.py", "src/egress_guard/policy.py", "src/egress_guard/feeds.py")
    passed = all(arm["status"] == "PASS" for arm in arms.values())
    return {"schema": 1, "status": "PASS" if passed else "FAIL",
            "scope": "Real Python clients, pinned proxy and controlled collectors; fixture and proxy-boundary evidence only.",
            "synthetic_subjects": 4, "registrable_sites": list(HOSTS[:2]),
            "runtime": {"python": platform.python_version(), "mitmproxy": metadata["mitmproxy"], "platform": sys.platform},
            "arms": arms,
            "not_covered": ["Native browser/extension execution", "GA4 or other first-party browser protocol enforcement",
                            "Browser high-entropy hints or GPC", "OS-wide routing", "Population anonymity or fingerprint linkability"],
            "residual": ("Opaque admitted first-party bodies still deliver the stable identifier and keep aggregate exact-token linkability at 1.0."
                         if passed else "Qualification incomplete: the required delivery, extraction and score controls did not all pass."),
            "source_sha256": {name: sha256((ROOT / name).read_bytes()).hexdigest() for name in source_files}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True, help="Create a new private JSON evidence file; never overwrite")
    args = parser.parse_args()
    # Reserve before running so an existing artifact is never replaced or tested
    # needlessly. An interrupted run leaves an empty/incomplete non-passing file.
    fd = os.open(args.out, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as out:
        result = qualify()
        json.dump(result, out, indent=2, sort_keys=True, allow_nan=False)
        out.write("\n")
    print(json.dumps({"status": result["status"], "native_browser": "NOT COVERED", "synthetic_subjects": 4}))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
