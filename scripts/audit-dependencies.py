#!/usr/bin/env python3
"""Inspect release dependency pins; --online checks their public versions with OSV."""
import argparse
from datetime import datetime, timezone
import http.client
import json
from pathlib import Path
import re
import sys
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from egress_guard.http_deadline import DeadlineHTTPSHandler, ResponseDeadline
from egress_guard.lockfile import read_lock

ADVISORY = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]{2,99}")


def inventory(directory):
    packages = set()
    for name in ("runtime.lock", "build.lock"):
        _, pins = read_lock(directory / name)
        packages.update(pins)
        if len(packages) > 512:
            raise ValueError("Too many release package versions")
    return [{"name": name, "version": version} for name, version in sorted(packages)]


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args):
        return None


def _unique_object(pairs):
    result = {}
    for name, value in pairs:
        if name in result:
            raise ValueError("Duplicate advisory fields")
        result[name] = value
    return result


def _constant(_):
    raise ValueError("Invalid advisory JSON number")


def fetch(packages):
    body = {"queries": [{"package": {"ecosystem": "PyPI", "name": item["name"]},
                         "version": item["version"]} for item in packages]}
    request = urllib.request.Request("https://api.osv.dev/v1/querybatch", data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json", "User-Agent": "EgressGuard-dependency-review/0.1"})
    try:
        with ResponseDeadline(20) as deadline:
            opener = urllib.request.build_opener(urllib.request.ProxyHandler(), NoRedirect(), DeadlineHTTPSHandler(deadline))
            with opener.open(request, timeout=10) as response:
                if response.status != 200 or response.headers.get_content_type() != "application/json":
                    raise ValueError("The advisory service did not return a complete response")
                lengths = response.headers.get_all("Content-Length", [])
                if len(lengths) > 1 or (lengths and (not lengths[0].isascii() or not lengths[0].isdecimal()
                        or len(lengths[0]) > 10 or int(lengths[0]) > 2 * 1024 * 1024)):
                    raise ValueError("The advisory response has an invalid length")
                raw = response.read(2 * 1024 * 1024 + 1)
                deadline.check()
                if len(raw) > 2 * 1024 * 1024 or (lengths and len(raw) != int(lengths[0])):
                    raise ValueError("The advisory response is too large or incomplete")
    except urllib.error.HTTPError as error:
        error.close()
        raise ValueError("The advisory service refused the request") from None
    return json.loads(raw, object_pairs_hook=_unique_object, parse_constant=_constant)


def findings(packages, payload):
    rows = payload.get("results") if isinstance(payload, dict) and set(payload) == {"results"} else None
    if not isinstance(rows, list) or len(rows) != len(packages):
        raise ValueError("The advisory response is incomplete")
    matches = []
    for package, row in zip(packages, rows):
        if (not isinstance(row, dict) or set(row) - {"vulns", "next_page_token"}
                or ("next_page_token" in row and not isinstance(row["next_page_token"], str))
                or row.get("next_page_token")):
            raise ValueError("The advisory response requires further review")
        advisories = row.get("vulns", [])
        if not isinstance(advisories, list) or any(not isinstance(item, dict)
                or not isinstance(item.get("id"), str) or not ADVISORY.fullmatch(item["id"]) for item in advisories):
            raise ValueError("The advisory response is invalid")
        if advisories:
            matches.append({**package, "advisories": sorted({item["id"] for item in advisories})})
    return matches


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--online", action="store_true", help="Send only public release package names and versions to OSV")
    args = parser.parse_args(argv)
    try:
        packages = inventory(ROOT / "requirements")
        result = {"scope": "release locks, all platform branches; not installed software or runtime reachability",
                  "package_versions": len(packages)}
        if args.online:
            matches = findings(packages, fetch(packages))
            result.update(status="advisories_found" if matches else "no_known_matches",
                          checked_at=datetime.now(timezone.utc).isoformat(), matches=matches)
            code = int(bool(matches))
        else:
            result.update(status="inventory_only", packages=packages)
            code = 0
        print(json.dumps(result, indent=2))
        return code
    except (OSError, ValueError, RecursionError, http.client.HTTPException):
        print(json.dumps({"status": "unavailable", "message": "Dependency review could not complete; no clean result is available"}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
