"""Audit-hook lifetime tests run in disposable interpreters, never the test runner."""
import os
from pathlib import Path
import subprocess
import sys
import textwrap
import unittest


SOURCE = Path(__file__).resolve().parents[1] / "src"


@unittest.skipUnless(sys.implementation.name == "cpython" and sys.platform in {"linux", "darwin"},
                     "experimental audit guard requires a CPython Unix selector loop")
class AddressGuardTests(unittest.TestCase):
    def run_isolated(self, code):
        result = subprocess.run([sys.executable, "-B", "-c", textwrap.dedent(code)], capture_output=True,
                                text=True, timeout=15, env={**os.environ, "PYTHONPATH": str(SOURCE)})
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_import_is_inert_and_disabled_lease_installs_no_hook(self):
        self.run_isolated('''
            import asyncio, sys
            from unittest.mock import patch
            with patch.object(sys, "addaudithook") as install:
                from egress_guard.address_guard import AddressGuard
                async def main():
                    guard = AddressGuard(lambda: None)
                    await guard.start(False)
                    assert guard.status() == {"selected": False, "state": "disabled", "reason": None}
                    assert guard.ready()
                    guard.close()
                asyncio.run(main())
                install.assert_not_called()
        ''')

    def test_current_policy_numeric_only_failure_and_ownership_lifetime(self):
        self.run_isolated('''
            import asyncio, socket, sys
            from egress_guard.address_guard import AddressGuard
            class Policy:
                def __init__(self, allowed): self.allowed = allowed
                def enforceable(self): return True
                def address_decision(self, ip):
                    return {"decision": "allowed" if self.allowed else "blocked"}
            current = [Policy(True)]
            def refused(sock, address):
                try: sys.audit("socket.connect", sock, address)
                except PermissionError: return True
                return False
            async def main():
                first = AddressGuard(lambda: current[0])
                await first.start(True)
                assert first.ready(), first.status()
                assert first.status() == {"selected": True, "state": "active", "reason": None}
                with socket.socket() as sock:
                    assert not refused(sock, ("203.0.113.1", 443))
                    assert refused(sock, ("unresolved.test", 443))
                    assert refused(sock, ("203.0.113.1", True))
                    current[0] = Policy(False)
                    assert refused(sock, ("203.0.113.1", 443))
                    current[0] = None
                    assert refused(sock, ("127.0.0.1", 443))
                    competitor = AddressGuard(lambda: Policy(True))
                    await competitor.start(False)
                    assert competitor.status()["reason"] == "ownership-conflict"
                    assert not competitor.ready()
                    competitor.close()
                    current[0] = Policy(True)
                    assert not refused(sock, ("203.0.113.1", 443))
                    first.close()
                    assert refused(sock, ("203.0.113.1", 443))
                    replacement = AddressGuard(lambda: None)
                    await replacement.start(False)
                    first.close()  # A retiring owner cannot revoke the replacement lease.
                    assert replacement.ready()
                    assert not refused(sock, ("203.0.113.1", 443))
                    replacement.close()
            asyncio.run(main())
        ''')

    def test_silently_rejected_hook_registration_is_never_claimed_active(self):
        self.run_isolated('''
            import asyncio, sys
            from egress_guard.address_guard import AddressGuard
            def veto(event, args):
                if event == "sys.addaudithook": raise RuntimeError("fixture veto")
            sys.addaudithook(veto)
            async def main():
                guard = AddressGuard(lambda: None)
                await guard.start(True)
                assert guard.status() == {"selected": True, "state": "unavailable", "reason": "registration-failed"}
                assert not guard.ready()
                guard.close()
            asyncio.run(main())
        ''')

    def test_connector_probe_failure_and_unsupported_loop_remain_unavailable(self):
        self.run_isolated('''
            import asyncio
            from unittest.mock import patch, AsyncMock
            from egress_guard import address_guard
            async def main():
                guard = address_guard.AddressGuard(lambda: None)
                loop = asyncio.get_running_loop()
                with patch.object(loop, "sock_connect", new=AsyncMock(return_value=None)):
                    await guard.start(True)
                assert guard.status()["reason"] == "self-test-failed"
                assert not guard.ready()
                guard.close()
                next_guard = address_guard.AddressGuard(lambda: None)
                with patch.object(address_guard, "supported", return_value=False):
                    await next_guard.start(True)
                assert next_guard.status()["reason"] == "unsupported-runtime"
                assert not next_guard.ready()
                next_guard.close()
            asyncio.run(main())
        ''')
