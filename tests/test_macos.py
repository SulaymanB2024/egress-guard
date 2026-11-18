import json
from pathlib import Path
import shlex
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import Mock, patch

from egress_guard import macos


FAKE_NETWORKSETUP = """
import json
from pathlib import Path
import sys

state_path = Path(sys.argv[1])
state = json.loads(state_path.read_text())
option, *arguments = sys.argv[2:]
if option == "-getcurrentlocation":
    print(state["location"])
    sys.exit()
if option == "-listallnetworkservices":
    print("An asterisk (*) denotes that a network service is disabled.")
    print(state["service"])
    sys.exit()
if arguments[0] != state["service"]:
    print("** Error: Unable to find item in network database.")
    sys.exit(1)
if option == "-getautoproxyurl":
    print("URL: (null)")
    print("Enabled:", "Yes" if state["pac"] else "No")
    sys.exit()
if option == "-getproxyautodiscovery":
    print("Auto Proxy Discovery:", "On" if state["discovery"] else "Off")
    sys.exit()
if option.startswith("-get"):
    proxy = state[option.removeprefix("-get")]
    print("Enabled:", "Yes" if proxy["enabled"] else "No")
    print("Server:", proxy["server"])
    print("Port:", proxy["port"])
    print("Authenticated Proxy Enabled:", int(proxy["authenticated"]))
    sys.exit()

state["calls"].append([option, *arguments])
proxy = state[option.removeprefix("-set").removesuffix("state")]
if option.endswith("state"):
    proxy["enabled"] = arguments[1] == "on"
else:
    proxy.update(enabled=True, server=arguments[1], port=int(arguments[2]), authenticated=False)
state_path.write_text(json.dumps(state))
# Simulate a failure that occurs after the setter commits the new preferences.
if option == state["fail"]:
    sys.exit(1)
"""


class MacOSProxyTests(unittest.TestCase):
    def setUp(self):
        temp = TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.directory = Path(temp.name)
        self.receipt = self.directory / "proxy-receipt.json"
        self.status_path = self.directory / "networksetup.json"
        self.marker = self.directory / "unexpected command"
        self.service = f"""Wi-Fi ' " ; $(/usr/bin/touch {shlex.quote(str(self.marker))})"""
        disabled = dict(enabled=False, server="", port=0, authenticated=False)
        self.write_status(dict(
            service=self.service, location="Automatic", webproxy=disabled,
            securewebproxy=disabled, socksfirewallproxy=disabled,
            pac=False, discovery=False, calls=[], fail=None,
        ))
        tool = self.directory / "fake networksetup"
        fake = self.directory / "fake.py"
        fake.write_text(FAKE_NETWORKSETUP)
        fake_command = shlex.join([sys.executable, str(fake), str(self.status_path)])
        tool.write_text(f'#!/bin/sh\nexec {fake_command} "$@"\n')
        tool.chmod(0o700)
        self.authorizations = []
        patches = [
            patch.object(macos, "NETWORKSETUP", str(tool)),
            patch.object(macos, "_authorized", self.authorize),
            patch.object(macos.sys, "platform", "darwin"),
            patch.object(macos.os, "geteuid", return_value=501),
        ]
        for patcher in patches:
            patcher.start()
            self.addCleanup(patcher.stop)
        self.verify = Mock()

    def read_status(self):
        return json.loads(self.status_path.read_text())

    def write_status(self, status):
        self.status_path.write_text(json.dumps(status))

    def authorize(self, script):
        self.authorizations.append(script)
        result = subprocess.run(["/bin/sh", "-c", script], capture_output=True, check=False)
        if result.returncode:
            raise macos.MacOSProxyError("Mock authorization returned an error.")

    def enable(self):
        return macos.enable_proxy(self.service, 18080, self.receipt, verify_health=self.verify)

    def test_read_only_inspection_and_shell_quoted_enable(self):
        status = macos.inspect_proxy(self.service)
        self.assertEqual(status["location"], "Automatic")
        self.assertFalse(status["http"]["enabled"])
        self.assertEqual(self.read_status()["calls"], [])
        self.assertFalse(self.receipt.exists())

        self.assertEqual(self.enable(), {"service": self.service, "port": 18080})
        self.verify.assert_called_once_with()
        self.assertEqual(len(self.authorizations), 1)
        self.assertFalse(self.marker.exists())
        self.assertEqual(self.receipt.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.read_status()["calls"], [
            ["-setwebproxy", self.service, "127.0.0.1", "18080", "off"],
            ["-setsecurewebproxy", self.service, "127.0.0.1", "18080", "off"],
        ])

    def test_health_failure_blocks_receipt_and_activation(self):
        self.verify.side_effect = macos.MacOSProxyError("Local proxy is unhealthy.")
        with self.assertRaisesRegex(macos.MacOSProxyError, "unhealthy"):
            self.enable()
        self.assertEqual(self.authorizations, [])
        self.assertFalse(self.receipt.exists())

    def test_refuses_pac_socks_authentication_auto_discovery_and_foreign_proxy(self):
        original = self.read_status()
        for label in ("pac", "socks", "authentication", "discovery", "foreign"):
            with self.subTest(label=label):
                status = json.loads(json.dumps(original))
                if label in ("pac", "discovery"):
                    status[label] = True
                elif label == "socks":
                    status["socksfirewallproxy"]["enabled"] = True
                elif label == "authentication":
                    status["webproxy"]["authenticated"] = True
                else:
                    status["securewebproxy"].update(enabled=True, server="example.invalid", port=8080)
                self.write_status(status)
                with self.assertRaisesRegex(macos.MacOSProxyError, "already configured"):
                    self.enable()
        self.assertEqual(self.authorizations, [])
        self.verify.assert_not_called()
        self.assertFalse(self.receipt.exists())

    def test_partial_activation_rolls_back_in_same_authorization(self):
        status = self.read_status()
        status["fail"] = "-setsecurewebproxy"
        self.write_status(status)

        with self.assertRaisesRegex(macos.MacOSProxyError, "both proxies are disabled"):
            self.enable()

        status = self.read_status()
        self.assertEqual(len(self.authorizations), 1)
        self.assertFalse(status["webproxy"]["enabled"])
        self.assertFalse(status["securewebproxy"]["enabled"])
        self.assertEqual([entry[0] for entry in status["calls"]], [
            "-setwebproxy", "-setsecurewebproxy", "-setwebproxystate", "-setsecurewebproxystate",
        ])
        self.assertEqual(macos.restore_proxy(self.receipt)["dormant_endpoints"], ["http", "https"])
        self.assertEqual(len(self.authorizations), 1)
        self.assertFalse(self.receipt.exists())

    def test_restore_preserves_subsequent_foreign_settings(self):
        original = self.read_status()
        original["securewebproxy"].update(server="old.example.invalid", port=5555)
        self.write_status(original)
        self.enable()

        status = self.read_status()
        status["webproxy"].update(server="new.example.invalid", port=6666)
        self.write_status(status)
        result = macos.restore_proxy(self.receipt)

        self.assertEqual(result["restored"], ["https"])
        self.assertEqual(result["preserved"], ["http"])
        self.assertEqual(result["dormant_endpoints"], ["https"])
        self.assertEqual(len(self.authorizations), 2)
        status = self.read_status()
        self.assertEqual(status["webproxy"]["server"], "new.example.invalid")
        self.assertTrue(status["webproxy"]["enabled"])
        self.assertFalse(status["securewebproxy"]["enabled"])
        self.assertEqual(status["calls"][-1], ["-setsecurewebproxystate", self.service, "off"])
        self.assertFalse(self.receipt.exists())

    def test_rechecks_settings_after_authorization_prompt(self):
        def change_settings_then_authorize(script):
            status = self.read_status()
            status["pac"] = True
            self.write_status(status)
            self.authorize(script)

        with patch.object(macos, "_authorized", change_settings_then_authorize):
            with self.assertRaisesRegex(macos.MacOSProxyError, "original proxy settings are intact"):
                self.enable()

        self.assertEqual(self.read_status()["calls"], [])
        self.assertFalse(self.receipt.exists())

    def test_location_recheck_protects_restore(self):
        self.enable()
        status = self.read_status()
        status["location"] = "Office"
        self.write_status(status)
        with self.assertRaisesRegex(macos.MacOSProxyError, "original network location"):
            macos.restore_proxy(self.receipt)
        self.assertEqual(len(self.authorizations), 1)
        self.assertTrue(self.receipt.exists())

    def test_requires_explicit_service_and_valid_port_and_private_receipt(self):
        for port in (0, 65536, True, "18080"):
            with self.subTest(port=port), self.assertRaisesRegex(macos.MacOSProxyError, "requires a port"):
                macos.enable_proxy(self.service, port, self.receipt, verify_health=self.verify)
        for service in ("", "-help", "Other network"):
            with self.subTest(service=service), self.assertRaises(macos.MacOSProxyError):
                macos.inspect_proxy(service)
        target = self.directory / "unrelated"
        target.write_text("Leave this file alone.")
        self.receipt.symlink_to(target)
        with self.assertRaises(macos.MacOSProxyError):
            self.enable()
        with self.assertRaises(macos.MacOSProxyError):
            macos.restore_proxy(self.receipt)
        self.assertEqual(target.read_text(), "Leave this file alone.")
        self.assertEqual(self.authorizations, [])


if __name__ == "__main__":
    unittest.main()
