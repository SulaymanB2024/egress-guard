"""Per-user macOS jobs; no privileged daemon or automatic proxy configuration."""
import hashlib
import os
from pathlib import Path
import plistlib
import subprocess
import sys

from .config import config_path, initialize, load_config
from .paths import atomic_private, data_dir, private_dir
from .policy import Policy


def jobs():
    suffix = hashlib.sha256(str(data_dir()).encode()).hexdigest()[:10]
    return [(f"org.egressguard.{name}.{suffix}", action) for name, action in
            (("proxy", "run"), ("dashboard", "dashboard"), ("feeds", "refresh"))]


def _macos():
    if sys.platform != "darwin":
        raise ValueError("Guided background setup is macOS-only; use run and dashboard on other systems")


def _owned_definition(path, label, action):
    if path.is_symlink():
        raise ValueError("Refusing a linked service definition")
    definition = plistlib.loads(path.read_bytes())
    arguments = definition.get("ProgramArguments", [])
    return (definition.get("Label") == label and len(arguments) == 6
            and arguments[1:] == ["-I", "-B", "-m", "egress_guard", action]
            and definition.get("EnvironmentVariables", {}).get("EGRESS_GUARD_DATA") == str(data_dir()))


def start():
    _macos()
    initialize()
    if not Policy(load_config(), data_dir()).ready():
        raise ValueError("Run 'egress-guard refresh' before starting background services")
    directory = Path.home() / "Library/LaunchAgents"
    directory.mkdir(exist_ok=True)
    if directory.is_symlink():
        raise ValueError("LaunchAgents must be a regular directory")
    for label, action in jobs():
        target = directory / f"{label}.plist"
        definition = {"Label": label, "ProgramArguments": [sys.executable, "-I", "-B", "-m", "egress_guard", action],
                      "EnvironmentVariables": {"EGRESS_GUARD_DATA": str(data_dir()), "EGRESS_GUARD_CONFIG": str(config_path())},
                      "ProcessType": "Background", "LowPriorityIO": True, "Umask": 0o077,
                      "StandardOutPath": "/dev/null", "StandardErrorPath": "/dev/null"}
        if action == "refresh":
            definition["StartCalendarInterval"] = {"Hour": 7, "Minute": 0}
        else:
            definition.update(RunAtLoad=True, KeepAlive=True, ThrottleInterval=30)
        if target.exists():
            if not _owned_definition(target, label, action) or plistlib.loads(target.read_bytes()) != definition:
                raise ValueError("An existing service definition differs. Restore and stop the old installation first.")
        else:
            if target.is_symlink():
                raise ValueError("Refusing a linked service definition")
            # LaunchAgents is shared with unrelated user jobs. Do not change its permissions.
            import tempfile
            fd, temporary = tempfile.mkstemp(dir=directory, prefix=".egress-guard-")
            try:
                with os.fdopen(fd, "wb") as handle:
                    handle.write(plistlib.dumps(definition))
                os.replace(temporary, target)
            finally:
                if os.path.exists(temporary):
                    os.unlink(temporary)
        already = subprocess.run(["/bin/launchctl", "print", f"gui/{os.getuid()}/{label}"], capture_output=True, timeout=5)
        if already.returncode:
            subprocess.run(["/bin/launchctl", "bootstrap", f"gui/{os.getuid()}", str(target)], capture_output=True, check=True, timeout=10)
    print("Background services started. Run 'egress-guard open' for the dashboard. System proxy settings are unchanged.")


def stop():
    _macos()
    for label, action in jobs():
        target = Path.home() / "Library/LaunchAgents" / f"{label}.plist"
        if (target.exists() or target.is_symlink()) and not _owned_definition(target, label, action):
            raise ValueError("A service definition is not owned by this installation; it was preserved")
    receipt = data_dir() / "proxy-receipt.json"
    if receipt.exists():
        from .macos import restore_proxy
        result = restore_proxy(receipt)
        print("Proxy restoration:", result)
    for label, _ in jobs():
        running = subprocess.run(["/bin/launchctl", "print", f"gui/{os.getuid()}/{label}"], capture_output=True, timeout=5)
        if not running.returncode:
            subprocess.run(["/bin/launchctl", "bootout", f"gui/{os.getuid()}/{label}"], capture_output=True, check=True, timeout=10)
        target = Path.home() / "Library/LaunchAgents" / f"{label}.plist"
        if target.exists():
            target.unlink()
    print("Services stopped. Configuration, canary registrations and logs have been retained.")
