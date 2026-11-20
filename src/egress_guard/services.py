"""Per-user macOS jobs; no privileged daemon or automatic proxy configuration."""
from contextlib import contextmanager
import hashlib
import os
from pathlib import Path
import plistlib
import stat
import subprocess
import sys
import tempfile
import time

from .config import config_path, initialize, load_config
from .health import proxy_health
from .paths import data_dir, private_dir
from .policy import Policy


READY_TIMEOUT_SECONDS = 10.0
READY_POLL_SECONDS = 0.25
ERROR_LOG_LIMIT = 256 * 1024


def jobs():
    suffix = hashlib.sha256(str(data_dir()).encode()).hexdigest()[:10]
    return [(f"org.egressguard.{name}.{suffix}", action) for name, action in
            (("proxy", "run"), ("dashboard", "dashboard"), ("feeds", "refresh"))]


def _macos():
    if sys.platform != "darwin":
        raise ValueError("Guided background setup is macOS-only; use run and dashboard on other systems")


def _read_definition(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
            raise ValueError("A service definition must be an owned regular file")
        body = handle.read(65537)
    if len(body) > 65536:
        raise ValueError("A service definition is too large")
    try:
        definition = plistlib.loads(body)
    except (ValueError, plistlib.InvalidFileException) as exc:
        raise ValueError("A service definition is invalid") from exc
    if not isinstance(definition, dict):
        raise ValueError("A service definition is invalid")
    return definition


def _owned_definition(path, label, action):
    definition = _read_definition(path)
    arguments = definition.get("ProgramArguments", [])
    environment = definition.get("EnvironmentVariables", {})
    return (definition.get("Label") == label and isinstance(arguments, list) and len(arguments) == 6
            and arguments[1:] == ["-I", "-B", "-m", "egress_guard", action]
            and isinstance(environment, dict) and environment.get("EGRESS_GUARD_DATA") == str(data_dir()))


@contextmanager
def _service_lock():
    import fcntl
    fd = os.open(private_dir(data_dir()) / ".services.lock",
                 os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    with os.fdopen(fd, "rb") as handle:
        info = os.fstat(handle.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or info.st_nlink != 1 or info.st_mode & 0o077):
            raise ValueError("The service lock must be a private owned regular file")
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ValueError("Another background service operation is already running") from None
        yield


def _prepare_error_log():
    """A private, size-bounded stderr file for the jobs; it never receives credentials or request contents."""
    directory = private_dir(private_dir(data_dir()) / "logs")
    path = directory / "services.err.log"
    fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    with os.fdopen(fd, "r+b") as handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1:
            raise ValueError("The service error log must be an owned regular file")
        os.fchmod(handle.fileno(), 0o600)
        if info.st_size > ERROR_LOG_LIMIT:
            # Keep the newest quarter of the budget so the latest failure stays readable.
            handle.seek(info.st_size - ERROR_LOG_LIMIT // 4)
            tail = handle.read()
            handle.seek(0)
            handle.write(tail)
            handle.truncate()
    return str(path)


def _wait_for_ready(port, timeout=None, interval=None, sleep=time.sleep, clock=time.monotonic):
    timeout = READY_TIMEOUT_SECONDS if timeout is None else timeout
    interval = READY_POLL_SECONDS if interval is None else interval
    deadline = clock() + timeout
    while True:
        if proxy_health(port, data_dir()).get("ready"):
            return True
        if clock() >= deadline:
            return False
        sleep(interval)


def _running(label):
    result = subprocess.run(["/bin/launchctl", "print", f"gui/{os.getuid()}/{label}"], capture_output=True, timeout=5)
    return result.returncode == 0


def _publish_definition(target, definition):
    # Publish a complete file without replacing a file created since preflight.
    fd, temporary = tempfile.mkstemp(dir=target.parent, prefix=".egress-guard-")
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(plistlib.dumps(definition))
            handle.flush()
            info = os.fstat(handle.fileno())
        os.link(temporary, target)
        return info.st_dev, info.st_ino
    finally:
        os.unlink(temporary)


def start():
    _macos()
    initialize()
    if not Policy(load_config(), data_dir()).ready():
        raise ValueError("Run 'egress-guard refresh' before starting background services")
    with _service_lock():
        _start()
    print("Background services started. Run 'egress-guard open' for the dashboard. System proxy settings are unchanged.")


def _start():
    directory = Path.home() / "Library/LaunchAgents"
    directory.mkdir(exist_ok=True)
    if directory.is_symlink():
        raise ValueError("LaunchAgents must be a regular directory")
    error_log = _prepare_error_log()
    port = load_config()["proxy"]["port"]
    plan = []
    for label, action in jobs():
        target = directory / f"{label}.plist"
        definition = {"Label": label, "ProgramArguments": [sys.executable, "-I", "-B", "-m", "egress_guard", action],
                      "EnvironmentVariables": {"EGRESS_GUARD_DATA": str(data_dir()), "EGRESS_GUARD_CONFIG": str(config_path())},
                      "ProcessType": "Background", "LowPriorityIO": True, "Umask": 0o077,
                      "StandardOutPath": "/dev/null", "StandardErrorPath": error_log}
        if action == "refresh":
            definition["StartCalendarInterval"] = {"Hour": 7, "Minute": 0}
        else:
            definition.update(RunAtLoad=True, KeepAlive=True, ThrottleInterval=30)
        exists = os.path.lexists(target)
        if exists:
            if not _owned_definition(target, label, action) or _read_definition(target) != definition:
                raise ValueError("An existing service definition differs. Restore and stop the old installation first.")
        plan.append((label, action, target, definition, exists))
    # Validate every definition and inspect preexisting jobs before mutations.
    preexisting = {label for label, *_ in plan if _running(label)}
    created = {}
    attempted = []
    try:
        for label, action, target, definition, exists in plan:
            if not exists:
                created[target] = (*_publish_definition(target, definition), definition)
            if label not in preexisting:
                # A timed-out bootstrap may already have loaded its job.
                attempted.append((label, action, target, definition))
                subprocess.run(["/bin/launchctl", "bootstrap", f"gui/{os.getuid()}", str(target)], capture_output=True, check=True, timeout=10)
        if any(action == "run" for _, action, *_ in attempted) and not _wait_for_ready(port):
            raise RuntimeError(f"The proxy worker did not become ready; setup was rolled back. See {error_log} for worker errors.")
    except BaseException:
        preserved = set()
        for label, action, target, definition in reversed(attempted):
            try:
                if not _owned_definition(target, label, action) or _read_definition(target) != definition:
                    raise ValueError("The service definition changed during setup")
                if _running(label):
                    subprocess.run(["/bin/launchctl", "bootout", f"gui/{os.getuid()}/{label}"], capture_output=True, check=True, timeout=10)
                    if _running(label):
                        raise RuntimeError("The service remains loaded")
            except (OSError, ValueError, RuntimeError, subprocess.SubprocessError):
                preserved.add(target)
        for target, (device, inode, definition) in created.items():
            if target in preserved:
                continue
            try:
                info = target.lstat()
                if (info.st_dev, info.st_ino) != (device, inode) or _read_definition(target) != definition:
                    raise ValueError("The service definition changed during setup")
                target.unlink()
            except FileNotFoundError:
                pass
            except (OSError, ValueError):
                preserved.add(target)
        if preserved:
            raise RuntimeError("Background setup could not roll back completely. Run 'egress-guard stop' to recover; service definitions were preserved.") from None
        raise


def stop():
    _macos()
    with _service_lock():
        _stop()


def _snapshot(path):
    """Identity and bytes of a definition, or None when nothing is there."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return None
    with os.fdopen(fd, "rb") as handle:
        info = os.fstat(handle.fileno())
        return info.st_dev, info.st_ino, handle.read(65537)


def _stop():
    seen = {}
    for label, action in jobs():
        target = Path.home() / "Library/LaunchAgents" / f"{label}.plist"
        if os.path.lexists(target):
            if not _owned_definition(target, label, action):
                raise ValueError("A service definition is not owned by this installation; it was preserved")
            seen[target] = _snapshot(target)
    receipt = data_dir() / "proxy-receipt.json"
    if receipt.exists():
        from .macos import restore_proxy
        result = restore_proxy(receipt)
        print("Proxy restoration:", result)
    changed = []
    for label, action in jobs():
        running = subprocess.run(["/bin/launchctl", "print", f"gui/{os.getuid()}/{label}"], capture_output=True, timeout=5)
        if not running.returncode:
            subprocess.run(["/bin/launchctl", "bootout", f"gui/{os.getuid()}/{label}"], capture_output=True, check=True, timeout=10)
        target = Path.home() / "Library/LaunchAgents" / f"{label}.plist"
        try:
            current = _snapshot(target)
            if current is None and target not in seen:
                continue
            if current != seen.get(target) or not _owned_definition(target, label, action):
                raise ValueError("replaced")
            target.unlink()
        except FileNotFoundError:
            pass
        except (OSError, ValueError):
            changed.append(target.name)
    if changed:
        raise ValueError("A service definition changed during stop and was preserved: " + ", ".join(changed))
    print("Services stopped. Configuration, canary registrations and logs have been retained.")
