"""Per-user application state; source and installed packages never hold secrets."""
import os
from pathlib import Path
import stat
import sys
import tempfile


def supports_private_identity() -> bool:
    return sys.platform != "win32" and hasattr(os, "getuid") and hasattr(os, "O_NOFOLLOW")


def data_dir() -> Path:
    override = os.environ.get("EGRESS_GUARD_DATA")
    if override:
        return Path(override).expanduser().absolute()
    if sys.platform == "darwin":
        return Path.home() / "Library/Application Support/Egress Guard/data"
    if sys.platform == "win32":
        return Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData/Local")) / "Egress Guard/data"
    return Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local/state")) / "egress-guard"


def private_dir(path: Path) -> Path:
    path.mkdir(parents=True, mode=0o700, exist_ok=True)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode):
        raise ValueError("Application data must be a regular directory, not a link")
    if os.name != "nt" and (info.st_uid != os.getuid() or info.st_mode & 0o077):
        raise ValueError("Application data must belong to this user and have mode 0700")
    return path


def atomic_private(path: Path, data: bytes, *, before_replace=None) -> None:
    """Write privately, optionally rechecking authority after the temporary fsync.

    The callback may refuse the replacement. It runs immediately before rename;
    it does not make checks of other files part of a filesystem transaction.
    """
    private_dir(path.parent)
    descriptor, temporary = tempfile.mkstemp(dir=path.parent, prefix=".")
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        if before_replace is not None:
            before_replace()
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
