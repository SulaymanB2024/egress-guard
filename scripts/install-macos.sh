#!/bin/sh
set -eu

if [ "$#" -gt 1 ]; then
    printf '%s\n' 'Usage: scripts/install-macos.sh [local-wheel]' >&2
    exit 2
fi
if [ "$(/usr/bin/uname -s)" != Darwin ]; then
    printf '%s\n' 'This installer is for macOS.' >&2
    exit 1
fi
if [ "$(/usr/bin/id -u)" -eq 0 ]; then
    printf '%s\n' 'Run this installer from your normal macOS account.' >&2
    exit 1
fi

source_root="$(CDPATH='' cd -P -- "$(/usr/bin/dirname -- "$0")/.." && pwd -P)"
python_bin="${EGRESS_GUARD_PYTHON:-python3}"
if ! command -v "$python_bin" >/dev/null; then
    printf '%s\n' 'Install Python 3.12 or later and set EGRESS_GUARD_PYTHON to its executable if needed.' >&2
    exit 1
fi

umask 077
"$python_bin" -I - "$source_root" "$@" <<'PY'
import os
import importlib.util
from pathlib import Path
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import venv


def install():
    if sys.version_info < (3, 12):
        raise RuntimeError("Install Python 3.12 or later and set EGRESS_GUARD_PYTHON to its executable if needed.")

    project = Path(sys.argv[1])
    target = project
    wheel_supplied = len(sys.argv) == 3
    if wheel_supplied:
        target = Path(sys.argv[2]).expanduser().resolve(strict=True)
        if not target.is_file() or target.suffix != ".whl":
            raise RuntimeError("Supply the path to a local wheel.")
    elif not (project / "pyproject.toml").is_file():
        raise RuntimeError("Run this script from the project checkout or supply a local wheel.")

    specification = importlib.util.spec_from_file_location("egress_guard_install_locks", project / "src/egress_guard/lockfile.py")
    lock_reader = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(lock_reader)
    names = ["runtime.lock"] if wheel_supplied else ["runtime.lock", "build.lock"]
    try:
        locks = [(name, lock_reader.read_lock(project / "requirements" / name)[0]) for name in names]
    except (OSError, ValueError) as error:
        raise RuntimeError("A release dependency lock is missing, linked or invalid.") from error

    install_root = Path.home()
    for name in ("Library", "Application Support", "Egress Guard"):
        install_root /= name
        install_root.mkdir(mode=0o700, exist_ok=True)
        info = install_root.lstat()
        forbidden = 0o077 if name == "Egress Guard" else 0o022
        if (
            not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) & forbidden
        ):
            raise RuntimeError(f"Unsafe install directory: {install_root}")

    environment = install_root / "venv"
    try:
        environment.mkdir(mode=0o700)
    except FileExistsError as exc:
        raise RuntimeError(f"An install path already exists: {environment}") from exc

    cli = environment / "bin" / "egress-guard"
    try:
        venv.create(environment, with_pip=True, symlinks=False)
        python = environment / "bin" / "python"
        pip = [str(python), "-I", "-m", "pip", "--isolated", "--disable-pip-version-check", "--no-cache-dir"]
        pip_env = {**os.environ, "PIP_CONFIG_FILE": os.devnull}
        with tempfile.TemporaryDirectory(prefix=".install-locks-", dir=install_root) as temporary:
            for name, body in locks:
                lock = Path(temporary) / name
                descriptor = os.open(lock, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(descriptor, "wb") as handle:
                    handle.write(body)
                subprocess.run(
                    [*pip, "install", "--require-hashes", "--only-binary=:all:",
                     "--index-url", "https://pypi.org/simple", "-r", str(lock)],
                    check=True, env=pip_env,
                )
            # The local project may not resolve or fetch dependencies after the
            # reviewed private lock snapshots have been installed.
            subprocess.run(
                [*pip, "install", "--no-deps", "--no-build-isolation", "--no-index", str(target)],
                check=True, env=pip_env,
            )
            subprocess.run([*pip, "check"], check=True, env=pip_env)
        if not cli.is_file() or cli.is_symlink() or not os.access(cli, os.X_OK):
            raise RuntimeError("The package did not install the Egress Guard command.")
    except (OSError, RuntimeError, subprocess.CalledProcessError, KeyboardInterrupt):
        shutil.rmtree(environment)
        raise
    print(f"Installed Egress Guard. Run {shlex.quote(str(cli))} --help")


try:
    install()
except (OSError, RuntimeError, subprocess.CalledProcessError) as exc:
    sys.exit(f"Installation stopped: {exc}")
PY
