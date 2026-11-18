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
from pathlib import Path
import shlex
import shutil
import stat
import subprocess
import sys
import venv


def install():
    if sys.version_info < (3, 12):
        raise RuntimeError("Install Python 3.12 or later and set EGRESS_GUARD_PYTHON to its executable if needed.")

    project = Path(sys.argv[1])
    target = project
    if len(sys.argv) == 3:
        target = Path(sys.argv[2]).expanduser().resolve(strict=True)
        if not target.is_file() or target.suffix != ".whl":
            raise RuntimeError("Supply the path to a local wheel.")
    elif not (project / "pyproject.toml").is_file():
        raise RuntimeError("Run this script from the project checkout or supply a local wheel.")

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
        subprocess.run(
            [str(python), "-I", "-m", "pip", "--isolated", "--disable-pip-version-check",
             "install", "--index-url", "https://pypi.org/simple", str(target)],
            check=True,
            env={**os.environ, "PIP_CONFIG_FILE": os.devnull},
        )
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
