"""Explicit setup, inspection, filtering and recovery commands."""
import argparse
import json
from pathlib import Path
import os
import shutil
import stat
import subprocess
import sys

from . import __version__
from .config import config_path, initialize, load_config
from .feeds import feed_status, update_feeds
from .health import proxy_health
from .paths import data_dir, private_dir
from .policy import Policy
from .bounded_json import loads as bounded_json


def _answers_file(path: str) -> object:
    """Read an explicit offline fixture without following links or waiting on pipes."""
    candidate = Path(path)
    if candidate.is_symlink():
        raise ValueError("The answers file must be a regular file, not a link")
    descriptor = os.open(candidate, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
                         | getattr(os, "O_BINARY", 0))
    with os.fdopen(descriptor, "rb") as handle:
        if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
            raise ValueError("The answers file must be a regular file")
        raw = handle.read(65537)
    if len(raw) > 65536:
        raise ValueError("The answers file exceeds 64 KiB")
    return bounded_json(raw, limit=65536)


def run_proxy() -> None:
    initialize()
    config = load_config()
    if not Policy(config, data_dir()).ready():
        raise ValueError("No verified filter cache is ready. Run 'egress-guard refresh' first.")
    executable = Path(sys.executable).parent / ("mitmdump.exe" if os.name == "nt" else "mitmdump")
    if not executable.is_file():
        discovered = shutil.which("mitmdump")
        if not discovered:
            raise ValueError("The installed mitmproxy transport is missing. Reinstall Egress Guard.")
        executable = Path(discovered)
    confdir = private_dir(data_dir() / "transport")
    os.environ["EGRESS_GUARD_DATA"] = str(data_dir())
    os.environ["EGRESS_GUARD_CONFIG"] = str(config_path())
    arguments = [str(executable), "--mode", "regular", "--listen-host", "127.0.0.1",
                 "--listen-port", str(config["proxy"]["port"]), "--ignore-hosts", ".*",
                 "--set", "connection_strategy=lazy", "--set", "flow_detail=0",
                 "--set", "termlog_verbosity=error", "--set", f"confdir={confdir}",
                 "-s", str(Path(__file__).with_name("addon.py"))]
    os.execv(str(executable), arguments)


def main(argv=None) -> int:
    os.umask(0o077)
    parser = argparse.ArgumentParser(prog="egress-guard", description="Local domain filtering with original HTTPS certificates.")
    parser.add_argument("--version", action="version", version=__version__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name, text in (("init", "Create private local configuration"), ("refresh", "Update validated filter feeds"),
                       ("run", "Run the loopback filtering proxy"), ("dashboard", "Run the local control dashboard"),
                       ("open", "Open the authenticated local dashboard"), ("doctor", "Read local protection status"),
                       ("start", "Start this user's macOS background services"), ("stop", "Restore owned proxy settings and stop services")):
        commands.add_parser(name, help=text)
    lookup = commands.add_parser("check", help="Explain the decision for a domain")
    lookup.add_argument("host")
    aliases = commands.add_parser("cname-check", help="Inspect DNS aliases without changing live filtering")
    aliases.add_argument("host")
    aliases.add_argument("--answers-file", help="Read an offline JSON observation fixture instead of making DNS queries")
    sponsors = commands.add_parser("sponsor-fetch", help="Explicitly fetch community timing suggestions by a short video hash prefix")
    sponsors.add_argument("video_id", help="Eleven-character YouTube video ID, without a URL")
    sponsors.add_argument("--duration", type=float, required=True, help="Current video duration in seconds, checked against provider timings")
    sponsors.add_argument("--include-selfpromo", action="store_true", help="Also request self-promotion timings")
    sponsors.add_argument("--output", type=Path, help="Atomically create a new JSON file; refuse an existing path")
    native = commands.add_parser("proxy", help="Explicit, reversible macOS system proxy settings")
    native.add_argument("operation", choices=("inspect", "restore"))
    native.add_argument("--service", help="Explicit network service, for example Wi-Fi")
    commands.add_parser("canary-import", help="Import one provider token as JSON from stdin; never put it in shell arguments")
    args = parser.parse_args(argv)
    try:
        if args.command == "init":
            initialize()
            print("Private configuration created. Run 'egress-guard refresh', then 'egress-guard start' on macOS.")
        elif args.command == "refresh":
            initialize()
            result = update_feeds(data_dir(), load_config())
            print(json.dumps(result, indent=2))
            return 0 if result.get("ok") else 1
        elif args.command == "run":
            run_proxy()
        elif args.command == "check":
            print(json.dumps(Policy(load_config(), data_dir()).decision(args.host), indent=2))
        elif args.command == "cname-check":
            from .cname import inspect_answers, normalize_cname_host
            from .dnssd import resolve_cnames
            host = normalize_cname_host(args.host)
            if host is None:
                raise ValueError("CNAME inspection requires a valid, fully qualified DNS hostname")
            policy = Policy(load_config(), data_dir())
            observations = _answers_file(args.answers_file) if args.answers_file else resolve_cnames(host)
            result = inspect_answers(host, observations, policy)
            result["observation_source"] = "offline-file" if args.answers_file else "system-resolver"
            print(json.dumps(result, indent=2))
            return 2 if result["indeterminate"] else 0
        elif args.command == "sponsor-fetch":
            from .sponsors import fetch_suggestions, save_export
            if args.output and os.path.lexists(args.output):
                raise ValueError("The output path already exists; choose a new filename")
            result = fetch_suggestions(args.video_id, args.duration, include_selfpromo=args.include_selfpromo)
            if args.output:
                save_export(args.output, result)
                print("Community timing suggestions saved. Review the video before using them.")
            else:
                print(json.dumps(result, indent=2, allow_nan=False))
        elif args.command == "doctor":
            config = load_config()
            print(json.dumps({"version": __version__, "proxy": proxy_health(config["proxy"]["port"]),
                              "feeds": feed_status(data_dir(), config), "data_directory": str(data_dir())}, indent=2))
        elif args.command in {"start", "stop"}:
            from .services import start, stop
            (start if args.command == "start" else stop)()
        elif args.command in {"dashboard", "open"}:
            from .dashboard_app import serve, open_dashboard
            (serve if args.command == "dashboard" else open_dashboard)()
        elif args.command == "canary-import":
            from .canaries import CanaryMonitor
            raw = sys.stdin.buffer.read(65537)
            if len(raw) > 65536:
                raise ValueError("Token import is too large")
            result = CanaryMonitor(private_dir(data_dir())).import_token(json.loads(raw))
            print(json.dumps(result, indent=2))
        elif args.command == "proxy":
            if sys.platform != "darwin":
                raise ValueError("Guided system proxy configuration is available on macOS only")
            from .macos import inspect_proxy, restore_proxy
            if args.operation == "restore":
                result = restore_proxy(data_dir() / "proxy-receipt.json")
            else:
                if not args.service:
                    raise ValueError("Choose a network service with --service; no service is selected automatically.")
                result = inspect_proxy(args.service)
            print(json.dumps(result, indent=2))
        return 0
    except KeyboardInterrupt:
        return 130
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as error:
        # Known configuration and adapter errors contain no submitted credentials.
        message = str(error) if isinstance(error, (RuntimeError, ValueError)) else "The local operation could not complete"
        print(f"egress-guard: {message}", file=sys.stderr)
        return 1
