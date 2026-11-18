"""Explicit setup, inspection, filtering and recovery commands."""
import argparse
import json
from pathlib import Path
import os
import shutil
import subprocess
import sys

from . import __version__
from .config import config_path, initialize, load_config
from .feeds import feed_status, update_feeds
from .health import proxy_health
from .paths import data_dir, private_dir
from .policy import Policy


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
    native = commands.add_parser("proxy", help="Explicit, reversible macOS system proxy settings")
    native.add_argument("operation", choices=("inspect", "enable", "restore"))
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
            from .macos import enable_proxy, inspect_proxy, restore_proxy
            if args.operation == "restore":
                result = restore_proxy(data_dir() / "proxy-receipt.json")
            else:
                if not args.service:
                    raise ValueError("Choose a network service with --service; no service is selected automatically.")
                if args.operation == "inspect":
                    result = inspect_proxy(args.service)
                else:
                    config = load_config()
                    def verify():
                        if not proxy_health(config["proxy"]["port"])["ready"]:
                            raise ValueError("Start a healthy Egress Guard proxy before changing network settings")
                    result = enable_proxy(args.service, config["proxy"]["port"], private_dir(data_dir()) / "proxy-receipt.json", verify_health=verify)
            print(json.dumps(result, indent=2))
        return 0
    except KeyboardInterrupt:
        return 130
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as error:
        # Known configuration and adapter errors contain no submitted credentials.
        message = str(error) if isinstance(error, (RuntimeError, ValueError)) else "The local operation could not complete"
        print(f"egress-guard: {message}", file=sys.stderr)
        return 1
