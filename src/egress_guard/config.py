"""Strict configuration loading without executing config-provided code or URLs."""
from copy import deepcopy
from importlib.resources import files
import os
from pathlib import Path
import stat
import tomllib

from .paths import atomic_private, data_dir, private_dir
from .feeds import dns_name

MAX_CONFIG_BYTES = 64 * 1024
# Opt-in compatibility presets. Each names exact hosts that skip tracker and
# CNAME decisions; threat and manual block rules still apply to them.
EXEMPTION_PRESETS = {
    "analytics-dashboards": (
        "analytics.google.com", "clarity.microsoft.com", "claritystatic.azureedge.net",
        "app.posthog.com", "us.posthog.com", "eu.posthog.com",
    ),
}


def config_path() -> Path:
    return Path(os.environ.get("EGRESS_GUARD_CONFIG", data_dir() / "config.toml")).expanduser().absolute()


def default_config() -> dict:
    return tomllib.loads(files("egress_guard").joinpath("default.toml").read_text())


def _read_config(path: Path) -> str | None:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return None
    if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_CONFIG_BYTES:
        raise ValueError("Configuration must be a small regular file")
    flags = (os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
             | getattr(os, "O_BINARY", 0))
    try:
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as handle:
            if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
                raise ValueError("Configuration must be a small regular file")
            body = handle.read(MAX_CONFIG_BYTES + 1)
    except OSError as exc:
        raise ValueError("Configuration could not be read as a small regular file") from exc
    if len(body) > MAX_CONFIG_BYTES:
        raise ValueError("Configuration exceeds its 64 KiB limit")
    return body.decode("utf-8")


def load_config(path: Path | None = None) -> dict:
    result = deepcopy(default_config())
    selected = path or config_path()
    text = _read_config(selected)
    if text is not None:
        try:
            user = tomllib.loads(text)
        except RecursionError as exc:
            raise ValueError("Configuration is nested too deeply") from exc
        if set(user) - set(result):
            raise ValueError("Unknown configuration section")
        for section, settings in user.items():
            if not isinstance(settings, dict) or set(settings) - set(result[section]):
                raise ValueError(f"Unknown setting in {section}")
            result[section].update(settings)
    for key in ("port", "dashboard_port"):
        value = result["proxy"][key]
        if type(value) is not int or not 1024 <= value <= 65535:
            raise ValueError(f"{key} must be between 1024 and 65535")
    if result["proxy"]["port"] == result["proxy"]["dashboard_port"]:
        raise ValueError("The proxy and dashboard need different ports")
    if (not isinstance(result["block"]["list_tier"], str)
            or result["block"]["list_tier"] not in {"pro", "pro.plus", "ultimate"}):
        raise ValueError("Unsupported filter tier")
    for key in ("cname_protection",):
        if type(result["block"][key]) is not bool:
            raise ValueError(f"{key} must be true or false")
    if type(result["risk"]["block_plaintext_credentials"]) is not bool:
        raise ValueError("block_plaintext_credentials must be true or false")
    for key in ("hosts", "allow", "dashboard_hosts"):
        values = result["block"][key]
        if not isinstance(values, list) or len(values) > 2000 or any(not isinstance(value, str) for value in values):
            raise ValueError(f"{key} must be a bounded list of domain names")
        normalized = [dns_name(value) for value in values]
        if any(value is None for value in normalized):
            raise ValueError(f"{key} contains an invalid domain name")
        result["block"][key] = normalized
    presets = result["block"]["exemption_presets"]
    if not isinstance(presets, list) or any(not isinstance(name, str) or name not in EXEMPTION_PRESETS
                                            for name in presets):
        raise ValueError("exemption_presets may only name: " + ", ".join(sorted(EXEMPTION_PRESETS)))
    for key, low, high in (("retention_days", 1, 30), ("max_queue", 100, 10000)):
        value = result["logging"][key]
        if type(value) is not int or not low <= value <= high:
            raise ValueError(f"Invalid {key}")
    return result


def initialize() -> Path:
    private_dir(data_dir())
    path = config_path()
    if not os.path.lexists(path):
        atomic_private(path, files("egress_guard").joinpath("default.toml").read_bytes())
    load_config(path)
    return path
