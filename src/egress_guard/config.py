"""Strict configuration loading without executing config-provided code or URLs."""
from copy import deepcopy
from importlib.resources import files
import os
from pathlib import Path
import tomllib

from .paths import atomic_private, data_dir, private_dir
from .feeds import dns_name


def config_path() -> Path:
    return Path(os.environ.get("EGRESS_GUARD_CONFIG", data_dir() / "config.toml")).expanduser().absolute()


def default_config() -> dict:
    return tomllib.loads(files("egress_guard").joinpath("default.toml").read_text())


def load_config(path: Path | None = None) -> dict:
    result = deepcopy(default_config())
    selected = path or config_path()
    if selected.exists():
        if selected.is_symlink() or selected.stat().st_size > 64 * 1024:
            raise ValueError("Configuration must be a small regular file")
        user = tomllib.loads(selected.read_text())
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
    if result["block"]["list_tier"] not in {"pro", "pro.plus", "ultimate"}:
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
    for key, low, high in (("retention_days", 1, 30), ("max_queue", 100, 10000)):
        value = result["logging"][key]
        if type(value) is not int or not low <= value <= high:
            raise ValueError(f"Invalid {key}")
    return result


def initialize() -> Path:
    private_dir(data_dir())
    path = config_path()
    if not path.exists():
        atomic_private(path, files("egress_guard").joinpath("default.toml").read_bytes())
    load_config(path)
    return path
