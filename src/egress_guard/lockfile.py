"""Read the constrained, hash-pinned pip lock format emitted for this release."""
import ast
import os
from pathlib import Path
import re
import stat

MAX_BYTES = 1024 * 1024
PIN = re.compile(r"([A-Za-z0-9][A-Za-z0-9_.-]*)==([0-9][A-Za-z0-9_.!+\-]*)")
HASH = re.compile(r"--hash=sha256:[0-9a-f]{64}")
ENVIRONMENT = {"python_version", "python_full_version", "os_name", "sys_platform", "platform_release",
               "platform_system", "platform_version", "platform_machine", "platform_python_implementation",
               "implementation_name", "implementation_version"}


def _marker(text):
    if not 0 < len(text) <= 1024 or any(char in text for char in ("\\", "$", "`", ";", "\n", "\r")):
        raise ValueError("Unsupported dependency marker")
    try:
        tree = ast.parse(text, mode="eval").body
    except (SyntaxError, RecursionError) as error:
        raise ValueError("Unsupported dependency marker") from error
    budget = [128]

    def visit(node, depth=0):
        budget[0] -= 1
        if budget[0] < 0 or depth > 16:
            raise ValueError("Dependency marker is too complex")
        if isinstance(node, ast.BoolOp) and isinstance(node.op, (ast.And, ast.Or)):
            for child in node.values:
                visit(child, depth + 1)
            return
        if (isinstance(node, ast.Compare) and len(node.ops) == len(node.comparators) == 1
                and isinstance(node.ops[0], (ast.Eq, ast.NotEq, ast.Lt, ast.LtE, ast.Gt, ast.GtE))):
            operands = [node.left, node.comparators[0]]
            names = [item for item in operands if isinstance(item, ast.Name) and item.id in ENVIRONMENT]
            values = [item for item in operands if isinstance(item, ast.Constant) and isinstance(item.value, str)
                      and re.fullmatch(r"[A-Za-z0-9 ._+*\-]{1,80}", item.value)]
            if len(names) == len(values) == 1:
                return
        raise ValueError("Unsupported dependency marker")

    visit(tree)


def parse_lock(data):
    if not 0 < len(data) <= MAX_BYTES:
        raise ValueError("Dependency lock size is invalid")
    # pip recognizes encoding declarations in comments. Use one unambiguous
    # byte grammar, including for marker text that Python would treat as a comment.
    if (b"#" in data or b"\r" in data.replace(b"\r\n", b"")
            or any(value not in (10, 13) and not 32 <= value <= 126 for value in data)):
        raise ValueError("Dependency locks require printable ASCII and LF/CRLF, without comments")
    pins, pending, continuing = set(), None, False
    for line in data.decode("utf-8").splitlines():
        text = line.strip()
        if not text:
            if pending:
                raise ValueError("Interrupted dependency lock entry")
            continue
        continuation = text.endswith("\\")
        entry = text[:-1].strip() if continuation else text
        if HASH.fullmatch(entry):
            if pending is None or not continuing:
                raise ValueError("A lock hash has no continued package entry")
            continuing = continuation
            if not continuation:
                pins.add(pending)
                pending = None
            continue
        if pending is not None or not continuation:
            raise ValueError("Every dependency requires a continued exact pin and SHA-256 hashes")
        requirement, separator, marker = entry.partition(";")
        match = PIN.fullmatch(requirement.strip())
        if not match:
            raise ValueError("Only exact dependency pins are supported; pip directives and URLs are forbidden")
        if separator:
            _marker(marker.strip())
        pending, continuing = match.groups(), True
        if len(pins) >= 512:
            raise ValueError("Too many dependency versions")
    if pending is not None or not pins:
        raise ValueError("A dependency lock is empty or lacks hashes")
    return sorted(pins)


def read_lock(path: Path):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= MAX_BYTES:
        raise ValueError("A dependency lock must be a bounded regular file")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
    descriptor = os.open(path, flags)
    with os.fdopen(descriptor, "rb") as handle:
        if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
            raise ValueError("A dependency lock must be a regular file")
        data = handle.read(MAX_BYTES + 1)
    return data, parse_lock(data)
