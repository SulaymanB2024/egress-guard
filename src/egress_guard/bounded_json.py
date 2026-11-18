"""Decode external JSON with structure limits before container allocation."""
import json
import math


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("JSON contains duplicate fields")
        result[key] = value
    return result


def _constant(_):
    raise ValueError("JSON contains a non-finite number")


def _float(value):
    number = float(value)
    if not math.isfinite(number):
        raise ValueError("JSON contains a non-finite number")
    return number


def _int(value):
    if len(value) > 32:
        raise ValueError("JSON integer exceeds its size limit")
    return int(value)


def loads(raw: bytes, *, limit: int, depth_limit: int = 16):
    if len(raw) > limit:
        raise ValueError("JSON exceeds its size limit")
    try:
        source = raw.decode("utf-8")
        depth = markers = 0
        quoted = escaped = False
        for char in source:
            if quoted:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == '"':
                    quoted = False
            elif char == '"':
                quoted = True
            elif char in "[{":
                depth += 1
                markers += 1
                if depth > depth_limit:
                    raise ValueError("JSON exceeds its nesting limit")
            elif char in "]}":
                depth -= 1
            elif char in ",:":
                markers += 1
            if markers > 100000:
                raise ValueError("JSON exceeds its structure limit")
        return json.loads(source, object_pairs_hook=_object, parse_constant=_constant,
                          parse_float=_float, parse_int=_int)
    except (UnicodeError, RecursionError, json.JSONDecodeError):
        raise ValueError("Invalid JSON") from None
