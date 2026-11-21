"""A bounded local-only proxy identity check."""
import http.client
import hashlib
import hmac
import json
import re
import secrets

from .paths import data_dir, supports_private_identity
from .http_deadline import request_json_object
from .transport_policy import runtime_receipt

HEALTH_RESPONSE_SECONDS = 2


def dashboard_health(port: int, state=None) -> dict:
    """Prove the dashboard identity without creating a login or opening a browser."""
    from .dashboard_http import installation_token
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
    try:
        key = installation_token(state or data_dir(), create=False)
        client = secrets.token_urlsafe(32)
        status, data = request_json_object(connection, "GET", "/api/challenge?client=" + client,
                                           seconds=HEALTH_RESPONSE_SECONDS)
        nonce, proof = data.get("challenge"), data.get("proof")
        if (status != 200 or not isinstance(nonce, str) or re.fullmatch(r"[A-Za-z0-9_-]{43}", nonce) is None
                or not isinstance(proof, str) or re.fullmatch(r"[0-9a-f]{64}", proof) is None):
            return {"ready": False, "port": port}
        origin = f"http://127.0.0.1:{port}"
        message = f"egress-guard/v2:server:{origin}:{client}:{nonce}"
        expected = hmac.new(key.encode(), message.encode(), hashlib.sha256).hexdigest()
        return {"ready": hmac.compare_digest(proof, expected), "port": port}
    except (OSError, ValueError, RuntimeError, http.client.HTTPException):
        return {"ready": False, "port": port}
    finally:
        connection.close()


def response_proof(nonce, port, state, *, create_identity=True):
    from .dashboard_http import installation_token
    key = installation_token(state, create=create_identity)
    return hmac.new(key.encode(), f"egress-guard/v1:proxy:{nonce}:{port}".encode(), hashlib.sha256).hexdigest()


def _canonical(status):
    return json.dumps(status, sort_keys=True, separators=(",", ":"), allow_nan=False)


def policy_proof(nonce, port, state, status, *, create_identity=True):
    """Bind the applied-policy report to the same nonce, port and installation key."""
    from .dashboard_http import installation_token
    key = installation_token(state, create=create_identity)
    message = f"egress-guard/v1:proxy-policy:{nonce}:{port}:{_canonical(status)}"
    return hmac.new(key.encode(), message.encode(), hashlib.sha256).hexdigest()


def _verified_policy(data, nonce, port, state, *, create_identity=True):
    status, proof = data.get("policy"), data.get("policy_proof")
    if not isinstance(status, dict) or not isinstance(proof, str):
        return None
    try:
        expected = policy_proof(nonce, port, state, status, create_identity=create_identity)
    except (OSError, RuntimeError, ValueError, TypeError):
        return None
    return status if hmac.compare_digest(proof.encode(), expected.encode()) else None


def proxy_health(port: int, state=None, *, create_identity=True) -> dict:
    if not supports_private_identity():
        return {"ready": False, "port": port, "https_decryption": False, "identity": "unavailable",
                "detail": "This platform needs an ACL-verified private identity backend"}
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
    try:
        state = state or data_dir()
        if not create_identity:
            # A read-only caller must not indirectly initialize the proxy's key by
            # sending its first health challenge to an uninitialized installation.
            from .dashboard_http import installation_token
            installation_token(state, create=False)
        nonce = secrets.token_urlsafe(32)
        status, data = request_json_object(connection, "GET", "http://egress-guard.invalid/health?nonce=" + nonce,
                                           seconds=HEALTH_RESPONSE_SECONDS)
        valid = (status == 200 and data.get("product") == "egress-guard"
                 and data.get("ready") is True and data.get("https_decryption") is False
                 and isinstance(data.get("proof"), str)
                 and hmac.compare_digest(data["proof"].encode(), response_proof(
                     nonce, port, state, create_identity=create_identity).encode()))
        # The applied-policy report is authenticated separately so it is visible while unready.
        reported = _verified_policy(data, nonce, port, state, create_identity=create_identity)
        transport = runtime_receipt(reported.get("transport")) if reported is not None else None
        if reported is not None:
            reported = {**reported, "transport": transport}
        valid = bool(valid and transport is not None and transport["applied"])
        return {"ready": bool(valid), "port": port, "https_decryption": False,
                "policy": reported,
                # Display-only resource figures, accepted only from a proxy that proved its identity.
                "footprint": data.get("footprint") if valid and isinstance(data.get("footprint"), dict) else None}
    except (OSError, ValueError, RuntimeError, http.client.HTTPException):
        return {"ready": False, "port": port, "https_decryption": False, "policy": None}
    finally:
        connection.close()
