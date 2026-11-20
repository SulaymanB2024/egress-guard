"""A bounded local-only proxy identity check."""
import http.client
import hashlib
import hmac
import json
import secrets

from .paths import data_dir, supports_private_identity
from .http_deadline import request_json_object

HEALTH_RESPONSE_SECONDS = 2


def response_proof(nonce, port, state):
    from .dashboard_http import installation_token
    key = installation_token(state)
    return hmac.new(key.encode(), f"egress-guard/v1:proxy:{nonce}:{port}".encode(), hashlib.sha256).hexdigest()


def _canonical(status):
    return json.dumps(status, sort_keys=True, separators=(",", ":"), allow_nan=False)


def policy_proof(nonce, port, state, status):
    """Bind the applied-policy report to the same nonce, port and installation key."""
    from .dashboard_http import installation_token
    key = installation_token(state)
    message = f"egress-guard/v1:proxy-policy:{nonce}:{port}:{_canonical(status)}"
    return hmac.new(key.encode(), message.encode(), hashlib.sha256).hexdigest()


def _verified_policy(data, nonce, port, state):
    status, proof = data.get("policy"), data.get("policy_proof")
    if not isinstance(status, dict) or not isinstance(proof, str):
        return None
    try:
        expected = policy_proof(nonce, port, state, status)
    except (OSError, RuntimeError, ValueError, TypeError):
        return None
    return status if hmac.compare_digest(proof.encode(), expected.encode()) else None


def proxy_health(port: int, state=None) -> dict:
    if not supports_private_identity():
        return {"ready": False, "port": port, "https_decryption": False, "identity": "unavailable",
                "detail": "This platform needs an ACL-verified private identity backend"}
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
    try:
        nonce = secrets.token_urlsafe(32)
        status, data = request_json_object(connection, "GET", "http://egress-guard.invalid/health?nonce=" + nonce,
                                           seconds=HEALTH_RESPONSE_SECONDS)
        state = state or data_dir()
        valid = (status == 200 and data.get("product") == "egress-guard"
                 and data.get("ready") is True and data.get("https_decryption") is False
                 and isinstance(data.get("proof"), str)
                 and hmac.compare_digest(data["proof"].encode(), response_proof(nonce, port, state).encode()))
        # The applied-policy report is authenticated separately so it is visible while unready.
        return {"ready": bool(valid), "port": port, "https_decryption": False,
                "policy": _verified_policy(data, nonce, port, state)}
    except (OSError, ValueError, RuntimeError, http.client.HTTPException):
        return {"ready": False, "port": port, "https_decryption": False, "policy": None}
    finally:
        connection.close()
