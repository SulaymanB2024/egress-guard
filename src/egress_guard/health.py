"""A bounded local-only proxy identity check."""
import http.client
import json
import hashlib
import hmac
import secrets

from .paths import data_dir, supports_private_identity


def response_proof(nonce, port, state):
    from .dashboard_http import installation_token
    key = installation_token(state)
    return hmac.new(key.encode(), f"egress-guard/v1:proxy:{nonce}:{port}".encode(), hashlib.sha256).hexdigest()


def proxy_health(port: int, state=None) -> dict:
    if not supports_private_identity():
        return {"ready": False, "port": port, "https_decryption": False, "identity": "unavailable",
                "detail": "This platform needs an ACL-verified private identity backend"}
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
    try:
        nonce = secrets.token_urlsafe(32)
        connection.request("GET", "http://egress-guard.invalid/health?nonce=" + nonce)
        response = connection.getresponse()
        data = json.loads(response.read(4096))
        if not isinstance(data, dict):
            return {"ready": False, "port": port, "https_decryption": False}
        valid = (response.status == 200 and data.get("product") == "egress-guard"
                 and data.get("ready") is True and data.get("https_decryption") is False
                 and isinstance(data.get("proof"), str)
                 and hmac.compare_digest(data["proof"].encode(), response_proof(nonce, port, state or data_dir()).encode()))
        return {"ready": bool(valid), "port": port, "https_decryption": False}
    except (OSError, ValueError, RuntimeError, http.client.HTTPException):
        return {"ready": False, "port": port, "https_decryption": False}
    finally:
        connection.close()
