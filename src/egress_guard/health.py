"""A bounded local-only proxy identity check."""
import http.client
import json


def proxy_health(port: int) -> dict:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
    try:
        connection.request("GET", "http://egress-guard.invalid/health")
        response = connection.getresponse()
        data = json.loads(response.read(4096))
        valid = (response.status == 200 and data.get("product") == "egress-guard"
                 and data.get("ready") is True and data.get("https_decryption") is False)
        return {"ready": bool(valid), "port": port, "https_decryption": False}
    except (OSError, ValueError, http.client.HTTPException):
        return {"ready": False, "port": port, "https_decryption": False}
    finally:
        connection.close()
