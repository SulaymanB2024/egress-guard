"""Small deterministic clients for the owned HTTP/1.1 and WebSocket origins."""
from __future__ import annotations

import base64
import http.client
import struct


def tunnel(lab, host):
    connection = http.client.HTTPConnection("127.0.0.1", lab.proxy_port, timeout=4)
    try:
        connection.set_tunnel(host, lab.server.server_port)
        connection.connect()
        stream = lab.client_tls.wrap_socket(connection.sock, server_hostname=host)
        if stream.getpeercert(binary_form=True) != lab.cert_der:
            stream.close()
            raise RuntimeError("The original controlled origin certificate changed")
        return stream
    except BaseException:
        connection.close()
        raise


def http_request(lab, host, target, *, body=None, headers=(), close=False):
    method = "GET" if body is None else "POST"
    lines = [f"{method} {target} HTTP/1.1", f"Host: {host}:{lab.server.server_port}"]
    if body is not None:
        lines.append(f"Content-Length: {len(body)}")
    lines.extend(f"{name}: {value}" for name, value in headers)
    if close:
        lines.append("Connection: close")
    return ("\r\n".join(lines) + "\r\n\r\n").encode("ascii") + (body or b"")


def response(reader):
    # A persistent reader is deliberate: a socket read can contain both HTTP
    # responses. Creating a fresh buffered reader would discard the second one.
    status = reader.readline(8193)
    if len(status) > 8192 or not status.startswith(b"HTTP/1.1 200 "):
        raise RuntimeError("Expected a functional HTTP/1.1 response")
    lengths = []
    for _ in range(100):
        line = reader.readline(8193)
        if line == b"\r\n":
            break
        if not line or len(line) > 8192:
            raise RuntimeError("Incomplete bounded response headers")
        name, _, value = line.partition(b":")
        if name.lower() == b"content-length":
            lengths.append(value.strip())
    else:
        raise RuntimeError("Too many response headers")
    if len(lengths) != 1 or not lengths[0].isdigit() or int(lengths[0]) > 8192:
        raise RuntimeError("Ambiguous response length")
    body = reader.read(int(lengths[0]))
    if body != b'{"ok":true}':
        raise RuntimeError("Functional response body changed")
    return body


def websocket(lab, host, visit, *, case="socket"):
    stream = tunnel(lab, host)
    try:
        key = base64.b64encode(b"0123456789abcdef").decode()
        request = http_request(lab, host, f"/socket?visit={visit}&case={case}", headers=(
            ("Upgrade", "websocket"), ("Connection", "Upgrade"),
            ("Sec-WebSocket-Key", key), ("Sec-WebSocket-Version", "13")))
        stream.sendall(request)
        header = bytearray()
        while not header.endswith(b"\r\n\r\n"):
            chunk = stream.recv(1)
            if not chunk or len(header) >= 8192:
                raise RuntimeError("Incomplete WebSocket upgrade")
            header.extend(chunk)
        if not header.startswith(b"HTTP/1.1 101 "):
            raise RuntimeError("WebSocket upgrade failed")
        return stream, len(request)
    except BaseException:
        stream.close()
        raise


def frame(body):
    if not isinstance(body, bytes) or len(body) > 8192:
        raise ValueError("Expected a bounded synthetic payload")
    mask = b"lab!"
    size = bytes([0x80 | len(body)]) if len(body) < 126 else b"\xfe" + struct.pack("!H", len(body))
    return b"\x81" + size + mask + bytes(value ^ mask[i % 4] for i, value in enumerate(body))


def ack(stream):
    data = bytearray()
    while len(data) < 5:
        chunk = stream.recv(5 - len(data))
        if not chunk:
            raise RuntimeError("Functional WebSocket acknowledgement missing")
        data.extend(chunk)
    if data != b"\x81\x03ack":
        raise RuntimeError("Unexpected WebSocket acknowledgement")
