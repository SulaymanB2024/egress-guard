"""Bound response headers and bodies independently of per-read idle timeouts.

The budget starts after TCP/TLS connection establishment. Name resolution and
connection/handshake limits remain the transport's responsibility.
"""
from contextlib import AbstractContextManager
from functools import partial
import http.client
import json
import socket
import ssl
import threading
import time
import urllib.request


class ResponseDeadline(AbstractContextManager):
    def __init__(self, seconds):
        if type(seconds) not in (int, float) or not 0 < seconds <= 3600:
            raise ValueError("A response deadline must be finite and positive")
        self.seconds = seconds
        self._lock = threading.Lock()
        self._socket = None
        self._timer = None
        self._due = None
        self._expired = False

    def attach(self, connection_socket):
        if connection_socket is None:
            raise OSError("The response transport is not connected")
        # urllib may close its SSLSocket object while a response's buffered
        # file still owns the connection. SSLSocket.shutdown() then refuses to
        # operate. Keep one raw duplicate solely for shutdown, never for I/O.
        descriptor = socket.dup(connection_socket.fileno())
        try:
            control = socket.socket(connection_socket.family, connection_socket.type,
                                    connection_socket.proto, fileno=descriptor)
        except BaseException:
            socket.close(descriptor)
            raise
        try:
            control.settimeout(connection_socket.gettimeout())
        except BaseException:
            control.close()
            raise
        with self._lock:
            if self._due is not None:
                control.close()
                raise RuntimeError("A response deadline can guard only one connection")
            self._socket = control
            self._due = time.monotonic() + self.seconds
            self._timer = threading.Timer(self.seconds, self._expire)
            self._timer.daemon = True
            timer = self._timer
        try:
            timer.start()
        except RuntimeError as exc:
            # Resource pressure must use the callers' normal network-failure
            # recovery path, rather than terminate a canary polling worker.
            raise OSError("The response deadline could not start") from exc

    def _expire(self):
        with self._lock:
            self._expired = True
            connection_socket = self._socket
        if connection_socket is not None:
            try:
                # Shutdown interrupts a buffered read, including one holding its
                # stream lock. Calling response.close() in this thread may wait
                # for that same lock and would not enforce the deadline.
                connection_socket.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

    def check(self):
        with self._lock:
            expired = self._expired or (self._due is not None and time.monotonic() >= self._due)
        if expired:
            raise TimeoutError("The response exceeded its time budget")

    def __exit__(self, *_):
        with self._lock:
            timer = self._timer
            connection_socket = self._socket
            self._socket = None
        if timer is not None:
            timer.cancel()
        if connection_socket is not None:
            connection_socket.close()


class _HTTPConnection(http.client.HTTPConnection):
    def __init__(self, host, *, response_deadline, **options):
        self.response_deadline = response_deadline
        super().__init__(host, **options)

    def connect(self):
        super().connect()
        self.response_deadline.attach(self.sock)


class _HTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host, *, response_deadline, **options):
        self.response_deadline = response_deadline
        super().__init__(host, **options)

    def connect(self):
        super().connect()
        self.response_deadline.attach(self.sock)


class DeadlineHTTPHandler(urllib.request.HTTPHandler):
    def __init__(self, response_deadline):
        super().__init__()
        self.response_deadline = response_deadline

    def http_open(self, request):
        return self.do_open(partial(_HTTPConnection, response_deadline=self.response_deadline), request)


class DeadlineHTTPSHandler(urllib.request.HTTPSHandler):
    def __init__(self, response_deadline):
        super().__init__()
        self.response_deadline = response_deadline

    def https_open(self, request):
        return self.do_open(partial(_HTTPSConnection, response_deadline=self.response_deadline), request,
                            context=ssl.create_default_context())


def request_json_object(connection, method, target, *, seconds, body=None, headers=None, limit=4096):
    """Read one bounded JSON reply, including across an explicit reconnect.

    Each exchange gets its own response budget. Callers retain ownership of
    the HTTP connection and close it in their outer recovery path.
    """
    if connection.sock is None:
        connection.connect()
    with ResponseDeadline(seconds) as deadline:
        deadline.attach(connection.sock)
        connection.request(method, target, body=body, headers=headers or {})
        with connection.getresponse() as response:
            status = response.status
            raw = response.read(limit + 1)
            deadline.check()
            if len(raw) > limit:
                raise ValueError("The local response exceeded its size limit")
    try:
        value = json.loads(raw)
    except RecursionError as exc:
        raise ValueError("The local response is nested too deeply") from exc
    if not isinstance(value, dict):
        raise ValueError("The local response must be a JSON object")
    return status, value
