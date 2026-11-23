"""Bounded metadata for SendData commands in the controlled proxy fixture.

This module is never loaded by the production proxy. It observes commands AFTER
the real PolicyRelay admits them. Counts describe emitted encrypted TLS bytes,
not kernel delivery, TCP acknowledgements or decrypted request attribution.
"""
from __future__ import annotations

import json
from mitmproxy.proxy import commands
from egress_guard.paths import atomic_private


def install(addon_module, path, origins, *, on_failure, maximum=8192):
    original = addon_module.PolicyRelay
    rows = {}
    overflow = False
    failed = False

    def fail():
        nonlocal failed
        if not failed:
            failed = True
            # The parent receives this over an independent inherited pipe, not
            # the filesystem whose write just failed. Never impede forwarding.
            try:
                on_failure()
            except Exception:
                pass

    def save():
        atomic_private(path, (json.dumps({"schema": 1, "overflow": overflow,
                       "tunnels": list(rows.values())}, sort_keys=True) + "\n").encode())

    class MeteredRelay(original):
        def handle_event(self, event):
            nonlocal overflow
            for command in super().handle_event(event):
                if isinstance(command, commands.SendData) and not failed:
                    try:
                        server = self.context.server
                        key = str(server.id)
                        if key not in rows:
                            if len(rows) >= maximum:
                                overflow = True
                            else:
                                rows[key] = {"tunnel_id": key, "host": origins.get(server.id),
                                             "peer_port": server.sockname[1] if server.sockname else None,
                                             "to_origin_bytes": 0, "to_client_bytes": 0,
                                             "origin_send_commands": 0, "client_send_commands": 0}
                        if key in rows:
                            row = rows[key]
                            if command.connection == server:
                                row["to_origin_bytes"] += len(command.data)
                                row["origin_send_commands"] += 1
                            elif command.connection == self.context.client:
                                row["to_client_bytes"] += len(command.data)
                                row["client_send_commands"] += 1
                            else:
                                overflow = True
                        save()
                    except Exception:
                        fail()
                yield command

    addon_module.PolicyRelay = MeteredRelay
    try:
        save()
    except Exception:
        fail()
