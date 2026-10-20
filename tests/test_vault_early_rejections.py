"""Rejets avant lecture du corps : fermeture effective HTTP/1.1 sous uvicorn/h11."""

import socket
import threading
import time
import unittest
from collections.abc import Iterator
from contextlib import contextmanager

import uvicorn
from starlette.types import ASGIApp, Receive, Scope, Send

from heimdall.vault.app import VaultSettings, create_app
from heimdall.vault.crypto import generate_api_key, hash_api_key


@contextmanager
def serve(app: ASGIApp) -> Iterator[int]:
    server = uvicorn.Server(
        uvicorn.Config(
            app,
            host="127.0.0.1",
            port=0,
            http="h11",
            loop="asyncio",
            lifespan="off",
            log_level="error",
            proxy_headers=False,
        )
    )
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    try:
        deadline = time.monotonic() + 10
        while not server.started:
            if not thread.is_alive() or time.monotonic() > deadline:
                raise RuntimeError("Le serveur de test n'a pas démarré.")
            time.sleep(0.01)
        yield server.servers[0].sockets[0].getsockname()[1]
    finally:
        server.should_exit = True
        thread.join(timeout=10)
        if thread.is_alive():
            raise RuntimeError("Le serveur de test ne s'est pas arrêté.")


def read_until_closed(sock: socket.socket) -> bytes:
    chunks = []
    while True:
        try:
            chunk = sock.recv(65536)
        except ConnectionResetError:
            break  # Fermeture TCP avec octets entrants non drainés.
        if not chunk:
            break
        chunks.append(chunk)
    return b"".join(chunks)


class EarlyRejectionTests(unittest.TestCase):
    def test_early_rejections_close_pipelined_connection(self) -> None:
        for rejection in ("peer", "global", "key", "loopback", "missing_peer", "header"):
            with self.subTest(rejection=rejection):
                self._check_rejection(rejection)

    def _check_rejection(self, rejection: str) -> None:
        target = create_app(
            VaultSettings(
                api_key_pepper="p" * 32,
                rate_limit_per_peer=1 if rejection == "peer" else 100,
                rate_limit_global=1 if rejection == "global" else 100,
                rate_limit_per_key=1,
            )
        )
        key = generate_api_key()
        target.state.register_api_key(key, "demo")
        if rejection in ("peer", "global"):
            target.state.rate_limiter.check("127.0.0.1")
        elif rejection == "key":
            target.state.rate_limiter.check_key(hash_api_key(key, pepper="p" * 32))
        elif rejection == "header":
            key = "A" * 513

        async def app(scope: Scope, receive: Receive, send: Send) -> None:
            if scope["path"] == "/api/v1/secrets":
                scope = dict(scope)
                if rejection == "loopback":
                    scope["client"] = ("203.0.113.1", 12345)
                elif rejection == "missing_peer":
                    scope["client"] = None
            await target(scope, receive, send)

        expected = (
            403
            if rejection in ("loopback", "missing_peer")
            else (401 if rejection == "header" else 429)
        )
        with serve(app) as port:
            body = b"x" * 1_048_577
            next_request = b"GET /api/v1/health HTTP/1.1\r\nHost: localhost\r\n\r\n"
            request = (
                (
                    "POST /api/v1/secrets HTTP/1.1\r\nHost: localhost\r\n"
                    f"X-Heimdall-API-Key: {key}\r\nContent-Length: {len(body)}\r\n"
                    "Connection: keep-alive\r\n\r\n"
                ).encode()
                + body
                + next_request
            )
            with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
                try:
                    sock.sendall(request)
                except (BrokenPipeError, ConnectionResetError):
                    pass  # Le serveur peut fermer avant la fin du corps.
                response = read_until_closed(sock)
            self.assertTrue(response.startswith(f"HTTP/1.1 {expected}".encode()), response[:100])
            self.assertIn(b"connection: close", response.lower())
            self.assertEqual(response.count(b"HTTP/1.1"), 1)
            if expected == 429:
                self.assertIn(b"retry-after:", response.lower())
            target.state.rate_limiter.clear()
            with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
                sock.sendall(next_request.replace(b"\r\n\r\n", b"\r\nConnection: close\r\n\r\n"))
                healthy = read_until_closed(sock)
            self.assertTrue(healthy.startswith(b"HTTP/1.1 200"), healthy[:100])
