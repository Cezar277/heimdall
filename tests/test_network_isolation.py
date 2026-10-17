"""Garde réseau runtime : Heimdall ne se connecte qu'à la boucle locale.

Ce garde intercepte les sockets Python avant l'appel système. Il complète,
mais ne remplace pas, une observation OS avec ``strace`` (voir
``docs/security/zero-egress.md``).
"""

from __future__ import annotations

import ipaddress
import socket
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from heimdall.cli.main import app


def _is_local_destination(family: int, address: object) -> bool:
    """Autorise les sockets locales et les adresses IP loopback littérales."""
    if family == socket.AF_UNIX:
        return True
    if family not in (socket.AF_INET, socket.AF_INET6):
        return False
    if not isinstance(address, tuple) or not address or not isinstance(address[0], str):
        return False
    try:
        ip = ipaddress.ip_address(address[0])
    except ValueError:
        # Refuse les noms d'hôte : leur résolution pourrait sortir sur DNS.
        return False
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return ip.ipv4_mapped.is_loopback
    return ip.is_loopback


@pytest.fixture
def loopback_only(monkeypatch: pytest.MonkeyPatch) -> list[tuple[int, object]]:
    """Interdit les destinations externes avant résolution ou syscall réseau."""
    attempted: list[tuple[int, object]] = []
    original_connect = socket.socket.connect
    original_connect_ex = socket.socket.connect_ex
    original_sendto = socket.socket.sendto
    original_getaddrinfo = socket.getaddrinfo

    def check_destination(sock: socket.socket, address: object) -> None:
        if not _is_local_destination(sock.family, address):
            raise AssertionError("sortie réseau interdite : destination hors boucle locale")
        if sock.family in (socket.AF_INET, socket.AF_INET6):
            attempted.append((sock.family, address))

    def guarded_connect(sock: socket.socket, address: Any) -> None:
        check_destination(sock, address)
        original_connect(sock, address)

    def guarded_connect_ex(sock: socket.socket, address: Any) -> int:
        check_destination(sock, address)
        return original_connect_ex(sock, address)

    def guarded_sendto(sock: socket.socket, data: bytes, *args: Any) -> int:
        # Formes admises : sendto(data, address) et sendto(data, flags, address).
        if len(args) >= 1 and isinstance(args[-1], (tuple, str, bytes)):
            check_destination(sock, args[-1])
        return original_sendto(sock, data, *args)

    def guarded_getaddrinfo(host: Any, port: Any, *args: Any, **kwargs: Any) -> Any:
        # Refuser les noms avant NSS/DNS : connect() seul arrive trop tard si
        # un client a déjà résolu le nom via getaddrinfo().
        if host is None:
            return original_getaddrinfo(host, port, *args, **kwargs)
        if not isinstance(host, str):
            raise AssertionError("résolution réseau interdite : hôte non textuel")
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            raise AssertionError("résolution réseau interdite : nom d'hôte") from None
        if not ip.is_loopback and not (
            isinstance(ip, ipaddress.IPv6Address)
            and ip.ipv4_mapped is not None
            and ip.ipv4_mapped.is_loopback
        ):
            raise AssertionError("résolution réseau interdite : IP hors boucle locale")
        return original_getaddrinfo(host, port, *args, **kwargs)

    monkeypatch.setattr(socket.socket, "connect", guarded_connect)
    monkeypatch.setattr(socket.socket, "connect_ex", guarded_connect_ex)
    monkeypatch.setattr(socket.socket, "sendto", guarded_sendto)
    monkeypatch.setattr(socket, "getaddrinfo", guarded_getaddrinfo)
    return attempted


def test_scan_ci_never_connects_outside_loopback(
    loopback_only: list[tuple[int, object]], tmp_path: Path
) -> None:
    """La commande scan reste locale, même lorsqu'elle échoue fail-closed."""
    result = CliRunner().invoke(app, ["scan", "--ci", str(tmp_path)])

    # Le scanner #22 n'est pas encore livré : son refus code 2 est attendu.
    # Quand il le sera, un dépôt vide pourra aussi terminer proprement (code 0).
    assert result.exit_code in (0, 2), result.output
    if result.exit_code == 2:
        assert "scanner non implémenté (voir #22)" in result.stderr
    assert all(_is_local_destination(family, address) for family, address in loopback_only)


@pytest.mark.parametrize(
    ("family", "address"),
    [
        (socket.AF_INET, ("203.0.113.7", 443)),
        (socket.AF_INET6, ("2001:db8::7", 443, 0, 0)),
        (socket.AF_INET, ("evil.example", 443)),
    ],
)
def test_guard_blocks_external_connect(
    loopback_only: list[tuple[int, object]], family: int, address: object
) -> None:
    """Vérifie que le garde échoue avant tout appel réseau réel."""
    with socket.socket(family, socket.SOCK_STREAM) as sock:
        with pytest.raises(AssertionError, match="destination hors boucle locale"):
            sock.connect(address)  # type: ignore[arg-type]
    assert loopback_only == []


def test_guard_blocks_external_udp_send(loopback_only: list[tuple[int, object]]) -> None:
    """Les datagrammes non connectés sont aussi refusés avant l'appel système."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        with pytest.raises(AssertionError, match="destination hors boucle locale"):
            sock.sendto(b"synthetic probe", ("203.0.113.9", 53))
    assert loopback_only == []


def test_guard_blocks_external_connect_ex(loopback_only: list[tuple[int, object]]) -> None:
    """La variante connect_ex est gardée avant l'appel système également."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        with pytest.raises(AssertionError, match="destination hors boucle locale"):
            sock.connect_ex(("198.51.100.5", 443))
    assert loopback_only == []


def test_guard_blocks_dns_before_resolution(loopback_only: list[tuple[int, object]]) -> None:
    """Un nom externe est refusé avant que le resolver système soit appelé."""
    with pytest.raises(AssertionError, match="résolution réseau interdite"):
        socket.getaddrinfo("evil.example", 443)
    with pytest.raises(AssertionError, match="résolution réseau interdite"):
        socket.getaddrinfo(b"evil.example", 443)
    assert loopback_only == []


def test_guard_accepts_loopback_ip_literals() -> None:
    assert _is_local_destination(socket.AF_INET, ("127.0.0.1", 11434))
    assert _is_local_destination(socket.AF_INET6, ("::1", 11434, 0, 0))
    assert _is_local_destination(socket.AF_INET6, ("::ffff:127.0.0.1", 11434, 0, 0))
    assert not _is_local_destination(socket.AF_INET, ("192.0.2.1", 443))
