"""Garde réseau runtime pour ``heimdall scan --ci``.

Les sockets Python sont interceptées avant l'appel système. Ce garde teste les
chemins applicatifs courants, mais ne remplace pas le contrôle OS ``strace`` ;
les sockets AF_UNIX restent une exception locale documentée.

Un alias ``from socket import getaddrinfo`` importé **après** le patch est
couvert (il relit l'attribut du module à chaque appel, vérifié par
``test_guard_blocks_dns_through_import_alias``) ; une valeur capturée **avant**
le patch (autre alias top-level, référence stockée) garde le wrapper original —
ce cas est verrouillé et documenté par
``test_early_bound_dns_alias_runs_unguarded_and_is_documented``. Les extensions
natives ou les appels syscalls directs hors wrappers Python restent couverts par
la trace OS.
"""

from __future__ import annotations

import ipaddress
import os
import socket
import ssl
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, cast
from unittest import mock

import pytest
from typer.testing import CliRunner

from heimdall.cli.main import app


def _is_local_destination(family: int, address: object) -> bool:
    """Autorise les sockets AF_UNIX et les adresses IP loopback littérales."""
    if family == socket.AF_UNIX:
        return True
    if family not in (socket.AF_INET, socket.AF_INET6):
        return False
    if not isinstance(address, tuple) or not address or not isinstance(address[0], str):
        return False
    try:
        ip = ipaddress.ip_address(address[0])
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return ip.ipv4_mapped.is_loopback
    return ip.is_loopback


@dataclass(frozen=True)
class NetworkAttempt:
    family: int
    destination: object
    blocked: bool


@dataclass
class NetworkLedger:
    attempts: list[NetworkAttempt] = field(default_factory=list)
    connected_loopback: set[socket.socket] = field(default_factory=set)
    # Références capturées avant le patch (preuve d'un trou connu du garde).
    original_getaddrinfo: Callable[..., object] | None = None

    @property
    def blocked(self) -> list[NetworkAttempt]:
        return [attempt for attempt in self.attempts if attempt.blocked]


@pytest.fixture
def loopback_only(monkeypatch: pytest.MonkeyPatch) -> NetworkLedger:  # noqa: PLR0915
    """Refuse les destinations externes et trace aussi les refus interceptés."""
    ledger = NetworkLedger(original_getaddrinfo=socket.getaddrinfo)
    original_connect = socket.socket.connect
    original_connect_ex = socket.socket.connect_ex
    original_send = socket.socket.send
    original_sendall = socket.socket.sendall
    original_sendto = socket.socket.sendto
    original_sendmsg = getattr(socket.socket, "sendmsg", None)
    original_sendfile = getattr(socket.socket, "sendfile", None)
    original_ssl_send = ssl.SSLSocket.send
    original_ssl_sendall = ssl.SSLSocket.sendall
    original_getaddrinfo = socket.getaddrinfo
    original_gethostbyname = socket.gethostbyname
    original_gethostbyname_ex = socket.gethostbyname_ex
    original_getnameinfo = socket.getnameinfo

    def precheck_destination(sock: socket.socket, address: object) -> bool:
        """Vérifie une destination et journalise, sans lever (hors wrappers)."""
        allowed = _is_local_destination(sock.family, address)
        ledger.attempts.append(NetworkAttempt(sock.family, address, not allowed))
        return allowed

    def check_destination(sock: socket.socket, address: object) -> None:
        if not precheck_destination(sock, address):
            raise AssertionError("sortie réseau interdite : destination hors boucle locale")

    def check_resolver_host(host: object) -> None:
        if isinstance(host, str):
            try:
                ip = ipaddress.ip_address(host)
            except ValueError:
                ledger.attempts.append(NetworkAttempt(socket.AF_INET, host, True))
                raise AssertionError("résolution réseau interdite : nom d'hôte") from None
            local = ip.is_loopback or (
                isinstance(ip, ipaddress.IPv6Address)
                and ip.ipv4_mapped is not None
                and ip.ipv4_mapped.is_loopback
            )
            family = socket.AF_INET6 if isinstance(ip, ipaddress.IPv6Address) else socket.AF_INET
            ledger.attempts.append(NetworkAttempt(family, host, not local))
            if not local:
                raise AssertionError("résolution réseau interdite : IP hors boucle locale")
            return
        ledger.attempts.append(NetworkAttempt(socket.AF_INET, repr(host), True))
        raise AssertionError("résolution réseau interdite : hôte non textuel")

    def check_connected_socket(sock: socket.socket) -> None:
        if sock.family == socket.AF_UNIX:
            ledger.attempts.append(NetworkAttempt(sock.family, "<IPC AF_UNIX>", False))
            return
        allowed = sock in ledger.connected_loopback
        ledger.attempts.append(NetworkAttempt(sock.family, "<socket connectée>", not allowed))
        if not allowed:
            raise AssertionError("envoi réseau interdit : socket non épinglée au loopback")

    def check_sendfile_file(sock: socket.socket, file: object) -> None:
        """Vérifie la socket puis exige un vrai fichier source.

        `sendfile` n'exporte que le contenu d'un fichier : un objet sans
        ``fileno`` est une erreur locale, pas une tentative réseau — on ne
        journalise pas de faux refus.
        """
        check_connected_socket(sock)
        if not hasattr(file, "fileno"):
            raise TypeError("sendfile attend un fichier")

    def guarded_connect(sock: socket.socket, address: Any) -> None:
        check_destination(sock, address)
        original_connect(sock, address)
        if sock.family in (socket.AF_INET, socket.AF_INET6):
            ledger.connected_loopback.add(sock)

    def guarded_connect_ex(sock: socket.socket, address: Any) -> int:
        check_destination(sock, address)
        result = original_connect_ex(sock, address)
        if result == 0 and sock.family in (socket.AF_INET, socket.AF_INET6):
            ledger.connected_loopback.add(sock)
        return result

    def guarded_send(sock: socket.socket, *args: Any, **kwargs: Any) -> int:
        check_connected_socket(sock)
        return original_send(sock, *args, **kwargs)

    def guarded_sendall(sock: socket.socket, *args: Any, **kwargs: Any) -> None:
        check_connected_socket(sock)
        original_sendall(sock, *args, **kwargs)

    def guarded_sendto(sock: socket.socket, data: bytes, *args: Any) -> int:
        # sendto(data, address), sendto(data, flags, address), ou sans adresse.
        address = args[-1] if args and isinstance(args[-1], (tuple, str, bytes)) else None
        if address is None:
            check_connected_socket(sock)
        else:
            check_destination(sock, address)
        return original_sendto(sock, data, *args)

    def guarded_sendmsg(sock: socket.socket, *args: Any, **kwargs: Any) -> int:
        address = kwargs.get("address")
        if address is None and len(args) >= 4:
            address = args[3]
        if address is None:
            check_connected_socket(sock)
        else:
            check_destination(sock, address)
        if original_sendmsg is None:
            raise AssertionError("sendmsg indisponible sur cette plateforme")
        return cast(int, original_sendmsg(sock, *args, **kwargs))

    def guarded_sendfile(sock: socket.socket, file: Any, *args: Any, **kwargs: Any) -> int:
        # Zéro-copie (os.sendfile) : ne passe ni par send ni par sendall.
        check_sendfile_file(sock, file)
        if original_sendfile is None:
            raise AssertionError("sendfile indisponible sur cette plateforme")
        return cast(int, original_sendfile(sock, file, *args, **kwargs))

    def guarded_ssl_send(sock: ssl.SSLSocket, *args: Any, **kwargs: Any) -> int:
        # SSLSocket.write passe par _sslobj : sans ce patch, un send TLS ne
        # traverserait pas socket.socket.send gardé.
        check_connected_socket(sock)
        return original_ssl_send(sock, *args, **kwargs)

    def guarded_ssl_sendall(sock: ssl.SSLSocket, *args: Any, **kwargs: Any) -> None:
        check_connected_socket(sock)
        original_ssl_sendall(sock, *args, **kwargs)

    def guarded_getaddrinfo(host: Any, port: Any, *args: Any, **kwargs: Any) -> Any:
        if host is not None:
            check_resolver_host(host)
        return original_getaddrinfo(host, port, *args, **kwargs)

    def guarded_gethostbyname(host: Any) -> str:
        check_resolver_host(host)
        return original_gethostbyname(host)

    def guarded_gethostbyname_ex(host: Any) -> tuple[str, list[str], list[str]]:
        check_resolver_host(host)
        return original_gethostbyname_ex(host)

    def guarded_gethostbyaddr(host: Any) -> tuple[str, list[str], list[str]]:
        # Même une adresse loopback pourrait déclencher une requête PTR.
        ledger.attempts.append(NetworkAttempt(socket.AF_INET, repr(host), True))
        raise AssertionError("résolution DNS inverse interdite")

    def guarded_getnameinfo(sockaddr: Any, flags: int) -> tuple[str, str]:
        if not flags & socket.NI_NUMERICHOST:
            ledger.attempts.append(NetworkAttempt(socket.AF_INET, repr(sockaddr), True))
            raise AssertionError("résolution DNS inverse interdite")
        if not isinstance(sockaddr, tuple) or not sockaddr:
            ledger.attempts.append(NetworkAttempt(socket.AF_INET, repr(sockaddr), True))
            raise AssertionError("adresse de résolution invalide")
        check_resolver_host(sockaddr[0])
        return original_getnameinfo(sockaddr, flags)

    monkeypatch.setattr(socket.socket, "connect", guarded_connect)
    monkeypatch.setattr(socket.socket, "connect_ex", guarded_connect_ex)
    monkeypatch.setattr(socket.socket, "send", guarded_send)
    monkeypatch.setattr(socket.socket, "sendall", guarded_sendall)
    monkeypatch.setattr(socket.socket, "sendto", guarded_sendto)
    if original_sendmsg is not None:
        monkeypatch.setattr(socket.socket, "sendmsg", guarded_sendmsg)
    if original_sendfile is not None:
        monkeypatch.setattr(socket.socket, "sendfile", guarded_sendfile)
    monkeypatch.setattr(ssl.SSLSocket, "send", guarded_ssl_send)
    monkeypatch.setattr(ssl.SSLSocket, "sendall", guarded_ssl_sendall)
    monkeypatch.setattr(socket, "getaddrinfo", guarded_getaddrinfo)
    monkeypatch.setattr(socket, "gethostbyname", guarded_gethostbyname)
    monkeypatch.setattr(socket, "gethostbyname_ex", guarded_gethostbyname_ex)
    monkeypatch.setattr(socket, "gethostbyaddr", guarded_gethostbyaddr)
    monkeypatch.setattr(socket, "getnameinfo", guarded_getnameinfo)

    original_os_sendfile = getattr(os, "sendfile", None)
    if original_os_sendfile is not None:

        def guarded_os_sendfile(
            out_fd: int, in_fd: int, offset: int = 0, count: int | None = None
        ) -> int:
            # Appel direct `os.sendfile(sock.fileno(), ...)`, sans passer par
            # Socket.sendfile : le descripteur doit être celui d'une socket
            # loopback déjà épinglée, sinon l'accès disque/fichier est refusé.
            pinned = any(sock.fileno() == out_fd for sock in ledger.connected_loopback)
            family = next(
                (sock.family for sock in ledger.connected_loopback if sock.fileno() == out_fd),
                socket.AF_INET,
            )
            ledger.attempts.append(NetworkAttempt(family, f"fd={out_fd}", not pinned))
            if not pinned:
                raise AssertionError("envoi réseau interdit : descripteur hors socket loopback")
            if count is None:
                return cast(int, original_os_sendfile(out_fd, in_fd, offset))
            return cast(int, original_os_sendfile(out_fd, in_fd, offset, count))

        monkeypatch.setattr(os, "sendfile", guarded_os_sendfile)
    return ledger


def test_scan_ci_never_attempts_external_traffic(
    loopback_only: NetworkLedger, tmp_path: Path
) -> None:
    """Une tentative externe reste visible même si la CLI la capture."""
    result = CliRunner().invoke(app, ["scan", "--ci", str(tmp_path)])

    # Le scanner #22 n'est pas livré : son refus code 2 est attendu.
    assert result.exit_code in (0, 2), result.output
    if result.exit_code == 2:
        assert "scanner non implémenté (voir #22)" in result.stderr
    assert loopback_only.blocked == []
    assert all(
        not attempt.blocked
        for attempt in loopback_only.attempts
        if attempt.family in (socket.AF_INET, socket.AF_INET6)
    )


@pytest.mark.parametrize(
    ("family", "address"),
    [
        (socket.AF_INET, ("203.0.113.7", 443)),
        (socket.AF_INET6, ("2001:db8::7", 443, 0, 0)),
        (socket.AF_INET, ("evil.example", 443)),
    ],
)
def test_guard_records_and_blocks_external_connect(
    loopback_only: NetworkLedger, family: int, address: object
) -> None:
    with socket.socket(family, socket.SOCK_STREAM) as sock:
        with pytest.raises(AssertionError, match="destination hors boucle locale"):
            sock.connect(address)  # type: ignore[arg-type]
    assert len(loopback_only.blocked) == 1


@pytest.mark.parametrize("method", ["send", "sendall", "sendto", "sendmsg"])
def test_guard_blocks_payload_on_unpinned_socket(loopback_only: NetworkLedger, method: str) -> None:
    if method == "sendmsg" and not hasattr(socket.socket, "sendmsg"):
        pytest.skip("sendmsg indisponible sur cette plateforme")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        with pytest.raises(AssertionError, match="socket non épinglée"):
            if method == "sendto":
                getattr(sock, method)(b"synthetic probe", 0)
            else:
                getattr(sock, method)(b"synthetic probe")
    assert len(loopback_only.blocked) == 1


def test_guard_allows_and_tracks_loopback_tcp(loopback_only: NetworkLedger) -> None:
    """L'Ollama local reste accessible et les envois suivent le connect autorisé."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
            client.connect(listener.getsockname())
            peer, _address = listener.accept()
            with peer:
                client.sendall(b"loopback")
                assert peer.recv(8) == b"loopback"
    assert loopback_only.blocked == []
    destinations = [
        attempt for attempt in loopback_only.attempts if isinstance(attempt.destination, tuple)
    ]
    assert destinations
    assert all(
        _is_local_destination(attempt.family, attempt.destination) for attempt in destinations
    )


def test_guard_blocks_external_udp_destination(loopback_only: NetworkLedger) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        with pytest.raises(AssertionError, match="destination hors boucle locale"):
            sock.sendto(b"synthetic probe", ("203.0.113.9", 53))
    assert len(loopback_only.blocked) == 1


@pytest.mark.parametrize(
    ("resolver", "host"),
    [
        ("getaddrinfo", "evil.example"),
        ("getaddrinfo", b"evil.example"),
        ("gethostbyname", "evil.example"),
        ("gethostbyname_ex", "evil.example"),
        ("gethostbyaddr", "203.0.113.7"),
    ],
)
def test_guard_blocks_and_records_dns_attempts(
    loopback_only: NetworkLedger, resolver: str, host: object
) -> None:
    with pytest.raises(AssertionError, match="résolution"):
        if resolver in ("getaddrinfo",):
            getattr(socket, resolver)(host, 443)
        else:
            getattr(socket, resolver)(host)
    assert len(loopback_only.blocked) == 1


def test_guard_blocks_reverse_name_lookup(loopback_only: NetworkLedger) -> None:
    with pytest.raises(AssertionError, match="résolution DNS inverse interdite"):
        socket.getnameinfo(("203.0.113.7", 443), 0)
    assert len(loopback_only.blocked) == 1


def test_guard_blocks_sendfile_on_unpinned_socket(
    loopback_only: NetworkLedger, tmp_path: Path
) -> None:
    """Le chemin zéro-copie (os.sendfile) est gardé comme send/sendall."""
    if not hasattr(socket.socket, "sendfile"):
        pytest.skip("sendfile indisponible sur cette plateforme")
    source = tmp_path / "source.bin"
    source.write_bytes(b"synthetic payload")
    with source.open("rb") as handle, socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        with pytest.raises(AssertionError, match="socket non épinglée"):
            sock.sendfile(handle)
    assert len(loopback_only.blocked) == 1


def test_guard_blocks_ssl_send_on_unpinned_socket(loopback_only: NetworkLedger) -> None:
    """SSLSocket.send ne peut pas contourner le garde par _sslobj.

    Un vrai SSLSocket exige une poignée de main TLS : on le simule par un mock
    marqué ``spec=socket.socket``, qui passe le contrôle de type du garde et
    échouerait ensuite sur ``_sslobj`` — l'``AssertionError`` du garde arrive
    donc bien avant tout écrit TLS.
    """
    fake = mock.Mock(spec=socket.socket)
    fake.family = socket.AF_INET
    with pytest.raises(AssertionError, match="socket non épinglée"):
        ssl.SSLSocket.send(fake, b"synthetic probe")
    with pytest.raises(AssertionError, match="socket non épinglée"):
        ssl.SSLSocket.sendall(fake, b"synthetic probe")
    assert len(loopback_only.blocked) == 2


def test_guard_blocks_dns_through_import_alias(loopback_only: NetworkLedger) -> None:
    """Alias importé APRÈS le patch : relu sur le module, donc gardé."""
    from socket import getaddrinfo  # noqa: PLC0415 - l'alias est le sujet du test

    with pytest.raises(AssertionError, match="résolution réseau interdite"):
        getaddrinfo("evil.example", 443)
    assert len(loopback_only.blocked) == 1


def test_early_bound_dns_alias_runs_unguarded_and_is_documented(
    loopback_only: NetworkLedger,
) -> None:
    """Valeur capturée AVANT le patch : trou connu, verrouillé et documenté.

    Un alias top-level garde la référence à la fonction d'origine. On capte
    cette référence à la construction de la fixture (preuve qu'elle diffère du
    wrapper), puis on montre qu'un appel sur une adresse qu'un wrapper aurait
    journalisée ne laisse aucune trace : c'est bien l'original non gardé, et
    le filet réel de ce cas est la trace OS ``strace``. L'exécution de
    l'original dépend de la table de routage de la machine de test (succès ou
    échec local) ; l'assertion qui compte est l'absence de journalisation.
    """
    original = loopback_only.original_getaddrinfo
    assert original is not None
    assert original is not socket.getaddrinfo  # référence d'origine, non patchée
    try:
        original("192.0.2.99", 443, type=socket.SOCK_DGRAM)
    except OSError:
        # Route absente sur la machine de test : échec local, aucun octet.
        pass
    assert loopback_only.attempts == []  # hors garde : rien n'est journalisé


def test_guard_blocks_os_sendfile_on_unpinned_fd(
    loopback_only: NetworkLedger, tmp_path: Path
) -> None:
    """`os.sendfile(fd)` direct n'échappe pas au garde (pas que Socket.sendfile)."""
    if not hasattr(os, "sendfile"):
        pytest.skip("os.sendfile indisponible sur cette plateforme")
    source = tmp_path / "source.bin"
    source.write_bytes(b"synthetic payload")
    with source.open("rb") as handle, socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        with pytest.raises(AssertionError, match="descripteur hors socket loopback"):
            os.sendfile(sock.fileno(), handle.fileno(), 0, 16)
    assert len(loopback_only.blocked) == 1


def test_guard_allows_only_loopback_ip_literals_and_notes_unix_exception() -> None:
    assert _is_local_destination(socket.AF_INET, ("127.0.0.1", 11434))
    assert _is_local_destination(socket.AF_INET6, ("::1", 11434, 0, 0))
    assert _is_local_destination(socket.AF_INET6, ("::ffff:127.0.0.1", 11434, 0, 0))
    assert not _is_local_destination(socket.AF_INET, ("192.0.2.1", 443))
    assert _is_local_destination(socket.AF_UNIX, "/run/local-service.sock")
