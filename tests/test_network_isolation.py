"""Garde réseau runtime pour ``heimdall scan --ci``.

Les sockets Python sont interceptées avant l'appel système. Ce garde teste des
chemins applicatifs courants **côté Python**, mais ne remplace pas le contrôle
OS ``strace`` ; les sockets AF_UNIX restent une exception locale documentée
(autorisées en ``send``, refusées en écriture par descripteur — asymétrie
verrouillée par test). Le lancement de processus enfants est refusé et
journalisé pour ``subprocess.Popen`` par accès d'attribut et pour
``os.system``/``fork``/``posix_spawn``/``exec*`` ; un lancement hors wrappers
(alias précoce ``from subprocess import Popen``, chemin C
``_posixsubprocess``, extension native, binaire) reste hors garde et n'est
visible que par ``strace -f``, qui suit les forks. Les six méthodes
que ``ssl.SSLSocket`` surcharge (``send``, ``sendall``, ``write``, ``sendto``,
``sendmsg``, ``sendfile``) sont patchées séparément : elles ne passent pas par
celles de ``socket.socket``. Les écritures par descripteur (``os.write``,
``os.writev``, ``os.sendfile``) sont gardées tant qu'elles passent par les
wrappers Python ; ``strace -e trace=%network`` ne traçant pas ``write``, le
rejeu OS utilise un filtre étendu (voir ``docs/security/zero-egress.md``).

Un alias ``from socket import getaddrinfo`` (ou ``from os import write``)
importé **après** le patch est couvert (il relit l'attribut du module à chaque
appel, vérifié par ``test_guard_blocks_dns_through_import_alias``) ; une valeur
capturée **avant** le patch (autre alias top-level, référence stockée) garde
l'original — verrouillé par
``test_early_bound_dns_alias_runs_unguarded_and_is_documented`` (DNS) et
``test_early_bound_os_write_runs_unguarded_and_is_documented`` (``os.*``). Le
filet OS de ces cas est le filtre ``strace`` étendu
(``%network,write,writev,sendfile``).
"""

from __future__ import annotations

import ipaddress
import os
import re
import socket
import ssl
import stat
import subprocess
import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final, cast
from unittest import mock

import pytest
from support.git_repo import GIT
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
    original_os_write: Callable[..., int] | None = None
    original_popen: Callable[..., Any] | None = None

    @property
    def blocked(self) -> list[NetworkAttempt]:
        return [attempt for attempt in self.attempts if attempt.blocked]


#: Args **exacts** des lectures git du produit. Toute dérive (nouvelle
#: option, sous-commande non listée) casse ce test au lieu d'être acceptée
#: comme « locale » par simple préfixe.
_GIT_DIFF_ARGUMENTS: Final[tuple[str, ...]] = (
    "diff",
    "--cached",
    "--unified=0",
    "--no-color",
    "--no-ext-diff",
    "--no-textconv",
)
_GIT_STAGED_RAW_ARGUMENTS: Final[tuple[str, ...]] = (
    "diff",
    "--cached",
    "--raw",
    "-z",
    "--no-abbrev",
    "--no-renames",
    "--no-ext-diff",
    "--no-textconv",
)
_GIT_OBJECT_RE: Final[re.Pattern[str]] = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})")


def _git_argv_ok(argv: Any) -> bool:
    """True pour l'argv figé des invocations git du produit, et lui seul.

    Binaire `git`, neutralisation `core.fsmonitor`, placement `-C <racine>`,
    puis **allowlist exacte** des arguments de lecture. Un `diff` avec une
    option d'egress ajoutée, un `cat-file --follow-symlinks` ou un `git log`
    préfixé valide sont refusés : le garde ne se contente pas du nom de la
    sous-commande. Noyau partagé par les deux couches d'exécution
    (`subprocess.Popen` et `os.posix_spawn`, par lequel CPython implémente
    `Popen`).
    """
    if not isinstance(argv, (list, tuple)) or len(argv) < 6:
        return False
    if not isinstance(argv[0], str) or os.path.basename(argv[0]) != "git":
        return False
    if list(argv[1:4]) != ["-c", "core.fsmonitor=false", "-C"]:
        return False
    if not isinstance(argv[4], str):
        return False
    tail = tuple(argv[5:])
    return (
        tail == ("rev-parse", "--show-toplevel")
        or tail in (_GIT_DIFF_ARGUMENTS, _GIT_STAGED_RAW_ARGUMENTS)
        or (
            len(tail) == 4
            and tail[:3] == ("check-ignore", "-q", "--")
            and isinstance(tail[3], str)
        )
        or (
            len(tail) == 4
            and tail[0] == "cat-file"
            and tail[1] in ("-s", "blob")
            and tail[2] == "--"
            and isinstance(tail[3], str)
            and _GIT_OBJECT_RE.fullmatch(tail[3]) is not None
        )
    )


def _is_local_git_call(args: Any, kwargs: Any) -> bool:
    """True pour les invocations git figées du produit, et elles seules.

    Forme exacte émise par `heimdall/mcp/gitdiff.py` : `argv` ci-dessus, plus
    `stdin=DEVNULL` — un appel git qui hériterait stdin ne vient pas du
    produit. Tout le reste (`git fetch`, `git init`, autre binaire, argv non
    liste) reste refusé.
    """
    if not isinstance(args, (list, tuple)) or not args:
        return False
    if kwargs.get("stdin") is not subprocess.DEVNULL:
        return False
    return _git_argv_ok(args[0])


def _is_local_git_spawn(args: Any) -> bool:
    """True pour l'appel `os.posix_spawn` sous-jacent à un appel produit.

    Même `argv` que ci-dessus (`posix_spawn(path, argv, env, …)`, donc en
    position 1). Le `stdin=DEVNULL` ne se vérifie pas à cette couche (il est
    déjà traduit en actions de fichiers) : il est exigé à la couche `Popen`,
    par laquelle passe tout appel du produit.
    """
    if not isinstance(args, (list, tuple)) or len(args) < 2:
        return False
    return _git_argv_ok(args[1])


@pytest.fixture
def loopback_only(monkeypatch: pytest.MonkeyPatch) -> NetworkLedger:  # noqa: PLR0915
    """Refuse les destinations externes et trace aussi les refus interceptés."""
    ledger = NetworkLedger(
        original_getaddrinfo=socket.getaddrinfo,
        original_os_write=os.write,
        original_popen=subprocess.Popen,
    )
    original_connect = socket.socket.connect
    original_connect_ex = socket.socket.connect_ex
    original_send = socket.socket.send
    original_sendall = socket.socket.sendall
    original_sendto = socket.socket.sendto
    original_sendmsg = getattr(socket.socket, "sendmsg", None)
    original_sendfile = getattr(socket.socket, "sendfile", None)
    # SSLSocket surcharge ces six méthodes : les patchs de socket.socket ne
    # s'appliquent pas aux instances TLS.
    original_ssl_send = ssl.SSLSocket.send
    original_ssl_sendall = ssl.SSLSocket.sendall
    original_ssl_write = ssl.SSLSocket.write
    original_ssl_sendto = ssl.SSLSocket.sendto
    original_ssl_sendmsg = ssl.SSLSocket.sendmsg
    original_ssl_sendfile = ssl.SSLSocket.sendfile
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

    def check_fd_destination(fd: int, label: str) -> None:
        """Refuse les écritures par descripteur vers une socket non épinglée.

        Les descripteurs qui ne sont pas des sockets (fichiers, tubes) restent
        des écritures locales autorisées ; un descripteur de socket qui
        n'appartient pas au loopback épinglé est journalisé puis refusé.
        """
        try:
            mode = os.fstat(fd).st_mode
        except OSError:
            return  # descripteur invalide : l'appel d'origine lèvera
        if not stat.S_ISSOCK(mode):
            return
        pinned_socket = next(
            (sock for sock in ledger.connected_loopback if sock.fileno() == fd), None
        )
        ledger.attempts.append(
            NetworkAttempt(
                pinned_socket.family if pinned_socket is not None else socket.AF_INET,
                f"fd={fd}",
                pinned_socket is None,
            )
        )
        if pinned_socket is None:
            raise AssertionError(f"{label} : descripteur hors socket loopback")

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

    def guarded_sendto(sock: socket.socket, data: bytes, *args: Any, **kwargs: Any) -> int:
        # sendto(data, address), sendto(data, flags, address) ; l'adresse peut
        # arriver en mot-clé : on la contrôle aussi (fail-closed) même si
        # CPython refuse ensuite les arguments nommés.
        address = kwargs.get("address")
        if address is None and args and isinstance(args[-1], (tuple, str, bytes)):
            address = args[-1]
        if address is None:
            check_connected_socket(sock)
        else:
            check_destination(sock, address)
        return original_sendto(sock, data, *args, **kwargs)

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

    def guarded_ssl_write(sock: ssl.SSLSocket, *args: Any, **kwargs: Any) -> int:
        # `SSLSocket.write` écrit via `_sslobj.write`, sans passer par `send`.
        check_connected_socket(sock)
        return original_ssl_write(sock, *args, **kwargs)

    def guarded_ssl_sendto(
        sock: ssl.SSLSocket, data: Any, flags_or_addr: Any, addr: Any = None
    ) -> int:
        # Signature TLS : sendto(data, addr) ou sendto(data, flags, addr).
        destination = addr if addr is not None else flags_or_addr
        if destination is None:
            check_connected_socket(sock)
        else:
            check_destination(sock, destination)
        return original_ssl_sendto(sock, data, flags_or_addr, addr)

    def guarded_ssl_sendmsg(sock: ssl.SSLSocket, *args: Any, **kwargs: Any) -> int:
        # `SSLSocket.sendmsg` refuse déjà l'envoi ; on bloque d'abord.
        check_connected_socket(sock)
        return original_ssl_sendmsg(sock, *args, **kwargs)

    def guarded_ssl_sendfile(
        sock: ssl.SSLSocket, file: Any, offset: int = 0, count: int | None = None
    ) -> int:
        check_sendfile_file(sock, file)
        return original_ssl_sendfile(sock, file, offset, count)

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
    monkeypatch.setattr(ssl.SSLSocket, "write", guarded_ssl_write)
    monkeypatch.setattr(ssl.SSLSocket, "sendto", guarded_ssl_sendto)
    monkeypatch.setattr(ssl.SSLSocket, "sendmsg", guarded_ssl_sendmsg)
    monkeypatch.setattr(ssl.SSLSocket, "sendfile", guarded_ssl_sendfile)
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
            # Socket.sendfile : le descripteur de sortie doit appartenir à une
            # socket loopback déjà épinglée.
            check_fd_destination(out_fd, "envoi réseau interdit")
            if count is None:
                return cast(int, original_os_sendfile(out_fd, in_fd, offset))
            return cast(int, original_os_sendfile(out_fd, in_fd, offset, count))

        monkeypatch.setattr(os, "sendfile", guarded_os_sendfile)

    original_os_write = os.write

    def guarded_os_write(fd: int, data: Any) -> int:
        # `os.write` sur un descripteur de socket ne passe pas par
        # socket.socket.send ; fichiers et tubes restent autorisés.
        check_fd_destination(fd, "écriture réseau interdite")
        return original_os_write(fd, data)

    monkeypatch.setattr(os, "write", guarded_os_write)

    original_os_writev = getattr(os, "writev", None)
    if original_os_writev is not None:

        def guarded_os_writev(fd: int, buffers: Any) -> int:
            check_fd_destination(fd, "écriture réseau interdite")
            return cast(int, original_os_writev(fd, buffers))

        monkeypatch.setattr(os, "writev", guarded_os_writev)

    def make_child_process_guard(name: str) -> Callable[..., Any]:
        def guarded(*args: Any, **kwargs: Any) -> Any:
            # Un processus enfant peut sortir sur le réseau sans passer par nos
            # patchs : on le refuse et on le journalise au lieu d'espérer.
            # Seule exception : les invocations git **locales et figées** du
            # produit (`rev-parse`, `diff`, `cat-file`, `check-ignore`), que
            # le scan réel exige — à la couche `Popen` comme à la couche
            # `os.posix_spawn` sous-jacente (CPython y implémente `Popen`).
            # Tout le reste — `curl`, `git fetch`, `git init`, shell, `fork`
            # — reste refusé (témoins ci-dessous).
            if name == "subprocess.Popen" and _is_local_git_call(args, kwargs):
                assert ledger.original_popen is not None
                return ledger.original_popen(*args, **kwargs)
            if name == "posix_spawn" and _is_local_git_spawn(args):
                assert original_posix_spawn is not None
                return original_posix_spawn(*args, **kwargs)
            ledger.attempts.append(
                NetworkAttempt(socket.AF_INET, f"<processus enfant : {name}>", True)
            )
            raise AssertionError("processus enfant interdit : hors périmètre du garde réseau")

        guarded.__name__ = f"guarded_{name}"
        return guarded

    original_posix_spawn = getattr(os, "posix_spawn", None)
    monkeypatch.setattr(subprocess, "Popen", make_child_process_guard("subprocess.Popen"))
    for child_process_name in (
        "system",
        "fork",
        "forkpty",
        "posix_spawn",
        "posix_spawnp",
        "execl",
        "execle",
        "execlp",
        "execlpe",
        "execv",
        "execve",
        "execvp",
        "execvpe",
    ):
        if hasattr(os, child_process_name):
            monkeypatch.setattr(
                os, child_process_name, make_child_process_guard(child_process_name)
            )
    return ledger


@pytest.fixture
def scan_repo(tmp_path: Path) -> Path:
    """Dépôt git initialisé **hors garde** (le garde interdit tout enfant).

    Ordre garanti : pytest instancie les fixtures dans l'ordre des paramètres,
    donc `scan_repo` (listé en premier) tourne avant `loopback_only`.
    """
    if GIT is None:  # pragma: no cover - garde-fou d'environnement de test.
        pytest.skip("git requis")
    assert GIT is not None
    termine = subprocess.run(  # noqa: S603 - argv figé, aucun shell
        [GIT, "-C", str(tmp_path), "init", "-q"],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert termine.returncode == 0, termine.stderr
    return tmp_path


def test_scan_ci_never_attempts_external_traffic(
    scan_repo: Path, loopback_only: NetworkLedger
) -> None:
    """Une tentative externe reste visible même si la CLI la capture.

    Depuis #29, la commande exécute un **scan réel** : le dépôt contient un
    fichier texte bénin, donc le code de sortie est 0 (un arbre réduit à sa
    base VCS serait refusé en ``--ci``). Le point du test reste le même :
    aucune connexion hors boucle locale n'est tentée sur ce chemin — y
    compris via les sous-processus git (autorisés par l'allowlist car
    locaux et figés, voir `_is_local_git_call`).
    """
    (scan_repo / "app.py").write_text("x = 1\n", encoding="utf-8")
    result = CliRunner().invoke(app, ["scan", "--ci", str(scan_repo)])

    # Scan opérationnel avec un contenu lisible : propre => 0 (jamais 2, qui
    # reste réservé à l'erreur d'outillage).
    assert result.exit_code == 0, result.output
    assert loopback_only.blocked == []
    assert all(
        not attempt.blocked
        for attempt in loopback_only.attempts
        if attempt.family in (socket.AF_INET, socket.AF_INET6)
    )


def test_guard_still_blocks_non_local_child_processes(
    loopback_only: NetworkLedger, tmp_path: Path
) -> None:
    """Témoin de l'allowlist : `curl`, `git fetch`, `git init` restent refusés.

    Sans ces témoins, l'exception git du garde ne prouverait rien : elle
    laisserait tout passer sous couvert d'invocation git.
    """
    if GIT is None:  # pragma: no cover - garde-fou d'environnement de test.
        pytest.skip("git requis")
    assert GIT is not None
    for argv in (
        ["curl", "https://example.invalid/"],
        [GIT, "-c", "core.fsmonitor=false", "-C", str(tmp_path), "fetch"],
        [GIT, "-C", str(tmp_path), "init", "-q"],
        [GIT, "rev-parse", "--show-toplevel"],
    ):
        with pytest.raises(AssertionError, match="hors périmètre"):
            subprocess.Popen(  # noqa: S603 - témoin volontairement refusé
                argv,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
            )
    # Même refus une couche plus bas : CPython implémente `Popen` par
    # `os.posix_spawn`, et un `fetch` direct ne doit pas passer entre les
    # mailles.
    with pytest.raises(AssertionError, match="hors périmètre"):
        os.posix_spawn(
            GIT,
            [GIT, "-c", "core.fsmonitor=false", "-C", str(tmp_path), "fetch"],
            {},
        )
    assert len(loopback_only.blocked) == 5


def test_git_allowlist_accepts_only_exact_product_argv(tmp_path: Path) -> None:
    """Revue (LOW) : l'allowlist couvre l'argv complet, pas le préfixe."""
    if GIT is None:  # pragma: no cover - garde-fou d'environnement de test.
        pytest.skip("git requis")
    root = str(tmp_path)
    valides = (
        ("rev-parse", "--show-toplevel"),
        _GIT_DIFF_ARGUMENTS,
        _GIT_STAGED_RAW_ARGUMENTS,
        ("cat-file", "-s", "--", "a" * 40),
        ("cat-file", "blob", "--", "a" * 64),
        ("check-ignore", "-q", "--", "a/b"),
    )
    for tail in valides:
        argv = [GIT, "-c", "core.fsmonitor=false", "-C", root, *tail]
        assert _git_argv_ok(argv), argv
        assert _is_local_git_call((argv,), {"stdin": subprocess.DEVNULL})
        assert _is_local_git_spawn([GIT, argv, {}])

    for tail in (
        (
            "diff",
            "--cached",
            "--raw",
            "-z",
            "--no-abbrev",
            "--no-renames",
            "--no-ext-diff",
            "--no-textconv",
            "--upload-pack=evil",
        ),
        ("cat-file", "--follow-symlinks", "--", "a" * 40),
        ("cat-file", "blob", "--", "A" * 40),
        ("check-ignore", "-q", "--"),
        ("log", "--format=%H"),
    ):
        argv = [GIT, "-c", "core.fsmonitor=false", "-C", root, *tail]
        assert not _git_argv_ok(argv), argv
        assert not _is_local_git_call((argv,), {"stdin": subprocess.DEVNULL})
        assert not _is_local_git_spawn([GIT, argv, {}])


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


def test_guard_blocks_sendto_with_keyword_address(loopback_only: NetworkLedger) -> None:
    """Une adresse en mot-clé doit être bloquée avant le TypeError de CPython."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        # typeshed marque `sendto` positionnel-only ; le cast permet de vérifier
        # que le garde bloque quand même l'appel par mot-clé.
        sendto = cast(Any, sock.sendto)
        with pytest.raises(AssertionError, match="destination hors boucle locale"):
            sendto(b"synthetic probe", address=("203.0.113.7", 443))
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
                # Écriture par descripteur autorisée sur une socket épinglée.
                assert os.write(client.fileno(), b"via-fd") == 6
                assert peer.recv(6) == b"via-fd"
    assert loopback_only.blocked == []
    destinations = [
        attempt for attempt in loopback_only.attempts if isinstance(attempt.destination, tuple)
    ]
    assert destinations
    assert all(
        _is_local_destination(attempt.family, attempt.destination) for attempt in destinations
    )


def test_guard_allows_af_unix_send_but_refuses_fd_write(loopback_only: NetworkLedger) -> None:
    """Asymétrie AF_UNIX assumée et documentée : `send` OK, écriture par fd non.

    Un socketpair AF_UNIX est de l'IPC local : `send` est autorisé et journalisé
    comme exception. Une écriture par descripteur (`os.write`) vers ce même fd
    est en revanche refusée, car un fd AF_UNIX n'est jamais épinglé au loopback
    — plus strict côté descripteur (fail-closed).
    """
    left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        left.send(b"ipc")
        assert right.recv(3) == b"ipc"
        unix_attempts = [
            attempt for attempt in loopback_only.attempts if attempt.family == socket.AF_UNIX
        ]
        assert len(unix_attempts) == 1
        assert not unix_attempts[0].blocked
        with pytest.raises(AssertionError, match="descripteur hors socket loopback"):
            os.write(left.fileno(), b"ipc")
    finally:
        left.close()
        right.close()
    assert len(loopback_only.blocked) == 1


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


def test_guard_blocks_ssl_write_on_unpinned_socket(loopback_only: NetworkLedger) -> None:
    """`SSLSocket.write` écrit via `_sslobj.write`, sans passer par `send`."""
    fake = mock.Mock(spec=socket.socket)
    fake.family = socket.AF_INET
    with pytest.raises(AssertionError, match="socket non épinglée"):
        ssl.SSLSocket.write(fake, b"synthetic probe")
    assert len(loopback_only.blocked) == 1


def test_guard_blocks_ssl_sendto_sendmsg_sendfile_on_unpinned_socket(
    loopback_only: NetworkLedger, tmp_path: Path
) -> None:
    """Les autres méthodes surchargées par `SSLSocket` passent par le garde."""
    source = tmp_path / "source.bin"
    source.write_bytes(b"synthetic payload")
    fake = mock.Mock(spec=socket.socket)
    fake.family = socket.AF_INET
    with source.open("rb") as handle:
        with pytest.raises(AssertionError, match="destination hors boucle locale"):
            ssl.SSLSocket.sendto(fake, b"synthetic probe", ("203.0.113.7", 443))
        # `sendmsg` est typé `Never` (il refuse toujours l'envoi) : le cast en
        # `Any` permet de vérifier que le garde bloque quand même l'appel.
        sendmsg = cast(Any, ssl.SSLSocket.sendmsg)
        with pytest.raises(AssertionError, match="socket non épinglée"):
            sendmsg(fake, b"synthetic probe")
        with pytest.raises(AssertionError, match="socket non épinglée"):
            ssl.SSLSocket.sendfile(fake, handle)
    assert len(loopback_only.blocked) == 3


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


def test_early_bound_os_write_runs_unguarded_and_is_documented(
    loopback_only: NetworkLedger,
) -> None:
    """Miroir du cas DNS pour `from os import write` capturé avant le patch.

    La référence d'origine contourne le garde et n'est journalisée nulle part.
    Sur une socket TCP non connectée, l'écriture échoue localement
    (``BrokenPipeError``/``ENOTCONN``) sans qu'aucun octet ne parte ; le filet
    réel de ce cas reste la trace OS ``strace`` (filtre étendu).
    """
    original = loopback_only.original_os_write
    assert original is not None
    assert original is not os.write  # référence d'origine, non patchée
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        with pytest.raises(OSError):  # échec local, aucun octet émis
            original(sock.fileno(), b"synthetic probe")
    assert loopback_only.attempts == []  # hors garde : rien n'est journalisé


def test_early_bound_subprocess_popen_runs_unguarded_and_is_documented(
    loopback_only: NetworkLedger,
) -> None:
    """Miroir `from subprocess import Popen` : trou connu, verrouillé-documenté.

    L'alias précoce garde la classe d'origine. Avec ``start_new_session=True``,
    CPython passe par le chemin C ``_posixsubprocess.fork_exec``, hors patchs :
    le processus enfant démarre sans alimenter le journal (chemin par défaut
    ``os.posix_spawn``, lui, serait rattrapé indirectement). Le processus du
    test est inoffensif (``sys.executable -c pass``) ; le filet réel de ce cas
    est ``strace -f``.
    """
    original = loopback_only.original_popen
    assert original is not None
    assert original is not subprocess.Popen  # référence d'origine, non patchée
    process = original([sys.executable, "-c", "pass"], start_new_session=True)
    assert process.wait() == 0
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


def test_guard_blocks_os_write_on_unpinned_socket_fd(loopback_only: NetworkLedger) -> None:
    """`os.write(sock.fileno(), ...)` ne contourne pas le garde via le fd."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        with pytest.raises(AssertionError, match="descripteur hors socket loopback"):
            os.write(sock.fileno(), b"synthetic probe")
    assert len(loopback_only.blocked) == 1


def test_guard_blocks_os_writev_on_unpinned_socket_fd(loopback_only: NetworkLedger) -> None:
    if not hasattr(os, "writev"):
        pytest.skip("os.writev indisponible sur cette plateforme")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        with pytest.raises(AssertionError, match="descripteur hors socket loopback"):
            os.writev(sock.fileno(), [b"synthetic ", b"probe"])
    assert len(loopback_only.blocked) == 1


def test_guard_allows_os_write_to_regular_file(
    loopback_only: NetworkLedger, tmp_path: Path
) -> None:
    """Le garde par descripteur ne perturbe pas les écritures fichier normales."""
    target = tmp_path / "synthetic.bin"
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        assert os.write(fd, b"synthetic") == len(b"synthetic")
    finally:
        os.close(fd)
    assert target.read_bytes() == b"synthetic"
    assert loopback_only.blocked == []


@pytest.mark.parametrize(
    "vector",
    [
        "system",
        "fork",
        "forkpty",
        "posix_spawn",
        "posix_spawnp",
        "execl",
        "execle",
        "execlp",
        "execlpe",
        "execv",
        "execve",
        "execvp",
        "execvpe",
    ],
)
def test_guard_patches_dangerous_child_process_vectors(
    loopback_only: NetworkLedger, vector: str
) -> None:
    """`fork`/`exec*` sont patchés — vérifié sans les invoquer (destructeurs)."""
    if not hasattr(os, vector):
        pytest.skip(f"os.{vector} indisponible sur cette plateforme")
    assert getattr(os, vector).__name__ == f"guarded_{vector}"


@pytest.mark.parametrize(
    ("vector", "call"),
    [
        ("subprocess.Popen", lambda: subprocess.Popen(["/bin/true"])),  # noqa: S603
        ("subprocess.run", lambda: subprocess.run(["/bin/true"], check=False)),  # noqa: S603
        ("os.system", lambda: os.system("/bin/true")),  # noqa: S605
        ("os.posix_spawn", lambda: os.posix_spawn("/bin/true", ["/bin/true"], {})),  # noqa: S606
    ],
    ids=["subprocess.Popen", "subprocess.run", "os.system", "os.posix_spawn"],
)
def test_guard_blocks_child_process_spawn(
    loopback_only: NetworkLedger, vector: str, call: Callable[[], object]
) -> None:
    """Un enfant pourrait sortir sur le réseau : le garde le refuse et le journalise."""
    if vector == "os.posix_spawn" and not hasattr(os, "posix_spawn"):
        pytest.skip("os.posix_spawn indisponible sur cette plateforme")
    with pytest.raises(AssertionError, match="processus enfant interdit"):
        call()
    assert len(loopback_only.blocked) == 1


def test_guard_allows_only_loopback_ip_literals_and_notes_unix_exception() -> None:
    assert _is_local_destination(socket.AF_INET, ("127.0.0.1", 11434))
    assert _is_local_destination(socket.AF_INET6, ("::1", 11434, 0, 0))
    assert _is_local_destination(socket.AF_INET6, ("::ffff:127.0.0.1", 11434, 0, 0))
    assert not _is_local_destination(socket.AF_INET, ("192.0.2.1", 443))
    assert _is_local_destination(socket.AF_UNIX, "/run/local-service.sock")
