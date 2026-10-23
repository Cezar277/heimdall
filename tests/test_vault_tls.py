"""Pentest du transport TLS du Vault (ticket #25 / #64).

La revue signalait : « TLS + SAN-IP en production déjà fail-closed dans
``run_server`` mais non pentesté hors boucle locale ». Ce module le prouve
réellement :

- un vrai serveur uvicorn est démarré avec un certificat TLS ;
- le certificat doit porter le SAN IP ``127.0.0.1`` (vérifié côté pair) ;
- un client qui fait confiance à l'Internal CA obtient la réponse ;
- un client qui ne fait PAS confiance à ce certificat est rejeté (aucun
  repli non vérifié) ;
- un client en clair sur le port TLS n'obtient aucune réponse HTTP (pas de
  downgrade) ;
- le lanceur refuse de démarrer en production sans certificat et clé.
"""

import datetime
import ipaddress
import os
import socket
import ssl
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import httpx
import uvicorn  # type: ignore[import-untyped]
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from pydantic import ValidationError

from heimdall.vault.app import VaultSettings, create_app, run_server
from heimdall.vault.client import VaultClient
from heimdall.vault.crypto import generate_encryption_key

_LOOPBACK = "127.0.0.1"


def _generate_self_signed_cert(directory: Path) -> tuple[Path, Path]:
    """Génère un certificat autosigné avec le SAN IP 127.0.0.1 (IP, pas DNS)."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, _LOOPBACK)])
    now = datetime.datetime.now(datetime.timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address(_LOOPBACK))]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    certfile = directory / "server.crt"
    keyfile = directory / "server.key"
    certfile.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    keyfile.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    os.chmod(keyfile, 0o600)
    return certfile, keyfile


class VaultTlsTransportTests(unittest.TestCase):
    """Le transport TLS est vérifié de bout en bout sur la boucle locale."""

    @classmethod
    def setUpClass(cls) -> None:
        cls._tmp = tempfile.TemporaryDirectory(prefix="heimdall-tls-")
        tmp_dir = Path(cls._tmp.name)
        cls.certfile, cls.keyfile = _generate_self_signed_cert(tmp_dir)
        cls.server = uvicorn.Server(
            uvicorn.Config(
                app=create_app(VaultSettings(api_key_pepper="t" * 32)),
                host=_LOOPBACK,
                port=0,
                log_level="error",
                ssl_certfile=str(cls.certfile),
                ssl_keyfile=str(cls.keyfile),
                proxy_headers=False,
                server_header=False,
                date_header=False,
            )
        )
        cls.thread = threading.Thread(target=cls.server.run, daemon=True)
        cls.thread.start()
        deadline = time.monotonic() + 15
        while not cls.server.started:
            if time.monotonic() > deadline:
                raise RuntimeError("Serveur uvicorn TLS de test non démarré à temps.")
            time.sleep(0.05)
        cls.port = cls.server.servers[0].sockets[0].getsockname()[1]

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.should_exit = True
        cls.thread.join(timeout=15)
        cls._tmp.cleanup()

    def test_certificate_advertises_loopback_ip_san(self) -> None:
        """Le certificat servi porte bien le SAN IP 127.0.0.1 (pas seulement le CN)."""
        context = ssl.create_default_context(cafile=str(self.certfile))
        with socket.create_connection((_LOOPBACK, self.port), timeout=10) as raw:
            with context.wrap_socket(raw, server_hostname=_LOOPBACK) as tls_sock:
                peer = tls_sock.getpeercert()
        alt_names = peer.get("subjectAltName", ())
        self.assertIn(("IP Address", _LOOPBACK), alt_names)

    def test_trusted_client_reaches_health_endpoint(self) -> None:
        """Un client qui approuve l'Internal CA obtient la réponse de santé."""
        context = ssl.create_default_context(cafile=str(self.certfile))
        with httpx.Client(
            base_url=f"https://{_LOOPBACK}:{self.port}",
            verify=context,
            timeout=10,
        ) as client:
            response = client.get("/api/v1/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"status": "ok"})

    def test_vault_client_loads_internal_ca_without_symlink(self) -> None:
        """Le client Heimdall charge le CA interne via un contexte SSL vérifié."""
        with VaultClient(
            f"https://{_LOOPBACK}:{self.port}",
            "synthetic_tls_client_api_key",
            ca_cert=self.certfile,
        ) as client:
            self.assertEqual(client.health()["status"], "ok")

    def test_vault_client_localhost_url_is_pinned_and_verified(self) -> None:
        """URL `localhost` épinglée vers l'IP à la construction, TLS vérifié sur SAN IP."""
        with VaultClient(
            f"https://localhost:{self.port}",
            "synthetic_tls_client_api_key",
            ca_cert=self.certfile,
        ) as client:
            self.assertNotIn("localhost", client._base_url)
            self.assertEqual(client.health()["status"], "ok")

    def test_untrusted_client_is_rejected_without_fallback(self) -> None:
        """Sans confiance explicite, la connexion est rompue : aucun repli non vérifié."""
        context = ssl.create_default_context()  # magasin CA public : ne connaît pas notre CA
        with self.assertRaises(ssl.SSLError):
            with socket.create_connection((_LOOPBACK, self.port), timeout=10) as raw:
                with context.wrap_socket(raw, server_hostname=_LOOPBACK):
                    pass

    def test_plaintext_client_cannot_downgrade_the_tls_port(self) -> None:
        """Une requête HTTP en clair sur le port TLS n'obtient aucune réponse HTTP."""
        with socket.create_connection((_LOOPBACK, self.port), timeout=10) as raw:
            raw.sendall(
                (
                    f"GET /api/v1/health HTTP/1.1\r\n"
                    f"Host: {_LOOPBACK}:{self.port}\r\n"
                    "Connection: close\r\n"
                    "\r\n"
                ).encode("ascii")
            )
            raw.settimeout(10)
            try:
                data = raw.recv(4096)
            except TimeoutError:  # pragma: no cover - garde-fou
                data = b""
        self.assertNotIn(b"HTTP/1.1 200", data)
        self.assertNotIn(b"HTTP/1.1 400", data)

    def test_tls_client_uses_the_server_certificate_chain(self) -> None:
        """La connexion TLS aboutit et le pair présente bien un certificat."""
        context = ssl.create_default_context(cafile=str(self.certfile))
        with socket.create_connection((_LOOPBACK, self.port), timeout=10) as raw:
            with context.wrap_socket(raw, server_hostname=_LOOPBACK) as tls_sock:
                self.assertIsNotNone(tls_sock.getpeercert())
                self.assertEqual(tls_sock.version(), "TLSv1.3")


class VaultTlsLauncherTests(unittest.TestCase):
    """Le lanceur refuse le HTTP en clair en production (fail-closed)."""

    def test_production_without_certificate_refuses_to_start(self) -> None:
        settings = VaultSettings(api_key_pepper="p" * 32)
        with (
            patch.dict(os.environ, {"HEIMDALL_ENV": "production"}, clear=False),
            patch("heimdall.vault.app.get_settings", return_value=settings),
            patch("uvicorn.run") as mock_run,
        ):
            with self.assertRaises(ValueError) as ctx:
                run_server()
        self.assertIn("TLS", str(ctx.exception))
        mock_run.assert_not_called()

    def test_certificate_pair_is_mandatory_and_validated(self) -> None:
        with tempfile.TemporaryDirectory(prefix="heimdall-tls-cfg-") as tmp:
            certfile, keyfile = _generate_self_signed_cert(Path(tmp))
            settings = VaultSettings(
                api_key_pepper="p" * 32,
                ssl_certfile=str(certfile),
                ssl_keyfile=str(keyfile),
                kek=generate_encryption_key(),
            )
            self.assertEqual(settings.ssl_certfile, str(certfile))
            self.assertEqual(settings.ssl_keyfile, str(keyfile))
            with self.assertRaises(ValueError):
                VaultSettings(api_key_pepper="p" * 32, ssl_certfile=str(certfile))

    def test_symlinked_certificate_and_key_are_refused(self) -> None:
        """LOW revue : les chemins TLS refusent les symlinks (invariant n°3).

        Même garde que la couche DB (`_assert_not_symlink` via lstat) :
        uvicorn suivrait sinon la cible à l'ouverture, hors du chemin validé.
        Répertoire résolu au préalable pour ne tester que le lien lui-même,
        pas un ancêtre.
        """
        with tempfile.TemporaryDirectory(prefix="heimdall-tls-link-") as tmp:
            base = Path(tmp).resolve()
            certfile, keyfile = _generate_self_signed_cert(base)
            cases = (
                ("cert-link.crt", certfile, keyfile),
                ("key-link.key", certfile, keyfile),
            )
            for link_name, real_cert, real_key in cases:
                with self.subTest(link=link_name):
                    link = base / link_name
                    target = real_cert if "cert" in link_name else real_key
                    link.symlink_to(target)
                    kwargs: dict[str, str] = {
                        "api_key_pepper": "p" * 32,
                        "ssl_certfile": str(link if "cert" in link_name else real_cert),
                        "ssl_keyfile": str(link if "key" in link_name else real_key),
                    }
                    with self.assertRaises(ValidationError) as ctx:
                        VaultSettings(**kwargs)  # type: ignore[arg-type]
                    self.assertIn("symbolique", str(ctx.exception))


class VaultTlsContractTests(unittest.TestCase):
    """La documentation et le contrat exposent bien l'exigence de TLS."""

    def test_documentation_requires_tls_in_production(self) -> None:
        root = Path(__file__).resolve().parents[1]
        readme = (root / "README.md").read_text(encoding="utf-8")
        self.assertIn("HEIMDALL_VAULT_SSL_CERTFILE", readme)
        self.assertIn("HEIMDALL_VAULT_SSL_KEYFILE", readme)
        contract = (root / "docs" / "contracts" / "vault-api.md").read_text(encoding="utf-8")
        self.assertIn("HEIMDALL_VAULT_SSL_CERTFILE", contract)
        self.assertIn("fail-closed", contract)

    def test_run_server_passes_certificate_to_uvicorn(self) -> None:
        with tempfile.TemporaryDirectory(prefix="heimdall-tls-run-") as tmp:
            certfile, keyfile = _generate_self_signed_cert(Path(tmp))
            settings = VaultSettings(
                api_key_pepper="p" * 32,
                ssl_certfile=str(certfile),
                ssl_keyfile=str(keyfile),
                kek=generate_encryption_key(),
            )
            with (
                patch.dict(os.environ, {"HEIMDALL_ENV": "production"}, clear=False),
                patch("heimdall.vault.app.get_settings", return_value=settings),
                patch("uvicorn.run") as mock_run,
            ):
                run_server()
        mock_run.assert_called_once()
        self.assertEqual(mock_run.call_args.kwargs["ssl_certfile"], str(certfile))
        self.assertEqual(mock_run.call_args.kwargs["ssl_keyfile"], str(keyfile))
