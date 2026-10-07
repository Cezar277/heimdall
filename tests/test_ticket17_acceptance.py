"""Acceptation du ticket #17 — écrite depuis le ticket, pas depuis le code.

Chaque test reprend une exigence du ticket (tâches, « comment t'y prendre »,
critères d'acceptation, piège). Boîte noire : ce fichier n'importe jamais
``heimdall`` ; il ne lit que le manifeste, l'arborescence et la doc, et
exécute les deux critères d'acceptation en sous-processus.
"""

import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10 : backport explicite (extra [dev]).
    import tomli as tomllib

ROOT = Path(__file__).resolve().parents[1]

# Ticket #17, « comment t'y prendre » : la stack imposée.
RUNTIME_STACK = ("fastapi", "mcp", "ollama", "cryptography", "argon2-cffi", "httpx", "typer")
DEV_STACK = ("pytest", "ruff", "mypy", "bandit")
ADR_KEYWORDS = (
    "fastapi",
    "mcp",
    "ollama",
    "cryptography",
    "argon2",
    "httpx",
    "typer",
    "pytest",
    "ruff",
    "mypy",
    "bandit",
)


def _load_pyproject() -> dict:
    return tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))


def _dep_names(entries: list) -> set:
    names = set()
    for entry in entries:
        name = re.split(r"[<>=!~\s\[]", entry, maxsplit=1)[0].strip().lower().replace("_", "-")
        names.add(name)
    return names


def _lock_names() -> set:
    for candidate in ("requirements.lock", "uv.lock", "poetry.lock", "pdm.lock"):
        path = ROOT / candidate
        if path.is_file():
            names = set()
            for line in path.read_text(encoding="utf-8").splitlines():
                match = re.match(r"^([A-Za-z0-9_.-]+)==[^;]+$", line.strip())
                if match:
                    names.add(match.group(1).lower().replace("_", "-"))
            return names
    return set()


class Ticket17AcceptanceTests(unittest.TestCase):
    # --- Tâches : pyproject + layout -------------------------------------
    def test_pyproject_declares_runtime_stack(self) -> None:
        deps = _dep_names(_load_pyproject()["project"]["dependencies"])
        for package in RUNTIME_STACK:
            with self.subTest(package=package):
                self.assertIn(package, deps)

    def test_pyproject_declares_dev_extras(self) -> None:
        dev = _dep_names(_load_pyproject()["project"]["optional-dependencies"]["dev"])
        for package in DEV_STACK:
            with self.subTest(package=package):
                self.assertIn(package, dev)

    def test_entry_point_heimdall_declared(self) -> None:
        scripts = _load_pyproject()["project"]["scripts"]
        self.assertIn("heimdall", scripts)
        target = scripts["heimdall"]
        self.assertRegex(target, r"^heimdall(\.[a-z_]+)+:[a-zA-Z_][a-zA-Z0-9_]*$")

    def test_package_layout(self) -> None:
        for sub in ("scanner", "mcp", "vault", "cli"):
            with self.subTest(sub=sub):
                package = ROOT / "heimdall" / sub
                self.assertTrue(package.is_dir(), f"manque heimdall/{sub}/")
                self.assertTrue((package / "__init__.py").is_file())
        self.assertTrue((ROOT / "heimdall" / "__init__.py").is_file())

    def test_tests_and_docs_dirs(self) -> None:
        self.assertTrue((ROOT / "tests").is_dir())
        self.assertTrue(list((ROOT / "tests").glob("test_*.py")), "tests/ sans test")
        self.assertTrue((ROOT / "docs").is_dir())
        self.assertTrue((ROOT / "docs" / "adr").is_dir())

    # --- Tâche : ADR de stack --------------------------------------------
    def test_adr_covers_full_stack(self) -> None:
        texts = [
            (p, p.read_text(encoding="utf-8").lower())
            for p in sorted((ROOT / "docs" / "adr").glob("*.md"))
        ]
        self.assertTrue(texts, "aucun ADR dans docs/adr/")
        covered = {kw: [p.name for p, t in texts if kw in t] for kw in ADR_KEYWORDS}
        missing = {kw: files for kw, files in covered.items() if not files}
        self.assertEqual(missing, {}, f"stack non justifiée en ADR : {sorted(missing)}")

    def test_adr_lock_doc_is_coherent(self) -> None:
        """LOW review : l'ADR-002 ne doit plus mentionner `pip freeze` ni `ignore_errors`."""
        text = (ROOT / "docs" / "adr" / "002-stack-python.md").read_text(encoding="utf-8")
        self.assertNotIn("pip freeze", text)
        self.assertIn("pip-compile --generate-hashes", text)
        self.assertNotIn("ignore_errors", text)
        self.assertNotIn("ignore_errors", (ROOT / "pyproject.toml").read_text(encoding="utf-8"))

    # --- Tâche : .gitignore / LICENSE / README --------------------------
    def test_gitignore_python(self) -> None:
        content = (ROOT / ".gitignore").read_text(encoding="utf-8")
        for pattern in (".venv", "__pycache__", ".pytest_cache"):
            with self.subTest(pattern=pattern):
                self.assertIn(pattern, content)
        self.assertTrue(
            any(re.match(r"^\*\.py\[cod\]$", line.strip()) for line in content.splitlines())
        )

    def test_gitignore_never_commits_env(self) -> None:
        lines = [
            line.strip() for line in (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
        ]
        self.assertIn(".env", lines)
        self.assertNotIn(".env.example", lines)

    def test_gitignore_actually_ignores_key_material(self) -> None:
        """Preuve comportementale : git ignore vraiment les secrets (LOW review)."""
        git_bin = shutil.which("git")
        if git_bin is None:
            self.skipTest("git requis")
        for name in ("id_rsa", "id_ed25519", ".env", "prod.jks", "prod.keystore"):
            with self.subTest(name=name):
                completed = subprocess.run(
                    [git_bin, "check-ignore", "-q", name],
                    cwd=ROOT,
                    capture_output=True,
                    timeout=60,
                    check=False,
                )
                self.assertEqual(completed.returncode, 0, msg=f"{name} ne serait pas ignoré")
        ignored = subprocess.run(
            [git_bin, "check-ignore", "-q", ".env.example"],
            cwd=ROOT,
            capture_output=True,
            timeout=60,
            check=False,
        )
        self.assertEqual(ignored.returncode, 1, msg=".env.example doit rester versionnable")

    def test_license_mit(self) -> None:
        content = (ROOT / "LICENSE").read_text(encoding="utf-8")
        self.assertTrue(content.strip())
        self.assertIn("MIT", content)

    def test_readme_basics(self) -> None:
        content = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertGreaterEqual(len(content), 500)
        for keyword in ("pip install", "pytest", "heimdall"):
            with self.subTest(keyword=keyword):
                self.assertIn(keyword, content)

    def test_readme_install_verified_first(self) -> None:
        """LOW review : le premier bloc d'install du README est la voie vérifiée."""
        content = (ROOT / "README.md").read_text(encoding="utf-8")
        blocks = re.findall(r"```sh\n(.*?)```", content, re.DOTALL)
        install_blocks = [block for block in blocks if "pip install" in block]
        self.assertTrue(install_blocks, "aucun bloc pip install dans le README")
        self.assertIn("--require-hashes", install_blocks[0])

    # --- « Verrouille les versions » --------------------------------------
    def test_versions_pinned_and_locked(self) -> None:
        pyproject = _load_pyproject()
        for entry in pyproject["project"]["dependencies"]:
            with self.subTest(entry=entry):
                self.assertIn("==", entry, "dépendance runtime non verrouillée en ==")
        locked = _lock_names()
        self.assertTrue(locked, "aucun fichier de lock (requirements.lock, uv.lock…)")
        direct = _dep_names(pyproject["project"]["dependencies"])
        self.assertGreaterEqual(len(direct), 9, "le socle runtime #17 a 9 directs")
        missing = {name for name in direct if name not in locked}
        self.assertEqual(missing, set(), f"hors du lock : {sorted(missing)}")

    def test_lock_carries_hashes(self) -> None:
        """Supply-chain : requirements.lock est installé avec --require-hashes."""
        path = ROOT / "requirements.lock"
        self.assertTrue(path.is_file(), "pas de requirements.lock")
        content = path.read_text(encoding="utf-8")
        self.assertIn("--hash=sha256:", content)
        self.assertIn("--require-hashes", content)

    # --- Piège : crypto confinée ------------------------------------------
    def test_crypto_module_exists_in_vault(self) -> None:
        self.assertTrue((ROOT / "heimdall" / "vault" / "crypto.py").is_file())

    # --- Critères d'acceptation (sous-processus) ---------------------------
    def test_pytest_starts(self) -> None:
        """« pytest se lance » : collecte du dépôt en échec si pytest casse."""
        completed = subprocess.run(
            [sys.executable, "-m", "pytest", "--collect-only", "-q"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=300,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, msg=completed.stderr[-2000:])

    def test_pip_install_editable(self) -> None:
        """« pip install -e . fonctionne » : venv isolé + entrée console réelle.

        Preuve d'installabilité, PAS de vérification supply-chain : les hashes
        sont couverts par test_lock_carries_hashes (statique) et la CI
        --require-hashes. Le pip du venv de preuve n'est pas épinglé
        volontairement (outil bootstrap, pas dépendance livrée).
        """
        if shutil.which("git") is None:  # pragma: no cover - garde-fou.
            self.skipTest("git requis pour le venv de preuve")
        with tempfile.TemporaryDirectory(prefix="heimdall-t17-") as tmp:
            venv = os.path.join(tmp, "venv")
            completed = subprocess.run(
                [sys.executable, "-m", "venv", venv],
                capture_output=True,
                text=True,
                timeout=120,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, msg=completed.stderr[-2000:])
            vpy = os.path.join(venv, "bin", "python")
            for argv in (
                [vpy, "-m", "pip", "install", "--upgrade", "pip"],
                [vpy, "-m", "pip", "install", "-e", str(ROOT)],
            ):
                completed = subprocess.run(
                    argv,
                    capture_output=True,
                    text=True,
                    timeout=600,
                    check=False,
                )
                if completed.returncode != 0 and re.search(
                    r"(Connection|Timeout|SSLError|Temporary failure"
                    r"|Network is unreachable|Max retries)",
                    completed.stderr,
                ):
                    self.skipTest("réseau indisponible pour la preuve d'installation")
                self.assertEqual(completed.returncode, 0, msg=completed.stderr[-2000:])
            entry = os.path.join(venv, "bin", "heimdall")
            self.assertTrue(os.path.isfile(entry), "entrée console absente du venv")
            completed = subprocess.run(
                [entry, "--version"],
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, msg=completed.stderr[-2000:])
            self.assertIn(_load_pyproject()["project"]["version"], completed.stdout)


if __name__ == "__main__":
    unittest.main()
