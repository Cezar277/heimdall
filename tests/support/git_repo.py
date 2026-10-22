"""Dépôt git jetable pour les tests du serveur MCP (outil de test).

Factorise le motif répété par les tests (`init`, écriture, `add`) : un
dépôt par test, dans un répertoire temporaire, jamais le dépôt Heimdall
lui-même. Ce module n'est pas importé par le produit.
"""

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

# Même règle que le produit (`heimdall/mcp/gitdiff.py`) : résolution hors
# `PATH` hérité (`os.defpath`, défaut système), jamais d'héritage — sinon un
# `PATH` compromis sur le poste ou la CI ferait exécuter un `git` piégé à
# chaque test, avec les privilèges du dev ou de la CI. Absent du défaut
# système : `SkipTest`, jamais de repli vers un `PATH` non fiable.
GIT = shutil.which("git", path=os.defpath)


class GitRepo:
    """Dépôt git jetable, prêt à recevoir des modifications indexées."""

    def __init__(self, prefix: str, test: unittest.TestCase | None = None) -> None:
        if GIT is None:  # pragma: no cover - garde-fou d'environnement de test.
            raise unittest.SkipTest("git requis")
        self._tmp = tempfile.TemporaryDirectory(prefix=prefix)
        if test is not None:
            test.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name) / "repo"
        self.root.mkdir()
        self.git("init", "-q")
        self.git("config", "user.email", "test@example.invalid")
        self.git("config", "user.name", "Heimdall Test")

    def close(self) -> None:
        """Supprime le dépôt jetable (usage pytest, sans ``TestCase``)."""
        self._tmp.cleanup()

    def git(self, *arguments: str) -> None:
        """Commande git d'aide au test (argv figé, sans shell)."""
        assert GIT is not None
        completed = subprocess.run(  # noqa: S603 - argv figé, aucun shell
            [GIT, "-C", str(self.root), *arguments],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        if completed.returncode != 0:
            raise AssertionError(f"git {arguments} a échoué : {completed.stderr}")

    def git_output(self, *arguments: str) -> str:
        """Sortie standard d'une commande git (échec = exception)."""
        assert GIT is not None
        completed = subprocess.run(  # noqa: S603 - argv figé, aucun shell
            [GIT, "-C", str(self.root), *arguments],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        if completed.returncode != 0:
            raise AssertionError(f"git {arguments} a échoué : {completed.stderr}")
        return completed.stdout

    def git_allow_failure(self, *arguments: str) -> int:
        """Code de retour d'une commande git, sans lever (conflit de fusion)."""
        assert GIT is not None
        completed = subprocess.run(  # noqa: S603 - argv figé, aucun shell
            [GIT, "-C", str(self.root), *arguments],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        return completed.returncode

    def write(self, relative: str, content: str) -> Path:
        """Écrit un fichier texte (crée les dossiers manquants)."""
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return path

    def write_bytes(self, relative: str, content: bytes) -> Path:
        """Écrit un fichier binaire (crée les dossiers manquants)."""
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        return path

    def stage(self, *relative: str) -> None:
        self.git("add", "--", *relative)

    def commit_all(self, message: str) -> None:
        self.git("add", "-A")
        self.git("commit", "-qm", message)
