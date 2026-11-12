"""Preuves T31 (#31) : génération de .env.example, .env (0600) et .gitignore.

Critères d'acceptation du ticket #31 :
1. .env.example avec les noms et des valeurs vides (aucun secret).
2. .env créé avec des droits stricts 0600 (os.open(..., 0o600)).
3. Ajoute .env au .gitignore seulement s'il n'y est pas déjà (idempotent, pas de doublons).
4. Si .env est déjà suivi par Git, propose git rm --cached .env.
5. git status ne montre jamais .env.

Valeurs entièrement synthétiques ; toutes les opérations sont confinées à tmp_path.
"""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

from heimdall.cli.review import TextChange
from heimdall.remediation import (
    EnvRemediationError,
    EnvRemediationReceipt,
    check_env_git_status,
    ensure_gitignore_ignores_env,
    plan_env_example_change,
    plan_gitignore_change,
    remediate_environment,
    update_env_example,
    update_env_file,
)

SECRET_VAL = "SYNTHETIC_TEST_SECRET_VALUE_123"  # noqa: S105
SECRET_VAL_2 = "ANOTHER_SYNTHETIC_SECRET_VAL_456"  # noqa: S105


@pytest.fixture
def git_repo(tmp_path: Path) -> Path:
    """Initialise un dépôt Git local vierge dans tmp_path."""
    git_bin = shutil.which("git")
    if git_bin:
        subprocess.run(  # noqa: S603
            [git_bin, "init", "-q", str(tmp_path)],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        subprocess.run(  # noqa: S603
            [git_bin, "config", "user.name", "Test Runner"],
            cwd=tmp_path,
            check=True,
        )
        subprocess.run(  # noqa: S603
            [git_bin, "config", "user.email", "test@example.com"],
            cwd=tmp_path,
            check=True,
        )
    return tmp_path


# ==============================================================================
# 1. Tests .env.example (valeurs vides, jamais de secret)
# ==============================================================================


def test_env_example_created_with_empty_values(tmp_path: Path) -> None:
    """Vérifie la création de .env.example avec des valeurs vides 'NOM='."""
    example_path = tmp_path / ".env.example"
    assert not example_path.exists()

    added = update_env_example(tmp_path, ["APP_KEY", "DATABASE_URL"])
    assert added == ["APP_KEY", "DATABASE_URL"]
    assert example_path.exists()

    content = example_path.read_text(encoding="utf-8")
    assert content == "APP_KEY=\nDATABASE_URL=\n"
    assert SECRET_VAL not in content


def test_env_example_never_writes_secret_values(tmp_path: Path) -> None:
    """Même si un dictionnaire avec secrets est passé, .env.example n'a que NOM=."""
    example_path = tmp_path / ".env.example"
    secrets_map = {
        "SUPER_SECRET_KEY": SECRET_VAL,
        "API_TOKEN": SECRET_VAL_2,
    }

    added = update_env_example(tmp_path, secrets_map)
    assert added == ["SUPER_SECRET_KEY", "API_TOKEN"]

    content = example_path.read_text(encoding="utf-8")
    assert "SUPER_SECRET_KEY=\n" in content
    assert "API_TOKEN=\n" in content
    assert SECRET_VAL not in content
    assert SECRET_VAL_2 not in content


def test_env_example_idempotent_no_duplicates(tmp_path: Path) -> None:
    """L'appel répété n'ajoute pas de doublons dans .env.example."""
    update_env_example(tmp_path, ["API_KEY", "DB_HOST"])
    added_second = update_env_example(tmp_path, ["API_KEY", "DB_HOST", "NEW_VAR"])

    assert added_second == ["NEW_VAR"]
    content = (tmp_path / ".env.example").read_text(encoding="utf-8")
    assert content == "API_KEY=\nDB_HOST=\nNEW_VAR=\n"
    assert content.count("API_KEY=") == 1
    assert content.count("DB_HOST=") == 1


def test_env_example_preserves_existing_comments_and_formatting(tmp_path: Path) -> None:
    """Préserve les commentaires et la structure préexistante de .env.example."""
    example_file = tmp_path / ".env.example"
    initial = "# Configuration principale\nAPP_PORT=\n\n# Base de données\nDB_USER="
    example_file.write_text(initial, encoding="utf-8")

    added = update_env_example(tmp_path, ["APP_PORT", "DB_PASS"])
    assert added == ["DB_PASS"]

    content = example_file.read_text(encoding="utf-8")
    expected_prefix = "# Configuration principale\nAPP_PORT=\n\n# Base de données\nDB_USER="
    assert content.startswith(expected_prefix)
    assert "DB_PASS=\n" in content
    assert content.count("APP_PORT=") == 1


def test_env_example_rejects_invalid_variable_names(tmp_path: Path) -> None:
    """Refuse les noms de variables non conformes (minuscules, injection, denylist)."""
    with pytest.raises(EnvRemediationError):
        update_env_example(tmp_path, ["invalid_lower"])

    with pytest.raises(EnvRemediationError):
        update_env_example(tmp_path, ["APP_KEY\nINJECTED=1"])

    with pytest.raises(EnvRemediationError):
        update_env_example(tmp_path, ["PATH"])  # Denylist système

    with pytest.raises(EnvRemediationError):
        update_env_example(tmp_path, ["LD_PRELOAD"])  # Denylist système

    with pytest.raises(EnvRemediationError):
        update_env_example(tmp_path, [123])  # type: ignore[arg-type]


# ==============================================================================
# 2. Tests .env (droits 0600, secrets échappés)
# ==============================================================================


def test_env_file_created_with_permissions_600(tmp_path: Path) -> None:
    """Vérifie la création de .env avec les droits stricts 0600 (POSIX)."""
    env_file = tmp_path / ".env"
    assert not env_file.exists()

    written_path = update_env_file(tmp_path, {"APP_SECRET": SECRET_VAL})
    assert written_path == env_file
    assert env_file.exists()

    if os.name == "posix":
        mode = stat.S_IMODE(env_file.stat().st_mode)
        assert mode == 0o600, f"Le mode attendu est 0600, obtenu : {oct(mode)}"

    content = env_file.read_text(encoding="utf-8")
    assert f'APP_SECRET="{SECRET_VAL}"\n' in content


def test_env_file_updates_existing_preserving_permissions(tmp_path: Path) -> None:
    """La mise à jour de .env fusionne les variables et conserve le mode 0600."""
    env_file = tmp_path / ".env"
    update_env_file(tmp_path, {"KEY_ONE": "val1"})
    update_env_file(tmp_path, {"KEY_TWO": "val2", "KEY_ONE": "updated1"})

    if os.name == "posix":
        mode = stat.S_IMODE(env_file.stat().st_mode)
        assert mode == 0o600

    content = env_file.read_text(encoding="utf-8")
    assert 'KEY_ONE="updated1"' in content
    assert 'KEY_TWO="val2"' in content


def test_env_file_escapes_special_characters_safely(tmp_path: Path) -> None:
    """Échappe les caractères significatifs ($ ` " \\) pour empêcher l'exécution shell."""
    special_value = 'val$with`backtick"and\\slash'
    env_file = tmp_path / ".env"
    update_env_file(tmp_path, {"COMPLEX_SECRET": special_value})

    content = env_file.read_text(encoding="utf-8")
    assert r'COMPLEX_SECRET="val\$with\`backtick\"and\\slash"' in content


def test_env_file_refuses_symlink_fail_closed(tmp_path: Path) -> None:
    """Refuse d'écrire dans un .env qui est un lien symbolique."""
    real_target = tmp_path / "real_file.txt"
    real_target.write_text("initial", encoding="utf-8")
    env_link = tmp_path / ".env"
    env_link.symlink_to(real_target)

    with pytest.raises(EnvRemediationError):
        update_env_file(tmp_path, {"SECRET": SECRET_VAL})

    assert real_target.read_text(encoding="utf-8") == "initial"


def test_env_file_rejects_empty_secrets_or_bad_types(tmp_path: Path) -> None:
    """Refuse les entrées invalides (dictionnaire vide, types étrangers)."""
    with pytest.raises(EnvRemediationError):
        update_env_file(tmp_path, {})

    with pytest.raises(EnvRemediationError):
        update_env_file(tmp_path, {"KEY": 12345})  # type: ignore[arg-type]

    with pytest.raises(EnvRemediationError):
        update_env_file(tmp_path, {123: "val"})  # type: ignore[arg-type]


# ==============================================================================
# 3. Tests .gitignore (idempotence, non-duplication)
# ==============================================================================


def test_gitignore_creates_and_adds_env_if_missing(tmp_path: Path) -> None:
    """Crée le .gitignore et y ajoute .env s'il n'existe pas."""
    gitignore = tmp_path / ".gitignore"
    assert not gitignore.exists()

    modified = ensure_gitignore_ignores_env(tmp_path)
    assert modified is True
    assert gitignore.exists()
    assert gitignore.read_text(encoding="utf-8") == ".env\n"


def test_gitignore_idempotent_no_duplicate_lines(tmp_path: Path) -> None:
    """Piège à éviter : n'ajoute pas la ligne au .gitignore plusieurs fois."""
    gitignore = tmp_path / ".gitignore"
    ensure_gitignore_ignores_env(tmp_path)
    assert gitignore.read_text(encoding="utf-8") == ".env\n"

    # Deuxième exécution : aucune modification
    modified_again = ensure_gitignore_ignores_env(tmp_path)
    assert modified_again is False
    assert gitignore.read_text(encoding="utf-8") == ".env\n"

    # Troisième exécution : toujours invariant
    assert ensure_gitignore_ignores_env(tmp_path) is False
    content = gitignore.read_text(encoding="utf-8")
    assert content.count(".env") == 1


def test_gitignore_recognizes_existing_env_patterns(tmp_path: Path) -> None:
    """Reconnaît les règles existantes (.env, /.env, *.env) sans dupliquer."""
    gitignore = tmp_path / ".gitignore"

    for pattern in ("/.env", "*.env", ".env*", ".env"):
        gitignore.write_text(f"# Regles\n{pattern}\n", encoding="utf-8")
        modified = ensure_gitignore_ignores_env(tmp_path)
        assert modified is False, f"Ne doit pas modifier pour le motif '{pattern}'"
        assert gitignore.read_text(encoding="utf-8") == f"# Regles\n{pattern}\n"


def test_gitignore_appends_cleanly_after_file_without_newline(tmp_path: Path) -> None:
    """Ajoute .env sur une nouvelle ligne même si le fichier existant n'a pas de saut final."""
    gitignore = tmp_path / ".gitignore"
    gitignore.write_text("node_modules", encoding="utf-8")

    modified = ensure_gitignore_ignores_env(tmp_path)
    assert modified is True
    content = gitignore.read_text(encoding="utf-8")
    assert content == "node_modules\n.env\n"


# ==============================================================================
# 4. Tests contrôle Git (is_git_tracked, git rm --cached .env, git status)
# ==============================================================================


def test_git_status_check_warns_when_env_is_tracked(git_repo: Path) -> None:
    """Si .env est déjà suivi par Git, propose 'git rm --cached .env'."""
    git_bin = shutil.which("git")
    if not git_bin:
        pytest.skip("git absent")

    env_file = git_repo / ".env"
    env_file.write_text('APP_KEY="val"\n', encoding="utf-8")

    # On simule un .env suivi dans Git
    subprocess.run([git_bin, "add", "-f", ".env"], cwd=git_repo, check=True)  # noqa: S603

    tracked, ignored, warn, rm_cmd = check_env_git_status(git_repo)
    assert tracked is True
    assert rm_cmd == "git rm --cached .env"
    assert warn is not None
    assert "ATTENTION : Le fichier .env est suivi par Git !" in warn
    assert "git rm --cached .env" in warn


def test_git_status_never_shows_env_after_remediation(git_repo: Path) -> None:
    """Critère d'acceptation : git status ne montre jamais .env après remédiation."""
    git_bin = shutil.which("git")
    if not git_bin:
        pytest.skip("git absent")

    receipt = remediate_environment(
        git_repo,
        {"DATABASE_SECRET": SECRET_VAL},
        warn_stderr=False,
    )
    assert receipt.env_created_or_updated is True
    assert receipt.gitignore_updated is True

    # Vérification git status : .env ne doit pas être visible comme non-suivi
    res = subprocess.run(  # noqa: S603
        [git_bin, "status", "--porcelain"],
        cwd=git_repo,
        capture_output=True,
        text=True,
        check=True,
    )
    lines = res.stdout.splitlines()
    assert not any(".env" in line and ".env.example" not in line for line in lines), (
        f".env apparaît dans git status : {lines}"
    )


# ==============================================================================
# 5. Tests remédiation intégrée & absence de fuite dans le reçu (repr)
# ==============================================================================


def test_remediate_environment_full_cycle(tmp_path: Path) -> None:
    """Exécution complète : .env.example, .env (0600), .gitignore et reçu."""
    receipt = remediate_environment(
        tmp_path,
        {"AUTH_TOKEN": SECRET_VAL, "DB_HOST": "localhost"},
        warn_stderr=False,
    )

    assert isinstance(receipt, EnvRemediationReceipt)
    assert receipt.env_file == ".env"
    assert receipt.example_file == ".env.example"
    assert receipt.gitignore_file == ".gitignore"
    assert "AUTH_TOKEN" in receipt.variables
    assert "DB_HOST" in receipt.variables

    # Sécurité fondamentale : le secret n'est ni dans .env.example ni dans le repr()
    example_text = (tmp_path / ".env.example").read_text(encoding="utf-8")
    assert "AUTH_TOKEN=\n" in example_text
    assert "DB_HOST=\n" in example_text
    assert SECRET_VAL not in example_text

    env_text = (tmp_path / ".env").read_text(encoding="utf-8")
    assert f'AUTH_TOKEN="{SECRET_VAL}"' in env_text

    if os.name == "posix":
        assert stat.S_IMODE((tmp_path / ".env").stat().st_mode) == 0o600

    gitignore_text = (tmp_path / ".gitignore").read_text(encoding="utf-8")
    assert ".env\n" in gitignore_text

    assert SECRET_VAL not in repr(receipt)


# ==============================================================================
# 6. Tests planification diff pour review humaine (plan_*_change)
# ==============================================================================


def test_plan_env_example_change(tmp_path: Path) -> None:
    """Calcul du diff pour .env.example compatible avec TextChange."""
    res = plan_env_example_change(tmp_path, ["TOKEN_KEY"])
    assert res is not None
    rel_path, before, after = res
    assert rel_path == ".env.example"
    assert before == ""
    assert after == "TOKEN_KEY=\n"

    # Vérifie la compatibilité avec TextChange de review.py
    change = TextChange(rel_path, before, after)
    assert change.file == ".env.example"
    assert change.after == "TOKEN_KEY=\n"

    # Après application, le plan doit retourner None (déjà à jour)
    update_env_example(tmp_path, ["TOKEN_KEY"])
    assert plan_env_example_change(tmp_path, ["TOKEN_KEY"]) is None


def test_plan_gitignore_change(tmp_path: Path) -> None:
    """Calcul du diff pour .gitignore compatible avec TextChange."""
    res = plan_gitignore_change(tmp_path)
    assert res is not None
    rel_path, before, after = res
    assert rel_path == ".gitignore"
    assert before == ""
    assert after == ".env\n"

    change = TextChange(rel_path, before, after)
    assert change.file == ".gitignore"
    assert change.after == ".env\n"

    # Après application, retourne None
    ensure_gitignore_ignores_env(tmp_path)
    assert plan_gitignore_change(tmp_path) is None


# ==============================================================================
# 7. Tests confinement et attaques de traversée de chemin
# ==============================================================================


def test_confinement_rejects_path_traversal(tmp_path: Path) -> None:
    """Refuse les chemins avec ../ ou absolus (fail-closed)."""
    with pytest.raises(EnvRemediationError):
        update_env_example(tmp_path, ["KEY"], example_path="../escape.example")

    with pytest.raises(EnvRemediationError):
        update_env_file(tmp_path, {"KEY": "val"}, env_path="../escape.env")

    with pytest.raises(EnvRemediationError):
        ensure_gitignore_ignores_env(tmp_path, gitignore_path="../escape.gitignore")

    with pytest.raises(EnvRemediationError):
        remediate_environment(tmp_path, {"KEY": "val"}, env_path="/tmp/outside.env")  # noqa: S108


def test_confinement_rejects_bad_root_type() -> None:
    """Refuse une racine qui n'est pas un objet Path."""
    with pytest.raises(EnvRemediationError):
        update_env_example("not-a-path", ["KEY"])  # type: ignore[arg-type]

    with pytest.raises(EnvRemediationError):
        update_env_file("not-a-path", {"KEY": "val"})  # type: ignore[arg-type]

    with pytest.raises(EnvRemediationError):
        ensure_gitignore_ignores_env("not-a-path")  # type: ignore[arg-type]

    with pytest.raises(EnvRemediationError):
        check_env_git_status("not-a-path")  # type: ignore[arg-type]

    with pytest.raises(EnvRemediationError):
        plan_env_example_change("not-a-path", ["KEY"])  # type: ignore[arg-type]

    with pytest.raises(EnvRemediationError):
        plan_gitignore_change("not-a-path")  # type: ignore[arg-type]

    with pytest.raises(EnvRemediationError):
        remediate_environment("not-a-path", {"KEY": "val"})  # type: ignore[arg-type]


# ==============================================================================
# 8. Tests robustesse : plafonds, fichiers non réguliers, encodage et symlinks
# ==============================================================================


def test_env_file_rejects_more_than_max_secrets(tmp_path: Path) -> None:
    """Refuse plus de 1024 secrets en un seul appel (protection DoS)."""
    too_many = {f"KEY_{i}": "val" for i in range(1025)}
    with pytest.raises(EnvRemediationError, match="trop de secrets"):
        update_env_file(tmp_path, too_many)


def test_env_file_rejects_cumulative_secret_volume_over_limit(tmp_path: Path) -> None:
    """Refuse un volume cumulé de secrets dépassant 1 Mio (protection DoS mémoire)."""
    huge_val = "x" * (1_048_576 + 10)
    with pytest.raises(EnvRemediationError, match="volume total des secrets"):
        update_env_file(tmp_path, {"HUGE_KEY": huge_val})


def test_env_example_rejects_more_than_max_variables(tmp_path: Path) -> None:
    """Refuse plus de 1024 variables pour .env.example."""
    too_many = [f"KEY_{i}" for i in range(1025)]
    with pytest.raises(EnvRemediationError, match="trop de variables"):
        update_env_example(tmp_path, too_many)


def test_env_example_rejects_empty_variable_list(tmp_path: Path) -> None:
    """Refuse une liste vide de variables."""
    with pytest.raises(EnvRemediationError, match="liste de variables vide"):
        update_env_example(tmp_path, [])


def test_symlink_checks_on_all_entrypoints(tmp_path: Path) -> None:
    """Refuse fail-closed si .gitignore ou .env.example sont des liens symboliques."""
    real_file = tmp_path / "real.txt"
    real_file.write_text("hello", encoding="utf-8")

    sym_example = tmp_path / ".env.example"
    sym_example.symlink_to(real_file)
    with pytest.raises(EnvRemediationError, match="lien symbolique"):
        update_env_example(tmp_path, ["KEY"])
    with pytest.raises(EnvRemediationError, match="lien symbolique"):
        plan_env_example_change(tmp_path, ["KEY"])

    sym_example.unlink()
    sym_git = tmp_path / ".gitignore"
    sym_git.symlink_to(real_file)
    with pytest.raises(EnvRemediationError, match="lien symbolique"):
        ensure_gitignore_ignores_env(tmp_path)
    with pytest.raises(EnvRemediationError, match="lien symbolique"):
        plan_gitignore_change(tmp_path)


def test_read_text_secure_rejects_non_regular_file(tmp_path: Path) -> None:
    """Refuse la lecture si la cible est un répertoire."""
    target_dir = tmp_path / ".env.example"
    target_dir.mkdir()
    with pytest.raises(EnvRemediationError):
        update_env_example(tmp_path, ["KEY"])


def test_read_text_secure_rejects_invalid_utf8(tmp_path: Path) -> None:
    """Refuse un fichier existant contenant des octets non UTF-8."""
    target = tmp_path / ".env.example"
    target.write_bytes(b"\xff\xfe\x00\x00")  # Invalid UTF-8
    with pytest.raises(EnvRemediationError, match="lecture refusée : encodage UTF-8 invalide"):
        update_env_example(tmp_path, ["KEY"])


def test_remediate_environment_warns_stderr_when_untracked(tmp_path: Path) -> None:
    """Émet un avertissement si le fichier n'est pas dans un dépôt Git valide."""
    with pytest.warns(UserWarning, match="statut Git indéterminé"):
        receipt = remediate_environment(
            tmp_path,
            {"VAR_TEST": "secret"},
            warn_stderr=True,
        )
    assert receipt.git_tracked is False
    assert receipt.warning is not None
