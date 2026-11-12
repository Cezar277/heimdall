"""Intégrité des preuves SAMM : permaliens permanents, re-pin déterministe (#22).

La relecture a relevé que les permaliens de `docs/t22-samm.md` pointaient sur
des **SHA intermédiaires** : la preuve est rejouable sur la branche mais
**pourrit à la fusion** (un squash n'apporte pas ces commits dans `main`).
Le re-pin est donc outillé (`scripts/repin_samm.py`) et vérifié ici : dépôt
attendu, révision connue, fichier présent à la révision — et re-pin
idempotent, qui ne touche pas aux permaliens historiques.

Ce test porte sur la **feuille de preuve**, pas sur le code : il échoue si un
permalien est mort (mauvais dépôt, révision inconnue, fichier absent à la
révision) ou si la fiche n'expose pas la procédure de re-pin.
"""

from __future__ import annotations

import importlib.util
import re
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
FICHE = REPO / "docs" / "t22-samm.md"
SCRIPT = REPO / "scripts" / "repin_samm.py"

DEPOT_ATTENDU = ("Cezar277", "heimdall")


@pytest.fixture
def depot_bidon(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Racine factice : ``main`` confine la fiche à ``parents[1]`` de son script."""
    racine = tmp_path / "repo"
    racine.mkdir()
    monkeypatch.setattr(repin, "__file__", str(racine / "scripts" / "repin_samm.py"))
    return racine


def _charger_script() -> object:
    """Charge `scripts/repin_samm.py` comme module (le dossier n'est pas un paquet)."""
    specification = importlib.util.spec_from_file_location("repin_samm", SCRIPT)
    assert specification is not None and specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    # Le module doit être enregistré avant l'exécution : `@dataclass(slots=True)`
    # lit `sys.modules[cls.__module__]`.
    sys.modules[specification.name] = module
    specification.loader.exec_module(module)
    return module


repin = _charger_script()


def _section_revisions_a_repinner(texte: str) -> set[str]:
    """SHAs déclarés « à re-pinner après la fusion » dans la fiche."""
    marqueur = "révisions à re-pinner après la fusion"
    bas = texte.casefold().find(marqueur)
    if bas < 0:
        return set()
    suite = texte[bas:]
    fin = suite.find("\n## ", 1)
    if fin > 0:
        suite = suite[:fin]
    return set(re.findall(r"\b[0-9a-f]{40}\b", suite))


def test_every_samm_permalink_points_to_the_expected_repository() -> None:
    """Aucun permalien ne pointe un autre dépôt (faute de frappe = preuve morte)."""
    texte = FICHE.read_text(encoding="utf-8")
    liens = repin.extraire(texte)
    assert liens, "la fiche de preuves ne contient aucun permalien"
    for lien in liens:
        assert (lien.owner, lien.repo) == DEPOT_ATTENDU, lien.complet


def test_every_samm_permalink_is_alive_or_declared() -> None:
    """Chaque permalien est vérifiable, ou son rot est **déclaré** dans la fiche."""
    texte = FICHE.read_text(encoding="utf-8")
    declares = _section_revisions_a_repinner(texte)
    for lien in repin.extraire(texte):
        if lien.sha in declares:
            # Rot déclaré : la fiche dit explicitement qu'il faut re-pinner.
            continue
        assert repin.revision_connue(lien.sha, REPO), (
            f"révision inconnue : {lien.sha} — re-pinner sur la révision finale"
        )
        assert repin.fichier_present(lien.sha, lien.path, REPO), (
            f"fichier absent à la révision {lien.sha} : {lien.path}"
        )


def test_the_fiche_declares_the_repin_procedure() -> None:
    """La fiche expose la procédure de re-pin, avant ou après fusion.

    Tant que la fusion n'a pas eu lieu, elle liste les révisions à re-pinner.
    Une fois le re-pin exécuté, elle déclare explicitement son achèvement :
    la procédure et la commande de contrôle restent écrites, la fiche ne peut
    donc pas pourrir en silence.
    """
    texte = FICHE.read_text(encoding="utf-8")
    assert "scripts/repin_samm.py" in texte
    assert "--sha" in texte
    assert "--check" in texte
    bas = texte.casefold()
    assert (
        "révisions à re-pinner après la fusion" in bas or "re-pin après fusion (effectué)" in bas
    ), "la fiche ne déclare ni les révisions à re-pinner ni la clôture du re-pin"


def test_the_repin_rewrites_only_the_links_of_delivered_files(tmp_path: Path) -> None:
    """Le re-pin est déterministe : il ne casse pas les preuves historiques."""
    sha = "a" * 40
    historique = "b" * 40
    texte = (
        f"[courant](https://github.com/{DEPOT_ATTENDU[0]}/{DEPOT_ATTENDU[1]}/blob/"
        f"{historique}/heimdall/scanner/detect.py#L1-L2)\n"
        f"[historique](https://github.com/{DEPOT_ATTENDU[0]}/{DEPOT_ATTENDU[1]}/blob/"
        f"{historique}/heimdall/scanner/signatures.py#L1-L2)\n"
    )
    reecrit = repin.reecrire(texte, sha, REPO)
    # Le fichier encore livré est re-pincé…
    assert f"blob/{sha}/heimdall/scanner/detect.py#L1-L2" in reecrit
    # … le fichier disparu depuis reste épinglé sur sa révision d'origine.
    assert f"blob/{historique}/heimdall/scanner/signatures.py#L1-L2" in reecrit
    # Le re-pin est idempotent.
    assert repin.reecrire(reecrit, sha, REPO) == reecrit


def test_the_repin_refuses_an_unknown_revision(depot_bidon: Path) -> None:
    """Un SHA inconnu (ou malformé) est refusé : aucune preuve inventée."""
    fiche = depot_bidon / "t22-samm.md"
    fiche.write_text("[x](https://github.com/Cezar277/heimdall/blob/" + "c" * 40 + "/a.py)\n")
    code = repin.main(["--sha", "d" * 40, "--fiche", str(fiche)])
    assert code == 2
    code = repin.main(["--sha", "pas-un-sha", "--fiche", str(fiche)])
    assert code == 2
    # La fiche n'a pas été modifiée.
    assert "c" * 40 in fiche.read_text(encoding="utf-8")


def test_the_repin_refuses_a_fiche_outside_the_repository(
    depot_bidon: Path, tmp_path: Path
) -> None:
    """Une fiche hors du dépôt est refusée (pas de lecture ni d'écriture)."""
    dehors = tmp_path / "ailleurs.md"
    contenu = "[x](https://github.com/Cezar277/heimdall/blob/" + "a" * 40 + "/a.py)\n"
    dehors.write_text(contenu, encoding="utf-8")
    assert repin.main(["--check", "--fiche", str(dehors)]) == 2
    assert repin.main(["--check", "--fiche", "../ailleurs.md"]) == 2
    # La fiche hors dépôt n'a pas été modifiée.
    assert dehors.read_text(encoding="utf-8") == contenu


def test_the_check_mode_reports_a_wrong_repository(depot_bidon: Path, tmp_path: Path) -> None:
    """Une fiche hors du dépôt est refusée (code 2) avant toute analyse des liens."""
    fiche = tmp_path / "t22-samm.md"
    fiche.write_text(
        "[x](https://github.com/Cezarwers/heimdall/blob/"
        + "a" * 40
        + "/heimdall/scanner/detect.py)\n"
    )
    assert repin.main(["--check", "--fiche", str(fiche)]) == 2
    # La fiche n'a pas été modifiée : `--check` ne réécrit rien.
    assert "Cezarwers" in fiche.read_text(encoding="utf-8")


def test_the_check_mode_reports_a_wrong_repository_inside_the_repository(
    depot_bidon: Path,
) -> None:
    """`--check` signale un dépôt inconnu quand la fiche est bien dans le dépôt."""
    fiche = depot_bidon / "t22-samm.md"
    fiche.write_text(
        "[x](https://github.com/Cezarwers/heimdall/blob/"
        + "a" * 40
        + "/heimdall/scanner/detect.py)\n"
    )
    assert repin.main(["--check", "--fiche", str(fiche)]) == 1
    # La fiche n'a pas été modifiée : `--check` ne réécrit rien.
    assert "Cezarwers" in fiche.read_text(encoding="utf-8")


def test_livre_refuses_symlinks_even_inside_the_repository(tmp_path: Path) -> None:
    """Revue (LOW) : un lien n'est jamais suivi avant le confinement.

    Le fichier visé peut être interne au dépôt : il n'est pas « livré » pour
    autant, car le permalien pointe un lien, pas un fichier régulier. Un lien
    planté vers l'extérieur ne peut donc pas faire croire qu'un fichier hors
    dépôt est livré.
    """
    racine = tmp_path / "repo"
    racine.mkdir()
    reel = racine / "reel.py"
    reel.write_text("x = 1\n", encoding="utf-8")
    interieur = racine / "interieur.py"
    interieur.symlink_to(reel)
    dehors = tmp_path / "dehors.py"
    dehors.write_text("x = 2\n", encoding="utf-8")
    exterieur = racine / "exterieur.py"
    exterieur.symlink_to(dehors)
    passwd = racine / "passwd.py"
    passwd.symlink_to("/etc/passwd")
    dossier = racine / "dossier"
    dossier.mkdir()
    (dossier / "fichier.py").write_text("x = 3\n", encoding="utf-8")
    dossier_lie = racine / "dossier_lie"
    dossier_lie.symlink_to(dossier)

    assert repin._livre(racine, "reel.py") is True
    assert repin._livre(racine, "interieur.py") is False
    assert repin._livre(racine, "exterieur.py") is False
    assert repin._livre(racine, "passwd.py") is False
    # Un lien intermédiaire est refusé avant même de résoudre le fichier.
    assert repin._livre(racine, "dossier_lie/fichier.py") is False
    # Les composants qui sortent du dépôt sont refusés sans les suivre.
    assert repin._livre(racine, "../dehors.py") is False
    assert repin._livre(racine, str(dehors)) is False


def test_the_repin_never_rewrites_a_permalink_to_a_symlink(tmp_path: Path) -> None:
    """Un permalien vers un lien reste historique : il n'est pas re-pincé."""
    sha = "a" * 40
    historique = "b" * 40
    racine = tmp_path / "repo"
    racine.mkdir()
    cible = racine / "cible.py"
    cible.write_text("x = 1\n", encoding="utf-8")
    (racine / "lien.py").symlink_to(cible)
    texte = (
        f"[lien](https://github.com/{DEPOT_ATTENDU[0]}/{DEPOT_ATTENDU[1]}/blob/"
        f"{historique}/lien.py)\n"
        f"[cible](https://github.com/{DEPOT_ATTENDU[0]}/{DEPOT_ATTENDU[1]}/blob/"
        f"{historique}/cible.py)\n"
    )
    reecrit = repin.reecrire(texte, sha, racine)
    assert f"blob/{historique}/lien.py" in reecrit
    assert f"blob/{sha}/cible.py" in reecrit


FICHE_T84 = REPO / "docs" / "t84-t85-t86-samm.md"


def test_t84_t85_t86_samm_permalinks_integrity_and_header_sync() -> None:
    """Preuves SAMM #84/#85/#86 : permaliens vivants, dépôt exact et en-tête synchrone.

    Vérifie :
    1. Aucun permalien mort (dépôt Cezar277/heimdall, commit connu, fichier présent).
    2. Synchronisation stricte entre le commit d'implémentation annoncé en en-tête
       et les permaliens du tableau (interdit la dérive 30fd0b0 vs 1692ead).
    3. Présence de la procédure de re-pin au merge (`scripts/repin_samm.py`).
    4. Exactitude des ancres de lignes vis-à-vis des symboles implémentés à cette révision.
    """
    texte = FICHE_T84.read_text(encoding="utf-8")
    liens = repin.extraire(texte)
    assert liens, "la fiche de preuves t84-t85-t86 ne contient aucun permalien"

    # 1. Vérification du dépôt et de la présence des fichiers
    for lien in liens:
        assert (lien.owner, lien.repo) == DEPOT_ATTENDU, lien.complet
        assert repin.revision_connue(lien.sha, REPO), (
            f"révision inconnue : {lien.sha} — re-pinner sur la révision finale"
        )
        assert repin.fichier_present(lien.sha, lien.path, REPO), (
            f"fichier absent à la révision {lien.sha} : {lien.path}"
        )

    # 2. Synchronisation de l'en-tête et du tableau
    header_commit = re.search(r"commit d'implémentation\*\*\s*\[`([0-9a-f]{40})`\]", texte)
    assert header_commit is not None, "SHA du commit d'implémentation absent de l'en-tête"
    base_tree = re.search(
        r"Base des liens :\s*`https://github\.com/Cezar277/heimdall/tree/([0-9a-f]{40})/?`",
        texte,
    )
    assert base_tree is not None, "SHA de base tree absent de l'en-tête"
    sha_entete = header_commit.group(1)
    assert sha_entete == base_tree.group(1), (
        f"Incohérence en-tête : commit ({sha_entete}) != tree ({base_tree.group(1)})"
    )

    table_shas = {lien.sha for lien in liens}
    assert table_shas == {sha_entete}, (
        f"Dérive de permaliens : tableau ({table_shas}) != en-tête ({sha_entete})"
    )

    # 3. Procédure de re-pin déclarée
    assert "scripts/repin_samm.py" in texte
    assert "--fiche docs/t84-t85-t86-samm.md" in texte
    assert "--sha" in texte
    assert "--check" in texte

    # 4. Cohérence des ancres symboliques à la révision d'implémentation
    expected_symbols = {
        ("heimdall/remediation/naming.py", 20): "_VARIABLE",
        ("heimdall/remediation/naming.py", 23): "_MAX_NAME_LENGTH",
        ("heimdall/remediation/naming.py", 30): "DANGEROUS_ENV_EXACT",
        ("heimdall/remediation/naming.py", 115): "DANGEROUS_ENV_PREFIXES",
        ("heimdall/remediation/naming.py", 162): "is_dangerous_env_var",
        ("heimdall/remediation/naming.py", 172): "validate_variable_name",
        ("heimdall/remediation/naming.py", 188): "deduplicate_variable_name",
        ("heimdall/cli/vault_client.py", 31): "is_dangerous_env_var",
        ("heimdall/cli/vault_client.py", 61): "preview_name",
        ("heimdall/remediation/apply.py", 53): "ApplyError",
        ("heimdall/remediation/apply.py", 61): "AppliedPatch",
        ("heimdall/remediation/apply.py", 71): "_read_current_secure",
        ("heimdall/remediation/apply.py", 106): "_check_backup_git_status",
        ("heimdall/remediation/apply.py", 161): "confine",
        ("heimdall/remediation/apply.py", 165): "plan.before",
        ("heimdall/remediation/apply.py", 168): "backup_file",
        ("heimdall/remediation/apply.py", 174): "_check_backup_git_status",
        ("heimdall/remediation/apply.py", 176): "write_file_atomic",
        ("heimdall/remediation/apply.py", 191): "undo_apply",
        ("heimdall/remediation/apply.py", 205): "confine",
        ("heimdall/remediation/apply.py", 208): "receipt.backup",
        ("heimdall/remediation/templates.py", 70): "_VARIABLE",
        ("heimdall/remediation/templates.py", 191): "__repr__",
    }
    for (rel_path, line_no), symbol in expected_symbols.items():
        code, content = repin._git("cat-file", "-p", f"{sha_entete}:{rel_path}", cwd=REPO)
        assert code == 0, f"impossible d'extraire {rel_path} à {sha_entete}"
        lines = content.splitlines()
        assert 1 <= line_no <= len(lines), f"{rel_path}:{line_no} hors limites"
        target_line = lines[line_no - 1]
        assert symbol in target_line, (
            f"Dérive de ligne à {rel_path}:{line_no} — attendu '{symbol}', trouvé : {target_line!r}"
        )


FICHE_T31 = REPO / "docs" / "t31-samm.md"


def test_t31_samm_permalinks_integrity_and_header_sync() -> None:
    """Preuves SAMM #31 : permaliens vivants, dépôt exact et en-tête synchrone."""
    texte = FICHE_T31.read_text(encoding="utf-8")
    liens = repin.extraire(texte)
    assert liens, "la fiche de preuves t31 ne contient aucun permalien"

    # 1. Vérification du dépôt et de la présence des fichiers
    for lien in liens:
        assert (lien.owner, lien.repo) == DEPOT_ATTENDU, lien.complet
        assert repin.revision_connue(lien.sha, REPO), (
            f"révision inconnue : {lien.sha} — re-pinner sur la révision finale"
        )
        assert repin.fichier_present(lien.sha, lien.path, REPO), (
            f"fichier absent à la révision {lien.sha} : {lien.path}"
        )

    # 2. Synchronisation de l'en-tête et du tableau
    header_commit = re.search(r"commit d'implémentation\*\*\s*\[`([0-9a-f]{40})`\]", texte)
    assert header_commit is not None, "SHA du commit d'implémentation absent de l'en-tête"
    base_tree = re.search(
        r"Base des liens :\s*`https://github\.com/Cezar277/heimdall/tree/([0-9a-f]{40})/?`",
        texte,
    )
    assert base_tree is not None, "SHA de base tree absent de l'en-tête"
    sha_entete = header_commit.group(1)
    assert sha_entete == base_tree.group(1), (
        f"Incohérence en-tête : commit ({sha_entete}) != tree ({base_tree.group(1)})"
    )

    table_shas = {lien.sha for lien in liens}
    assert table_shas == {sha_entete}, (
        f"Dérive de permaliens : tableau ({table_shas}) != en-tête ({sha_entete})"
    )

    # 3. Procédure de re-pin déclarée
    assert "scripts/repin_samm.py" in texte
    assert "--fiche docs/t31-samm.md" in texte
    assert "--sha" in texte
    assert "--check" in texte

    # 4. Cohérence des ancres symboliques à la révision d'implémentation
    expected_symbols = {
        ("heimdall/remediation/env.py", 64): "_SECURE_ENV_MODE",
        ("heimdall/remediation/env.py", 73): "EnvRemediationError",
        ("heimdall/remediation/env.py", 84): "EnvRemediationReceipt",
        ("heimdall/remediation/env.py", 103): "__repr__",
        ("heimdall/remediation/env.py", 145): "_validate_gitignore_pattern",
        ("heimdall/remediation/env.py", 174): "_read_text_secure",
        ("heimdall/remediation/env.py", 221): "_extract_and_validate_names",
        ("heimdall/remediation/env.py", 269): "_parse_example_lines",
        ("heimdall/remediation/env.py", 283): "_pattern_matches_target",
        ("heimdall/remediation/env.py", 309): "_is_env_covered_in_gitignore",
        ("heimdall/remediation/env.py", 333): "ensure_gitignore_ignores_env",
        ("heimdall/remediation/env.py", 382): "update_env_example",
        ("heimdall/remediation/env.py", 439): "update_env_file",
        ("heimdall/remediation/env.py", 546): "check_env_git_status",
        ("heimdall/remediation/env.py", 595): "plan_env_example_change",
        ("heimdall/remediation/env.py", 637): "plan_gitignore_change",
        ("heimdall/remediation/env.py", 674): "remediate_environment",
    }
    for (rel_path, line_no), symbol in expected_symbols.items():
        code, content = repin._git("cat-file", "-p", f"{sha_entete}:{rel_path}", cwd=REPO)
        assert code == 0, f"impossible d'extraire {rel_path} à {sha_entete}"
        lines = content.splitlines()
        assert 1 <= line_no <= len(lines), f"{rel_path}:{line_no} hors limites"
        target_line = lines[line_no - 1]
        assert symbol in target_line, (
            f"Dérive de ligne à {rel_path}:{line_no} — attendu '{symbol}', trouvé : {target_line!r}"
        )
