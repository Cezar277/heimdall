#!/usr/bin/env python3
"""Re-pince les permaliens de preuve SAMM sur la révision finale (#22).

La fiche ``docs/t22-samm.md`` épingle ses permaliens sur la **révision du
code testé**. Tant que cette révision est un commit *intermédiaire* de la
branche, la preuve est rejouable sur la branche mais **pourrit à la fusion** :
un squash n'apporte pas les commits intermédiaires dans ``main``, les liens
deviennent morts et la preuve n'est plus vérifiable par un auditeur.

Ce script rend le re-pin **déterministe** (aucune chasse au SHA à la main) :

.. code-block:: sh

    python scripts/repin_samm.py --sha <sha-final>   # réécrit la fiche
    python scripts/repin_samm.py --check             # vérifie les permaliens

Règle de ré-écriture : un permalien est re-pincé sur la révision cible
**seulement** si le fichier visé existe encore dans l'arborescence livrée. Un
permalien qui pointe un fichier depuis déplacé (ou supprimé) est une preuve
**historique** : il reste épinglé sur sa révision d'origine, sinon il
deviendrait un lien mort.

``--check`` signale (code de sortie 1) : un dépôt inconnu, une révision
absente de l'historique local, ou un fichier qui n'existait pas à la révision
référencée. Il ne modifie rien.

Le script ne lit aucun secret et n'écrit que le fichier de documentation
désigné : il est donc sans effet sur le code livré.
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import stat
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

#: Dépôt attendu : toute permalien vers un autre dépôt est une erreur.
DEPOT_ATTENDU: tuple[str, str] = ("Cezar277", "heimdall")

#: Fiche de preuves par défaut.
FICHE_DEFAUT: Path = Path("docs/t22-samm.md")

#: Permalien GitHub vers un fichier, avec son ancre de lignes optionnelle.
PERMALIEN = re.compile(
    r"https://github\.com/(?P<owner>[A-Za-z0-9_.-]+)/(?P<repo>[A-Za-z0-9_.-]+)"
    r"/blob/(?P<sha>[0-9a-f]{40})/(?P<path>[^)\s#]+)(?P<ancre>#[^)\s]*)?"
)

#: SHA hexadécimal isolé (40 caractères), utilisé pour les mentions en prose.
SHA_ISOLE = re.compile(r"\b[0-9a-f]{40}\b")


@dataclass(frozen=True, slots=True)
class Permalien:
    """Un permalien de preuve : dépôt, révision, fichier, ancre."""

    owner: str
    repo: str
    sha: str
    path: str
    ancre: str
    debut: int
    fin: int

    @property
    def complet(self) -> str:
        """Le permalien tel qu'il apparaît dans la fiche."""
        return (
            f"https://github.com/{self.owner}/{self.repo}/blob/{self.sha}/{self.path}{self.ancre}"
        )


def extraire(text: str) -> list[Permalien]:
    """Extrait les permaliens d'un texte, dans l'ordre d'apparition."""
    trouves: list[Permalien] = []
    for match in PERMALIEN.finditer(text):
        trouves.append(
            Permalien(
                owner=match.group("owner"),
                repo=match.group("repo"),
                sha=match.group("sha"),
                path=match.group("path"),
                ancre=match.group("ancre") or "",
                debut=match.start(),
                fin=match.end(),
            )
        )
    return trouves


def _git(*args: str, cwd: Path) -> tuple[int, str]:
    """Exécute ``git`` et rend (code de sortie, sortie standard)."""
    # Chemin **absolu** de `git` : pas de résolution par le `PATH` (un `PATH`
    # détourné ne doit pas pouvoir substituer un autre programme), et pas de
    # shell (aucune interpretation de la ligne de commande).
    executable = shutil.which("git")
    if executable is None:
        return 1, ""
    try:
        fini = subprocess.run(  # noqa: S603 — arguments fixes, aucun shell
            (executable, *args),
            cwd=cwd,
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError:
        return 1, ""
    return fini.returncode, fini.stdout.strip()


def revision_connue(sha: str, racine: Path) -> bool:
    """Vrai si ``sha`` est un commit connu de l'historique local."""
    code, _ = _git("cat-file", "-e", f"{sha}^{{commit}}", cwd=racine)
    return code == 0


def fichier_present(revision: str, chemin: str, racine: Path) -> bool:
    """Vrai si ``chemin`` existait dans l'arborescence de ``revision``."""
    code, _ = _git("cat-file", "-e", f"{revision}:{chemin}", cwd=racine)
    return code == 0


def reecrire(text: str, sha_cible: str, racine: Path) -> str:
    """Ré-écrit les permaliens des fichiers encore livrés sur ``sha_cible``.

    Les permaliens historiques (fichier déplacé ou supprimé depuis) sont
    laissés intacts : ils documentent une révision antérieure, pas le code
    livré.
    """
    resultat: list[str] = []
    curseur = 0
    for lien in extraire(text):
        resultat.append(text[curseur : lien.debut])
        if (lien.owner, lien.repo) == DEPOT_ATTENDU and _livre(racine, lien.path):
            resultat.append(
                f"https://github.com/{lien.owner}/{lien.repo}/blob/{sha_cible}/{lien.path}{lien.ancre}"
            )
        else:
            resultat.append(lien.complet)
        curseur = lien.fin
    resultat.append(text[curseur:])
    return "".join(resultat)


def _livre(racine: Path, chemin: str) -> bool:
    """Vrai si le fichier visé existe encore dans l'arborescence livrée.

    Aucun lien symbolique n'est suivi, y compris dans les composants
    intermédiaires : un permalien vers un lien — même interne — n'est pas
    re-pincé, et un lien planté ne peut pas faire croire qu'un fichier hors
    dépôt est livré. Les composants ``..``, vides ou absolus sont refusés
    avant tout accès disque.
    """
    relatif = PurePosixPath(chemin)
    if relatif.is_absolute() or not relatif.parts:
        return False
    if any(partie in {"", ".", ".."} for partie in relatif.parts):
        return False
    try:
        racine = racine.resolve()
        candidat = racine
        for partie in relatif.parts:
            candidat = candidat / partie
            if stat.S_ISLNK(os.lstat(candidat).st_mode):
                return False
        chemin_resolu = candidat.resolve(strict=True)
        if not chemin_resolu.is_relative_to(racine):
            return False
        return stat.S_ISREG(os.stat(chemin_resolu, follow_symlinks=False).st_mode)
    except (OSError, RuntimeError, ValueError):
        return False


def verifier(text: str, racine: Path) -> list[str]:
    """Liste les problèmes des permaliens d'une fiche (liste vide = sain)."""
    problemes: list[str] = []
    for lien in extraire(text):
        if (lien.owner, lien.repo) != DEPOT_ATTENDU:
            problemes.append(
                f"dépôt inconnu : {lien.owner}/{lien.repo} (attendu "
                f"{DEPOT_ATTENDU[0]}/{DEPOT_ATTENDU[1]}) — {lien.path}"
            )
            continue
        if not revision_connue(lien.sha, racine):
            problemes.append(
                f"révision absente de l'historique local : {lien.sha} — "
                f"re-pinner sur la révision finale"
            )
            continue
        if not fichier_present(lien.sha, lien.path, racine):
            problemes.append(
                f"fichier absent à la révision {lien.sha} : {lien.path} — permalien mort"
            )
    return problemes


def _resoudre_fiche(fiche: Path, racine: Path) -> Path | None:
    """Résout ``--fiche`` et la confine strictement au dépôt.

    Un chemin absolu hors dépôt (``/tmp/x``), une remontée (``../../x``) ou
    un lien symbolique interne pointant à l'extérieur sont refusés : la fiche
    de preuves ne doit jamais être lue ni écrite hors de la racine.
    """
    if not fiche.is_absolute():
        fiche = racine / fiche
    try:
        fiche = fiche.resolve()
    except (OSError, RuntimeError, ValueError):
        print(f"fiche invalide : {fiche}", file=sys.stderr)
        return None
    if not fiche.is_relative_to(racine):
        print(f"fiche hors du dépôt : {fiche}", file=sys.stderr)
        return None
    if not fiche.is_file():
        print(f"fiche introuvable : {fiche}", file=sys.stderr)
        return None
    return fiche


def main(argv: list[str] | None = None) -> int:
    """Point d'entrée : réécrit (ou vérifie) la fiche de preuves."""
    analyseur = argparse.ArgumentParser(description=__doc__)
    analyseur.add_argument(
        "--sha",
        help="révision finale (40 caractères hexadécimaux) sur laquelle re-pince",
    )
    analyseur.add_argument(
        "--fiche",
        type=Path,
        default=FICHE_DEFAUT,
        help=f"fiche de preuves à traiter (défaut : {FICHE_DEFAUT})",
    )
    analyseur.add_argument(
        "--check",
        action="store_true",
        help="vérifier les permaliens sans modifier la fiche",
    )
    arguments = analyseur.parse_args(argv)

    racine = Path(__file__).resolve().parents[1]
    fiche = _resoudre_fiche(arguments.fiche, racine)
    if fiche is None:
        return 2
    texte = fiche.read_text(encoding="utf-8")

    if arguments.check:
        problemes = verifier(texte, racine)
        for probleme in problemes:
            print(f"permalink mort : {probleme}", file=sys.stderr)
        return 1 if problemes else 0

    if not arguments.sha:
        print("il faut --sha <révision finale> (ou --check)", file=sys.stderr)
        return 2
    sha = arguments.sha.strip().lower()
    if not re.fullmatch(r"[0-9a-f]{40}", sha):
        print("SHA invalide : 40 caractères hexadécimaux attendus", file=sys.stderr)
        return 2
    if not revision_connue(sha, racine):
        print(f"révision inconnue de l'historique local : {sha}", file=sys.stderr)
        return 2

    contenu = reecrire(texte, sha, racine)
    temporaire = fiche.with_suffix(".tmp")
    try:
        # Écriture atomique : un crash en cours d'écriture ne doit jamais
        # laisser une fiche de preuve tronquée. Le `fsync` garantit que les
        # octets sont sur disque avant le remplacement. `O_EXCL` et
        # `O_NOFOLLOW` empêchent le détournement du fichier temporaire par un
        # lien symbolique préexistant.
        descripteur = os.open(
            temporaire,
            os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW,
            0o644,
        )
        with os.fdopen(descripteur, "w", encoding="utf-8", newline="\n") as flux:
            flux.write(contenu)
            flux.flush()
            os.fsync(flux.fileno())
        os.replace(temporaire, fiche)
    finally:
        temporaire.unlink(missing_ok=True)
    print(f"permaliens re-pincés sur {sha} : {fiche.relative_to(racine)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
