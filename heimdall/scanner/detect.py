"""Détection déterministe des candidats secrets (#22).

Ce module fait deux choses, et les deux sont **fail-closed** :

- il parcourt une racine confinée (dépôt ou fichier explicite) en appliquant
  la politique de périmètre (``exclusions``) ;
- il délègue la détection au moteur de signatures (``signature_engine``),
  appelé par la façade ``interface.Scanner`` avec une cible ``FileTarget``.

La sortie est conforme au contrat Finding v1 (#14) : la classe ``Finding``
vient de ``heimdall.scanner.finding``, source de vérité unique — c'est la
réconciliation annoncée par ``docs/scanner-interface.md`` (« l'épic importe
``Finding`` au lieu de le redéclarer ; le moteur de l'épic est appelé par la
façade ``Scanner`` de #53 »).

Invariants :

- un scan incomplet lève ``ScanError`` (fail-closed, jamais une liste
  partielle) : ``scan()`` et ``find_candidates()`` refusent dès qu'un
  fichier du périmètre n'a pas pu être analysé ;
- un verdict « propre » n'est fondé que si ``RapportScan.complet`` est
  vrai : le rapport expose **tout** ce qui n'a pas été lu (binaire, lien
  non suivi, base VCS non parcourue, fichier illisible) ;
- un verdict « propre » ne peut pas être **inventé** par un appelant :
  l'API stricte ``scan_complet()`` (et ``exiger_complet()``) refuse un
  rapport incomplet, et ``scan()`` avertit (``ScanIncomplet``) quand une
  liste vide signifie seulement « rien trouvé dans ce qui a été lu » ;
- un Finding ne contient jamais la valeur candidate, seulement son empreinte
  HMAC-SHA-256 et son entropie ;
- les chemins sont relatifs, en ``/``, sans ``..`` ni segment vide ;
- les liens symboliques ne sont jamais suivis, ni dans le périmètre, ni dans
  le chemin de la racine, et les fichiers restent confinés à la racine résolue ;
- les lectures sont bornées (1 Mio) et les regex sont linéaires et bornées ;
- **aucun nom de fichier n'exclut un fichier du scan** : le contenu décide.
  Un ``evil.png``, un ``package-lock.json`` ou un ``vendor/secret.txt`` dont le
  contenu est du texte est lu et scanné ; seul un contenu réellement binaire
  est ignoré, et il est **tracé** (chemin journalisé, compteur dans le
  rapport) pour qu'un dépôt propre ne soit jamais confondu avec un dépôt dont
  une partie n'a pas été analysée.

Deux classes portent le nom « scanner » et ne doivent jamais être confondues :

- ``heimdall.scanner.interface.Scanner`` : la façade contractuelle (#53), qui
  délègue à un moteur injecté et garantit la forme de la sortie ;
- ``heimdall.scanner.detect.ScannerRacine`` : le parcours d'une racine (#22),
  qui construit les cibles et fait appel à cette façade.
"""

from __future__ import annotations

import os
import stat
import sys
import unicodedata
import warnings
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from heimdall.scanner.errors import ScanError, ScanIncomplet
from heimdall.scanner.exclusions import (
    Perimetre,
    classer_chemin,
    classer_repertoire,
    decode_text,
)
from heimdall.scanner.finding import (
    Finding,
    FindingSource,
    FindingStatus,
    validate_relative_path,
)
from heimdall.scanner.hashing import SnippetHasher
from heimdall.scanner.interface import FileTarget, Scanner
from heimdall.scanner.signature_engine import SignatureEngine

#: Taille maximale d'un fichier analysé (1 Mio). Un fichier plus large est
#: **refusé** (``ScanError``), jamais tronqué en silence.
MAX_FILE_BYTES: Final[int] = 1_048_576
#: Taille de lecture par ``os.read`` : borne de mémoire, pas de sémantique.
_READ_CHUNK: Final[int] = 65_536
#: Message statique : ni chemin, ni extrait, ni valeur candidate n'est
#: jamais reflété (invariant 8).
_SCAN_ERROR: Final[str] = "scan impossible : entrée non analysable"
#: Message statique du refus « rapport incomplet » : c'est la sortie 2
#: d'outillage attendue par #29 (jamais 0, jamais 1).
_SCAN_INCOMPLET: Final[str] = "scan incomplet : verdict propre non fondé"
#: Avertissement statique émis quand des contenus ont été laissés de côté
#: alors que le scan n'a pas échoué : un ``[]`` ne signifie donc pas
#: « dépôt propre », et l'appelant est invité à consommer l'API stricte.
_SCAN_INCOMPLET_AVERTISSEMENT: Final[str] = (
    "scan incomplet : des contenus n'ont pas été lus (binaire, lien symbolique, "
    "base VCS) ; le verdict « propre » n'est pas fondé — utiliser scan_complet() "
    "pour un usage hook/CI"
)

#: Préfixe des traces : le journal ne porte **jamais** de contenu, seulement
#: un chemin relatif déjà assaini.
_TRACE_PREFIX: Final[str] = "heimdall scanner :"
#: Motifs de trace (statiques : aucune donnée d'entrée n'y figure).
_MOT_BINAIRE: Final[str] = "binaire ignoré (contenu non textuel)"
_MOT_NON_ANALYSE: Final[str] = "non analysable (illisible, hors borne ou modifié)"
_MOT_LIEN: Final[str] = "lien symbolique non suivi"
_MOT_HORS_PERIMETRE: Final[str] = "répertoire hors périmètre (non analysé)"
#: Longueur maximale d'un chemin tracé : un nom de fichier est une donnée non
#: fiable (longueur, caractères de contrôle) — il ne doit ni noyer le journal
#: ni y injecter de fausses lignes.
_TRACE_PATH_MAX: Final[int] = 256
#: Catégories Unicode neutralisées dans le journal : ``Cc`` (contrôle, dont
#: U+0085), ``Cf`` (format, dont l'override bidirectionnel U+202E), ``Zl``
#: et ``Zp`` (séparateurs de ligne, dont U+2028/U+2029). Un séparateur de
#: ligne Unicode ne se voit pas dans un terminal classique, mais il casse
#: l'affichage ligne à ligne des journaux et des consoles d'audit : un nom
#: adverse ne doit jamais pouvoir insérer une fausse ligne de journal.
_UNSAFE_CATEGORIES: Final[frozenset[str]] = frozenset({"Cc", "Cf", "Zl", "Zp"})

__all__ = [
    "MAX_FILE_BYTES",
    "Finding",
    "FindingSource",
    "FindingStatus",
    "Perimetre",
    "RapportScan",
    "ScanError",
    "ScanIncomplet",
    "ScannerRacine",
    "exiger_complet",
    "find_candidates",
    "scan",
    "scan_complet",
    "scan_rapport",
]


def _safe_path(relative: str) -> str:
    """Chien de garde du journal : caractères de contrôle neutralisés.

    Un nom de fichier est une donnée **non fiable** : il peut contenir un
    retour à la ligne (injection de fausses lignes de journal), un
    séparateur de ligne Unicode (U+2028), un séparateur de paragraphe
    (U+2029), un « next line » (U+0085) ou un override bidirectionnel
    (U+202E). Les caractères de contrôle (``Cc``), de format (``Cf``) et les
    séparateurs de ligne (``Zl``/``Zp``) sont remplacés ; la longueur est
    bornée.
    """
    nettoye = "".join(
        "?" if unicodedata.category(character) in _UNSAFE_CATEGORIES else character
        for character in relative
    )
    if len(nettoye) > _TRACE_PATH_MAX:
        return nettoye[: _TRACE_PATH_MAX - 1] + "…"
    return nettoye


def _journal_stderr(message: str) -> None:
    """Trace par défaut : ``stderr``, jamais ``stdout`` (le verdict sort à part)."""
    sys.stderr.write(message + "\n")


class _RefusInterne(Exception):
    """Refus interne : le fichier n'a pas pu être analysé.

    La décision — interrompre le scan (``ScanError``) ou tracer l'ignorance —
    appartient à l'appelant, qui connaît le régime de périmètre du fichier.
    """


@dataclass(frozen=True, slots=True)
class RapportScan:
    """Bilan d'un scan : les Findings et ce qui n'a pas pu être analysé.

    Les compteurs sont la preuve qu'un verdict « propre » est fondé :

    - ``binaires_ignores`` : fichiers au contenu binaire connu, ignorés par
      politique et journalisés ;
    - ``non_analyses`` : fichiers du périmètre que le scan n'a pas pu lire
      (illisibles, hors borne, modifiés) — un fichier du périmètre strict
      est fatal, donc ce compteur reste nul dans un scan complet ;
    - ``hors_perimetre`` : répertoires non parcourus (base VCS) ;
    - ``liens_ignores`` : liens symboliques non suivis.

    ``complet`` est vrai quand **rien** n'a été laissé de côté : c'est la
    condition pour qu'un verdict « propre » soit fondé. Un binaire ignoré,
    un lien non suivi ou une base VCS non parcourue sont autant de
    contenus **non lus** : un secret peut y dormir, donc le verdict ne
    serait pas fondé.
    """

    findings: tuple[Finding, ...] = ()
    binaires_ignores: int = 0
    non_analyses: int = 0
    hors_perimetre: int = 0
    liens_ignores: int = 0

    @property
    def complet(self) -> bool:
        """Vrai si rien n'a été laissé de côté pendant le scan.

        Un verdict « propre » n'est fondé que si cette propriété est vraie :
        le moindre compteur non nul signifie qu'une partie du périmètre
        n'a pas été lue (binaire, lien, base VCS, fichier illisible).
        """
        return (
            self.non_analyses == 0
            and self.binaires_ignores == 0
            and self.liens_ignores == 0
            and self.hors_perimetre == 0
        )


def exiger_complet(rapport: RapportScan) -> RapportScan:
    """Garde **programmatique** : un rapport incomplet ne fonde aucun verdict.

    C'est la garde d'usage que #29 doit appliquer : tant que le rapport
    n'est pas complet, un dépôt peut cacher un secret dans un binaire, un
    lien symbolique ou une base VCS — donc « aucun candidat » ne veut pas
    dire « dépôt propre ». La garde est ici **exécutable** (et non laissée à
    une simple consigne de documentation) : elle refuse par ``ScanError``,
    message statique, sans chemin ni valeur.

    Le refus est l'erreur d'outillage attendue par la CLI (code 2, jamais 0
    ni 1) : un verdict « propre » inventé ne peut pas sortir d'ici.
    """
    if not rapport.complet:
        raise ScanError(_SCAN_INCOMPLET)
    return rapport


def _validate_relative_path(relative: str) -> str:
    """Refuse un chemin qui violerait le contrat Finding v1.

    La grammaire est celle de ``finding.validate_relative_path`` (source de
    vérité unique) ; l'échec devient un ``ScanError`` au message statique du
    scanner, jamais une ``ValueError`` nue.
    """
    try:
        return validate_relative_path(relative)
    except ValueError:
        raise ScanError(_SCAN_ERROR) from None


def _open_flags() -> int:
    """Descripteur de lecture : un lien symbolique n'est jamais suivi."""
    return (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_BINARY", 0)
    )


def _resolve_root(root: str | os.PathLike[str]) -> Path:
    """Résout la racine sans jamais suivre un lien symbolique.

    La racine elle-même et chacun de ses ancêtres sont vérifiés par
    ``lstat`` : un lien symbolique dans le chemin de la racine est refusé
    (``ScanError``) au lieu d'être suivi en silence. La promesse « les liens
    symboliques ne sont jamais suivis » vaut donc aussi pour la racine et
    pour le fichier unique.

    Une racine invalide — chemin vide, octet NUL, racine absente — est
    refusée par ``ScanError`` au message statique : jamais une
    ``ValueError`` nue qui court-circuiterait le contrat d'erreur.
    """
    try:
        absolute = Path(os.path.abspath(Path(root).expanduser()))
        for candidate in (absolute, *absolute.parents):
            if candidate.is_symlink():
                raise ScanError(_SCAN_ERROR)
        resolved = absolute.resolve(strict=True)
        # Course symlink (check-then-resolve) : si un composant a été remplacé
        # entre le `lstat` et le `resolve`, le résolu diffère du demandé et la
        # racine serait détournée hors périmètre — refus au lieu de suivre.
        if resolved != absolute:
            raise ScanError(_SCAN_ERROR)
        return resolved
    except (OSError, RuntimeError, ValueError):
        raise ScanError(_SCAN_ERROR) from None


class ScannerRacine:
    """Scanner déterministe d'une racine confinée (#22).

    ``root`` peut être un répertoire ou un fichier régulier explicite. La
    racine est résolue une fois, sans suivre de lien symbolique ; chaque
    fichier est ensuite vérifié à l'usage (identité de descripteur, chemin
    résolu sous la racine, refus des liens).

    La détection n'est pas implémentée ici : chaque fichier lu devient une
    cible ``FileTarget``, analysée par la façade #53 branchée sur le moteur de
    signatures #54. Une seule implémentation de la détection existe donc dans
    le paquet, et la garantie de forme de la sortie reste celle de #53.

    Ce qui n'a pas pu être analysé est **tracé** : ``journal`` reçoit une
    ligne par fichier ignoré (chemin seul, jamais de contenu) et le rapport
    rendu par ``analyser()`` porte les compteurs.
    """

    __slots__ = (
        "_binaires",
        "_journal",
        "_liens",
        "_moteur",
        "_non_analyses",
        "_hors_perimetre",
        "_root",
        "_single",
    )

    def __init__(
        self,
        root: str | os.PathLike[str],
        *,
        hasher: SnippetHasher | None = None,
        journal: Callable[[str], None] | None = None,
    ) -> None:
        resolved = _resolve_root(root)
        if resolved.is_dir():
            self._root = resolved
            self._single: Path | None = None
        elif resolved.is_file():
            self._root = resolved.parent
            self._single = resolved
        else:
            raise ScanError(_SCAN_ERROR)
        # La clé HMAC est chargée paresseusement par le moteur : instancier le
        # scanner ne crée aucun fichier et ne touche pas au stockage local.
        self._moteur = Scanner(SignatureEngine(hasher))
        self._journal = _journal_stderr if journal is None else journal
        self._binaires = 0
        self._non_analyses = 0
        self._hors_perimetre = 0
        self._liens = 0

    def analyser(self) -> RapportScan:
        """Analyse tout le périmètre et retourne le bilan complet.

        Toute erreur de lecture **du périmètre strict** interrompt le scan :
        aucun résultat partiel n'est retourné. Ce qui est ignoré dans les
        arbres de tiers ou la base VCS est compté et journalisé.

        Le rapport rendu par cette méthode est la seule source de vérité
        sur ce qui n'a pas été lu : ``RapportScan.complet`` est vrai quand
        rien n'a été laissé de côté. C'est cette API que #29 doit
        consommer — un verdict « propre » n'est fondé que si ``complet``
        est vrai.
        """
        self._binaires = 0
        self._non_analyses = 0
        self._hors_perimetre = 0
        self._liens = 0
        findings: list[Finding] = []
        # Pas de `list()` sur le périmètre : un dépôt adverse avec un très
        # grand nombre de fichiers ne doit pas OOM le hook/CI. Le tri final
        # porte sur les findings, pas sur les chemins.
        files = (
            [(self._single, self._single.name, Perimetre.STRICT)]
            if self._single is not None
            else self._iter_files()
        )
        for path, relative, perimetre in files:
            findings.extend(self._analyser_fichier(path, relative, perimetre))
        findings.sort(
            key=lambda finding: (
                finding.file,
                finding.line,
                finding.type,
                finding.snippet_hash,
            )
        )
        return RapportScan(
            findings=tuple(findings),
            binaires_ignores=self._binaires,
            non_analyses=self._non_analyses,
            hors_perimetre=self._hors_perimetre,
            liens_ignores=self._liens,
        )

    def analyser_complet(self) -> RapportScan:
        """Analyse et **refuse** un rapport incomplet (``ScanError``).

        C'est l'API stricte : elle rend un bilan seulement si rien n'a été
        laissé de côté. Un appelant qui veut annoncer un verdict « propre »
        (hook, CI) consomme celle-ci : il ne peut pas obtenir un bilan
        partiel qu'il confondrait avec un dépôt propre.
        """
        return exiger_complet(self.analyser())

    def scan(self) -> list[Finding]:
        """Analyse tout le périmètre et retourne les Findings triés.

        **Fail-closed** : dès qu'un fichier du périmètre n'a pas pu être
        analysé, ``ScanError`` est levé. Un scan incomplet ne devient
        jamais une liste vide ou partielle — sans quoi l'appelant
        confondrait un dépôt propre et un dépôt partiellement lu.

        Les exclusions de politique (binaire connu, lien symbolique, base
        VCS) ne sont pas des échecs de lecture : elles sont comptées et
        journalisées par ``analyser()``. Pour un verdict « propre » fondé,
        il faut ``analyser()`` **et** ``RapportScan.complet`` — ou, mieux,
        ``analyser_complet()`` (ou ``scan_complet()``), qui **refusent** un
        rapport incomplet au lieu de le rendre.

        Une liste vide n'est donc **pas** la preuve d'un dépôt propre : si
        des contenus ont été laissés de côté, un avertissement
        ``ScanIncomplet`` est émis (message statique, jamais de chemin ni de
        valeur).
        """
        rapport = self.analyser()
        if rapport.non_analyses:
            raise ScanError(_SCAN_ERROR)
        if not rapport.complet:
            warnings.warn(
                _SCAN_INCOMPLET_AVERTISSEMENT,
                ScanIncomplet,
                stacklevel=2,
            )
        return list(rapport.findings)

    def _iter_files(self) -> Iterator[tuple[Path, str, Perimetre]]:
        """Parcourt la racine sans jamais suivre un lien symbolique.

        Aucun répertoire n'est exclu *par son nom* : les répertoires de tiers
        sont parcourus (un secret y est un secret) et la base VCS est écartée
        mais **tracée**.
        """
        for current, directories, filenames in os.walk(
            self._root,
            topdown=True,
            onerror=self._on_walk_error,
            followlinks=False,
        ):
            current_path = Path(current)
            kept: list[str] = []
            for name in sorted(directories):
                regime = classer_repertoire(name)
                if regime is Perimetre.HORS_PERIMETRE:
                    self._hors_perimetre += 1
                    self._tracer(_MOT_HORS_PERIMETRE, self._relatif(current_path / name))
                    continue
                if self._est_lien(current_path / name):
                    self._liens += 1
                    self._tracer(_MOT_LIEN, self._relatif(current_path / name))
                    continue
                kept.append(name)
            directories[:] = kept
            for name in sorted(filenames):
                path = current_path / name
                relative = self._relatif(path)
                if self._est_lien(path):
                    self._liens += 1
                    self._tracer(_MOT_LIEN, relative)
                    continue
                yield path, relative, classer_chemin(relative)

    def _est_lien(self, path: Path) -> bool:
        """Vrai si le chemin est un lien symbolique (jamais suivi)."""
        try:
            return path.is_symlink()
        except OSError:
            raise ScanError(_SCAN_ERROR) from None

    def _relatif(self, path: Path) -> str:
        """Chemin relatif à la racine (jamais absolu, jamais hors racine)."""
        try:
            return path.relative_to(self._root).as_posix()
        except ValueError:
            raise ScanError(_SCAN_ERROR) from None

    def _on_walk_error(self, error: OSError) -> None:
        """Une erreur de parcours interrompt le scan, sauf en arbre de tiers."""
        nom = error.filename or ""
        regime = Perimetre.STRICT
        if nom:
            try:
                relatif = Path(nom).relative_to(self._root).as_posix()
            except ValueError:
                relatif = nom
            regime = classer_chemin(relatif)
        if regime is Perimetre.STRICT:
            raise ScanError(_SCAN_ERROR) from None
        self._non_analyses += 1
        self._tracer(_MOT_NON_ANALYSE, nom or "")

    def _analyser_fichier(
        self,
        path: Path,
        relative: str,
        perimetre: Perimetre,
    ) -> list[Finding]:
        """Analyse un fichier du périmètre et applique la règle du régime.

        Dans le périmètre **strict**, tout ce qui n'est pas analysable est
        fatal (``ScanError``) : un verdict « propre » doit être fondé. Dans un
        arbre de tiers, le même cas est **tracé** et compté.
        """
        try:
            chemin = _validate_relative_path(relative)
        except ScanError:
            if perimetre is Perimetre.STRICT:
                raise
            self._non_analyses += 1
            self._tracer(_MOT_NON_ANALYSE, relative)
            return []
        try:
            texte = self._read_text(path)
        except _RefusInterne:
            if perimetre is Perimetre.STRICT:
                raise ScanError(_SCAN_ERROR) from None
            self._non_analyses += 1
            self._tracer(_MOT_NON_ANALYSE, relative)
            return []
        if texte is None:
            # Binaire connu : ignoré par politique, mais **tracé** — un dépôt
            # propre et un dépôt dont un binaire n'a pas été lu ne doivent
            # jamais être confondus.
            self._binaires += 1
            self._tracer(_MOT_BINAIRE, relative)
            return []
        return self._scan_text(texte, chemin)

    def _read_text(self, path: Path) -> str | None:
        """Lit un fichier borné ; ``None`` signifie « binaire connu ».

        Lève ``_RefusInterne`` si le fichier n'a pas pu être analysé et
        ``ScanError`` si le chemin sort de la racine (rupture de
        confinement : ce n'est pas un simple fichier illisible).
        """
        try:
            resolved = path.resolve(strict=True)
        except (OSError, RuntimeError):
            raise _RefusInterne from None
        if not resolved.is_relative_to(self._root):
            raise ScanError(_SCAN_ERROR) from None
        try:
            before = os.stat(path, follow_symlinks=False)
        except OSError:
            raise _RefusInterne from None
        if not stat.S_ISREG(before.st_mode):
            raise _RefusInterne from None
        try:
            descriptor = os.open(path, _open_flags())
        except OSError:
            raise _RefusInterne from None
        try:
            data = self._lire_borne(descriptor, before)
        finally:
            os.close(descriptor)
        try:
            return decode_text(data)
        except ScanError:
            # Contenu ambigu (NUL non décodable, BOM invalide) : le fichier
            # n'est pas analysable. L'appelant décide si c'est fatal.
            raise _RefusInterne from None

    def _lire_borne(self, descriptor: int, before: os.stat_result) -> bytes:
        """Lit le descripteur et vérifie que le fichier n'a pas changé.

        Trois comparaisons, toutes nécessaires :

        - l'identité (``dev``/``ino``) : le descripteur doit désigner le
          même fichier que le ``stat`` ;
        - l'état **avant** (``stat``) contre l'état **après ouverture**
          (``fstat``) : un fichier tronqué ou réécrit entre les deux
          appels donnerait un ``after`` plus petit que le contenu lu, et
          le scan porterait sur un **préfixe** — un verdict « propre »
          partiel, obtenu sans le moindre secret détecté ;
        - l'état après lecture contre l'état à l'ouverture : le fichier
          ne doit pas avoir changé pendant la lecture.

        La taille et la date de modification (en nanosecondes) sont
        comparées à chaque fois : un fichier remplacé ou modifié pendant
        le scan n'est pas analysable (fail-closed).
        """
        try:
            after = os.fstat(descriptor)
            if not stat.S_ISREG(after.st_mode) or after.st_size > MAX_FILE_BYTES:
                raise _RefusInterne from None
            if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
                raise _RefusInterne from None
            # Troncature (ou réécriture) entre le `stat` et l'`open` : la
            # lecture ne porterait que sur un préfixe du fichier, et le
            # secret placé dans la partie tronquée disparaîtrait du scan.
            if before.st_size != after.st_size or before.st_mtime_ns != after.st_mtime_ns:
                raise _RefusInterne from None
            chunks: list[bytes] = []
            remaining = MAX_FILE_BYTES + 1
            while remaining > 0:
                chunk = os.read(descriptor, min(_READ_CHUNK, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            data = b"".join(chunks)
            final = os.fstat(descriptor)
            unchanged = (
                final.st_size == after.st_size
                and final.st_mtime_ns == after.st_mtime_ns
                and len(data) == after.st_size
            )
            if not unchanged or len(data) > MAX_FILE_BYTES:
                raise _RefusInterne from None
        except OSError:
            raise _RefusInterne from None
        return data

    def _scan_text(self, text: str, relative: str) -> list[Finding]:
        """Analyse un fichier déjà lu et borné, via la façade #53."""
        cible = FileTarget(path=relative, text=text)
        return self._moteur.scan(cible)

    def _tracer(self, motif: str, chemin: str) -> None:
        """Journalise ce qui n'a pas été analysé (chemin seul, sans contenu)."""
        self._journal(f"{_TRACE_PREFIX} {motif} : {_safe_path(chemin)}")


def scan(
    root: str | os.PathLike[str],
    *,
    hasher: SnippetHasher | None = None,
    journal: Callable[[str], None] | None = None,
) -> list[Finding]:
    """Analyse ``root`` et retourne des objets :class:`Finding`.

    **Fail-closed** : ``ScanError`` dès qu'un fichier du périmètre n'a pas
    pu être analysé. Un scan incomplet ne devient jamais une liste vide
    ou partielle.

    ⚠️ Une liste vide n'est **pas** la preuve d'un dépôt propre : des
    contenus peuvent avoir été laissés de côté (binaire, lien symbolique,
    base VCS). Un avertissement ``ScanIncomplet`` est alors émis. Pour un
    usage hook/CI, consommer ``scan_complet()`` : il **refuse** (code 2
    attendu) tout rapport incomplet.
    """
    return ScannerRacine(root, hasher=hasher, journal=journal).scan()


def scan_rapport(
    root: str | os.PathLike[str],
    *,
    hasher: SnippetHasher | None = None,
    journal: Callable[[str], None] | None = None,
) -> RapportScan:
    """Analyse ``root`` et retourne le bilan complet (Findings + compteurs).

    Un verdict « propre » n'est fondé que si ``RapportScan.complet`` est
    vrai — c'est-à-dire si **rien** n'a été laissé de côté (binaire, lien,
    base VCS, fichier illisible). Le bilan est donc à contrôler par
    l'appelant : ``exiger_complet()`` (ou ``scan_complet()``) le fait à sa
    place.
    """
    return ScannerRacine(root, hasher=hasher, journal=journal).analyser()


def scan_complet(
    root: str | os.PathLike[str],
    *,
    hasher: SnippetHasher | None = None,
    journal: Callable[[str], None] | None = None,
) -> RapportScan:
    """Analyse ``root`` et rend un bilan **seulement s'il est complet**.

    API stricte, destinée au hook et à la CI : si un contenu n'a pas pu
    être lu (binaire, lien symbolique, base VCS, fichier illisible), le
    scan **refuse** par ``ScanError`` (message statique) au lieu de rendre
    un bilan partiel qu'un appelant confondrait avec un dépôt propre.

    Le refus est l'erreur d'outillage attendue par la CLI : code 2, jamais
    0 ni 1. Un dépôt réellement propre rend un rapport complet et vide.
    """
    return ScannerRacine(root, hasher=hasher, journal=journal).analyser_complet()


def find_candidates(path: str) -> list[dict[str, object]]:
    """Repère les candidats secrets sous ``path`` (dépôt ou fichier).

    Retourne des dictionnaires conformes au contrat Finding v1 (#14). Lève
    ``ScanError`` dès qu'un fichier du périmètre ne peut pas être analysé :
    un scan incomplet ne devient jamais une liste vide ou partielle.

    ⚠️ Cette fonction **ne dit pas** ce qui a été laissé de côté : une
    liste vide n'est pas la preuve d'un dépôt propre (un avertissement
    ``ScanIncomplet`` est émis dans ce cas). Pour un verdict « propre »
    **fondé**, consommer ``scan_complet()`` (qui refuse un rapport
    incomplet) ou ``scan_rapport()`` avec ``RapportScan.complet``.
    """
    return [finding.as_dict() for finding in scan(path)]
