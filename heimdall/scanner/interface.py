"""Interface du scanner déterministe : cible d'analyse et sortie (#53).

Le scanner est le seul composant qui décide qu'un candidat est un secret. Sa
surface est volontairement étroite : **une** méthode ``scan(cible) ->
list[Finding]`` et deux formes de cible.

- ``DiffTarget`` : les lignes **ajoutées** du diff indexé, avec le numéro de
  ligne réel de chaque ligne dans le fichier (côté « nouveau » du diff). C'est
  le flux nominal : on ne relit que ce que le commit ajoute.
- ``FileTarget`` : un fichier entier. C'est le démarrage à froid : au premier
  lancement, tout le dépôt est passé fichier par fichier.

Le moteur de détection (signatures, entropie) est **injecté** : il reste la
responsabilité des tickets #54 et #59, et cette interface n'en dépend pas.
Le scanner n'a aucun accès réseau, aucun LLM et aucune crypto : il rend des
Findings, pas des verdicts sur un secret.
"""

from __future__ import annotations

import os
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final, Protocol, TypeVar, cast

from heimdall.scanner.errors import InvalidTarget, ScanError
from heimdall.scanner.finding import (
    SCANNER_SOURCES,
    Finding,
    validate_relative_path,
)

#: Message statique : le scan est impossible (invariant 8).
_MSG_SCAN_IMPOSSIBLE: Final[str] = "scan impossible : entrée non analysable"


def _open_flags() -> int:
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
    pour le fichier unique. Un chemin non analysable (octet NUL, type
    inattendu, racine absente) est refusé en ``ScanError`` statique, jamais
    en ``ValueError``/``TypeError`` brut (contrat d'erreur unique).
    """
    try:
        absolute = Path(os.path.abspath(Path(root).expanduser()))
        for candidate in (absolute, *absolute.parents):
            if candidate.is_symlink():
                raise ScanError(_MSG_SCAN_IMPOSSIBLE)
        resolved = absolute.resolve(strict=True)
        # Course symlink (check-then-resolve) : si un composant a été remplacé
        # entre le `lstat` et le `resolve`, le résolu diffère du demandé et la
        # racine serait détournée hors périmètre — refus au lieu de suivre.
        if resolved != absolute:
            raise ScanError(_MSG_SCAN_IMPOSSIBLE)
        return resolved
    except (OSError, RuntimeError, ValueError, TypeError):
        raise ScanError(_MSG_SCAN_IMPOSSIBLE) from None

#: Nombre de parties d'une ligne ajoutée : ``(numéro, texte)``.
_LINE_PARTS: Final[int] = 2

#: Message statique : le moteur injecté a levé une exception (invariant 8 :
#: ni le message du moteur, ni ``str(e)`` ne sont jamais reflétés).
_MSG_ENGINE_FAILURE: Final[str] = "moteur de détection en échec"
#: Message statique : la sortie du moteur n'est pas conforme au contrat.
_MSG_BAD_OUTPUT: Final[str] = "sortie scanner non conforme au contrat Finding v1"
#: Message statique : la suite de cibles n'est pas exploitable.
_MSG_BAD_TARGETS: Final[str] = "cible d'analyse non conforme : liste de cibles"

_T = TypeVar("_T")


def _guard_call(action: Callable[[], _T], message: str) -> _T:
    """Exécute ``action`` et convertit toute exception en ``ScanError``.

    Le contrat d'erreur de la façade est **unique** : une exception levée
    par le moteur (ou pendant la consommation de son rendu) ne doit jamais
    atteindre l'appelant, qui ne sait catcher que ``ScanError`` /
    ``InvalidFinding`` / ``InvalidTarget``.

    Le message de l'erreur est **statique** : ni le message de l'exception
    d'origine, ni son type ne sont reflétés (invariant 8). L'erreur est
    relancée **hors** du bloc ``except`` : ``__context__`` reste vide, donc
    même une inspection de la traceback ne ressuscite pas le message du
    moteur. Une ``ScanError`` déjà typée est laissée telle quelle.
    """
    echec = False
    resultat: _T | None = None
    try:
        resultat = action()
    except ScanError:
        raise
    except Exception:
        echec = True
    if echec:
        raise ScanError(message) from None
    return cast(_T, resultat)


def _check_path(value: object) -> None:
    """Refuse un chemin qui n'est pas relatif au dépôt (contrat #14).

    Garde lexicale seule (délègue à ``validate_relative_path``), sans I/O :
    insuffisante contre les liens symboliques sortants et les TOCTOU
    (invariant 3). Le consommateur qui ouvre le fichier DOIT résoudre avec
    une racine fixée au démarrage (``resolve()`` + ``is_relative_to()``,
    voir ``heimdall.mcp.paths.confine``) — exigible côté moteur #54/#59
    et ``heimdall/mcp/gitdiff.py``.
    """
    try:
        validate_relative_path(value)
    except ValueError:
        raise InvalidTarget("cible d'analyse non conforme : chemin relatif") from None


def _check_lines(lines: object) -> tuple[tuple[int, str], ...]:
    """Valide et normalise les lignes ajoutées d'une cible.

    La cible vient d'un parseur de diff ou d'un appelant non fiable : toute
    forme inattendue est refusée par ``InvalidTarget``, et **jamais** par un
    ``TypeError`` ou un ``ValueError`` brut que l'appelant (CLI, Vault) ne
    catcherait pas. Le résultat est normalisé en couples ``(int, str)``.
    """
    if not isinstance(lines, (tuple, list)):
        raise InvalidTarget("cible d'analyse non conforme : lignes")
    entries = tuple(lines)
    normalisees: list[tuple[int, str]] = []
    previous = 0
    for entry in entries:
        if not isinstance(entry, (tuple, list)) or len(entry) != _LINE_PARTS:
            raise InvalidTarget("cible d'analyse non conforme : ligne")
        number, text = entry
        # `type(...) is not int` refuse aussi les booléens : `True` vaut 1 en
        # Python, alors que le schéma distingue le booléen de l'entier.
        if type(number) is not int or number < 1:
            raise InvalidTarget("cible d'analyse non conforme : numéro de ligne")
        if number <= previous:
            raise InvalidTarget("cible d'analyse non conforme : lignes désordonnées")
        if not isinstance(text, str):
            raise InvalidTarget("cible d'analyse non conforme : texte de ligne")
        previous = number
        normalisees.append((number, text))
    return tuple(normalisees)


@dataclass(frozen=True, slots=True)
class DiffTarget:
    """Les lignes ajoutées du diff indexé, avec leur numéro de ligne réel.

    ``lines`` est une suite de couples ``(numéro, texte)`` : le numéro est la
    position de la ligne **dans le fichier**, pas sa position dans le diff.
    Les numéros sont strictement croissants (le parseur de diff du MCP
    produit cette forme : ``DiffEntry.lines``).

    **Le contenu n'apparaît jamais dans le ``repr``** : ces lignes sont
    précisément là où vivent les secrets, et un ``log.debug("%r", cible)`` ou
    une traceback les écrirait en clair (invariant 8). Le ``repr`` résumé ne
    montre que le chemin et le nombre de lignes.
    """

    path: str
    lines: tuple[tuple[int, str], ...] = field(repr=False)

    def __post_init__(self) -> None:
        _check_path(self.path)
        entries = _check_lines(self.lines)
        # Normalisation : `lines` est désormais un tuple de couples (int, str),
        # quoi que l'appelant ait fourni.
        object.__setattr__(self, "lines", entries)

    def __repr__(self) -> str:
        """Résumé sans le contenu des lignes (jamais de secret en clair)."""
        return f"DiffTarget(path={self.path!r}, lignes={len(self.lines)})"

    def lignes(self) -> tuple[tuple[int, str], ...]:
        """Les lignes à analyser, numérotées comme dans le fichier."""
        return self.lines


@dataclass(frozen=True, slots=True)
class FileTarget:
    """Un fichier entier (démarrage à froid : premier scan du dépôt).

    **Le contenu n'apparaît jamais dans le ``repr``** : c'est le fichier
    entier, secrets compris ; seul le chemin et la taille sont affichés
    (invariant 8).
    """

    path: str
    text: str = field(repr=False)

    def __post_init__(self) -> None:
        _check_path(self.path)
        if not isinstance(self.text, str):
            raise InvalidTarget("cible d'analyse non conforme : contenu")

    def __repr__(self) -> str:
        """Résumé sans le contenu du fichier (jamais de secret en clair)."""
        return f"FileTarget(path={self.path!r}, caracteres={len(self.text)})"

    def lignes(self) -> tuple[tuple[int, str], ...]:
        """Les lignes à analyser, numérotées à partir de 1."""
        return tuple(enumerate(self.text.splitlines(), start=1))


#: Les deux cibles acceptées par le scanner.
ScanTarget = DiffTarget | FileTarget


class Moteur(Protocol):
    """Moteur de détection injecté dans le scanner (signatures #54, entropie #59).

    Le moteur analyse une cible et rend des Findings. Il ne rend **jamais** la
    valeur brute du candidat : le scanner ne manipule que des empreintes.
    """

    def analyser(self, cible: ScanTarget) -> list[Finding]:
        """Analyse la cible et rend les Findings détectés."""
        ...


def _check_finding(finding: object, cible: ScanTarget) -> None:
    """Garantit qu'un Finding rendu par le moteur tient le contrat #14.

    Trois invariants, tous vérifiés ici : l'objet est un ``Finding``, il porte
    le chemin de la cible, il est dans l'état initial ``detecte`` et son
    origine est déterministe (``regex`` ou ``entropy``).
    Un LLM ne change pas l'état d'un Finding : le trieur travaille sur une
    copie et rend son avis à l'humain, jamais dans le Finding lui-même.
    """
    if not isinstance(finding, Finding):
        raise ScanError(_MSG_BAD_OUTPUT)
    if finding.file != cible.path:
        raise ScanError(_MSG_BAD_OUTPUT)
    if finding.status != "detecte" or finding.source not in SCANNER_SOURCES:
        raise ScanError(_MSG_BAD_OUTPUT)


def _valider_et_trier(findings: list[Finding], cible: ScanTarget) -> None:
    """Vérifie chaque Finding rendu par le moteur, puis trie la liste.

    Le tri est stable et déterministe : ``(ligne, type, empreinte)``.
    """
    for finding in findings:
        _check_finding(finding, cible)
    findings.sort(key=lambda item: (item.line, item.type, item.snippet_hash))


class Scanner:
    """Façade contractuelle du scanner déterministe (#53).

    Elle n'implémente **aucune** détection : elle délègue au moteur injecté
    et garantit la sortie. Un Finding rendu par le moteur est conforme au
    contrat #14 *par construction* ; la façade refuse en plus toute sortie
    qui ne serait pas attachée à la cible analysée, dans l'état ``detecte``,
    avec une origine déterministe.

    Refuser est fail-closed : une sortie non conforme est une **erreur**, pas
    une liste partielle présentée comme complète.

    **Un seul type d'erreur sort de la façade** : ``ScanError`` (dont
    ``InvalidTarget`` hérite) pour la cible, le moteur et la sortie. Aucune
    ``TypeError`` ni ``AttributeError`` brute ne doit atteindre l'appelant : la
    cible et le moteur viennent d'autres composants (parseur MCP, CLI), donc
    d'une frontière non fiable.

    Cela vaut aussi pour les **exceptions levées par le moteur lui-même** :
    une panne du moteur, un rendu non conforme ou une itération qui échoue
    remontent en ``ScanError``, avec un message **statique** — ni le message
    du moteur, ni une valeur candidate, ne sont jamais reflétés (invariant 8).
    """

    __slots__ = ("_moteur",)

    def __init__(self, moteur: Moteur) -> None:
        echec = False
        analyser: object = None
        try:
            analyser = getattr(moteur, "analyser", None)
        except Exception:
            echec = True
        if echec or not callable(analyser):
            raise ScanError("moteur de détection invalide") from None
        self._moteur = moteur

    def scan(self, cible: ScanTarget) -> list[Finding]:
        """Analyse une cible et rend ses Findings, triés de façon stable.

        L'ordre de tri est ``(ligne, type, empreinte)`` : deux scans de la
        même cible rendent la même liste, dans le même ordre.

        **Toute exception du moteur est convertie en ``ScanError``** : le
        contrat d'erreur est unique, et le message de l'exception du moteur
        (qui pourrait contenir un extrait de secret ou un chemin) n'est
        jamais reflété (invariant 8).
        """
        if not isinstance(cible, (DiffTarget, FileTarget)):
            raise InvalidTarget("cible d'analyse non conforme : type")
        resultat = _guard_call(lambda: self._moteur.analyser(cible), _MSG_ENGINE_FAILURE)
        if resultat is None:
            raise ScanError(_MSG_BAD_OUTPUT)
        # Rendu non itérable **ou** générateur qui lève à la consommation :
        # la sortie ne peut pas être vérifiée, donc elle est refusée.
        findings = _guard_call(lambda: list(resultat), _MSG_BAD_OUTPUT)
        _guard_call(lambda: _valider_et_trier(findings, cible), _MSG_BAD_OUTPUT)
        return findings

    def scan_all(self, cibles: Iterable[ScanTarget]) -> list[Finding]:
        """Analyse plusieurs cibles et rend tous les Findings, triés par fichier.

        La matérialisation de ``cibles`` est protégée : un générateur qui
        lève en cours d'itération est une ``ScanError``, jamais une exception
        brute que l'appelant (CLI, Vault) ne catcherait pas.
        """
        iterables = _guard_call(lambda: list(cibles), _MSG_BAD_TARGETS)
        findings: list[Finding] = []
        for cible in iterables:
            findings.extend(self.scan(cible))
        findings.sort(key=lambda item: (item.file, item.line, item.type, item.snippet_hash))
        return findings
