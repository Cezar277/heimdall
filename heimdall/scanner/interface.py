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

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Protocol

from heimdall.scanner.errors import InvalidTarget, ScanError
from heimdall.scanner.finding import (
    SCANNER_SOURCES,
    Finding,
    validate_relative_path,
)


def _check_path(value: object) -> None:
    """Refuse un chemin qui n'est pas relatif au dépôt (contrat #14)."""
    try:
        validate_relative_path(value)
    except ValueError:
        raise InvalidTarget("cible d'analyse non conforme : chemin relatif") from None


@dataclass(frozen=True, slots=True)
class DiffTarget:
    """Les lignes ajoutées du diff indexé, avec leur numéro de ligne réel.

    ``lines`` est une suite de couples ``(numéro, texte)`` : le numéro est la
    position de la ligne **dans le fichier**, pas sa position dans le diff.
    Les numéros sont strictement croissants (le parseur de diff du MCP
    produit cette forme : ``DiffEntry.lines``).
    """

    path: str
    lines: tuple[tuple[int, str], ...]

    def __post_init__(self) -> None:
        _check_path(self.path)
        previous = 0
        for number, text in self.lines:
            if type(number) is not int or number < 1:
                raise InvalidTarget("cible d'analyse non conforme : numéro de ligne")
            if number <= previous:
                raise InvalidTarget("cible d'analyse non conforme : lignes désordonnées")
            if not isinstance(text, str):
                raise InvalidTarget("cible d'analyse non conforme : texte de ligne")
            previous = number

    def lignes(self) -> tuple[tuple[int, str], ...]:
        """Les lignes à analyser, numérotées comme dans le fichier."""
        return self.lines


@dataclass(frozen=True, slots=True)
class FileTarget:
    """Un fichier entier (démarrage à froid : premier scan du dépôt)."""

    path: str
    text: str

    def __post_init__(self) -> None:
        _check_path(self.path)
        if not isinstance(self.text, str):
            raise InvalidTarget("cible d'analyse non conforme : contenu")

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
        raise ScanError("sortie scanner non conforme au contrat Finding v1")
    if finding.file != cible.path:
        raise ScanError("sortie scanner non conforme au contrat Finding v1")
    if finding.status != "detecte" or finding.source not in SCANNER_SOURCES:
        raise ScanError("sortie scanner non conforme au contrat Finding v1")


class Scanner:
    """Façade contractuelle du scanner déterministe (#53).

    Elle n'implémente **aucune** détection : elle délègue au moteur injecté
    et garantit la sortie. Un Finding rendu par le moteur est conforme au
    contrat #14 *par construction* ; la façade refuse en plus toute sortie
    qui ne serait pas attachée à la cible analysée, dans l'état ``detecte``,
    avec une origine déterministe.

    Refuser est fail-closed : une sortie non conforme est une **erreur**, pas
    une liste partielle présentée comme complète.
    """

    __slots__ = ("_moteur",)

    def __init__(self, moteur: Moteur) -> None:
        self._moteur = moteur

    def scan(self, cible: ScanTarget) -> list[Finding]:
        """Analyse une cible et rend ses Findings, triés de façon stable.

        L'ordre de tri est ``(ligne, type, empreinte)`` : deux scans de la
        même cible rendent la même liste, dans le même ordre.
        """
        findings = list(self._moteur.analyser(cible))
        for finding in findings:
            _check_finding(finding, cible)
        findings.sort(key=lambda item: (item.line, item.type, item.snippet_hash))
        return findings

    def scan_all(self, cibles: Iterable[ScanTarget]) -> list[Finding]:
        """Analyse plusieurs cibles et rend tous les Findings, triés par fichier."""
        findings: list[Finding] = []
        for cible in cibles:
            findings.extend(self.scan(cible))
        findings.sort(key=lambda item: (item.file, item.line, item.type, item.snippet_hash))
        return findings
