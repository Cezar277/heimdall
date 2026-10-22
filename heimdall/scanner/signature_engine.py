"""Moteur de détection par signatures (#54), branché sur l'interface #53.

Le moteur ne lit **aucun fichier** : il reçoit une ``DiffTarget`` (lignes
ajoutées d'un diff) ou une ``FileTarget`` (fichier entier) déjà validée par
l'interface. Le parcours du dépôt et les exclusions appartiennent à #59.

Invariants :

- la valeur candidate n'est jamais rendue : le Finding ne porte qu'une
  empreinte HMAC-SHA-256 et l'entropie ;
- la valeur candidate n'est **pas conservée** au-delà de son hachage : la
  déduplication porte sur l'empreinte, pas sur la valeur brute ;
- une même valeur identique n'est produite qu'une fois par ligne, mais deux
  valeurs distinctes du même type restent deux Findings ;
- la jointure de deux lignes pour un secret coupé est **bornée** à 4 Kio
  (4096 octets UTF-8) et n'a lieu qu'entre lignes **contiguës** ;
- les regex du registre sont linéaires et bornées (anti-ReDoS).
"""

from __future__ import annotations

from typing import Final

from heimdall.scanner.entropy import shannon_entropy
from heimdall.scanner.errors import ScanError
from heimdall.scanner.finding import Finding
from heimdall.scanner.hashing import SnippetHasher
from heimdall.scanner.interface import ScanTarget
from heimdall.scanner.signatures import SignatureMatch, find_signature_matches

#: Fenêtre maximale de jointure de deux lignes, en **octets UTF-8** (4 Kio).
MULTILINE_WINDOW: Final[int] = 4096

#: Plafond du nombre de Findings rendus en une passe (#29). Les bornes
#: d'entrée ne suffisent pas : un dépôt adverse dense en candidats (un millier
#: de blobs bourrés de matches) ferait gonfler la liste et le tri final en
#: mémoire et en temps CI. Au-delà, le scan est **refusé** (``ScanError``),
#: jamais tronqué : un rapport partiel présenté comme complet serait un
#: faux « propre ». 10 000 Findings sont déjà inexploitables par un humain
#: comme par un journal CI : le refus force le triage, pas le silence.
#: Source unique : ``heimdall.scanner.detect`` la réexporte (compatibilité
#: des appelants qui patchent `detect.MAX_FINDINGS`).
MAX_FINDINGS: Final[int] = 10_000

#: Refus statique du plafond Findings : même libellé que le scanner
#: bibliothèque (`detect.py`), invariant 8 (aucune entrée reflétée).
_MAX_FINDINGS_ERROR: Final[str] = "scan impossible : entrée non analysable"


class SignatureEngine:
    """Moteur déterministe : signatures du registre, puis Finding v1.

    La clé HMAC est chargée **paresseusement** au premier scan : instancier le
    moteur ne crée aucun fichier et ne touche pas au stockage local.

    ``max_findings`` borne le nombre de Findings rendus (**par candidat**,
    dans ``_append``) : au-delà, ``ScanError``. Le défaut est le plafond
    partagé (:data:`MAX_FINDINGS`) : un appelant qui analyserait un blob
    dense sans le renseigner reste fail-closed au lieu d'accumuler sans
    borne (#29). La CLI ``--staged`` renseigne explicitement sa propre
    constante (même valeur, knob documenté côté CLI).
    """

    __slots__ = ("_hasher", "_max_findings")

    def __init__(
        self,
        hasher: SnippetHasher | None = None,
        *,
        max_findings: int | None = MAX_FINDINGS,
    ) -> None:
        self._hasher = hasher
        self._max_findings = max_findings

    def analyser(self, cible: ScanTarget) -> list[Finding]:
        """Analyse la cible et rend un Finding par candidat distinct."""
        findings: list[Finding] = []
        # Clé de déduplication : (ligne, type, **empreinte**). La valeur
        # brute n'y entre jamais : elle est hachée à la volée puis oubliée.
        seen: set[tuple[int, str, str]] = set()
        lines = cible.lignes()
        for index, (line_number, line) in enumerate(lines):
            for match in find_signature_matches(line):
                self._append(findings, seen, match, line_number, cible.path)
            following = self._joined_window(line, lines, index)
            if following is None:
                continue
            joined, limit = following
            for match in find_signature_matches(joined):
                # Une correspondance qui commence après la jonction appartient
                # à la ligne suivante : elle y sera déjà signalée.
                if match.start >= limit:
                    continue
                self._append(findings, seen, match, line_number, cible.path)
        return findings

    def _joined_window(
        self,
        line: str,
        lines: tuple[tuple[int, str], ...],
        index: int,
    ) -> tuple[str, int] | None:
        """Jointure bornée de deux lignes **contiguës**, pour un secret coupé.

        ``DiffTarget`` ne contient que les lignes *ajoutées* du diff : deux
        entrées voisines de la liste peuvent porter des numéros distants
        (12 puis 15). Les joindre fabriquerait une chaîne qui n'existe dans
        aucun fichier et attribuerait le Finding à la mauvaise ligne. La
        jointure exige donc ``numéro_suivant == numéro_courant + 1``.

        La borne est mesurée en octets UTF-8, conformément à la fenêtre de
        4 Kio documentée.
        """
        if index + 1 >= len(lines):
            return None
        current_number, _current = lines[index]
        following_number, following = lines[index + 1]
        if following_number != current_number + 1:
            return None
        joined = line + following
        if len(joined) > MULTILINE_WINDOW:
            return None
        # Le nombre de caractères minore le nombre d'octets UTF-8 : le premier
        # contrôle évite d'encoder les lignes déjà trop longues.
        if not joined.isascii() and len(joined.encode("utf-8")) > MULTILINE_WINDOW:
            return None
        return joined, len(line)

    def _append(
        self,
        findings: list[Finding],
        seen: set[tuple[int, str, str]],
        match: SignatureMatch,
        line_number: int,
        relative_path: str,
    ) -> None:
        # La valeur brute n'est **jamais conservée** : elle est hachée à la
        # volée, puis abandonnée. La clé de déduplication porte l'empreinte
        # HMAC-SHA-256, pas la valeur : deux valeurs distinctes ont deux
        # empreintes distinctes (la collision est infaisable en pratique),
        # donc la déduplication est inchangée — mais aucun secret en clair
        # ne survit dans l'ensemble `seen` pendant tout le scan.
        snippet_hash = self._get_hasher().hash(match.value)
        key = (line_number, match.secret_type, snippet_hash)
        if key in seen:
            return
        seen.add(key)
        findings.append(
            Finding(
                file=relative_path,
                line=line_number,
                type=match.secret_type,
                entropy=round(shannon_entropy(match.value.encode("utf-8")), 4),
                snippet_hash=snippet_hash,
            )
        )
        if self._max_findings is not None and len(findings) > self._max_findings:
            # Compteur vérifié **par candidat** : un seul blob dense ne fait
            # jamais gonfler la liste avant le refus (#29). `ScanError`
            # traverse la façade `Scanner` tel quel (contrat #53).
            raise ScanError(_MAX_FINDINGS_ERROR)

    def _get_hasher(self) -> SnippetHasher:
        if self._hasher is None:
            self._hasher = SnippetHasher()
        return self._hasher


#: Alias français, pour les appelants qui parlent du « moteur » de #53.
MoteurSignatures = SignatureEngine

__all__ = ["MAX_FINDINGS", "MULTILINE_WINDOW", "MoteurSignatures", "SignatureEngine"]
