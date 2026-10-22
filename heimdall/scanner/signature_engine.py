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
- la jointure de deux ou trois lignes pour un secret coupé est **bornée** à
  4 Kio (4096 octets UTF-8) et n'a lieu qu'entre lignes **contiguës** ;
- les regex du registre sont linéaires et bornées (anti-ReDoS).
"""

from __future__ import annotations

from typing import Final

from heimdall.scanner.entropy import shannon_entropy
from heimdall.scanner.finding import Finding
from heimdall.scanner.hashing import SnippetHasher
from heimdall.scanner.interface import ScanTarget
from heimdall.scanner.signatures import SignatureMatch, find_signature_matches

#: Fenêtre maximale de jointure de lignes, en **octets UTF-8** (4 Kio).
MULTILINE_WINDOW: Final[int] = 4096
#: Nombre de lignes jointes au maximum (la ligne courante comprise).
MULTILINE_LINES: Final[int] = 3
#: Nombre minimal de lignes jointes pour qu'une fenêtre existe.
MULTILINE_MIN_LINES: Final[int] = 2


class SignatureEngine:
    """Moteur déterministe : signatures du registre, puis Finding v1.

    La clé HMAC est chargée **paresseusement** au premier scan : instancier le
    moteur ne crée aucun fichier et ne touche pas au stockage local.
    """

    __slots__ = ("_hasher",)

    def __init__(self, hasher: SnippetHasher | None = None) -> None:
        self._hasher = hasher

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
        """Jointure bornée de deux ou trois lignes **contiguës**.

        Une clé peut être coupée par un retour à la ligne, et même par une
        ligne vide intercalée (``aws_secret_access_key =`` / ligne vide /
        ``"valeur"``). La fenêtre joint donc jusqu'à trois lignes
        consécutives : sans elle, un secret coupé par plus d'un ``\\n``
        disparaissait silencieusement.

        ``DiffTarget`` ne contient que les lignes *ajoutées* du diff : deux
        entrées voisines de la liste peuvent porter des numéros distants
        (12 puis 15). Les joindre fabriquerait une chaîne qui n'existe dans
        aucun fichier et attribuerait le Finding à la mauvaise ligne. La
        jointure exige donc ``numéro_suivant == numéro_courant + 1`` (et
        ``+ 2`` pour la troisième ligne).

        La borne est mesurée en octets UTF-8, conformément à la fenêtre de
        4 Kio documentée. Une ligne qui ferait dépasser la borne est
        **écartée mais pas fatale** : la jointure plus courte reste valable.
        """
        current_number, _current = lines[index]
        joined = ""
        jointes = 0
        for offset in range(MULTILINE_LINES):
            position = index + offset
            if position >= len(lines):
                break
            number, text = lines[position]
            if number != current_number + offset:
                break
            candidate = joined + text
            if len(candidate) > MULTILINE_WINDOW:
                break
            # Le nombre de caractères minore le nombre d'octets UTF-8 : le
            # premier contrôle évite d'encoder les lignes déjà trop longues.
            if not candidate.isascii() and len(candidate.encode("utf-8")) > MULTILINE_WINDOW:
                break
            joined = candidate
            jointes += 1
        if jointes < MULTILINE_MIN_LINES:
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

    def _get_hasher(self) -> SnippetHasher:
        if self._hasher is None:
            self._hasher = SnippetHasher()
        return self._hasher


#: Alias français, pour les appelants qui parlent du « moteur » de #53.
MoteurSignatures = SignatureEngine

__all__ = ["MULTILINE_WINDOW", "MoteurSignatures", "SignatureEngine"]
