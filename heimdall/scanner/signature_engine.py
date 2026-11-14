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

import time
from typing import Final

from heimdall.scanner.allowlist import Allowlist, AllowlistTrace
from heimdall.scanner.entropy import shannon_entropy
from heimdall.scanner.entropy_detection import (
    DEFAULT_ENTROPY_CONFIG,
    EntropyConfig,
    check_multiline_overflow,
    find_line_matches,
)
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
#: Refus statique d'un plafond explicite hors contrat (0, négatif, géant).
_MAX_FINDINGS_INVALID: Final[str] = "plafond de findings hors contrat"
#: Refus statique de l'échéance dépassée (même libellé que les autres refus).
_DEADLINE_ERROR: Final[str] = "scan impossible : entrée non analysable"


class SignatureEngine:
    """Moteur déterministe : signatures du registre, puis Finding v1.

    La clé HMAC est chargée **paresseusement** au premier scan : instancier le
    moteur ne crée aucun fichier et ne touche pas au stockage local.

    ``max_findings`` borne le nombre de Findings rendus (**par candidat**,
    dans ``_append``) : au-delà, ``ScanError``. Le défaut est le plafond
    partagé (:data:`MAX_FINDINGS`) : un appelant qui analyserait un blob
    dense sans le renseigner reste fail-closed au lieu d'accumuler sans
    borne (#29). ``None`` explicite retombe sur ce même défaut borné — il
    n'existe **aucun** opt-out non borné, comme pour ``Scanner``. Un
    ``max_findings`` explicite doit rester dans ``1..MAX_FINDINGS`` : un
    entier géant ne peut pas relever la borne (``ValueError``). La CLI
    ``--staged`` renseigne explicitement sa propre constante (même valeur,
    knob documenté côté CLI).

    ``deadline`` (``time.monotonic()``, optionnelle) borne la durée de la
    passe **à l'intérieur** d'une cible : vérifiée toutes les 256 lignes et
    tous les 256 Findings, comme ``Scanner._scan_text`` en arbre. Sans elle,
    un blob d'1 Mio de lignes vides coûte ~10 s de moteur, et la deadline
    ``--staged`` ne serait vue qu'entre blobs. Au-delà : ``ScanError``. Un
    moteur construit pour une passe ne se réutilise pas après son échéance.
    """

    __slots__ = (
        "_allowlist",
        "_deadline",
        "_entropy_config",
        "_hasher",
        "_max_findings",
        "_traces",
    )

    def __init__(
        self,
        hasher: SnippetHasher | None = None,
        entropy_config: EntropyConfig = DEFAULT_ENTROPY_CONFIG,
        *,
        max_findings: int | None = None,
        deadline: float | None = None,
        allowlist: Allowlist | None = None,
    ) -> None:
        self._deadline = deadline
        if not isinstance(entropy_config, EntropyConfig):
            raise ValueError("configuration d'entropie invalide")
        self._entropy_config = entropy_config
        self._hasher = hasher
        self._allowlist = allowlist
        self._traces: list[AllowlistTrace] = []
        # `None` ne doit jamais désactiver la borne : on retombe sur le
        # défaut, y compris pour un appelant non typé qui passerait `None`
        # en croyant conserver l'ancien mode non borné. Un entier explicite
        # ne peut pas non plus relever le plafond (même refus loud que la
        # couche scanner).
        if max_findings is None:
            max_findings = MAX_FINDINGS
        if (
            isinstance(max_findings, bool)
            or not isinstance(max_findings, int)
            or not 1 <= max_findings <= MAX_FINDINGS
        ):
            raise ValueError(_MAX_FINDINGS_INVALID)
        self._max_findings = max_findings

    @property
    def traces(self) -> tuple[AllowlistTrace, ...]:
        """Traces déterministes des rejets par l'allowlist (#24)."""
        return tuple(self._traces)

    def analyser(self, cible: ScanTarget) -> list[Finding]:
        """Analyse la cible et rend un Finding par candidat distinct."""
        findings: list[Finding] = []
        # Clé de déduplication : (ligne, type, **empreinte**). La valeur
        # brute n'y entre jamais : elle est hachée à la volée puis oubliée.
        seen: set[tuple[int, str, str]] = set()
        lines = cible.lignes()
        preceding: tuple[SignatureMatch, ...] = ()
        for index, (line_number, line) in enumerate(lines):
            # Contrôle périodique intra-cible (cf. `deadline`) : sans lui, la
            # deadline `--staged` n'est vue qu'après la fin du blob.
            if (
                index % 256 == 0
                and self._deadline is not None
                and time.monotonic() > self._deadline
            ):
                raise ScanError(_DEADLINE_ERROR)
            following = self._joined_window(line, lines, index)
            current_window = () if following is None else tuple(
                match for match in find_signature_matches(following[0])
                if match.start < following[1] and match.context_end <= following[1]
            )
            for match in find_line_matches(
                line, self._entropy_config, preceding + current_window, deadline=self._deadline
            ):
                self._append(findings, seen, match, line_number, cible.path)
            preceding = current_window
            for match in preceding:
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
            check_multiline_overflow(line, following, self._entropy_config, deadline=self._deadline)
            return None
        # Le nombre de caractères minore le nombre d'octets UTF-8 : le premier
        # contrôle évite d'encoder les lignes déjà trop longues.
        if not joined.isascii() and len(joined.encode("utf-8")) > MULTILINE_WINDOW:
            check_multiline_overflow(line, following, self._entropy_config, deadline=self._deadline)
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
        # Un blob dense peut porter des milliers de candidats : la deadline est
        # revue aussi tous les 256 Findings, avant le hachage HMAC.
        if (
            self._deadline is not None
            and len(findings) % 256 == 0
            and time.monotonic() > self._deadline
        ):
            raise ScanError(_DEADLINE_ERROR)
        snippet_hash = self._get_hasher().hash(match.value)
        key = (line_number, match.secret_type, snippet_hash)
        if key in seen:
            return
        seen.add(key)

        # Allowlist déterministe (#24) : écarte les cas évidents sans passer
        # par le LLM. Chaque rejet émet une trace traçable (règle, fichier, ligne).
        if self._allowlist is not None and not self._allowlist.is_empty():
            rule_name = self._allowlist.evaluate(
                value=match.value,
                file=relative_path,
                line=line_number,
                secret_type=match.secret_type,
            )
            if rule_name is not None:
                self._traces.append(
                    AllowlistTrace(rule=rule_name, file=relative_path, line=line_number)
                )
                return

        findings.append(
            Finding(
                file=relative_path,
                line=line_number,
                type=match.secret_type,
                entropy=round(shannon_entropy(match.value.encode("utf-8")), 4),
                snippet_hash=snippet_hash,
                source=match.source,
            )
        )
        if len(findings) > self._max_findings:
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
