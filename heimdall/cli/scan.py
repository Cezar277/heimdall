"""Scan de la CLI ``heimdall scan`` (#29).

Ce module porte la **logique** du scan ; ``heimdall/cli/main.py`` ne fait que
traduire le résultat en code de sortie et en affichage. Il n'écrit **rien
dans le dépôt scanné** : un scan est une lecture, jamais une remédiation
(celle-ci arrive avec #32, et seulement après validation humaine Y/N/E). La
seule écriture possible est la clé d'empreinte locale, hors dépôt
(``$XDG_DATA_HOME/heimdall/snippet-hmac.key``, créée en 0600 au premier
run) ; son indisponibilité est une erreur d'outillage (code 2), jamais un
verdict propre.

Deux périmètres, un seul verdict :

- ``working-tree`` (par défaut) : l'arbre de travail, en **mode strict** —
  seule la base VCS est écartée (métadonnées, pas du contenu) ; ``vendor/``,
  ``node_modules/``, ``third_party/``, les lockfiles et les fichiers de
  contrôle sont parcourus et leur contenu décide, parce qu'un secret y est un
  secret ; un rapport incomplet (binaire, lien, illisible) refuse le verdict ;
- ``staged`` (``--staged``) : les blobs **ajoutés ou modifiés** dans l'index
  git, lus blob par blob, **sans aucune exclusion de chemin**. C'est ce que
  le commit va contenir, donc ce que le hook et la CI doivent juger.

Invariant 8 : **aucun secret n'est jamais affiché**. Un ``Finding`` ne porte
qu'une empreinte HMAC-SHA-256 et une entropie ; la sortie de la CLI ne fait
que relire ces champs. Les messages d'erreur sont **statiques** : ni le
chemin fourni, ni le contenu analysé ne sont reflétés.

Invariant fail-closed (REQ-SEC-07) : une entrée non analysable (racine
absente, blob illisible, index en conflit, fichier modifié pendant la
lecture) est une **erreur** — code 2 — jamais un verdict « propre ». Un
résultat partiel n'est jamais présenté comme complet.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from heimdall.mcp.errors import ToolFailure
from heimdall.mcp.gitdiff import GIT_TIMEOUT_SECONDS, GitAccess
from heimdall.scanner.detect import MAX_FILE_BYTES
from heimdall.scanner.detect import Scanner as TreeScanner
from heimdall.scanner.errors import ScanError
from heimdall.scanner.exclusions import decode_text
from heimdall.scanner.finding import Finding
from heimdall.scanner.hashing import SnippetHasher
from heimdall.scanner.interface import FileTarget
from heimdall.scanner.interface import Scanner as TargetScanner
from heimdall.scanner.signature_engine import SignatureEngine

#: Codes de sortie (invariant 11, REQ-SEC-07).
#: 0 = aucun secret détecté, 1 = secrets détectés, 2 = erreur d'outillage.
EXIT_CLEAN: Final[int] = 0
EXIT_FINDINGS: Final[int] = 1
EXIT_ERROR: Final[int] = 2

#: Périmètre « arbre de travail ».
SCOPE_TREE: Final[str] = "working-tree"
#: Périmètre « index git ».
SCOPE_STAGED: Final[str] = "staged"

#: Version du contrat de sortie JSON (``--json``).
JSON_SCHEMA: Final[str] = "heimdall.scan.v1"

#: Plafond du nombre de blobs indexés analysés en une passe. Au-delà, le
#: scan est **refusé** (code 2) : un résultat tronqué ne vaut pas verdict
#: propre.
MAX_STAGED_FILES: Final[int] = 1000
#: Plafond du volume total de blobs indexés lus (octets).
MAX_STAGED_BYTES: Final[int] = 32 * 1024 * 1024
#: Plafond du nombre de Findings rendus en une passe `--staged`. Les bornes
#: d'entrée ne suffisent pas : un millier de blobs denses en candidats
#: ferait gonfler la liste et le tri final. Au-delà, refus (code 2), jamais
#: un rapport tronqué présenté comme complet (même valeur que le mode arbre).
MAX_STAGED_FINDINGS: Final[int] = 10_000
#: Deadline globale d'une passe `--staged`, en secondes. Les bornes de volume
#: ne bornent pas le nombre d'appels `git cat-file` (deux par blob, 2 000 au
#: plus) ni leur durée cumulée : un index adverse ferait durer la CI sans
#: verdict. Au-delà, refus (code 2). Chaque appel git garde son timeout
#: unitaire (30 s) ; la deadline empêche d'en lancer de nouveaux.
MAX_STAGED_SECONDS: Final[float] = 120.0
#: Deadline globale du mode arbre, en secondes. Les plafonds de volume
#: (50 000 fichiers, 256 Mio) ne bornent pas le temps de regex + HMAC : un
#: dépôt adverse de petits fichiers pourrait faire durer la CI sans verdict.
#: Au-delà, refus (code 2), vérifié entre chaque fichier et avant le rendu.
MAX_TREE_SECONDS: Final[float] = 120.0

#: Messages d'erreur **statiques** (invariant 8 : aucune entrée reflétée).
_MSG_NOT_A_REPO: Final[str] = "scan impossible : entrée non analysable"
_MSG_TOO_MANY_FILES: Final[str] = "scan impossible : entrée non analysable"
_MSG_TOO_LARGE: Final[str] = "scan impossible : entrée non analysable"
_MSG_TOO_MANY_FINDINGS: Final[str] = "scan impossible : entrée non analysable"
_MSG_BLOB_CHANGED: Final[str] = "scan impossible : entrée non analysable"
_MSG_INDEX_CHANGED: Final[str] = "scan impossible : entrée non analysable"
_MSG_ROOT_CHANGED: Final[str] = "scan impossible : entrée non analysable"
_MSG_TIMEOUT: Final[str] = "scan impossible : entrée non analysable"

#: Libellés du périmètre, affichés à l'humain.
_SCOPE_LABELS: Final[dict[str, str]] = {
    SCOPE_TREE: "arbre de travail (base VCS hors périmètre, contenu décide)",
    SCOPE_STAGED: "index git (blobs ajoutés ou modifiés, aucune exclusion de chemin)",
}

#: Rappel du contrat de codes de sortie, affiché à l'humain.
_CODES_LINE: Final[str] = (
    "Codes de sortie : 0 = aucun secret, 1 = secrets détectés, 2 = erreur d'outillage."
)

#: Longueur de l'empreinte affichée à l'humain (le reste est dans le JSON).
_HASH_PREFIX: Final[int] = 12


@dataclass(frozen=True, slots=True)
class ScanReport:
    """Le résultat d'un scan : un périmètre et des Findings.

    Les Findings ne contiennent aucun secret (contrat #14) : les reporter
    tels quels, y compris dans le JSON, ne fuit rien.
    """

    scope: str
    findings: tuple[Finding, ...]


def collect(root: Path, *, staged: bool) -> ScanReport:
    """Analyse ``root`` et rend ses Findings.

    Lève ``ScanError`` (ou ``ToolFailure``) si le périmètre n'a pas pu être
    analysé **en entier** : l'appelant transforme cela en code 2, jamais en
    code 0.
    """
    if staged:
        return _collect_staged(root)
    return _collect_tree(root)


def _verify_root_unchanged(access: GitAccess, root: Path) -> None:
    """Refuse si la racine a été échangée pendant le scan (TOCTOU).

    `access` fige la racine résolue ET son identité à l'entrée ; une
    reconstruction fraîche refait la garde unique (refus symlink compris).
    Toute différence — chemin résolu différent, identité (`st_dev`,
    `st_ino`) différente — refuse le verdict : un dossier remplacé par un
    autre au même chemin a le même résolu mais pas la même identité. Pur
    `lstat`/`stat`, aucun `git`.
    """
    try:
        current = GitAccess(root)
    except ToolFailure:
        raise ScanError(_MSG_ROOT_CHANGED) from None
    if current.root != access.root or current.root_id != access.root_id:
        raise ScanError(_MSG_ROOT_CHANGED)


def _collect_tree(root: Path) -> ScanReport:
    """Scanne l'arbre de travail, en mode strict (#29).

    Le mode ``strict=True`` écarte seulement la **base VCS** (métadonnées,
    pas du contenu audité) : ``vendor/``, ``node_modules/``, les lockfiles et
    les fichiers de contrôle sont parcourus et leur contenu décide. Un secret
    y est un secret.

    Le verdict « propre » exige un rapport **complet** : un binaire, un lien
    symbolique ou un fichier illisible rend le scan incomplet et la CLI sort
    en 2 (``scan_complet``), jamais en 0. Le périmètre contractuel est la
    **racine d'un dépôt git** : hors dépôt (répertoire quelconque, fichier
    isolé), pas de verdict « propre » mais une erreur — une CI mal configurée
    (mauvais chemin) doit échouer loud, pas rendre 0 en silence. Le scan de
    fichier isolé reste possible en bibliothèque (`Scanner`, #22), hors
    contrat hook/CI.
    """
    deadline = time.monotonic() + MAX_TREE_SECONDS
    access = GitAccess(root)
    if not access.is_repository(timeout=_call_timeout(deadline)):
        raise ScanError(_MSG_NOT_A_REPO)
    # `access.root` est la forme **figée** (résolue, symlink refusé) : le
    # scanner ne re-résout pas l'entrée brute, donc une seule résolution et
    # une seule course possible, alignée sur l'identité épinglée par
    # `GitAccess`. La deadline est vérifiée dans la boucle du scanner.
    # Le hasher est construit **avant** l'analyse : la CLI vérifie ainsi
    # qu'elle peut produire les empreintes HMAC avant d'annoncer un verdict.
    # Une clé indisponible est une erreur d'outillage (2), même sur un dépôt
    # sans candidat — un `0` ne doit pas dépendre d'un stockage non testé.
    findings = TreeScanner(access.root, strict=True, hasher=SnippetHasher()).scan_complet(
        deadline=deadline
    )
    _call_timeout(deadline)
    _verify_root_unchanged(access, root)
    return ScanReport(scope=SCOPE_TREE, findings=tuple(findings))


def _call_timeout(deadline: float) -> float:
    """Timeout à passer au prochain appel git, borné par la deadline globale.

    Le restant de deadline est propagé comme ``timeout``, mais jamais au-delà
    du timeout unitaire : un git bloqué ne peut donc dépasser ni les 30 s
    unitaires ni la deadline (le prochain contrôle refuse). Deadline expirée
    → ``ScanError`` avant de lancer l'appel.
    """
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise ScanError(_MSG_TIMEOUT)
    return min(remaining, GIT_TIMEOUT_SECONDS)


def _collect_staged(root: Path) -> ScanReport:
    """Scanne les blobs **ajoutés ou modifiés** de l'index git.

    Aucune exclusion de chemin : c'est le contenu que le commit va contenir
    qui est jugé, quel que soit son chemin (``vendor/evil.py``,
    ``package-lock.json``…). Un blob binaire connu est ignoré (rien à
    analyser) ; un blob illisible ou trop gros est une **erreur** (code 2).

    Les lectures sont adressées par SHA : un ``git add`` concurrent ne peut
    pas corrompre un blob déjà lu, mais la **liste** figée au départ peut
    devenir périmée (un fichier ajouté après le snapshot sera committé sans
    avoir été scanné). L'index est donc relu après l'analyse, et toute
    divergence refuse le scan (code 2) : un verdict sur un snapshot périmé
    ne vaut ni 0 ni 1. Une **deadline globale** (:data:`MAX_STAGED_SECONDS`)
    borne aussi la durée cumulée des appels git : un index adverse ne peut
    pas enchaîner 2 000 lectures jusqu'à épuisement du job CI.
    """
    deadline = time.monotonic() + MAX_STAGED_SECONDS
    access = GitAccess(root)
    if not access.is_repository(timeout=_call_timeout(deadline)):
        raise ScanError(_MSG_NOT_A_REPO)
    changes = access.staged_changes(timeout=_call_timeout(deadline))
    if len(changes) > MAX_STAGED_FILES:
        raise ScanError(_MSG_TOO_MANY_FILES)
    moteur = TargetScanner(
        SignatureEngine(
            SnippetHasher(),
            max_findings=MAX_STAGED_FINDINGS,
        )
    )
    findings: list[Finding] = []
    total = 0
    for change in changes:
        size = access.blob_size(
            change.blob,
            timeout=_call_timeout(deadline),
        )
        # Plancher explicite : même si un `GitAccess` dérivé rendait une
        # taille négative, `total` ne doit jamais reculer (la borne de
        # volume serait sinon contournable). Zéro reste valide : un blob
        # vide ne porte aucun candidat.
        if size < 0 or size > MAX_FILE_BYTES:
            raise ScanError(_MSG_TOO_LARGE)
        total += size
        if total > MAX_STAGED_BYTES:
            raise ScanError(_MSG_TOO_LARGE)
        data = access.blob_bytes(
            change.blob,
            timeout=_call_timeout(deadline),
        )
        # La taille annoncée par `cat-file -s` est un oracle, pas une
        # garantie : le contenu relu doit faire exactement cette taille.
        # Un écart (store incohérent, objet remplacé) refuserait sinon un
        # scan partiel ou ferait lire un blob au-delà de la borne 1 Mio.
        if len(data) != size:
            raise ScanError(_MSG_BLOB_CHANGED)
        if len(data) > MAX_FILE_BYTES:
            raise ScanError(_MSG_TOO_LARGE)
        text = decode_text(data)
        # Le texte n'est jamais retenu : chaque blob est lu, décodé, scanné
        # puis oublié avant le suivant — au plus un blob (1 Mio) vit en
        # mémoire, pas les 32 Mio du périmètre. `text`, `data` et `target`
        # sont réassignés à chaque tour ; rien ne les accumule.
        if text is None:
            # Binaire reconnu : aucun texte à analyser. Ce n'est pas une
            # exclusion de chemin, c'est une impossibilité technique.
            continue
        # `FileTarget` valide le chemin (contrat #14) : un chemin que le
        # contrat ne sait pas représenter est une erreur, pas un fichier
        # ignoré en silence.
        target = FileTarget(path=change.path, text=text)
        # Cible par cible, pas `scan_all` : le plafond Findings est vérifié
        # par candidat dans le moteur (un seul blob dense ne fait jamais
        # gonfler la liste), et ici entre cibles (l'accumulation sur tout
        # l'index reste bornée). L'ordre de sortie reste celui de `scan_all`
        # (même clé de tri ci-dessous).
        findings.extend(moteur.scan(target))
        if len(findings) > MAX_STAGED_FINDINGS:
            raise ScanError(_MSG_TOO_MANY_FINDINGS)
    findings.sort(
        key=lambda finding: (
            finding.file,
            finding.line,
            finding.type,
            finding.snippet_hash,
        )
    )
    if access.staged_changes(timeout=_call_timeout(deadline)) != changes:
        # L'index a bougé pendant le scan : le snapshot analysé ne décrit
        # plus ce qui sera committé. Refus, pas de verdict périmé.
        raise ScanError(_MSG_INDEX_CHANGED)
    _call_timeout(deadline)
    _verify_root_unchanged(access, root)
    return ScanReport(scope=SCOPE_STAGED, findings=tuple(findings))


def render_json(report: ScanReport) -> str:
    """Rend le rapport au format JSON (contrat machine ``--json``).

    Le document contient le périmètre, le nombre de Findings et les Findings
    eux-mêmes (les sept champs du contrat #14). Aucun secret : un Finding ne
    porte qu'une empreinte et une entropie.
    """
    payload = {
        "schema": JSON_SCHEMA,
        "scope": report.scope,
        "count": len(report.findings),
        "findings": [finding.as_dict() for finding in report.findings],
    }
    return json.dumps(
        payload,
        ensure_ascii=False,
        indent=2,
        sort_keys=True,
        allow_nan=False,
    )


def render_text(report: ScanReport) -> str:
    """Rend le rapport pour un humain.

    Jamais la valeur d'un secret : ni le contenu analysé, ni un extrait de
    ligne — seulement le chemin, le numéro de ligne, le type, l'entropie et
    un début d'empreinte (qui permet de rapprocher deux scans du même
    candidat sans le révéler).
    """
    lines = [f"heimdall scan : périmètre {_SCOPE_LABELS[report.scope]}"]
    if not report.findings:
        lines.append("Aucun secret détecté.")
    else:
        lines.append(f"{len(report.findings)} secret(s) détecté(s) :")
        for finding in report.findings:
            lines.append(
                f"  {finding.file}:{finding.line}  type={finding.type}  "
                f"entropie={finding.entropy}  "
                f"empreinte={finding.snippet_hash[:_HASH_PREFIX]}…  "
                f"source={finding.source}"
            )
    lines.append(_CODES_LINE)
    return "\n".join(lines)


__all__ = [
    "EXIT_CLEAN",
    "EXIT_ERROR",
    "EXIT_FINDINGS",
    "JSON_SCHEMA",
    "MAX_STAGED_BYTES",
    "MAX_STAGED_FILES",
    "MAX_STAGED_FINDINGS",
    "MAX_STAGED_SECONDS",
    "MAX_TREE_SECONDS",
    "SCOPE_STAGED",
    "SCOPE_TREE",
    "ScanReport",
    "ToolFailure",
    "collect",
    "render_json",
    "render_text",
]
