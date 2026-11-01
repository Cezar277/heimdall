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
  la base VCS et les entrées **non suivies** qu'un ``.gitignore`` du dépôt
  déclare ignorées sont écartées ; ``vendor/``, ``third_party/``, les
  lockfiles et les fichiers de contrôle sont parcourus dès qu'ils sont
  suivis ou non ignorés, parce qu'un secret y est un secret ;
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

import hashlib
import json
import logging
import os
import stat
import time
import unicodedata
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Literal

from heimdall.mcp.errors import ToolFailure
from heimdall.mcp.gitdiff import GIT_TIMEOUT_SECONDS, GitAccess
from heimdall.scanner.allowlist import (
    MAX_CONFIG_BYTES,
    Allowlist,
    AllowlistTrace,
    load_allowlist,
    parse_allowlist_bytes,
)
from heimdall.scanner.detect import MAX_FILE_BYTES
from heimdall.scanner.detect import Scanner as TreeScanner
from heimdall.scanner.errors import ScanError
from heimdall.scanner.exclusions import decode_text
from heimdall.scanner.finding import Finding
from heimdall.scanner.interface import FileTarget, _open_flags, _resolve_root
from heimdall.scanner.interface import Scanner as TargetScanner
from heimdall.scanner.signature_engine import SignatureEngine

#: Codes de sortie (invariant 11, REQ-SEC-07).
#: 0 = aucun secret détecté, 1 = secrets détectés, 2 = erreur d'outillage.
EXIT_CLEAN: Final[int] = 0
EXIT_FINDINGS: Final[int] = 1
EXIT_ERROR: Final[int] = 2

#: Périmètres contractuels du scan (contrat de sortie JSON, `scope`).
Scope = Literal["working-tree", "staged"]

#: Périmètre « arbre de travail ».
SCOPE_TREE: Final[Scope] = "working-tree"
#: Périmètre « index git ».
SCOPE_STAGED: Final[Scope] = "staged"

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
_MSG_BINARY: Final[str] = "scan impossible : entrée non analysable"
_MSG_INDEX_CHANGED: Final[str] = "scan impossible : entrée non analysable"
_MSG_ROOT_CHANGED: Final[str] = "scan impossible : entrée non analysable"
_MSG_TIMEOUT: Final[str] = "scan impossible : entrée non analysable"
_MSG_INVALID_SCOPE: Final[str] = "scan impossible : entrée non analysable"
#: Mode CI strict : un arbre réduit à sa base VCS n'a lu aucun contenu. Le
#: code 2 évite qu'une automatisation ne confonde « propre » et « non parcouru ».
_MSG_VCS_ONLY: Final[str] = "scan impossible : entrée non analysable"

#: Journal de diagnostic (niveau debug uniquement) : les causes de refus de
#: la garde anti auto-attestation y sont distinguées par des libellés
#: statiques (aucune entrée ni secret reflété, invariant 8).
logger = logging.getLogger("heimdall.cli.scan")

#: Libellés du périmètre, affichés à l'humain.
_SCOPE_LABELS: Final[dict[Scope, str]] = {
    SCOPE_TREE: "arbre de travail (base VCS et entrées .gitignore non suivies écartées)",
    SCOPE_STAGED: "index git (blobs ajoutés ou modifiés, aucune exclusion de chemin)",
}

#: Rappel du contrat de codes de sortie, affiché à l'humain.
_CODES_LINE: Final[str] = (
    "Codes de sortie : 0 = aucun secret, 1 = secrets détectés, 2 = erreur d'outillage."
)

#: Longueur de l'empreinte affichée à l'humain (le reste est dans le JSON).
_HASH_PREFIX: Final[int] = 12

#: Catégories Unicode jamais affichées brutes à l'humain : contrôles (Cc),
#: caractères de format (Cf : marques directionnelles U+202A-E, U+2066-9,
#: U+200E-F, espaces de largeur nulle U+200B-D, U+FEFF…), séparateurs de
#: ligne et de paragraphe (Zl, Zp).
_ESCAPED_CATEGORIES: Final[frozenset[str]] = frozenset({"Cc", "Cf", "Zl", "Zp"})


@dataclass(frozen=True, slots=True)
class ScanReport:
    """Le résultat d'un scan : un périmètre, des Findings et traces d'allowlist.

    Les Findings ne contiennent aucun secret (contrat #14) : les reporter
    tels quels, y compris dans le JSON, ne fuit rien.
    Les traces d'allowlist (#24) ne portent que : règle, fichier, ligne.
    """

    scope: Scope
    findings: tuple[Finding, ...]
    traces: tuple[AllowlistTrace, ...] = ()
    config_hash: str | None = None
    vcs_ignored: int = 0
    git_ignored: int = 0

    def __post_init__(self) -> None:
        # Garde runtime pour les appelants non typés : le `Literal` protège
        # mypy, cette vérification protège l'exécution (jamais de `KeyError`
        # ni de `TypeError` hors contrat dans `render_text`).
        if not isinstance(self.scope, str) or self.scope not in _SCOPE_LABELS:
            raise ScanError(_MSG_INVALID_SCOPE)
        if type(self.vcs_ignored) is not int or self.vcs_ignored < 0:
            raise ScanError(_MSG_INVALID_SCOPE)
        if type(self.git_ignored) is not int or self.git_ignored < 0:
            raise ScanError(_MSG_INVALID_SCOPE)

    @property
    def ignored_count(self) -> int:
        """Nombre de findings ignorés par l'allowlist déterministe (#24)."""
        return len(self.traces)


def collect(  # noqa: PLR0913 - explicit scan options
    root: Path,
    *,
    staged: bool,
    config: str | Path | None = None,
    allowlist: Allowlist | None = None,
    ci: bool = False,
    max_file_bytes: int | None = None,
    skipped_files: list[str] | None = None,
) -> ScanReport:
    """Analyse ``root`` et rend ses Findings et traces d'allowlist (#24).

    Lève ``ScanError`` si le périmètre n'a pas pu être
    analysé **en entier** : l'appelant transforme cela en code 2, jamais en
    code 0.

    ``max_file_bytes`` et ``skipped_files`` sont réservés au mode arbre.
    Les fournir avec ``staged=True`` lève ``ScanError`` avant tout accès Git.

    **Auto-attestation (CWE-345)** : si ``allowlist`` est fourni (API), la
    garde anti auto-attestation est contournée. Le seul usage légitime dans
    les chemins CLI/hook est ``Allowlist.empty()`` via ``--no-allowlist``.
    Pour tout autre ``Allowlist`` injecté, **l'appelant assume** que celui-ci
    ne provient pas du dépôt scanné et ne doit pas permettre l'auto-attestation
    de ``heimdall.toml`` interne. En cas de doute, ne pas injecter
    d'allowlist non-vide ou utiliser ``config`` externe / ``--no-allowlist``.
    """
    if staged and (max_file_bytes is not None or skipped_files is not None):
        raise ScanError("limite de fichier invalide")
    if max_file_bytes is not None and (
        type(max_file_bytes) is not int or not 1 <= max_file_bytes <= MAX_FILE_BYTES
    ):
        raise ScanError("limite de fichier invalide")
    try:
        if staged:
            return _collect_staged(root, config=config, custom_allowlist=allowlist, ci=ci)
        return _collect_tree(
            root,
            config=config,
            custom_allowlist=allowlist,
            ci=ci,
            max_file_bytes=max_file_bytes,
            skipped_files=skipped_files,
        )
    except ToolFailure:
        raise ScanError(_MSG_NOT_A_REPO) from None


def _verify_root_unchanged(access: GitAccess, root: Path) -> None:
    """Refuse si la racine a été échangée pendant le scan (TOCTOU).

    `access` fige la racine résolue ET son identité à l'entrée ; une
    reconstruction fraîche refait la garde unique (refus symlink compris).
    Toute différence — chemin résolu différent, identité (`st_dev`,
    `st_ino`, `st_ctime_ns`) différente — refuse le verdict : un dossier
    remplacé par un autre au même chemin a le même résolu mais pas la même
    identité, même quand le système lui recycle l'inode. Pur `lstat`/`stat`,
    aucun `git`.
    """
    try:
        current = GitAccess(root)
    except ToolFailure:
        raise ScanError(_MSG_ROOT_CHANGED) from None
    if current.root != access.root or current.root_id != access.root_id:
        raise ScanError(_MSG_ROOT_CHANGED)


def _read_worktree_file(path: Path, *, max_bytes: int = MAX_CONFIG_BYTES) -> bytes | None:
    """Lit un fichier du worktree via la garde unique, sans suivre de lien.

    Retourne ``None`` au moindre doute : chemin non résoluble, lien
    symbolique, non-régulier, trop gros ou lecture incomplète. La taille est
    bornée par :data:`MAX_CONFIG_BYTES` pour la config ; le cold start peut
    demander au plus :data:`MAX_FILE_BYTES` pour un contexte candidat.
    """
    if type(max_bytes) is not int or not 1 <= max_bytes <= MAX_FILE_BYTES:
        return None
    try:
        resolved = _resolve_root(path)
        # O_NONBLOCK évite qu'un FIFO placé à la place du fichier ne bloque
        # l'ouverture ; le fstat ci-dessous refuse ensuite tout non-régulier.
        descriptor = os.open(resolved, _open_flags() | getattr(os, "O_NONBLOCK", 0))
    except (ScanError, OSError):
        return None
    # Le `try` interne calcule le résultat, le `finally` ferme toujours le
    # descripteur, et le `except` externe convertit toute `OSError` (lecture
    # comme `os.close` en échec — EBADF/EINTR sur FS adverse) en `None`
    # fail-closed : jamais d'`OSError` brute vers l'appelant.
    try:
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > max_bytes:
                return None
            expected = metadata.st_size
            chunks: list[bytes] = []
            remaining = expected + 1  # un octet de plus détecte une croissance
            while remaining > 0:
                chunk = os.read(descriptor, remaining)
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            content = b"".join(chunks)
            # Refuser aussi une réécriture de même taille pendant la lecture.
            final = os.fstat(descriptor)
            if (
                len(content) != expected
                or final.st_size != metadata.st_size
                or final.st_mtime_ns != metadata.st_mtime_ns
            ):
                return None
            return content
        finally:
            os.close(descriptor)
    except OSError:
        return None


def _is_worktree_file_clean_and_tracked(
    access: GitAccess,
    rel_path: str,
    *,
    timeout: float,
) -> bytes | None:
    """Vérifie que le fichier du worktree est suivi dans l'index et non modifié (CWE-345).

    Retourne le contenu vérifié (``bytes``) si et seulement si :
    1. Le fichier existe, est un fichier ordinaire et est lisible dans l'arbre
       de travail (ouverture `O_NOFOLLOW` via la garde unique) ;
    2. Le fichier est présent dans l'index Git au stage 0, en mode fichier
       ordinaire (git plumbing `ls-files -s`, donc index v2/v3/v4, worktrees
       et sous-modules couverts sans parseur DIRC maison) ;
    3. L'empreinte de blob Git du contenu du worktree correspond exactement à
       l'index (SHA-1 ou SHA-256).

    Le contenu est rendu pour que l'appelant parse exactement les octets
    vérifiés, sans relire le fichier (fenêtre TOCTOU éliminée). En cas de
    doute (erreur I/O, index symlinké, format non reconnu, dirty/untracked,
    sous-module), retourne ``None`` : l'appelant refuse le scan. Chaque
    cause de refus est journalisée en debug avec un libellé statique
    (distinguer un `None` légitime d'une panne, sans rien refléter).
    """
    content = _read_worktree_file(access.root / rel_path)
    if content is None:
        logger.debug("refus anti auto-attestation : lecture worktree impossible (CWE-345)")
        return None
    try:
        entry = access.index_entry(rel_path, timeout=timeout)
    except ToolFailure:
        # Index illisible (symlinké, git en échec) : panne d'outillage,
        # fail-closed comme un untracked, mais journalisée distinctement.
        logger.debug("refus anti auto-attestation : lecture index impossible (CWE-345)")
        return None
    except Exception:
        logger.debug("refus anti auto-attestation : entrée index inattendue (CWE-345)")
        return None
    if entry is None:
        logger.debug("refus anti auto-attestation : configuration non suivie (CWE-345)")
        return None
    verified: bytes | None
    try:
        _, index_sha = entry
        blob_sha1 = hashlib.sha1(
            f"blob {len(content)}\0".encode("ascii") + content,
            usedforsecurity=False,
        ).hexdigest()
        blob_sha256 = hashlib.sha256(f"blob {len(content)}\0".encode("ascii") + content).hexdigest()
        verified = content if index_sha in (blob_sha1, blob_sha256) else None
        if verified is None:
            logger.debug("refus anti auto-attestation : configuration divergente (CWE-345)")
    except Exception:
        logger.debug("refus anti auto-attestation : empreinte incalculable (CWE-345)")
        verified = None
    return verified


@dataclass(frozen=True, slots=True)
class _VerifiedConfig:
    """Contenu de configuration vérifié contre l'index (CWE-345)."""

    path: str
    content: bytes


def _default_config_present(root: Path) -> bool:
    """Vrai si `heimdall.toml` existe à la racine du dépôt.

    `exists()` lève `OSError` sur un répertoire illisible (panne
    d'outillage) : c'est un `ScanError` statique (code 2, invariant 11),
    pas une absence silencieuse — comme `load_allowlist` le fait déjà.
    """
    try:
        return (root / "heimdall.toml").exists()
    except OSError:
        raise ScanError(_MSG_NOT_A_REPO) from None


def _guard_anti_self_attestation(  # noqa: PLR0912, PLR0913
    access: GitAccess,
    *,
    ci: bool,
    config: str | Path | None,
    custom_allowlist: Allowlist | None,
    staged_changes: Sequence[object],
    timeout: float,
    is_staged_scan: bool = False,
) -> _VerifiedConfig | None:
    """Protection anti auto-attestation (CWE-345).

    1. En mode CI, la configuration du dépôt scanné ne peut JAMAIS s'auto-attester :
       - si --config est passé, il DOIT être situé hors du dépôt scanné.
       - si aucun --config n'est passé et que heimdall.toml existe dans le dépôt,
         refuser en code 2 (exiger --config externe ou --no-allowlist).
    2. En mode hors CI :
       - si la configuration (heimdall.toml ou --config interne) est modifiée/ajoutée
         dans l'index (staged_changes), refuser en code 2.
       - en mode --staged, si la configuration du worktree est modifiée (dirty) ou
         non suivie (untracked) par rapport à l'index, refuser en code 2 (fail-closed).
         Le contenu vérifié est rendu pour être parsé sans relecture.
       - en mode arbre local, la propreté du worktree n'est PAS vérifiée
         (seule une configuration stagée est refusée) : ce périmètre est
         indicatif, seuls --ci et --staged sont opposables.
    3. Un `--config` explicite peut vivre hors du dépôt scanné, y compris hors
       CI : c'est un choix opérateur (disponibilité), équivalent au cas CI.
       La garde unique `_resolve_root` + `O_NOFOLLOW`, le plafond de taille et
       le contrat fermé s'appliquent dans les deux cas ; le contenu ne peut
       pas rendre l'allowlist aveugle (motifs universels refusés).

    Remarque (CWE-345) : si `custom_allowlist` est injecté (API), cette garde
    est **contournée par conception**. Le chemin CLI ne l'utilise qu'avec
    `Allowlist.empty()` via `--no-allowlist`. Tout autre injecteur assume la
    provenance hors dépôt et la responsabilité de l'absence d'auto-attestation.
    """
    if custom_allowlist is not None:
        return None

    root = access.root
    rel_cfg: str | None = None
    if config is not None:
        # `Path()` lève `ValueError` sur un octet NUL : fail-closed en
        # `ScanError` statique (contrat unique, invariant 11), comme
        # `_resolve_root` ci-dessous. Le texte est volontairement le message
        # générique (aucune entrée reflétée, invariant 8).
        try:
            cfg_path = Path(config)
        except (OSError, RuntimeError, ValueError, TypeError):
            raise ScanError(_MSG_NOT_A_REPO) from None
        if not cfg_path.is_absolute():
            cfg_path = root / cfg_path
        resolved_cfg = _resolve_root(cfg_path)
        if resolved_cfg.is_relative_to(root):
            rel_cfg = resolved_cfg.relative_to(root).as_posix()
    elif _default_config_present(root):
        rel_cfg = "heimdall.toml"

    if ci:
        if rel_cfg is not None:
            if config is None:
                raise ScanError(
                    "auto-attestation refusée : en mode --ci, l'allowlist du dépôt exige "
                    "--config externe ou --no-allowlist (CWE-345)"
                )
            raise ScanError(
                "auto-attestation refusée : en mode --ci, la configuration ne peut pas "
                "provenir du dépôt scanné (CWE-345)"
            )
        return None

    if rel_cfg is not None:
        # Comparaison stricte sur le chemin normalisé : un `subdir/heimdall.toml`
        # stagé n'est PAS la config chargée (`rel_cfg == "heimdall.toml"`) et ne
        # doit pas bloquer le scan (disponibilité). Idem pour `--config`
        # interne (`subdir/custom.toml` vs `other/subdir/custom.toml`).
        # Les deux côtés sont déjà normalisés (relatif au dépôt, `/`).
        is_cfg_staged = any(getattr(change, "path", None) == rel_cfg for change in staged_changes)
        if is_cfg_staged:
            # Message strictement statique : `rel_cfg` (entrée opérateur
            # normalisée) n'est jamais reflété (invariant 8). En CLI le
            # libellé est de toute façon masqué par le message générique.
            raise ScanError("auto-attestation refusée : configuration stagée (CWE-345)")
        if is_staged_scan:
            content = _is_worktree_file_clean_and_tracked(
                access,
                rel_cfg,
                timeout=timeout,
            )
            if content is None:
                raise ScanError(
                    "auto-attestation refusée : configuration du worktree non propre "
                    "ou non suivie en mode --staged (CWE-345)"
                )
            return _VerifiedConfig(path=rel_cfg, content=content)
    return None


def _load_allowlist_verified(
    access: GitAccess,
    verified: _VerifiedConfig,
) -> Allowlist:
    """Parse le contenu déjà vérifié, puis re-contrôle le fichier (CWE-345).

    Le parseur ne relit jamais la configuration : il consomme les octets
    validés contre l'index par la garde. Un second contrôle détecte une
    substitution concurrente entre la garde et le parsing et refuse en code 2.
    """
    allowlist = parse_allowlist_bytes(verified.content)
    current = _read_worktree_file(access.root / verified.path)
    if current is None or current != verified.content:
        # Message strictement statique : `verified.path` (entrée opérateur)
        # n'est jamais reflété (invariant 8), comme pour la garde ci-dessus.
        raise ScanError(
            "auto-attestation refusée : configuration modifiée pendant le chargement (CWE-345)"
        )
    return allowlist


def _collect_tree(  # noqa: PLR0913 - explicit scan options
    root: Path,
    *,
    config: str | Path | None = None,
    custom_allowlist: Allowlist | None = None,
    ci: bool = False,
    max_file_bytes: int | None = None,
    skipped_files: list[str] | None = None,
) -> ScanReport:
    """Scanne l'arbre de travail, en mode strict (#29) avec allowlist (#24).

    ``strict=True`` ne change plus le périmètre : seule la base VCS est
    écartée (comptée dans :attr:`ScanReport.vcs_ignored`) ; ``vendor/``, les
    lockfiles et les fichiers de contrôle sont parcourus. Un secret y est un
    secret. Un fichier binaire connu est refusé (``ScanError``, code 2),
    comme en ``--staged`` : aucun contenu n'est sauté en silence.

    ``respect_gitignore`` (défaut ``True``) ajoute une exclusion **sûre** :
    les entrées non suivies qu'un ``.gitignore`` du dépôt déclare ignorées
    sont écartées et comptées dans :attr:`ScanReport.git_ignored`. Un
    fichier **suivi** reste toujours scanné (``git add -f``), donc aucun nom
    ni motif ne peut cacher un secret qui peut partir dans un commit. Une
    panne de Git désactive l'exclusion et parcourt tout l'arbre (le scanner
    lit plus, jamais moins). ``False`` restaure un parcours intégral.

    Un arbre vide (seule la base VCS existe) reste un verdict 0 en local : il
    est réellement vide, pas illisible. En revanche, le mode **``--ci``** est
    strict : dès qu'une exclusion a été appliquée **sans aucun contenu lu**
    (``vcs_ignored > 0`` ou ``git_ignored > 0``, et ``files_scanned == 0``),
    le scan est refusé (``ScanError``, code 2) — une automatisation qui ne
    lit que le code de sortie ne doit jamais confondre « propre » et « non
    parcouru ». ``--staged`` reste le périmètre opposable pour le contenu
    indexé.

    L'allowlist déterministe (#24) écarte les cas évidents (example,
    changeme, dummy, fixtures de test) et produit une trace pour chaque rejet.

    Le périmètre contractuel est la **racine d'un dépôt git** : hors dépôt
    (répertoire quelconque, fichier isolé), pas de verdict « propre » mais
    une erreur — une CI mal configurée (mauvais chemin) doit échouer loud,
    pas rendre 0 en silence. Le scan de fichier isolé reste possible en
    bibliothèque (`Scanner`, #22), hors contrat hook/CI.
    """
    deadline = time.monotonic() + MAX_TREE_SECONDS
    access = GitAccess(root)
    if not access.is_repository(timeout=_call_timeout(deadline)):
        raise ScanError(_MSG_NOT_A_REPO)

    staged_changes = access.staged_changes(timeout=_call_timeout(deadline))
    verified = _guard_anti_self_attestation(
        access,
        ci=ci,
        config=config,
        custom_allowlist=custom_allowlist,
        staged_changes=staged_changes,
        timeout=_call_timeout(deadline),
        is_staged_scan=False,
    )

    allowlist = (
        custom_allowlist
        if custom_allowlist is not None
        else (
            _load_allowlist_verified(access, verified)
            if verified is not None
            else load_allowlist(
                access.root,
                config_file=config,
                allow_external=ci or config is not None,
            )
        )
    )
    scanner = TreeScanner(
        access.root,
        strict=True,
        allowlist=allowlist,
        max_file_bytes=max_file_bytes,
        skipped_files=skipped_files,
    )
    skipped_before = len(skipped_files) if skipped_files is not None else 0
    findings = scanner.scan(deadline=deadline)
    skipped_now = len(skipped_files) - skipped_before if skipped_files is not None else 0
    if ci and scanner.vcs_ignored > 0 and scanner.files_scanned == 0 and skipped_now == 0:
        # Aucun contenu n'a été lu : le seul périmètre observé est une base
        # VCS élaguée. En CI stricte, un code 0 serait indistinguable d'un
        # dépôt propre pour une automatisation qui ne lit que la sortie.
        # Le cold start rend explicitement les fichiers trop volumineux dans
        # un rapport incomplet (code 2) : ce cas n'est pas un arbre VCS seul.
        logger.debug("refus --ci : arbre réduit à sa base VCS (aucun contenu lu)")
        raise ScanError(_MSG_VCS_ONLY)
    _call_timeout(deadline)
    _verify_root_unchanged(access, root)
    traces = scanner.traces
    return ScanReport(
        scope=SCOPE_TREE,
        findings=tuple(findings),
        traces=tuple(traces),
        config_hash=allowlist.sha256,
        vcs_ignored=scanner.vcs_ignored,
        git_ignored=scanner.git_ignored,
    )


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


def _collect_staged(
    root: Path,
    *,
    config: str | Path | None = None,
    custom_allowlist: Allowlist | None = None,
    ci: bool = False,
) -> ScanReport:
    """Scanne les blobs **ajoutés ou modifiés** de l'index git avec allowlist (#24).

    Aucune exclusion de chemin : c'est le contenu que le commit va contenir
    qui est jugé, quel que soit son chemin (``vendor/evil.py``,
    ``package-lock.json``…). Un blob binaire connu est **refusé** (code 2),
    exactement comme un fichier binaire connu en mode arbre : il n'y a pas de
    texte à analyser, donc aucun verdict propre ne peut être rendu. Un blob
    illisible ou trop gros est également une **erreur** (code 2).

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

    verified = _guard_anti_self_attestation(
        access,
        ci=ci,
        config=config,
        custom_allowlist=custom_allowlist,
        staged_changes=changes,
        timeout=_call_timeout(deadline),
        is_staged_scan=True,
    )

    allowlist = (
        custom_allowlist
        if custom_allowlist is not None
        else (
            _load_allowlist_verified(access, verified)
            if verified is not None
            else load_allowlist(
                access.root,
                config_file=config,
                allow_external=ci or config is not None,
            )
        )
    )
    # Même échéance que la passe : un blob dense est interrompu à l'intérieur,
    # pas seulement entre deux blobs (cf. `SignatureEngine`, `deadline`).
    engine = SignatureEngine(
        max_findings=MAX_STAGED_FINDINGS,
        deadline=deadline,
        allowlist=allowlist,
    )
    moteur = TargetScanner(engine)
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
            # Binaire reconnu : aucun texte à analyser. Contrairement à une
            # exclusion de chemin, ce n'est pas une raison de rendre un
            # verdict propre : un secret peut vivre dans le binaire (même
            # limite qu'en mode arbre). Refus fail-closed, code 2.
            raise ScanError(_MSG_BINARY)
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
    if set(access.staged_changes(timeout=_call_timeout(deadline))) != set(changes):
        # L'index a bougé pendant le scan : le snapshot analysé ne décrit
        # plus ce qui sera committé. Refus, pas de verdict périmé. La
        # comparaison est **insensible à l'ordre** : `diff --cached --raw`
        # n'offre pas d'ordre contractuel, et une permutation à contenu
        # identique ne doit pas faire échouer un scan sain.
        raise ScanError(_MSG_INDEX_CHANGED)
    _call_timeout(deadline)
    _verify_root_unchanged(access, root)
    traces = engine.traces
    return ScanReport(
        scope=SCOPE_STAGED,
        findings=tuple(findings),
        traces=tuple(traces),
        config_hash=allowlist.sha256,
    )


def render_json(report: ScanReport) -> str:
    """Rend le rapport au format JSON (contrat machine ``--json``).

    Le document contient le périmètre, le nombre de Findings et les Findings
    eux-mêmes (les sept champs du contrat #14), ainsi que le nombre de
    findings ignorés et les traces de chaque rejet par l'allowlist (#24), le
    nombre de bases VCS élaguées (``vcs_ignored``, toujours 0 en
    ``--staged``) et le nombre d'entrées non suivies ignorées par
    ``.gitignore`` (``git_ignored``, toujours 0 en ``--staged`` et avec
    ``--no-gitignore``). Aucun secret n'est inclus.
    """
    payload = {
        "schema": JSON_SCHEMA,
        "scope": report.scope,
        "count": len(report.findings),
        "findings": [finding.as_dict() for finding in report.findings],
        "ignored_count": report.ignored_count,
        "traces": [trace.as_dict() for trace in report.traces],
        "config_hash": report.config_hash,
        "vcs_ignored": report.vcs_ignored,
        "git_ignored": report.git_ignored,
    }
    return json.dumps(
        payload,
        ensure_ascii=False,
        indent=2,
        sort_keys=True,
        allow_nan=False,
    )


def _visible(chemin: str) -> str:
    """Chemin tel qu'il s'affiche : caractères invisibles ou directionnels échappés.

    Un nom de fichier peut porter U+202E (RLO), qui inverse l'ordre visuel de
    ce qui suit : affiché brut, le nom ment sur le fichier où se trouve le
    secret, au moment même où l'opérateur valide (Y/N/E). Le contrat Finding v1
    autorise ces caractères (son schéma ne les exclut pas) : le chemin n'est donc
    pas refusé, il est échappé **à l'affichage seulement**. Le JSON garde le
    chemin exact.
    """
    return "".join(
        caractere.encode("unicode_escape").decode("ascii")
        if unicodedata.category(caractere) in _ESCAPED_CATEGORIES
        else caractere
        for caractere in chemin
    )


def render_text(report: ScanReport) -> str:
    """Rend le rapport pour un humain.

    Jamais la valeur d'un secret : ni le contenu analysé, ni un extrait de
    ligne — seulement le chemin, le numéro de ligne, le type, l'entropie et
    un début d'empreinte (qui permet de rapprocher deux scans du même
    candidat sans le révéler). Le chemin est affiché échappé (:func:`_visible`).
    Affiche toujours le nombre de findings ignorés par l'allowlist (#24).
    """
    lines = [f"heimdall scan : périmètre {_SCOPE_LABELS[report.scope]}"]
    if not report.findings:
        lines.append("Aucun secret détecté.")
    else:
        lines.append(f"{len(report.findings)} secret(s) détecté(s) :")
        for finding in report.findings:
            lines.append(
                f"  {_visible(finding.file)}:{finding.line}  type={finding.type}  "
                f"entropie={finding.entropy}  "
                f"empreinte={finding.snippet_hash[:_HASH_PREFIX]}…  "
                f"source={finding.source}"
            )
    if not report.traces:
        lines.append("Allowlist : 0 finding(s) ignoré(s).")
    else:
        lines.append(f"Allowlist : {report.ignored_count} finding(s) ignoré(s) :")
        for trace in report.traces:
            lines.append(f"  {_visible(trace.file)}:{trace.line}  règle={trace.rule}")
    # L'élagage VCS est une politique, pas un résultat : l'afficher évite de
    # lire un « aucun secret » comme une couverture de l'historique.
    lines.append(
        f"Base VCS : {report.vcs_ignored} base(s) élaguée(s) "
        "(historique non parcouru)."
    )
    # Les exclusions .gitignore sont aussi une politique : un fichier non
    # suivi et ignoré n'a pas été lu. Le compteur évite de lire un « aucun
    # secret » comme une couverture de ces entrées.
    lines.append(
        f"Gitignore : {report.git_ignored} entrée(s) non suivie(s) et ignorée(s) "
        "écartée(s) (non analysée(s))."
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
    "Scope",
    "ToolFailure",
    "collect",
    "render_json",
    "render_text",
]
