"""Masquage des valeurs candidates AVANT sérialisation (contrat #16).

Obligation ``masking_before_serialization`` : tous les champs texte lus par
le LLM sont masqués par le programme **avant** l'appel à ``json.dumps``.
Masquer après sérialisation laisserait la valeur dans un buffer ou dans
une trace.

Le scanner déterministe (#22) n'est pas encore livré : ce module porte donc
un masquage **volontairement conservateur** — en cas de doute on masque.
Le LLM juge sur la forme (type, longueur, contexte), jamais sur la valeur :
une valeur masquée en trop ne coûte rien, une valeur oubliée coûte un secret
relu par le LLM et potentiellement recopié dans son historique de
conversation Ollama. Le jour où #22 arrive, ses règles remplacent
``_looks_like_secret`` sans changer l'interface ``mask_text``.
"""

import math
import re
from collections import Counter
from dataclasses import dataclass
from typing import Final

# Marqueur de masquage. Le compte ``redactions`` des contrats est le nombre
# de valeurs remplacées, jamais le nombre de lignes touchées.
REDACTION_MARKER: Final[str] = "<REDACTED:"

# clé = "valeur"  /  clé: 'valeur'  (Python, PHP, JSON, YAML, .env)
_QUOTED_ASSIGNMENT: Final[re.Pattern[str]] = re.compile(
    r"(?P<key>[A-Za-z_][A-Za-z0-9_.\-]{0,63})"
    r"\s*[:=]\s*"
    r"(?P<quote>[\"'])"
    r"(?P<value>(?:[^\"'\\\n]|\\.){4,20000})"
    r"(?P=quote)"
)

# clé = valeur  (shell, export KEY=..., YAML sans guillemets, TOML)
_UNQUOTED_ASSIGNMENT: Final[re.Pattern[str]] = re.compile(
    r"(?P<key>[A-Za-z_][A-Za-z0-9_.\-]{0,63})"
    r"\s*[:=]\s*"
    r"(?P<value>[^\s\"'`,;)}\]]{12,4096})"
)

# Authorization: Bearer <jeton>
_AUTH_HEADER: Final[re.Pattern[str]] = re.compile(
    r"(?P<key>Authorization)"
    r"\s*[:=]\s*"
    r"(?P<type>[Bb]earer|[Bb]asic|[Tt]oken|[Dd]igest|[Nn]egotiate|"
    r"[Aa]WS4-HMAC-SHA256|[Mm]AC|[Hh]OBA)"
    r"\s+(?P<value>[^\s\"']{6,})"
)

# schéma://utilisateur:motdepasse@hôte
_URL_CREDENTIALS: Final[re.Pattern[str]] = re.compile(
    r"(?P<scheme>[A-Za-z][A-Za-z0-9+.\-]{1,16}://)"
    r"(?P<user>[^/@:\s]{1,64})"
    r":"
    r"(?P<value>[^/@\s]{4,256})"
    r"@"
)

# En-tête de clé privée PEM (la valeur s'étale sur plusieurs lignes : chaque
# ligne est masquée séparément, le marqueur suffit au LLM).
_PEM_HEADER: Final[re.Pattern[str]] = re.compile(r"-----BEGIN[ A-Z0-9]*PRIVATE KEY(?: BLOCK)?-----")

# Une valeur qui n'est qu'une référence d'environnement n'est pas un secret.
_ENV_REFERENCE: Final[re.Pattern[str]] = re.compile(
    r"^(?:\$\{[^}\s]{1,128}\}|\$[A-Za-z_][A-Za-z0-9_]{0,63}|%[A-Za-z0-9_]{1,64}%|"
    r"os\.(?:environ|getenv)|environ\[[^\]]{1,64}\]|getenv\([^)]{1,64}\)|"
    r"<[^>\n]{1,64}>|\{\{[^}\n]{1,64}\}\})$"
)

# Nom de variable évocateur : le masquage est presque toujours légitime.
_SECRET_KEY: Final[re.Pattern[str]] = re.compile(
    r"(?i)(passwd|password|pwd|secret|token|api[-_.]?key|access[-_.]?key|"
    r"private[-_.]?key|credential|auth|salt|signature|licen[cs]e|bearer|"
    r"session|cert|webhook|connection[-_.]?string)"
)

# Préfixes de jetons connus (liste courte, à compléter avec #22).
_KNOWN_PREFIXES: Final[tuple[str, ...]] = (
    "akia",
    "asia",
    "sk_live_",
    "sk_test_",
    "pk_live_",
    "rk_live_",
    "ghp_",
    "gho_",
    "ghu_",
    "ghs_",
    "ghr_",
    "github_pat_",
    "glpat-",
    "xoxb-",
    "xoxp-",
    "xoxa-",
    "shpat_",
    "whsec_",
    "npm_",
    "dop_v1_",
    "AIza",
    "ya29.",
)


@dataclass(frozen=True)
class _Match:
    """Valeur à masquer : l'intervalle à remplacer et son type."""

    start: int
    end: int
    secret_type: str
    length: int


def shannon_entropy(value: str) -> float:
    """Entropie de Shannon en bits par caractère (même mesure que le #22)."""
    if not value:
        return 0.0
    counts = Counter(value)
    total = float(len(value))
    return -sum((count / total) * math.log2(count / total) for count in counts.values())


def _secret_type(key: str | None, value: str) -> str:
    """Catégorie annoncée dans le marqueur (``SecretType`` du contrat)."""
    lowered = (key or "").lower()
    token = value.lower()
    if token.startswith(_KNOWN_PREFIXES):
        for prefixes, secret_type in (
            (("ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_"), "github"),
            (("glpat-",), "gitlab"),
            (("xoxb-", "xoxp-", "xoxa-"), "slack"),
            (("sk_live_", "sk_test_", "pk_live_", "rk_live_"), "stripe"),
            (("shpat_", "whsec_"), "webhook_secret"),
            (("npm_", "dop_v1_"), "package_token"),
            (("AIza", "ya29."), "google_api_key"),
            (("akia", "asia"), "aws"),
        ):
            if token.startswith(prefixes):
                return secret_type
    if token.startswith("-----begin") or ("private" in lowered and "key" in lowered):
        return "private_key"
    if "aws" in lowered:
        return "aws"
    if "ssh" in lowered:
        return "ssh_key"
    if "openai" in lowered:
        return "openai"
    return "generic_secret"


# Seuils d'entropie (bits par caractère) et de longueur : sans indice dans
# le nom de la variable, une valeur courte ou prévisible n'est pas un secret.
# Ces valeurs seront remplacées par celles du scanner #22.
MIN_ENTROPY_LENGTH: Final[int] = 16
MIN_ENTROPY_BITS: Final[float] = 3.5


def _looks_like_secret(key: str | None, value: str) -> bool:
    """Décide si une valeur doit être masquée (conservateur en cas de doute)."""
    if not value or _ENV_REFERENCE.match(value):
        return False
    if value.lower().startswith(_KNOWN_PREFIXES):
        return True
    if key is not None and _SECRET_KEY.search(key):
        return True
    # Sans indice de nom, il faut une valeur longue et dense : c'est la règle
    # d'entropie du scanner #22, appliquée ici pour ne rien laisser passer.
    return len(value) >= MIN_ENTROPY_LENGTH and shannon_entropy(value) >= MIN_ENTROPY_BITS


def _iter_matches(text: str) -> list[_Match]:
    """Collecte les valeurs à masquer, sans se recouvrir."""
    found: list[_Match] = []

    for match in _PEM_HEADER.finditer(text):
        found.append(_Match(match.start(), match.end(), "private_key", match.end() - match.start()))

    for match in _AUTH_HEADER.finditer(text):
        if _looks_like_secret(match.group("key"), match.group("value")):
            found.append(
                _Match(
                    match.start("value"),
                    match.end("value"),
                    _secret_type(match.group("key"), match.group("value")),
                    len(match.group("value")),
                )
            )

    for match in _URL_CREDENTIALS.finditer(text):
        found.append(
            _Match(
                match.start("value"),
                match.end("value"),
                "url_password",
                len(match.group("value")),
            )
        )

    for match in _QUOTED_ASSIGNMENT.finditer(text):
        key = match.group("key")
        value = match.group("value")
        if _looks_like_secret(key, value):
            found.append(
                _Match(
                    match.start("value"),
                    match.end("value"),
                    _secret_type(key, value),
                    len(value),
                )
            )

    for match in _UNQUOTED_ASSIGNMENT.finditer(text):
        key = match.group("key")
        value = match.group("value")
        if _looks_like_secret(key, value):
            found.append(
                _Match(
                    match.start("value"),
                    match.end("value"),
                    _secret_type(key, value),
                    len(value),
                )
            )

    # Premier arrivé, premier servi : si deux motifs se recouvrent (une
    # assignation citant une URI avec mot de passe), le plus à gauche gagne.
    found.sort(key=lambda item: (item.start, -(item.end - item.start)))
    kept: list[_Match] = []
    for candidate in found:
        if kept and candidate.start < kept[-1].end:
            continue
        kept.append(candidate)
    return kept


def mask_text(text: str) -> tuple[str, int]:
    """Remplace les valeurs candidates par ``<REDACTED:type:len=N>``.

    Renvoie le texte masqué et le **nombre de valeurs remplacées**
    (compteur ``redactions`` du contrat). Une ligne sans secret repart
    inchangée avec un compteur nul : le schéma ne peut pas exiger de
    marqueur sur chaque ligne, la plupart n'en portent légitimement aucun.
    """
    matches = _iter_matches(text)
    if not matches:
        return text, 0
    pieces: list[str] = []
    cursor = 0
    for item in matches:
        pieces.append(text[cursor : item.start])
        pieces.append(f"{REDACTION_MARKER}{item.secret_type}:len={item.length}>")
        cursor = item.end
    pieces.append(text[cursor:])
    return "".join(pieces), len(matches)
