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
    r"(?P<value>[^\s\"'`,;)}\]]{6,4096})"
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

# Pied de clé privée PEM : structurel comme l'en-tête, masqué pour la même
# raison (cohérence : un bloc dont le corps est masqué ne doit pas garder
# ses deux balises en clair, le LLM n'en a pas besoin pour trier).
_PEM_FOOTER: Final[re.Pattern[str]] = re.compile(r"-----END[ A-Z0-9]*PRIVATE KEY(?: BLOCK)?-----")

# Jeton nu à préfixe connu : tableau JSON, secret collé seul, copier-coller
# sans affectation. Sans `clé =` devant lui, aucune des règles ci-dessus ne
# le voyait : il sortait en clair (fuite vers l'historique Ollama).
# La queue minimale (8) attrape les vrais jetons (plusieurs dizaines de
# caractères) en ignorant les bouts de factices trop courts pour être
# exploitables. Insensible à la casse : les formes canoniques sont en casse
# fixe (`AKIA`, `ghp_`) mais un secret recopié à la main peut varier.
# Pas de garde à gauche volontairement : un secret *collé* à du remplissage
# (`aaa<jeton>bbb`, évasion par collage) doit être attrapé ; un rattrapage
# au milieu d'un identifiant n'est qu'un faux positif bénin (un marqueur
# au lieu du texte, le tri n'en souffre pas).
_BARE_PREFIXES: Final[tuple[str, ...]] = (
    r"akia",
    r"asia",
    r"sk_live_",
    r"sk_test_",
    r"pk_live_",
    r"pk_test_",
    r"rk_live_",
    r"rk_test_",
    r"ghp_",
    r"gho_",
    r"ghu_",
    r"ghs_",
    r"ghr_",
    r"github_pat_",
    r"glpat-",
    r"xoxb-",
    r"xoxp-",
    r"xoxa-",
    r"shpat_",
    r"whsec_",
    r"npm_",
    r"dop_v1_",
    r"AIza",
    r"ya29\.",
)
_BARE_KNOWN_TOKEN: Final[re.Pattern[str]] = re.compile(
    r"(?:" + r"|".join(_BARE_PREFIXES) + r")[A-Za-z0-9_\-+=/]{8,256}",
    re.IGNORECASE,
)

# Jeton nu sans aucun indice (ni nom, ni préfixe) : il faut exiger plus
# (32 caractères denses) pour ne pas masquer le code ordinaire. Le tiret
# et la barre oblique sont exclus de la classe : un UUID (`8-4-4-4-12` à
# tirets) ou une URL ne matchent jamais — pas de bruit. Un SHA de commit
# copié dans un commentaire, lui, est masqué : c'est un faux positif
# bénin assumé (le LLM juge sur la forme, l'humain valide).
MIN_BARE_DENSE_LENGTH: Final[int] = 32
MIN_BARE_DENSE_BITS: Final[float] = 3.9
_BARE_DENSE_TOKEN: Final[re.Pattern[str]] = re.compile(
    r"(?<![A-Za-z0-9_~+.=-])[A-Za-z0-9_~+.=]{32,512}(?![A-Za-z0-9_~+.=-])"
)

# Alphabet base64 strict : dans un contexte PEM, une longue ligne de cet
# alphabet est le corps d'une clé, pas un hash d'intégrité (`sha512-…`
# contient un tiret, exclu d'ici).
_PEM_BODY_MIN_LENGTH: Final[int] = 64
_STRICT_BASE64: Final[re.Pattern[str]] = re.compile(r"\A[A-Za-z0-9+/=]+\Z")

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
#
# **DÉRIVÉS** de `_BARE_PREFIXES` : le vocabulaire qui masque un jeton nu et
# celui qui sait dire de quel fournisseur il s'agit ne peuvent plus diverger.
# La liste était recopiée à la main, et `pk_test_` en manquait — le jeton
# était bien masqué, mais typé `generic_secret` : pas de fuite, un tri
# dégradé et un test d'invariant (`prefix_vocabulary_is_fully_mapped`) qui
# passait parce qu'il ne parcourait que la liste de typage. Un préfixe
# ajouté au masquage est donc maintenant connu partout, sans double saisie.
# Normalisation : minuscules (le motif nu est `IGNORECASE`) et échappements
# regex retirés (`ya29\.` → `ya29.`), comme le fait `_secret_type` qui
# compare toujours `value.lower()`.
_KNOWN_PREFIXES: Final[tuple[str, ...]] = tuple(
    prefix.lower().replace("\\", "") for prefix in _BARE_PREFIXES
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
        # Invariant : chaque préfixe du vocabulaire est mappé ci-dessous
        # (prouvé par test_prefix_vocabulary_is_fully_mapped). La sortie de
        # boucle sans retour est donc inatteignable ; le repli générique
        # reste par sécurité si le vocabulaire bouge sans la table.
        for prefixes, secret_type in (  # pragma: no branch
            (("ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_"), "github"),
            (("glpat-",), "gitlab"),
            (("xoxb-", "xoxp-", "xoxa-"), "slack"),
            (("sk_live_", "sk_test_", "pk_live_", "pk_test_", "rk_live_", "rk_test_"), "stripe"),
            (("shpat_", "whsec_"), "webhook_secret"),
            (("npm_", "dop_v1_"), "package_token"),
            (("aiza", "ya29."), "google_api_key"),
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
# Borne assumée et documentée (ADR-003 §7) : une valeur courte (moins de 16
# caractères) à nom neutre (`MY_DATA="motdepasse12"`) N'EST PAS masquée.
# L'alternative — masquer toute valeur affectée dès 8 caractères —
# noierait le tri sous les faux positifs (`name="production"`,
# `host="database-01"` : indiscernables par entropie) et apprendrait au LLM
# à ignorer les marqueurs (fatigue d'alerte). La détection de précision
# appartient au scanner déterministe (#22) mesuré en #21 ; ce module reste
# un filet large, jamais un détecteur.
MIN_ENTROPY_LENGTH: Final[int] = 16
MIN_ENTROPY_BITS: Final[float] = 3.5


_AUTH_SCHEMES: Final[frozenset[str]] = frozenset(
    {"bearer", "basic", "token", "digest", "negotiate", "aws4-hmac-sha256", "mac", "hoba"}
)


def _looks_like_secret(key: str | None, value: str) -> bool:
    """Décide si une valeur doit être masquée (conservateur en cas de doute)."""
    if not value or _ENV_REFERENCE.match(value):
        return False
    if key is not None and key.lower() == "authorization" and value.lower() in _AUTH_SCHEMES:
        return False
    if value.lower().startswith(_KNOWN_PREFIXES):
        return True
    if key is not None and _SECRET_KEY.search(key):
        return True
    # Sans indice de nom, il faut une valeur longue et dense : c'est la règle
    # d'entropie du scanner #22, appliquée ici pour ne rien laisser passer.
    return len(value) >= MIN_ENTROPY_LENGTH and shannon_entropy(value) >= MIN_ENTROPY_BITS


def _bare_known_matches(text: str) -> list[_Match]:
    """Jetons nus à préfixe connu, où qu'ils apparaissent."""
    return [
        _Match(match.start(), match.end(), _secret_type(None, match.group(0)), len(match.group(0)))
        for match in _BARE_KNOWN_TOKEN.finditer(text)
    ]


def _bare_dense_matches(text: str, pem_context: bool) -> list[_Match]:
    """Longs jetons denses sans indice : secrets probables, jamais du code.

    Pas de contrôle de référence d'environnement ici : la classe du motif
    exclut `$`, `%`, `<`, `>`, `{`, `}`, `(`, `)`, `[`, `]`, donc aucune
    valeur du motif ne peut en être une — un contrôle mort serait un
    passif, pas une défense.
    """
    found: list[_Match] = []
    for match in _BARE_DENSE_TOKEN.finditer(text):
        value = match.group(0)
        if shannon_entropy(value) < MIN_BARE_DENSE_BITS:
            continue
        if (
            pem_context
            and len(value) >= _PEM_BODY_MIN_LENGTH
            and _STRICT_BASE64.match(value) is not None
        ):
            category = "private_key"
        else:
            category = "generic_secret"
        found.append(_Match(match.start(), match.end(), category, len(value)))
    return found


def _span_match(match: re.Match[str], group: str, secret_type: str) -> _Match:
    """Construit un masquage sur le groupe nommé d'un match de règle."""
    return _Match(match.start(group), match.end(group), secret_type, len(match.group(group)))


def _overlaps(candidate: _Match, kept: list[_Match]) -> bool:
    """True si le candidat recouvre un masquage déjà retenu."""
    return any(
        candidate.start < kept_item.end and kept_item.start < candidate.end for kept_item in kept
    )


def _iter_matches(text: str) -> list[_Match]:
    """Collecte les valeurs à masquer, sans se recouvrir.

    Fusion par **spécificité** : quand deux règles se recouvrent, la plus
    précise gagne (`postgres://u:p@h` → seul le mot de passe part, l'hôte
    reste lisible pour le tri), pas simplement la plus à gauche. À
    spécificité égale (impossible entre règles distinctes : leurs motifs
    ne commencent jamais au même point sauf inclusion, tranchée par
    l'ordre), l'ordre positionnel est conservé en sortie pour la
    reconstruction du texte.
    """
    pem_context = bool(_PEM_HEADER.search(text) or _PEM_FOOTER.search(text))
    groups: list[list[_Match]] = [
        [
            _Match(match.start(), match.end(), "private_key", match.end() - match.start())
            for match in _PEM_HEADER.finditer(text)
        ],
        [
            _Match(match.start(), match.end(), "private_key", match.end() - match.start())
            for match in _PEM_FOOTER.finditer(text)
        ],
        [
            _span_match(match, "value", _secret_type(match.group("key"), match.group("value")))
            for match in _AUTH_HEADER.finditer(text)
            if _looks_like_secret(match.group("key"), match.group("value"))
        ],
        [_span_match(match, "value", "url_password") for match in _URL_CREDENTIALS.finditer(text)],
        [
            _span_match(match, "value", _secret_type(match.group("key"), match.group("value")))
            for match in _QUOTED_ASSIGNMENT.finditer(text)
            if _looks_like_secret(match.group("key"), match.group("value"))
        ],
        [
            _span_match(match, "value", _secret_type(match.group("key"), match.group("value")))
            for match in _UNQUOTED_ASSIGNMENT.finditer(text)
            if _looks_like_secret(match.group("key"), match.group("value"))
        ],
        _bare_known_matches(text),
        _bare_dense_matches(text, pem_context),
    ]
    kept: list[_Match] = []
    for group in groups:
        for candidate in group:
            if _overlaps(candidate, kept):
                continue
            kept.append(candidate)
    kept.sort(key=lambda item: item.start)
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
