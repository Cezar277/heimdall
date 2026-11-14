"""Masquage des valeurs candidates AVANT sérialisation (contrat #16).

Obligation ``masking_before_serialization`` : tous les champs texte lus par
le LLM sont masqués par le programme **avant** l'appel à ``json.dumps``.
Masquer après sérialisation laisserait la valeur dans un buffer ou dans
une trace.

Le scanner déterministe (#22) est livré ; le masquage reste volontairement
conservateur et indépendant. Le LLM juge sur la forme (type, longueur, contexte),
jamais sur la valeur : une valeur masquée en trop ne coûte rien, une valeur
oubliée coûte un secret relu par le LLM et potentiellement recopié dans son
historique de conversation Ollama.
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
#
# PAS de borne haute : `{4,}` et non `{4,20000}`. La borne ne protégeait de
# rien (aucun quantificateur imbriqué, et le groupe de valeur s'arrête au
# premier guillemet non échappé — donc aucun backtracking catastrophique)
# mais elle COUPAIT le match : sur `SECRET="` + 50000 caractères + `"`, la
# valeur ne matchait plus, aucun filet ne la rattrapait à basse entropie,
# puis `_masked_line` tronquait à 2000 caractères et le préfixe `SECRET="aaa…`
# repartait **en clair** vers le LLM — vérifié par exécution. La valeur reste
# bornée par sa ligne (1 Mo au plus, `MAX_FILE_BYTES`), et `_looks_like_secret`
# décide toujours si elle est un secret. Coût mesuré : linéaire, sans
# backtracking (voir `MaskingPerformanceTests`).
#
# Les guillemets autour de la CLÉ sont optionnels : `{"password": "…"}` et
# `'api_key': '…'` (JSON, YAML, dict Python) ne matchent plus seulement la
# forme `password = "…"`. Le séparateur `=>` couvre PHP/Ruby.
#
# Deux motifs distincts pour la VALEUR, au lieu d'une classe qui excluait les
# deux types de guillemets : une chaîne entre guillemets doubles peut contenir
# une apostrophe (`password = "it's-secret-123"`) et inversement
# (`password = 'say "hi"'`). Un seul motif ne pouvait pas exprimer les deux
# sans couper la valeur au premier guillemet interne.
#
# Le préfixe `(?<![A-Za-z])` évite de relancer le motif à chaque caractère
# d'une longue valeur (`password = ` + 120 Ko : ~0,45 s → ~0,05 s mesuré).
# Un nom de clé ne peut pas commencer au milieu d'une suite de lettres ; les
# formes utiles (`123password`, `_password`, `.password`) restent couvertes
# car le caractère qui les précède n'est pas une lettre.
_QUOTED_ASSIGNMENT: Final[re.Pattern[str]] = re.compile(
    r"(?<![A-Za-z])[\"']?(?P<key>[A-Za-z_][A-Za-z0-9_.\-]{0,63})[\"']?"
    r"\s*(?:=>|[:=])\s*"
    r'"(?P<value>(?:[^"\\\n]|\\.){4,})"'
)

# Même règle pour une valeur entre guillemets simples, qui peut donc contenir
# des guillemets doubles (`'say "hi"'`). L'apostrophe interne échappée reste
# couverte par `\\.` ; une apostrophe non échappée termine la chaîne, comme
# le veut la syntaxe.
_SINGLE_QUOTED_ASSIGNMENT: Final[re.Pattern[str]] = re.compile(
    r"(?<![A-Za-z])[\"']?(?P<key>[A-Za-z_][A-Za-z0-9_.\-]{0,63})[\"']?"
    r"\s*(?:=>|[:=])\s*"
    r"'(?P<value>(?:[^'\\\n]|\\.){4,})'"
)

# clé = valeur  (shell, export KEY=..., YAML sans guillemets, TOML)
#
# PAS de borne haute : `{6,}` et non `{6,4096}`. La borne ne protégeait de
# rien (aucun quantificateur imbriqué, et rien ne suit le groupe de valeur —
# donc aucun backtracking possible) mais elle COUPAIT le match : sur
# `SECRET=` + 5000 caractères, les 4096 premiers étaient masqués et les
# 904 derniers repartaient **en clair** après le marqueur, vérifié par
# exécution — une fuite déguisée en masquage. La classe de valeur exclut
# l'espace, les quotes et la ponctuation : une affectation reste donc
# bornée par son segment, jamais par le fichier entier. Coût mesuré sur
# 1 Mo de valeur dense : linéaire, pas de backtracking (voir
# `MaskingPerformanceTests`).
_UNQUOTED_ASSIGNMENT: Final[re.Pattern[str]] = re.compile(
    r"(?<![A-Za-z])[\"']?(?P<key>[A-Za-z_][A-Za-z0-9_.\-]{0,63})[\"']?"
    r"\s*(?:=>|[:=])\s*"
    r"(?P<value>[^\s\"'`,;)}\]]{6,})"
)

# clé = valeur COURTE (1 à 5 caractères) sous un nom ÉVOCATEUR :
# `SECRET=abc12`, `PASSWORD=1234`, `TOKEN=x1` — un code court, un PIN, un mot
# de passe par défaut. La borne de 6 de `_UNQUOTED_ASSIGNMENT` les laissait
# partir en clair vers le LLM et son historique alors que le nom dit déjà
# « secret ».
#
# Règle SÉPARÉE, et non une borne abaissée dans `_UNQUOTED_ASSIGNMENT` : le
# premier match d'un motif gagne, donc une valeur courte matche TÔT dans la
# ligne (`max_bytes: int` dans une signature) et consommerait la suite du
# texte — le masquage long perdrait alors ses cibles (`DEFAULT_MAX_BYTES`
# n'était plus vu). Deux motifs, deux fenêtres, aucun ombrage : c'est
# vérifié par test (`test_short_rule_does_not_shadow_the_long_one`).
#
# Guillemets d'encadrement OPTIONNELS mais symétriques : `TOKEN="x1"` (2 car.)
# ne matchait aucune règle — `_QUOTED_ASSIGNMENT` exige `{4,}` et les règles
# courtes excluent les quotes — alors que `TOKEN=x1` était masqué. Le groupe
# `value` reste l'intérieur nu (le jugement par
# `_short_evocative_looks_secret` et le marqueur `len=` sont inchangés) ;
# sans guillemet fermant, le motif échoue au lieu de consommer (pas de
# match partiel qui masquerait du code).
_EVOCATIVE_SHORT_VALUE: Final[re.Pattern[str]] = re.compile(
    r"(?<![A-Za-z])[\"']?(?P<key>[A-Za-z_][A-Za-z0-9_.\-]{0,63})[\"']?"
    r"\s*(?:=>|[:=])\s*"
    r"(?P<quote>[\"']?)"
    r"(?P<value>[^\s\"'`,;)}\]]{1,5})"
    r"(?P=quote)"
)

# Valeur NON QUOTÉE à nom évocateur, avec espaces et ponctuation :
# `password = my secret pass phrase 42`, `password=abc,defghijk99`,
# `DB_PASSWORD: p@ss;word1234`. Les règles précédentes s'arrêtaient au premier
# espace ou à la première virgule/point-virgule, donc la queue de la valeur
# partait en clair. Cette règle prend le reste de la ligne jusqu'à un
# commentaire précédé d'espace (` #`) ou la fin de ligne.
#
# Elle est SÉPARÉE et placée après les règles citées : une valeur entre
# guillemets doit être jugée par la règle citée (intérieur exact, apostrophe
# interne supportée), pas avalée jusqu'à la fin de ligne. Le filtre
# `_evocative_unquoted_looks_secret` refuse en plus les annotations de type et
# les appels de fonction (`api_key: str`, `password = get_password()`) pour ne
# pas noyer le tri sous les faux positifs.
_EVOCATIVE_UNQUOTED_VALUE: Final[re.Pattern[str]] = re.compile(
    r"(?<![A-Za-z])[\"']?(?P<key>[A-Za-z_][A-Za-z0-9_.\-]{0,63})[\"']?"
    r"\s*(?:=>|[:=])\s*"
    r"(?P<value>[^\n]+?)(?=[ \t]+#|\n|$)"
)

# Valeur quotée NON REFERMÉE : `password="hunter2!hunter` (ligne de diff
# tronquée, coquille, multiligne). Les règles citées exigent le guillemet
# fermant, et la règle non quotée refuse explicitement les valeurs commençant
# par un guillemet : le secret partait en clair (revue). Le guillemet ouvrant
# est exclu du span, la valeur va jusqu'à la fin de ligne ou au commentaire
# ` #`, et le jugement reste `_looks_like_secret`. Si un guillemet fermant
# non échappé est trouvé, `_unclosed_quoted_spans` rend la main aux règles
# citées (pas de double masquage).
_UNCLOSED_QUOTED_VALUE: Final[re.Pattern[str]] = re.compile(
    r"(?<![A-Za-z])[\"']?(?P<key>[A-Za-z_][A-Za-z0-9_.\-]{0,63})[\"']?"
    r"\s*(?:=>|[:=])\s*"
    r"(?P<quote>[\"'])(?P<value>[^\n]*?)(?=[ \t]+#|\n|$)"
)

# Balise XML sensible : `<password>…</password>`, `<api_key>…</api_key>`.
# Le nom de la balise est jugé par `_SECRET_KEY` (voir `_iter_matches`), la
# valeur masquée est l'intérieur seulement.
_XML_SENSITIVE_ELEMENT: Final[re.Pattern[str]] = re.compile(
    r"<(?P<tag>[A-Za-z_][A-Za-z0-9_.:\-]{0,63})(?:\s[^<>]*)?>"
    r"(?P<value>[^<\n]{1,})"
    r"</(?P=tag)\s*>"
)

# `define('DB_PASSWORD', 'S3cr3tValue99')` (PHP/Ruby). Nom ET valeur peuvent
# être nus (`define(DB_PASSWORD, S3cr3tValue99)`) : PHP les accepte comme
# constantes, et la valeur reste un secret. Guillemets optionnels mais
# symétriques ; le jugement final reste `_looks_like_secret`. Insensible à la
# casse : les fonctions PHP le sont (`DEFINE(...)` est valide).
_DEFINE_ASSIGNMENT: Final[re.Pattern[str]] = re.compile(
    r"(?i)define\(\s*(?P<keyquote>[\"']?)"
    r"(?P<key>[A-Za-z_][A-Za-z0-9_.\-]{0,63})"
    r"(?P=keyquote)\s*,\s*"
    r"(?P<valuequote>[\"']?)"
    r"(?P<value>(?:[^\\\n]|\\.)*?)"
    r"(?P=valuequote)\s*\)"
)

# `.netrc` : `machine github.com login bob password S3cretP4ss`. Le nom
# `password` n'est pas suivi de `:`/`=`, donc aucune règle d'affectation ne
# le voyait. Insensible à la casse : `Password` est accepté par les clients
# `.netrc` et était oublié.
_NETRC_PASSWORD: Final[re.Pattern[str]] = re.compile(
    r"(?i)(?<![\w-])password[ \t]+(?![=:])(?P<value>[^\s\"']{1,})"
)

# Option CLI `--password <val>` / `--password=<val>` / `--api-key=…`.
# La valeur peut être citée (`--password "my secret"`).
_CLI_SECRET_OPTION: Final[re.Pattern[str]] = re.compile(
    r"(?<![\w-])--(?P<key>[A-Za-z][A-Za-z0-9_-]{0,63})"
    r"(?:\s*=\s*|\s+)"
    r"(?:(?P<quote>[\"'])(?P<quoted>(?:[^\\\n]|\\.)*?)(?P=quote)"
    r"|(?P<value>[^\s\"']+))"
)

# Option CLI à valeur quotée non refermée : `--password "hunter2!hunter`.
# La branche citée ci-dessus exige le guillemet fermant ; sans cette règle,
# la valeur partait en clair. Même filtrage de fermeture que
# `_UNCLOSED_QUOTED_VALUE`.
_CLI_UNCLOSED_QUOTED_OPTION: Final[re.Pattern[str]] = re.compile(
    r"(?<![\w-])--(?P<key>[A-Za-z][A-Za-z0-9_-]{0,63})"
    r"(?:\s*=\s*|\s+)"
    r"(?P<quote>[\"'])(?P<value>[^\n]*?)(?=[ \t]+#|\n|$)"
)

# `curl -u admin:Sup3rS3cret` : identifiants passés en argument CLI, hors URL.
_CLI_USER_PASSWORD: Final[re.Pattern[str]] = re.compile(
    r"(?<![\w-])-u[ \t]+(?P<user>[^\s:\"']{1,64}):(?P<value>[^\s\"']{1,})"
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

# schéma://<jeton>@hôte — jeton d'accès dans le userinfo SANS mot de passe,
# forme standard d'une remote git ou d'un en-tête CI. `_URL_CREDENTIALS`
# exige `utilisateur:motdepasse@`, donc ce jeton-là n'était vu par AUCUNE
# règle : court et sans préfixe connu, il partait en clair (les filets `bare`
# ne rattrapent qu'au-delà de 32 caractères denses ou d'un préfixe connu).
# On masque donc tout userinfo qui A L'AIR d'être un jeton — voir
# `_url_userinfo_looks_secret`.
_URL_USERINFO: Final[re.Pattern[str]] = re.compile(
    r"(?P<scheme>[A-Za-z][A-Za-z0-9+.\-]{1,16}://)(?P<value>[^/@\s]{1,256})@"
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
#
# `token(?!izer\b)` n'épargne QUE le faux positif `tokenizer`/`TOKENIZER` :
# `token(?![a-z])`, essayé d'abord, excluait aussi `tokens`/`TOKENS` — un
# secret sous une clé au pluriel repartait en clair (régression fail-closed).
# De même `auth(?!or(?:s|ities|ity)?\b)` épargne `author`, `authors`,
# `authority`/`authorities` sans toucher `authorization`, `authentication`
# ni `auth_token`.
_SECRET_KEY: Final[re.Pattern[str]] = re.compile(
    r"(?i)(passwd|password|pwd|secret|token(?!izer\b)|api[-_.]?key|access[-_.]?key|"
    r"private[-_.]?key|credential|authorization|auth(?!or(?:s|ities|ity)?\b)|salt|"
    r"signature|licen[cs]e|bearer|session|cert|webhook|connection[-_.]?string)"
)

# Noms GÉNÉRIQUES de second rang : un nom qui se TERMINE par `key`/`pass`/
# `passphrase`, sans qualificatif (`KEY=`, `PASS=`, `AWS_KEY=`, `DB_PASS=`).
# Ils manquaient, et la valeur partait en clair : `KEY=hunter2`,
# `PASS=abc12345`, `AWS_KEY="hunter2"` — vérifié par exécution. Un `key`
# ou `pass` seul est FAIBLE (d'où le second rang, et non l'ajout direct à
# `_SECRET_KEY` : `key = "production"` et `key: "name"` sont du JSON/YAML
# ordinaire, pas des secrets).
#
# Ancrage par FIN : `key$` attrape `AWS_KEY` et `MYKEY` là où `\bkey\b` les
# manquerait (`_` et les majuscules sont des caractères de mot), et laisse
# `keyboard`, `keyword`, `monkey`, `bypass`, `compass` — qui ne se terminent
# pas par ces mots. Volontairement limité à ces trois radicaux : `seed`,
# `nonce` et `pin` ont été essayés puis retirés, ils sont trop fréquents
# hors secret (`cnonce = md5(…)`, `best_key = max(…, key=…)`) pour un gain
# de couverture réel — le bruit se mesure, il ne se devine pas.
_GENERIC_SECRET_KEY: Final[re.Pattern[str]] = re.compile(r"(?i)(?:key|pass|passphrase)\Z")

# Littéraux de langage : jamais un secret, et roadblocks du bruit de la
# règle des valeurs COURTES (`session = None`, `auth = None`, `cert = null`
# — du code ordinaire, pas un secret). Volontairement N'UTILISÉ QUE PAR
# `_short_evocative_looks_secret` : l'appliquer aussi aux règles longues
# changerait leur comportement (mesuré : 10 lignes tierces cesseraient d'être
# masquées), alors qu'aucune n'est demandée par le correctif. Portée
# minimale, effet mesuré.
_CODE_LITERAL: Final[re.Pattern[str]] = re.compile(
    r"(?i)\A(?:none|null|nil|nan|true|false|undefined|self|this|object|void)\Z"
)

# Préfixes de jetons connus (liste courte, maintenue avec le scanner #22).
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
# Le scanner #22 utilise la même mesure sur les octets ; le masquage garde ses
# seuils conservateurs car il couvre aussi les champs non produits par lui.
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

# Seuils du userinfo d'URL : ce qu'il faut pour distinguer un jeton d'accès
# d'un simple nom d'utilisateur. Mesurés sur un corpus (secrets ≥ 3,09 bits
# par caractère — `monmotdepasse`, `tok1234567890`, `dXNlcjpwYXNz…` — contre
# identités ≤ 2,91 — `utilisateur`, `robotaccount` — plus `alice` et
# `deploy`, trop courtes de toute façon) : 3,0 bits sépare les deux groupes
# sans faux positif mesuré. Le préfixe connu court-circuite le seuil : un
# `ghp_…` est un jeton même tronqué.
MIN_URL_USERINFO_LENGTH: Final[int] = 8
MIN_URL_USERINFO_BITS: Final[float] = 3.0

# Longueur minimale de la valeur dans la règle courte : sous 2 caractères,
# ce n'est pas un credential mais une constante (`token = 0`).
MIN_SHORT_VALUE_LENGTH: Final[int] = 2

# Valeur non quotée évocatrice : sous 6 caractères, la règle longue ou la
# règle courte s'en charge ; au-delà, plusieurs mots peuvent être une phrase
# de passe (`correct horse battery staple`).
MIN_EVOCATIVE_UNQUOTED_LENGTH: Final[int] = 6
MIN_PASSPHRASE_WORDS: Final[int] = 2


def _generic_name_carries_a_secret(key: str, value: str) -> bool:
    """`KEY=`, `PASS=`, `AWS_KEY=` : la valeur vaut-elle un credential ?

    Second rang assumé : le nom est faible (`key`, `pass` sont aussi les
    champs d'un JSON ou d'un YAML ordinaire), donc la valeur doit encore
    y ressembler — au moins un chiffre (`hunter2`, `abc12345`, `ab12`) ou
    un préfixe de jeton connu. Mesuré sur 1,29 million de lignes de corpus
    : `key = "production"` et `key: "name"` restent lisibles, tandis que
    `KEY=hunter2`, `PASS=abc12345`, `AWS_KEY="hunter2"` et `MYKEY=ab12`
    passent au marqueur.
    """
    if _GENERIC_SECRET_KEY.search(key) is None:
        return False
    if value.lower().startswith(_KNOWN_PREFIXES):
        return True
    return any(character.isdigit() for character in value)


def _looks_like_secret(key: str | None, value: str) -> bool:
    """Décide si une valeur doit être masquée (conservateur en cas de doute)."""
    if not value or _ENV_REFERENCE.match(value):
        return False
    if key is not None and key.lower() == "authorization" and value.lower() in _AUTH_SCHEMES:
        return False
    if value.lower().startswith(_KNOWN_PREFIXES):
        return True
    if key is not None:
        if _SECRET_KEY.search(key):
            return True
        if _generic_name_carries_a_secret(key, value):
            return True
    # Sans indice de nom, il faut une valeur longue et dense : c'est la même
    # mesure d'entropie que le scanner #22, appliquée ici pour ne rien laisser passer.
    return len(value) >= MIN_ENTROPY_LENGTH and shannon_entropy(value) >= MIN_ENTROPY_BITS


def _url_userinfo_looks_secret(value: str) -> bool:
    """Un userinfo d'URL est-il un jeton plutôt qu'un nom d'utilisateur ?"""
    if value.lower().startswith(_KNOWN_PREFIXES):
        return True
    return len(value) >= MIN_URL_USERINFO_LENGTH and shannon_entropy(value) >= MIN_URL_USERINFO_BITS


def _url_credential_spans(match: re.Match[str]) -> list[_Match]:
    """Spans d'une URL `user:password@` : mot de passe toujours, user si jeton.

    Sans le second span, un secret en position user (`https://<jeton>:pwd@h`,
    contenu scanné piégé) partait en clair : `_URL_USERINFO` (userinfo seul)
    était ensuite écarté par `_overlaps`, la règle mot-de-passe ayant gagné
    la fusion. Le `user` seul (`alice`, `admin`) reste lisible : c'est lui
    qui sert au tri, et le seuil est le même que pour l'userinfo seul.
    """
    spans = [_span_match(match, "value", "url_password")]
    if _url_userinfo_looks_secret(match.group("user")):
        spans.append(_span_match(match, "user", "url_userinfo"))
    return spans


def _short_evocative_looks_secret(key: str, value: str) -> bool:
    """Valeur de 1 à 5 caractères sous un nom évocateur : secret ou code ?

    Deux filtres, dans cet ordre :

    1. `_CODE_LITERAL` : `session = None`, `auth = None`, `cert = null` — du
       code ordinaire, jamais un secret.
    2. **au moins un chiffre** et **au moins deux caractères** dans la
       valeur : un credential court est alphanumérique (`1234`, `abc12`,
       `x1`), alors qu'un mot de 1 à 5 lettres — ou une constante
       numérique d'un caractère (`token = 0`, `AUTHTYPE_SERVER = 0`) — est du
       vocabulaire de code. Mesuré sur 1,29 million de lignes de corpus
       (dépôt Heimdall + bibliothèques tierces) : 0 faux positif dans le
       dépôt lui-même, et 0 ligne précédemment masquée n'est démasquée par
       ce correctif.
    """
    if len(value) < MIN_SHORT_VALUE_LENGTH or _CODE_LITERAL.match(value):
        return False
    if not any(character.isdigit() for character in value):
        return False
    return _SECRET_KEY.search(key) is not None or _generic_name_carries_a_secret(key, value)


def _unquoted_name_is_evocative(key: str, value: str) -> bool:
    """Le nom suffit-il à lui seul, ou faut-il un indice dans la valeur ?"""
    if _SECRET_KEY.search(key):
        return True
    if _generic_name_carries_a_secret(key, value):
        return True
    return _GENERIC_SECRET_KEY.search(key) is not None and (
        len(value.split()) >= MIN_PASSPHRASE_WORDS or any(character in value for character in ",;")
    )


def _unquoted_value_has_credential_signal(value: str) -> bool:
    """Au moins un signal qui distingue un secret d'un mot de code."""
    if value.lower().startswith(_KNOWN_PREFIXES):
        return True
    if any(character.isdigit() for character in value):
        return True
    if any(character in value for character in ",;"):
        return True
    return len(value.split()) >= MIN_PASSPHRASE_WORDS


def _evocative_unquoted_looks_secret(key: str, value: str) -> bool:
    """Valeur non quotée à nom évocateur : jusqu'où masquer ?

    Le motif prend le reste de la ligne (espaces, `,`, `;` inclus), mais tout
    l'espace n'est pas un secret : une annotation de type (`api_key: str`), un
    appel de fonction (`password = get_password()`) ou un littéral
    (`session = None`) doivent rester lisibles. On exige donc, en plus d'un
    nom évocateur, un signal de credential : préfixe connu, chiffre, virgule
    ou point-virgule, plusieurs mots (phrase de passe) — et on refuse la
    ponctuation de code (`()[]{}`, `->`). Le commentaire éventuel n'est pas
    inclus dans la valeur masquée (le motif s'arrête avant ` #`), mais une
    valeur qui contient un `#` collé est masquée jusqu'au bout : une valeur
    en trop ne coûte rien, une queue de secret coûte une fuite.
    """
    candidate = value.strip()
    if not candidate:
        return False
    significant = candidate.split("#", 1)[0].rstrip()
    if len(significant) < MIN_EVOCATIVE_UNQUOTED_LENGTH or significant[0] in "\"'":
        return False
    if _ENV_REFERENCE.match(significant) or _CODE_LITERAL.match(significant):
        return False
    if not _unquoted_name_is_evocative(key, significant):
        return False
    if any(character in significant for character in "()[]{}") or "->" in significant:
        return False
    return _unquoted_value_has_credential_signal(significant)


def _evocative_unquoted_span(match: re.Match[str]) -> _Match:
    """Span du reste de ligne, espaces de fin exclus."""
    value = match.group("value").rstrip()
    start = match.start("value")
    return _Match(start, start + len(value), _secret_type(match.group("key"), value), len(value))


def _unclosed_quoted_spans(match: re.Match[str]) -> list[_Match]:
    """Valeur après guillemet ouvrant, si la ligne ne referme pas la citation.

    Un guillemet fermant non échappé est cherché dans la valeur (les `\\"`
    comptent comme échappés). S'il existe, les règles citées s'en chargent et
    cette règle de rattrapage ne produit aucun span : pas de double masquage
    ni de commentaire avalé. Sinon, un nom évocateur suffit à masquer jusqu'à
    la fin de la valeur, commentaire ` #` exclu.
    """
    value = match.group("value")
    quote = match.group("quote")
    index = 0
    while index < len(value):
        character = value[index]
        if character == "\\":
            index += 2
            continue
        if character == quote:
            return []
        index += 1
    value = value.rstrip()
    if not value or not _looks_like_secret(match.group("key"), value):
        return []
    start = match.start("value")
    return [_Match(start, start + len(value), _secret_type(match.group("key"), value), len(value))]


def _xml_sensitive_spans(match: re.Match[str]) -> list[_Match]:
    """`<password>…</password>` : seule la valeur intérieure est masquée."""
    key = match.group("tag")
    value = match.group("value")
    if not _looks_like_secret(key, value):
        return []
    return [_span_match(match, "value", _secret_type(key, value))]


def _define_spans(match: re.Match[str]) -> list[_Match]:
    """`define('DB_PASSWORD', '…')` : seule la valeur est masquée."""
    key = match.group("key")
    value = match.group("value")
    if not _looks_like_secret(key, value):
        return []
    return [_span_match(match, "value", _secret_type(key, value))]


def _netrc_spans(match: re.Match[str]) -> list[_Match]:
    """`.netrc` : `password <valeur>`, seule la valeur est masquée."""
    value = match.group("value")
    if not _looks_like_secret("password", value):
        return []
    return [_span_match(match, "value", _secret_type("password", value))]


def _cli_secret_option_spans(match: re.Match[str]) -> list[_Match]:
    """`--password <val>` : valeur citée ou nue, jamais le nom de l'option."""
    group = "quoted" if match.group("quoted") is not None else "value"
    value = match.group(group)
    key = match.group("key")
    if not _looks_like_secret(key, value):
        return []
    return [_span_match(match, group, _secret_type(key, value))]


def _cli_user_password_spans(match: re.Match[str]) -> list[_Match]:
    """`-u user:pass` : le mot de passe seul, l'utilisateur reste lisible."""
    value = match.group("value")
    if not _looks_like_secret("password", value):
        return []
    return [_span_match(match, "value", _secret_type("password", value))]


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
        [
            span
            for match in _URL_CREDENTIALS.finditer(text)
            for span in _url_credential_spans(match)
        ],
        [
            _span_match(match, "value", "url_userinfo")
            for match in _URL_USERINFO.finditer(text)
            if _url_userinfo_looks_secret(match.group("value"))
        ],
        [
            _span_match(match, "value", _secret_type(match.group("key"), match.group("value")))
            for match in _QUOTED_ASSIGNMENT.finditer(text)
            if _looks_like_secret(match.group("key"), match.group("value"))
        ],
        [
            _span_match(match, "value", _secret_type(match.group("key"), match.group("value")))
            for match in _SINGLE_QUOTED_ASSIGNMENT.finditer(text)
            if _looks_like_secret(match.group("key"), match.group("value"))
        ],
        [
            span
            for match in _UNCLOSED_QUOTED_VALUE.finditer(text)
            for span in _unclosed_quoted_spans(match)
        ],
        [
            span
            for match in _XML_SENSITIVE_ELEMENT.finditer(text)
            for span in _xml_sensitive_spans(match)
        ],
        [span for match in _DEFINE_ASSIGNMENT.finditer(text) for span in _define_spans(match)],
        [span for match in _NETRC_PASSWORD.finditer(text) for span in _netrc_spans(match)],
        [
            span
            for match in _CLI_SECRET_OPTION.finditer(text)
            for span in _cli_secret_option_spans(match)
        ],
        [
            span
            for match in _CLI_UNCLOSED_QUOTED_OPTION.finditer(text)
            for span in _unclosed_quoted_spans(match)
        ],
        [
            span
            for match in _CLI_USER_PASSWORD.finditer(text)
            for span in _cli_user_password_spans(match)
        ],
        [
            _evocative_unquoted_span(match)
            for match in _EVOCATIVE_UNQUOTED_VALUE.finditer(text)
            if _evocative_unquoted_looks_secret(match.group("key"), match.group("value"))
        ],
        [
            _span_match(match, "value", _secret_type(match.group("key"), match.group("value")))
            for match in _UNQUOTED_ASSIGNMENT.finditer(text)
            if _looks_like_secret(match.group("key"), match.group("value"))
        ],
        [
            _span_match(match, "value", _secret_type(match.group("key"), match.group("value")))
            for match in _EVOCATIVE_SHORT_VALUE.finditer(text)
            if _short_evocative_looks_secret(match.group("key"), match.group("value"))
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
