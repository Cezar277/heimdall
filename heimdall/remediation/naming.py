"""Validation des noms de variables d'environnement (T30.2, #84).

Le nom est proposé par le LLM : c'est une entrée **non fiable** qui finira
dans du code et dans un fichier ``.env``. Toute entrée passe donc par
:func:`validate_variable_name` (grammaire fermée + denylist système) avant
usage, et les doublons sont levés par :func:`deduplicate_variable_name`
(suffixes ``_2``, ``_3``…).

Ce module est la **source unique** de la politique de nommage côté
remédiation : ``cli/vault_client.py`` délègue sa denylist ici (mêmes
constantes, même fonction) au lieu de la dupliquer.
"""

from __future__ import annotations

import itertools
from collections.abc import Iterable
from typing import Final

from heimdall.remediation.templates import _VARIABLE, MAX_VARIABLE_CHARS, TemplateError

#: Longueur maximale d'un nom : un suffixe ``_N`` doit encore tenir dedans.
_MAX_NAME_LENGTH: Final[int] = MAX_VARIABLE_CHARS

#: Nombre maximal de noms existants lus lors d'une déduplication.
_MAX_TAKEN: Final[int] = 10_000

#: Noms exacts refusés : variables système/shell dont l'écrasement détournerait
#: l'exécution des processus enfants (voir ticket #84).
DANGEROUS_ENV_EXACT: Final[frozenset[str]] = frozenset(
    {
        "PATH",
        "SHELL",
        "IFS",
        "BASH_ENV",
        "BASHOPTS",
        "SHELLOPTS",
        "ENV",
        "PS0",
        "PS1",
        "PS2",
        "PS3",
        "PS4",
        "PROMPT_COMMAND",
        "ZDOTDIR",
        "GLIBC_TUNABLES",
        "GCONV_PATH",
        "LOCPATH",
        "NLSPATH",
        "HOSTALIASES",
        "CORE_PAGER",
        "PAGER",
        "MANPAGER",
        "LESSOPEN",
        "LESSCLOSE",
        "EDITOR",
        "VISUAL",
        "SUDO_ASKPASS",
        "SSH_ASKPASS",
        "SSH_ASKPASS_REQUIRE",
        "SSH_AUTH_SOCK",
        "SSH_ORIGINAL_COMMAND",
        "KUBECONFIG",
        "GOBIN",
        "GOCACHE",
        "GOFLAGS",
        "GOMODCACHE",
        "GOPATH",
        "GOROOT",
        "GOTOOLCHAIN",
        "CC",
        "CXX",
        "CPP",
        "CFLAGS",
        "CPPFLAGS",
        "CXXFLAGS",
        "LDFLAGS",
        "MAKEFLAGS",
        "MFLAGS",
        "HOME",
        "TMPDIR",
        "TMP",
        "TEMP",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
        "REQUESTS_CA_BUNDLE",
        "CURL_CA_BUNDLE",
        # Comportement du shell enfant (LOW) : un Vault compromis ne doit pas
        # détourner les `cd`/globs/historique des scripts enfants de `run`.
        # La racine de confiance reste l'allowlist locale (seuls les noms listés
        # localement sont demandés) ; la denylist n'est qu'une défense en
        # profondeur. Tout nom listé localement (--name/.env.example/.env) est
        # une entrée de confiance : ne pas y inscrire de variable système.
        "CDPATH",
        "GLOBIGNORE",
        "HISTFILE",
        "MAILCAPS",
        # État du shell/environnement d'exécution (LOW) : chemins terminfo et
        # cible venv — détournement des enfants via TERMINFO/TERMPATH/VIRTUAL_ENV.
        "TERMINFO",
        "TERMPATH",
        "VIRTUAL_ENV",
        "INPUTRC",
        "TERM",
        "TZ",
        "TERMCAP",
        "LUA_PATH",
        "LUA_CPATH",
        "LUA_INIT",
    }
)

#: Préfixes refusés : familles d'outils, runtimes et chargeurs dynamiques dont
#: la redéfinition détournerait les enfants (compilateurs, paquets, credentials).
DANGEROUS_ENV_PREFIXES: Final[tuple[str, ...]] = (
    "LD_",
    "DYLD_",
    "PYTHON",
    "NODE_",
    "NPM_",
    "YARN_",
    "PNPM_",
    "RUBY",
    "PERL",
    "GIT_",
    "BASH_",
    "PROMPT_",
    "SYSTEMD_",
    "JAVA_",
    "JDK_",
    "_JAVA_",
    "MAVEN_",
    "GRADLE_",
    "DOTNET_",
    "COMPOSE_",
    "DOCKER_",
    "AWS_",
    "TF_",
    "KUBE_",
    "HELM_",
    "XDG_",
    "CARGO_",
    "RUSTUP_",
    "RUSTC_",
    "OPENSSL_",
    "MALLOC_",
    # Shadowing credential/processus : un Vault compromis ne doit pas
    # écraser la credential du fils via `{**os.environ, **injected}`.
    "HEIMDALL_",
    # Gestionnaires de runtimes/paquets (LOW) : redirection d'installations
    # ou d'interpréteurs via l'enfant (BUN_/DENO_/UV_/PIP_/BUNDLE_/GEM_/CONDA_).
    "BUN_",
    "DENO_",
    "UV_",
    "PIP_",
    "BUNDLE_",
    "GEM_",
    "CONDA_",
)


def is_dangerous_env_var(name: object) -> bool:
    """Vrai si un nom de variable est dangereux (fail-closed : non-str = dangereux)."""
    if not isinstance(name, str):
        return True
    upper = name.upper()
    if upper in DANGEROUS_ENV_EXACT or upper.endswith("_PROXY"):
        return True
    if upper in {
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "NO_PROXY",
        "SSLKEYLOGFILE",
        "CLASSPATH",
        "PHPRC",
        "PHP_INI_SCAN_DIR",
        "CURL_HOME",
        "WGETRC",
        "GNUPGHOME",
        "ELECTRON_RUN_AS_NODE",
        "NODE_OPTIONS",
    }:
        return True
    return any(upper.startswith(prefix) for prefix in DANGEROUS_ENV_PREFIXES)


#: Noms exacts bloqués à l'exécution (`heimdall run`) et dans le Vault (`push`/`pull`).
EXECUTION_DANGEROUS_ENV_EXACT: Final[frozenset[str]] = DANGEROUS_ENV_EXACT | frozenset(
    {
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "NO_PROXY",
        "SSLKEYLOGFILE",
        "CLASSPATH",
        "PHPRC",
        "PHP_INI_SCAN_DIR",
        "CURL_HOME",
        "WGETRC",
        "GNUPGHOME",
        "ELECTRON_RUN_AS_NODE",
        "NODE_OPTIONS",
        "GIT_SSH_COMMAND",
        "DOCKER_HOST",
        "NPM_CONFIG_REGISTRY",
        "PIP_INDEX_URL",
        "TF_CLI_CONFIG_FILE",
        "MAVEN_OPTS",
        "GRADLE_OPTS",
        "DOTNET_STARTUP_HOOKS",
        "COMPOSE_FILE",
        "CARGO_HOME",
        "BUN_INSTALL",
        "DENO_DIR",
        "UV_PYTHON",
        "BUNDLE_GEMFILE",
        "GEM_HOME",
        "CONDA_ENVS_PATH",
    }
)

#: Variables légitimes autorisées explicitement dans `vault push/pull/run`
#: malgré l'appartenance de leur préfixe à la denylist LLM/système.
ALLOWED_EXEC_SECRET_EXACT: Final[frozenset[str]] = frozenset(
    {
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "AWS_SECURITY_TOKEN",
        "DOCKER_PASSWORD",
        "DOCKER_TOKEN",
        "DOCKER_USERNAME",
        "DOCKER_REGISTRY_PASSWORD",
        "NPM_TOKEN",
        "NPM_AUTH_TOKEN",
        "GIT_TOKEN",
        "GITHUB_TOKEN",
        "GITLAB_TOKEN",
        "GIT_PASSWORD",
        "PIP_PASSWORD",
        "PIP_TOKEN",
        "KUBE_TOKEN",
        "KUBE_PASSWORD",
        "NODE_ENV",
    }
)

#: Préfixes de variables de secrets applicatifs autorisés dans `vault push/pull/run`
#: (ex. `TF_VAR_*`), tandis que les variables de configuration d'outil (`TF_DATA_DIR`,
#: `TF_CLI_CONFIG_FILE`, `GIT_DIR`, `NODE_PATH`, `AWS_CONFIG_FILE`, etc.) restent bloquées.
ALLOWED_EXEC_SECRET_PREFIXES: Final[tuple[str, ...]] = ("TF_VAR_",)

#: Préfixes bloqués à l'exécution (`heimdall run`) : reprend la denylist
#: complète (chargeurs dynamiques, runtimes, redirecteurs d'outils).
EXECUTION_DANGEROUS_ENV_PREFIXES: Final[tuple[str, ...]] = DANGEROUS_ENV_PREFIXES


def is_dangerous_exec_env_var(name: object) -> bool:
    """Vrai si un nom est interdit pour `vault push/pull/run` (fail-closed)."""
    if not isinstance(name, str):
        return True
    upper = name.upper()
    if upper in ALLOWED_EXEC_SECRET_EXACT:
        return False
    if any(upper.startswith(prefix) for prefix in ALLOWED_EXEC_SECRET_PREFIXES):
        return False
    if upper in EXECUTION_DANGEROUS_ENV_EXACT:
        return True
    return is_dangerous_env_var(name)


def validate_variable_name(name: object) -> str:
    """Valide un nom proposé (LLM : entrée non fiable) ; lève ``TemplateError`` sinon.

    Grammaire fermée ``^[A-Z][A-Z0-9_]{1,63}$`` (donc sans retour à la ligne
    ni injection ``.env`` possible) + denylist système. Erreur statique,
    jamais de reflet de l'entrée.
    """
    if not isinstance(name, str):
        raise TemplateError
    if _VARIABLE.fullmatch(name) is None:
        raise TemplateError
    if is_dangerous_env_var(name):
        raise TemplateError
    return name


def deduplicate_variable_name(desired: str, taken: Iterable[str]) -> str:
    """Rend un nom validé unique en ajoutant ``_2``, ``_3``… si besoin.

    ``desired`` est d'abord validé (donc un nom dangereux ou mal formé est
    rejeté, jamais « corrigé » en un autre nom). ``taken`` est lu au plus
    ``_MAX_TAKEN + 1`` éléments (un générateur infini ne bloque pas) et la
    recherche est bornée : au-delà, ``TemplateError``.
    """
    base = validate_variable_name(desired)
    names = list(itertools.islice(taken, _MAX_TAKEN + 1))
    if len(names) > _MAX_TAKEN:
        raise TemplateError
    used = set(names)
    if base not in used:
        return base
    for n in range(2, len(used) + 3):
        candidate = f"{base}_{n}"
        if len(candidate) > _MAX_NAME_LENGTH:
            raise TemplateError
        if candidate in used or is_dangerous_env_var(candidate):
            continue
        return candidate
    raise TemplateError
