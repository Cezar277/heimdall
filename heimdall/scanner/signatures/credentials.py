"""Identifiants contextualisés, sans dépendance envers le masquage MCP (#230)."""

import re
from typing import Final

from heimdall.scanner.entropy import shannon_entropy
from heimdall.scanner.errors import ScanError
from heimdall.scanner.signatures.model import Rule, RuleMatch, make_rule

_NAME = (
    r"(?i)(?<![A-Za-z0-9_])[\"']?(?P<key>[A-Za-z0-9_.-]{0,48}"
    r"(?:password|passwd|pwd|secret|token(?!izer\b)|api[_-]?key|auth(?!or(?:s|ity|ities)?\b))"
    r"[A-Za-z0-9_.-]{0,48})[\"']?[ \t]{0,32}[:=][ \t]{0,32}"
)
_NON_VALUES: Final[frozenset[str]] = frozenset(
    {
        "none",
        "null",
        "true",
        "false",
        "undefined",
        "string",
        "str",
        "bytes",
        "int",
        "bool",
        "basic",
        "bearer",
        "your_key_here",
    }
)
MIN_CONTEXT_ENTROPY: Final[float] = 1.5


def _literal_value(value: str, *, quoted: bool) -> bool:
    lowered = value.casefold()
    if lowered == "your_key_here" or value.startswith(("${", "{{", "<", "***")):
        return False
    if not quoted and (
        lowered in _NON_VALUES
        or lowered.startswith(("os.environ", "process.env", "getenv(", "get_password("))
    ):
        return False
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError:
        raise ScanError("ligne d'analyse non conforme au contrat") from None
    return shannon_entropy(encoded) >= MIN_CONTEXT_ENTROPY


class LiteralRule(Rule):
    """Règle déclarative dont les valeurs doivent être des littéraux plausibles."""

    __slots__ = ()

    def matches(self, line: str) -> tuple[RuleMatch, ...]:
        return tuple(
            match
            for match in super().matches(line)
            if _literal_value(match.group("value"), quoted=not self.id.endswith("_unquoted"))
        )


def _assignment(quote: str, name: str) -> Rule:
    # Classes bornées, séparées par style de citation : aucun backreference
    # ni quantificateur imbriqué, et la ponctuation fait partie de la valeur.
    value = r"[^\s\"'`,;)}\]]{4,256}" if not quote else "[^" + quote + r"\r\n]{4,256}"
    pattern = _NAME + re.escape(quote) + r"(?P<value>" + value + ")" + re.escape(quote)
    if not quote:
        pattern += r"(?=$|[\s,;)}\]])"
    finding_type = "credential"
    return LiteralRule(
        id=f"credential_{name}",
        description="Nom de clé sensible et valeur littérale, ponctuation comprise.",
        regex=pattern,
        secret_type=finding_type,
        positive_example="DB_PASSWORD=" + quote + "FAKE!only#42" + quote,
        negative_example="DB_PASSWORD=" + quote + "${ENV_VAR}" + quote,
    )


RULES: Final[tuple[Rule, ...]] = (
    make_rule(
        id="url_password",
        description="Mot de passe dans le userinfo d'une URL.",
        regex=(
            r"[A-Za-z][A-Za-z0-9+.-]{0,16}://[^/@:\s\"']{1,64}:"
            r"(?P<value>[^/@\s\"']{1,256})@(?=[A-Za-z0-9]|\[)"
        ),
        finding_type="url_credentials",
        positive="postgres://user:" + "FAKE-only" + "@host/db",
        negative="postgres://host/db",
    ),
    make_rule(
        id="authorization_header",
        description="En-tête Authorization Basic ou Bearer.",
        regex=(
            r"(?i)(?<![A-Za-z0-9_])authorization[\"']?[ \t]{0,16}[:=][ \t]{0,16}"
            r"[\"']?(?:Basic|Bearer)[ \t]{1,16}(?P<value>[A-Za-z0-9._~+/=-]{4,512})"
            r"(?![A-Za-z0-9._~+/=-])"
        ),
        finding_type="authorization",
        positive="Authorization: Basic " + "RkFLRTpPTkxZ",
        negative="Authorization: None",
    ),
    _assignment('"', "double_quoted"),
    _assignment("'", "single_quoted"),
    _assignment("", "unquoted"),
)
