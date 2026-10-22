"""Famille AWS et cloud (#55).

Chaque motif est ancré sur un préfixe publié ou sur un nom de paramètre
explicite. Une chaîne de 40 caractères sans préfixe ni mot-clé n'est jamais
signalée : ce serait un générateur de faux positifs, pas une signature.

Les identifiants d'accès AWS sont les quatre préfixes reconnus par le ticket
(AKIA, ASIA, ABIA, ACCA). La clé secrète est ancrée sur le **nom du
paramètre** qui la porte : `aws_secret_access_key`, `aws_secret_key` ou
`secret_access_key` (casse ignorée). Ces trois noms sont les seuls acceptés,
et ils sont déclarés à la fois dans la regex et dans les mots-clés : un
mot-clé sans effet dans le motif serait une couverture annoncée plus large
que le code. Les autres fournisseurs cloud (GCP, Azure) sont hors du
périmètre de ce ticket : leurs formats seront ajoutés au registre, sans
toucher au moteur, quand ils seront spécifiés.
"""

from __future__ import annotations

from typing import Final

from heimdall.scanner.signatures.model import Rule, make_rule

# Valeurs synthétiques : aucune clé émise, aucun appel fournisseur.
_AWS_ACCESS_KEY_ID = "AKIA" + "IOSFODNN7EXAMPLE"
_AWS_CREDENTIAL_EXAMPLE = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

RULES: Final[tuple[Rule, ...]] = (
    make_rule(
        id="aws_access_key_id",
        description="Identifiant de clé d'accès AWS (AKIA/ASIA/ABIA/ACCA + 16 caractères).",
        regex=(
            r"(?P<value>(?<![A-Za-z0-9])(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}"
            r"(?![A-Za-z0-9]))"
        ),
        finding_type="aws",
        keywords=(),
        positive=f'AWS_ACCESS_KEY_ID = "{_AWS_ACCESS_KEY_ID}"',
        negative='AWS_ACCESS_KEY_ID = "AKIA1234"',
    ),
    make_rule(
        id="aws_secret_access_key",
        description=(
            "Clé secrète AWS associée à un nom de paramètre "
            "(aws_secret_access_key, aws_secret_key ou secret_access_key)."
        ),
        # L'alternance couvre **exactement** les trois noms déclarés en
        # `keywords` : un mot-clé sans effet dans la regex serait une
        # couverture annoncée plus large que le code (faux sentiment de
        # sécurité, puis faux négatif sur un nom de paramètre réel).
        # L'ordre place le nom le plus long d'abord : `aws_secret_access_key`
        # est consommé en entier, jamais tronqué en `secret_access_key`.
        # Le guillemet fermant et le crochet de subscription sont optionnels
        # après le nom : les écritures les plus fréquentes en dépôt sont
        # `"aws_secret_access_key": "…"` (JSON/TOML) et
        # `os.environ["AWS_SECRET_ACCESS_KEY"] = "…"` (Python). Sans eux, la
        # règle ratait toutes ces formes.
        regex=(
            r"(?i:(?:aws_secret_access_key|aws_secret_key|secret_access_key))"
            r"[\"']?\]?\s*[:=]\s*[\"']?"
            r"(?P<value>[A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])"
        ),
        finding_type="aws",
        keywords=("aws_secret_access_key", "aws_secret_key", "secret_access_key"),
        positive=f'aws_secret_access_key = "{_AWS_CREDENTIAL_EXAMPLE}"',
        negative='aws_secret_access_key = "changeme"',
    ),
)
