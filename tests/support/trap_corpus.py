"""Corpus T21 synthétique, indépendant du scanner et sans accès réseau."""

import base64
import hashlib
import json
from pathlib import Path

from jsonschema import Draft202012Validator

from heimdall.scanner.detect import find_candidates
from support.fake_secrets import fake_pem_body, fake_token

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "tests" / "fixtures" / "trap_repo"


def load_expected():
    """Oracle versionné: jamais recalculé depuis les résultats du scanner."""
    return json.loads((FIXTURES / "expected.json").read_text(encoding="utf-8"))


def _replacements():
    def b64(value):
        return base64.urlsafe_b64encode(value).decode().rstrip("=")

    stripe = fake_token("sk_" + "live_", 24)
    aws = "AK" + "IA" + hashlib.sha256(b"heimdall-t21-aws").hexdigest()[:16].upper()
    jwt = ".".join(
        [
            b64(b'{"alg":"HS256","typ":"JWT"}'),
            b64(b'{"sub":"heimdall-factice","exp":0}'),
            b64(hashlib.sha256(b"heimdall-invalid-signature").digest()),
        ]
    )
    return {
        "AWS": aws,
        "STRIPE": stripe,
        "PAT": fake_token("gh" + "p_", 36),
        "JWT": jwt,
        "PEM": "-----BEGIN "
        + "RSA PRIVATE KEY-----\\n"
        + fake_pem_body().replace("\n", "\\n")
        + "\\n-----END "
        + "RSA PRIVATE KEY-----",
        "B64": base64.b64encode(stripe.encode()).decode(),
        "LEFT": stripe[:5],
        "RIGHT": stripe[5:],
        "SHA256": hashlib.sha256(b"public package contents").hexdigest(),
        "COMMIT": hashlib.sha1(b"public commit", usedforsecurity=False).hexdigest(),
        "INTEGRITY": base64.b64encode(hashlib.sha512(b"public package").digest()).decode(),
    }


def build_corpus(destination: Path):
    """Matérialise les gabarits dans un dossier temporaire vide, sans les exécuter."""
    if destination.exists() and any(destination.iterdir()):
        raise ValueError("Le dossier du corpus doit être vide")
    source_root = FIXTURES.resolve()
    destination_root = destination.resolve()
    for template in sorted(FIXTURES.rglob("*.tmpl")):
        if template.is_symlink() or not template.resolve().is_relative_to(source_root):
            raise ValueError("Gabarit hors corpus ou lien symbolique interdit")
        target = destination / template.relative_to(FIXTURES).with_suffix("")
        if not target.resolve().is_relative_to(destination_root):
            raise ValueError("Destination du gabarit hors corpus temporaire")
        content = template.read_text(encoding="utf-8")
        for key, value in _replacements().items():
            content = content.replace("{{" + key + "}}", value)
        if "{{" in content:
            raise ValueError("Marqueur de fixture non résolu")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8", newline="\n")


def measure(expected, findings):
    """Compare les positions uniques; les alertes hors oracle sont aussi des FP.

    Les limites connues restent des FN dans le total. Seules leurs positions
    sont retirées du seuil principal, jamais un fichier entier.
    """
    positives = {(c["file"], c["line"]) for c in expected if c["leak"]}
    limits = {(c["file"], c["line"]) for c in expected if c["group"] == "obfuscated"}
    predicted = {(f["file"], f["line"]) for f in findings}

    def scores(truth, observed):
        tp, fp, fn = len(truth & observed), len(observed - truth), len(truth - observed)
        return {
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "precision": tp / (tp + fp) if tp + fp else 0.0,
            "recall": tp / (tp + fn) if tp + fn else 0.0,
        }

    return {
        "core": scores(positives - limits, predicted - limits),
        "all": scores(positives, predicted),
        "known_limits_missed": [list(p) for p in sorted(limits - predicted)],
    }


def scan_corpus(destination: Path):
    """Appelle le vrai scanner; toute erreur ou sortie hors contrat échoue."""
    build_corpus(destination)
    findings = find_candidates(str(destination))
    if not isinstance(findings, list):
        raise ValueError("Le scanner doit retourner une liste de Finding")
    validator = Draft202012Validator(
        json.loads((ROOT / "schemas" / "finding.schema.json").read_text(encoding="utf-8"))
    )
    for finding in findings:
        # Ne pas afficher ValidationError: elle pourrait refléter un secret.
        if not validator.is_valid(finding):
            raise ValueError("Finding non conforme au contrat T14")
    return measure(load_expected(), findings)
