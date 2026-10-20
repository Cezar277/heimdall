# T22 — preuves pour la ligne SAMM

Périmètre : ticket #22 et ses sous-tickets #53 (interface Scanner/Finding),
#54 (signatures), #59 (exclusions), #60 (tests et mesure T21). Cette fiche
fournit les couples **module + ligne** et les permaliens du code testé ; elle
ne prétend pas modifier une feuille externe.

Révision du code testé : `ed6b72b5b0d742ed35cbcfb7cf40fad29a451b4e`
(commit `feat(scanner): détection regex, exclusions et Finding (#22)`).
Les permaliens épinglent cette révision de code, pas le commit de documentation
qui archive cette fiche : les fichiers de production et de tests ne changent
plus après ce SHA.

| Exigence vérifiée | Implémentation (module + ligne) | Test et preuve permanente | Résultat local |
|---|---|---|---|
| Sortie Finding conforme au contrat #14, sans valeur brute | [heimdall/scanner/detect.py:48–69](https://github.com/Cezar277/heimdall/blob/ed6b72b5b0d742ed35cbcfb7cf40fad29a451b4e/heimdall/scanner/detect.py#L48-L69) | [tests/test_scanner_detect.py:161–194](https://github.com/Cezar277/heimdall/blob/ed6b72b5b0d742ed35cbcfb7cf40fad29a451b4e/tests/test_scanner_detect.py#L161-L194) | Schéma draft 2020-12 validé ; 69 tests ciblés passés |
| Parcours déterministe d'un dépôt ou fichier, tri stable | [heimdall/scanner/detect.py:104–151](https://github.com/Cezar277/heimdall/blob/ed6b72b5b0d742ed35cbcfb7cf40fad29a451b4e/heimdall/scanner/detect.py#L104-L151) | [tests/test_scanner_detect.py:288–346](https://github.com/Cezar277/heimdall/blob/ed6b72b5b0d742ed35cbcfb7cf40fad29a451b4e/tests/test_scanner_detect.py#L288-L346) | Fichier unique, CRLF et ordre trié vérifiés |
| Signatures AWS, Stripe, Slack, GitHub, JWT, PEM | [heimdall/scanner/signatures.py:39–101](https://github.com/Cezar277/heimdall/blob/ed6b72b5b0d742ed35cbcfb7cf40fad29a451b4e/heimdall/scanner/signatures.py#L39-L101) | [tests/test_scanner_detect.py:106–212](https://github.com/Cezar277/heimdall/blob/ed6b72b5b0d742ed35cbcfb7cf40fad29a451b4e/tests/test_scanner_detect.py#L106-L212) | 9 détections positives ; 12 formes négatives sans alerte |
| Exclusions `.gitignore`, binaires, lockfiles, vendor | [heimdall/scanner/exclusions.py:20–131](https://github.com/Cezar277/heimdall/blob/ed6b72b5b0d742ed35cbcfb7cf40fad29a451b4e/heimdall/scanner/exclusions.py#L20-L131) | [tests/test_scanner_detect.py:216–286](https://github.com/Cezar277/heimdall/blob/ed6b72b5b0d742ed35cbcfb7cf40fad29a451b4e/tests/test_scanner_detect.py#L216-L286) | `.env`/`.pem`/`requirements.txt` scannés ; vendor/lock/binaire ignorés |
| Confinement : refus des liens, non-réguliers et chemins hors contrat | [heimdall/scanner/detect.py:72–102](https://github.com/Cezar277/heimdall/blob/ed6b72b5b0d742ed35cbcfb7cf40fad29a451b4e/heimdall/scanner/detect.py#L72-L102), [heimdall/scanner/detect.py:154–227](https://github.com/Cezar277/heimdall/blob/ed6b72b5b0d742ed35cbcfb7cf40fad29a451b4e/heimdall/scanner/detect.py#L154-L227) | [tests/test_scanner_detect.py:268–326](https://github.com/Cezar277/heimdall/blob/ed6b72b5b0d742ed35cbcfb7cf40fad29a451b4e/tests/test_scanner_detect.py#L268-L326) | Symlinks ignorés, FIFO/nom invalide refusés |
| Fail-closed : entrée illisible, > 1 Mio ou racine absente | [heimdall/scanner/detect.py:182–247](https://github.com/Cezar277/heimdall/blob/ed6b72b5b0d742ed35cbcfb7cf40fad29a451b4e/heimdall/scanner/detect.py#L182-L247) | [tests/security/test_scanner_bypass.py:32–74](https://github.com/Cezar277/heimdall/blob/ed6b72b5b0d742ed35cbcfb7cf40fad29a451b4e/tests/security/test_scanner_bypass.py#L32-L74) | `ScanError` statique, aucun reflet d'entrée |
| Empreinte HMAC-SHA-256 locale, clé hors dépôt | [heimdall/scanner/hashing.py:116–144](https://github.com/Cezar277/heimdall/blob/ed6b72b5b0d742ed35cbcfb7cf40fad29a451b4e/heimdall/scanner/hashing.py#L116-L144) | [tests/test_scanner_detect.py:152–159](https://github.com/Cezar277/heimdall/blob/ed6b72b5b0d742ed35cbcfb7cf40fad29a451b4e/tests/test_scanner_detect.py#L152-L159), [tests/test_scanner_detect.py:355–400](https://github.com/Cezar277/heimdall/blob/ed6b72b5b0d742ed35cbcfb7cf40fad29a451b4e/tests/test_scanner_detect.py#L355-L400) | Valeur brute absente de la sérialisation ; clé `0600` |
| Métadonnée d'entropie 0–8 bits/octet | [heimdall/scanner/entropy.py:16–32](https://github.com/Cezar277/heimdall/blob/ed6b72b5b0d742ed35cbcfb7cf40fad29a451b4e/heimdall/scanner/entropy.py#L16-L32) | [tests/test_scanner_detect.py:348–353](https://github.com/Cezar277/heimdall/blob/ed6b72b5b0d742ed35cbcfb7cf40fad29a451b4e/tests/test_scanner_detect.py#L348-L353) | Vide = 0, deux symboles = 1, plafond 8 |
| Anti-ReDoS : lignes proches de 1 Mio | [heimdall/scanner/signatures.py:39–101](https://github.com/Cezar277/heimdall/blob/ed6b72b5b0d742ed35cbcfb7cf40fad29a451b4e/heimdall/scanner/signatures.py#L39-L101) | [tests/test_scanner_detect.py:402–419](https://github.com/Cezar277/heimdall/blob/ed6b72b5b0d742ed35cbcfb7cf40fad29a451b4e/tests/test_scanner_detect.py#L402-L419) | 7 lignes de ~1 Mio, chacune < 10 s (mesure locale) |
| Mesure T21 sur le jeu piège, xfail retiré | [tests/test_trap_acceptance.py:204–209](https://github.com/Cezar277/heimdall/blob/ed6b72b5b0d742ed35cbcfb7cf40fad29a451b4e/tests/test_trap_acceptance.py#L204-L209) | [tests/support/trap_corpus.py:81–121](https://github.com/Cezar277/heimdall/blob/ed6b72b5b0d742ed35cbcfb7cf40fad29a451b4e/tests/support/trap_corpus.py#L81-L121) | `core` précision 1,00 / rappel 1,00 |

## Résultats locaux

Environnement : Linux, Python 3.14.6, venv du dépôt.

```text
.venv/bin/python -m pytest tests/test_scanner_detect.py \
  tests/test_trap_acceptance.py tests/security/test_scanner_bypass.py \
  --cov=heimdall.scanner --cov-branch --cov-report=term-missing \
  --cov-fail-under=85
69 passed
heimdall/scanner : 89,14 % (branches incluses), seuil 85 % atteint

.venv/bin/python -m pytest --cov=heimdall --cov-branch \
  --cov-report=term-missing --cov-fail-under=85
suite complète : code retour 0
couverture Heimdall : 96,77 %

.venv/bin/python tests/measure_trap.py
core : tp=10, fp=0, fn=0, precision=1.0, recall=1.0
all  : tp=10, fp=0, fn=6, recall=0.625 (6 limites connues T21)

.venv/bin/ruff check heimdall tests        # All checks passed
.venv/bin/mypy heimdall tests/contracts/fastapi_contract_fixture.py
                                            # Success: no issues found
.venv/bin/bandit -r heimdall -q             # aucun rapport d'erreur
```

Les six positions obfusquées restent des `limite_connue` : le scanner de
signatures ne décode pas base64 et n'analyse pas le flux des variables
(voir [scanner.md](scanner.md#limites-connues-honnetes)). Elles ne sont pas
comptées dans le seuil principal T21.

## Relecture et PR

- PR : à ouvrir sur la branche
  `22-t22-scanner-regex-de-signatures-et-exclusions` avec `Closes #22`.
- Relecture inter-domaines et check `CI (/ci)` restent requis avant fusion.
- La feuille SAMM externe n'est pas accessible depuis le dépôt ; reporter la
  ligne ci-dessus avec le lien de la PR et le SHA `ed6b72b5b0d742ed35cbcfb7cf40fad29a451b4e`.
