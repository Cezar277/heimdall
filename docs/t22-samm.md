# T22 — preuves pour la ligne SAMM

Périmètre : ticket #22 et ses sous-tickets #53 (interface Scanner/Finding),
#54 (signatures), #59 (exclusions), #60 (tests et mesure T21). Cette fiche
fournit les couples **module + ligne** et les permaliens du code testé ; elle
ne prétend pas modifier une feuille externe.

Révision du code testé : `01dc80cca8ccfc00c5fed21adadda8c8cdb02f80`
(commit `fix(scanner): déduplication par valeur, décodage UTF-16/32, clé HMAC
durcie (#22)`), qui porte les correctifs de la relecture « REQUEST CHANGES ».
Révision de la documentation : `81a67dfd7978c9ed1dc8ceab83f9f35b57389a12`.

Les permaliens de code épinglent `01dc80c…` ; ceux de documentation épinglent
`81a67df…`. Aucun fichier de production ni de test ne change après
`01dc80c…` : contrôle effectué avec
`git diff 01dc80cca8ccfc00c5fed21adadda8c8cdb02f80 HEAD -- heimdall tests`
(sortie vide au moment de l'archivage de cette fiche).

| Exigence vérifiée | Implémentation (module + ligne) | Test et preuve permanente | Résultat local |
|---|---|---|---|
| Sortie Finding conforme au contrat #14, sans valeur brute | [heimdall/scanner/detect.py:48–69](https://github.com/Cezar277/heimdall/blob/01dc80cca8ccfc00c5fed21adadda8c8cdb02f80/heimdall/scanner/detect.py#L48-L69) | [tests/test_scanner_detect.py:154–177](https://github.com/Cezar277/heimdall/blob/01dc80cca8ccfc00c5fed21adadda8c8cdb02f80/tests/test_scanner_detect.py#L154-L196) | Schéma draft 2020-12 validé ; valeur brute absente de la sérialisation |
| Aucun candidat perdu : deux valeurs distinctes, même type, même ligne | [heimdall/scanner/detect.py:233–255](https://github.com/Cezar277/heimdall/blob/01dc80cca8ccfc00c5fed21adadda8c8cdb02f80/heimdall/scanner/detect.py#L233-L255) | [tests/test_scanner_detect.py:216–243](https://github.com/Cezar277/heimdall/blob/01dc80cca8ccfc00c5fed21adadda8c8cdb02f80/tests/test_scanner_detect.py#L216-L243) | 2 Findings, 2 empreintes distinctes ; valeur identique dédupliquée |
| Parcours déterministe d'un dépôt ou fichier, tri stable | [heimdall/scanner/detect.py:134–159](https://github.com/Cezar277/heimdall/blob/01dc80cca8ccfc00c5fed21adadda8c8cdb02f80/heimdall/scanner/detect.py#L134-L159) | [tests/test_scanner_detect.py:461–476](https://github.com/Cezar277/heimdall/blob/01dc80cca8ccfc00c5fed21adadda8c8cdb02f80/tests/test_scanner_detect.py#L461-L476) | Fichier unique, CRLF et ordre trié vérifiés |
| Signatures AWS (`AKIA`/`ASIA`/`ABIA`/`ACCA`), Stripe, Slack, GitHub, JWT (charge 64 Kio), PEM | [heimdall/scanner/signatures.py:39–83](https://github.com/Cezar277/heimdall/blob/01dc80cca8ccfc00c5fed21adadda8c8cdb02f80/heimdall/scanner/signatures.py#L39-L83) | [tests/test_scanner_detect.py:108–243](https://github.com/Cezar277/heimdall/blob/01dc80cca8ccfc00c5fed21adadda8c8cdb02f80/tests/test_scanner_detect.py#L108-L243) | 4 préfixes AWS, 9 détections positives ; 12 formes négatives sans alerte |
| Exclusions `.gitignore`, lockfiles, vendor, binaires connus ; `env/` **scanné** | [heimdall/scanner/exclusions.py:25–133](https://github.com/Cezar277/heimdall/blob/01dc80cca8ccfc00c5fed21adadda8c8cdb02f80/heimdall/scanner/exclusions.py#L25-L133) | [tests/test_scanner_detect.py:248–305](https://github.com/Cezar277/heimdall/blob/01dc80cca8ccfc00c5fed21adadda8c8cdb02f80/tests/test_scanner_detect.py#L248-L305) | `.env`/`.pem`/`requirements.txt` scannés ; vendor/lock/binaire ignorés ; `.venv`/`venv`/`virtualenv` exclus, `env/` non |
| UTF-16/UTF-32 (BOM et sans BOM) décodés ; NUL ambigu fail-closed | [heimdall/scanner/exclusions.py:136–259](https://github.com/Cezar277/heimdall/blob/01dc80cca8ccfc00c5fed21adadda8c8cdb02f80/heimdall/scanner/exclusions.py#L136-L259) | [tests/test_scanner_detect.py:307–366](https://github.com/Cezar277/heimdall/blob/01dc80cca8ccfc00c5fed21adadda8c8cdb02f80/tests/test_scanner_detect.py#L307-L366) | 8 encodages détectés ; NUL non décodable → `ScanError` ; binaire à signature connue → ignoré |
| Confinement : refus des liens, non-réguliers et chemins hors contrat | [heimdall/scanner/detect.py:72–102](https://github.com/Cezar277/heimdall/blob/01dc80cca8ccfc00c5fed21adadda8c8cdb02f80/heimdall/scanner/detect.py#L72-L102), [heimdall/scanner/detect.py:161–188](https://github.com/Cezar277/heimdall/blob/01dc80cca8ccfc00c5fed21adadda8c8cdb02f80/heimdall/scanner/detect.py#L161-L188) | [tests/test_scanner_detect.py:373–432](https://github.com/Cezar277/heimdall/blob/01dc80cca8ccfc00c5fed21adadda8c8cdb02f80/tests/test_scanner_detect.py#L373-L432) | Symlinks ignorés, FIFO/nom invalide refusés |
| Fail-closed : entrée illisible, > 1 Mio, racine absente, fichier modifié pendant la lecture | [heimdall/scanner/detect.py:189–231](https://github.com/Cezar277/heimdall/blob/01dc80cca8ccfc00c5fed21adadda8c8cdb02f80/heimdall/scanner/detect.py#L189-L231) | [tests/security/test_scanner_bypass.py:32–74](https://github.com/Cezar277/heimdall/blob/01dc80cca8ccfc00c5fed21adadda8c8cdb02f80/tests/security/test_scanner_bypass.py#L32-L74), [tests/test_scanner_detect.py:405–459](https://github.com/Cezar277/heimdall/blob/01dc80cca8ccfc00c5fed21adadda8c8cdb02f80/tests/test_scanner_detect.py#L405-L459) | `ScanError` statique, aucun reflet d'entrée |
| Clé HMAC locale durcie : `0600`, propriétaire vérifié, parent `0700`, parent symlink refusé, **pas de clé éphémère** | [heimdall/scanner/hashing.py:57–185](https://github.com/Cezar277/heimdall/blob/01dc80cca8ccfc00c5fed21adadda8c8cdb02f80/heimdall/scanner/hashing.py#L57-L185) | [tests/test_scanner_detect.py:487–648](https://github.com/Cezar277/heimdall/blob/01dc80cca8ccfc00c5fed21adadda8c8cdb02f80/tests/test_scanner_detect.py#L487-L648) | `0644`, autre UID, stockage indisponible, écriture partielle → `ScanError` |
| Empreinte HMAC stdlib : invariant 5 intact (`cryptography`/`argon2` confinés au Vault) | [docs/adr/002-stack-python.md:75–82](https://github.com/Cezar277/heimdall/blob/81a67dfd7978c9ed1dc8ceab83f9f35b57389a12/docs/adr/002-stack-python.md#L75-L82), [docs/adr/001-finding-et-etats.md:22–27](https://github.com/Cezar277/heimdall/blob/81a67dfd7978c9ed1dc8ceab83f9f35b57389a12/docs/adr/001-finding-et-etats.md#L22-L28) | [tests/test_crypto_confinement.py:88–90](https://github.com/Cezar277/heimdall/blob/01dc80cca8ccfc00c5fed21adadda8c8cdb02f80/tests/test_crypto_confinement.py#L88-L90) | Aucun import crypto hors `vault/crypto.py` ; clarification actée dans ADR-001/ADR-002 |
| Métadonnée d'entropie 0–8 bits/octet | [heimdall/scanner/entropy.py:16–33](https://github.com/Cezar277/heimdall/blob/01dc80cca8ccfc00c5fed21adadda8c8cdb02f80/heimdall/scanner/entropy.py#L16-L33) | [tests/test_scanner_detect.py:480–486](https://github.com/Cezar277/heimdall/blob/01dc80cca8ccfc00c5fed21adadda8c8cdb02f80/tests/test_scanner_detect.py#L480-L486) | Vide = 0, deux symboles = 1, plafond 8 |
| Anti-ReDoS : lignes proches de 1 Mio | [heimdall/scanner/signatures.py:39–83](https://github.com/Cezar277/heimdall/blob/01dc80cca8ccfc00c5fed21adadda8c8cdb02f80/heimdall/scanner/signatures.py#L39-L83) | [tests/test_scanner_detect.py:652–668](https://github.com/Cezar277/heimdall/blob/01dc80cca8ccfc00c5fed21adadda8c8cdb02f80/tests/test_scanner_detect.py#L652-L668) | 7 lignes de ~1 Mio, chacune < 10 s (mesure locale) |
| Mesure T21 sur le jeu piège, xfail retiré | [tests/test_trap_acceptance.py:204–209](https://github.com/Cezar277/heimdall/blob/01dc80cca8ccfc00c5fed21adadda8c8cdb02f80/tests/test_trap_acceptance.py#L204-L209) | [tests/support/trap_corpus.py:81–121](https://github.com/Cezar277/heimdall/blob/01dc80cca8ccfc00c5fed21adadda8c8cdb02f80/tests/support/trap_corpus.py#L81-L121) | `core` précision 1,00 / rappel 1,00 |

## Corrections issues de la relecture « REQUEST CHANGES »

| Remarque | Correctif | Preuve |
|---|---|---|
| HIGH — déduplication `(ligne, type)` : un second secret distinct disparaît | clé de déduplication `(ligne, type, valeur)` ; un Finding par valeur distincte, tri complété par `snippet_hash` | [detect.py:233–255](https://github.com/Cezar277/heimdall/blob/01dc80cca8ccfc00c5fed21adadda8c8cdb02f80/heimdall/scanner/detect.py#L233-L255) + [test_scanner_detect.py:216–243](https://github.com/Cezar277/heimdall/blob/01dc80cca8ccfc00c5fed21adadda8c8cdb02f80/tests/test_scanner_detect.py#L216-L243) |
| MEDIUM — fichier UTF-16/UTF-32 ignoré à cause de l'octet NUL | `decode_text` : BOM strict, heuristique UTF-16/32 sans BOM bornée par la proportion ASCII ; NUL non décodable sans signature binaire → `ScanError` | [exclusions.py:136–259](https://github.com/Cezar277/heimdall/blob/01dc80cca8ccfc00c5fed21adadda8c8cdb02f80/heimdall/scanner/exclusions.py#L136-L259) + [test_scanner_detect.py:307–366](https://github.com/Cezar277/heimdall/blob/01dc80cca8ccfc00c5fed21adadda8c8cdb02f80/tests/test_scanner_detect.py#L307-L366) |
| MEDIUM — répertoire `env` exclu trop générique | `env` retiré de `EXCLUDED_DIRECTORIES` ; seuls `.venv`, `venv`, `virtualenv` le restent | [exclusions.py:25–49](https://github.com/Cezar277/heimdall/blob/01dc80cca8ccfc00c5fed21adadda8c8cdb02f80/heimdall/scanner/exclusions.py#L25-L49) + [test_scanner_detect.py:295–305](https://github.com/Cezar277/heimdall/blob/01dc80cca8ccfc00c5fed21adadda8c8cdb02f80/tests/test_scanner_detect.py#L295-L305) |
| MEDIUM — préfixes AWS incomplets | préfixes `ABIA` et `ACCA` ajoutés à `AKIA`/`ASIA` | [signatures.py:39–44](https://github.com/Cezar277/heimdall/blob/01dc80cca8ccfc00c5fed21adadda8c8cdb02f80/heimdall/scanner/signatures.py#L39-L44) + [test_scanner_detect.py:211–214](https://github.com/Cezar277/heimdall/blob/01dc80cca8ccfc00c5fed21adadda8c8cdb02f80/tests/test_scanner_detect.py#L211-L214) |
| MEDIUM — crypto hors `vault/crypto.py` (invariant 5) | clarification actée : l'invariant porte sur `cryptography`/`argon2` ; l'empreinte HMAC stdlib du Finding est autorisée hors Vault | [ADR-002:75–82](https://github.com/Cezar277/heimdall/blob/81a67dfd7978c9ed1dc8ceab83f9f35b57389a12/docs/adr/002-stack-python.md#L75-L82) + [ADR-001:22–27](https://github.com/Cezar277/heimdall/blob/81a67dfd7978c9ed1dc8ceab83f9f35b57389a12/docs/adr/001-finding-et-etats.md#L22-L28) |
| MEDIUM — clé éphémère masquant une panne | plus de repli sur une clé de processus : clé absente, trop permissive, d'un autre propriétaire ou impossible à créer → `ScanError` | [hashing.py:102–185](https://github.com/Cezar277/heimdall/blob/01dc80cca8ccfc00c5fed21adadda8c8cdb02f80/heimdall/scanner/hashing.py#L102-L185) + [test_scanner_detect.py:532–648](https://github.com/Cezar277/heimdall/blob/01dc80cca8ccfc00c5fed21adadda8c8cdb02f80/tests/test_scanner_detect.py#L532-L648) |
| LOW — clé sans vérification de permissions/propriétaire | fichier `0600` et propriétaire courant exigés, parent durci `0700`, parent symlink refusé, création `O_EXCL`+`O_NOFOLLOW` | [hashing.py:57–120](https://github.com/Cezar277/heimdall/blob/01dc80cca8ccfc00c5fed21adadda8c8cdb02f80/heimdall/scanner/hashing.py#L57-L120) + [test_scanner_detect.py:531–557](https://github.com/Cezar277/heimdall/blob/01dc80cca8ccfc00c5fed21adadda8c8cdb02f80/tests/test_scanner_detect.py#L532-L560) |
| LOW — hygiène de PR : quatre sous-tickets dans une PR | exception signalée dans la description de PR et dans cette fiche ; à valider par les mainteneurs | [docs/t22-samm.md](#exception-de-regroupement) |
| Tests manquants — tous ajoutés | valeurs distinctes, UTF-16/32, `env/` vs `.venv/`, `0644`/autre UID, stockage indisponible, `ABIA`/`ACCA`, JWT > 8 Kio, modification pendant lecture | [tests/test_scanner_detect.py](https://github.com/Cezar277/heimdall/blob/01dc80cca8ccfc00c5fed21adadda8c8cdb02f80/tests/test_scanner_detect.py) |

## Résultats locaux

Environnement : Linux, Python 3.14.6, venv du dépôt.

```text
.venv/bin/python -m pytest tests/test_scanner_detect.py \
  tests/test_trap_acceptance.py tests/security/test_scanner_bypass.py \
  --cov=heimdall.scanner --cov-branch --cov-report=term-missing \
  --cov-fail-under=85
102 passed
heimdall/scanner : 90,66 % (branches incluses), seuil 85 % atteint

.venv/bin/python -m pytest --cov=heimdall --cov-branch \
  --cov-report=term-missing --cov-fail-under=85
suite complète : 916 passed, code retour 0
couverture Heimdall : 96,68 %

.venv/bin/python tests/measure_trap.py
core : tp=10, fp=0, fn=0, precision=1.0, recall=1.0
all  : tp=10, fp=0, fn=6, recall=0.625 (6 limites connues T21)

.venv/bin/ruff check heimdall tests        # All checks passed
.venv/bin/mypy heimdall tests/contracts/fastapi_contract_fixture.py
                                            # Success: no issues found
.venv/bin/bandit -r heimdall -q             # code retour 0, aucun rapport
```

Les six positions obfusquées restent des `limite_connue` : le scanner de
signatures ne décode pas base64 et n'analyse pas le flux des variables
(voir [scanner.md](scanner.md#limites-connues-honnêtes)). Elles ne sont pas
comptées dans le seuil principal T21.

## Exception de regroupement

Le découpage du projet prévoit une PR par sous-ticket. Cette PR regroupe les
quatre sous-tickets du parent #22 (#53, #54, #59, #60) parce que le ticket
parent a été demandé comme un tout ; l'exception est signalée ici et dans la
description de PR. Elle **doit être validée explicitement par les
mainteneurs** avant fusion ; les PR suivantes suivront le découpage habituel.

## Relecture et PR

- PR : à ouvrir sur la branche
  `22-t22-scanner-regex-de-signatures-et-exclusions` avec `Closes #22`.
- Relecture inter-domaines et check `CI (/ci)` restent requis avant fusion.
- La feuille SAMM externe n'est pas accessible depuis le dépôt ; reporter la
  ligne ci-dessus avec le lien de la PR et le SHA
  `01dc80cca8ccfc00c5fed21adadda8c8cdb02f80`.
