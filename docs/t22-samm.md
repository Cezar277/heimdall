# T22 — preuves pour la ligne SAMM

Périmètre : ticket #22 et ses sous-tickets #53 (interface Scanner/Finding),
#54 (signatures), #59 (exclusions), #60 (tests et mesure T21). Cette fiche
fournit les couples **module + ligne** et les permaliens du code testé ; elle
ne prétend pas modifier une feuille externe.

Révision du code testé : `b38dec179de6baf22fefd50056014e8ea26fc185`
(commit `fix(scanner): racine symlinkée refusée, magie binaire conditionnée,
fenêtre multi-ligne (#22)`), qui porte les correctifs de la relecture
« APPROVE WITH COMMENTS ». Révisions de la documentation :
`f4dc3c8832dcad31e187e8f56f803ea9997dbd0a` (docs/scanner.md,
docs/security/requirements.md), `4ffbf8515eaccb0a3e4595d5c2d06d64d231ce31`
(chiffres de preuve) et `81a67dfd7978c9ed1dc8ceab83f9f35b57389a12`
(ADR-001/ADR-002).

Les permaliens de code épinglent `b38dec1…` ; ceux de documentation épinglent
`f4dc3c8…` (ADR-002) et `81a67df…` (ADR-001). Cette fiche décrit la révision
`b38dec1…` **avant** l'intégration `main` et la restauration post-merge
(`11ff992`, `420ec98`, `c6b04ea`) : après ces commits, `heimdall/scanner`
suit l'architecture #53/#54 (`finding.py`, `interface.py`,
`signatures/` en paquet) et `git diff b38dec1… HEAD -- heimdall tests`
n'est plus vide. Re-pinner sur le SHA final du merge avant clôture SAMM.

| Exigence vérifiée | Implémentation (module + ligne) | Test et preuve permanente | Résultat local |
|---|---|---|---|
| Sortie Finding conforme au contrat #14, sans valeur brute | [heimdall/scanner/detect.py:49–70](https://github.com/Cezar277/heimdall/blob/b38dec179de6baf22fefd50056014e8ea26fc185/heimdall/scanner/detect.py#L49-L70) | [tests/test_scanner_detect.py:156–179](https://github.com/Cezar277/heimdall/blob/b38dec179de6baf22fefd50056014e8ea26fc185/tests/test_scanner_detect.py#L156-L179) | Schéma draft 2020-12 validé ; valeur brute absente de la sérialisation |
| Aucun candidat perdu : deux valeurs distinctes, même type, même ligne | [heimdall/scanner/detect.py:251–274](https://github.com/Cezar277/heimdall/blob/b38dec179de6baf22fefd50056014e8ea26fc185/heimdall/scanner/detect.py#L251-L274) | [tests/test_scanner_detect.py:218–232](https://github.com/Cezar277/heimdall/blob/b38dec179de6baf22fefd50056014e8ea26fc185/tests/test_scanner_detect.py#L218-L232) | 2 Findings, 2 empreintes distinctes ; valeur identique dédupliquée |
| Parcours déterministe d'un dépôt ou fichier, tri stable | [heimdall/scanner/detect.py:152–178](https://github.com/Cezar277/heimdall/blob/b38dec179de6baf22fefd50056014e8ea26fc185/heimdall/scanner/detect.py#L152-L178) | [tests/test_scanner_detect.py:563–576](https://github.com/Cezar277/heimdall/blob/b38dec179de6baf22fefd50056014e8ea26fc185/tests/test_scanner_detect.py#L563-L576) | Fichier unique, CRLF et ordre trié vérifiés |
| **Racine et fichier unique : aucun lien symbolique suivi** | [heimdall/scanner/detect.py:105–122](https://github.com/Cezar277/heimdall/blob/b38dec179de6baf22fefd50056014e8ea26fc185/heimdall/scanner/detect.py#L105-L122) | [tests/test_scanner_detect.py:431–474](https://github.com/Cezar277/heimdall/blob/b38dec179de6baf22fefd50056014e8ea26fc185/tests/test_scanner_detect.py#L431-L474) | racine, fichier unique et ancêtre symlinkés → `ScanError` ; la cible n'est pas lue |
| Signatures AWS (`AKIA`/`ASIA`/`ABIA`/`ACCA`), Stripe, Slack, GitHub, JWT (charge 64 Kio), PEM | [heimdall/scanner/signatures.py:40–94](https://github.com/Cezar277/heimdall/blob/b38dec179de6baf22fefd50056014e8ea26fc185/heimdall/scanner/signatures.py#L40-L94) | [tests/test_scanner_detect.py:108–246](https://github.com/Cezar277/heimdall/blob/b38dec179de6baf22fefd50056014e8ea26fc185/tests/test_scanner_detect.py#L108-L246) | 4 préfixes AWS, 9 détections positives ; 12 formes négatives sans alerte |
| Familles Slack publiées (`xoxb-`, `xoxp-`, `xapp-`, `xwfp-`, `xoxe.`, historiques) | [heimdall/scanner/signatures.py:58–71](https://github.com/Cezar277/heimdall/blob/b38dec179de6baf22fefd50056014e8ea26fc185/heimdall/scanner/signatures.py#L58-L71) | [tests/test_scanner_detect.py:248–265](https://github.com/Cezar277/heimdall/blob/b38dec179de6baf22fefd50056014e8ea26fc185/tests/test_scanner_detect.py#L248-L265) | 7 familles détectées ; famille non publiée non couverte (limite tracée) |
| **Secret coupé par un retour à la ligne** (fenêtre 4 Kio) | [heimdall/scanner/detect.py:251–289](https://github.com/Cezar277/heimdall/blob/b38dec179de6baf22fefd50056014e8ea26fc185/heimdall/scanner/detect.py#L251-L289) | [tests/test_scanner_detect.py:267–280](https://github.com/Cezar277/heimdall/blob/b38dec179de6baf22fefd50056014e8ea26fc185/tests/test_scanner_detect.py#L267-L280) | secret coupé détecté ; au-delà de 4 Kio, limite figée par un test |
| Exclusions `.gitignore`, lockfiles, vendor, binaires connus ; `env/` **scanné** | [heimdall/scanner/exclusions.py:25–133](https://github.com/Cezar277/heimdall/blob/b38dec179de6baf22fefd50056014e8ea26fc185/heimdall/scanner/exclusions.py#L25-L133) | [tests/test_scanner_detect.py:285–343](https://github.com/Cezar277/heimdall/blob/b38dec179de6baf22fefd50056014e8ea26fc185/tests/test_scanner_detect.py#L285-L343) | `.env`/`.pem`/`requirements.txt` scannés ; vendor/lock/binaire ignorés ; `.venv`/`venv`/`virtualenv` exclus, `env/` non |
| **Magie binaire conditionnée** : une signature suivie de texte clair est refusée | [heimdall/scanner/exclusions.py:197–211](https://github.com/Cezar277/heimdall/blob/b38dec179de6baf22fefd50056014e8ea26fc185/heimdall/scanner/exclusions.py#L197-L211), [heimdall/scanner/exclusions.py:256–286](https://github.com/Cezar277/heimdall/blob/b38dec179de6baf22fefd50056014e8ea26fc185/heimdall/scanner/exclusions.py#L256-L286) | [tests/test_scanner_detect.py:389–424](https://github.com/Cezar277/heimdall/blob/b38dec179de6baf22fefd50056014e8ea26fc185/tests/test_scanner_detect.py#L389-L424) | `PK\x03\x04\x00AKIA…` et en-tête PNG + secret → `ScanError` ; vrai binaire → ignoré |
| UTF-16/UTF-32 (BOM et sans BOM) décodés ; NUL ambigu fail-closed | [heimdall/scanner/exclusions.py:225–254](https://github.com/Cezar277/heimdall/blob/b38dec179de6baf22fefd50056014e8ea26fc185/heimdall/scanner/exclusions.py#L225-L254) | [tests/test_scanner_detect.py:344–388](https://github.com/Cezar277/heimdall/blob/b38dec179de6baf22fefd50056014e8ea26fc185/tests/test_scanner_detect.py#L344-L388) | 8 encodages détectés ; NUL non décodable → `ScanError` |
| Confinement des fichiers : refus des liens, non-réguliers et chemins hors contrat | [heimdall/scanner/detect.py:179–206](https://github.com/Cezar277/heimdall/blob/b38dec179de6baf22fefd50056014e8ea26fc185/heimdall/scanner/detect.py#L179-L206) | [tests/test_scanner_detect.py:475–534](https://github.com/Cezar277/heimdall/blob/b38dec179de6baf22fefd50056014e8ea26fc185/tests/test_scanner_detect.py#L475-L534) | Symlinks ignorés, FIFO/nom invalide refusés |
| Fail-closed : entrée illisible, > 1 Mio, racine absente, fichier modifié pendant la lecture | [heimdall/scanner/detect.py:207–250](https://github.com/Cezar277/heimdall/blob/b38dec179de6baf22fefd50056014e8ea26fc185/heimdall/scanner/detect.py#L207-L250) | [tests/security/test_scanner_bypass.py:32–74](https://github.com/Cezar277/heimdall/blob/b38dec179de6baf22fefd50056014e8ea26fc185/tests/security/test_scanner_bypass.py#L32-L74), [tests/test_scanner_detect.py:507–561](https://github.com/Cezar277/heimdall/blob/b38dec179de6baf22fefd50056014e8ea26fc185/tests/test_scanner_detect.py#L507-L561) | `ScanError` statique, aucun reflet d'entrée |
| Clé HMAC locale durcie : `0600`, propriétaire vérifié, parent `0700`, parent symlink refusé, `..` refusé, **pas de clé éphémère** | [heimdall/scanner/hashing.py:34–52](https://github.com/Cezar277/heimdall/blob/b38dec179de6baf22fefd50056014e8ea26fc185/heimdall/scanner/hashing.py#L34-L52), [heimdall/scanner/hashing.py:68–190](https://github.com/Cezar277/heimdall/blob/b38dec179de6baf22fefd50056014e8ea26fc185/heimdall/scanner/hashing.py#L68-L190) | [tests/test_scanner_detect.py:589–759](https://github.com/Cezar277/heimdall/blob/b38dec179de6baf22fefd50056014e8ea26fc185/tests/test_scanner_detect.py#L589-L759) | `0644`, autre UID, stockage indisponible, écriture partielle, `..` → `ScanError` |
| Empreinte HMAC stdlib : invariant 5 intact (`cryptography`/`argon2` confinés au Vault) | [docs/adr/002-stack-python.md:75–82](https://github.com/Cezar277/heimdall/blob/f4dc3c8832dcad31e187e8f56f803ea9997dbd0a/docs/adr/002-stack-python.md#L75-L82), [docs/adr/001-finding-et-etats.md:22–27](https://github.com/Cezar277/heimdall/blob/81a67dfd7978c9ed1dc8ceab83f9f35b57389a12/docs/adr/001-finding-et-etats.md#L22-L27) | [tests/test_crypto_confinement.py:88–90](https://github.com/Cezar277/heimdall/blob/b38dec179de6baf22fefd50056014e8ea26fc185/tests/test_crypto_confinement.py#L88-L90) | Aucun import crypto hors `vault/crypto.py` ; clarification actée dans ADR-001/ADR-002 |
| Métadonnée d'entropie 0–8 bits/octet | [heimdall/scanner/entropy.py:16–33](https://github.com/Cezar277/heimdall/blob/b38dec179de6baf22fefd50056014e8ea26fc185/heimdall/scanner/entropy.py#L16-L33) | [tests/test_scanner_detect.py:582–587](https://github.com/Cezar277/heimdall/blob/b38dec179de6baf22fefd50056014e8ea26fc185/tests/test_scanner_detect.py#L582-L587) | Vide = 0, deux symboles = 1, plafond 8 |
| Anti-ReDoS : lignes proches de 1 Mio | [heimdall/scanner/signatures.py:40–94](https://github.com/Cezar277/heimdall/blob/b38dec179de6baf22fefd50056014e8ea26fc185/heimdall/scanner/signatures.py#L40-L94) | [tests/test_scanner_detect.py:764–780](https://github.com/Cezar277/heimdall/blob/b38dec179de6baf22fefd50056014e8ea26fc185/tests/test_scanner_detect.py#L764-L780) | 7 lignes de ~1 Mio, chacune < 10 s (mesure locale) |
| Mesure T21 sur le jeu piège, xfail retiré | [tests/test_trap_acceptance.py:204–209](https://github.com/Cezar277/heimdall/blob/b38dec179de6baf22fefd50056014e8ea26fc185/tests/test_trap_acceptance.py#L204-L209) | [tests/support/trap_corpus.py:81–121](https://github.com/Cezar277/heimdall/blob/b38dec179de6baf22fefd50056014e8ea26fc185/tests/support/trap_corpus.py#L81-L121) | `core` précision 1,00 / rappel 1,00 |

## Corrections issues de la relecture « REQUEST CHANGES » (poussée par `01dc80c`/`81a67df`)

| Remarque | Correctif | Preuve |
|---|---|---|
| HIGH — déduplication `(ligne, type)` : un second secret distinct disparaît | clé de déduplication `(ligne, type, valeur)` ; un Finding par valeur distincte, tri complété par `snippet_hash` | [detect.py:251–274](https://github.com/Cezar277/heimdall/blob/b38dec179de6baf22fefd50056014e8ea26fc185/heimdall/scanner/detect.py#L251-L274) + [test_scanner_detect.py:218–232](https://github.com/Cezar277/heimdall/blob/b38dec179de6baf22fefd50056014e8ea26fc185/tests/test_scanner_detect.py#L218-L232) |
| MEDIUM — fichier UTF-16/UTF-32 ignoré à cause de l'octet NUL | `decode_text` : BOM strict, heuristique UTF-16/32 sans BOM bornée par la proportion ASCII ; NUL non décodable → `ScanError` | [exclusions.py:225–286](https://github.com/Cezar277/heimdall/blob/b38dec179de6baf22fefd50056014e8ea26fc185/heimdall/scanner/exclusions.py#L225-L286) + [test_scanner_detect.py:344–388](https://github.com/Cezar277/heimdall/blob/b38dec179de6baf22fefd50056014e8ea26fc185/tests/test_scanner_detect.py#L344-L388) |
| MEDIUM — répertoire `env` exclu trop générique | `env` retiré de `EXCLUDED_DIRECTORIES` ; seuls `.venv`, `venv`, `virtualenv` le restent | [exclusions.py:25–49](https://github.com/Cezar277/heimdall/blob/b38dec179de6baf22fefd50056014e8ea26fc185/heimdall/scanner/exclusions.py#L25-L49) + [test_scanner_detect.py:332–343](https://github.com/Cezar277/heimdall/blob/b38dec179de6baf22fefd50056014e8ea26fc185/tests/test_scanner_detect.py#L332-L343) |
| MEDIUM — préfixes AWS incomplets | préfixes `ABIA` et `ACCA` ajoutés à `AKIA`/`ASIA` | [signatures.py:40–44](https://github.com/Cezar277/heimdall/blob/b38dec179de6baf22fefd50056014e8ea26fc185/heimdall/scanner/signatures.py#L40-L44) + [test_scanner_detect.py:213–216](https://github.com/Cezar277/heimdall/blob/b38dec179de6baf22fefd50056014e8ea26fc185/tests/test_scanner_detect.py#L213-L216) |
| MEDIUM — crypto hors `vault/crypto.py` (invariant 5) | clarification actée : l'invariant porte sur `cryptography`/`argon2` ; l'empreinte HMAC stdlib du Finding est autorisée hors Vault | [ADR-002:75–82](https://github.com/Cezar277/heimdall/blob/f4dc3c8832dcad31e187e8f56f803ea9997dbd0a/docs/adr/002-stack-python.md#L75-L82) + [ADR-001:22–27](https://github.com/Cezar277/heimdall/blob/81a67dfd7978c9ed1dc8ceab83f9f35b57389a12/docs/adr/001-finding-et-etats.md#L22-L27) |
| MEDIUM — clé éphémère masquant une panne | plus de repli sur une clé de processus : clé absente, trop permissive, d'un autre propriétaire ou impossible à créer → `ScanError` | [hashing.py:177–190](https://github.com/Cezar277/heimdall/blob/b38dec179de6baf22fefd50056014e8ea26fc185/heimdall/scanner/hashing.py#L177-L190) + [test_scanner_detect.py:634–759](https://github.com/Cezar277/heimdall/blob/b38dec179de6baf22fefd50056014e8ea26fc185/tests/test_scanner_detect.py#L634-L759) |
| LOW — clé sans vérification de permissions/propriétaire | fichier `0600` et propriétaire courant exigés, parent durci `0700`, parent symlink refusé, création `O_EXCL`+`O_NOFOLLOW` | [hashing.py:68–106](https://github.com/Cezar277/heimdall/blob/b38dec179de6baf22fefd50056014e8ea26fc185/heimdall/scanner/hashing.py#L68-L106) + [test_scanner_detect.py:634–660](https://github.com/Cezar277/heimdall/blob/b38dec179de6baf22fefd50056014e8ea26fc185/tests/test_scanner_detect.py#L634-L660) |

## Corrections issues de la relecture « APPROVE WITH COMMENTS » (poussée par `b38dec1`/`f4dc3c8`)

| Remarque | Correctif | Preuve |
|---|---|---|
| MEDIUM — racine et fichier unique suivaient les symlinks | `_resolve_root` vérifie par `lstat` la racine **et** chacun de ses ancêtres ; un lien dans le chemin lève `ScanError` au lieu de faire lire la cible | [detect.py:105–122](https://github.com/Cezar277/heimdall/blob/b38dec179de6baf22fefd50056014e8ea26fc185/heimdall/scanner/detect.py#L105-L122) + [test_scanner_detect.py:431–474](https://github.com/Cezar277/heimdall/blob/b38dec179de6baf22fefd50056014e8ea26fc185/tests/test_scanner_detect.py#L431-L474) |
| MEDIUM — évasion par préfixe magique | le décodage UTF-16/32 est tenté **avant** la magie, et la magie n'ignore un fichier que si son contenu est majoritairement binaire (≥ 50 % d'octets non textuels) ; sinon `ScanError` | [exclusions.py:197–211](https://github.com/Cezar277/heimdall/blob/b38dec179de6baf22fefd50056014e8ea26fc185/heimdall/scanner/exclusions.py#L197-L211), [exclusions.py:256–286](https://github.com/Cezar277/heimdall/blob/b38dec179de6baf22fefd50056014e8ea26fc185/heimdall/scanner/exclusions.py#L256-L286) + [test_scanner_detect.py:389–424](https://github.com/Cezar277/heimdall/blob/b38dec179de6baf22fefd50056014e8ea26fc185/tests/test_scanner_detect.py#L389-L424) |
| LOW — secrets coupés par `\n` manqués | jointure de deux lignes bornée à 4 Kio ; le Finding porte la ligne de début de la correspondance ; au-delà de la borne, limite documentée et figée | [detect.py:251–289](https://github.com/Cezar277/heimdall/blob/b38dec179de6baf22fefd50056014e8ea26fc185/heimdall/scanner/detect.py#L251-L289) + [test_scanner_detect.py:267–280](https://github.com/Cezar277/heimdall/blob/b38dec179de6baf22fefd50056014e8ea26fc185/tests/test_scanner_detect.py#L267-L280) |
| LOW — préfixes Slack incomplets | familles publiées ajoutées (`xapp-`, `xwfp-`, `xoxe.`) d'après [docs.slack.dev](https://docs.slack.dev/authentication/tokens) ; la liste des familles couvertes est documentée, une famille future reste une limite #23/#24 | [signatures.py:58–71](https://github.com/Cezar277/heimdall/blob/b38dec179de6baf22fefd50056014e8ea26fc185/heimdall/scanner/signatures.py#L58-L71) + [test_scanner_detect.py:248–265](https://github.com/Cezar277/heimdall/blob/b38dec179de6baf22fefd50056014e8ea26fc185/tests/test_scanner_detect.py#L248-L265) |
| LOW — `KEY_FILE` réécrit silencieusement | un chemin de clé contenant `..` est refusé : le fichier utilisé est toujours celui demandé | [hashing.py:34–52](https://github.com/Cezar277/heimdall/blob/b38dec179de6baf22fefd50056014e8ea26fc185/heimdall/scanner/hashing.py#L34-L52) + [test_scanner_detect.py:718–726](https://github.com/Cezar277/heimdall/blob/b38dec179de6baf22fefd50056014e8ea26fc185/tests/test_scanner_detect.py#L718-L726) |
| LOW — hygiène de PR : quatre sous-tickets dans une PR | exception signalée dans la description de PR et dans cette fiche ; à valider par les mainteneurs | [docs/t22-samm.md](#exception-de-regroupement) |

## Résultats locaux

Environnement : Linux, Python 3.14.6, venv du dépôt.

```text
.venv/bin/python -m pytest tests/test_scanner_detect.py \
  tests/test_trap_acceptance.py tests/security/test_scanner_bypass.py \
  --cov=heimdall.scanner --cov-branch --cov-report=term-missing \
  --cov-fail-under=85
122 passed
heimdall/scanner : 91,31 % (branches incluses), seuil 85 % atteint

.venv/bin/python -m pytest --cov=heimdall --cov-branch \
  --cov-report=term-missing --cov-fail-under=85
suite complète : 936 passed (+ 3852 subtests), code retour 0
couverture Heimdall : 96,69 %

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
  `b38dec179de6baf22fefd50056014e8ea26fc185`.
