# T22 — preuves pour la ligne SAMM

Périmètre : ticket #22 et ses sous-tickets #53 (interface Scanner/Finding),
#54 (signatures), #59 (exclusions), #60 (tests et mesure T21). Cette fiche
fournit les couples **module + ligne** et les permaliens du code testé ; elle
ne prétend pas modifier une feuille externe.

Révision du code testé par le tableau principal : `b38dec179de6baf22fefd50056014e8ea26fc185`
(commit `fix(scanner): racine symlinkée refusée, magie binaire conditionnée,
fenêtre multi-ligne (#22)`), qui porte les correctifs de la relecture
« APPROVE WITH COMMENTS ». Révisions de la documentation :
`f4dc3c8832dcad31e187e8f56f803ea9997dbd0a` (docs/scanner.md,
docs/security/requirements.md), `4ffbf8515eaccb0a3e4595d5c2d06d64d231ce31`
(chiffres de preuve) et `81a67dfd7978c9ed1dc8ceab83f9f35b57389a12`
(ADR-001/ADR-002).

Révision du code testé **actuel** : `5de5140153f593248b5f1823f271f2d7528a3205`
(commit `fix(scanner): le contenu decide, plus jamais le nom du fichier (#22)`,
rejoué sur `origin/22-t22-scanner-regex-de-signatures-et-exclusions`). Il
reprend la livraison `b38dec1…`, y ajoute le correctif du 2ᵉ passage de la
relecture, et conserve les durcissements de l'amont (anti-TOCTOU, périmètre en
flux) — voir « Durcissements de l'amont conservés au rebase ».

Révision du code testé **actuel** : `b2304c645445b9609b5d2ee50aed7a4255a55eef`
(commit `fix(scanner): aucun verdict propre partiel, journal et troncation (#22)`,
rejoué sur `origin/22-t22-scanner-regex-de-signatures-et-exclusions`). Il
reprend la livraison `5de5140…` et y ajoute le correctif du 3ᵉ passage de la
relecture (« REQUEST CHANGES » : verdict propre partiel masqué, troncature
entre `stat` et `open`, `complet` trop optimiste, `ValueError` brute, journal
Unicode, garde Slack inconditionnelle).

Révision du code testé **actuel** : `c391cc0b15cd58743e826a2d5947e9743507b9ef`
(commit `fix(scanner): garde executable du verdict propre, bornes Slack
couplees (#22)`, rejoué sur
`origin/22-t22-scanner-regex-de-signatures-et-exclusions`). Il reprend la
livraison `b2304c6…` et y ajoute le correctif du 4ᵉ passage de la relecture
(« APPROVE WITH COMMENTS » : garde **exécutable** du verdict propre, bornes
Slack couplées par construction, re-pin des permaliens outillé).

Les permaliens du tableau principal épinglent `b38dec1…` ; ceux de documentation
épinglent `f4dc3c8…` (ADR-002) et `81a67df…` (ADR-001). **Ces permaliens
décrivent la livraison précédente** : la relecture « REQUEST CHANGES » (2ᵉ
passage) a modifié le périmètre, la fenêtre multi-ligne et les règles Slack.
Les corrections correspondantes sont prouvées dans la section « 2ᵉ passage »,
dont les permaliens sont épinglés sur `5de5140153f593248b5f1823f271f2d7528a3205` (commit `fix(scanner): le contenu
decide, plus jamais le nom du fichier (#22)`). Les corrections du 3ᵉ passage
sont prouvées dans la section « 3ᵉ passage », épinglée sur
`b2304c645445b9609b5d2ee50aed7a4255a55eef`. Les lignes du tableau principal
qui portent sur un module modifié (périmètre, fenêtre multi-ligne) sont
signalées ci-dessous.

> **État livré après le 5ᵉ passage (à lire avant les sections historiques).**
> Les sections 3ᵉ et 4ᵉ passages décrivent un état **historique** du code :
> `RapportScan`, `scan_complet()`, `exiger_complet()`, les compteurs de
> contenus « tracés » et les avertissements `ScanIncomplet` **n'existent plus**
> dans la branche livrée. Le contrat actuel est plus simple et fail-closed :
> `scan()`/`find_candidates()` lèvent `ScanError` pour tout fichier du
> périmètre non analysable (binaire connu, lien, illisible, modifié) ; seule
> la base VCS est élaguée par politique, et
> `heimdall.scanner.detect.Scanner.vcs_ignored` compte ces bases sans exposer
> de chemin. La section « 5ᵉ passage » ci-dessous fige cet état et corrige les
> affirmations devenues fausses. Le 6ᵉ passage remplace ensuite la garde regex
> Slack des sections 3ᵉ/4ᵉ par une neutralisation conditionnelle dans
> `find_signature_matches` : seule la section « 6ᵉ passage » décrit ce point.
Depuis #29, le mode strict de la CLI
(`heimdall.scanner.detect.Scanner(root, strict=True)`) ajoute des
bornes (fichiers, volume total, Findings) et écarte la base VCS du périmètre
audité. Il ne réintroduit **aucune exclusion nominale de contenu** : le
scanner bibliothèque et la CLI lisent `vendor/`, `node_modules/`, les
lockfiles et les sorties de build par contenu. Les permaliens ci-dessus
restent valides pour le code #22 tel qu'il a été testé ; l'extension CLI est
documentée dans [t29-samm.md](t29-samm.md).

| Exigence vérifiée | Implémentation (module + ligne) | Test et preuve permanente | Résultat local |
|---|---|---|---|
| Sortie Finding conforme au contrat #14, sans valeur brute | [heimdall/scanner/detect.py:49–70](https://github.com/Cezar277/heimdall/blob/b38dec179de6baf22fefd50056014e8ea26fc185/heimdall/scanner/detect.py#L49-L70) | [tests/test_scanner_detect.py:156–179](https://github.com/Cezar277/heimdall/blob/b38dec179de6baf22fefd50056014e8ea26fc185/tests/test_scanner_detect.py#L156-L179) | Schéma draft 2020-12 validé ; valeur brute absente de la sérialisation |
| Aucun candidat perdu : deux valeurs distinctes, même type, même ligne | [heimdall/scanner/detect.py:251–274](https://github.com/Cezar277/heimdall/blob/b38dec179de6baf22fefd50056014e8ea26fc185/heimdall/scanner/detect.py#L251-L274) | [tests/test_scanner_detect.py:218–232](https://github.com/Cezar277/heimdall/blob/b38dec179de6baf22fefd50056014e8ea26fc185/tests/test_scanner_detect.py#L218-L232) | 2 Findings, 2 empreintes distinctes ; valeur identique dédupliquée |
| Parcours déterministe d'un dépôt ou fichier, tri stable | [heimdall/scanner/detect.py:152–178](https://github.com/Cezar277/heimdall/blob/b38dec179de6baf22fefd50056014e8ea26fc185/heimdall/scanner/detect.py#L152-L178) | [tests/test_scanner_detect.py:563–576](https://github.com/Cezar277/heimdall/blob/b38dec179de6baf22fefd50056014e8ea26fc185/tests/test_scanner_detect.py#L563-L576) | Fichier unique, CRLF et ordre trié vérifiés |
| **Racine et fichier unique : aucun lien symbolique suivi** | [heimdall/scanner/detect.py:105–122](https://github.com/Cezar277/heimdall/blob/b38dec179de6baf22fefd50056014e8ea26fc185/heimdall/scanner/detect.py#L105-L122) | [tests/test_scanner_detect.py:431–474](https://github.com/Cezar277/heimdall/blob/b38dec179de6baf22fefd50056014e8ea26fc185/tests/test_scanner_detect.py#L431-L474) | racine, fichier unique et ancêtre symlinkés → `ScanError` ; la cible n'est pas lue |
| Signatures AWS (`AKIA`/`ASIA`/`ABIA`/`ACCA`), Stripe, Slack, GitHub, JWT (charge 64 Kio), PEM | [heimdall/scanner/signatures.py:40–94](https://github.com/Cezar277/heimdall/blob/b38dec179de6baf22fefd50056014e8ea26fc185/heimdall/scanner/signatures.py#L40-L94) | [tests/test_scanner_detect.py:108–246](https://github.com/Cezar277/heimdall/blob/b38dec179de6baf22fefd50056014e8ea26fc185/tests/test_scanner_detect.py#L108-L246) | 4 préfixes AWS, 9 détections positives ; 12 formes négatives sans alerte |
| Familles Slack publiées (`xoxb-`, `xoxp-`, `xapp-`, `xwfp-`, `xoxe.`, historiques) | [heimdall/scanner/signatures.py:58–71](https://github.com/Cezar277/heimdall/blob/b38dec179de6baf22fefd50056014e8ea26fc185/heimdall/scanner/signatures.py#L58-L71) | [tests/test_scanner_detect.py:248–265](https://github.com/Cezar277/heimdall/blob/b38dec179de6baf22fefd50056014e8ea26fc185/tests/test_scanner_detect.py#L248-L265) | 7 familles détectées ; famille non publiée non couverte (limite tracée) |
| ⚠️ **Secret coupé par un retour à la ligne** (fenêtre 4 Kio ; 3 lignes depuis le 2ᵉ passage) | [heimdall/scanner/detect.py:251–289](https://github.com/Cezar277/heimdall/blob/b38dec179de6baf22fefd50056014e8ea26fc185/heimdall/scanner/detect.py#L251-L289) | [tests/test_scanner_detect.py:267–280](https://github.com/Cezar277/heimdall/blob/b38dec179de6baf22fefd50056014e8ea26fc185/tests/test_scanner_detect.py#L267-L280) | secret coupé détecté ; au-delà de 4 Kio, limite figée par un test |
| ⚠️ Exclusions par **nom** (revue précédente, caduque : plus aucune exclusion par nom) | [heimdall/scanner/exclusions.py:25–133](https://github.com/Cezar277/heimdall/blob/b38dec179de6baf22fefd50056014e8ea26fc185/heimdall/scanner/exclusions.py#L25-L133) | [tests/test_scanner_detect.py:285–343](https://github.com/Cezar277/heimdall/blob/b38dec179de6baf22fefd50056014e8ea26fc185/tests/test_scanner_detect.py#L285-L343) | `.env`/`.pem`/`requirements.txt` scannés ; vendor/lock/binaire ignorés ; `.venv`/`venv`/`virtualenv` exclus, `env/` non |
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

## Corrections issues de la relecture « REQUEST CHANGES » (2ᵉ passage)

Cette section décrit le correctif demandé par la relecture « REQUEST CHANGES »
(contournement par exclusion nominale, binaire ignoré sans trace, secret coupé
par une ligne vide, lookbehind Slack). Les permaliens sont épinglés sur la
révision du code testé `5de5140153f593248b5f1823f271f2d7528a3205` (les sections antérieures restent
épinglées sur `b38dec1…`).

| Remarque | Correctif | Preuve |
|---|---|---|
| **HIGH** — contournement par exclusion nominale seule : `evil.png`, `evil.lock`, `package-lock.json`, `vendor/s.txt` contenant un secret rendaient `[]` (faux verdict propre) | le **contenu** décide : plus aucune exclusion par nom de fichier. Un fichier textuel est lu et scanné quelle que soit son extension ; un binaire connu est ignoré mais **tracé** ; un contenu ambigu est refusé. Les répertoires sont classés en trois régimes (`Perimetre`) : `strict` (échec fatal), `tiers` (arbres parcourus, échec tracé), `hors_perimetre` (base VCS, tracée) | [heimdall/scanner/exclusions.py:46–124](https://github.com/Cezar277/heimdall/blob/5de5140153f593248b5f1823f271f2d7528a3205/heimdall/scanner/exclusions.py#L46-L124), [heimdall/scanner/detect.py:312–411](https://github.com/Cezar277/heimdall/blob/5de5140153f593248b5f1823f271f2d7528a3205/heimdall/scanner/detect.py#L312-L411), [tests/test_scanner_detect.py:385–518](https://github.com/Cezar277/heimdall/blob/5de5140153f593248b5f1823f271f2d7528a3205/tests/test_scanner_detect.py#L385-L518), [tests/security/test_scanner_bypass.py:82–120](https://github.com/Cezar277/heimdall/blob/5de5140153f593248b5f1823f271f2d7528a3205/tests/security/test_scanner_bypass.py#L82-L120) |
| **MEDIUM** — binaire réellement binaire ignoré **sans trace** : un dépôt propre et un dépôt dont un binaire n'a pas été lu étaient indiscernables | le binaire ignoré est **journalisé sur `stderr`** (chemin seul, caractères de contrôle neutralisés, longueur bornée) et **compté** dans `RapportScan.binaires_ignores` ; la valeur n'est jamais reflétée | [heimdall/scanner/detect.py:108–123](https://github.com/Cezar277/heimdall/blob/5de5140153f593248b5f1823f271f2d7528a3205/heimdall/scanner/detect.py#L108-L123), [heimdall/scanner/detect.py:139–165](https://github.com/Cezar277/heimdall/blob/5de5140153f593248b5f1823f271f2d7528a3205/heimdall/scanner/detect.py#L139-L165), [heimdall/scanner/detect.py:487–489](https://github.com/Cezar277/heimdall/blob/5de5140153f593248b5f1823f271f2d7528a3205/heimdall/scanner/detect.py#L487-L489), [tests/test_scanner_detect.py:454–475](https://github.com/Cezar277/heimdall/blob/5de5140153f593248b5f1823f271f2d7528a3205/tests/test_scanner_detect.py#L454-L475) |
| **MEDIUM** — secret coupé par une ligne vide intercalée (`>\n\n`) : jamais détecté, sans `ScanError`, et la doc ne bornait que « 4 Kio / 2 lignes » | la fenêtre multi-ligne joint **deux lignes contiguës uniquement** (bornée à 4 Kio) ; les lignes vides intercalées (`\n\n`) sont **hors périmètre** (limite documentée tickets #23/#24) et figées par un test | [heimdall/scanner/signature_engine.py:31–35](https://github.com/Cezar277/heimdall/blob/5de5140153f593248b5f1823f271f2d7528a3205/heimdall/scanner/signature_engine.py#L31-L35), [heimdall/scanner/signature_engine.py:72–118](https://github.com/Cezar277/heimdall/blob/5de5140153f593248b5f1823f271f2d7528a3205/heimdall/scanner/signature_engine.py#L72-L118), [tests/test_scanner_detect.py:336–364](https://github.com/Cezar277/heimdall/blob/5de5140153f593248b5f1823f271f2d7528a3205/tests/test_scanner_detect.py#L336-L364) |
| **LOW** — lookbehind Slack élargi au `.` : `foo.xapp-…` et `foo.xoxe.…` devenaient des faux négatifs | retour au lookbehind d'origine `(?<![A-Za-z0-9-])` ; le point n'est pas une frontière de mot. La garde `(?<!xoxe\.)` (précise, préfixe rotatif seul) évite le double signalement d'un même secret — **un** secret, **une** empreinte, **une** entrée Vault | [heimdall/scanner/signatures/stripe_slack.py:33–86](https://github.com/Cezar277/heimdall/blob/5de5140153f593248b5f1823f271f2d7528a3205/heimdall/scanner/signatures/stripe_slack.py#L33-L86), [tests/test_scanner_detect.py:286–319](https://github.com/Cezar277/heimdall/blob/5de5140153f593248b5f1823f271f2d7528a3205/tests/test_scanner_detect.py#L286-L319) |
| **LOW** — hygiène de PR : quatre sous-tickets dans une PR | exception déjà tracée dans cette fiche (section « Exception de regroupement ») et dans la description de PR ; **à valider explicitement par les mainteneurs** avant fusion. Les PR suivantes suivront le découpage habituel | `docs/t22-samm.md#exception-de-regroupement` |
| Hors remarque — CLI : le message de refus annonçait encore « scanner non implémenté (voir #22) » alors que #22 est livré | message aligné sur l'état réel : « commande non branchée (voir #29) — refus par défaut », code 2 inchangé | [heimdall/cli/main.py:39–49](https://github.com/Cezar277/heimdall/blob/5de5140153f593248b5f1823f271f2d7528a3205/heimdall/cli/main.py#L39-L49), [tests/test_package.py:55–74](https://github.com/Cezar277/heimdall/blob/5de5140153f593248b5f1823f271f2d7528a3205/tests/test_package.py#L55-L74) |

### Ce que le correctif permet désormais de prouver

| Exigence vérifiée | Implémentation | Test et preuve permanente |
|---|---|---|
| **Aucun nom de fichier n'exclut un fichier du scan** (le secret dans `evil.png`, `package-lock.json` ou `vendor/` est détecté) | [heimdall/scanner/exclusions.py:46–124](https://github.com/Cezar277/heimdall/blob/5de5140153f593248b5f1823f271f2d7528a3205/heimdall/scanner/exclusions.py#L46-L124), [heimdall/scanner/detect.py:312–411](https://github.com/Cezar277/heimdall/blob/5de5140153f593248b5f1823f271f2d7528a3205/heimdall/scanner/detect.py#L312-L411) | [tests/test_scanner_detect.py:385–452](https://github.com/Cezar277/heimdall/blob/5de5140153f593248b5f1823f271f2d7528a3205/tests/test_scanner_detect.py#L385-L452), [tests/security/test_scanner_bypass.py:82–105](https://github.com/Cezar277/heimdall/blob/5de5140153f593248b5f1823f271f2d7528a3205/tests/security/test_scanner_bypass.py#L82-L105) |
| **Un contenu non analysé est tracé, jamais silencieusement ignoré** | [heimdall/scanner/detect.py:139–165](https://github.com/Cezar277/heimdall/blob/5de5140153f593248b5f1823f271f2d7528a3205/heimdall/scanner/detect.py#L139-L165), [heimdall/scanner/detect.py:487–489](https://github.com/Cezar277/heimdall/blob/5de5140153f593248b5f1823f271f2d7528a3205/heimdall/scanner/detect.py#L487-L489) | [tests/test_scanner_detect.py:454–499](https://github.com/Cezar277/heimdall/blob/5de5140153f593248b5f1823f271f2d7528a3205/tests/test_scanner_detect.py#L454-L499), [tests/security/test_scanner_bypass.py:107–120](https://github.com/Cezar277/heimdall/blob/5de5140153f593248b5f1823f271f2d7528a3205/tests/security/test_scanner_bypass.py#L107-L120) |
| **Un verdict « propre » est fondé** : le rapport expose ce qui n'a pas été lu (`RapportScan.complet`) | [heimdall/scanner/detect.py:139–165](https://github.com/Cezar277/heimdall/blob/5de5140153f593248b5f1823f271f2d7528a3205/heimdall/scanner/detect.py#L139-L165), [heimdall/scanner/detect.py:502–513](https://github.com/Cezar277/heimdall/blob/5de5140153f593248b5f1823f271f2d7528a3205/heimdall/scanner/detect.py#L502-L513) | [tests/test_scanner_detect.py:477–500](https://github.com/Cezar277/heimdall/blob/5de5140153f593248b5f1823f271f2d7528a3205/tests/test_scanner_detect.py#L477-L500) |
| **Un secret coupé par une ligne vide est hors périmètre** (`\n\n`, tickets #23/#24), la limite est figée | [heimdall/scanner/signature_engine.py:72–118](https://github.com/Cezar277/heimdall/blob/5de5140153f593248b5f1823f271f2d7528a3205/heimdall/scanner/signature_engine.py#L72-L118) | [tests/test_scanner_detect.py:336–364](https://github.com/Cezar277/heimdall/blob/5de5140153f593248b5f1823f271f2d7528a3205/tests/test_scanner_detect.py#L336-L364) |
| **Un jeton Slack après un point est détecté**, un jeton rotatif n'est signalé qu'une fois | [heimdall/scanner/signatures/stripe_slack.py:33–86](https://github.com/Cezar277/heimdall/blob/5de5140153f593248b5f1823f271f2d7528a3205/heimdall/scanner/signatures/stripe_slack.py#L33-L86) | [tests/test_scanner_detect.py:286–319](https://github.com/Cezar277/heimdall/blob/5de5140153f593248b5f1823f271f2d7528a3205/tests/test_scanner_detect.py#L286-L319) |

## Corrections issues de la relecture « REQUEST CHANGES » (3ᵉ passage)

Cette section décrit le correctif demandé par la relecture « REQUEST CHANGES »
(3ᵉ passage) : **aucun verdict propre partiel**. Les permaliens sont
épinglés sur la révision du code testé
`b2304c645445b9609b5d2ee50aed7a4255a55eef` (commit `fix(scanner): aucun
verdict propre partiel, journal et troncation (#22)`) ; les sections
antérieures restent épinglées sur `b38dec1…` et `5de5140…`.

| Remarque | Correctif | Preuve |
|---|---|---|
| **HIGH** — résultat partiel masqué en arbre tiers : `scan()` et `find_candidates()` jetaient les compteurs, donc un `vendor/` illisible, hors borne, non régulier ou mal nommé rendait `[]` — un **verdict propre inventé** alors que la docstring promettait déjà `ScanError` | `ScannerRacine.scan()` lève `ScanError` dès que `non_analyses > 0` ; `find_candidates()` et `scan()` en héritent. Seul `scan_rapport()` expose un bilan partiel (avec ses compteurs) ; les trois docstrings disent désormais ce qu'elles font | [heimdall/scanner/detect.py:343–359](https://github.com/Cezar277/heimdall/blob/b2304c645445b9609b5d2ee50aed7a4255a55eef/heimdall/scanner/detect.py#L343-L359), [heimdall/scanner/detect.py:558–601](https://github.com/Cezar277/heimdall/blob/b2304c645445b9609b5d2ee50aed7a4255a55eef/heimdall/scanner/detect.py#L558-L601), [tests/test_scanner_detect.py:629–716](https://github.com/Cezar277/heimdall/blob/b2304c645445b9609b5d2ee50aed7a4255a55eef/tests/test_scanner_detect.py#L629-L716), [tests/security/test_scanner_bypass.py:123–147](https://github.com/Cezar277/heimdall/blob/b2304c645445b9609b5d2ee50aed7a4255a55eef/tests/security/test_scanner_bypass.py#L123-L147) |
| **HIGH** — troncature entre `stat` et `open` : l'identité `dev`/`ino` ne voyait pas un fichier tronqué **sur le même inode** ; la lecture ne portait que sur un préfixe, le secret placé dans la partie tronquée disparaissait et le verdict « propre » était partiel | `_lire_borne` compare désormais l'état **avant** (`stat`) à l'état **après ouverture** (`fstat`) : taille et `mtime_ns` en plus de `dev`/`ino`. Toute divergence → refus (`ScanError`) avant lecture | [heimdall/scanner/detect.py:497–542](https://github.com/Cezar277/heimdall/blob/b2304c645445b9609b5d2ee50aed7a4255a55eef/heimdall/scanner/detect.py#L497-L542), [tests/test_scanner_detect.py:1076–1112](https://github.com/Cezar277/heimdall/blob/b2304c645445b9609b5d2ee50aed7a4255a55eef/tests/test_scanner_detect.py#L1076-L1112) |
| **HIGH** — `RapportScan.complet` ignorait `binaires_ignores`, `liens_ignores` et `hors_perimetre` : un dépôt avec un vrai binaire, un lien interne ou une base VCS rendait `complet is True` | `complet` est vrai **seulement** si les quatre compteurs sont nuls : rien n'a été laissé de côté, donc rien n'a pu cacher un secret. #29 doit refuser (code 2) tant que `complet` est faux | [heimdall/scanner/detect.py:151–190](https://github.com/Cezar277/heimdall/blob/b2304c645445b9609b5d2ee50aed7a4255a55eef/heimdall/scanner/detect.py#L151-L190), [tests/test_scanner_detect.py:719–762](https://github.com/Cezar277/heimdall/blob/b2304c645445b9609b5d2ee50aed7a4255a55eef/tests/test_scanner_detect.py#L719-L762), [tests/security/test_scanner_bypass.py:149–175](https://github.com/Cezar277/heimdall/blob/b2304c645445b9609b5d2ee50aed7a4255a55eef/tests/security/test_scanner_bypass.py#L149-L175) |
| **MEDIUM** — une racine contenant un octet NUL levait une `ValueError` nue, qui traversait le contrat d'erreur (message statique, code 2) | `_resolve_root` capture `ValueError` au même titre que `OSError`/`RuntimeError` : `ScanError` au message statique | [heimdall/scanner/detect.py:216–242](https://github.com/Cezar277/heimdall/blob/b2304c645445b9609b5d2ee50aed7a4255a55eef/heimdall/scanner/detect.py#L216-L242), [tests/test_scanner_detect.py:1114–1124](https://github.com/Cezar277/heimdall/blob/b2304c645445b9609b5d2ee50aed7a4255a55eef/tests/test_scanner_detect.py#L1114-L1124) |
| **MEDIUM** — le journal neutralisait seulement les contrôles ASCII : U+2028, U+2029, U+0085 et l'override U+202E subsistaient et pouvaient injecter une fausse ligne d'audit | `_safe_path` neutralise les catégories Unicode `Cc`, `Cf`, `Zl` et `Zp` : le journal reste **une ligne logique** par fichier | [heimdall/scanner/detect.py:91–134](https://github.com/Cezar277/heimdall/blob/b2304c645445b9609b5d2ee50aed7a4255a55eef/heimdall/scanner/detect.py#L91-L134), [tests/test_scanner_detect.py:789–840](https://github.com/Cezar277/heimdall/blob/b2304c645445b9609b5d2ee50aed7a4255a55eef/tests/test_scanner_detect.py#L789-L840) |
| **LOW** — la garde `xoxe.` était **inconditionnelle** : un préfixe rotatif bourré (`xxoxe.xapp-…`) ne correspondait plus à la forme rotative, et le jeton qu'il contient disparaissait (faux négatif). La charge de la forme rotative (250) était en outre plus courte que celle du jeton qu'elle porte (250 + `xoxe.`) : un jeton detectable seul pouvait ne plus l'être une fois préfixé | la garde devient **conditionnelle** à l'ancrage du préfixe (`(?<!(?<![A-Za-z0-9-])xoxe\.)`) : elle ne neutralise le jeton interne que si la règle rotative reconnaît le préfixe. La charge rotative passe à **255** (250 + 5) : un jeton detectable seul le reste une fois préfixé. « Un secret, une empreinte, une entrée Vault » est conservé, « jamais un manqué » aussi | [heimdall/scanner/signatures/stripe_slack.py:38–101](https://github.com/Cezar277/heimdall/blob/b2304c645445b9609b5d2ee50aed7a4255a55eef/heimdall/scanner/signatures/stripe_slack.py#L38-L101), [tests/test_scanner_detect.py:322–389](https://github.com/Cezar277/heimdall/blob/b2304c645445b9609b5d2ee50aed7a4255a55eef/tests/test_scanner_detect.py#L322-L389) |

### Ce que le correctif permet désormais de prouver

| Exigence vérifiée | Implémentation | Test et preuve permanente |
|---|---|---|
| **Aucun verdict propre partiel** : un fichier non analysable ne rend jamais une liste vide | [heimdall/scanner/detect.py:343–359](https://github.com/Cezar277/heimdall/blob/b2304c645445b9609b5d2ee50aed7a4255a55eef/heimdall/scanner/detect.py#L343-L359) | [tests/test_scanner_detect.py:629–716](https://github.com/Cezar277/heimdall/blob/b2304c645445b9609b5d2ee50aed7a4255a55eef/tests/test_scanner_detect.py#L629-L716), [tests/security/test_scanner_bypass.py:123–147](https://github.com/Cezar277/heimdall/blob/b2304c645445b9609b5d2ee50aed7a4255a55eef/tests/security/test_scanner_bypass.py#L123-L147) |
| **Un verdict « propre » n'est fondé que si rien n'a été laissé de côté** (binaire, lien, base VCS, fichier illisible) | [heimdall/scanner/detect.py:151–190](https://github.com/Cezar277/heimdall/blob/b2304c645445b9609b5d2ee50aed7a4255a55eef/heimdall/scanner/detect.py#L151-L190) | [tests/test_scanner_detect.py:719–762](https://github.com/Cezar277/heimdall/blob/b2304c645445b9609b5d2ee50aed7a4255a55eef/tests/test_scanner_detect.py#L719-L762), [tests/security/test_scanner_bypass.py:149–175](https://github.com/Cezar277/heimdall/blob/b2304c645445b9609b5d2ee50aed7a4255a55eef/tests/security/test_scanner_bypass.py#L149-L175) |
| **Un fichier tronqué entre le `stat` et l'`open` n'est jamais scanné partiellement** | [heimdall/scanner/detect.py:497–542](https://github.com/Cezar277/heimdall/blob/b2304c645445b9609b5d2ee50aed7a4255a55eef/heimdall/scanner/detect.py#L497-L542) | [tests/test_scanner_detect.py:1076–1112](https://github.com/Cezar277/heimdall/blob/b2304c645445b9609b5d2ee50aed7a4255a55eef/tests/test_scanner_detect.py#L1076-L1112) |
| **Le contrat d'erreur est unique** : une racine invalide ne produit jamais une `ValueError` nue | [heimdall/scanner/detect.py:216–242](https://github.com/Cezar277/heimdall/blob/b2304c645445b9609b5d2ee50aed7a4255a55eef/heimdall/scanner/detect.py#L216-L242) | [tests/test_scanner_detect.py:1114–1124](https://github.com/Cezar277/heimdall/blob/b2304c645445b9609b5d2ee50aed7a4255a55eef/tests/test_scanner_detect.py#L1114-L1124) |
| **Le journal reste une ligne logique par fichier** (contrôles ASCII, U+2028/U+2029, U+0085, U+202E) | [heimdall/scanner/detect.py:91–134](https://github.com/Cezar277/heimdall/blob/b2304c645445b9609b5d2ee50aed7a4255a55eef/heimdall/scanner/detect.py#L91-L134) | [tests/test_scanner_detect.py:789–840](https://github.com/Cezar277/heimdall/blob/b2304c645445b9609b5d2ee50aed7a4255a55eef/tests/test_scanner_detect.py#L789-L840) |
| **« Un secret, une empreinte, une entrée Vault » sans « jamais un manqué »** : l'« inner » d'un jeton rotatif reste détecté seul, et un préfixe rotatif bourré ne masque plus le secret | [heimdall/scanner/signatures/stripe_slack.py:38–101](https://github.com/Cezar277/heimdall/blob/b2304c645445b9609b5d2ee50aed7a4255a55eef/heimdall/scanner/signatures/stripe_slack.py#L38-L101) | [tests/test_scanner_detect.py:322–389](https://github.com/Cezar277/heimdall/blob/b2304c645445b9609b5d2ee50aed7a4255a55eef/tests/test_scanner_detect.py#L322-L389) |

## Corrections issues de la relecture « APPROVE WITH COMMENTS » (4ᵉ passage)

Cette section décrit le correctif demandé par la relecture « APPROVE WITH
COMMENTS » (4ᵉ passage) : *aucun verdict propre sans garde exécutable*, et
*aucun couplage fragile entre deux bornes*. Les permaliens sont épinglés sur
la révision du code testé
`c391cc0b15cd58743e826a2d5947e9743507b9ef` (commit `fix(scanner): garde executable du verdict propre, bornes
Slack couplees (#22)`) ; les sections antérieures restent épinglées sur
`b38dec1…`, `5de5140…` et `b2304c6…`.

| Remarque | Correctif | Preuve |
|---|---|---|
| **MEDIUM** — un verdict « propre » n'était fondé que par une **consigne de documentation** : `scan()`/`find_candidates()` rendent `[]` quand un binaire, un lien symbolique ou une base VCS ont été laissés de côté ; rien n'empêchait un futur appelant (#29) de confondre `[]` et « dépôt propre » | la garde est désormais **programmatique** : `exiger_complet(rapport)` refuse un rapport incomplet par `ScanError` (message statique — le refus que la CLI traduit par le **code 2**, jamais 0 ni 1) ; `ScannerRacine.analyser_complet()` et `scan_complet()` l'appliquent d'office ; `scan()`/`find_candidates()` **avertissent** (`ScanIncomplet`) quand une liste vide ne signifie que « rien trouvé dans ce qui a été lu ». La CLI reste refusée par défaut (code 2) | [heimdall/scanner/detect.py:212–236](https://github.com/Cezar277/heimdall/blob/c391cc0b15cd58743e826a2d5947e9743507b9ef/heimdall/scanner/detect.py#L212-L236), [heimdall/scanner/detect.py:380–388](https://github.com/Cezar277/heimdall/blob/c391cc0b15cd58743e826a2d5947e9743507b9ef/heimdall/scanner/detect.py#L380-L388), [heimdall/scanner/detect.py:656–673](https://github.com/Cezar277/heimdall/blob/c391cc0b15cd58743e826a2d5947e9743507b9ef/heimdall/scanner/detect.py#L656-L673), [heimdall/scanner/errors.py:26–36](https://github.com/Cezar277/heimdall/blob/c391cc0b15cd58743e826a2d5947e9743507b9ef/heimdall/scanner/errors.py#L26-L36), [tests/security/test_scanner_bypass.py:183–276](https://github.com/Cezar277/heimdall/blob/c391cc0b15cd58743e826a2d5947e9743507b9ef/tests/security/test_scanner_bypass.py#L183-L276) |
| **LOW** — couplage fragile des bornes Slack (250 / 255) entre deux règles : la garde `xoxe.` neutralise le jeton interne sans vérifier la charge ; si une borne évoluait sans l'autre, un secret préfixé devenait invisible **des deux** règles | les bornes sont **dérivées** des mêmes constantes (`SLACK_PAYLOAD_MAX` → `SLACK_TOKEN_MAX` → `ROTATING_PAYLOAD_MAX`) : elles ne peuvent plus diverger par retouche locale. L'invariant « la forme rotative couvre tout jeton detectable seul » est **vérifié au chargement** du registre (fail-closed : un registre incohérent refuse d'être importé) et **figé par un test** aux bornes exactes (jeton interne à charge maximale : exactement un finding, la forme rotative) | [heimdall/scanner/signatures/stripe_slack.py:30–91](https://github.com/Cezar277/heimdall/blob/c391cc0b15cd58743e826a2d5947e9743507b9ef/heimdall/scanner/signatures/stripe_slack.py#L30-L91), [tests/test_scanner_detect.py:400–452](https://github.com/Cezar277/heimdall/blob/c391cc0b15cd58743e826a2d5947e9743507b9ef/tests/test_scanner_detect.py#L400-L452) |
| **LOW** — le commentaire « garde conditionnelle » sur-promettait : il annonçait que le jeton interne n'est neutralisé que « si la règle `slack_rotating_token` le reconnaît », alors que la regex ne teste ni la longueur ni la frontière avale | le commentaire et la documentation disent maintenant **exactement** ce qui est garanti : la neutralisation est conditionnelle à l'**ancrage** du préfixe `xoxe.`, et elle coïncide avec la reconnaissance de la forme rotative **dans les bornes documentées** — coïncidence rendue structurelle par les bornes dérivées. La limite au-delà (charge > 250) est **écrite** et figée par un test : un jeton hors bornes n'est detectable ni seul ni préfixé | [heimdall/scanner/signatures/stripe_slack.py:56–73](https://github.com/Cezar277/heimdall/blob/c391cc0b15cd58743e826a2d5947e9743507b9ef/heimdall/scanner/signatures/stripe_slack.py#L56-L73), [heimdall/scanner/signatures/stripe_slack.py:108–130](https://github.com/Cezar277/heimdall/blob/c391cc0b15cd58743e826a2d5947e9743507b9ef/heimdall/scanner/signatures/stripe_slack.py#L108-L130), [docs/scanner.md](scanner.md#signatures-54), [docs/scanner-signatures.md](scanner-signatures.md#les-dix-règles), [tests/test_scanner_detect.py:442–452](https://github.com/Cezar277/heimdall/blob/c391cc0b15cd58743e826a2d5947e9743507b9ef/tests/test_scanner_detect.py#L442-L452) |
| **LOW** — hygiène de PR : quatre sous-tickets dans une PR | exception **signalée à nouveau** dans cette fiche (section « Exception de regroupement ») : elle reste une exception, à faire **valider explicitement par les mainteneurs** avant fusion. Le 4ᵉ passage ne modifie ni le découpage ni le périmètre des sous-tickets | [docs/t22-samm.md](#exception-de-regroupement) |
| **LOW** — preuves SAMM épinglées sur des SHA intermédiaires : les permaliens pointaient vers `5de5140…`, `b2304c6…` et `2ba3ebf…`, pas vers le SHA final : la preuve **pourrit** dès la fusion | le re-pin est **outillé** et **déterministe** : `scripts/repin_samm.py --sha <sha-final>` ré-écrit les permaliens des fichiers encore livrés (les preuves historiques, dont le fichier a disparu depuis, restent épinglées sur leur révision d'origine), et `scripts/repin_samm.py --check` signale tout permalien mort. Les **29 permaliens** pointant vers un dépôt mal orthographié (`Cezarwers`) sont corrigés : une preuve morte n'est plus une preuve | [scripts/repin_samm.py](https://github.com/Cezar277/heimdall/blob/c391cc0b15cd58743e826a2d5947e9743507b9ef/scripts/repin_samm.py), [tests/security/test_samm_permalinks.py](https://github.com/Cezar277/heimdall/blob/c391cc0b15cd58743e826a2d5947e9743507b9ef/tests/security/test_samm_permalinks.py) |

### Ce que le correctif permet désormais de prouver

| Exigence vérifiée | Implémentation | Test et preuve permanente |
|---|---|---|
| **Aucun verdict « propre » sans garde exécutable** : un rapport incomplet est **refusé** (`ScanError`, code 2 attendu), jamais rendu comme un dépôt propre | [heimdall/scanner/detect.py:212–236](https://github.com/Cezar277/heimdall/blob/c391cc0b15cd58743e826a2d5947e9743507b9ef/heimdall/scanner/detect.py#L212-L236) | [tests/security/test_scanner_bypass.py:183–220](https://github.com/Cezar277/heimdall/blob/c391cc0b15cd58743e826a2d5947e9743507b9ef/tests/security/test_scanner_bypass.py#L183-L220) (binaire, lien, base VCS, fichier non analysable : refus dans les quatre cas) |
| **La CLI ne peut pas annoncer de verdict propre tant que #29 n'est pas branché** (sortie 2, jamais 0) | [heimdall/cli/main.py:38–49](https://github.com/Cezar277/heimdall/blob/c391cc0b15cd58743e826a2d5947e9743507b9ef/heimdall/cli/main.py#L38-L49) | [tests/security/test_scanner_bypass.py:264–276](https://github.com/Cezar277/heimdall/blob/c391cc0b15cd58743e826a2d5947e9743507b9ef/tests/security/test_scanner_bypass.py#L264-L276), [tests/test_package.py:53–69](https://github.com/Cezar277/heimdall/blob/c391cc0b15cd58743e826a2d5947e9743507b9ef/tests/test_package.py#L53-L69) |
| **Les bornes Slack sont couplées par construction** : la forme rotative couvre tout jeton detectable seul, invariant vérifié au chargement du registre | [heimdall/scanner/signatures/stripe_slack.py:30–91](https://github.com/Cezar277/heimdall/blob/c391cc0b15cd58743e826a2d5947e9743507b9ef/heimdall/scanner/signatures/stripe_slack.py#L30-L91) | [tests/test_scanner_detect.py:400–418](https://github.com/Cezar277/heimdall/blob/c391cc0b15cd58743e826a2d5947e9743507b9ef/tests/test_scanner_detect.py#L400-L418) |
| **Aux bornes exactes, un jeton préfixé reste détecté** (un seul finding : la forme rotative) ; au-delà, la limite est écrite et figée | [heimdall/scanner/signatures/stripe_slack.py:155–176](https://github.com/Cezar277/heimdall/blob/c391cc0b15cd58743e826a2d5947e9743507b9ef/heimdall/scanner/signatures/stripe_slack.py#L155-L176) | [tests/test_scanner_detect.py:420–452](https://github.com/Cezar277/heimdall/blob/c391cc0b15cd58743e826a2d5947e9743507b9ef/tests/test_scanner_detect.py#L420-L452) |
| **Les preuves SAMM ne sont pas des liens morts** : dépôt attendu, révision connue, fichier présent à la révision, re-pin outillé | [scripts/repin_samm.py](https://github.com/Cezar277/heimdall/blob/c391cc0b15cd58743e826a2d5947e9743507b9ef/scripts/repin_samm.py) | [tests/security/test_samm_permalinks.py](https://github.com/Cezar277/heimdall/blob/c391cc0b15cd58743e826a2d5947e9743507b9ef/tests/security/test_samm_permalinks.py) |

## Corrections issues de la relecture « APPROVE WITH COMMENTS » (5ᵉ passage)

Cette section décrit le correctif demandé par la relecture du 5ᵉ passage :
*l'élagage VCS doit être observable*, *un gitlink `.git` légitime ne doit pas
bloquer le scan*, *la documentation ne doit plus promettre une API absente*,
*le mode fichier unique doit re-vérifier sa racine*, et *le helper binaire
nominal ne doit plus pouvoir décider du périmètre*. Les preuves ci-dessous
sont des **noms de modules et de tests** (pas de permalien sur un SHA
intermédiaire) ; après le squash, `scripts/repin_samm.py --sha <sha-final>`
re-pince les liens historiques et `--check` refuse tout lien mort.

| Remarque | Correctif | Preuve |
|---|---|---|
| **MEDIUM** — base VCS élaguée silencieusement : un dépôt dont le seul `.git/config` contient un candidat rend `[]`, indistinguable d'un dépôt propre | l'élagage reste une politique (l'historique n'est pas le contenu), mais il est **compté** : `heimdall.scanner.detect.Scanner.vcs_ignored` expose le nombre de bases VCS écartées lors du dernier scan, sans chemin ni valeur. `docs/scanner.md`, `docs/cli.md` et `docs/security/requirements.md` disent explicitement que l'arbre ne couvre jamais l'historique et que `--staged` couvre l'index, pas les commits déjà écrits | `heimdall/scanner/detect.py` (`vcs_ignored`, `_iter_files`) ; `tests/test_scanner_detect.py::test_the_vcs_skip_is_counted_and_never_claimed_complete`, `::test_a_vcs_database_with_a_secret_returns_an_empty_list` |
| **MEDIUM** — un fichier `.git` gitlink (`gitdir: …`) était classé hors périmètre et levait `ScanError`, bloquant les worktrees et sous-modules légitimes | `est_chemin_hors_perimetre` n'examine plus que les segments **parents** : le dernier segment est un fichier. Un `.git` régulier est lu par contenu ; le répertoire `.git/` reste élagué par `est_base_vcs`. Le test fige les deux cas (gitlink légitime sans erreur, contenu `.git` scanné) | `heimdall/scanner/exclusions.py` (`est_chemin_hors_perimetre`) ; `tests/test_scanner_detect.py::test_a_gitlink_file_is_not_mistaken_for_the_vcs_database` |
| **MEDIUM** — `requirements.md` promettait `RapportScan.complet` et `scan_complet()`, API absente du code : preuve SAMM mensongère | la documentation est alignée sur le code : `scan()`/`find_candidates()` lèvent `ScanError` pour tout fichier du périmètre non analysable ; seule la base VCS est élaguée, comptée par `heimdall.scanner.detect.Scanner.vcs_ignored` ; aucune API de rapport complet n'est annoncée tant qu'elle n'est pas livrée. Les références aux tests supprimés (`test_named_exclusions_cannot_hide_a_secret`, `test_a_binary_ignored_is_traced_and_never_leaks`, etc.) sont remplacées par les tests réellement présents | `docs/security/requirements.md` (REQ-SEC-07), `docs/scanner.md`, `docs/cli.md`, `docs/t22-samm.md` ; `tests/test_scanner_detect.py::test_a_real_binary_is_fail_closed`, `::test_symlinks_are_fail_closed`, `::test_a_broken_file_in_the_strict_perimeter_is_fail_closed` |
| **LOW** — fenêtre TOCTOU en mode fichier unique : `__init__` suit `is_dir()`/`is_file()`, et `_single` ne re-`lstat` pas la racine parente avant lecture | `Scanner.scan()` re-vérifie la racine par `lstat` (répertoire, pas un lien) **avant** toute lecture, y compris en mode fichier unique ; `_read_text` conserve ses gardes (`resolve` + `is_relative_to` + `lstat` + `O_NOFOLLOW` + `fstat`/`mtime_ns`). Aucun contenu n'est lu après un remplacement de la racine parente | `heimdall/scanner/detect.py` (`_recheck_root`, `scan`) ; `tests/test_scanner_detect.py::test_a_single_file_parent_replaced_by_a_symlink_before_reading_is_fail_closed` |
| **LOW** — `is_known_binary` restait exporté comme si le nom pouvait décider du périmètre | le helper de décision devient interne (`_is_known_binary`), utilisé par `decode_text` ; `is_known_binary` reste un **alias déprécié** de compatibilité, sans autorité. Instrumenter l'alias public ne change donc jamais un verdict : le test le patche pour lever et vérifie qu'un binaire connu reste refusé par `ScanError` | `heimdall/scanner/exclusions.py` (`_is_known_binary`, `is_known_binary`, `decode_text`) ; `tests/test_scanner_detect.py::test_scanner_does_not_consult_the_deprecated_binary_helper` |
| **LOW** — hygiène de PR : quatre sous-tickets dans une PR | exception **maintenue et signalée** dans la section « Exception de regroupement » ; elle reste à valider par les mainteneurs avant fusion. Aucun nouveau sous-ticket n'est ajouté | `docs/t22-samm.md#exception-de-regroupement` |

### Ce que le correctif permet désormais de prouver

| Exigence vérifiée | Implémentation | Test et preuve permanente |
|---|---|---|
| **L'élagage VCS est observable, jamais présenté comme un historique propre** | `heimdall.scanner.detect.Scanner.vcs_ignored` ; docs alignées | `tests/test_scanner_detect.py::test_the_vcs_skip_is_counted_and_never_claimed_complete`, `::test_a_vcs_database_with_a_secret_returns_an_empty_list` |
| **Un gitlink `.git` légitime ne bloque plus le scan ; son contenu décide** | `est_chemin_hors_perimetre` (segments parents seulement) | `tests/test_scanner_detect.py::test_a_gitlink_file_is_not_mistaken_for_the_vcs_database` |
| **La documentation ne promet aucune API absente** | `docs/security/requirements.md` (REQ-SEC-07), `docs/scanner.md`, `docs/cli.md` | `grep` de contrôle dans la revue ; tests `test_scanner_detect.py` cités dans REQ-SEC-07 |
| **Aucune lecture après remplacement de la racine parente en mode fichier unique** | `_recheck_root` appelé par `scan()` | `tests/test_scanner_detect.py::test_a_single_file_parent_replaced_by_a_symlink_before_reading_is_fail_closed` |
| **Le nom public du helper binaire n'a plus d'autorité** | `_is_known_binary` interne + alias déprécié | `tests/test_scanner_detect.py::test_scanner_does_not_consult_the_deprecated_binary_helper` |

## Corrections issues de la relecture « APPROVE WITH COMMENTS » (6ᵉ passage)

Cette section décrit le correctif demandé par la relecture du 6ᵉ passage :
*la neutralisation du jeton interne doit tester la forme rotative complète*,
*le helper binaire déprécié doit être explicitement interdit dans la doc*,
*le re-pin ne doit suivre aucun lien symbolique*, et *les tests manquants
doivent figer le compteur VCS, la matrice gitlink et les bornes Slack*.
Les preuves ci-dessous sont des **noms de modules et de tests** (pas de
permalien sur un SHA intermédiaire) ; après le squash,
`scripts/repin_samm.py --sha <sha-final>` re-pince les liens historiques et
`--check` refuse tout lien mort.

| Remarque | Correctif | Preuve |
|---|---|---|
| **LOW** — la garde rotative neutralisait le jeton interne sans tester la longueur de la forme rotative | la garde regex est supprimée : les règles « seul » reconnaissent le jeton, puis `signatures.find_signature_matches` écarte le doublon **seulement si** une forme `xoxe.` complète a été reconnue et que le jeton interne occupe exactement sa charge. La neutralisation teste donc la longueur et la frontière avale ; un préfixe bourré ou une charge hors bornes ne masque rien | `heimdall/scanner/signatures/stripe_slack.py`, `heimdall/scanner/signatures/__init__.py` ; `tests/test_scanner_detect.py::test_a_maximal_inner_token_stays_detectable_once_prefixed`, `::test_an_oversized_inner_token_is_a_documented_limit`, `::test_a_padded_rotating_prefix_does_not_hide_the_inner_token` |
| **LOW** — `is_known_binary` restait exporté comme si le nom pouvait décider du périmètre | `docs/scanner.md` interdit explicitement de brancher le périmètre sur ce nom public et rappelle que `decode_text` n'utilise que `_is_known_binary` ; l'alias reste sans autorité et sa suppression est renvoyée à un ticket dédié | `docs/scanner.md` (Périmètre), `heimdall/scanner/exclusions.py` ; `tests/test_scanner_detect.py::test_scanner_does_not_consult_the_deprecated_binary_helper` |
| **LOW** — `_livre()` suivait les liens symboliques avant le confinement | `_livre()` refuse désormais tout composant symbolique par `lstat` avant de résoudre et de confiner le chemin ; un lien interne, externe ou vers `/etc/passwd` n'est jamais « livré » et n'est donc pas re-pincé | `scripts/repin_samm.py` (`_livre`) ; `tests/security/test_samm_permalinks.py::test_livre_refuses_symlinks_even_inside_the_repository`, `::test_the_repin_never_rewrites_a_permalink_to_a_symlink` |
| **LOW** — tests manquants : compteur VCS remis à zéro, matrice gitlink, bornes Slack 250/256 | les tests figent le comportement : re-scan après ajout puis suppression de `.git/` (0 → 1 → 0), fichier `.git` lu vs répertoire `.git/` élagué et compté vs `a/.git/b.txt` refusé, jeton interne à charge 250 préfixé (un seul Finding rotatif) et charges 251/256 (limite documentée) | `tests/test_scanner_detect.py::test_vcs_ignored_is_reset_between_scans`, `::test_gitlink_file_and_vcs_directory_scan_matrix`, `::test_a_maximal_inner_token_stays_detectable_once_prefixed`, `::test_an_oversized_inner_token_is_a_documented_limit` |
| **LOW** — hygiène PR : quatre sous-tickets dans une PR | exception maintenue et signalée ; elle reste à valider par les mainteneurs. Le 6ᵉ passage ne modifie pas le découpage | `docs/t22-samm.md#exception-de-regroupement` |
| **LOW** — preuves à re-pinner après squash | `repin_samm.py --check` est vert sur l'arbre courant ; le SHA du squash reste la seule valeur à fournir après fusion (`--sha <sha-final>`) | `scripts/repin_samm.py`, `tests/security/test_samm_permalinks.py` |

### Ce que le correctif permet désormais de prouver

| Exigence vérifiée | Implémentation | Test et preuve permanente |
|---|---|---|
| **La neutralisation d'un jeton rotatif est conditionnelle à la reconnaissance de la forme complète** (longueur et frontière avale) | `heimdall/scanner/signatures/__init__.py` (`find_signature_matches`, `_matches_rotatifs`), `stripe_slack.py` (bornes dérivées) | `tests/test_scanner_detect.py::test_a_maximal_inner_token_stays_detectable_once_prefixed`, `::test_an_oversized_inner_token_is_a_documented_limit`, `::test_a_padded_rotating_prefix_does_not_hide_the_inner_token` |
| **Le helper binaire déprécié ne peut pas décider du périmètre** | `docs/scanner.md` (API dépréciée), `exclusions.py` (`_is_known_binary`) | `tests/test_scanner_detect.py::test_scanner_does_not_consult_the_deprecated_binary_helper` |
| **Le re-pin ne suit aucun lien symbolique et reste confiné** | `scripts/repin_samm.py` (`_livre`, `_resoudre_fiche`) | `tests/security/test_samm_permalinks.py::test_livre_refuses_symlinks_even_inside_the_repository`, `::test_the_repin_never_rewrites_a_permalink_to_a_symlink`, `::test_the_repin_refuses_a_fiche_outside_the_repository` |
| **Le compteur VCS décrit le scan courant, la matrice gitlink est figée** | `heimdall/scanner/detect.py` (`scan`, `_iter_files`), `exclusions.py` | `tests/test_scanner_detect.py::test_vcs_ignored_is_reset_between_scans`, `::test_gitlink_file_and_vcs_directory_scan_matrix` |

## Corrections issues de la relecture « APPROVE WITH COMMENTS » (7ᵉ passage)

Cette section décrit le correctif demandé par la relecture du 7ᵉ passage
(run `40239618119`) : *la limite d'un arbre réduit à sa base VCS est figée par
test plutôt que masquée par le code de sortie* (option explicitement acceptée
par la revue), *le helper binaire déprécié ne doit pas être exposé comme une
API de périmètre*, *le code mort du re-pin est supprimé*, et *les tests
manquants sont figés au niveau du scan et de la CLI*. Les preuves ci-dessous
sont des **noms de modules et de tests** (pas de permalien sur un SHA
intermédiaire) ; après le squash,
`scripts/repin_samm.py --sha <sha-final>` re-pince les liens historiques et
`--check` refuse tout lien mort.

| Remarque | Correctif | Preuve |
|---|---|---|
| **LOW** — un `[]` avec base VCS élaguée restait exit 0 : une automatisation qui ne lit que le code de sortie confondait « propre » et « non parcouru » | la politique est **figée par test** (option acceptée par la revue) : la bibliothèque rend `[]`, `vcs_ignored == 1` et le nouveau `files_scanned == 0` ; la CLI rend 0 pour un arbre réellement vide et rappelle `vcs_ignored` en JSON/`--ci`. Le test rejoue ensuite `--staged` sur le même dépôt et prouve qu'un secret indexé est détecté (code 1) : seul `--staged` couvre le contenu commité. Aucun dépôt vide légitime ne régresse en code 2 | `heimdall/scanner/detect.py` (`files_scanned`), `docs/scanner.md`, `docs/cli.md` ; `tests/test_cli_scan.py::test_scan_tree_vcs_only_is_policy_and_staged_covers_content`, `tests/test_scanner_detect.py::test_files_scanned_describes_the_current_scan` |
| **LOW** — le helper binaire déprécié restait exporté comme une API de périmètre | la surface publique est **fermée** : `exclusions.__all__` ne contient plus `is_known_binary` (l'alias reste importable pour compatibilité, sans autorité). La documentation interdit explicitement de brancher un périmètre, une allowlist ou un skip sur ce nom ; `decode_text` n'utilise que `_is_known_binary` | `heimdall/scanner/exclusions.py` (`__all__`), `docs/scanner.md` (API dépréciée) ; `tests/test_scanner_detect.py::test_the_deprecated_binary_helper_is_not_exported`, `::test_scanner_does_not_consult_the_deprecated_binary_helper` |
| **LOW** — `SHA_ISOLE` était du code mort dans un outil de preuve | la regex inutilisée est supprimée ; aucun comportement de `repin_samm.py` ne change | `scripts/repin_samm.py` ; `tests/security/test_samm_permalinks.py` |
| **LOW** — tests manquants : compteur VCS, matrice gitlink, bornes Slack, non-autorité du helper | les tests figent le re-scan (0 → 1 → 0), les trois cas gitlink (fichier lu, répertoire élagué et compté, parent refusé), les bornes Slack au niveau du scan (`xoxe.` + 250 → un Finding rotatif ; 251/256 → limite documentée) et l'absence d'autorité du helper public | `tests/test_scanner_detect.py::test_vcs_ignored_is_reset_between_scans`, `::test_gitlink_file_and_vcs_directory_scan_matrix`, `::test_the_rotating_bounds_are_frozen_at_scan_level`, `::test_scanner_does_not_consult_the_deprecated_binary_helper` |
| **LOW** — hygiène PR : quatre sous-tickets dans une PR | exception maintenue et signalée ; elle reste à valider par les mainteneurs. Le 7ᵉ passage ne modifie pas le découpage | `docs/t22-samm.md#exception-de-regroupement` |
| **LOW** — preuves à re-pinner après squash | `repin_samm.py --check` est vert sur l'arbre courant ; le SHA du squash reste la seule valeur à fournir après fusion (`--sha <sha-final>`) | `scripts/repin_samm.py`, `tests/security/test_samm_permalinks.py` |

### Ce que le correctif permet désormais de prouver

| Exigence vérifiée | Implémentation | Test et preuve permanente |
|---|---|---|
| **Un arbre vide reste un 0 assumé ; `--staged` couvre le contenu indexé** (secret indexé => 1) | `heimdall/scanner/detect.py` (`files_scanned`), `heimdall/cli/scan.py` (`_collect_staged`) | `tests/test_cli_scan.py::test_scan_tree_vcs_only_is_policy_and_staged_covers_content` |
| **Le contenu indexé reste couvert par `--staged`**, indépendamment de l'élagage VCS de l'arbre | `heimdall/cli/scan.py` (`_collect_staged`) | `tests/test_cli_scan.py::test_scan_tree_vcs_only_is_policy_and_staged_covers_content` |
| **Le helper binaire déprécié n'est pas une API de périmètre** : ni exporté, ni consulté par le scanner | `heimdall/scanner/exclusions.py` (`__all__`, `_is_known_binary`) | `tests/test_scanner_detect.py::test_the_deprecated_binary_helper_is_not_exported`, `::test_scanner_does_not_consult_the_deprecated_binary_helper` |
| **Les bornes Slack sont figées jusqu'au Finding** (250 détecté une fois, 251/256 limite documentée) | `heimdall/scanner/signatures/stripe_slack.py` (bornes dérivées) | `tests/test_scanner_detect.py::test_the_rotating_bounds_are_frozen_at_scan_level` |
| **Le compteur VCS décrit le scan courant** et ne compte jamais un fichier de contenu | `heimdall/scanner/detect.py` (`scan`, `files_scanned`, `vcs_ignored`) | `tests/test_scanner_detect.py::test_vcs_ignored_is_reset_between_scans`, `::test_files_scanned_describes_the_current_scan` |

## Révisions à re-pinner après la fusion

Les permaliens de cette fiche sont épinglés sur la révision du code testé
`c391cc0b15cd58743e826a2d5947e9743507b9ef` (et, pour les sections
antérieures, sur `b2304c6…`, `5de5140…` et `b38dec1…`). Tant que ces
révisions sont des commits **intermédiaires** de la branche, la preuve est
rejouable sur la branche mais **pourrit à la fusion** (un squash n'apporte pas
les commits intermédiaires dans `main`) : les liens deviennent morts et la
preuve n'est plus vérifiable par un auditeur.

Le correctif du 5ᵉ passage est intégré dans l'historique de la branche
(`44bfb19` → `05884f4` → `5be81e4`), puis `eb68425` résout le conflit de
`main.py`. Ses preuves sont volontairement citées par **nom de test**
(section « 5ᵉ passage »), sans permalien sur un SHA intermédiaire. Elles
seront re-pinées avec le reste au SHA du squash.

Le correctif du 6ᵉ passage est appliqué dans l'arbre de travail au-dessus de
`eb684254ec6544f632a1f4732cd28aa1a14941ee` ; il n'a pas encore de SHA propre.
Ses preuves sont également citées par **nom de test** (section « 6ᵉ passage »)
et seront re-pinées avec le reste au SHA du squash. `repin_samm.py --check`
est vert sur cet arbre ; il ne reste que le SHA final à fournir après fusion.

| Révision | Commit | Passe |
|---|---|---|
| `c391cc0b15cd58743e826a2d5947e9743507b9ef` | fix(scanner): garde executable du verdict propre, bornes Slack couplees (#22) | 4ᵉ passage |
| `44bfb191af4c804014eb108eac5c4f995973a1e6` | Fix(scanner): sécurisation TOCTOU et alignement documentaire | Base du correctif du 5ᵉ passage |
| `5be81e45529a60e4c59523caf677bc4b90220256` | Fix(scanner): sécurisation finale --staged, observabilité CLI et TOCTOU ancêtres | 5ᵉ passage (intégré) |
| `eb684254ec6544f632a1f4732cd28aa1a14941ee` | Résolution du conflit dans main.py : conservation de la version en ligne | Base du correctif du 6ᵉ passage (non commité) |

Après la fusion (SHA du squash connu), re-pince **en une commande** :

```sh
python scripts/repin_samm.py --sha <sha-du-squash>   # ré-écrit la fiche
python scripts/repin_samm.py --check                 # contrôle : 0 permutation
```

Le re-pin ne touche qu'aux permaliens dont le fichier est **encore livré** :
les preuves historiques (fichier déplacé ou supprimé depuis) restent épinglées
sur leur révision d'origine, sinon elles deviendraient des liens morts. La
table ci-dessus est alors vidée, et `tests/security/test_samm_permalinks.py`
vérifie qu'aucun permalien mort ne subsiste.

## Durcissements de l'amont conservés au rebase

Le correctif ci-dessus a été rejoué sur `origin/22-t22-scanner-regex-de-signatures-et-exclusions`
(branche distante, commits `420ec98` → `2ba3ebf` → `a03b6ab`). Les durcissements
apportés en amont **ne sont pas perdus** : ils sont reportés dans le code local,
et les permaliens ci-dessous sont épinglés sur la révision du code testé
`5de5140153f593248b5f1823f271f2d7528a3205`.

| Durcissement | Porté dans | Preuve |
|---|---|---|
| **Anti-TOCTOU** : après le `lstat` des ancêtres, `resolve()` est revérifié — un composant remplacé par un lien entre les deux appels est **refusé** (`ScanError`) au lieu de scanner une cible détournée | [heimdall/scanner/detect.py:191–213](https://github.com/Cezar277/heimdall/blob/5de5140153f593248b5f1823f271f2d7528a3205/heimdall/scanner/detect.py#L191-L213) | [tests/test_scanner_detect.py:685–727](https://github.com/Cezar277/heimdall/blob/5de5140153f593248b5f1823f271f2d7528a3205/tests/test_scanner_detect.py#L685-L727) (racine, fichier unique et ancêtre symlinkés → `ScanError`) |
| **Racine canonique** : une racine dont la résolution dévie est refusée (ex. `/tmp` symlinké vers `/private/tmp` sur macOS) — il faut un chemin canonique, sans lien | [heimdall/scanner/detect.py:191–213](https://github.com/Cezar277/heimdall/blob/5de5140153f593248b5f1823f271f2d7528a3205/heimdall/scanner/detect.py#L191-L213) | [tests/test_scanner_detect.py:685–727](https://github.com/Cezar277/heimdall/blob/5de5140153f593248b5f1823f271f2d7528a3205/tests/test_scanner_detect.py#L685-L727) |
| **Périmètre en flux** : le parcours n'est pas matérialisé en liste — un dépôt adverse ne doit pas provoquer d'OOM dans un hook/CI ; le tri final porte sur les findings, pas sur les chemins | [heimdall/scanner/detect.py:270–292](https://github.com/Cezar277/heimdall/blob/5de5140153f593248b5f1823f271f2d7528a3205/heimdall/scanner/detect.py#L270-L292) | [tests/test_scanner_detect.py:385–518](https://github.com/Cezar277/heimdall/blob/5de5140153f593248b5f1823f271f2d7528a3205/tests/test_scanner_detect.py#L385-L518) |
| **Contradiction Slack arbitrée** : l'amont tolérait le doublon (`xoxe.xapp-…` signalé deux fois, « doublon acceptable, jamais un manqué ») ; le contrat local « un secret, une empreinte, une entrée Vault » le supprime. « Jamais un manqué » reste couvert : l'évasion par préfixe (`.xapp-…`) est toujours détectée | [heimdall/scanner/signatures/stripe_slack.py:33–86](https://github.com/Cezar277/heimdall/blob/5de5140153f593248b5f1823f271f2d7528a3205/heimdall/scanner/signatures/stripe_slack.py#L33-L86) | [tests/test_scanner_detect.py:258–279](https://github.com/Cezar277/heimdall/blob/5de5140153f593248b5f1823f271f2d7528a3205/tests/test_scanner_detect.py#L258-L279), [286–319](https://github.com/Cezar277/heimdall/blob/5de5140153f593248b5f1823f271f2d7528a3205/tests/test_scanner_detect.py#L286-L319) |

Le 3ᵉ passage **étend** ces durcissements au lieu de les remplacer : la
race de la racine (`_resolve_root`, désormais `detect.py:216–242` sur
`b2304c6…`) est conservée et gagne la conversion de la `ValueError` ; la race
de la **lecture** est fermée par la comparaison `before`/`after`
(`detect.py:497–542` sur `b2304c6…`) ; la contradiction Slack est arbitrée
dans les deux sens — « un secret, une empreinte » **et** « jamais un manqué »
(voir la section « 3ᵉ passage »).

Le durcissement de lecture est complété sans changer le contrat : une racine
**vide** ou d'un **type non chemin** est refusée (`ScanError` statique, jamais
`TypeError`/`ValueError` nue) ; l'ouverture est `O_NONBLOCK`, donc un fichier
régulier remplacé par un FIFO entre le `stat` et l'`open` est refusé par
`fstat` au lieu de bloquer le hook/CI ; le journal neutralise aussi les
surrogates d'un nom non UTF-8 (`Cs`) ; une erreur de parcours sur un répertoire
de tiers est classée avec **son propre nom**, donc un `vendor/` illisible à la
racine est tracé/compté comme les autres échecs de l'arbre de tiers. Tests :
`test_an_empty_root_is_fail_closed`, `test_a_non_path_root_is_fail_closed`,
`test_open_flags_are_read_only_non_blocking_and_never_follow_links`,
`test_the_trace_neutralises_surrogates_from_non_utf8_names`,
`test_an_unreadable_tier_directory_at_the_root_is_traced`.

## Résultats locaux

Environnement : Linux, Python 3.14.6, venv du dépôt.

```text
.venv/bin/python -m pytest tests/test_scanner_detect.py \
  tests/test_scanner_interface.py tests/test_scanner_signatures.py \
  tests/test_trap_acceptance.py tests/security/test_scanner_bypass.py \
  --cov=heimdall.scanner --cov-branch --cov-report=term-missing \
  --cov-fail-under=85
483 passed
heimdall/scanner : 98,37 % (branches incluses), seuil 85 % atteint

.venv/bin/python -m pytest --cov=heimdall --cov-branch \
  --cov-report=term-missing --cov-fail-under=85
suite complète : 1493 passed, code retour 0
couverture Heimdall : 96,60 %

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

La relecture « REQUEST CHANGES » (2ᵉ passage) **signale à nouveau** cette
exception : le regroupement reste une exception, pas une règle. Elle est
tracée ici pour arbitrage des mainteneurs ; le correctif de ce 2ᵉ passage ne
modifie ni le découpage ni le périmètre des sous-tickets. Le correctif du 3ᵉ
passage ne modifie pas non plus le découpage : il porte sur le comportement
fail-closed du scanner (#59 et #60), pas sur un nouveau sous-ticket.

La relecture « APPROVE WITH COMMENTS » (4ᵉ passage) **la signale encore** :
c'est un point de vigilance d'usage, pas un blocage technique — le
correctif de ce 4ᵉ passage ne modifie ni le découpage ni le périmètre des
sous-tickets (il porte sur la garde du verdict propre et sur les bornes
Slack). L'exception reste **à valider explicitement par les mainteneurs**
avant fusion ; les PR suivantes suivront le découpage habituel (1 PR = 1
sous-ticket).

La relecture « APPROVE WITH COMMENTS » (5ᵉ passage) **maintient l'exception** :
le correctif porte sur l'observabilité de l'élagage VCS, le gitlink `.git`,
l'alignement documentaire et deux gardes de lecture ; il ne change ni le
découpage ni le périmètre des sous-tickets. L'exception reste **à valider
explicitement par les mainteneurs** avant fusion.

La relecture « APPROVE WITH COMMENTS » (6ᵉ passage) **maintient également
l'exception** : le correctif porte sur la neutralisation Slack, le helper
binaire déprécié, le confinement du re-pin et les tests manquants ; il ne
change ni le découpage ni le périmètre des sous-tickets. L'exception reste
**à valider explicitement par les mainteneurs** avant fusion.

La relecture « APPROVE WITH COMMENTS » (7ᵉ passage) **maintient l'exception** :
le correctif porte sur le verdict d'un arbre réduit à sa base VCS, la surface
publique du helper binaire déprécié, le code mort du re-pin et les tests
manquants ; il ne change ni le découpage ni le périmètre des sous-tickets.
L'exception reste **à valider explicitement par les mainteneurs** avant
fusion.

## Relecture et PR

- PR : à ouvrir sur la branche
  `22-t22-scanner-regex-de-signatures-et-exclusions` avec `Closes #22`.
- Relecture inter-domaines et check `CI (/ci)` restent requis avant fusion.
- La feuille SAMM externe n'est pas accessible depuis le dépôt ; reporter la
  ligne ci-dessus avec le lien de la PR et le SHA final du **squash** (le
  correctif du 5ᵉ passage est testé dans l'arbre de travail au-dessus de
  `44bfb191af4c804014eb108eac5c4f995973a1e6`). Le tableau principal reste
  épinglé sur la révision historique `b38dec179de6baf22fefd50056014e8ea26fc185`,
  signalée par ⚠️ ; les corrections du 2ᵉ passage sont prouvées plus haut,
  celles du 3ᵉ passage dans la section « 3ᵉ passage », celles du 4ᵉ passage
  dans la section « 4ᵉ passage », celles du 5ᵉ passage dans la section
  « 5ᵉ passage », celles du 6ᵉ passage dans la section « 6ᵉ passage » et
  celles du 7ᵉ passage dans la section « 7ᵉ passage ».
- **Permaliens des 5ᵉ, 6ᵉ et 7ᵉ passages** : pas de nouveau permalien sur un
  SHA intermédiaire ; preuves citées par nom de test, re-pinées au SHA du
  squash.
- **Après la fusion** : re-pince la fiche sur le SHA du squash (une
  commande, voir « Révisions à re-pinner après la fusion »), puis contrôle
  `python scripts/repin_samm.py --check` : aucun permalien mort ne doit
  subsister.

## Correctifs de la revue finale (run 40220479006)

| Remarque | Correctif | Preuve |
|---|---|---|
| LOW — `_recheck_root` ne vérifiait que le dernier segment | re-`lstat` de la racine **et de tous ses parents**, puis comparaison de l'identité `(st_dev, st_ino)` figée à la construction : un ancêtre symlinké ou un répertoire substitué est refusé avant `os.walk` | `heimdall/scanner/detect.py` (`__init__`, `_recheck_root`) ; `tests/test_scanner_detect.py::test_an_ancestor_of_the_root_replaced_by_a_symlink_is_fail_closed`, `::test_the_root_replaced_by_another_directory_is_fail_closed` |
| LOW — branche `classer_chemin` hors périmètre inatteignable et `Perimetre.STRICT` sans effet | enum et classifieurs supprimés : `est_base_vcs(name)` est le seul prédicat de périmètre, `est_chemin_hors_perimetre` ne regarde que les parents (gitlink `.git` lu) ; branche conservée en défense en profondeur et documentée | `heimdall/scanner/exclusions.py` ; `tests/test_scanner_detect.py::test_gitlink_file_is_scanned_vs_vcs_directory_matrix` |
| MEDIUM — `vcs_ignored` non propagé à la CLI | `ScanReport.vcs_ignored`, champ JSON `vcs_ignored`, résumé `--ci` et rapport humain ; le schéma le documente comme compteur d'élagage, jamais comme couverture de l'historique | `heimdall/cli/scan.py`, `heimdall/cli/main.py`, `schemas/scan.schema.json` ; `tests/test_cli_scan.py::test_scan_tree_reports_the_vcs_skip_in_json_and_ci` |
| MEDIUM — binaire `--staged` sauté avec un `0` possible | `_collect_staged` refuse tout blob binaire connu (`ScanError`, code 2), parité avec l'arbre ; un secret dans un PNG/ZIP ne peut plus produire un faux propre | `heimdall/cli/scan.py` (`_collect_staged`) ; `tests/test_cli_scan.py::test_scan_staged_refuses_a_binary_blob` |
