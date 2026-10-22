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

Les permaliens du tableau principal épinglent `b38dec1…` ; ceux de documentation
épinglent `f4dc3c8…` (ADR-002) et `81a67df…` (ADR-001). **Ces permaliens
décrivent la livraison précédente** : la relecture « REQUEST CHANGES » (2ᵉ
passage) a modifié le périmètre, la fenêtre multi-ligne et les règles Slack.
Les corrections correspondantes sont prouvées dans la section « 2ᵉ passage »,
dont les permaliens sont épinglés sur `5de5140153f593248b5f1823f271f2d7528a3205` (commit `fix(scanner): le contenu
decide, plus jamais le nom du fichier (#22)`). Les lignes du tableau principal
qui portent sur un module modifié (périmètre, fenêtre multi-ligne) sont
signalées ci-dessous.

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
| **MEDIUM** — secret coupé par une ligne vide intercalée (`>\n\n`) : jamais détecté, sans `ScanError`, et la doc ne bornait que « 4 Kio / 2 lignes » | la fenêtre multi-ligne joint **jusqu'à trois lignes contiguës** (bornée à 4 Kio) : la ligne vide intercalée est couverte. La limite restante (plus de deux `\n` consécutifs) est **documentée et figée par un test** | [heimdall/scanner/signature_engine.py:31–35](https://github.com/Cezar277/heimdall/blob/5de5140153f593248b5f1823f271f2d7528a3205/heimdall/scanner/signature_engine.py#L31-L35), [heimdall/scanner/signature_engine.py:72–118](https://github.com/Cezar277/heimdall/blob/5de5140153f593248b5f1823f271f2d7528a3205/heimdall/scanner/signature_engine.py#L72-L118), [tests/test_scanner_detect.py:336–364](https://github.com/Cezar277/heimdall/blob/5de5140153f593248b5f1823f271f2d7528a3205/tests/test_scanner_detect.py#L336-L364) |
| **LOW** — lookbehind Slack élargi au `.` : `foo.xapp-…` et `foo.xoxe.…` devenaient des faux négatifs | retour au lookbehind d'origine `(?<![A-Za-z0-9-])` ; le point n'est pas une frontière de mot. La garde `(?<!xoxe\.)` (précise, préfixe rotatif seul) évite le double signalement d'un même secret — **un** secret, **une** empreinte, **une** entrée Vault | [heimdall/scanner/signatures/stripe_slack.py:33–86](https://github.com/Cezar277/heimdall/blob/5de5140153f593248b5f1823f271f2d7528a3205/heimdall/scanner/signatures/stripe_slack.py#L33-L86), [tests/test_scanner_detect.py:286–319](https://github.com/Cezar277/heimdall/blob/5de5140153f593248b5f1823f271f2d7528a3205/tests/test_scanner_detect.py#L286-L319) |
| **LOW** — hygiène de PR : quatre sous-tickets dans une PR | exception déjà tracée dans cette fiche (section « Exception de regroupement ») et dans la description de PR ; **à valider explicitement par les mainteneurs** avant fusion. Les PR suivantes suivront le découpage habituel | `docs/t22-samm.md#exception-de-regroupement` |
| Hors remarque — CLI : le message de refus annonçait encore « scanner non implémenté (voir #22) » alors que #22 est livré | message aligné sur l'état réel : « commande non branchée (voir #29) — refus par défaut », code 2 inchangé | [heimdall/cli/main.py:39–49](https://github.com/Cezar277/heimdall/blob/5de5140153f593248b5f1823f271f2d7528a3205/heimdall/cli/main.py#L39-L49), [tests/test_package.py:55–74](https://github.com/Cezar277/heimdall/blob/5de5140153f593248b5f1823f271f2d7528a3205/tests/test_package.py#L55-L74) |

### Ce que le correctif permet désormais de prouver

| Exigence vérifiée | Implémentation | Test et preuve permanente |
|---|---|---|
| **Aucun nom de fichier n'exclut un fichier du scan** (le secret dans `evil.png`, `package-lock.json` ou `vendor/` est détecté) | [heimdall/scanner/exclusions.py:46–124](https://github.com/Cezar277/heimdall/blob/5de5140153f593248b5f1823f271f2d7528a3205/heimdall/scanner/exclusions.py#L46-L124), [heimdall/scanner/detect.py:312–411](https://github.com/Cezar277/heimdall/blob/5de5140153f593248b5f1823f271f2d7528a3205/heimdall/scanner/detect.py#L312-L411) | [tests/test_scanner_detect.py:385–452](https://github.com/Cezar277/heimdall/blob/5de5140153f593248b5f1823f271f2d7528a3205/tests/test_scanner_detect.py#L385-L452), [tests/security/test_scanner_bypass.py:82–105](https://github.com/Cezar277/heimdall/blob/5de5140153f593248b5f1823f271f2d7528a3205/tests/security/test_scanner_bypass.py#L82-L105) |
| **Un contenu non analysé est tracé, jamais silencieusement ignoré** | [heimdall/scanner/detect.py:139–165](https://github.com/Cezar277/heimdall/blob/5de5140153f593248b5f1823f271f2d7528a3205/heimdall/scanner/detect.py#L139-L165), [heimdall/scanner/detect.py:487–489](https://github.com/Cezar277/heimdall/blob/5de5140153f593248b5f1823f271f2d7528a3205/heimdall/scanner/detect.py#L487-L489) | [tests/test_scanner_detect.py:454–499](https://github.com/Cezar277/heimdall/blob/5de5140153f593248b5f1823f271f2d7528a3205/tests/test_scanner_detect.py#L454-L499), [tests/security/test_scanner_bypass.py:107–120](https://github.com/Cezar277/heimdall/blob/5de5140153f593248b5f1823f271f2d7528a3205/tests/security/test_scanner_bypass.py#L107-L120) |
| **Un verdict « propre » est fondé** : le rapport expose ce qui n'a pas été lu (`RapportScan.complet`) | [heimdall/scanner/detect.py:139–165](https://github.com/Cezar277/heimdall/blob/5de5140153f593248b5f1823f271f2d7528a3205/heimdall/scanner/detect.py#L139-L165), [heimdall/scanner/detect.py:502–513](https://github.com/Cezar277/heimdall/blob/5de5140153f593248b5f1823f271f2d7528a3205/heimdall/scanner/detect.py#L502-L513) | [tests/test_scanner_detect.py:477–500](https://github.com/Cezar277/heimdall/blob/5de5140153f593248b5f1823f271f2d7528a3205/tests/test_scanner_detect.py#L477-L500) |
| **Un secret coupé par une ligne vide est détecté**, la limite au-delà est figée | [heimdall/scanner/signature_engine.py:72–118](https://github.com/Cezar277/heimdall/blob/5de5140153f593248b5f1823f271f2d7528a3205/heimdall/scanner/signature_engine.py#L72-L118) | [tests/test_scanner_detect.py:336–364](https://github.com/Cezar277/heimdall/blob/5de5140153f593248b5f1823f271f2d7528a3205/tests/test_scanner_detect.py#L336-L364) |
| **Un jeton Slack après un point est détecté**, un jeton rotatif n'est signalé qu'une fois | [heimdall/scanner/signatures/stripe_slack.py:33–86](https://github.com/Cezar277/heimdall/blob/5de5140153f593248b5f1823f271f2d7528a3205/heimdall/scanner/signatures/stripe_slack.py#L33-L86) | [tests/test_scanner_detect.py:286–319](https://github.com/Cezar277/heimdall/blob/5de5140153f593248b5f1823f271f2d7528a3205/tests/test_scanner_detect.py#L286-L319) |

### Durcissements de l'amont conservés au rebase

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

## Résultats locaux

Environnement : Linux, Python 3.14.6, venv du dépôt.

```text
.venv/bin/python -m pytest tests/test_scanner_detect.py \
  tests/test_scanner_interface.py tests/test_scanner_signatures.py \
  tests/test_trap_acceptance.py tests/security/test_scanner_bypass.py \
  --cov=heimdall.scanner --cov-branch --cov-report=term-missing \
  --cov-fail-under=85
445 passed
heimdall/scanner : 98,36 % (branches incluses), seuil 85 % atteint

.venv/bin/python -m pytest --cov=heimdall --cov-branch \
  --cov-report=term-missing --cov-fail-under=85
suite complète : 1455 passed (+ 4317 subtests), code retour 0
couverture Heimdall : 96,59 %

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
modifie ni le découpage ni le périmètre des sous-tickets.

## Relecture et PR

- PR : à ouvrir sur la branche
  `22-t22-scanner-regex-de-signatures-et-exclusions` avec `Closes #22`.
- Relecture inter-domaines et check `CI (/ci)` restent requis avant fusion.
- La feuille SAMM externe n'est pas accessible depuis le dépôt ; reporter la
  ligne ci-dessus avec le lien de la PR et le SHA du **code testé**
  `5de5140153f593248b5f1823f271f2d7528a3205` (le tableau principal reste
  épinglé sur la révision historique `b38dec179de6baf22fefd50056014e8ea26fc185`,
  signalée par ⚠️ ; les corrections du 2ᵉ passage sont prouvées plus haut).
- **Permaliens du 2ᵉ passage** : épinglés sur `5de5140153f593248b5f1823f271f2d7528a3205` (code testé) ; la
  présente révision de documentation est celle qui les contient.
