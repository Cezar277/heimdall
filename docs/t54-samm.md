# T54 — preuves pour la ligne SAMM

Périmètre : ticket #54 « Signatures de secrets » et ses quatre sous-tickets
#55 (AWS/cloud), #56 (Stripe/Slack), #57 (GitHub PAT/JWT) et #58 (PEM). Cette
fiche fournit les couples **module + ligne**, les tests et les permaliens du
code livré ; elle ne prétend pas modifier une feuille externe.

Révision de livraison initiale :
`49bafee86c8b3bceca594462773136bb7b147933` (`feat(scanner): registre de
signatures AWS, Stripe, Slack, GitHub, JWT et PEM (#54)`). Les permaliens
ci-dessous épinglent cette révision ; ils restent la trace de la livraison
initiale. Les correctifs de la relecture sont appliqués dans l'arbre courant :

- `repr(SignatureMatch)` masqué et `Rule.matches()` rendant des `RuleMatch`
  au `repr` masqué (invariant 8) ;
- jointure multi-ligne limitée aux numéros de ligne **contigus** ;
- fenêtre de jointure mesurée en **octets UTF-8** (4096), pas en caractères ;
- chemin de clé HMAC résolu et reconfronté au chemin demandé (aucun lien
  symbolique, même intermédiaire) ; répertoire partagé accessible en écriture
  au monde refusé sans chmod ;
- chemins d'erreur POSIX de `hashing.py` désormais testés ;
- **règle AWS alignée sur ses mots-clés** : les trois noms annoncés
  (`aws_secret_access_key`, `aws_secret_key`, `secret_access_key`) sont
  détectés, et le nom est reconnu dans les écritures JSON/TOML et
  `os.environ[...]` ; un nom hors périmètre reste muet ;
- **entrée non textuelle fail-closed** : `Rule.matches()` lève `ScanError`
  au lieu de rendre un « miss » silencieux ;
- **comportement d'écriture de la clé documenté pour la CI** :
  `HEIMDALL_SNIPPET_HMAC_KEY` exportée = aucun fichier écrit, empreintes
  stables ; sans elle, le comportement fail-closed est conservé.

La description fonctionnelle du registre et ses limites sont dans
[scanner-signatures.md](scanner-signatures.md).

## Traçabilité par sous-ticket

| Sous-ticket | Livraison | Implémentation | Exemples et tests |
| --- | --- | --- | --- |
| #55 AWS / cloud | 2 règles : identifiant d'accès et clé secrète AWS | [aws_cloud.py:23–47](https://github.com/Cezar277/heimdall/blob/49bafee86c8b3bceca594462773136bb7b147933/heimdall/scanner/signatures/aws_cloud.py#L23-L47) | [test_scanner_signatures.py:87–116](https://github.com/Cezar277/heimdall/blob/49bafee86c8b3bceca594462773136bb7b147933/tests/test_scanner_signatures.py#L87-L116) |
| #56 Stripe / Slack | 4 règles : Stripe, Slack historique, app-level, rotatif | [stripe_slack.py:19–67](https://github.com/Cezar277/heimdall/blob/49bafee86c8b3bceca594462773136bb7b147933/heimdall/scanner/signatures/stripe_slack.py#L19-L67) | [test_scanner_signatures.py:75–106](https://github.com/Cezar277/heimdall/blob/49bafee86c8b3bceca594462773136bb7b147933/tests/test_scanner_signatures.py#L75-L106) |
| #57 GitHub PAT / JWT | 3 règles : PAT classique, fine-grained, JWT | [github_jwt.py:23–59](https://github.com/Cezar277/heimdall/blob/49bafee86c8b3bceca594462773136bb7b147933/heimdall/scanner/signatures/github_jwt.py#L23-L59) | [test_scanner_signatures.py:75–106](https://github.com/Cezar277/heimdall/blob/49bafee86c8b3bceca594462773136bb7b147933/tests/test_scanner_signatures.py#L75-L106) |
| #58 PEM | 1 règle : en-tête de clé privée, certificat et clé publique exclus | [pem.py:17–29](https://github.com/Cezar277/heimdall/blob/49bafee86c8b3bceca594462773136bb7b147933/heimdall/scanner/signatures/pem.py#L17-L29) | [test_scanner_signatures.py:87–98](https://github.com/Cezar277/heimdall/blob/49bafee86c8b3bceca594462773136bb7b147933/tests/test_scanner_signatures.py#L87-L98) |

## Exigences vérifiées

| Exigence vérifiée | Implémentation (module + ligne) | Test et preuve permanente | Résultat local |
|---|---|---|---|
| **Une règle = id, description, regex, mots-clés optionnels, exemple positif et négatif** | [model.py:27–75](https://github.com/Cezar277/heimdall/blob/49bafee86c8b3bceca594462773136bb7b147933/heimdall/scanner/signatures/model.py#L27-L75), [model.py:131–147](https://github.com/Cezar277/heimdall/blob/49bafee86c8b3bceca594462773136bb7b147933/heimdall/scanner/signatures/model.py#L131-L147) | [test_scanner_signatures.py:75–84](https://github.com/Cezar277/heimdall/blob/49bafee86c8b3bceca594462773136bb7b147933/tests/test_scanner_signatures.py#L75-L84) | Les 10 règles déclarent les six champs ; `make_rule` garde les noms de paramètres non ambigus pour Bandit |
| **Un fichier de règles par famille** | [signatures/__init__.py:19–39](https://github.com/Cezar277/heimdall/blob/49bafee86c8b3bceca594462773136bb7b147933/heimdall/scanner/signatures/__init__.py#L19-L39) | [test_scanner_signatures.py:57–72](https://github.com/Cezar277/heimdall/blob/49bafee86c8b3bceca594462773136bb7b147933/tests/test_scanner_signatures.py#L57-L72) | 4 familles, 4 fichiers, 10 identifiants uniques ; un nom inconnu lève `KeyError` |
| **Test paramétré relisant tous les exemples** | [signatures/__init__.py:34–36](https://github.com/Cezar277/heimdall/blob/49bafee86c8b3bceca594462773136bb7b147933/heimdall/scanner/signatures/__init__.py#L34-L36) | [test_scanner_signatures.py:87–106](https://github.com/Cezar277/heimdall/blob/49bafee86c8b3bceca594462773136bb7b147933/tests/test_scanner_signatures.py#L87-L106) | 10 positifs reconnus, 10 négatifs ignorés, 10 positifs retrouvés par le matcher public |
| Validation fail-closed du registre (exemples, regex, métadonnées) | [model.py:49–75](https://github.com/Cezar277/heimdall/blob/49bafee86c8b3bceca594462773136bb7b147933/heimdall/scanner/signatures/model.py#L49-L75), [model.py:119–128](https://github.com/Cezar277/heimdall/blob/49bafee86c8b3bceca594462773136bb7b147933/heimdall/scanner/signatures/model.py#L119-L128) | [test_scanner_signatures.py:151–226](https://github.com/Cezar277/heimdall/blob/49bafee86c8b3bceca594462773136bb7b147933/tests/test_scanner_signatures.py#L151-L226) | Exemple positif faux, exemple négatif reconnu, regex invalide, groupe `value` absent, registre vide et id dupliqué refusés |
| **Ancrage par préfixe ou mot-clé, pas de regex trop large** | [model.py:92–106](https://github.com/Cezar277/heimdall/blob/49bafee86c8b3bceca594462773136bb7b147933/heimdall/scanner/signatures/model.py#L92-L106), [aws_cloud.py:23–35](https://github.com/Cezar277/heimdall/blob/49bafee86c8b3bceca594462773136bb7b147933/heimdall/scanner/signatures/aws_cloud.py#L23-L35), [stripe_slack.py:19–67](https://github.com/Cezar277/heimdall/blob/49bafee86c8b3bceca594462773136bb7b147933/heimdall/scanner/signatures/stripe_slack.py#L19-L67), [github_jwt.py:23–59](https://github.com/Cezar277/heimdall/blob/49bafee86c8b3bceca594462773136bb7b147933/heimdall/scanner/signatures/github_jwt.py#L23-L59) | [test_scanner_signatures.py:109–116](https://github.com/Cezar277/heimdall/blob/49bafee86c8b3bceca594462773136bb7b147933/tests/test_scanner_signatures.py#L109-L116), [test_scanner_signatures.py:129–148](https://github.com/Cezar277/heimdall/blob/49bafee86c8b3bceca594462773136bb7b147933/tests/test_scanner_signatures.py#L129-L148) | Le mot-clé AWS filtre le contexte ; UUID, hashes, base64, placeholders, préfixes tronqués et JWT incomplet restent muets |
| **Couverture AWS réelle : les mots-clés annoncés sont couverts par le motif** (arbre courant) | `heimdall/scanner/signatures/aws_cloud.py:41–67` | `tests/test_scanner_signatures.py:146–160` (`test_every_declared_aws_parameter_name_is_really_covered`), `tests/test_scanner_signatures.py:195–204` (`test_a_parameter_name_outside_the_announced_scope_stays_silent`) | Les 3 noms annoncés (`aws_secret_access_key`, `aws_secret_key`, `secret_access_key`) et leurs variantes de casse donnent 1 correspondance avec la valeur complète de 40 caractères ; 5 noms hors périmètre restent muets. Plus de « mot-clé sans effet » |
| **Le nom AWS est reconnu dans toutes les formes d'écriture** (arbre courant) | `heimdall/scanner/signatures/aws_cloud.py:47–62` | `tests/test_scanner_signatures.py:172–184` (`test_aws_secret_is_detected_in_every_common_assignment_form`) | 6 formes (`=`, `:`, JSON, JSON espacé, `os.environ[...]`) détectées ; le guillemet fermant et le crochet de subscription sont optionnels |
| **Entrée non textuelle : fail-closed, jamais un « miss » silencieux** (arbre courant) | `heimdall/scanner/signatures/model.py:29`, `heimdall/scanner/signatures/model.py:183–212` | `tests/test_scanner_signatures.py:280–298` | `Rule.matches()` et `find_signature_matches()` lèvent `ScanError` sur une ligne non `str` (message statique) ; l'interface #53 refusait déjà ce cas (`interface._check_lines`) |
| **CI : clé exportée = aucun fichier écrit, empreintes stables** (arbre courant) | `heimdall/scanner/hashing.py:186–212` | `tests/test_scanner_signatures.py:763–796` (`test_ci_scan_with_an_exported_key_writes_no_file`), `tests/test_scanner_signatures.py:801–823` (`test_scan_without_any_usable_key_fails_closed`) | Avec `HEIMDALL_SNIPPET_HMAC_KEY` et un `XDG_DATA_HOME` en lecture seule : scan réussi, **aucun** fichier créé, `snippet_hash` reproductible ; sans clé ni répertoire inscriptible : `ScanError` (fail-closed conservé) |
| **Anti-ReDoS : chaque règle sur 100 000 caractères** | [signature_engine.py:7–14](https://github.com/Cezar277/heimdall/blob/49bafee86c8b3bceca594462773136bb7b147933/heimdall/scanner/signature_engine.py#L7-L14), [github_jwt.py:48–59](https://github.com/Cezar277/heimdall/blob/49bafee86c8b3bceca594462773136bb7b147933/heimdall/scanner/signatures/github_jwt.py#L48-L59) | [test_scanner_signatures.py:232–249](https://github.com/Cezar277/heimdall/blob/49bafee86c8b3bceca594462773136bb7b147933/tests/test_scanner_signatures.py#L232-L249) | 30 exécutions (10 règles × 3 payloads) sous budget de 2 s ; pire mesure locale de l'ordre de **quelques millisecondes** (≈ 2,5 ms pour `aws_secret_access_key`, la plus lente après l'élargissement de son ancrage) |
| **Aucun vrai secret, même expiré** | [aws_cloud.py:19–21](https://github.com/Cezar277/heimdall/blob/49bafee86c8b3bceca594462773136bb7b147933/heimdall/scanner/signatures/aws_cloud.py#L19-L21), [stripe_slack.py:14–17](https://github.com/Cezar277/heimdall/blob/49bafee86c8b3bceca594462773136bb7b147933/heimdall/scanner/signatures/stripe_slack.py#L14-L17), [github_jwt.py:15–21](https://github.com/Cezar277/heimdall/blob/49bafee86c8b3bceca594462773136bb7b147933/heimdall/scanner/signatures/github_jwt.py#L15-L21) | [test_scanner_signatures.py:12](https://github.com/Cezar277/heimdall/blob/49bafee86c8b3bceca594462773136bb7b147933/tests/test_scanner_signatures.py#L12) | Valeurs synthétiques, littéraux concaténés, aucun appel fournisseur ; `bandit -r heimdall -q` silencieux |
| Moteur branché sur l'interface #53, Finding conforme au schéma #14 | [signature_engine.py:31–61](https://github.com/Cezar277/heimdall/blob/49bafee86c8b3bceca594462773136bb7b147933/heimdall/scanner/signature_engine.py#L31-L61) | [test_scanner_signatures.py:259–273](https://github.com/Cezar277/heimdall/blob/49bafee86c8b3bceca594462773136bb7b147933/tests/test_scanner_signatures.py#L259-L273) | Schéma draft 2020-12 validé ; `detecte`, `regex`, ligne 1, valeur absente du JSON et du `repr` |
| **Jamais de valeur brute ni de fuite par l'empreinte** | [signature_engine.py:77–102](https://github.com/Cezar277/heimdall/blob/49bafee86c8b3bceca594462773136bb7b147933/heimdall/scanner/signature_engine.py#L77-L102), [hashing.py:188–200](https://github.com/Cezar277/heimdall/blob/49bafee86c8b3bceca594462773136bb7b147933/heimdall/scanner/hashing.py#L188-L200) | [test_scanner_signatures.py:259–273](https://github.com/Cezar277/heimdall/blob/49bafee86c8b3bceca594462773136bb7b147933/tests/test_scanner_signatures.py#L259-L273), [test_scanner_signatures.py:341–348](https://github.com/Cezar277/heimdall/blob/49bafee86c8b3bceca594462773136bb7b147933/tests/test_scanner_signatures.py#L341-L348) | HMAC-SHA-256 stable, 64 hexadécimaux, distinct par valeur ; aucune valeur brute sérialisée |
| Déduplication : une valeur identique une fois, deux valeurs distinctes conservées | [signatures/__init__.py:82–107](https://github.com/Cezar277/heimdall/blob/49bafee86c8b3bceca594462773136bb7b147933/heimdall/scanner/signatures/__init__.py#L82-L107), [signature_engine.py:43–61](https://github.com/Cezar277/heimdall/blob/49bafee86c8b3bceca594462773136bb7b147933/heimdall/scanner/signature_engine.py#L43-L61) | [test_scanner_signatures.py:119–126](https://github.com/Cezar277/heimdall/blob/49bafee86c8b3bceca594462773136bb7b147933/tests/test_scanner_signatures.py#L119-L126), [test_scanner_signatures.py:289–302](https://github.com/Cezar277/heimdall/blob/49bafee86c8b3bceca594462773136bb7b147933/tests/test_scanner_signatures.py#L289-L302) | 1 Finding pour une valeur répétée, 2 Findings et 2 empreintes pour deux valeurs |
| **Secret coupé sur deux lignes contiguës, fenêtre bornée à 4096 octets UTF-8** | [signature_engine.py:27–28](https://github.com/Cezar277/heimdall/blob/49bafee86c8b3bceca594462773136bb7b147933/heimdall/scanner/signature_engine.py#L27-L28), [signature_engine.py:63–75](https://github.com/Cezar277/heimdall/blob/49bafee86c8b3bceca594462773136bb7b147933/heimdall/scanner/signature_engine.py#L63-L75) | [test_scanner_signatures.py:305–318](https://github.com/Cezar277/heimdall/blob/49bafee86c8b3bceca594462773136bb7b147933/tests/test_scanner_signatures.py#L305-L318) | Coupure sur deux lignes contiguës détectée et attribuée à la ligne 1 ; au-delà de 4096 octets UTF-8 ou pour des lignes non contiguës, aucune jointure |
| Numéros de ligne réels du diff conservés | [signature_engine.py:48–60](https://github.com/Cezar277/heimdall/blob/49bafee86c8b3bceca594462773136bb7b147933/heimdall/scanner/signature_engine.py#L48-L60) | [test_scanner_signatures.py:276–286](https://github.com/Cezar277/heimdall/blob/49bafee86c8b3bceca594462773136bb7b147933/tests/test_scanner_signatures.py#L276-L286) | Ligne 15 du diff conservée, pas la position dans la liste |
| Ordre déterministe et stable | [interface.py:214–279](https://github.com/Cezar277/heimdall/blob/49bafee86c8b3bceca594462773136bb7b147933/heimdall/scanner/interface.py#L214-L279), [signature_engine.py:43–61](https://github.com/Cezar277/heimdall/blob/49bafee86c8b3bceca594462773136bb7b147933/heimdall/scanner/signature_engine.py#L43-L61) | [test_scanner_signatures.py:321–328](https://github.com/Cezar277/heimdall/blob/49bafee86c8b3bceca594462773136bb7b147933/tests/test_scanner_signatures.py#L321-L328) | Deux scans rendent la même liste, triée par `(ligne, type, empreinte)` |
| **Clé HMAC locale, hors dépôt, permissions durcies** | [hashing.py:29–46](https://github.com/Cezar277/heimdall/blob/49bafee86c8b3bceca594462773136bb7b147933/heimdall/scanner/hashing.py#L29-L46), [hashing.py:63–96](https://github.com/Cezar277/heimdall/blob/49bafee86c8b3bceca594462773136bb7b147933/heimdall/scanner/hashing.py#L63-L96), [hashing.py:103–156](https://github.com/Cezar277/heimdall/blob/49bafee86c8b3bceca594462773136bb7b147933/heimdall/scanner/hashing.py#L103-L156) | [test_scanner_signatures.py:351–366](https://github.com/Cezar277/heimdall/blob/49bafee86c8b3bceca594462773136bb7b147933/tests/test_scanner_signatures.py#L351-L366) | Clé de 32 octets, `0600`, parent `0700`, refus des chemins relatifs et des clés courtes, `ScanError` sans repli éphémère |
| Entropie de Shannon bornée, métadonnée seulement | [entropy.py:15–32](https://github.com/Cezar277/heimdall/blob/49bafee86c8b3bceca594462773136bb7b147933/heimdall/scanner/entropy.py#L15-L32) | [test_scanner_signatures.py:334–338](https://github.com/Cezar277/heimdall/blob/49bafee86c8b3bceca594462773136bb7b147933/tests/test_scanner_signatures.py#L334-L338) | 0 pour une entrée vide ou constante, 1 pour deux symboles, ≤ 8 pour 256 octets |
| **Aucun faux positif sur le corpus T21** | [signatures/__init__.py:82–107](https://github.com/Cezar277/heimdall/blob/49bafee86c8b3bceca594462773136bb7b147933/heimdall/scanner/signatures/__init__.py#L82-L107) | [test_scanner_signatures.py:129–148](https://github.com/Cezar277/heimdall/blob/49bafee86c8b3bceca594462773136bb7b147933/tests/test_scanner_signatures.py#L129-L148) | 14 non-fuites (UUID, hashes, base64, placeholders, préfixes tronqués, certificat) → aucun candidat |

## Résultats locaux

Environnement : Linux, Python 3.11/3.14 selon le venv du dépôt, 21 octobre
2026.

```text
.venv/bin/python -m pytest tests/test_scanner_signatures.py
148 passed

.venv/bin/python -m pytest
1259 passed, 1 xfailed, 4251 subtests passed

.venv/bin/python -m pytest --cov=heimdall.scanner --cov-branch --cov-report=term-missing
heimdall/scanner/hashing.py           : 96 %
heimdall/scanner/signature_engine.py  : 100 %
heimdall/scanner/signatures/*.py      : 100 % (model.py inclus)
heimdall/scanner/entropy.py           : 100 %

.venv/bin/ruff check heimdall tests        # All checks passed
.venv/bin/ruff format --check …            # 15 files already formatted
.venv/bin/mypy heimdall                    # Success: no issues found (35 fichiers)
.venv/bin/bandit -r heimdall -q            # code retour 0, aucun rapport
```

Le `xfailed` restant est celui de T21 (`tests/test_trap_acceptance.py`) : il
attend le branchement du parcours réel #59. `heimdall/scanner/hashing.py` est
passé de 69 % à 96 % de couverture : propriétaire, permissions, lien
symbolique final et intermédiaire, chemin relatif ou avec `..`, clé hexadécimale
invalide ou de mauvaise longueur, course `FileExists` → second `_read_key`,
écriture partielle, `fchmod` indisponible et taille inattendue sont exercés.
Les branches restantes sont le chemin non-POSIX, un parent non répertoire
(court-circuité par `mkdir`) et l'échec de `unlink` après une création
incomplète.

Les 20 tests ajoutés par la relecture couvrent le périmètre AWS (6 cas de
nom : les 3 noms annoncés + 3 variantes de casse ; 6 formes d'écriture ;
5 noms hors périmètre), le refus fail-closed d'une ligne non textuelle
(2 tests) et le comportement de la clé en CI (2 tests : aucun fichier écrit
avec une clé exportée, `ScanError` sans clé ni répertoire inscriptible).

## Limites assumées

- La jointure multi-ligne est limitée à **deux lignes contiguës et 4096
  octets UTF-8** ; un secret sur trois lignes, sur des lignes non contiguës
  d'un diff ou au-delà de la fenêtre n'est pas détecté.
- Les fournisseurs cloud autres qu'AWS ne sont pas couverts ; l'ajout se fait
  dans un fichier de famille, sans toucher au moteur.
- PEM ne lit que l'en-tête : le corps de la clé n'est ni parsé ni conservé.
- Le moteur ne fait aucune I/O et ne parcourt pas le dépôt : le confinement,
  les exclusions et la lecture appartiennent à #59.
- Le test anti-ReDoS est une **borne d'exécution** (2 s sur 100 000
  caractères), pas une preuve formelle de linéarité. Toute nouvelle règle doit
  conserver des bornes explicites et passer ce test.
- La règle AWS n'accepte que **trois noms de paramètre** (`aws_secret_access_key`,
  `aws_secret_key`, `secret_access_key`). Un secret AWS stocké sous un autre
  nom (`aws_secret`, `session_token`…) n'est pas détecté : c'est un choix
  assumé, élargir l'ancrage à « tout nom contenant `secret` » produirait
  plus de faux positifs que de détections utiles.
- **La clé d'empreinte doit être exportée en CI** (`HEIMDALL_SNIPPET_HMAC_KEY`,
  64 caractères hexadécimaux). Sans elle, le premier scan écrit
  `$XDG_DATA_HOME/heimdall/snippet-hmac.key` : `ScanError` sur un runner en
  lecture seule, empreintes instables sur un runner inscriptible. Le
  comportement fail-closed est conservé (aucune clé éphémère). Voir
  [scanner-signatures.md](scanner-signatures.md#scan-en-ci--exporter-la-clé-nécrire-aucun-fichier).

## Relecture et PR

- PR à ouvrir sur `54-t222-signatures-de-secrets` avec `Closes #54` et
  `Refs #22`.
- Le commentaire de ticket doit reporter `Temps: 1h30` et le lien de la PR.
- La CI `CI (/ci)` et la relecture par un membre d'un autre domaine restent
  requises avant fusion.
- Reporter ce tableau dans la feuille SAMM de l'équipe avec le SHA
  `49bafee86c8b3bceca594462773136bb7b147933` et le lien de la PR.
