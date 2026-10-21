# T54 — preuves pour la ligne SAMM

Périmètre : ticket #54 « Signatures de secrets » et ses quatre sous-tickets
#55 (AWS/cloud), #56 (Stripe/Slack), #57 (GitHub PAT/JWT) et #58 (PEM). Cette
fiche fournit les couples **module + ligne**, les tests et les permaliens du
code livré ; elle ne prétend pas modifier une feuille externe.

Révision du code testé : `991f34d06b3fc339805dff78ae1efd9e4b499a0a`
(`fix(scanner): verrouille le type, la cle et la deduplication (#54)`), au-dessus
de la révision de relecture `25c6280d609748852113bc381b61e4a17bac2538`
(`docs(samm): preuves de relecture du registre de signatures (#54)`).

Les permaliens épinglent la révision du code, pas le commit de documentation qui
archive cette fiche. Le code #54 référencé est inchangé jusqu'à la livraison :
contrôle effectué avec
`git diff 991f34d06b3fc339805dff78ae1efd9e4b499a0a HEAD -- heimdall/scanner/ tests/test_scanner_signatures.py`
(sortie vide) ; les commits suivants ne modifient que la documentation.

La **livraison initiale** du registre est
`49bafee86c8b3bceca594462773136bb7b147933` (`feat(scanner): registre de
signatures AWS, Stripe, Slack, GitHub, JWT et PEM (#54)`) : elle reste
consultable dans l'historique git, mais elle est **supersédée** (motif AWS à un
seul nom, jointure non contiguë, `repr` fuyants). Les permaliens ci-dessous
pointent donc sur la révision auditée : un lien vers `49bafee` montrerait à
l'auditeur un code que le correctif a déjà remplacé.

La description fonctionnelle du registre et ses limites sont dans
[scanner-signatures.md](scanner-signatures.md).

## 1. Correctifs de la relecture (PR #54)

| Remarque du relecteur | Correctif | Preuve permanente |
|---|---|---|
| **LOW** — `validate_rules` annonce un contrôle de « type incohérent » qu'il n'implémente pas | l'ensemble fermé `ALLOWED_SECRET_TYPES` (`aws`/`stripe`/`slack`/`pat`/`jwt`/`pem`) est vérifié au chargement : un `secret_type` hors ensemble est refusé fail-closed à l'import du registre | [heimdall/scanner/signatures/model.py:29–38](https://github.com/Cezar277/heimdall/blob/991f34d06b3fc339805dff78ae1efd9e4b499a0a/heimdall/scanner/signatures/model.py#L29-L38), [heimdall/scanner/signatures/model.py:238–256](https://github.com/Cezar277/heimdall/blob/991f34d06b3fc339805dff78ae1efd9e4b499a0a/heimdall/scanner/signatures/model.py#L238-L256) + [tests/test_scanner_signatures.py:281–302](https://github.com/Cezar277/heimdall/blob/991f34d06b3fc339805dff78ae1efd9e4b499a0a/tests/test_scanner_signatures.py#L281-L302) |
| **LOW** — le `seen` du moteur retient les valeurs brutes pendant tout le scan, pas « le temps du hachage » | la déduplication porte sur `(ligne, type, empreinte HMAC)` et non sur la valeur : aucun secret en clair ne survit dans l'ensemble de déduplication ; la valeur est abandonnée après son hachage | [heimdall/scanner/signature_engine.py:46–66](https://github.com/Cezar277/heimdall/blob/991f34d06b3fc339805dff78ae1efd9e4b499a0a/heimdall/scanner/signature_engine.py#L46-L66), [heimdall/scanner/signature_engine.py:100–127](https://github.com/Cezar277/heimdall/blob/991f34d06b3fc339805dff78ae1efd9e4b499a0a/heimdall/scanner/signature_engine.py#L100-L127) + [tests/test_scanner_signatures.py:505–541](https://github.com/Cezar277/heimdall/blob/991f34d06b3fc339805dff78ae1efd9e4b499a0a/tests/test_scanner_signatures.py#L505-L541) |
| **LOW** — `bytes.fromhex` accepte espaces et retours à la ligne dans la clé d'environnement | le format est **strict** (64 caractères hexadécimaux contigus) et vérifié avant le décodage : une clé séparée est refusée fail-closed, avec le message statique existant | [heimdall/scanner/hashing.py:43–45](https://github.com/Cezar277/heimdall/blob/991f34d06b3fc339805dff78ae1efd9e4b499a0a/heimdall/scanner/hashing.py#L43-L45), [heimdall/scanner/hashing.py:191–208](https://github.com/Cezar277/heimdall/blob/991f34d06b3fc339805dff78ae1efd9e4b499a0a/heimdall/scanner/hashing.py#L191-L208) + [tests/test_scanner_signatures.py:684–713](https://github.com/Cezar277/heimdall/blob/991f34d06b3fc339805dff78ae1efd9e4b499a0a/tests/test_scanner_signatures.py#L684-L713) |
| **LOW** — permaliens SAMM épinglés sur une révision supersédée pour les lignes modifiées depuis | tous les permaliens de cette fiche épinglent la révision auditée `991f34d` (le code testé), et non plus `49bafee` ; la livraison initiale reste nommée dans l'en-tête et dans l'historique git | cette fiche (en-tête « Révision du code testé ») + `git diff 991f34d HEAD -- heimdall/scanner/ tests/test_scanner_signatures.py` (sortie vide) |
| Test manquant — type de Finding hors ensemble fermé | `validate_rules` refuse un `secret_type` non documenté | [tests/test_scanner_signatures.py:281–297](https://github.com/Cezar277/heimdall/blob/991f34d06b3fc339805dff78ae1efd9e4b499a0a/tests/test_scanner_signatures.py#L281-L297) |
| Test manquant — clé d'environnement contenant des espaces | refus fail-closed, message statique | [tests/test_scanner_signatures.py:684–705](https://github.com/Cezar277/heimdall/blob/991f34d06b3fc339805dff78ae1efd9e4b499a0a/tests/test_scanner_signatures.py#L684-L705) |

## 2. Traçabilité par sous-ticket

| Sous-ticket | Livraison | Implémentation | Exemples et tests |
| --- | --- | --- | --- |
| #55 AWS / cloud | 2 règles : identifiant d'accès et clé secrète AWS | [aws_cloud.py:28–68](https://github.com/Cezar277/heimdall/blob/991f34d06b3fc339805dff78ae1efd9e4b499a0a/heimdall/scanner/signatures/aws_cloud.py#L28-L68) | [test_scanner_signatures.py:88–119](https://github.com/Cezar277/heimdall/blob/991f34d06b3fc339805dff78ae1efd9e4b499a0a/tests/test_scanner_signatures.py#L88-L119) |
| #56 Stripe / Slack | 4 règles : Stripe, Slack historique, app-level, rotatif | [stripe_slack.py:19–68](https://github.com/Cezar277/heimdall/blob/991f34d06b3fc339805dff78ae1efd9e4b499a0a/heimdall/scanner/signatures/stripe_slack.py#L19-L68) | [test_scanner_signatures.py:88–119](https://github.com/Cezar277/heimdall/blob/991f34d06b3fc339805dff78ae1efd9e4b499a0a/tests/test_scanner_signatures.py#L88-L119) |
| #57 GitHub PAT / JWT | 3 règles : PAT classique, fine-grained, JWT | [github_jwt.py:23–60](https://github.com/Cezar277/heimdall/blob/991f34d06b3fc339805dff78ae1efd9e4b499a0a/heimdall/scanner/signatures/github_jwt.py#L23-L60) | [test_scanner_signatures.py:88–119](https://github.com/Cezar277/heimdall/blob/991f34d06b3fc339805dff78ae1efd9e4b499a0a/tests/test_scanner_signatures.py#L88-L119) |
| #58 PEM | 1 règle : en-tête de clé privée, certificat et clé publique exclus | [pem.py:17–30](https://github.com/Cezar277/heimdall/blob/991f34d06b3fc339805dff78ae1efd9e4b499a0a/heimdall/scanner/signatures/pem.py#L17-L30) | [test_scanner_signatures.py:88–119](https://github.com/Cezar277/heimdall/blob/991f34d06b3fc339805dff78ae1efd9e4b499a0a/tests/test_scanner_signatures.py#L88-L119) |

## 3. Exigences vérifiées

| Exigence vérifiée | Implémentation (module + ligne) | Test et preuve permanente | Résultat local |
|---|---|---|---|
| **Une règle = id, description, regex, mots-clés optionnels, exemple positif et négatif** | [model.py:130–151](https://github.com/Cezar277/heimdall/blob/991f34d06b3fc339805dff78ae1efd9e4b499a0a/heimdall/scanner/signatures/model.py#L130-L151), [model.py:153–178](https://github.com/Cezar277/heimdall/blob/991f34d06b3fc339805dff78ae1efd9e4b499a0a/heimdall/scanner/signatures/model.py#L153-L178) | [test_scanner_signatures.py:88–119](https://github.com/Cezar277/heimdall/blob/991f34d06b3fc339805dff78ae1efd9e4b499a0a/tests/test_scanner_signatures.py#L88-L119) | Les 10 règles déclarent les six champs ; `make_rule` garde les noms de paramètres non ambigus pour Bandit |
| **Un fichier de règles par famille** | [signatures/__init__.py:25–36](https://github.com/Cezar277/heimdall/blob/991f34d06b3fc339805dff78ae1efd9e4b499a0a/heimdall/scanner/signatures/__init__.py#L25-L36) | [test_scanner_signatures.py:70–85](https://github.com/Cezar277/heimdall/blob/991f34d06b3fc339805dff78ae1efd9e4b499a0a/tests/test_scanner_signatures.py#L70-L85) | 4 familles, 4 fichiers, 10 identifiants uniques ; un nom inconnu lève `KeyError` |
| **Test paramétré relisant tous les exemples** | [signatures/__init__.py:33–36](https://github.com/Cezar277/heimdall/blob/991f34d06b3fc339805dff78ae1efd9e4b499a0a/heimdall/scanner/signatures/__init__.py#L33-L36) | [test_scanner_signatures.py:88–119](https://github.com/Cezar277/heimdall/blob/991f34d06b3fc339805dff78ae1efd9e4b499a0a/tests/test_scanner_signatures.py#L88-L119) | 10 positifs reconnus, 10 négatifs ignorés, 10 positifs retrouvés par le matcher public |
| Validation fail-closed du registre (exemples, regex, métadonnées, type de Finding) | [model.py:153–178](https://github.com/Cezar277/heimdall/blob/991f34d06b3fc339805dff78ae1efd9e4b499a0a/heimdall/scanner/signatures/model.py#L153-L178), [model.py:238–256](https://github.com/Cezar277/heimdall/blob/991f34d06b3fc339805dff78ae1efd9e4b499a0a/heimdall/scanner/signatures/model.py#L238-L256) | [test_scanner_signatures.py:238–302](https://github.com/Cezar277/heimdall/blob/991f34d06b3fc339805dff78ae1efd9e4b499a0a/tests/test_scanner_signatures.py#L238-L302) | Exemple positif faux, exemple négatif reconnu, regex invalide, groupe `value` absent, registre vide, id dupliqué et **type hors ensemble fermé** refusés |
| **Type de Finding dans un ensemble fermé** (`aws`/`stripe`/`slack`/`pat`/`jwt`/`pem`) | [model.py:29–38](https://github.com/Cezar277/heimdall/blob/991f34d06b3fc339805dff78ae1efd9e4b499a0a/heimdall/scanner/signatures/model.py#L29-L38), [model.py:238–256](https://github.com/Cezar277/heimdall/blob/991f34d06b3fc339805dff78ae1efd9e4b499a0a/heimdall/scanner/signatures/model.py#L238-L256) | [test_scanner_signatures.py:281–302](https://github.com/Cezar277/heimdall/blob/991f34d06b3fc339805dff78ae1efd9e4b499a0a/tests/test_scanner_signatures.py#L281-L302) | Un `secret_type` hors ensemble est refusé à l'import ; le registre livré utilise exactement les 6 types documentés |
| **Ancrage par préfixe ou mot-clé, pas de regex trop large** | [model.py:196–225](https://github.com/Cezar277/heimdall/blob/991f34d06b3fc339805dff78ae1efd9e4b499a0a/heimdall/scanner/signatures/model.py#L196-L225), [aws_cloud.py:28–40](https://github.com/Cezar277/heimdall/blob/991f34d06b3fc339805dff78ae1efd9e4b499a0a/heimdall/scanner/signatures/aws_cloud.py#L28-L40), [stripe_slack.py:19–68](https://github.com/Cezar277/heimdall/blob/991f34d06b3fc339805dff78ae1efd9e4b499a0a/heimdall/scanner/signatures/stripe_slack.py#L19-L68), [github_jwt.py:23–60](https://github.com/Cezar277/heimdall/blob/991f34d06b3fc339805dff78ae1efd9e4b499a0a/heimdall/scanner/signatures/github_jwt.py#L23-L60) | [test_scanner_signatures.py:146–203](https://github.com/Cezar277/heimdall/blob/991f34d06b3fc339805dff78ae1efd9e4b499a0a/tests/test_scanner_signatures.py#L146-L203), [test_scanner_signatures.py:216–235](https://github.com/Cezar277/heimdall/blob/991f34d06b3fc339805dff78ae1efd9e4b499a0a/tests/test_scanner_signatures.py#L216-L235) | Le mot-clé AWS filtre le contexte ; UUID, hashes, base64, placeholders, préfixes tronqués et JWT incomplet restent muets |
| **Couverture AWS réelle : les mots-clés annoncés sont couverts par le motif** | [aws_cloud.py:41–67](https://github.com/Cezar277/heimdall/blob/991f34d06b3fc339805dff78ae1efd9e4b499a0a/heimdall/scanner/signatures/aws_cloud.py#L41-L67) | [test_scanner_signatures.py:146–159](https://github.com/Cezar277/heimdall/blob/991f34d06b3fc339805dff78ae1efd9e4b499a0a/tests/test_scanner_signatures.py#L146-L159) (`test_every_declared_aws_parameter_name_is_really_covered`), [test_scanner_signatures.py:186–203](https://github.com/Cezar277/heimdall/blob/991f34d06b3fc339805dff78ae1efd9e4b499a0a/tests/test_scanner_signatures.py#L186-L203) (`test_a_parameter_name_outside_the_announced_scope_stays_silent`) | Les 3 noms annoncés (`aws_secret_access_key`, `aws_secret_key`, `secret_access_key`) et leurs variantes de casse donnent 1 correspondance avec la valeur complète de 40 caractères ; 5 noms hors périmètre restent muets. Plus de « mot-clé sans effet » |
| **Le nom AWS est reconnu dans toutes les formes d'écriture** | [aws_cloud.py:47–62](https://github.com/Cezar277/heimdall/blob/991f34d06b3fc339805dff78ae1efd9e4b499a0a/heimdall/scanner/signatures/aws_cloud.py#L47-L62) | [test_scanner_signatures.py:162–183](https://github.com/Cezar277/heimdall/blob/991f34d06b3fc339805dff78ae1efd9e4b499a0a/tests/test_scanner_signatures.py#L162-L183) (`test_aws_secret_is_detected_in_every_common_assignment_form`) | 6 formes (`=`, `:`, JSON, JSON espacé, `os.environ[...]`) détectées ; le guillemet fermant et le crochet de subscription sont optionnels |
| **Entrée non textuelle : fail-closed, jamais un « miss » silencieux** | [model.py:39–41](https://github.com/Cezar277/heimdall/blob/991f34d06b3fc339805dff78ae1efd9e4b499a0a/heimdall/scanner/signatures/model.py#L39-L41), [model.py:196–225](https://github.com/Cezar277/heimdall/blob/991f34d06b3fc339805dff78ae1efd9e4b499a0a/heimdall/scanner/signatures/model.py#L196-L225) | [test_scanner_signatures.py:305–321](https://github.com/Cezar277/heimdall/blob/991f34d06b3fc339805dff78ae1efd9e4b499a0a/tests/test_scanner_signatures.py#L305-L321) | `Rule.matches()` et `find_signature_matches()` lèvent `ScanError` sur une ligne non `str` (message statique) ; l'interface #53 refusait déjà ce cas (`interface._check_lines`) |
| **CI : clé exportée = aucun fichier écrit, empreintes stables** | [hashing.py:191–224](https://github.com/Cezar277/heimdall/blob/991f34d06b3fc339805dff78ae1efd9e4b499a0a/heimdall/scanner/hashing.py#L191-L224) | [test_scanner_signatures.py:859–890](https://github.com/Cezar277/heimdall/blob/991f34d06b3fc339805dff78ae1efd9e4b499a0a/tests/test_scanner_signatures.py#L859-L890) (`test_ci_scan_with_an_exported_key_writes_no_file`), [test_scanner_signatures.py:893–917](https://github.com/Cezar277/heimdall/blob/991f34d06b3fc339805dff78ae1efd9e4b499a0a/tests/test_scanner_signatures.py#L893-L917) (`test_scan_without_any_usable_key_fails_closed`) | Avec `HEIMDALL_SNIPPET_HMAC_KEY` et un `XDG_DATA_HOME` en lecture seule : scan réussi, **aucun** fichier créé, `snippet_hash` reproductible ; sans clé ni répertoire inscriptible : `ScanError` (fail-closed conservé) |
| **Clé d'environnement : format strict, pas de séparateur accepté** | [hashing.py:43–45](https://github.com/Cezar277/heimdall/blob/991f34d06b3fc339805dff78ae1efd9e4b499a0a/heimdall/scanner/hashing.py#L43-L45), [hashing.py:191–208](https://github.com/Cezar277/heimdall/blob/991f34d06b3fc339805dff78ae1efd9e4b499a0a/heimdall/scanner/hashing.py#L191-L208) | [test_scanner_signatures.py:675–713](https://github.com/Cezar277/heimdall/blob/991f34d06b3fc339805dff78ae1efd9e4b499a0a/tests/test_scanner_signatures.py#L675-L713) | 64 caractères hexadécimaux contigus acceptés (majuscules inclus) ; espaces et sauts de ligne refusés avec le message statique `clé d'empreinte locale invalide` |
| **Anti-ReDoS : chaque règle sur 100 000 caractères** | [signature_engine.py:7–18](https://github.com/Cezar277/heimdall/blob/991f34d06b3fc339805dff78ae1efd9e4b499a0a/heimdall/scanner/signature_engine.py#L7-L18), [github_jwt.py:48–59](https://github.com/Cezar277/heimdall/blob/991f34d06b3fc339805dff78ae1efd9e4b499a0a/heimdall/scanner/signatures/github_jwt.py#L48-L59) | [test_scanner_signatures.py:356–406](https://github.com/Cezar277/heimdall/blob/991f34d06b3fc339805dff78ae1efd9e4b499a0a/tests/test_scanner_signatures.py#L356-L406) | 30 exécutions (10 règles × 3 payloads) sous budget de 2 s ; pire mesure locale de l'ordre de **quelques millisecondes** (≈ 4 ms pour `aws_secret_access_key`, la plus lente après l'élargissement de son ancrage ; ≈ 1,7 ms pour les neuf autres) |
| **Aucun vrai secret, même expiré** | [aws_cloud.py:24–26](https://github.com/Cezar277/heimdall/blob/991f34d06b3fc339805dff78ae1efd9e4b499a0a/heimdall/scanner/signatures/aws_cloud.py#L24-L26), [stripe_slack.py:14–17](https://github.com/Cezar277/heimdall/blob/991f34d06b3fc339805dff78ae1efd9e4b499a0a/heimdall/scanner/signatures/stripe_slack.py#L14-L17), [github_jwt.py:15–21](https://github.com/Cezar277/heimdall/blob/991f34d06b3fc339805dff78ae1efd9e4b499a0a/heimdall/scanner/signatures/github_jwt.py#L15-L21) | [test_scanner_signatures.py:12](https://github.com/Cezar277/heimdall/blob/991f34d06b3fc339805dff78ae1efd9e4b499a0a/tests/test_scanner_signatures.py#L12) | Valeurs synthétiques, littéraux concaténés, aucun appel fournisseur ; `bandit -r heimdall -q` silencieux |
| Moteur branché sur l'interface #53, Finding conforme au schéma #14 | [signature_engine.py:34–66](https://github.com/Cezar277/heimdall/blob/991f34d06b3fc339805dff78ae1efd9e4b499a0a/heimdall/scanner/signature_engine.py#L34-L66) | [test_scanner_signatures.py:416–430](https://github.com/Cezar277/heimdall/blob/991f34d06b3fc339805dff78ae1efd9e4b499a0a/tests/test_scanner_signatures.py#L416-L430) | Schéma draft 2020-12 validé ; `detecte`, `regex`, ligne 1, valeur absente du JSON et du `repr` |
| **Jamais de valeur brute ni de fuite par l'empreinte** | [signature_engine.py:100–127](https://github.com/Cezar277/heimdall/blob/991f34d06b3fc339805dff78ae1efd9e4b499a0a/heimdall/scanner/signature_engine.py#L100-L127), [hashing.py:227–239](https://github.com/Cezar277/heimdall/blob/991f34d06b3fc339805dff78ae1efd9e4b499a0a/heimdall/scanner/hashing.py#L227-L239) | [test_scanner_signatures.py:416–450](https://github.com/Cezar277/heimdall/blob/991f34d06b3fc339805dff78ae1efd9e4b499a0a/tests/test_scanner_signatures.py#L416-L450), [test_scanner_signatures.py:621–628](https://github.com/Cezar277/heimdall/blob/991f34d06b3fc339805dff78ae1efd9e4b499a0a/tests/test_scanner_signatures.py#L621-L628) | HMAC-SHA-256 stable, 64 hexadécimaux, distinct par valeur ; aucune valeur brute sérialisée |
| **La valeur brute n'est conservée que le temps du hachage** | [signature_engine.py:46–66](https://github.com/Cezar277/heimdall/blob/991f34d06b3fc339805dff78ae1efd9e4b499a0a/heimdall/scanner/signature_engine.py#L46-L66), [signature_engine.py:100–127](https://github.com/Cezar277/heimdall/blob/991f34d06b3fc339805dff78ae1efd9e4b499a0a/heimdall/scanner/signature_engine.py#L100-L127) | [test_scanner_signatures.py:505–541](https://github.com/Cezar277/heimdall/blob/991f34d06b3fc339805dff78ae1efd9e4b499a0a/tests/test_scanner_signatures.py#L505-L541) | La déduplication porte sur l'empreinte, pas sur la valeur : un hacheur constant fusionne deux valeurs distinctes, preuve que la clé de déduplication ne contient aucun secret en clair |
| Déduplication : une valeur identique une fois, deux valeurs distinctes conservées | [signatures/__init__.py:91–122](https://github.com/Cezar277/heimdall/blob/991f34d06b3fc339805dff78ae1efd9e4b499a0a/heimdall/scanner/signatures/__init__.py#L91-L122), [signature_engine.py:46–66](https://github.com/Cezar277/heimdall/blob/991f34d06b3fc339805dff78ae1efd9e4b499a0a/heimdall/scanner/signature_engine.py#L46-L66) | [test_scanner_signatures.py:206–213](https://github.com/Cezar277/heimdall/blob/991f34d06b3fc339805dff78ae1efd9e4b499a0a/tests/test_scanner_signatures.py#L206-L213), [test_scanner_signatures.py:489–502](https://github.com/Cezar277/heimdall/blob/991f34d06b3fc339805dff78ae1efd9e4b499a0a/tests/test_scanner_signatures.py#L489-L502) | 1 Finding pour une valeur répétée, 2 Findings et 2 empreintes pour deux valeurs |
| **Secret coupé sur deux lignes contiguës, fenêtre bornée à 4096 octets UTF-8** | [signature_engine.py:30–31](https://github.com/Cezar277/heimdall/blob/991f34d06b3fc339805dff78ae1efd9e4b499a0a/heimdall/scanner/signature_engine.py#L30-L31), [signature_engine.py:68–98](https://github.com/Cezar277/heimdall/blob/991f34d06b3fc339805dff78ae1efd9e4b499a0a/heimdall/scanner/signature_engine.py#L68-L98) | [test_scanner_signatures.py:544–598](https://github.com/Cezar277/heimdall/blob/991f34d06b3fc339805dff78ae1efd9e4b499a0a/tests/test_scanner_signatures.py#L544-L598) | Coupure sur deux lignes contiguës détectée et attribuée à la ligne 1 ; au-delà de 4096 octets UTF-8 ou pour des lignes non contiguës, aucune jointure |
| Numéros de ligne réels du diff conservés | [signature_engine.py:46–66](https://github.com/Cezar277/heimdall/blob/991f34d06b3fc339805dff78ae1efd9e4b499a0a/heimdall/scanner/signature_engine.py#L46-L66) | [test_scanner_signatures.py:476–486](https://github.com/Cezar277/heimdall/blob/991f34d06b3fc339805dff78ae1efd9e4b499a0a/tests/test_scanner_signatures.py#L476-L486) | Ligne 15 du diff conservée, pas la position dans la liste |
| Ordre déterministe et stable | [interface.py:212–219](https://github.com/Cezar277/heimdall/blob/991f34d06b3fc339805dff78ae1efd9e4b499a0a/heimdall/scanner/interface.py#L212-L219), [signature_engine.py:46–66](https://github.com/Cezar277/heimdall/blob/991f34d06b3fc339805dff78ae1efd9e4b499a0a/heimdall/scanner/signature_engine.py#L46-L66) | [test_scanner_signatures.py:601–608](https://github.com/Cezar277/heimdall/blob/991f34d06b3fc339805dff78ae1efd9e4b499a0a/tests/test_scanner_signatures.py#L601-L608) | Deux scans rendent la même liste, triée par `(ligne, type, empreinte)` |
| **Clé HMAC locale, hors dépôt, permissions durcies** | [hashing.py:39–45](https://github.com/Cezar277/heimdall/blob/991f34d06b3fc339805dff78ae1efd9e4b499a0a/heimdall/scanner/hashing.py#L39-L45), [hashing.py:76–85](https://github.com/Cezar277/heimdall/blob/991f34d06b3fc339805dff78ae1efd9e4b499a0a/heimdall/scanner/hashing.py#L76-L85), [hashing.py:88–128](https://github.com/Cezar277/heimdall/blob/991f34d06b3fc339805dff78ae1efd9e4b499a0a/heimdall/scanner/hashing.py#L88-L128) | [test_scanner_signatures.py:638–646](https://github.com/Cezar277/heimdall/blob/991f34d06b3fc339805dff78ae1efd9e4b499a0a/tests/test_scanner_signatures.py#L638-L646), [test_scanner_signatures.py:716–782](https://github.com/Cezar277/heimdall/blob/991f34d06b3fc339805dff78ae1efd9e4b499a0a/tests/test_scanner_signatures.py#L716-L782) | Clé de 32 octets, `0600`, parent `0700`, refus des chemins relatifs et des clés courtes, `ScanError` sans repli éphémère |
| Entropie de Shannon bornée, métadonnée seulement | [entropy.py:15–32](https://github.com/Cezar277/heimdall/blob/991f34d06b3fc339805dff78ae1efd9e4b499a0a/heimdall/scanner/entropy.py#L15-L32) | [test_scanner_signatures.py:614–618](https://github.com/Cezar277/heimdall/blob/991f34d06b3fc339805dff78ae1efd9e4b499a0a/tests/test_scanner_signatures.py#L614-L618) | 0 pour une entrée vide ou constante, 1 pour deux symboles, ≤ 8 pour 256 octets |
| **Aucun faux positif sur le corpus T21** | [signatures/__init__.py:91–122](https://github.com/Cezar277/heimdall/blob/991f34d06b3fc339805dff78ae1efd9e4b499a0a/heimdall/scanner/signatures/__init__.py#L91-L122) | [test_scanner_signatures.py:216–235](https://github.com/Cezar277/heimdall/blob/991f34d06b3fc339805dff78ae1efd9e4b499a0a/tests/test_scanner_signatures.py#L216-L235) | 14 non-fuites (UUID, hashes, base64, placeholders, préfixes tronqués, certificat) → aucun candidat |

## 4. Résultats locaux

Environnement : Linux, Python 3.14.6 selon le venv du dépôt, 21 octobre
2026.

```text
.venv/bin/python -m pytest tests/test_scanner_signatures.py
158 passed

.venv/bin/python -m pytest
1269 passed, 1 xfailed, 4251 subtests passed

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

Les 30 tests ajoutés par les deux lectures couvrent le périmètre AWS (6 cas de
nom : les 3 noms annoncés + 3 variantes de casse ; 6 formes d'écriture ;
5 noms hors périmètre), le refus fail-closed d'une ligne non textuelle
(2 tests), le comportement de la clé en CI (2 tests : aucun fichier écrit
avec une clé exportée, `ScanError` sans clé ni répertoire inscriptible) et
les correctifs de la seconde lecture (10 tests : type de Finding hors
ensemble fermé, déduplication sur l'empreinte et absence de valeur brute
résiduelle, clé d'environnement avec séparateurs).

## 5. Limites assumées

- La jointure multi-ligne est limitée à **deux lignes contiguës et 4096
  octets UTF-8** ; un secret sur trois lignes, sur des lignes non contiguës
  d'un diff ou au-delà de la fenêtre n'est pas détecté.
- Les fournisseurs cloud autres qu'AWS ne sont pas couverts ; l'ajout se fait
  dans un fichier de famille, sans toucher au moteur. Un nouveau type de
  Finding impose de l'ajouter à `ALLOWED_SECRET_TYPES`.
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
- La déduplication du moteur porte sur l'empreinte HMAC-SHA-256 : deux
  valeurs distinctes ne sont fusionnées que sur collision HMAC-SHA-256,
  inatteignable en pratique.
- **La clé d'empreinte doit être exportée en CI** (`HEIMDALL_SNIPPET_HMAC_KEY`,
  64 caractères hexadécimaux **sans séparateur**). Sans elle, le premier scan
  écrit `$XDG_DATA_HOME/heimdall/snippet-hmac.key` : `ScanError` sur un runner
  en lecture seule, empreintes instables sur un runner inscriptible. Le
  comportement fail-closed est conservé (aucune clé éphémère). Voir
  [scanner-signatures.md](scanner-signatures.md#scan-en-ci--exporter-la-clé-nécrire-aucun-fichier).

## 6. Relecture et PR

- PR à ouvrir sur `54-t222-signatures-de-secrets` avec `Closes #54` et
  `Refs #22`.
- Le commentaire de ticket doit reporter `Temps: 1h30` et le lien de la PR.
- La CI `CI (/ci)` et la relecture par un membre d'un autre domaine restent
  requises avant fusion.
- Reporter ce tableau dans la feuille SAMM de l'équipe avec le SHA
  `991f34d06b3fc339805dff78ae1efd9e4b499a0a` (révision du code testé) et le
  lien de la PR. La livraison initiale `49bafee86c8b3bceca594462773136bb7b147933`
  reste la trace du premier dépôt du registre.
