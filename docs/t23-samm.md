# T23 — preuves après revue REQUEST CHANGES

Ticket : [#23](https://github.com/Cezar277/heimdall/issues/23).
Révision corrigée : `da8c4b618ee150d39be17a318d8f204161d5bbb4`.
Cette fiche remplace les preuves de la première livraison `0ebc661` : ses
filtres digest/data URI/UUID et sa surface de contexte brut sont supprimés.
La feuille SAMM externe n'est pas modifiée ; relecture et merge restent à
effectuer par l'équipe. Aucun `/ci` distant n'est déclenché.

| Exigence | Code permanent | Preuve permanente |
| --- | --- | --- |
| Seuils validés, rejet bool/NaN/inf | [entropy_detection.py:26](https://github.com/Cezar277/heimdall/blob/da8c4b618ee150d39be17a318d8f204161d5bbb4/heimdall/scanner/entropy_detection.py#L26) | [tests/test_scanner_entropy.py](https://github.com/Cezar277/heimdall/blob/da8c4b618ee150d39be17a318d8f204161d5bbb4/tests/test_scanner_entropy.py) |
| Aucune exclusion implicite digest/data URI/UUID | [entropy_detection.py:61](https://github.com/Cezar277/heimdall/blob/da8c4b618ee150d39be17a318d8f204161d5bbb4/heimdall/scanner/entropy_detection.py#L61) | [abus sur les deux moteurs:135](https://github.com/Cezar277/heimdall/blob/da8c4b618ee150d39be17a318d8f204161d5bbb4/tests/test_scanner_entropy.py#L135) |
| Fenêtre multiligne : garde indépendante du fournisseur | [entropy_detection.py:106](https://github.com/Cezar277/heimdall/blob/da8c4b618ee150d39be17a318d8f204161d5bbb4/heimdall/scanner/entropy_detection.py#L106) | [Stripe/Slack/PAT/JWT/inconnu:153](https://github.com/Cezar277/heimdall/blob/da8c4b618ee150d39be17a318d8f204161d5bbb4/tests/test_scanner_entropy.py#L153) |
| Entrées directes invalides : ScanError statique | [entropy_detection.py:61](https://github.com/Cezar277/heimdall/blob/da8c4b618ee150d39be17a318d8f204161d5bbb4/heimdall/scanner/entropy_detection.py#L61) | [tests/test_scanner_entropy.py:168](https://github.com/Cezar277/heimdall/blob/da8c4b618ee150d39be17a318d8f204161d5bbb4/tests/test_scanner_entropy.py#L168) |
| Jeton > 4096 refusé avant Shannon/signatures, deadline intra-ligne | [entropy_detection.py:50](https://github.com/Cezar277/heimdall/blob/da8c4b618ee150d39be17a318d8f204161d5bbb4/heimdall/scanner/entropy_detection.py#L50) | [test 1 Mio:173](https://github.com/Cezar277/heimdall/blob/da8c4b618ee150d39be17a318d8f204161d5bbb4/tests/test_scanner_entropy.py#L173), [deadline:183](https://github.com/Cezar277/heimdall/blob/da8c4b618ee150d39be17a318d8f204161d5bbb4/tests/test_scanner_entropy.py#L183), [borne inclusive:202](https://github.com/Cezar277/heimdall/blob/da8c4b618ee150d39be17a318d8f204161d5bbb4/tests/test_scanner_entropy.py#L202) |
| Source explicite, collision avec Rule.id="entropy" sans effet | [signatures/__init__.py](https://github.com/Cezar277/heimdall/blob/da8c4b618ee150d39be17a318d8f204161d5bbb4/heimdall/scanner/signatures/__init__.py) | [règle réelle renommée:231](https://github.com/Cezar277/heimdall/blob/da8c4b618ee150d39be17a318d8f204161d5bbb4/tests/test_scanner_entropy.py#L231) |
| Types génériques gouvernés par l'ensemble fermé | [signatures/model.py](https://github.com/Cezar277/heimdall/blob/da8c4b618ee150d39be17a318d8f204161d5bbb4/heimdall/scanner/signatures/model.py) | [test du registre](https://github.com/Cezar277/heimdall/blob/da8c4b618ee150d39be17a318d8f204161d5bbb4/tests/test_scanner_signatures.py#L306) |
| Surface de contexte brut supprimée, Finding sérialisé sans clair | [entropy_detection.py](https://github.com/Cezar277/heimdall/blob/da8c4b618ee150d39be17a318d8f204161d5bbb4/heimdall/scanner/entropy_detection.py) | [absence API et json.dumps(asdict):244](https://github.com/Cezar277/heimdall/blob/da8c4b618ee150d39be17a318d8f204161d5bbb4/tests/test_scanner_entropy.py#L244) |

Le contexte ±5 lignes demandé initialement est différé, conformément à la
revue : aucun consommateur ne justifie cette nouvelle surface sensible.
Le comportement UTF-8 strict déjà livré reste couvert par les tests des
fichiers et de la CLI (faux PNG : erreur code 2, jamais propre).

## Mesure T21 : résultat non masqué

[Rapport JSON archivé](t23-trap-report.json), oracle inchangé, 34 cas dont
18 non-secrets. Huit faux positifs : UUID, SHA-256, commit et intégrité,
dans chacun des deux langages.

| Périmètre | VP | FP | FN | Précision | Rappel |
| --- | --- | --- | --- | --- | --- |
| core | 10 | 8 | 0 | 55,56 % | 100 % |
| all | 12 | 8 | 4 | 60 % | 75 % |

`PYTHONPATH=. python tests/measure_trap.py` retourne **1** : le seuil de
précision T21 de 90 % est conservé et n'est pas atteint. Le test de régression
vérifie les comptes exacts, sans altérer l'oracle ni retirer des faux positifs.
Une suite pytest verte n'atteste pas l'atteinte de ce seuil. La réduction des
faux positifs exige une allowlist explicite et auditée (#24), pas une étiquette
contrôlée par le commiteur.

## Validation locale

Debian/WSL, Python 3.13.5, environnement de test existant :

```sh
python -m ruff check heimdall tests scripts
python -m mypy heimdall tests/contracts/fastapi_contract_fixture.py scripts/regen_lock.py
python -m bandit -q -r heimdall
python -m pytest --cov=heimdall --cov-branch --cov-report=term --cov-fail-under=85 --tb=short
PYTHONPATH=. python tests/measure_trap.py  # attendu : code 1, précision < 90 %
```

Ruff, mypy strict et Bandit passent. Les 466 tests ciblés scanner, CLI et
corpus passent. Les skips de tests Ollama/manuels ne constituent pas des
preuves d'exécution du modèle local.

Suite complète sur la révision corrigée : **1937 passed, 16 skipped**,
4480 sous-tests passés, 7 avertissements ; couverture globale branches
incluses **91,98 %** (seuil 85 % satisfait), durée 204,10 s, code de sortie 0.
Le rapport de mesure T21 reste distinct et retourne 1, comme détaillé plus haut.

## Complément après APPROVE WITH COMMENTS

Révision du complément : `35c6672e6d6d1caebdda6917848b357cfae43dd5`.
Les preuves ci-dessus restent épinglées à la révision du premier correctif.

- Validation commune des lignes, de la configuration et des deadlines :
  [entropy_detection.py:52](https://github.com/Cezar277/heimdall/blob/35c6672e6d6d1caebdda6917848b357cfae43dd5/heimdall/scanner/entropy_detection.py#L52).
  Rejet des booléens, chaînes, NaN, infinis et entiers hors conversion
  flottante ; `ScanError` statique, même sur des lignes vides.
- `preceding_matches` doit être un tuple de `SignatureMatch` :
  [entrée:76](https://github.com/Cezar277/heimdall/blob/35c6672e6d6d1caebdda6917848b357cfae43dd5/heimdall/scanner/entropy_detection.py#L76),
  [tests paramétrés:254](https://github.com/Cezar277/heimdall/blob/35c6672e6d6d1caebdda6917848b357cfae43dd5/tests/test_scanner_entropy.py#L254),
  [deadlines des deux fonctions:272](https://github.com/Cezar277/heimdall/blob/35c6672e6d6d1caebdda6917848b357cfae43dd5/tests/test_scanner_entropy.py#L272).
- Disponibilité : la politique conservatrice reste assumée. Deux lignes
  JSON bénignes > 4 Kio avec `:`, sans candidat entropie, refusent le scan :
  [test des deux moteurs:305](https://github.com/Cezar277/heimdall/blob/35c6672e6d6d1caebdda6917848b357cfae43dd5/tests/test_scanner_entropy.py#L305).
  La CLI sort en 2, en mode arbre comme en mode indexé :
  [tests CLI:821](https://github.com/Cezar277/heimdall/blob/35c6672e6d6d1caebdda6917848b357cfae43dd5/tests/test_cli_scan.py#L821).
  Ce refus peut bloquer un bundle ou un fichier minifié sans secret ; il
  n'est pas présenté comme un verdict de fuite.

Validation du complément : Ruff, mypy strict et Bandit passent ;
**623 tests ciblés passent**, couverture scanner branches incluses **96,52 %**,
module `entropy_detection.py` **100 %**, durée 41,74 s, code de sortie 0.
La suite globale de 1937 tests ci-dessus concerne la révision précédente ;
elle n'a pas été relancée pour ce complément limité aux gardes et à la politique
déjà conservatrice. Les mesures T21 et leurs limites restent inchangées.

```sh
python -m pytest tests/test_scanner_entropy.py tests/test_scanner_detect.py \
  tests/test_scanner_signatures.py tests/test_scanner_interface.py \
  tests/test_trap_acceptance.py tests/test_cli_scan.py \
  tests/security/test_scanner_bypass.py --cov=heimdall.scanner --cov-branch \
  --cov-report=term --cov-fail-under=85 --tb=short
```

Aucun `/ci` distant déclenché ; feuille SAMM externe toujours non modifiée.

## Correctif CRITICAL — affixes de jetons hexadécimaux

Révision : `7f65bbf6731f9ebb529225879930bc45a73f69b6`.
La classification du jeton entier ne suffit pas : un préfixe non hex peut
imposer à tort le seuil base64 à une charge hex. La recherche des suites
hexadécimales maximales dans chaque jeton borné s'effectue désormais avant
la classification de repli. Le traitement spécial `sha512-` est supprimé.

| Exigence | Code permanent | Preuve permanente |
| --- | --- | --- |
| Fragments hex détectés malgré un affixe non hex | [_hex_matches:77](https://github.com/Cezar277/heimdall/blob/7f65bbf6731f9ebb529225879930bc45a73f69b6/heimdall/scanner/entropy_detection.py#L77) | [affixes paramétrés, deux moteurs:150](https://github.com/Cezar277/heimdall/blob/7f65bbf6731f9ebb529225879930bc45a73f69b6/tests/test_scanner_entropy.py#L150) |
| Position réelle, HMAC et score du fragment seul | [entropy_detection.py:77](https://github.com/Cezar277/heimdall/blob/7f65bbf6731f9ebb529225879930bc45a73f69b6/heimdall/scanner/entropy_detection.py#L77) | [positions/empreintes:163](https://github.com/Cezar277/heimdall/blob/7f65bbf6731f9ebb529225879930bc45a73f69b6/tests/test_scanner_entropy.py#L163), [deux fragments dans un jeton:184](https://github.com/Cezar277/heimdall/blob/7f65bbf6731f9ebb529225879930bc45a73f69b6/tests/test_scanner_entropy.py#L184) |
| Deadline avant le score d'un fragment | [entropy_detection.py:77](https://github.com/Cezar277/heimdall/blob/7f65bbf6731f9ebb529225879930bc45a73f69b6/heimdall/scanner/entropy_detection.py#L77) | [test:193](https://github.com/Cezar277/heimdall/blob/7f65bbf6731f9ebb529225879930bc45a73f69b6/tests/test_scanner_entropy.py#L193) |
| Une signature connue ne masque pas un autre fragment hex du même jeton | [entropy_detection.py](https://github.com/Cezar277/heimdall/blob/7f65bbf6731f9ebb529225879930bc45a73f69b6/heimdall/scanner/entropy_detection.py) | [test:200](https://github.com/Cezar277/heimdall/blob/7f65bbf6731f9ebb529225879930bc45a73f69b6/tests/test_scanner_entropy.py#L200) |
| CLI locale --ci : code 1, jamais 0, sans valeur brute en sortie | [détection](https://github.com/Cezar277/heimdall/blob/7f65bbf6731f9ebb529225879930bc45a73f69b6/heimdall/scanner/entropy_detection.py) | [tests arbre/index:848](https://github.com/Cezar277/heimdall/blob/7f65bbf6731f9ebb529225879930bc45a73f69b6/tests/test_cli_scan.py#L848) |

Les cas incluent `sha1-`, `sha256-`, `sha384-`, `sha512-`, `md5-`,
`prefix-`, `prefix.`, `x`, `a`, `x-`, `x_`, `x+`, `x/`, ainsi que
les suffixes `-suffix` et `x`. Les deux alphabets sont exercés et une
charge hex conserve le type `high_entropy_hex` malgré son affixe.
La borne 4096 est appliquée au jeton avant la recherche de fragments :
aucun fractionnement d'un jeton trop long ne permet de contourner le refus.

Ruff, mypy strict et Bandit passent. Les 674 tests ciblés passent et le
test supplémentaire de deadline du fragment passe. La mesure T21 a été
réexécutée : comptes et rapport JSON inchangés (core 10/8/0, all 12/8/4),
commande de mesure en code 1 attendu, précision toujours sous 90 %.
Les tests locaux de `--ci` ne déclenchent aucune exécution GitHub `/ci`.

Suite complète finale sur `7f65bbf` : **2013 passed, 16 skipped**,
4480 sous-tests passés, 7 avertissements ; couverture globale branches
incluses **92,04 %** (seuil 85 % satisfait), durée 199,25 s, code de sortie 0.
Cette validation remplace, pour le code actuel, les résultats globaux
historiques des sections précédentes. Le seuil de précision T21 reste
distinct, inchangé et non atteint, comme indiqué dans le rapport archivé.

## Complément LOW — fragmentation mono-ligne et parcours lexical unique

Révision : `b0877156871104b99e23778ddcf01ff28320121b`.

- **Limite connue assumée :** hex de 64 caractères découpé en blocs de 8
  par `-`, espace, `.` ou `_` ; les deux moteurs rendent `[]`, sans erreur.
  La reconstruction par suppression des séparateurs n'est pas effectuée :
  [test paramétré:386](https://github.com/Cezar277/heimdall/blob/b0877156871104b99e23778ddcf01ff28320121b/tests/test_scanner_entropy.py#L386),
  [limite documentée](https://github.com/Cezar277/heimdall/blob/b0877156871104b99e23778ddcf01ff28320121b/docs/scanner-entropy.md).
  Ces cas ne sont pas ajoutés à l'oracle T21 ni présentés comme détectés.
- **Un seul parcours lexical** collecte les seuls candidats assez longs,
  tout en refusant un jeton > 4096 avant signatures/Shannon :
  [find_entropy_matches:104](https://github.com/Cezar277/heimdall/blob/b0877156871104b99e23778ddcf01ff28320121b/heimdall/scanner/entropy_detection.py#L104).
  Le test compte exactement un parcours et 500 000 petits jetons, sans
  signatures ni Shannon dans le détecteur d'entropie :
  [test:400](https://github.com/Cezar277/heimdall/blob/b0877156871104b99e23778ddcf01ff28320121b/tests/test_scanner_entropy.py#L400).
- **Deadline expirée avant parcours :** ligne dense de 500 000 petits jetons,
  `deadline=0.0`, `ScanError` statique avant analyse lexicale ou signatures,
  sur l'import direct et les deux moteurs :
  [test:423](https://github.com/Cezar277/heimdall/blob/b0877156871104b99e23778ddcf01ff28320121b/tests/test_scanner_entropy.py#L423).
  Les regex de signatures existantes ne deviennent pas interruptibles ; les
  candidats retenus sont revérifiés contre la deadline après cette phase.

Validation locale du complément : Ruff, mypy strict et Bandit passent ;
**681 tests ciblés passent**, couverture scanner branches incluses **96,43 %**,
durée 41,97 s, code de sortie 0. La sélection est celle du complément LOW
précédent (scanner, interface, CLI, corpus et tests de bypass). La suite
globale de 2013 tests reste une preuve historique de la révision précédente ;
elle n'a pas été relancée pour ce complément. Les tests T21 conservent les
comptes documentés (core 10/8/0, all 12/8/4), sans changer le seuil de 90 %.
Aucun `/ci` GitHub déclenché ; feuille SAMM externe non modifiée.
