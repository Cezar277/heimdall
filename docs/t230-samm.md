# T230 — Audit E-02 : détection et allowlist

Ticket #230. Code testé : `d50d0f6660b79b01d7711c9b9b71f180da87b71e`.
Base : `336bc02`. Le commit contient `Closes #230`.

## Propriétés démontrées

| Périmètre | Code et témoins |
| --- | --- |
| Préfixes de services | [`service_tokens.py:9`](https://github.com/Cezar277/heimdall/blob/d50d0f6660b79b01d7711c9b9b71f180da87b71e/heimdall/scanner/signatures/service_tokens.py#L9) ajoute sept préfixes, bornes et exemples vérifiés à l'import. [Inventaire indépendant dans le test](https://github.com/Cezar277/heimdall/blob/d50d0f6660b79b01d7711c9b9b71f180da87b71e/tests/test_issue230_scanner_allowlist.py#L246). |
| URL, Authorization, affectations | [`credentials.py:64`](https://github.com/Cezar277/heimdall/blob/d50d0f6660b79b01d7711c9b9b71f180da87b71e/heimdall/scanner/signatures/credentials.py#L64), règles bornées ; [`LiteralRule`](https://github.com/Cezar277/heimdall/blob/d50d0f6660b79b01d7711c9b9b71f180da87b71e/heimdall/scanner/signatures/credentials.py#L51) distingue les valeurs citées des expressions non citées. [Candidats sans valeur brute dans les findings](https://github.com/Cezar277/heimdall/blob/d50d0f6660b79b01d7711c9b9b71f180da87b71e/tests/test_issue230_scanner_allowlist.py#L90), [quatre parcours CLI](https://github.com/Cezar277/heimdall/blob/d50d0f6660b79b01d7711c9b9b71f180da87b71e/tests/test_issue230_scanner_allowlist.py#L196), [littéraux versus expressions](https://github.com/Cezar277/heimdall/blob/d50d0f6660b79b01d7711c9b9b71f180da87b71e/tests/test_issue230_scanner_allowlist.py#L241). |
| Jetons courts | [`entropy_detection.py:35`](https://github.com/Cezar277/heimdall/blob/d50d0f6660b79b01d7711c9b9b71f180da87b71e/heimdall/scanner/entropy_detection.py#L35) et [:165](https://github.com/Cezar277/heimdall/blob/d50d0f6660b79b01d7711c9b9b71f180da87b71e/heimdall/scanner/entropy_detection.py#L165) : correction de seuil configurable pour 20–22 caractères, sous condition minuscules/majuscules/chiffres ; [réglages et refus des valeurs invalides](https://github.com/Cezar277/heimdall/blob/d50d0f6660b79b01d7711c9b9b71f180da87b71e/tests/test_issue230_scanner_allowlist.py#L98). |
| Regex quasi universelles | [`allowlist.py:405`](https://github.com/Cezar277/heimdall/blob/d50d0f6660b79b01d7711c9b9b71f180da87b71e/heimdall/scanner/allowlist.py#L405) calcule le minimum de littéraux obligatoires ; les assertions et atomes/groupes optionnels n'y contribuent pas. Les alternances sont analysées par groupe. [Contournements, y compris bornes zéro avec zéros initiaux](https://github.com/Cezar277/heimdall/blob/d50d0f6660b79b01d7711c9b9b71f180da87b71e/tests/test_issue230_scanner_allowlist.py#L134), [marqueurs spécifiques acceptés](https://github.com/Cezar277/heimdall/blob/d50d0f6660b79b01d7711c9b9b71f180da87b71e/tests/test_issue230_scanner_allowlist.py#L152), [refus CLI](https://github.com/Cezar277/heimdall/blob/d50d0f6660b79b01d7711c9b9b71f180da87b71e/tests/test_issue230_scanner_allowlist.py#L225). La longueur maximale et les gardes anti-ReDoS sont conservées. |
| Globs de chemin | [`allowlist.py:465`](https://github.com/Cezar277/heimdall/blob/d50d0f6660b79b01d7711c9b9b71f180da87b71e/heimdall/scanner/allowlist.py#L465) : seuls les segments `**` traversent les répertoires, casse explicite et refus des segments de traversée. [Tests directs](https://github.com/Cezar277/heimdall/blob/d50d0f6660b79b01d7711c9b9b71f180da87b71e/tests/test_issue230_scanner_allowlist.py#L174) et [configuration valide en CLI : top-level ignoré, nested signalé](https://github.com/Cezar277/heimdall/blob/d50d0f6660b79b01d7711c9b9b71f180da87b71e/tests/test_issue230_scanner_allowlist.py#L264). |
| Jointures et contrat d'erreur | [`detect.py:915`](https://github.com/Cezar277/heimdall/blob/d50d0f6660b79b01d7711c9b9b71f180da87b71e/heimdall/scanner/detect.py#L915) et [`signature_engine.py:150`](https://github.com/Cezar277/heimdall/blob/d50d0f6660b79b01d7711c9b9b71f180da87b71e/heimdall/scanner/signature_engine.py#L150) partagent le résultat de fenêtre avant l'entropie des fragments, sans fabriquer de clé sur une frontière. [Témoin de commentaire adjacent](https://github.com/Cezar277/heimdall/blob/d50d0f6660b79b01d7711c9b9b71f180da87b71e/tests/test_issue230_scanner_allowlist.py#L286). [Overflow de compilation](https://github.com/Cezar277/heimdall/blob/d50d0f6660b79b01d7711c9b9b71f180da87b71e/tests/test_issue230_scanner_allowlist.py#L258) et [Unicode invalide](https://github.com/Cezar277/heimdall/blob/d50d0f6660b79b01d7711c9b9b71f180da87b71e/tests/test_issue230_scanner_allowlist.py#L281) deviennent des `ScanError` statiques. |

## Mesures et limites

Le [corpus E-02](https://github.com/Cezar277/heimdall/blob/d50d0f6660b79b01d7711c9b9b71f180da87b71e/tests/test_issue230_scanner_allowlist.py#L76)
contient 75 positifs synthétiques et 15 négatifs : 74 vrais positifs,
1 faux négatif (jeton court) et 1 faux positif (UUID, entropie historique).
Rappel et précision : **98,67 % sur ce seul corpus**.

Le corpus historique T21 et son oracle restent inchangés. Les candidats
`changeme` et mocks à nom sensible augmentent ses faux positifs de 8 à 12 :
`core` TP=10, FP=12, FN=0, précision 45,45 %, rappel 100 % ; `all` TP=12,
FP=12, FN=4, précision 50 %, rappel 75 %. Le script de mesure historique
garde son seuil de 90 % et retourne 1. Aucune exclusion silencieuse n'est
ajoutée pour embellir ces résultats.

La propriété prouvée est l'élargissement des formats et le refus des
contournements d'allowlist couverts, pas « aucun secret manqué ». Les
heuristiques et bornes sont décrites dans
[t230-scanner-allowlist.md](t230-scanner-allowlist.md). Aucun nouveau réseau,
shell, chiffrement ou paquet externe ; les fixtures sont synthétiques.

## Validation

Les six modules ciblés passent : **776 tests en 13,81 s**. Sur le commit
figé, les commandes de contrôle de la CI passent localement : Ruff,
MyPy (66 fichiers) et Bandit (aucune alerte, avertissements `nosec`
existants). Le rejeu complet après le commit de code passe : **4056 tests,
7125 sous-tests, 18 ignorés**, en **361,50 s**. Les 14 avertissements
existants concernent les sauvegardes de remédiation. Aucun code ni test
n'a changé après ce rejeu ; seuls les documents de preuve ont été actualisés.
Rapport JUnit : `/home/nathan/heimdall-t230-final.xml`.

Environnement : Debian WSL, Python 3.13, dépendances locales existantes ;
aucune revendication d'exécution native Windows/macOS. La CI n'a pas été
déclenchée et aucune fusion n'a été effectuée.
Transcription : [acceptance/t230-validation.txt](acceptance/t230-validation.txt).

Après une fusion squash, re-pinner avec
`python scripts/repin_samm.py --sha <SHA> --fiche docs/t230-samm.md`, puis
vérifier avec `python scripts/repin_samm.py --check --fiche docs/t230-samm.md`.
