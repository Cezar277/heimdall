# T60 — preuves pour la ligne SAMM

Périmètre : ticket #60 « Tests unitaires et mesure sur le jeu piège », sous-ticket de l'épic #22 « Scanner : regex de signatures et exclusions ». Cette fiche fournit les couples **module + ligne**, les tests et les permaliens du code livré ; elle ne prétend pas modifier une feuille externe.

Cette PR est **strictement documentaire** : elle n'ajoute ni ne modifie aucun test. Les tests cités ci-dessous pré-existent sur `main` et ont été livrés par les PR #54 (registre de signatures) et #21 (corpus piège, mesure et acceptation) ; ils sont référencés ici comme preuve, pas comme livraison du ticket #60.

Révision du code testé : `981e404ae844cace1f470549501d81018c94e809` (tête de `main`, merge PR #190, incluant #59 — PR #202). Les couples module + ligne ci-dessous sont vérifiés à cette révision ; pour un lien permanent, utiliser `blob/981e404ae844cace1f470549501d81018c94e809/<chemin>#L<début>-L<fin>`.

## 1. Exigences vérifiées

| Exigence du ticket | Implémentation (module + ligne) | Test et preuve permanente | Résultat local |
|---|---|---|---|
| **Un test unitaire par règle**, via les exemples du registre | `heimdall/scanner/signatures/__init__.py:33–36` (agrégation des familles), `heimdall/scanner/signatures/model.py:130–178` (règle) | `tests/test_scanner_signatures.py:94–125` (règle paramétrée : contrat, exemple positif reconnu, exemple négatif ignoré, matcher public), `tests/test_scanner_signatures.py:403–452` (bornes anti-ReDoS) | **10 règles / 4 familles** ; 10 positifs reconnus, 10 négatifs ignorés, linéaires sur une ligne hostile de 100 000 caractères |
| **Mesure de précision et de rappel** sur le jeu piège, script du sous-ticket #21.4 | `tests/support/trap_corpus.py:81–121` (`measure`, `scan_corpus`), `tests/measure_trap.py:9–26` | `tests/test_trap_acceptance.py:43–67`, `tests/test_trap_acceptance.py:204–213` | `core` : VP=10, FP=8, FN=0, précision=0,5556, rappel=1,00 — seuil de 0,90 non atteint, `tests/measure_trap.py` retourne **1** |
| **Couverture du module > 85 %**, branches incluses | `heimdall/scanner/*` (détection, signatures, entropie, exclusions, interface, finding, hashing, gitignore, allowlist) | `tests/test_scanner_*.py`, `tests/security/test_scanner_bypass.py` | module `heimdall/scanner` : **91 %** (branches incluses), seuil 85 % atteint |

## 2. Résultats locaux

Environnement : Linux, Python 3.14.6, venv du dépôt.

```text
.venv/bin/python -m pytest --cov=heimdall --cov-branch \
  --cov-report=term-missing --cov-fail-under=85
→ suite complète : couverture globale **91,67 %**, seuil 85 % atteint

.venv/bin/python -m pytest \
  tests/test_scanner_allowlist.py tests/test_scanner_detect.py \
  tests/test_scanner_entropy.py tests/test_scanner_gitignore.py \
  tests/test_scanner_interface.py tests/test_scanner_signatures.py \
  tests/test_trap_acceptance.py tests/security/test_scanner_bypass.py \
  --cov=heimdall.scanner --cov-branch --cov-report=term-missing \
  --cov-fail-under=85
→ module `heimdall/scanner` : **91 %** (branches incluses), seuil 85 % atteint

.venv/bin/python tests/measure_trap.py
→ code **1** : le seuil de précision T21 (0,90) n'est pas atteint
```

## 3. Mesure sur le jeu piège (corpus T21)

Oracle versionné `tests/fixtures/trap_repo/expected.json` (34 cas : 10 leaks
« plain », 18 non-leaks, 6 obfuscations « limite_connue »), mesure
indépendante via `tests/support/trap_corpus.py::scan_corpus`.

| Périmètre | VP | FP | FN | Précision | Rappel |
| --- | --- | --- | --- | --- | --- |
| `core` (hors positions obfusquées) | 10 | 8 | 0 | **0,5556** | **1,00** |
| `all` (inclut les obfusquées) | 12 | 8 | 4 | **0,60** | **0,75** |

- **Rappel `core` = 1,00** : les 10 leaks « plain » (AWS, Stripe, JWT, PAT,
  PEM, en Python et en JavaScript) sont détectés, aucun faux négatif.
- **Précision `core` = 0,5556** : 8 fausses alertes sur les 18 non-leaks,
  portées par la détection par entropie sur les étiquettes `UUID`, `SHA-256`,
  `commit` et `integrity` (base64), dans chaque langage. L'oracle n'est ni
  modifié ni filtré ; le seuil T21 de 0,90 est conservé et `measure_trap.py`
  retourne **1**. L'allowlist explicite relève du sous-ticket #24.
- **Rappel `all` = 0,75** : les 4 positions obfusquées restantes
  (`known_limits_missed`) sont les cas de concaténation / reconstruction de
  variables — limite connue, figée par tests.

## 4. Limites assumées

- Le seuil de précision T21 (0,90) n'est pas atteint sur le corpus actuel ;
  les 8 faux positifs sont comptés honnêtement et ne passent pas dans le seuil
  principal via une heuristique de nom.
- Les secrets coupés sur plus de deux lignes ou au-delà de la fenêtre de 4 Kio
  restent des `limite_connue`.
- Le module `heimdall.scanner` est mesuré avec `--cov-branch` : les branches
  partielles sont comptées, le seuil 85 % est atteint (91 %).

## 5. Relecture et PR

- PR : branche `60-t224-tests-unitaires-et-mesure-sur-le-jeu-piège`, liée au
  ticket parent **#22** (sous-tickets #53, #54, #59, #60) avec `Closes #60`.
- Commentaire de ticket à la fin de la livraison : `Temps: 1h30`.
- CI `CI (/ci)` et relecture inter-domaine restent requises avant fusion ;
  les résultats locaux Linux ci-dessus n'y remplacent pas le check.

## 6. Preuves pour le rapport

- Couverture : `pytest --cov=heimdall --cov-branch --cov-report=term-missing
  --cov-fail-under=85` → **91,67 %** global, **91 %** sur `heimdall/scanner`.
- Mesure : `python tests/measure_trap.py` → **précision 0,5556 / rappel 1,00**
  (`core`), **précision 0,60 / rappel 0,75** (`all`).
- Tests : un test par règle sur les exemples du registre, tous verts.
