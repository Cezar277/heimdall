# T53 — preuves pour la ligne SAMM

Périmètre : ticket #53 (sous-ticket #53 de l'épic #22, « Interface Scanner et
sortie Finding »). Cette fiche fournit les couples **module + ligne** et les
permaliens du code testé ; elle ne prétend pas modifier une feuille externe.

Révision du code testé : `11ecffa79f6b2e10de10a5b68756ea9b359282f7`
(commit `feat(scanner): interface scanner et sortie Finding (#53)`).

Les permaliens épinglent la révision du **code**, pas le commit de
documentation qui archive cette fiche. Aucun fichier de production ni de test
ne change après `11ecffa…` : contrôle effectué avec

```sh
git diff 11ecffa79f6b2e10de10a5b68756ea9b359282f7 HEAD -- heimdall tests
```

(sortie vide au moment de l'archivage de cette fiche).

| Exigence vérifiée | Implémentation (module + ligne) | Test et preuve permanente | Résultat local |
|---|---|---|---|
| **Sortie Finding conforme au schéma #14** : sérialisation validée par `jsonschema` | [heimdall/scanner/finding.py:152–217](https://github.com/Cezar277/heimdall/blob/11ecffa79f6b2e10de10a5b68756ea9b359282f7/heimdall/scanner/finding.py#L152-L217) | [tests/test_scanner_interface.py:77–86](https://github.com/Cezar277/heimdall/blob/11ecffa79f6b2e10de10a5b68756ea9b359282f7/tests/test_scanner_interface.py#L77-L86) | Schéma draft 2020-12 validé sur la sortie sérialisée |
| Un Finding non conforme **n'existe pas** (validation à la construction) | [heimdall/scanner/finding.py:100–148](https://github.com/Cezar277/heimdall/blob/11ecffa79f6b2e10de10a5b68756ea9b359282f7/heimdall/scanner/finding.py#L100-L148), [heimdall/scanner/finding.py:168–176](https://github.com/Cezar277/heimdall/blob/11ecffa79f6b2e10de10a5b68756ea9b359282f7/heimdall/scanner/finding.py#L168-L176) | [tests/test_scanner_interface.py:199–214](https://github.com/Cezar277/heimdall/blob/11ecffa79f6b2e10de10a5b68756ea9b359282f7/tests/test_scanner_interface.py#L199-L214) | 12 cas valides acceptés, 38 cas invalides refusés : **accord code / schéma** |
| Aucun champ surnuméraire, aucun champ manquant (anti-dérive du contrat) | [heimdall/scanner/finding.py:30–38](https://github.com/Cezar277/heimdall/blob/11ecffa79f6b2e10de10a5b68756ea9b359282f7/heimdall/scanner/finding.py#L30-L38), [heimdall/scanner/finding.py:196–217](https://github.com/Cezar277/heimdall/blob/11ecffa79f6b2e10de10a5b68756ea9b359282f7/heimdall/scanner/finding.py#L196-L217) | [tests/test_scanner_interface.py:89–94](https://github.com/Cezar277/heimdall/blob/11ecffa79f6b2e10de10a5b68756ea9b359282f7/tests/test_scanner_interface.py#L89-L94) | Champs du dataclass = propriétés = `required` du schéma |
| **Jamais de valeur de secret** dans un Finding (piège du ticket) | [heimdall/scanner/finding.py:178–193](https://github.com/Cezar277/heimdall/blob/11ecffa79f6b2e10de10a5b68756ea9b359282f7/heimdall/scanner/finding.py#L178-L193) | [tests/test_scanner_interface.py:257–267](https://github.com/Cezar277/heimdall/blob/11ecffa79f6b2e10de10a5b68756ea9b359282f7/tests/test_scanner_interface.py#L257-L267) | Sérialisation sans canari ; ni `value`, ni `secret`, ni `snippet` |
| Messages d'erreur statiques (invariant 8 : aucun reflet d'entrée) | [heimdall/scanner/errors.py:14–23](https://github.com/Cezar277/heimdall/blob/11ecffa79f6b2e10de10a5b68756ea9b359282f7/heimdall/scanner/errors.py#L14-L23) | [tests/test_scanner_interface.py:270–283](https://github.com/Cezar277/heimdall/blob/11ecffa79f6b2e10de10a5b68756ea9b359282f7/tests/test_scanner_interface.py#L270-L283) | Canari absent des messages `InvalidFinding` et `InvalidTarget` |
| Cible = lignes ajoutées du diff indexé, numéros de ligne réels | [heimdall/scanner/interface.py:42–68](https://github.com/Cezar277/heimdall/blob/11ecffa79f6b2e10de10a5b68756ea9b359282f7/heimdall/scanner/interface.py#L42-L68) | [tests/test_scanner_interface.py:311–324](https://github.com/Cezar277/heimdall/blob/11ecffa79f6b2e10de10a5b68756ea9b359282f7/tests/test_scanner_interface.py#L311-L324) | Numéros conservés ; lignes désordonnées, nulles ou dupliquées refusées |
| Cible = fichier entier (démarrage à froid) | [heimdall/scanner/interface.py:72–85](https://github.com/Cezar277/heimdall/blob/11ecffa79f6b2e10de10a5b68756ea9b359282f7/heimdall/scanner/interface.py#L72-L85) | [tests/test_scanner_interface.py:327–329](https://github.com/Cezar277/heimdall/blob/11ecffa79f6b2e10de10a5b68756ea9b359282f7/tests/test_scanner_interface.py#L327-L329) | Lignes numérotées à partir de 1 |
| Chemins hors dépôt refusés **avant** toute lecture (traversée) | [heimdall/scanner/finding.py:68–97](https://github.com/Cezar277/heimdall/blob/11ecffa79f6b2e10de10a5b68756ea9b359282f7/heimdall/scanner/finding.py#L68-L97), [heimdall/scanner/interface.py:33–38](https://github.com/Cezar277/heimdall/blob/11ecffa79f6b2e10de10a5b68756ea9b359282f7/heimdall/scanner/interface.py#L33-L38) | [tests/test_scanner_interface.py:333–337](https://github.com/Cezar277/heimdall/blob/11ecffa79f6b2e10de10a5b68756ea9b359282f7/tests/test_scanner_interface.py#L333-L337) | `../`, absolu, `C:/` → `InvalidTarget` |
| `scan(cible) -> list[Finding]` : délégation, tri stable, ordre reproductible | [heimdall/scanner/interface.py:121–157](https://github.com/Cezar277/heimdall/blob/11ecffa79f6b2e10de10a5b68756ea9b359282f7/heimdall/scanner/interface.py#L121-L157) | [tests/test_scanner_interface.py:367–399](https://github.com/Cezar277/heimdall/blob/11ecffa79f6b2e10de10a5b68756ea9b359282f7/tests/test_scanner_interface.py#L367-L399) | Tri `(ligne, type, empreinte)` puis `(fichier, …)` |
| Fail-closed : sortie non conforme refusée, jamais de liste partielle | [heimdall/scanner/interface.py:104–118](https://github.com/Cezar277/heimdall/blob/11ecffa79f6b2e10de10a5b68756ea9b359282f7/heimdall/scanner/interface.py#L104-L118) | [tests/test_scanner_interface.py:411–414](https://github.com/Cezar277/heimdall/blob/11ecffa79f6b2e10de10a5b68756ea9b359282f7/tests/test_scanner_interface.py#L411-L414) | Objet non-Finding, autre fichier, état `confirme`, origine `llm` → `ScanError` |
| Le LLM n'a aucun droit de transition sur le Finding | [heimdall/scanner/interface.py:104–118](https://github.com/Cezar277/heimdall/blob/11ecffa79f6b2e10de10a5b68756ea9b359282f7/heimdall/scanner/interface.py#L104-L118), [docs/contracts/finding.md:50–64](https://github.com/Cezar277/heimdall/blob/11ecffa79f6b2e10de10a5b68756ea9b359282f7/docs/contracts/finding.md#L50-L64) | [tests/test_scanner_interface.py:411–414](https://github.com/Cezar277/heimdall/blob/11ecffa79f6b2e10de10a5b68756ea9b359282f7/tests/test_scanner_interface.py#L411-L414) | Le scanner ne rend que `detecte` + origine déterministe |
| Le code est **au moins aussi strict** que le schéma (anti-dérive) | [heimdall/scanner/finding.py:100–148](https://github.com/Cezar277/heimdall/blob/11ecffa79f6b2e10de10a5b68756ea9b359282f7/heimdall/scanner/finding.py#L100-L148) | [tests/test_scanner_interface.py:231–251](https://github.com/Cezar277/heimdall/blob/11ecffa79f6b2e10de10a5b68756ea9b359282f7/tests/test_scanner_interface.py#L231-L251) | 2 écarts assumés, où le code refuse ce que le schéma tolère (`line: 1.0`, `entropy: NaN`) |

## Résultats locaux

Environnement : Linux, Python 3.14.6, venv du dépôt.

```text
.venv/bin/python -m pytest tests/test_scanner_interface.py
77 passed

.venv/bin/python -m pytest --cov=heimdall --cov-branch --cov-report=term-missing
suite complète : 923 passed, 1 xfailed (+ 3848 subtests), code retour 0
couverture Heimdall : 98 %
heimdall/scanner/finding.py : 100 % (branches incluses)
heimdall/scanner/interface.py : 100 % (branches incluses)
heimdall/scanner/errors.py : 100 % (branches incluses)

.venv/bin/ruff check heimdall tests        # All checks passed
.venv/bin/mypy heimdall tests/contracts/fastapi_contract_fixture.py
                                            # Success: no issues found
.venv/bin/bandit -r heimdall -q             # code retour 0, aucun rapport
```

Le `xfailed` restant est celui de T21 (`tests/test_trap_acceptance.py`) : il
attend la livraison du scanner #22 et devient un `XPASS(strict)` dès que le
moteur réel (#54/#59) est branché sur cette interface.

## Chevauchement avec l'épic #22

La branche de l'épic (#22) livre déjà un scanner complet — signatures,
exclusions, empreintes — et y redéclare sa propre classe `Finding` et son
propre `Scanner(root)`. Ce ticket est le sous-ticket **nommé** par le
découpage : il fixe l'interface et la sortie, sans détection.

Deux définitions concurrentes de la sortie ne peuvent pas rester en place
(audit de code, revue). Deux options pour le relecteur :

1. **fusionner cette PR d'abord**, puis adapter l'épic : `Finding` vient de
   `heimdall.scanner.finding`, le moteur de l'épic est appelé par la façade
   `Scanner` de `heimdall.scanner.interface` (cible = diff indexé ou fichier) ;
2. **garder l'épic** et refermer #53 comme couvert, en reportant dans la
   fiche SAMM de l'épic les preuves de cette PR pour la sortie et l'interface.

Dans les deux cas, il faut **une seule** classe `Finding` dans le paquet :
c'est vérifié par
[tests/test_scanner_interface.py:434–438](https://github.com/Cezar277/heimdall/blob/11ecffa79f6b2e10de10a5b68756ea9b359282f7/tests/test_scanner_interface.py#L434-L438).

## Relecture et PR

- PR : à ouvrir sur la branche `53-t221-interface-scanner-et-sortie-finding`
  avec `Closes #53` (et `Refs #22`).
- Relecture par un membre d'un autre domaine et check `CI (/ci)` restent
  requis avant fusion.
- Reporter la ligne ci-dessus dans la feuille SAMM de l'équipe avec le lien de
  la PR et le SHA `11ecffa79f6b2e10de10a5b68756ea9b359282f7`.
