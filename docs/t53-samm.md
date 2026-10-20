# T53 — preuves pour la ligne SAMM

Périmètre : ticket #53 (sous-ticket #53 de l'épic #22, « Interface Scanner et
sortie Finding »). Cette fiche fournit les couples **module + ligne** et les
permaliens du code testé ; elle ne prétend pas modifier une feuille externe.

Révision du code testé : `8b163cece98f83a1f33f99eff3bee8ebbc687a0d`
(commit `fix(scanner): repr sans secret et erreurs de contrat typées (#53)`,
au-dessus de `9fc039bf032ff29420427b1fa645564c2ff30989` — `fix(scanner): refus
de contrat pour un nombre hors bornes (#53)` et
`11ecffa79f6b2e10de10a5b68756ea9b359282f7` — `feat(scanner): interface scanner
et sortie Finding (#53)`).

Les permaliens épinglent la révision du **code**, pas le commit de
documentation qui archive cette fiche. Aucun fichier de production ni de test
ne change après `8b163ce…` : contrôle effectué avec

```sh
git diff 8b163cece98f83a1f33f99eff3bee8ebbc687a0d HEAD -- heimdall tests
```

(sortie vide au moment de l'archivage de cette fiche).

| Exigence vérifiée | Implémentation (module + ligne) | Test et preuve permanente | Résultat local |
|---|---|---|---|
| **Sortie Finding conforme au schéma #14** : sérialisation validée par `jsonschema` | [heimdall/scanner/finding.py:158–223](https://github.com/Cezar277/heimdall/blob/8b163cece98f83a1f33f99eff3bee8ebbc687a0d/heimdall/scanner/finding.py#L158-L223) | [tests/test_scanner_interface.py:77–86](https://github.com/Cezar277/heimdall/blob/8b163cece98f83a1f33f99eff3bee8ebbc687a0d/tests/test_scanner_interface.py#L77-L86) | Schéma draft 2020-12 validé sur la sortie sérialisée |
| Un Finding non conforme **n'existe pas** (validation à la construction) | [heimdall/scanner/finding.py:99–154](https://github.com/Cezar277/heimdall/blob/8b163cece98f83a1f33f99eff3bee8ebbc687a0d/heimdall/scanner/finding.py#L99-L154), [heimdall/scanner/finding.py:174–182](https://github.com/Cezar277/heimdall/blob/8b163cece98f83a1f33f99eff3bee8ebbc687a0d/heimdall/scanner/finding.py#L174-L182) | [tests/test_scanner_interface.py:201–216](https://github.com/Cezar277/heimdall/blob/8b163cece98f83a1f33f99eff3bee8ebbc687a0d/tests/test_scanner_interface.py#L201-L216) | 12 cas valides acceptés, 39 cas invalides refusés, 2 propriétés inconnues refusées : **accord code / schéma** |
| Aucun champ surnuméraire, aucun champ manquant (anti-dérive du contrat) | [heimdall/scanner/finding.py:29–37](https://github.com/Cezar277/heimdall/blob/8b163cece98f83a1f33f99eff3bee8ebbc687a0d/heimdall/scanner/finding.py#L29-L37), [heimdall/scanner/finding.py:202–223](https://github.com/Cezar277/heimdall/blob/8b163cece98f83a1f33f99eff3bee8ebbc687a0d/heimdall/scanner/finding.py#L202-L223) | [tests/test_scanner_interface.py:89–94](https://github.com/Cezar277/heimdall/blob/8b163cece98f83a1f33f99eff3bee8ebbc687a0d/tests/test_scanner_interface.py#L89-L94) | Champs du dataclass = propriétés = `required` du schéma |
| **Jamais de valeur de secret** dans un Finding (piège du ticket) | [heimdall/scanner/finding.py:184–199](https://github.com/Cezar277/heimdall/blob/8b163cece98f83a1f33f99eff3bee8ebbc687a0d/heimdall/scanner/finding.py#L184-L199) | [tests/test_scanner_interface.py:259–269](https://github.com/Cezar277/heimdall/blob/8b163cece98f83a1f33f99eff3bee8ebbc687a0d/tests/test_scanner_interface.py#L259-L269) | Sérialisation sans canari ; ni `value`, ni `secret`, ni `snippet` |
| **Pas de fuite par les logs / le `repr`** : le contenu analysé n'apparaît jamais | [heimdall/scanner/interface.py:75–131](https://github.com/Cezar277/heimdall/blob/8b163cece98f83a1f33f99eff3bee8ebbc687a0d/heimdall/scanner/interface.py#L75-L131) | [tests/test_scanner_interface.py:288–308](https://github.com/Cezar277/heimdall/blob/8b163cece98f83a1f33f99eff3bee8ebbc687a0d/tests/test_scanner_interface.py#L288-L308) | `repr` de la cible = chemin + nombre de lignes ; canari absent du `repr` comme du `str` |
| Messages d'erreur statiques (invariant 8 : aucun reflet d'entrée) | [heimdall/scanner/errors.py:14–23](https://github.com/Cezar277/heimdall/blob/8b163cece98f83a1f33f99eff3bee8ebbc687a0d/heimdall/scanner/errors.py#L14-L23) | [tests/test_scanner_interface.py:272–285](https://github.com/Cezar277/heimdall/blob/8b163cece98f83a1f33f99eff3bee8ebbc687a0d/tests/test_scanner_interface.py#L272-L285) | Canari absent des messages `InvalidFinding` et `InvalidTarget` |
| **Refus fail-closed typé** : jamais de `TypeError`/`AttributeError` brute | [heimdall/scanner/finding.py:144–154](https://github.com/Cezar277/heimdall/blob/8b163cece98f83a1f33f99eff3bee8ebbc687a0d/heimdall/scanner/finding.py#L144-L154), [heimdall/scanner/interface.py:44–71](https://github.com/Cezar277/heimdall/blob/8b163cece98f83a1f33f99eff3bee8ebbc687a0d/heimdall/scanner/interface.py#L44-L71), [heimdall/scanner/interface.py:167–223](https://github.com/Cezar277/heimdall/blob/8b163cece98f83a1f33f99eff3bee8ebbc687a0d/heimdall/scanner/interface.py#L167-L223) | [tests/test_scanner_interface.py:564–583](https://github.com/Cezar277/heimdall/blob/8b163cece98f83a1f33f99eff3bee8ebbc687a0d/tests/test_scanner_interface.py#L564-L583) | 8 entrées hostiles → `InvalidFinding` / `InvalidTarget` / `ScanError` |
| `status`/`source` non hashables (liste, dict) → erreur de contrat | [heimdall/scanner/finding.py:144–154](https://github.com/Cezar277/heimdall/blob/8b163cece98f83a1f33f99eff3bee8ebbc687a0d/heimdall/scanner/finding.py#L144-L154) | [tests/test_scanner_interface.py:313–321](https://github.com/Cezar277/heimdall/blob/8b163cece98f83a1f33f99eff3bee8ebbc687a0d/tests/test_scanner_interface.py#L313-L321) | 16 cas → `InvalidFinding` (et non `TypeError`) |
| Conteneur de lignes ou entrée malformée → `InvalidTarget` | [heimdall/scanner/interface.py:44–71](https://github.com/Cezar277/heimdall/blob/8b163cece98f83a1f33f99eff3bee8ebbc687a0d/heimdall/scanner/interface.py#L44-L71) | [tests/test_scanner_interface.py:387–401](https://github.com/Cezar277/heimdall/blob/8b163cece98f83a1f33f99eff3bee8ebbc687a0d/tests/test_scanner_interface.py#L387-L401) | `(None,)`, `"ab"`, `[["ok"]*3]`, `[None]`, `42`, `None` → `InvalidTarget` ; normalisation en tuple |
| Cible = lignes ajoutées du diff indexé, numéros de ligne réels | [heimdall/scanner/interface.py:75–105](https://github.com/Cezar277/heimdall/blob/8b163cece98f83a1f33f99eff3bee8ebbc687a0d/heimdall/scanner/interface.py#L75-L105) | [tests/test_scanner_interface.py:358–371](https://github.com/Cezar277/heimdall/blob/8b163cece98f83a1f33f99eff3bee8ebbc687a0d/tests/test_scanner_interface.py#L358-L371) | Numéros conservés ; lignes désordonnées, nulles ou dupliquées refusées |
| Cible = fichier entier (démarrage à froid) | [heimdall/scanner/interface.py:109–131](https://github.com/Cezar277/heimdall/blob/8b163cece98f83a1f33f99eff3bee8ebbc687a0d/heimdall/scanner/interface.py#L109-L131) | [tests/test_scanner_interface.py:404–406](https://github.com/Cezar277/heimdall/blob/8b163cece98f83a1f33f99eff3bee8ebbc687a0d/tests/test_scanner_interface.py#L404-L406) | Lignes numérotées à partir de 1 |
| Chemins hors dépôt refusés **avant** toute lecture (traversée) | [heimdall/scanner/finding.py:67–96](https://github.com/Cezar277/heimdall/blob/8b163cece98f83a1f33f99eff3bee8ebbc687a0d/heimdall/scanner/finding.py#L67-L96), [heimdall/scanner/interface.py:36–41](https://github.com/Cezar277/heimdall/blob/8b163cece98f83a1f33f99eff3bee8ebbc687a0d/heimdall/scanner/interface.py#L36-L41) | [tests/test_scanner_interface.py:410–414](https://github.com/Cezar277/heimdall/blob/8b163cece98f83a1f33f99eff3bee8ebbc687a0d/tests/test_scanner_interface.py#L410-L414) | `../`, absolu, `C:/` → `InvalidTarget` |
| `scan(cible) -> list[Finding]` : délégation, tri stable, ordre reproductible | [heimdall/scanner/interface.py:167–223](https://github.com/Cezar277/heimdall/blob/8b163cece98f83a1f33f99eff3bee8ebbc687a0d/heimdall/scanner/interface.py#L167-L223) | [tests/test_scanner_interface.py:444–476](https://github.com/Cezar277/heimdall/blob/8b163cece98f83a1f33f99eff3bee8ebbc687a0d/tests/test_scanner_interface.py#L444-L476) | Tri `(ligne, type, empreinte)` puis `(fichier, …)` |
| Fail-closed : sortie non conforme refusée, jamais de liste partielle | [heimdall/scanner/interface.py:150–164](https://github.com/Cezar277/heimdall/blob/8b163cece98f83a1f33f99eff3bee8ebbc687a0d/heimdall/scanner/interface.py#L150-L164) | [tests/test_scanner_interface.py:491–500](https://github.com/Cezar277/heimdall/blob/8b163cece98f83a1f33f99eff3bee8ebbc687a0d/tests/test_scanner_interface.py#L491-L500) | Objet non-Finding, autre fichier, états `confirme`/`vaulte`/`rote`/`faux_positif`, origine `llm` → `ScanError` |
| Le LLM n'a aucun droit de transition sur le Finding | [heimdall/scanner/interface.py:150–164](https://github.com/Cezar277/heimdall/blob/8b163cece98f83a1f33f99eff3bee8ebbc687a0d/heimdall/scanner/interface.py#L150-L164), [docs/contracts/finding.md:50–64](https://github.com/Cezar277/heimdall/blob/8b163cece98f83a1f33f99eff3bee8ebbc687a0d/docs/contracts/finding.md#L50-L64) | [tests/test_scanner_interface.py:491–500](https://github.com/Cezar277/heimdall/blob/8b163cece98f83a1f33f99eff3bee8ebbc687a0d/tests/test_scanner_interface.py#L491-L500) | Le scanner ne rend que `detecte` + origine déterministe |
| Cible, moteur et sortie : un seul type d'erreur | [heimdall/scanner/interface.py:188–211](https://github.com/Cezar277/heimdall/blob/8b163cece98f83a1f33f99eff3bee8ebbc687a0d/heimdall/scanner/interface.py#L188-L211) | [tests/test_scanner_interface.py:513–546](https://github.com/Cezar277/heimdall/blob/8b163cece98f83a1f33f99eff3bee8ebbc687a0d/tests/test_scanner_interface.py#L513-L546) | Cible non cible, moteur sans `analyser`, sortie `None`/non itérable → `ScanError` |
| Le code est **au moins aussi strict** que le schéma (anti-dérive) | [heimdall/scanner/finding.py:99–154](https://github.com/Cezar277/heimdall/blob/8b163cece98f83a1f33f99eff3bee8ebbc687a0d/heimdall/scanner/finding.py#L99-L154) | [tests/test_scanner_interface.py:233–253](https://github.com/Cezar277/heimdall/blob/8b163cece98f83a1f33f99eff3bee8ebbc687a0d/tests/test_scanner_interface.py#L233-L253) | 2 écarts assumés, où le code refuse ce que le schéma tolère (`line: 1.0`, `entropy: NaN`) |

## Corrections issues de la relecture « REQUEST CHANGES »

| Remarque | Correctif | Preuve |
|---|---|---|
| HIGH — `repr` par défaut exposait les lignes ajoutées et le fichier entier (donc les secrets en clair) | `lines` et `text` sortent du `repr` (`field(repr=False)`) ; `repr` résumé : chemin + nombre de lignes / de caractères | [interface.py:75–131](https://github.com/Cezar277/heimdall/blob/8b163cece98f83a1f33f99eff3bee8ebbc687a0d/heimdall/scanner/interface.py#L75-L131) + [test_scanner_interface.py:288–308](https://github.com/Cezar277/heimdall/blob/8b163cece98f83a1f33f99eff3bee8ebbc687a0d/tests/test_scanner_interface.py#L288-L308) |
| MEDIUM — `status`/`source` non hashables : `TypeError` au lieu de `InvalidFinding` | test de type avant l'appartenance au `frozenset` | [finding.py:144–154](https://github.com/Cezar277/heimdall/blob/8b163cece98f83a1f33f99eff3bee8ebbc687a0d/heimdall/scanner/finding.py#L144-L154) + [test_scanner_interface.py:313–321](https://github.com/Cezar277/heimdall/blob/8b163cece98f83a1f33f99eff3bee8ebbc687a0d/tests/test_scanner_interface.py#L313-L321) |
| LOW — déballage des lignes non protégé (`TypeError`/`ValueError` bruts) | validation du conteneur puis de chaque entrée avant déballage ; normalisation en tuple de couples | [interface.py:44–71](https://github.com/Cezar277/heimdall/blob/8b163cece98f83a1f33f99eff3bee8ebbc687a0d/heimdall/scanner/interface.py#L44-L71) + [test_scanner_interface.py:387–401](https://github.com/Cezar277/heimdall/blob/8b163cece98f83a1f33f99eff3bee8ebbc687a0d/tests/test_scanner_interface.py#L387-L401) |
| LOW — `Scanner.scan` sans garde de type sur la cible ni sur le moteur | cible non cible → `InvalidTarget` ; moteur sans `analyser` → `ScanError` ; sortie `None` ou non itérable → `ScanError` | [interface.py:188–211](https://github.com/Cezar277/heimdall/blob/8b163cece98f83a1f33f99eff3bee8ebbc687a0d/heimdall/scanner/interface.py#L188-L211) + [test_scanner_interface.py:513–546](https://github.com/Cezar277/heimdall/blob/8b163cece98f83a1f33f99eff3bee8ebbc687a0d/tests/test_scanner_interface.py#L513-L546) |

## Résultats locaux

Environnement : Linux, Python 3.14.6, venv du dépôt.

```text
.venv/bin/python -m pytest tests/test_scanner_interface.py
123 passed

.venv/bin/python -m pytest --cov=heimdall --cov-branch --cov-report=term-missing
suite complète : 969 passed, 1 xfailed (+ 3852 subtests), code retour 0
couverture Heimdall : 98 %
heimdall/scanner/finding.py : 100 % (branches incluses)
heimdall/scanner/interface.py : 100 % (branches incluses)
heimdall/scanner/errors.py : 100 % (branches incluses)

.venv/bin/ruff check heimdall tests        # All checks passed
.venv/bin/mypy heimdall tests/contracts/fastapi_contract_fixture.py
                                            # Success: no issues found
.venv/bin/bandit -r heimdall -q             # code retour 0, aucun rapport
.venv/bin/python docs/security/check_model.py
                                            # OK (48 scénarios, DFD, PNG)
```

Le `xfailed` restant est celui de T21 (`tests/test_trap_acceptance.py`) : il
attend la livraison du scanner #22 et devient un `XPASS(strict)` dès que le
moteur réel (#54/#59) est branché sur cette interface.

## Limite assumée : la garde de chemin reste lexicale

La garde de chemin de cette interface est **lexicale** (`..`, absolu, `C:/`,
caractères de contrôle refusés avant toute lecture) et cette PR ne fait
**aucune I/O**. Conformément à l'invariant 3, le confinement complet
(`resolve` + `is_relative_to` sur une racine fixée au démarrage, refus des
liens sortants, identité de descripteur revérifiée à l'usage) reste à faire
par #54/#59 et par `heimdall/mcp/gitdiff.py` : la garde lexicale **ne doit pas
être considérée comme suffisante** contre les liens symboliques et le TOCTOU.
C'est écrit dans `docs/scanner-interface.md` (« Ce que ce ticket ne fait pas »
et « Contraintes pour le moteur »).

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
[tests/test_scanner_interface.py:557–561](https://github.com/Cezar277/heimdall/blob/8b163cece98f83a1f33f99eff3bee8ebbc687a0d/tests/test_scanner_interface.py#L557-L561).

## Relecture et PR

- PR : à ouvrir sur la branche `53-t221-interface-scanner-et-sortie-finding`
  avec `Closes #53` (et `Refs #22`).
- Relecture par un membre d'un autre domaine et check `CI (/ci)` restent
  requis avant fusion.
- Reporter la ligne ci-dessus dans la feuille SAMM de l'équipe avec le lien de
  la PR et le SHA `8b163cece98f83a1f33f99eff3bee8ebbc687a0d`.
