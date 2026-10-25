# T53 — preuves pour la ligne SAMM

Périmètre : ticket #53 (sous-ticket #53 de l'épic #22, « Interface Scanner et
sortie Finding »). Cette fiche fournit les couples **module + ligne** et les
permaliens du code testé ; elle ne prétend pas modifier une feuille externe.

Révision du code testé pour la preuve initiale : `b6730cb9b62ff6e9fd58ce409de5b76a2c5e9072`
(commit `fix(scanner): exceptions du moteur et de l'itération enveloppées (#53)`,
au-dessus de `8b163cece98f83a1f33f99eff3bee8ebbc687a0d` — `fix(scanner): repr
sans secret et erreurs de contrat typées (#53)`).

Les permaliens de la première table épinglent cette révision **historique**,
pas le commit de documentation qui archive cette fiche. Les correctifs de
suivi de la revue #155 modifient ensuite `finding.py`, `interface.py`,
`errors.py`, `detect.py` et les tests ; leurs preuves sont dans la section
« Suivi de la revue #155 » ci-dessous, avec leurs propres permaliens.

| Exigence vérifiée | Implémentation (module + ligne) | Test et preuve permanente | Résultat local |
|---|---|---|---|
| **Sortie Finding conforme au schéma #14** : sérialisation validée par `jsonschema` | [heimdall/scanner/finding.py:158–223](https://github.com/Cezar277/heimdall/blob/b6730cb9b62ff6e9fd58ce409de5b76a2c5e9072/heimdall/scanner/finding.py#L158-L223) | [tests/test_scanner_interface.py:81–90](https://github.com/Cezar277/heimdall/blob/b6730cb9b62ff6e9fd58ce409de5b76a2c5e9072/tests/test_scanner_interface.py#L81-L90) | Schéma draft 2020-12 validé sur la sortie sérialisée |
| Un Finding non conforme **n'existe pas** (validation à la construction) | [heimdall/scanner/finding.py:99–154](https://github.com/Cezar277/heimdall/blob/b6730cb9b62ff6e9fd58ce409de5b76a2c5e9072/heimdall/scanner/finding.py#L99-L154), [heimdall/scanner/finding.py:174–182](https://github.com/Cezar277/heimdall/blob/b6730cb9b62ff6e9fd58ce409de5b76a2c5e9072/heimdall/scanner/finding.py#L174-L182) | [tests/test_scanner_interface.py:205–220](https://github.com/Cezar277/heimdall/blob/b6730cb9b62ff6e9fd58ce409de5b76a2c5e9072/tests/test_scanner_interface.py#L205-L220) | 12 cas valides acceptés, 39 cas invalides refusés, 2 propriétés inconnues refusées : **accord code / schéma** |
| Aucun champ surnuméraire, aucun champ manquant (anti-dérive du contrat) | [heimdall/scanner/finding.py:29–37](https://github.com/Cezar277/heimdall/blob/b6730cb9b62ff6e9fd58ce409de5b76a2c5e9072/heimdall/scanner/finding.py#L29-L37), [heimdall/scanner/finding.py:202–223](https://github.com/Cezar277/heimdall/blob/b6730cb9b62ff6e9fd58ce409de5b76a2c5e9072/heimdall/scanner/finding.py#L202-L223) | [tests/test_scanner_interface.py:93–98](https://github.com/Cezar277/heimdall/blob/b6730cb9b62ff6e9fd58ce409de5b76a2c5e9072/tests/test_scanner_interface.py#L93-L98) | Champs du dataclass = propriétés = `required` du schéma |
| **Jamais de valeur de secret** dans un Finding (piège du ticket) | [heimdall/scanner/finding.py:184–199](https://github.com/Cezar277/heimdall/blob/b6730cb9b62ff6e9fd58ce409de5b76a2c5e9072/heimdall/scanner/finding.py#L184-L199) | [tests/test_scanner_interface.py:263–273](https://github.com/Cezar277/heimdall/blob/b6730cb9b62ff6e9fd58ce409de5b76a2c5e9072/tests/test_scanner_interface.py#L263-L273) | Sérialisation sans canari ; ni `value`, ni `secret`, ni `snippet` |
| **Pas de fuite par les logs / le `repr`** : le contenu analysé n'apparaît jamais | [heimdall/scanner/interface.py:112–168](https://github.com/Cezar277/heimdall/blob/b6730cb9b62ff6e9fd58ce409de5b76a2c5e9072/heimdall/scanner/interface.py#L112-L168) | [tests/test_scanner_interface.py:292–312](https://github.com/Cezar277/heimdall/blob/b6730cb9b62ff6e9fd58ce409de5b76a2c5e9072/tests/test_scanner_interface.py#L292-L312) | `repr` de la cible = chemin + nombre de lignes ; canari absent du `repr` comme du `str` |
| Messages d'erreur statiques (invariant 8 : aucun reflet d'entrée) | [heimdall/scanner/errors.py:14–23](https://github.com/Cezar277/heimdall/blob/b6730cb9b62ff6e9fd58ce409de5b76a2c5e9072/heimdall/scanner/errors.py#L14-L23) | [tests/test_scanner_interface.py:276–289](https://github.com/Cezar277/heimdall/blob/b6730cb9b62ff6e9fd58ce409de5b76a2c5e9072/tests/test_scanner_interface.py#L276-L289) | Canari absent des messages `InvalidFinding` et `InvalidTarget` |
| **Refus fail-closed typé** : jamais de `TypeError`/`AttributeError` brute | [heimdall/scanner/finding.py:144–154](https://github.com/Cezar277/heimdall/blob/b6730cb9b62ff6e9fd58ce409de5b76a2c5e9072/heimdall/scanner/finding.py#L144-L154), [heimdall/scanner/interface.py:46–70](https://github.com/Cezar277/heimdall/blob/b6730cb9b62ff6e9fd58ce409de5b76a2c5e9072/heimdall/scanner/interface.py#L46-L70), [heimdall/scanner/interface.py:81–108](https://github.com/Cezar277/heimdall/blob/b6730cb9b62ff6e9fd58ce409de5b76a2c5e9072/heimdall/scanner/interface.py#L81-L108), [heimdall/scanner/interface.py:214–279](https://github.com/Cezar277/heimdall/blob/b6730cb9b62ff6e9fd58ce409de5b76a2c5e9072/heimdall/scanner/interface.py#L214-L279) | [tests/test_scanner_interface.py:646–687](https://github.com/Cezar277/heimdall/blob/b6730cb9b62ff6e9fd58ce409de5b76a2c5e9072/tests/test_scanner_interface.py#L646-L687) | 11 entrées hostiles → `InvalidFinding` / `InvalidTarget` / `ScanError` |
| `status`/`source` non hashables (liste, dict) → erreur de contrat | [heimdall/scanner/finding.py:144–154](https://github.com/Cezar277/heimdall/blob/b6730cb9b62ff6e9fd58ce409de5b76a2c5e9072/heimdall/scanner/finding.py#L144-L154) | [tests/test_scanner_interface.py:317–325](https://github.com/Cezar277/heimdall/blob/b6730cb9b62ff6e9fd58ce409de5b76a2c5e9072/tests/test_scanner_interface.py#L317-L325) | 16 cas → `InvalidFinding` (et non `TypeError`) |
| Conteneur de lignes ou entrée malformée → `InvalidTarget` | [heimdall/scanner/interface.py:81–108](https://github.com/Cezar277/heimdall/blob/b6730cb9b62ff6e9fd58ce409de5b76a2c5e9072/heimdall/scanner/interface.py#L81-L108) | [tests/test_scanner_interface.py:391–405](https://github.com/Cezar277/heimdall/blob/b6730cb9b62ff6e9fd58ce409de5b76a2c5e9072/tests/test_scanner_interface.py#L391-L405) | `(None,)`, `"ab"`, `[["ok"]*3]`, `[None]`, `42`, `None` → `InvalidTarget` ; normalisation en tuple |
| Cible = lignes ajoutées du diff indexé, numéros de ligne réels | [heimdall/scanner/interface.py:112–142](https://github.com/Cezar277/heimdall/blob/b6730cb9b62ff6e9fd58ce409de5b76a2c5e9072/heimdall/scanner/interface.py#L112-L142) | [tests/test_scanner_interface.py:362–375](https://github.com/Cezar277/heimdall/blob/b6730cb9b62ff6e9fd58ce409de5b76a2c5e9072/tests/test_scanner_interface.py#L362-L375) | Numéros conservés ; lignes désordonnées, nulles ou dupliquées refusées |
| Cible = fichier entier (démarrage à froid) | [heimdall/scanner/interface.py:146–168](https://github.com/Cezar277/heimdall/blob/b6730cb9b62ff6e9fd58ce409de5b76a2c5e9072/heimdall/scanner/interface.py#L146-L168) | [tests/test_scanner_interface.py:408–410](https://github.com/Cezar277/heimdall/blob/b6730cb9b62ff6e9fd58ce409de5b76a2c5e9072/tests/test_scanner_interface.py#L408-L410) | Lignes numérotées à partir de 1 |
| Chemins hors dépôt refusés **avant** toute lecture (traversée) | [heimdall/scanner/finding.py:67–96](https://github.com/Cezar277/heimdall/blob/b6730cb9b62ff6e9fd58ce409de5b76a2c5e9072/heimdall/scanner/finding.py#L67-L96), [heimdall/scanner/interface.py:73–78](https://github.com/Cezar277/heimdall/blob/b6730cb9b62ff6e9fd58ce409de5b76a2c5e9072/heimdall/scanner/interface.py#L73-L78) | [tests/test_scanner_interface.py:414–418](https://github.com/Cezar277/heimdall/blob/b6730cb9b62ff6e9fd58ce409de5b76a2c5e9072/tests/test_scanner_interface.py#L414-L418) | `../`, absolu, `C:/` → `InvalidTarget` |
| `scan(cible) -> list[Finding]` : délégation, tri stable, ordre reproductible | [heimdall/scanner/interface.py:214–279](https://github.com/Cezar277/heimdall/blob/b6730cb9b62ff6e9fd58ce409de5b76a2c5e9072/heimdall/scanner/interface.py#L214-L279) | [tests/test_scanner_interface.py:448–480](https://github.com/Cezar277/heimdall/blob/b6730cb9b62ff6e9fd58ce409de5b76a2c5e9072/tests/test_scanner_interface.py#L448-L480) | Tri `(ligne, type, empreinte)` puis `(fichier, …)` |
| Fail-closed : sortie non conforme refusée, jamais de liste partielle | [heimdall/scanner/interface.py:187–201](https://github.com/Cezar277/heimdall/blob/b6730cb9b62ff6e9fd58ce409de5b76a2c5e9072/heimdall/scanner/interface.py#L187-L201) | [tests/test_scanner_interface.py:495–504](https://github.com/Cezar277/heimdall/blob/b6730cb9b62ff6e9fd58ce409de5b76a2c5e9072/tests/test_scanner_interface.py#L495-L504) | Objet non-Finding, autre fichier, états `confirme`/`vaulte`/`rote`/`faux_positif`, origine `llm` → `ScanError` |
| Le LLM n'a aucun droit de transition sur le Finding | [heimdall/scanner/interface.py:187–201](https://github.com/Cezar277/heimdall/blob/b6730cb9b62ff6e9fd58ce409de5b76a2c5e9072/heimdall/scanner/interface.py#L187-L201), [docs/contracts/finding.md:50–64](https://github.com/Cezar277/heimdall/blob/b6730cb9b62ff6e9fd58ce409de5b76a2c5e9072/docs/contracts/finding.md#L50-L64) | [tests/test_scanner_interface.py:495–504](https://github.com/Cezar277/heimdall/blob/b6730cb9b62ff6e9fd58ce409de5b76a2c5e9072/tests/test_scanner_interface.py#L495-L504) | Le scanner ne rend que `detecte` + origine déterministe |
| Cible, moteur et sortie : un seul type d'erreur | [heimdall/scanner/interface.py:240–265](https://github.com/Cezar277/heimdall/blob/b6730cb9b62ff6e9fd58ce409de5b76a2c5e9072/heimdall/scanner/interface.py#L240-L265) | [tests/test_scanner_interface.py:595–628](https://github.com/Cezar277/heimdall/blob/b6730cb9b62ff6e9fd58ce409de5b76a2c5e9072/tests/test_scanner_interface.py#L595-L628) | Cible non cible, moteur sans `analyser`, sortie `None`/non itérable → `ScanError` |
| **Les exceptions du moteur et de l'itération sont enveloppées** (message statique, jamais de canari) | [heimdall/scanner/interface.py:46–70](https://github.com/Cezar277/heimdall/blob/b6730cb9b62ff6e9fd58ce409de5b76a2c5e9072/heimdall/scanner/interface.py#L46-L70), [heimdall/scanner/interface.py:245–279](https://github.com/Cezar277/heimdall/blob/b6730cb9b62ff6e9fd58ce409de5b76a2c5e9072/heimdall/scanner/interface.py#L245-L279) | [tests/test_scanner_interface.py:507–591](https://github.com/Cezar277/heimdall/blob/b6730cb9b62ff6e9fd58ce409de5b76a2c5e9072/tests/test_scanner_interface.py#L507-L591) | Moteur qui lève (`ValueError`, `RuntimeError`, `KeyError`, `ZeroDivisionError`), rendu qui lève à la consommation, générateur de cibles fautif → `ScanError` ; canari absent du type, du message, de `__context__` et de la traceback |
| Le code est **au moins aussi strict** que le schéma (anti-dérive) | [heimdall/scanner/finding.py:99–154](https://github.com/Cezar277/heimdall/blob/b6730cb9b62ff6e9fd58ce409de5b76a2c5e9072/heimdall/scanner/finding.py#L99-L154) | [tests/test_scanner_interface.py:237–257](https://github.com/Cezar277/heimdall/blob/b6730cb9b62ff6e9fd58ce409de5b76a2c5e9072/tests/test_scanner_interface.py#L237-L257) | 2 écarts assumés, où le code refuse ce que le schéma tolère (`line: 1.0`, `entropy: NaN`) |

## Corrections issues de la relecture « REQUEST CHANGES »

| Remarque | Correctif | Preuve |
|---|---|---|
| HIGH — `repr` par défaut exposait les lignes ajoutées et le fichier entier (donc les secrets en clair) | `lines` et `text` sortent du `repr` (`field(repr=False)`) ; `repr` résumé : chemin + nombre de lignes / de caractères | [interface.py:112–168](https://github.com/Cezar277/heimdall/blob/b6730cb9b62ff6e9fd58ce409de5b76a2c5e9072/heimdall/scanner/interface.py#L112-L168) + [test_scanner_interface.py:292–312](https://github.com/Cezar277/heimdall/blob/b6730cb9b62ff6e9fd58ce409de5b76a2c5e9072/tests/test_scanner_interface.py#L292-L312) |
| MEDIUM — `status`/`source` non hashables : `TypeError` au lieu de `InvalidFinding` | test de type avant l'appartenance au `frozenset` | [finding.py:144–154](https://github.com/Cezar277/heimdall/blob/b6730cb9b62ff6e9fd58ce409de5b76a2c5e9072/heimdall/scanner/finding.py#L144-L154) + [test_scanner_interface.py:317–325](https://github.com/Cezar277/heimdall/blob/b6730cb9b62ff6e9fd58ce409de5b76a2c5e9072/tests/test_scanner_interface.py#L317-L325) |
| LOW — déballage des lignes non protégé (`TypeError`/`ValueError` bruts) | validation du conteneur puis de chaque entrée avant déballage ; normalisation en tuple de couples | [interface.py:81–108](https://github.com/Cezar277/heimdall/blob/b6730cb9b62ff6e9fd58ce409de5b76a2c5e9072/heimdall/scanner/interface.py#L81-L108) + [test_scanner_interface.py:391–405](https://github.com/Cezar277/heimdall/blob/b6730cb9b62ff6e9fd58ce409de5b76a2c5e9072/tests/test_scanner_interface.py#L391-L405) |
| LOW — `Scanner.scan` sans garde de type sur la cible ni sur le moteur | cible non cible → `InvalidTarget` ; moteur sans `analyser` → `ScanError` ; sortie `None` ou non itérable → `ScanError` | [interface.py:240–265](https://github.com/Cezar277/heimdall/blob/b6730cb9b62ff6e9fd58ce409de5b76a2c5e9072/heimdall/scanner/interface.py#L240-L265) + [test_scanner_interface.py:595–628](https://github.com/Cezar277/heimdall/blob/b6730cb9b62ff6e9fd58ce409de5b76a2c5e9072/tests/test_scanner_interface.py#L595-L628) |

## Corrections issues de la relecture « APPROVE WITH COMMENTS »

La seconde relecture a vérifié **en exécution** que les quatre remarques
précédentes (HIGH `repr`, MEDIUM `status`/`source`, LOW déballage, LOW garde
`scan`) sont corrigées : rien à rouvrir. Il restait un écart de contrat réel,
sur le **message d'erreur du moteur**.

| Remarque | Correctif | Preuve |
|---|---|---|
| MEDIUM — « exceptions du moteur et de l'itération non enveloppées » : `scan()` appelle `moteur.analyser(cible)` hors `try` (une `ValueError` traversait brute), `scan_all()` ne catchait que `TypeError` sur `list(cibles)` (un générateur fautif traversait en `RuntimeError`), et `list(resultat)` ne couvrait que le rendu non itérable (un générateur qui explose à la consommation traversait) | `_guard_call` enveloppe chaque appel fautif : toute exception devient une `ScanError` au message **statique**. L'erreur est relancée **hors** du bloc `except`, donc `__cause__` et `__context__` restent vides et la traceback journalisée ne ressuscite pas le message du moteur (invariant 8). Les `BaseException` (`KeyboardInterrupt`, `SystemExit`) ne sont pas capturées | [interface.py:46–70](https://github.com/Cezar277/heimdall/blob/b6730cb9b62ff6e9fd58ce409de5b76a2c5e9072/heimdall/scanner/interface.py#L46-L70) + [interface.py:245–279](https://github.com/Cezar277/heimdall/blob/b6730cb9b62ff6e9fd58ce409de5b76a2c5e9072/heimdall/scanner/interface.py#L245-L279) + [test_scanner_interface.py:507–591](https://github.com/Cezar277/heimdall/blob/b6730cb9b62ff6e9fd58ce409de5b76a2c5e9072/tests/test_scanner_interface.py#L507-L591) |

Les trois tests demandés par la relecture sont présents : moteur qui lève
(avec canari dans le message), `scan_all` sur générateur qui lève en cours
d'itération, et moteur dont `analyser` rend un générateur qui lève à la
consommation. Le canari est vérifié absent du **type**, du **message**, de
`__context__` **et** de la traceback formatée.

## Suivi de la revue #155

Révision des correctifs : `f75c1f9cbdbb4f649fcdd0668ac51f389ffa970f`
(`fix(scanner): corriger la revue #155 sans changer le contrat`). Les
remarques MEDIUM/LOW encore applicables après la fusion de `main` et les
tests manquants sont traités sans changer le contrat de sortie ni le
fail-closed. La remarque sur `find_candidates`/`NotImplementedError` est
devenue sans objet : `find_candidates` est désormais implémenté (#22).

| Remarque | Correctif | Preuve |
|---|---|---|
| MEDIUM — `FileTarget.lignes()` utilisait `splitlines()` (coupait aussi sur `\v`, `\f`, `\u2028/29`) | découpage sur `\n` seul, `\r\n` normalisé, autres séparateurs conservés dans le contenu | [interface.py:174–190](https://github.com/Cezar277/heimdall/blob/f75c1f9cbdbb4f649fcdd0668ac51f389ffa970f/heimdall/scanner/interface.py#L174-L190) + [tests:424–451](https://github.com/Cezar277/heimdall/blob/f75c1f9cbdbb4f649fcdd0668ac51f389ffa970f/tests/test_scanner_interface.py#L424-L451) |
| LOW — `Scanner` relisait `moteur.analyser` à chaque scan (TOCTOU) | méthode liée figée à la construction et appelée ensuite | [interface.py:261–273](https://github.com/Cezar277/heimdall/blob/f75c1f9cbdbb4f649fcdd0668ac51f389ffa970f/heimdall/scanner/interface.py#L261-L273), [interface.py:288](https://github.com/Cezar277/heimdall/blob/f75c1f9cbdbb4f649fcdd0668ac51f389ffa970f/heimdall/scanner/interface.py#L288) + [tests:534–555](https://github.com/Cezar277/heimdall/blob/f75c1f9cbdbb4f649fcdd0668ac51f389ffa970f/tests/test_scanner_interface.py#L534-L555) |
| Tests manquants | `bool` refusé comme numéro de ligne, `KeyboardInterrupt` non converti, `scan_all` fail-closed sur liste mixte | [tests:375–387](https://github.com/Cezar277/heimdall/blob/f75c1f9cbdbb4f649fcdd0668ac51f389ffa970f/tests/test_scanner_interface.py#L375-L387), [tests:603–611](https://github.com/Cezar277/heimdall/blob/f75c1f9cbdbb4f649fcdd0668ac51f389ffa970f/tests/test_scanner_interface.py#L603-L611), [tests:758–768](https://github.com/Cezar277/heimdall/blob/f75c1f9cbdbb4f649fcdd0668ac51f389ffa970f/tests/test_scanner_interface.py#L758-L768) |

## Résultats locaux

Environnement : Linux, Python 3.14.7, venv reconstruit depuis
`requirements.lock` (mêmes versions que la CI).

```text
.venv-ci/bin/python -m pytest tests/test_scanner_interface.py
148 passed

.venv-ci/bin/python -m pytest --cov=heimdall --cov-branch --cov-report=term-missing --cov-fail-under=85
suite complète : 1128 passed, 1 skipped, 1 xfailed (+ 4251 subtests), code retour 0
couverture Heimdall : 96,31 % (seuil CI 85 %)
heimdall/scanner/* : 100 % (branches incluses)

.venv-ci/bin/ruff check heimdall tests        # All checks passed
.venv-ci/bin/mypy heimdall tests/contracts/fastapi_contract_fixture.py
                                            # Success: no issues found in 27 source files
.venv-ci/bin/bandit -r heimdall -q             # code retour 0, aucun rapport
.venv-ci/bin/python docs/security/check_model.py
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
[tests/test_scanner_interface.py:639–643](https://github.com/Cezar277/heimdall/blob/b6730cb9b62ff6e9fd58ce409de5b76a2c5e9072/tests/test_scanner_interface.py#L639-L643).

## Relecture et PR

- PR : à ouvrir sur la branche `53-t221-interface-scanner-et-sortie-finding`
  avec `Closes #53` (et `Refs #22`).
- Relecture par un membre d'un autre domaine et check `CI (/ci)` restent
  requis avant fusion.
- Reporter la ligne ci-dessus dans la feuille SAMM de l'équipe avec le lien de
  la PR et le SHA `b6730cb9b62ff6e9fd58ce409de5b76a2c5e9072`.
