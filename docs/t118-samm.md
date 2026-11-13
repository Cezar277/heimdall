# T118 — preuves pour la ligne SAMM (tests des transitions interdites)

Sous-ticket **T404** (ticket GitHub **#118**) du grand ticket
`#40 « États du secret dans le Vault »`, branche
`118-t404-tests-des-transitions-interdites`. Cette fiche fournit les couples
**module + ligne** et les tests qui prouvent la checklist du ticket ; elle ne
remplace pas la revue de code.

> **Permaliens** : les liens ci-dessous sont épinglés sur la révision
> [`3020159`](https://github.com/Cezar277/heimdall/commit/30201593c50a869492c8dd0cc9811acbb20c9c95),
> qui contient la suite de tests exhaustive des transitions interdites (version
> revue). Les plages de lignes des modules déjà livrés (#115, #117) sont celles
> de cette révision.
>
> **Base de la PR** : la preuve porte sur le chemin *opérationnel* (route HTTP
> + stores du Vault), introduit par le sous-ticket #117 (§8 de l'ADR-006). La
> branche #118 est donc rebasée sur `117-t403-api-de-transition` (`e8f63eb`) :
> elle en est un fast-forward strict, **sans commit de fusion avec `main`**, et
> le diff de la PR — base `117-t403-api-de-transition` — ne contient que les
> fichiers #118 :
>
> ```text
> $ git diff --name-only origin/117-t403-api-de-transition..HEAD
> README.md
> docs/adr/006-table-etats-et-transitions.md
> docs/contracts/vault-traceability.md
> docs/t118-samm.md
> tests/test_vault_transitions_forbidden.py
> ```
>
> Aucun fichier de production n'est modifié par #118 : ni `heimdall/**`,
> ni `openapi.yaml`, ni `schemas/**`. Le diff contre `main` contient en plus
> #117, qui doit être fusionné en amont (le maintainer est le seul habilité à
> merger, cf. CONTRIBUTING §6).

## 1. Exigences du ticket et preuves

| Exigence vérifiée | Implémentation (module + ligne) | Test et preuve permanente | Résultat local |
|---|---|---|---|
| **Toutes les transitions interdites sont refusées** : test paramétré sur les 25 couples (état de départ, état d'arrivée), dont les **20 interdits** de la matrice 5x5 | [transitions.py:256-274](https://github.com/Cezar277/heimdall/blob/30201593c50a869492c8dd0cc9811acbb20c9c95/heimdall/vault/transitions.py#L256-L274) (`validate_transition`), [transitions.py:93-95](https://github.com/Cezar277/heimdall/blob/30201593c50a869492c8dd0cc9811acbb20c9c95/heimdall/vault/transitions.py#L93-L95) (`ALLOWED_TRANSITIONS`), [test_vault_transitions_forbidden.py:161-261](https://github.com/Cezar277/heimdall/blob/30201593c50a869492c8dd0cc9811acbb20c9c95/tests/test_vault_transitions_forbidden.py#L161-L260) | `tests/test_vault_transitions_forbidden.py::TestForbiddenTransitionMatrix::test_forbidden_transition_raises_with_the_formal_reason` (20 cas paramétrés, un par paire interdite) | Réussi (20/20 refusés avec la justification formelle) |
| **Les transitions autorisées restent acceptées** : la preuve ne bloque pas tout (5 paires) | [transitions.py:93-95](https://github.com/Cezar277/heimdall/blob/30201593c50a869492c8dd0cc9811acbb20c9c95/heimdall/vault/transitions.py#L93-L95) | `::TestForbiddenTransitionMatrix::test_allowed_transition_is_accepted` (5 cas) | Réussi |
| **La table des justifications est complète et exclusive** : une justification pour chaque paire interdite, aucune pour une paire autorisée | [transitions.py:179-181](https://github.com/Cezar277/heimdall/blob/30201593c50a869492c8dd0cc9811acbb20c9c95/heimdall/vault/transitions.py#L179-L181) (`FORBIDDEN_TRANSITION_REASONS`) | `::TestTransitionMatrixIntegrity::test_forbidden_reason_table_covers_exactly_the_forbidden_pairs`, `::test_matrix_partitions_the_25_ordered_pairs` | Réussi |
| **Un refus ne mute ni l'état ni le journal** (backend mémoire, 25 paires testées) | [store.py:259-331](https://github.com/Cezar277/heimdall/blob/30201593c50a869492c8dd0cc9811acbb20c9c95/heimdall/vault/store.py#L259-L331) (`InMemorySecretStore.transition`) | `::TestForbiddenTransitionStore::test_memory_store_applies_the_matrix_without_side_effect` (25 cas) | Réussi (25/25) |
| **Un refus ne mute ni l'état ni le journal** (backend SQLite, backend de production) | [store.py:632-678](https://github.com/Cezar277/heimdall/blob/30201593c50a869492c8dd0cc9811acbb20c9c95/heimdall/vault/store.py#L632-L678) (`SqliteSecretStore.transition`), [database.py:1920-1992](https://github.com/Cezar277/heimdall/blob/30201593c50a869492c8dd0cc9811acbb20c9c95/heimdall/vault/database.py#L1920-L1992) (`transition_secret`) | `::TestForbiddenTransitionStore::test_sqlite_store_applies_the_matrix_without_side_effect` (10 cas) | Réussi (10/10) |
| **Un état source non persistable ne peut pas quitter le Vault** : les 11 paires à source `detecte` / `confirme` / `faux_positif` sont inaccessibles en base (contrainte `CHECK`) et refusées par le store mémoire | [database.py:92](https://github.com/Cezar277/heimdall/blob/30201593c50a869492c8dd0cc9811acbb20c9c95/heimdall/vault/database.py#L92) (`PERSISTED_STATUSES`), [database.py:189](https://github.com/Cezar277/heimdall/blob/30201593c50a869492c8dd0cc9811acbb20c9c95/heimdall/vault/database.py#L189) (`CHECK(status IN ('vaulte','rote'))`) | `::TestForbiddenTransitionStore::test_sqlite_check_constraint_blocks_non_persistable_source_states`, `::test_memory_store_never_leaves_a_non_persistable_state` | Réussi |
| **L'API HTTP refuse chaque transition interdite atteignable** : 400 contractuel statique, `no-store`, sans reflet de l'entrée, sans effet de bord (état et journal inchangés) | [app.py:1739-1807](https://github.com/Cezar277/heimdall/blob/30201593c50a869492c8dd0cc9811acbb20c9c95/heimdall/vault/app.py#L1739-L1807) (route `POST /api/v1/secrets/{project}/{env}/{name}/transition`), [test_vault_transitions_forbidden.py:485-576](https://github.com/Cezar277/heimdall/blob/30201593c50a869492c8dd0cc9811acbb20c9c95/tests/test_vault_transitions_forbidden.py#L485-L580) | `::TestForbiddenTransitionApi::test_forbidden_transition_is_refused_without_side_effect` (9 paires × 2 backends = 18 cas), `::test_refused_transition_keeps_the_secret_readable` (18 cas) | Réussi (36/36) |
| **Le client ne peut pas forger l'état source** : l'état de départ est toujours relu côté serveur, un champ supplémentaire est refusé | [app.py:469-479](https://github.com/Cezar277/heimdall/blob/30201593c50a869492c8dd0cc9811acbb20c9c95/heimdall/vault/app.py#L469-L479) (`SecretTransitionRequest`, `extra="forbid"`) | `::TestForbiddenTransitionApi::test_client_cannot_forge_the_source_state` | Réussi |
| **Fail-closed sur état inconnu** : état cible ou source inconnu refusé, jamais reflété | [transitions.py:188-196](https://github.com/Cezar277/heimdall/blob/30201593c50a869492c8dd0cc9811acbb20c9c95/heimdall/vault/transitions.py#L188-L196) (`UnknownStateError`), [transitions.py:210-230](https://github.com/Cezar277/heimdall/blob/30201593c50a869492c8dd0cc9811acbb20c9c95/heimdall/vault/transitions.py#L210-L230) (`canonicalize_state`), [transitions.py:241-254](https://github.com/Cezar277/heimdall/blob/30201593c50a869492c8dd0cc9811acbb20c9c95/heimdall/vault/transitions.py#L241-L254) (`is_transition_allowed`) | `::TestForbiddenTransitionMatrix::test_unknown_state_fails_closed`, `::test_public_predicates_are_fail_closed_on_unknown_states`, `::TestForbiddenTransitionApi::test_unknown_target_state_is_refused` | Réussi |
| **Invariant 8 — aucun secret ni entrée brute dans les erreurs** | [transitions.py:188-207](https://github.com/Cezar277/heimdall/blob/30201593c50a869492c8dd0cc9811acbb20c9c95/heimdall/vault/transitions.py#L188-L207) (messages statiques, `UnknownStateError` sans argument) | `::TestForbiddenTransitionMatrix::test_error_message_never_reflects_a_secret`, `::test_forbidden_reason_is_deterministic` | Réussi |
| **Scénarios d'attaque nommés** (audit croisé / pentest) : déclasser un secret vaulté, reclasser un secret compromis en faux positif, court-circuiter la validation humaine, ressusciter une version révoquée, rejouer une écriture réflexive | [test_vault_transitions_forbidden.py:583-626](https://github.com/Cezar277/heimdall/blob/30201593c50a869492c8dd0cc9811acbb20c9c95/tests/test_vault_transitions_forbidden.py#L588-L630) | `::TestForbiddenTransitionAttackScenarios` (5 scénarios : `test_unvaulting_a_secret_to_hide_it_is_refused`, `test_relabelling_a_vaulted_secret_as_false_positive_is_refused`, `test_rotating_without_confirmation_is_refused`, `test_resurrecting_a_rotated_secret_is_refused`, `test_reflexive_transition_cannot_rewrite_the_journal`) | Réussi (5/5) |
| **Un refus est tracé (rebut) sans fuite** : l'audit conserve la tentative, jamais la valeur ni la clé brute | [app.py:1739-1807](https://github.com/Cezar277/heimdall/blob/30201593c50a869492c8dd0cc9811acbb20c9c95/heimdall/vault/app.py#L1739-L1807) (route journalisée par le middleware d'audit) | `::TestForbiddenTransitionApi::test_refused_transition_is_audited_without_leaking` | Réussi |
| **Couverture de la machine d'états à 100 %**, vérifiée *mécaniquement* (instructions **et** branches), et non seulement constatée dans un rapport | [test_vault_transitions_forbidden.py:633-709](https://github.com/Cezar277/heimdall/blob/30201593c50a869492c8dd0cc9811acbb20c9c95/tests/test_vault_transitions_forbidden.py#L638-L714) (pilote `_exhaust_state_machine` + mesure `coverage` en processus, `data_file=None`) | `::TestStateMachineCoverage::test_state_machine_module_is_fully_covered` | Réussi (100 %, 0 ligne et 0 branche manquantes) |

## 2. Checklist du ticket

- [x] **Test paramétré sur toutes les paires (état de départ, état d'arrivée) non autorisées** : les 20 paires
  interdites de la matrice 5x5 sont passées au banc d'essai, une par une, au niveau de la machine d'états
  (`@pytest.mark.parametrize` sur les 25 couples, filtre sur les 20 interdits).
- [x] **Erreur attendue pour chacune** : `InvalidTransitionError` porte l'état source, l'état cible et la
  justification formelle de la table `FORBIDDEN_TRANSITION_REASONS`.
- [x] **Les 5 transitions autorisées passent** : la preuve ne se contente pas de tout bloquer.
- [x] **Preuve au niveau opérationnel** : les stores (mémoire et SQLite) et l'API HTTP appliquent la même règle —
  un refus ne mute ni l'état ni le journal et retourne 400 sans|reflet.
- [x] **Couverture de la machine d'états à 100 %** : mesurée par l'outil (`--cov-branch`), contrôlée par un test
  (échec dès qu'une instruction ou une branche du module n'est plus exercée).
- [x] **Aucun secret réel** : le canari est un placeholder factice ; les messages d'erreur vérifiés sans
  reflet d'entrée (invariant 8).
- [x] **Aucun test existant modifié** : la suite #118 est un fichier dédié (`tests/test_vault_transitions_forbidden.py`).

## 3. Preuve à garder pour le rapport

Exécution de la suite dédiée #118 :

```sh
.venv/bin/python -m pytest tests/test_vault_transitions_forbidden.py -o addopts="" -q
```

```text
........................................................................ [ 51%]
....................................................................     [100%]
140 passed in 5.91s
```

Couverture de la machine d'états produite par cette suite seule :

```sh
.venv/bin/python -m pytest tests/test_vault_transitions_forbidden.py -o addopts="" -q \
  --cov=heimdall.vault.transitions --cov-branch --cov-report=term-missing
```

```text
Name                            Stmts   Miss Branch BrPart  Cover   Missing
---------------------------------------------------------------------------
heimdall/vault/transitions.py      65      0      8      0   100%
---------------------------------------------------------------------------
TOTAL                              65      0      8      0   100%
140 passed in 5.91s
```

Exécution conjointe avec les briques #115 et #117 (non-régression) :

```sh
.venv/bin/python -m pytest tests/test_vault_transitions.py tests/test_vault_transitions_api.py \
  tests/test_vault_transitions_forbidden.py -o addopts="" -q
```

```text
220 passed
```

Contrôles statiques :

```sh
.venv/bin/ruff check heimdall tests scripts     # All checks passed!
.venv/bin/ruff format --check tests/test_vault_transitions_forbidden.py
.venv/bin/mypy heimdall tests/contracts/fastapi_contract_fixture.py
                                              # Success: no issues found in 56 source files
.venv/bin/bandit -r heimdall -q                 # Aucun problème de sécurité détecté
```

## 4. STRIDE et invariants

| Menace / exigence | Traitement | Preuve |
|---|---|---|
| **Tampering** — déclasser un secret vaulté (`vaulte -> detecte`) pour le soustraire au scan | `validate_transition()` est appelé sur l'état réellement persisté ; la régression arrière est interdite avec justification formelle | `::TestForbiddenTransitionMatrix::test_forbidden_transition_raises_with_the_formal_reason`, `::TestForbiddenTransitionAttackScenarios::test_unvaulting_a_secret_to_hide_it_is_refused` |
| **Tampering** — court-circuiter la validation humaine (`detecte -> rote`) ou le passage par le Vault (`detecte -> vaulte`) | Ces deux sauts d'étape sont des paires interdites de la matrice, testées nommément | `::TestForbiddenTransitionMatrix::test_skipping_a_step_is_refused` |
| **Tampering** — reclasser un secret compromis en faux positif (`vaulte -> faux_positif`) | Interdiction formelle (pollution du Vault et de l'audit) | `::TestForbiddenTransitionAttackScenarios::test_relabelling_a_vaulted_secret_as_false_positive_is_refused` |
| **Tampering** — réécrire l'historique par une transition réflexive (`vaulte -> vaulte`) | Transition réflexive refusée par la matrice, journal inchangé | `::TestForbiddenTransitionMatrix::test_reflexive_transition_is_refused`, `::TestForbiddenTransitionAttackScenarios::test_reflexive_transition_cannot_rewrite_the_journal` |
| **Tampering / Elevation of Privilege** — ressusciter une version révoquée (`rote -> vaulte`) | `rote` est terminal : aucune transition sortante | `::TestForbiddenTransitionAttackScenarios::test_resurrecting_a_rotated_secret_is_refused` |
| **Spoofing** — forger l'état de départ pourchoisir une transition permise | L'état source est relu côté serveur ; le corps strict refuse tout champ supplémentaire | `::TestForbiddenTransitionApi::test_client_cannot_forge_the_source_state` |
| **Repudiation** — un refus doit rester traçable | Le middleware d'audit journalise la tentative (`outcome` `rejected`) et la cible, sans valeur ni clé brute | `::TestForbiddenTransitionApi::test_refused_transition_is_audited_without_leaking` |
| **Information Disclosure** — fuite de la valeur du secret dans une réponse d'erreur | Réponses 400 statiques du contrat ; la valeur canari n'apparaît ni dans la réponse ni dans l'audit | `::TestForbiddenTransitionApi::test_refused_transition_keeps_the_secret_readable`, `::test_refused_transition_is_audited_without_leaking`, `::TestForbiddenTransitionMatrix::test_error_message_never_reflects_a_secret` |
| **Denial of Service** — un refus ne doit pas consommer de ressources ni désynchroniser l'état | Le refus est treatmenté avant toute écriture : état et journal inchangés, secret toujours lisible | `::TestForbiddenTransitionStore::test_memory_store_applies_the_matrix_without_side_effect`, `::TestForbiddenTransitionApi::test_forbidden_transition_is_refused_without_side_effect` |
| **Invariant 1** — état et journal désynchronisés | Un refus n'écrit rien dans le journal ni dans l'état (les deux backends) | `::TestForbiddenTransitionStore::test_sqlite_store_applies_the_matrix_without_side_effect` |
| **Invariant 8** — reflet d'entrée ou de secret dans les erreurs | Messages statiques ; `UnknownStateError` sans paramètre ; justification formelle sans donnée sensible | `::TestForbiddenTransitionMatrix::test_unknown_state_fails_closed`, `::test_every_forbidden_reason_is_a_static_non_empty_justification` |
| **Fail-closed** — état inconnu, table de justifications incomplète, table altérée à l'exécution | État inconnu refusé partout ; la table des raisons couvre exactement les 20 paires interdites ; les tables sont des `MappingProxyType` immuables | `::TestTransitionMatrixIntegrity::test_forbidden_reason_table_covers_exactly_the_forbidden_pairs`, `::test_transition_tables_cannot_be_altered_at_runtime`, `::TestForbiddenTransitionMatrix::test_public_predicates_are_fail_closed_on_unknown_states` |

## 5. Résultats locaux

Environnement : Linux, Python 3.14.6, venv local (`.venv`).

```sh
.venv/bin/python -m pytest tests/test_vault_transitions_forbidden.py -o addopts="" -q
# 140 passed

.venv/bin/python -m pytest tests/test_vault_transitions.py tests/test_vault_transitions_api.py \
  tests/test_vault_transitions_forbidden.py -o addopts="" -q
# 220 passed

.venv/bin/python -m pytest --cov=heimdall --cov-branch --cov-fail-under=85
# 3731 passed, 16 skipped, 6829 subtests passed in 451.15s
# Required test coverage of 85% reached. Total coverage: 89.07%
# heimdall/vault/* : 90 % (seuil CI 70 %) ; heimdall/scanner/* : 91 % (seuil 70 %)
# heimdall/mcp/* : 97 % (seuil 70 %) ; heimdall/vault/transitions.py : 100 %

.venv/bin/ruff check heimdall tests scripts
# All checks passed!

.venv/bin/mypy heimdall tests/contracts/fastapi_contract_fixture.py
# Success: no issues found in 56 source files

.venv/bin/bandit -r heimdall -q
# Aucun problème de sécurité détecté
```

## 6. Re-pin après fusion

Comme toute preuve par permalien, les liens sont épinglés sur la révision
`30201593c50a869492c8dd0cc9811acbb20c9c95`. Si la fusion est un *squash*
(cette révision disparaît alors de l'historique de `main`), re-pinner
mécaniquement la fiche :

```sh
.venv/bin/python scripts/repin_samm.py --fiche docs/t118-samm.md --sha <sha-final>
.venv/bin/python scripts/repin_samm.py --fiche docs/t118-samm.md --check
```

Révisions à re-pinner après la fusion : `30201593c50a869492c8dd0cc9811acbb20c9c95`.

## 7. Corrections issues de la revue (APPROVE WITH COMMENTS)

| Remarque | Correctif | Preuve |
|---|---|---|
| **[LOW] PR empilée : le diff contre `main` embarquait le chemin opérationnel #117**, alors que la description annonçait « aucun code de production modifié » | La branche #118 est rebasée sur `117-t403-api-de-transition` (`e8f63eb`) : fast-forward strict, **sans commit de fusion avec `main`**. La **base de la PR est la branche #117**, et le diff de la PR ne contient plus que les 5 fichiers #118 (885 insertions, aucun fichier de production). | § « Base de la PR » ci-dessus ; `git diff --stat origin/117-t403-api-de-transition..HEAD` |
| **[LOW] Assertion de non-reflet fragile en sous-chaîne** (`assert target not in response.text`) : les noms d'état sont des mots courts qu'une recherche sur la réponse entière confond avec un autre mot (« rote » dans « protégé ») | Le non-reflet de l'état demandé est mesuré sur le **corps JSON** (`target not in json.dumps(response.json())`). La garantie principale reste l'**égalité stricte** au payload contractuel `{"code": "bad_request", "message": "Requête invalide"}`. Le canari, jeton unique, reste cherché dans toute la réponse, en-têtes compris. | `::TestForbiddenTransitionApi::test_forbidden_transition_is_refused_without_side_effect` (18 cas), `::test_unknown_target_state_is_refused` |
| **[Tests manquants signalés]** — cible hostile de type secret en API, acteur `\n`/SQL : **hors périmètre de #118**, à traiter dans #117 | Non ajoutés ici (la revue l'exclut explicitement du périmètre de #118) ; le point est à porter sur #117. | — |

Vérification que la suite détecte une vraie régression (mutation test, non commité) :
neutraliser `validate_transition()` (la matrice ne refuse plus rien) fait **échouer 66 tests** de la
suite #118 ; faire refléter l'état demandé dans le payload d'erreur 400 fait **échouer les 18 cas**
du test API. Les assertions ne sont donc pas vacantes.

Temps passé reporté sur le ticket : `Temps: 2h00`.
