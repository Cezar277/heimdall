# T118 — preuves pour la ligne SAMM (tests des transitions interdites)

Sous-ticket **T404** (ticket GitHub **#118**) du grand ticket
`#40 « États du secret dans le Vault »`, branche
`118-t404-tests-des-transitions-interdites` (PR GitHub
**[#225](https://github.com/Cezar277/heimdall/pull/225)**). Cette fiche fournit
les couples **module + ligne** et les tests qui prouvent la checklist du
ticket ; elle ne remplace pas la revue de code.

> **Permaliens** : les liens ci-dessous sont épinglés sur la révision
> [`14ab58f`](https://github.com/Cezar277/heimdall/commit/14ab58fe1472898b7f8a546cd5ef797295b5fb22),
> qui contient la suite de tests exhaustive des transitions interdites, son pin
> direct de `coverage` et le correctif de la remarque LOW de revue (version
> revue). Les plages de lignes des modules déjà livrés (#115, #117) sont celles
> de cette révision.
>
> **Base de la PR** : la preuve porte sur le chemin *opérationnel* (route HTTP
> + stores du Vault), introduit par le sous-ticket #117 (§8 de l'ADR-006). La
> branche #118 est donc empilée sur `117-t403-api-de-transition` : elle en est
> un **fast-forward strict** jusqu'à `e8f63eb`, puis un **unique commit de
> fusion** avec la branche #117 (`4a49890`, tests uniquement) — **aucun commit
> de fusion avec `main`**, aucune divergence d'historique. La **base de la PR
> [#225](https://github.com/Cezar277/heimdall/pull/225) est la branche #117** —
> le diff affiché par GitHub (base commune = tête de la branche #117) ne
> contient donc que les fichiers #118 :
>
> ```text
> $ git diff --name-only "$(git merge-base origin/117-t403-api-de-transition HEAD)"..HEAD
> README.md
> docs/adr/006-table-etats-et-transitions.md
> docs/contracts/vault-traceability.md
> docs/t118-samm.md
> pyproject.toml
> requirements.lock
> tests/security/test_ci_workflow_static.py
> tests/test_vault_transitions_forbidden.py
> ```
>
> Le commit de fusion avec #117 n'apporte que les **tests** de cible et
> d'acteur hostiles (`4a49890`) : il appartient à #117, n'est pas dans le diff
> de #118 et ne modifie aucun fichier de production.
>
> Aucun fichier de production n'est modifié par #118 : ni `heimdall/**`,
> ni `openapi.yaml`, ni `schemas/**`. Le diff contre `main` contient en plus
> #117, qui doit être fusionné en amont (le mainteneur est le seul habilité à
> merger, cf. CONTRIBUTING §6). **Après** le merge de #117 dans `main`, la
> branche #118 est rebasée sur `main` et la base de la PR rebascule sur `main` :
> le diff reste identique (les 8 fichiers ci-dessus), la PR redevient
> mergeable dans `main` sans base empilée.
>
> `pyproject.toml` et `requirements.lock` ne sont pas du code de production :
> ils ne portent que la **déclaration directe et épinglée de `coverage`**, dont
> la suite #118 fait l'`import` (correctif de la remarque LOW de revue, § 7).
> `tests/security/test_ci_workflow_static.py` n'est modifié que pour que la
> garde existante « pins directs `pyproject.toml` == pins du lock » accepte les
> extras PEP 508 (`coverage[toml]`) : son exigence — même version des deux
> côtés — est inchangée et même renforcée (§ 7).

## 1. Exigences du ticket et preuves

| Exigence vérifiée | Implémentation (module + ligne) | Test et preuve permanente | Résultat local |
|---|---|---|---|
| **Toutes les transitions interdites sont refusées** : test paramétré sur les 25 couples (état de départ, état d'arrivée), dont les **20 interdits** de la matrice 5x5 | [transitions.py:256-274](https://github.com/Cezar277/heimdall/blob/14ab58fe1472898b7f8a546cd5ef797295b5fb22/heimdall/vault/transitions.py#L256-L274) (`validate_transition`), [transitions.py:93-95](https://github.com/Cezar277/heimdall/blob/14ab58fe1472898b7f8a546cd5ef797295b5fb22/heimdall/vault/transitions.py#L93-L95) (`ALLOWED_TRANSITIONS`), [test_vault_transitions_forbidden.py:167-267](https://github.com/Cezar277/heimdall/blob/14ab58fe1472898b7f8a546cd5ef797295b5fb22/tests/test_vault_transitions_forbidden.py#L167-L266) | `tests/test_vault_transitions_forbidden.py::TestForbiddenTransitionMatrix::test_forbidden_transition_raises_with_the_formal_reason` (20 cas paramétrés, un par paire interdite) | Réussi (20/20 refusés avec la justification formelle) |
| **Les transitions autorisées restent acceptées** : la preuve ne bloque pas tout (5 paires) | [transitions.py:93-95](https://github.com/Cezar277/heimdall/blob/14ab58fe1472898b7f8a546cd5ef797295b5fb22/heimdall/vault/transitions.py#L93-L95) | `::TestForbiddenTransitionMatrix::test_allowed_transition_is_accepted` (5 cas) | Réussi |
| **La table des justifications est complète et exclusive** : une justification pour chaque paire interdite, aucune pour une paire autorisée | [transitions.py:179-181](https://github.com/Cezar277/heimdall/blob/14ab58fe1472898b7f8a546cd5ef797295b5fb22/heimdall/vault/transitions.py#L179-L181) (`FORBIDDEN_TRANSITION_REASONS`) | `::TestTransitionMatrixIntegrity::test_forbidden_reason_table_covers_exactly_the_forbidden_pairs`, `::test_matrix_partitions_the_25_ordered_pairs` | Réussi |
| **Un refus ne mute ni l'état ni le journal** (backend mémoire, 25 paires testées) | [store.py:259-331](https://github.com/Cezar277/heimdall/blob/14ab58fe1472898b7f8a546cd5ef797295b5fb22/heimdall/vault/store.py#L259-L331) (`InMemorySecretStore.transition`) | `::TestForbiddenTransitionStore::test_memory_store_applies_the_matrix_without_side_effect` (25 cas) | Réussi (25/25) |
| **Un refus ne mute ni l'état ni le journal** (backend SQLite, backend de production) | [store.py:632-678](https://github.com/Cezar277/heimdall/blob/14ab58fe1472898b7f8a546cd5ef797295b5fb22/heimdall/vault/store.py#L632-L678) (`SqliteSecretStore.transition`), [database.py:1920-1992](https://github.com/Cezar277/heimdall/blob/14ab58fe1472898b7f8a546cd5ef797295b5fb22/heimdall/vault/database.py#L1920-L1992) (`transition_secret`) | `::TestForbiddenTransitionStore::test_sqlite_store_applies_the_matrix_without_side_effect` (10 cas) | Réussi (10/10) |
| **Un état source non persistable ne peut pas quitter le Vault** : les 11 paires à source `detecte` / `confirme` / `faux_positif` sont inaccessibles en base (contrainte `CHECK`) et refusées par le store mémoire | [database.py:92](https://github.com/Cezar277/heimdall/blob/14ab58fe1472898b7f8a546cd5ef797295b5fb22/heimdall/vault/database.py#L92) (`PERSISTED_STATUSES`), [database.py:189](https://github.com/Cezar277/heimdall/blob/14ab58fe1472898b7f8a546cd5ef797295b5fb22/heimdall/vault/database.py#L189) (`CHECK(status IN ('vaulte','rote'))`) | `::TestForbiddenTransitionStore::test_sqlite_check_constraint_blocks_non_persistable_source_states`, `::test_memory_store_never_leaves_a_non_persistable_state` | Réussi |
| **L'API HTTP refuse chaque transition interdite atteignable** : 400 contractuel statique, `no-store`, sans reflet de l'entrée, sans effet de bord (état et journal inchangés) | [app.py:1739-1807](https://github.com/Cezar277/heimdall/blob/14ab58fe1472898b7f8a546cd5ef797295b5fb22/heimdall/vault/app.py#L1739-L1807) (route `POST /api/v1/secrets/{project}/{env}/{name}/transition`), [test_vault_transitions_forbidden.py:491-582](https://github.com/Cezar277/heimdall/blob/14ab58fe1472898b7f8a546cd5ef797295b5fb22/tests/test_vault_transitions_forbidden.py#L491-L586) | `::TestForbiddenTransitionApi::test_forbidden_transition_is_refused_without_side_effect` (9 paires × 2 backends = 18 cas), `::test_refused_transition_keeps_the_secret_readable` (18 cas) | Réussi (36/36) |
| **Le client ne peut pas forger l'état source** : l'état de départ est toujours relu côté serveur, un champ supplémentaire est refusé | [app.py:469-479](https://github.com/Cezar277/heimdall/blob/14ab58fe1472898b7f8a546cd5ef797295b5fb22/heimdall/vault/app.py#L469-L479) (`SecretTransitionRequest`, `extra="forbid"`) | `::TestForbiddenTransitionApi::test_client_cannot_forge_the_source_state` | Réussi |
| **Fail-closed sur état inconnu** : état cible ou source inconnu refusé, jamais reflété | [transitions.py:188-196](https://github.com/Cezar277/heimdall/blob/14ab58fe1472898b7f8a546cd5ef797295b5fb22/heimdall/vault/transitions.py#L188-L196) (`UnknownStateError`), [transitions.py:210-230](https://github.com/Cezar277/heimdall/blob/14ab58fe1472898b7f8a546cd5ef797295b5fb22/heimdall/vault/transitions.py#L210-L230) (`canonicalize_state`), [transitions.py:241-254](https://github.com/Cezar277/heimdall/blob/14ab58fe1472898b7f8a546cd5ef797295b5fb22/heimdall/vault/transitions.py#L241-L254) (`is_transition_allowed`) | `::TestForbiddenTransitionMatrix::test_unknown_state_fails_closed`, `::test_public_predicates_are_fail_closed_on_unknown_states`, `::TestForbiddenTransitionApi::test_unknown_target_state_is_refused` | Réussi |
| **Invariant 8 — aucun secret ni entrée brute dans les erreurs** | [transitions.py:188-207](https://github.com/Cezar277/heimdall/blob/14ab58fe1472898b7f8a546cd5ef797295b5fb22/heimdall/vault/transitions.py#L188-L207) (messages statiques, `UnknownStateError` sans argument) | `::TestForbiddenTransitionMatrix::test_error_message_never_reflects_a_secret`, `::test_forbidden_reason_is_deterministic` | Réussi |
| **Scénarios d'attaque nommés** (audit croisé / pentest) : déclasser un secret vaulté, reclasser un secret compromis en faux positif, court-circuiter la validation humaine, ressusciter une version révoquée, rejouer une écriture réflexive | [test_vault_transitions_forbidden.py:589-632](https://github.com/Cezar277/heimdall/blob/14ab58fe1472898b7f8a546cd5ef797295b5fb22/tests/test_vault_transitions_forbidden.py#L594-L636) | `::TestForbiddenTransitionAttackScenarios` (5 scénarios : `test_unvaulting_a_secret_to_hide_it_is_refused`, `test_relabelling_a_vaulted_secret_as_false_positive_is_refused`, `test_rotating_without_confirmation_is_refused`, `test_resurrecting_a_rotated_secret_is_refused`, `test_reflexive_transition_cannot_rewrite_the_journal`) | Réussi (5/5) |
| **Un refus est tracé (rebut) sans fuite** : l'audit conserve la tentative, jamais la valeur ni la clé brute | [app.py:1739-1807](https://github.com/Cezar277/heimdall/blob/14ab58fe1472898b7f8a546cd5ef797295b5fb22/heimdall/vault/app.py#L1739-L1807) (route journalisée par le middleware d'audit) | `::TestForbiddenTransitionApi::test_refused_transition_is_audited_without_leaking` | Réussi |
| **Couverture de la machine d'états à 100 %**, vérifiée *mécaniquement* (instructions **et** branches), et non seulement constatée dans un rapport | [test_vault_transitions_forbidden.py:639-715](https://github.com/Cezar277/heimdall/blob/14ab58fe1472898b7f8a546cd5ef797295b5fb22/tests/test_vault_transitions_forbidden.py#L644-L720) (pilote `_exhaust_state_machine` + mesure `coverage` en processus, `data_file=None`) | `::TestStateMachineCoverage::test_state_machine_module_is_fully_covered` | Réussi (100 %, 0 ligne et 0 branche manquantes) |
| **L'outil de mesure est déclaré et épinglé** : la preuve « 100 % » est reproductible à l'identique — `coverage` est une dépendance **directe** (et non seulement transitive via `pytest-cov`), avec un pin exact identique dans `pyproject.toml` et dans le lock installé par la CI, et c'est bien cette version qui mesure | [pyproject.toml:46-51](https://github.com/Cezar277/heimdall/blob/14ab58fe1472898b7f8a546cd5ef797295b5fb22/pyproject.toml#L46-L51) (dépendance directe `coverage[toml]==7.16.2`), [requirements.lock:450-573](https://github.com/Cezar277/heimdall/blob/14ab58fe1472898b7f8a546cd5ef797295b5fb22/requirements.lock#L450-L573) (même pin, hashes SHA-256), [test_vault_transitions_forbidden.py:728-768](https://github.com/Cezar277/heimdall/blob/14ab58fe1472898b7f8a546cd5ef797295b5fb22/tests/test_vault_transitions_forbidden.py#L728-L768) (`TestCoverageToolPinning`) | `::TestCoverageToolPinning::test_coverage_is_a_pinned_direct_dev_dependency` | Réussi |

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
- [x] **L'outil de mesure est déclaré et épinglé** : `coverage` est une dépendance directe de dev avec un pin exact
  (identique dans `pyproject.toml` et dans le lock installé par la CI) ; la preuve « 100 % » est donc reproductible
  à l'identique et ne peut pas dériver de version.
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
.....................................................................    [100%]
141 passed in 6.80s
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
141 passed in 6.08s
```

Exécution conjointe avec les briques #115 et #117 (non-régression) :

```sh
.venv/bin/python -m pytest tests/test_vault_transitions.py tests/test_vault_transitions_api.py \
  tests/test_vault_transitions_forbidden.py -o addopts="" -q
```

```text
233 passed, 81 subtests passed in 12.24s
```

> Le décompte est désormais **233 + 81 sous-tests** (26 pour #115, 66 pour #117, 141 pour #118) : le
> « 220 » qui figurait dans la version revue de cette fiche était antérieur au commit de
> fusion avec #117 (`4a49890`) et ne comptait pas les sous-tests.

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
# 141 passed

.venv/bin/python -m pytest tests/test_vault_transitions.py tests/test_vault_transitions_api.py \
  tests/test_vault_transitions_forbidden.py -o addopts="" -q
# 233 passed, 81 subtests passed

.venv/bin/python -m pytest --cov=heimdall --cov-branch --cov-fail-under=85
# 3731 passed, 16 skipped, 6833 subtests passed in 427.41s
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
`14ab58fe1472898b7f8a546cd5ef797295b5fb22`. Si la fusion est un *squash*
(cette révision disparaît alors de l'historique de `main`), re-pinner
mécaniquement la fiche :

```sh
.venv/bin/python scripts/repin_samm.py --fiche docs/t118-samm.md --sha <sha-final>
.venv/bin/python scripts/repin_samm.py --fiche docs/t118-samm.md --check
```

Révisions à re-pinner après la fusion : `14ab58fe1472898b7f8a546cd5ef797295b5fb22`.

## 7. Corrections issues des revues successives (APPROVE WITH COMMENTS → APPROVE)

| Remarque | Correctif | Preuve |
|---|---|---|
| **[LOW] PR empilée : le diff contre `main` embarquait le chemin opérationnel #117**, alors que la description annonçait « aucun code de production modifié » | La **base de la PR #225 est la branche #117** (`117-t403-api-de-transition`) : le diff affiché par GitHub part de la base commune et ne contient plus que les 8 fichiers #118, aucun fichier de production (ni `heimdall/**`, ni `openapi.yaml`, ni `schemas/**`). La branche #118 est un fast-forward strict de `e8f63eb` puis un unique commit de fusion avec #117 (`4a49890`, tests uniquement), **sans commit de fusion avec `main`**. | § « Base de la PR » ci-dessus ; `git diff --name-only "$(git merge-base origin/117-t403-api-de-transition HEAD)"..HEAD` |
| **[LOW] Assertion de non-reflet fragile en sous-chaîne** (`assert target not in response.text`) : les noms d'état sont des mots courts qu'une recherche sur la réponse entière confond avec un autre mot (« rote » dans « protégé ») | Le non-reflet de l'état demandé est mesuré sur le **corps JSON** (`target not in json.dumps(response.json())`). La garantie principale reste l'**égalité stricte** au payload contractuel `{"code": "bad_request", "message": "Requête invalide"}`. Le canari, jeton unique, reste cherché dans toute la réponse, en-têtes compris. | `::TestForbiddenTransitionApi::test_forbidden_transition_is_refused_without_side_effect` (18 cas), `::test_unknown_target_state_is_refused` |
| **[LOW] Import direct `coverage` sans dépendance directe épinglée** : la suite #118 importe `coverage` (mesure in-process, `data_file=None`) alors que `pyproject.toml` n'épinglait que `pytest-cov` — le paquet ne résolvait donc que transitivement, version susceptible de dériver et preuve « 100 % » non reproductible à l'identique | **Option retenue : épingler la dépendance**, pas remplacer la mesure — la mesure in-process reste ce qui fait *échouer un test* quand une instruction ou une branche du module n'est plus exercée (DoD § 2) ; la mesure `--cov` documentée en § 3 ne le ferait pas. `coverage` est donc déclaré **directement** en dépendance de dev, avec un pin exact `coverage[toml]==7.16.2` (satisfait `coverage[toml]>=7.10.6` exigé par `pytest-cov==7.1.0`), identique dans `pyproject.toml` et dans `requirements.lock` installé par la CI. Une garde `TestCoverageToolPinning` vérifie les trois points (déclaration directe à pin exact, pin identique dans le lock, version installée égale au pin) : la dérive de version échoue désormais la suite au lieu de passer inaperçue. La garde existante `tests/security/test_ci_workflow_static.py::test_pins_directs_pyproject_synchronises_avec_le_lock` (« pins directs `pyproject.toml` == pins du lock ») a été rendue **consciente des extras PEP 508** (`coverage[toml]`) : son exigence est inchangée — même version des deux côtés — et elle porte désormais aussi le nouveau pin. | [pyproject.toml:46-51](https://github.com/Cezar277/heimdall/blob/14ab58fe1472898b7f8a546cd5ef797295b5fb22/pyproject.toml#L46-L51), [requirements.lock:450-573](https://github.com/Cezar277/heimdall/blob/14ab58fe1472898b7f8a546cd5ef797295b5fb22/requirements.lock#L450-L573), `::TestCoverageToolPinning::test_coverage_is_a_pinned_direct_dev_dependency`, `tests/security/test_ci_workflow_static.py::test_pins_directs_pyproject_synchronises_avec_le_lock` |
| **[Tests manquants signalés]** — cible hostile de type secret en API, acteur `\n`/SQL : **hors périmètre de #118**, à traiter dans #117 | Non ajoutés ici (la revue l'exclut explicitement du périmètre de #118) ; **traités dans #117** (commit `4a49890`) : `tests/test_vault_transitions_api.py::test_hostile_target_status_is_400_static_without_reflection` (4 cibles × 2 backends) et `::test_hostile_actor_is_normalized_to_unknown_and_never_persisted` (4 acteurs). Aucun code de production modifié. | § 6 de `docs/t117-samm.md` |

Vérification que la suite détecte une vraie régression (mutation test, non commité) :
neutraliser `validate_transition()` (la matrice ne refuse plus rien) fait **échouer 66 tests** de la
suite #118 ; faire refléter l'état demandé dans le payload d'erreur 400 fait **échouer les 18 cas**
du test API. La garde `TestCoverageToolPinning` n'est pas vacante non plus : retirer la déclaration
directe de `coverage` de `pyproject.toml`, dériver le pin du lock ou installer une version de `coverage`
différente du pin fait **échouer son test**. Les assertions ne sont donc pas vacantes.

Temps passé reporté sur le ticket : `Temps: 2h00`.
