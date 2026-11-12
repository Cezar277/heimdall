# T117 — preuves pour la ligne SAMM (API de transition)

Sous-ticket **T403** (ticket GitHub **#117**) du grand ticket `#40 « États du secret dans le Vault »`,
branche `117-t403-api-de-transition`. Cette fiche fournit les couples **module + ligne** et les
tests qui prouvent la checklist ; elle ne remplace pas la revue de code.

## 1. Exigences du ticket et preuves

> **Permaliens** : les liens ci-dessous sont épinglés à la révision du code
> [`8d19101`](https://github.com/Cezar277/heimdall/commit/69439f9ae21006d7cabb7dc13e4a27f530bc2a71),
> qui contient la route de transition, l'application fail-closed de la matrice #115, le journal
> atomique `secret_transitions`, la rétention bornée et les tests des deux backends. La présente
> fiche est le commit de documentation associé.

| Exigence vérifiée | Implémentation (module + ligne) | Test et preuve permanente | Résultat local |
|---|---|---|---|
| **Route protégée par la même authentification que les autres routes Vault** : 401 sans clé valide, 403 pour un projet étranger, 404 pour un secret absent, décisions prises avant toute écriture | [app.py:1750-1760](https://github.com/Cezar277/heimdall/blob/69439f9ae21006d7cabb7dc13e4a27f530bc2a71/heimdall/vault/app.py#L1749-L1759) (décorateur et `require_project_access`), [app.py:1805-1809](https://github.com/Cezar277/heimdall/blob/69439f9ae21006d7cabb7dc13e4a27f530bc2a71/heimdall/vault/app.py#L1805-L1809) (404) | `tests/test_vault_transitions_api.py::test_authentication_and_project_isolation_precede_any_write`, `::test_missing_secret_is_404_and_creates_no_journal_entry` | Réussi |
| **Corps strict limité à l'état cible** : le client ne fournit jamais l'état source ; les champs supplémentaires sont refusés | [app.py:472-483](https://github.com/Cezar277/heimdall/blob/69439f9ae21006d7cabb7dc13e4a27f530bc2a71/heimdall/vault/app.py#L472-L483) (`SecretTransitionRequest`, `extra="forbid"`), [database.py:2039-2047](https://github.com/Cezar277/heimdall/blob/69439f9ae21006d7cabb7dc13e4a27f530bc2a71/heimdall/vault/database.py#L2039-L2047) (lecture de l'état réel en base) | `tests/test_vault_transitions_api.py::test_invalid_transition_body_is_400_without_reflection`, `::test_transition_uses_server_side_source_state` | Réussi |
| **Transition valide acceptée** : `vaulte -> rote`, réponse 200 `no-store` limitée aux métadonnées de transition | [app.py:1787-1817](https://github.com/Cezar277/heimdall/blob/69439f9ae21006d7cabb7dc13e4a27f530bc2a71/heimdall/vault/app.py#L1786-L1816), [database.py:2011-2081](https://github.com/Cezar277/heimdall/blob/69439f9ae21006d7cabb7dc13e4a27f530bc2a71/heimdall/vault/database.py#L2011-L2081), [openapi.yaml:258-321](https://github.com/Cezar277/heimdall/blob/69439f9ae21006d7cabb7dc13e4a27f530bc2a71/openapi.yaml#L258-L321) | `tests/test_vault_transitions_api.py::test_valid_transition_changes_state_and_returns_metadata_only` | Réussi |
| **Transitions interdites refusées selon la matrice #115** : réflexives, régressions, cibles non persistables et états inconnus retournent 400 statique, sans mutation ni entrée de journal | [database.py:2046-2054](https://github.com/Cezar277/heimdall/blob/69439f9ae21006d7cabb7dc13e4a27f530bc2a71/heimdall/vault/database.py#L2046-L2054) (`validate_transition`, `PERSISTED_STATUSES`), [store.py:288-339](https://github.com/Cezar277/heimdall/blob/69439f9ae21006d7cabb7dc13e4a27f530bc2a71/heimdall/vault/store.py#L288-L339) (backend mémoire), [store.py:1116-1157](https://github.com/Cezar277/heimdall/blob/69439f9ae21006d7cabb7dc13e4a27f530bc2a71/heimdall/vault/store.py#L1116-L1157) (backend SQLite) | `tests/test_vault_transitions_api.py::test_reflexive_and_forbidden_transitions_are_400_without_mutation`, `::test_invalid_transition_body_is_400_without_reflection`, `::test_rote_is_terminal` | Réussi |
| **Journal de chaque transition acceptée** : acteur, horodatage UTC, ancien état, nouvel état | [database.py:212-228](https://github.com/Cezar277/heimdall/blob/69439f9ae21006d7cabb7dc13e4a27f530bc2a71/heimdall/vault/database.py#L212-L228) (table et index), [database.py:2056-2071](https://github.com/Cezar277/heimdall/blob/69439f9ae21006d7cabb7dc13e4a27f530bc2a71/heimdall/vault/database.py#L2056-L2071) (horodatage et INSERT), [database.py:2084-2106](https://github.com/Cezar277/heimdall/blob/69439f9ae21006d7cabb7dc13e4a27f530bc2a71/heimdall/vault/database.py#L2084-L2106) (`list_secret_transitions`) | `tests/test_vault_transitions_api.py::test_transition_journal_contains_actor_timestamp_and_states` | Réussi |
| **Acteur non forgeable par le client** : identifiant interne `key_<32 hexadécimaux>` issu de la clé authentifiée, toute autre valeur remplacée par `unknown` | [app.py:1789-1797](https://github.com/Cezar277/heimdall/blob/69439f9ae21006d7cabb7dc13e4a27f530bc2a71/heimdall/vault/app.py#L1788-L1796) (`request.state.audit_key_id`), [database.py:1969-1979](https://github.com/Cezar277/heimdall/blob/69439f9ae21006d7cabb7dc13e4a27f530bc2a71/heimdall/vault/database.py#L1969-L1979) (`normalize_transition_actor`) | `tests/test_vault_transitions_api.py::test_actor_is_normalized_and_never_taken_from_request`, `::test_transition_journal_contains_actor_timestamp_and_states` | Réussi |
| **Atomicité état + journal** : UPDATE conditionnel et INSERT dans la même transaction `BEGIN IMMEDIATE` ; deux transitions concurrentes ne peuvent pas réussir toutes les deux | [database.py:2039-2071](https://github.com/Cezar277/heimdall/blob/69439f9ae21006d7cabb7dc13e4a27f530bc2a71/heimdall/vault/database.py#L2039-L2071), [database.py:134-135](https://github.com/Cezar277/heimdall/blob/69439f9ae21006d7cabb7dc13e4a27f530bc2a71/heimdall/vault/database.py#L134-L135) (`TransitionConcurrencyError`) | `tests/test_vault_transitions_api.py::test_concurrent_transitions_accept_exactly_one` | Réussi |
| **Aucune valeur, empreinte ou clé dans le journal ni dans la réponse HTTP** ; réponse sans acteur | [app.py:485-492](https://github.com/Cezar277/heimdall/blob/69439f9ae21006d7cabb7dc13e4a27f530bc2a71/heimdall/vault/app.py#L485-L493) (`SecretTransitionResult`), [app.py:1811-1817](https://github.com/Cezar277/heimdall/blob/69439f9ae21006d7cabb7dc13e4a27f530bc2a71/heimdall/vault/app.py#L1810-L1816), [database.py:2084-2106](https://github.com/Cezar277/heimdall/blob/69439f9ae21006d7cabb7dc13e4a27f530bc2a71/heimdall/vault/database.py#L2084-L2106) | `tests/test_vault_transitions_api.py::test_valid_transition_changes_state_and_returns_metadata_only`, `::test_sqlite_journal_never_contains_secret_value_or_fingerprint` | Réussi |
| **Après `rote`, l'ancienne valeur n'est plus restituée** : `GET` du secret retourne 404 ; `GET .../state` continue d'exposer `rote` sans valeur | [app.py:1673-1677](https://github.com/Cezar277/heimdall/blob/69439f9ae21006d7cabb7dc13e4a27f530bc2a71/heimdall/vault/app.py#L1673-L1677) (404 sur `rote`), [app.py:1690-1748](https://github.com/Cezar277/heimdall/blob/69439f9ae21006d7cabb7dc13e4a27f530bc2a71/heimdall/vault/app.py#L1690-L1748) (route `/state`) | `tests/test_vault_transitions_api.py::test_valid_transition_changes_state_and_returns_metadata_only` (assertions `/state` et 404) | Réussi |
| **Rétention bornée du journal** : au plus `MAX_SECRET_TRANSITIONS` (10 000) entrées les plus récentes, purge dans la transaction ; listage borné 1..1000 | [database.py:98-100](https://github.com/Cezar277/heimdall/blob/69439f9ae21006d7cabb7dc13e4a27f530bc2a71/heimdall/vault/database.py#L98-L100), [database.py:1982-2005](https://github.com/Cezar277/heimdall/blob/69439f9ae21006d7cabb7dc13e4a27f530bc2a71/heimdall/vault/database.py#L1982-L2005), [store.py:168](https://github.com/Cezar277/heimdall/blob/69439f9ae21006d7cabb7dc13e4a27f530bc2a71/heimdall/vault/store.py#L168) (`deque(maxlen=...)`) | `tests/test_vault_transitions_api.py::test_memory_journal_is_bounded`, `::test_sqlite_journal_is_bounded`, `::test_journal_listing_is_bounded` | Réussi |
| **Historique conservé après suppression du secret** (aucune clé étrangère vers `secrets`) | [database.py:212-228](https://github.com/Cezar277/heimdall/blob/69439f9ae21006d7cabb7dc13e4a27f530bc2a71/heimdall/vault/database.py#L212-L228) | `tests/test_vault_transitions_api.py::test_journal_survives_secret_deletion` | Réussi |
| **Contrat OpenAPI et non-régression** : nouvelle route et schémas distincts, `SecretStatus` non élargi, fixture de contrat alignée, runtime et contrat identiques | [openapi.yaml:258-321](https://github.com/Cezar277/heimdall/blob/69439f9ae21006d7cabb7dc13e4a27f530bc2a71/openapi.yaml#L258-L321), [openapi.yaml:540-567](https://github.com/Cezar277/heimdall/blob/69439f9ae21006d7cabb7dc13e4a27f530bc2a71/openapi.yaml#L540-L567) | `tests/contracts/test_vault_openapi.py` (110 tests de contrat avec les transitions), `tests/test_vault_integration_testclient.py` | Réussi |
| **Non-reflet des entrées et absence de secret réel dans le dépôt** : messages 400 statiques, valeur canari uniquement dans les tests | [app.py:1799-1810](https://github.com/Cezar277/heimdall/blob/69439f9ae21006d7cabb7dc13e4a27f530bc2a71/heimdall/vault/app.py#L1798-L1809) | `tests/test_vault_transitions_api.py::test_invalid_transition_body_is_400_without_reflection`, `::test_reflexive_and_forbidden_transitions_are_400_without_mutation`, `::test_valid_transition_changes_state_and_returns_metadata_only` | Réussi |

## 2. Checklist du ticket

- [x] **Route ajoutée au contrat** : `POST /api/v1/secrets/{project}/{env}/{name}/transition`, protégée par `require_project_access()` comme les autres routes Vault.
- [x] **État source côté serveur** : le corps strict ne porte que `target_status` ; l'état courant est relu dans le store ou en base avant validation.
- [x] **Matrice #115 appliquée fail-closed** : `validate_transition()` puis contrôle `PERSISTED_STATUSES` ; seule `vaulte -> rote` réussit, toute autre demande retourne 400 statique.
- [x] **Journal complet** : `occurred_at` UTC, acteur interne normalisé, `previous_status`, `new_status`, dans la même transaction que le changement d'état.
- [x] **Acteur non contrôlé par le client** : extrait de `request.state.audit_key_id` ; une valeur arbitraire devient `unknown` sans être persistée.
- [x] **Aucune donnée sensible** : ni valeur, ni empreinte, ni clé API dans la table, le journal mémoire ou la réponse HTTP.
- [x] **Rétention** : `MAX_SECRET_TRANSITIONS = 10 000`, purge atomique, listage borné 1..1000, `clear()` nettoie le journal.
- [x] **Terminalité et non-régression de lecture** : `rote` refuse toute transition ; `GET` du secret retourne 404, `GET .../state` reste disponible.
- [x] **Atomicité et concurrence** : compare-and-set sur l'ancien état sous `BEGIN IMMEDIATE`, journal et état indissociables ; un seul succès sur deux transitions concurrentes.
- [x] **Contrat et tests** : `openapi.yaml`, fixture de contrat, tests runtime et suite complète verts ; aucun test existant modifié en régression.

## 3. Preuve à garder pour le rapport

Exécution de la suite dédiée #117 (40 tests paramétrés mémoire/SQLite) :

```sh
.venv/bin/python -m pytest tests/test_vault_transitions_api.py -o addopts="" -q
```

Extrait du journal de test :

```text
........................................                                 [100%]
40 passed in 4.20s
```

Exécution conjointe des transitions et des contrats :

```sh
.venv/bin/python -m pytest tests/test_vault_transitions_api.py tests/contracts -o addopts="" -q
```

```text
..............................................................................................................               [100%]
110 passed, 5204 subtests passed in 6.74s
```

Contrôles statiques et contrat :

```sh
.venv/bin/ruff check heimdall tests
.venv/bin/mypy heimdall tests/contracts/fastapi_contract_fixture.py
./node_modules/.bin/spectral lint openapi.yaml --fail-severity warn
git diff --check
```

```text
All checks passed!
Success: no issues found in 52 source files
No results with a severity of 'warn' or higher found!
```

## 4. STRIDE et invariants

| Menace / exigence | Traitement | Preuve |
|---|---|---|
| **Spoofing** — Un client forge l'état source ou l'acteur | Le corps refuse tout champ supplémentaire et ne contient pas d'état source ; l'acteur vient exclusivement de la clé authentifiée (`audit_key_id`) puis est normalisé. | `::test_invalid_transition_body_is_400_without_reflection`, `::test_actor_is_normalized_and_never_taken_from_request` |
| **Tampering** — Transition interdite ou contournement de la matrice | `validate_transition()` est appelé sur l'état réellement persisté ; `PERSISTED_STATUSES` limite l'écriture à `vaulte`/`rote` ; l'UPDATE est conditionné à l'ancien état. | `::test_reflexive_and_forbidden_transitions_are_400_without_mutation`, `::test_concurrent_transitions_accept_exactly_one` |
| **Repudiation** — Transition non traçable | Chaque succès écrit acteur, horodatage, ancien et nouvel état dans la même transaction ; l'échec de journalisation annule la transition. | `::test_transition_journal_contains_actor_timestamp_and_states` |
| **Information Disclosure** — Fuite de valeur, d'empreinte ou de clé | La réponse et le journal ne contiennent que les métadonnées de transition ; aucune valeur n'est lue pour changer l'état. | `::test_valid_transition_changes_state_and_returns_metadata_only`, `::test_sqlite_journal_never_contains_secret_value_or_fingerprint` |
| **Information Disclosure** — Lecture de l'ancienne valeur après rotation | `GET` d'un secret `rote` retourne 404 ; `/state` ne renvoie que l'état. | `::test_valid_transition_changes_state_and_returns_metadata_only` |
| **Denial of Service** — Croissance illimitée du journal | Rétention `MAX_SECRET_TRANSITIONS` et purge dans la transaction ; listage borné. | `::test_memory_journal_is_bounded`, `::test_sqlite_journal_is_bounded`, `::test_journal_listing_is_bounded` |
| **Elevation of Privilege** — Clé d'un autre projet | `require_project_access()` répond 403 avant toute recherche ou écriture. | `::test_authentication_and_project_isolation_precede_any_write` |
| **Invariant 1** — État et journal désynchronisés | UPDATE conditionnel et INSERT dans une seule transaction `BEGIN IMMEDIATE` ; toute transition acceptée a exactement une entrée. | `::test_concurrent_transitions_accept_exactly_one`, `::test_journal_survives_secret_deletion` |
| **Invariant 8** — Reflet d'entrée ou de secret dans les erreurs | Messages 400/401/403/404 statiques du contrat ; aucune interpolation du corps, de l'état ou de la valeur. | `::test_invalid_transition_body_is_400_without_reflection`, `::test_reflexive_and_forbidden_transitions_are_400_without_mutation` |
| **Contrat** — Dérive runtime / OpenAPI | Nouvelle route et schémas comparés strictement entre `openapi.yaml` et `app.openapi()` ; `SecretStatus` reste limité à `vaulte`/`rote`. | `tests/contracts/test_vault_openapi.py`, `tests/test_vault_integration_testclient.py` |

## 5. Résultats locaux

Environnement : Linux, Python 3.14.7, venv local.

```sh
.venv/bin/python -m pytest -q
# suite complète verte (aucun échec)

.venv/bin/python -m pytest tests/test_vault_transitions_api.py -o addopts="" -q
# 40 passed in 4.20s

.venv/bin/python -m pytest tests/test_vault_transitions_api.py tests/contracts -o addopts="" -q
# 110 passed, 5204 subtests passed in 6.74s

.venv/bin/ruff check heimdall tests
# All checks passed!

.venv/bin/mypy heimdall tests/contracts/fastapi_contract_fixture.py
# Success: no issues found in 52 source files

./node_modules/.bin/spectral lint openapi.yaml --fail-severity warn
# No results with a severity of 'warn' or higher found!

npm run test:js
# 13 pass, 0 fail
```

Temps passé reporté sur le ticket : `Temps: 1h30`.
