# T117 — preuves pour la ligne SAMM (API de transition)

Sous-ticket **T403** (ticket GitHub **#117**) du grand ticket `#40 « États du secret dans le Vault »`,
branche `117-t403-api-de-transition`. Cette fiche fournit les couples **module + ligne** et les
tests qui prouvent la checklist ; elle ne remplace pas la revue de code.

## 1. Exigences du ticket et preuves

> **Permaliens** : les liens ci-dessous sont épinglés à la révision du code
> [`465c30d`](https://github.com/Cezar277/heimdall/commit/465c30db7b935cee509b76dd713fb5c959db36c1),
> qui contient la route de transition, l'application fail-closed de la matrice #115, le journal
> atomique `secret_transitions`, la rétention bornée par projet et les tests des deux backends.
> La présente fiche est le commit de documentation associé.

| Exigence vérifiée | Implémentation (module + ligne) | Test et preuve permanente | Résultat local |
|---|---|---|---|
| **Route protégée par la même authentification que les autres routes Vault** : 401 sans clé valide, 403 pour un projet étranger, 404 pour un secret absent, décisions prises avant toute écriture | [app.py:1727-1738](https://github.com/Cezar277/heimdall/blob/465c30db7b935cee509b76dd713fb5c959db36c1/heimdall/vault/app.py#L1727-L1738) (décorateur et `require_project_access`), [app.py:1784-1788](https://github.com/Cezar277/heimdall/blob/465c30db7b935cee509b76dd713fb5c959db36c1/heimdall/vault/app.py#L1784-L1788) (404) | `tests/test_vault_transitions_api.py::test_authentication_and_project_isolation_precede_any_write`, `::test_missing_secret_is_404_and_creates_no_journal_entry` | Réussi |
| **Corps strict limité à l'état cible** : le client ne fournit jamais l'état source ; les champs supplémentaires sont refusés | [app.py:469-479](https://github.com/Cezar277/heimdall/blob/465c30db7b935cee509b76dd713fb5c959db36c1/heimdall/vault/app.py#L469-L479) (`SecretTransitionRequest`, `extra="forbid"`), [database.py:1950-1957](https://github.com/Cezar277/heimdall/blob/465c30db7b935cee509b76dd713fb5c959db36c1/heimdall/vault/database.py#L1950-L1957) (lecture de l'état réel en base) | `tests/test_vault_transitions_api.py::test_invalid_transition_body_is_400_without_reflection`, `::test_transition_uses_server_side_source_state` | Réussi |
| **Transition valide acceptée** : `vaulte -> rote`, réponse 200 `no-store` limitée aux métadonnées de transition | [app.py:1764-1795](https://github.com/Cezar277/heimdall/blob/465c30db7b935cee509b76dd713fb5c959db36c1/heimdall/vault/app.py#L1764-L1795), [database.py:1920-1992](https://github.com/Cezar277/heimdall/blob/465c30db7b935cee509b76dd713fb5c959db36c1/heimdall/vault/database.py#L1920-L1992), [openapi.yaml:258-321](https://github.com/Cezar277/heimdall/blob/465c30db7b935cee509b76dd713fb5c959db36c1/openapi.yaml#L258-L321) | `tests/test_vault_transitions_api.py::test_valid_transition_changes_state_and_returns_metadata_only` | Réussi |
| **Transitions interdites refusées selon la matrice #115** : réflexives, régressions, cibles non persistables et états inconnus retournent 400 statique, sans mutation ni entrée de journal | [database.py:1947-1965](https://github.com/Cezar277/heimdall/blob/465c30db7b935cee509b76dd713fb5c959db36c1/heimdall/vault/database.py#L1947-L1965) (`validate_transition`, `PERSISTED_STATUSES`), [store.py:259-314](https://github.com/Cezar277/heimdall/blob/465c30db7b935cee509b76dd713fb5c959db36c1/heimdall/vault/store.py#L259-L314) (backend mémoire), [store.py:608-649](https://github.com/Cezar277/heimdall/blob/465c30db7b935cee509b76dd713fb5c959db36c1/heimdall/vault/store.py#L608-L649) (backend SQLite) | `tests/test_vault_transitions_api.py::test_reflexive_and_forbidden_transitions_are_400_without_mutation`, `::test_invalid_transition_body_is_400_without_reflection`, `::test_rote_is_terminal` | Réussi |
| **Journal de chaque transition acceptée** : acteur, horodatage serveur, ancien état, nouvel état | [database.py:210-227](https://github.com/Cezar277/heimdall/blob/465c30db7b935cee509b76dd713fb5c959db36c1/heimdall/vault/database.py#L210-L227) (table et index), [database.py:1967-1982](https://github.com/Cezar277/heimdall/blob/465c30db7b935cee509b76dd713fb5c959db36c1/heimdall/vault/database.py#L1967-L1982) (horodatage et INSERT), [database.py:1995-2018](https://github.com/Cezar277/heimdall/blob/465c30db7b935cee509b76dd713fb5c959db36c1/heimdall/vault/database.py#L1995-L2018) (`_list_secret_transitions`) | `tests/test_vault_transitions_api.py::test_transition_journal_contains_actor_timestamp_and_states`, `::test_occurred_at_cannot_be_forged` | Réussi |
| **Acteur non forgeable par le client** : identifiant interne `key_<32 hexadécimaux>` issu de la clé authentifiée, toute autre valeur remplacée par `unknown` | [app.py:1766-1774](https://github.com/Cezar277/heimdall/blob/465c30db7b935cee509b76dd713fb5c959db36c1/heimdall/vault/app.py#L1766-L1774) (`request.state.audit_key_id`), [database.py:1866-1876](https://github.com/Cezar277/heimdall/blob/465c30db7b935cee509b76dd713fb5c959db36c1/heimdall/vault/database.py#L1866-L1876) (`normalize_transition_actor`) | `tests/test_vault_transitions_api.py::test_actor_is_normalized_and_never_taken_from_request`, `::test_transition_journal_contains_actor_timestamp_and_states` | Réussi |
| **Atomicité état + journal** : UPDATE conditionnel et INSERT dans la même transaction `BEGIN IMMEDIATE` ; deux transitions concurrentes ne peuvent pas réussir toutes les deux ; un CAS perdant est mappé en 400 statique | [database.py:1950-1982](https://github.com/Cezar277/heimdall/blob/465c30db7b935cee509b76dd713fb5c959db36c1/heimdall/vault/database.py#L1950-L1982), [database.py:133-134](https://github.com/Cezar277/heimdall/blob/465c30db7b935cee509b76dd713fb5c959db36c1/heimdall/vault/database.py#L133-L134) (`TransitionConcurrencyError`), [app.py:1776-1783](https://github.com/Cezar277/heimdall/blob/465c30db7b935cee509b76dd713fb5c959db36c1/heimdall/vault/app.py#L1776-L1783) (mapping 400) | `tests/test_vault_transitions_api.py::test_concurrent_transitions_accept_exactly_one`, `::test_transition_concurrency_error_maps_to_static_400`, `::test_transition_secret_rejects_lost_compare_and_set` | Réussi |
| **Aucune valeur, empreinte ou clé dans le journal ni dans la réponse HTTP** ; réponse sans acteur | [app.py:482-490](https://github.com/Cezar277/heimdall/blob/465c30db7b935cee509b76dd713fb5c959db36c1/heimdall/vault/app.py#L482-L490) (`SecretTransitionResult`), [app.py:1789-1795](https://github.com/Cezar277/heimdall/blob/465c30db7b935cee509b76dd713fb5c959db36c1/heimdall/vault/app.py#L1789-L1795), [database.py:1995-2018](https://github.com/Cezar277/heimdall/blob/465c30db7b935cee509b76dd713fb5c959db36c1/heimdall/vault/database.py#L1995-L2018) | `tests/test_vault_transitions_api.py::test_valid_transition_changes_state_and_returns_metadata_only`, `::test_sqlite_journal_never_contains_secret_value_or_fingerprint` | Réussi |
| **Après `rote`, l'ancienne valeur n'est plus restituée** : `GET` du secret retourne 404 ; `GET .../state` continue d'exposer `rote` sans valeur. Un statut corrompu est canonicalisé puis refusé en 404 | [app.py:1630-1653](https://github.com/Cezar277/heimdall/blob/465c30db7b935cee509b76dd713fb5c959db36c1/heimdall/vault/app.py#L1630-L1653) (canonicalisation et 404 sur `rote`), [app.py:1665-1725](https://github.com/Cezar277/heimdall/blob/465c30db7b935cee509b76dd713fb5c959db36c1/heimdall/vault/app.py#L1665-L1725) (route `/state`) | `tests/test_vault_transitions_api.py::test_valid_transition_changes_state_and_returns_metadata_only`, `::test_get_secret_rejects_corrupted_status` | Réussi |
| **Rétention bornée du journal, isolée par projet** : au plus `MAX_SECRET_TRANSITIONS` (10 000) entrées les plus récentes **par projet**, purge dans la transaction avec alerte, listage borné 1..1000 ; une inondation d'un projet n'évince pas les autres | [database.py:97-98](https://github.com/Cezar277/heimdall/blob/465c30db7b935cee509b76dd713fb5c959db36c1/heimdall/vault/database.py#L97-L98), [database.py:1890-1917](https://github.com/Cezar277/heimdall/blob/465c30db7b935cee509b76dd713fb5c959db36c1/heimdall/vault/database.py#L1890-L1917), [store.py:164](https://github.com/Cezar277/heimdall/blob/465c30db7b935cee509b76dd713fb5c959db36c1/heimdall/vault/store.py#L164), [store.py:291-305](https://github.com/Cezar277/heimdall/blob/465c30db7b935cee509b76dd713fb5c959db36c1/heimdall/vault/store.py#L291-L305) (`deque(maxlen=...)` par projet) | `tests/test_vault_transitions_api.py::test_memory_journal_is_bounded`, `::test_sqlite_journal_is_bounded`, `::test_journal_listing_is_bounded`, `::test_journal_retention_is_isolated_by_project`, `::test_journal_purge_emits_warning_without_secret` | Réussi |
| **Historique conservé après suppression du secret** (aucune clé étrangère vers `secrets`) | [database.py:210-227](https://github.com/Cezar277/heimdall/blob/465c30db7b935cee509b76dd713fb5c959db36c1/heimdall/vault/database.py#L210-L227) | `tests/test_vault_transitions_api.py::test_journal_survives_secret_deletion` | Réussi |
| **Contrat OpenAPI et non-régression** : nouvelle route et schémas distincts, `SecretStatus` non élargi, fixture de contrat alignée, runtime et contrat identiques | [openapi.yaml:258-321](https://github.com/Cezar277/heimdall/blob/465c30db7b935cee509b76dd713fb5c959db36c1/openapi.yaml#L258-L321), [openapi.yaml:543-570](https://github.com/Cezar277/heimdall/blob/465c30db7b935cee509b76dd713fb5c959db36c1/openapi.yaml#L543-L570) | `tests/contracts/test_vault_openapi.py` (contrat avec les transitions), `tests/test_vault_integration_testclient.py` | Réussi |
| **Non-reflet des entrées et absence de secret réel dans le dépôt** : messages 400 statiques, valeur canari uniquement dans les tests | [app.py:1756-1763](https://github.com/Cezar277/heimdall/blob/465c30db7b935cee509b76dd713fb5c959db36c1/heimdall/vault/app.py#L1756-L1763), [app.py:1776-1783](https://github.com/Cezar277/heimdall/blob/465c30db7b935cee509b76dd713fb5c959db36c1/heimdall/vault/app.py#L1776-L1783) | `tests/test_vault_transitions_api.py::test_invalid_transition_body_is_400_without_reflection`, `::test_reflexive_and_forbidden_transitions_are_400_without_mutation`, `::test_valid_transition_changes_state_and_returns_metadata_only` | Réussi |

## 2. Checklist du ticket

- [x] **Route ajoutée au contrat** : `POST /api/v1/secrets/{project}/{env}/{name}/transition`, protégée par `require_project_access()` comme les autres routes Vault.
- [x] **État source côté serveur** : le corps strict ne porte que `target_status` ; l'état courant est relu dans le store ou en base avant validation.
- [x] **Matrice #115 appliquée fail-closed** : `validate_transition()` puis contrôle `PERSISTED_STATUSES` ; seule `vaulte -> rote` réussit, toute autre demande retourne 400 statique.
- [x] **Journal complet** : `occurred_at` toujours généré côté serveur, acteur interne normalisé, `previous_status`, `new_status`, dans la même transaction que le changement d'état.
- [x] **Acteur non contrôlé par le client** : extrait de `request.state.audit_key_id` ; une valeur arbitraire devient `unknown` sans être persistée.
- [x] **Aucune donnée sensible** : ni valeur, ni empreinte, ni clé API dans la table, le journal mémoire ou la réponse HTTP.
- [x] **Rétention** : `MAX_SECRET_TRANSITIONS = 10 000` **par projet**, purge atomique (SQLite) et éviction bornée (mémoire) avec alerte, listage borné 1..1000, `clear()` nettoie le journal ; une inondation d'un projet n'évince pas les autres.
- [x] **Terminalité et non-régression de lecture** : `rote` refuse toute transition ; `GET` du secret retourne 404, `GET .../state` reste disponible ; un statut corrompu est canonicalisé et refusé en 404.
- [x] **Atomicité et concurrence** : compare-and-set sur l'ancien état sous `BEGIN IMMEDIATE`, journal et état indissociables ; un seul succès sur deux transitions concurrentes ; un CAS perdant est mappé en 400 statique.
- [x] **Contrat et tests** : `openapi.yaml`, fixture de contrat, tests runtime et suite complète verts ; aucun test existant modifié en régression.

## 3. Preuve à garder pour le rapport

Exécution de la suite dédiée #117 (54 tests paramétrés mémoire/SQLite) :

```sh
.venv/bin/python -m pytest tests/test_vault_transitions_api.py -o addopts="" -q
```

Extrait du journal de test :

```text
...................................................                      [100%]
54 passed in 4.50s
```

Exécution conjointe des transitions et des contrats :

```sh
.venv/bin/python -m pytest tests/test_vault_transitions_api.py tests/contracts -o addopts="" -q
```

Contrôles statiques et contrat :

```sh
.venv/bin/ruff check heimdall tests
.venv/bin/mypy heimdall tests/contracts/fastapi_contract_fixture.py
./node_modules/.bin/spectral lint openapi.yaml --fail-severity warn
git diff --check
```

## 4. STRIDE et invariants

| Menace / exigence | Traitement | Preuve |
|---|---|---|
| **Spoofing** — Un client forge l'état source ou l'acteur | Le corps refuse tout champ supplémentaire et ne contient pas d'état source ; l'acteur vient exclusivement de la clé authentifiée (`audit_key_id`) puis est normalisé. | `::test_invalid_transition_body_is_400_without_reflection`, `::test_actor_is_normalized_and_never_taken_from_request` |
| **Tampering** — Transition interdite, contournement de la matrice ou horodatage forgé | `validate_transition()` est appelé sur l'état réellement persisté ; `PERSISTED_STATUSES` limite l'écriture à `vaulte`/`rote` ; l'UPDATE est conditionné à l'ancien état ; `occurred_at` n'est pas un paramètre d'API. | `::test_reflexive_and_forbidden_transitions_are_400_without_mutation`, `::test_concurrent_transitions_accept_exactly_one`, `::test_occurred_at_cannot_be_forged` |
| **Repudiation** — Transition non traçable | Chaque succès écrit acteur, horodatage serveur, ancien et nouvel état dans la même transaction ; l'échec de journalisation annule la transition. | `::test_transition_journal_contains_actor_timestamp_and_states` |
| **Information Disclosure** — Fuite de valeur, d'empreinte ou de clé | La réponse et le journal ne contiennent que les métadonnées de transition ; aucune valeur n'est lue pour changer l'état. | `::test_valid_transition_changes_state_and_returns_metadata_only`, `::test_sqlite_journal_never_contains_secret_value_or_fingerprint` |
| **Information Disclosure** — Lecture de l'ancienne valeur après rotation ou avec un statut corrompu | `GET` d'un secret `rote` retourne 404 ; le statut persisté est canonicalisé avant la garde ; `/state` ne renvoie que l'état canonique. | `::test_valid_transition_changes_state_and_returns_metadata_only`, `::test_get_secret_rejects_corrupted_status` |
| **Denial of Service** — Croissance illimitée du journal | Rétention `MAX_SECRET_TRANSITIONS` par projet et purge dans la transaction ; listage borné ; une inondation locale n'évince pas les autres projets. | `::test_memory_journal_is_bounded`, `::test_sqlite_journal_is_bounded`, `::test_journal_listing_is_bounded`, `::test_journal_retention_is_isolated_by_project` |
| **Elevation of Privilege** — Clé d'un autre projet | `require_project_access()` répond 403 avant toute recherche ou écriture. | `::test_authentication_and_project_isolation_precede_any_write` |
| **Invariant 1** — État et journal désynchronisés | UPDATE conditionnel et INSERT dans une seule transaction `BEGIN IMMEDIATE` ; toute transition acceptée a exactement une entrée ; un CAS perdant n'écrit rien. | `::test_concurrent_transitions_accept_exactly_one`, `::test_transition_secret_rejects_lost_compare_and_set`, `::test_journal_survives_secret_deletion` |
| **Invariant 8** — Reflet d'entrée ou de secret dans les erreurs | Messages 400/401/403/404 statiques du contrat ; aucune interpolation du corps, de l'état ou de la valeur. | `::test_invalid_transition_body_is_400_without_reflection`, `::test_reflexive_and_forbidden_transitions_are_400_without_mutation` |
| **Contrat** — Dérive runtime / OpenAPI | Nouvelle route et schémas comparés strictement entre `openapi.yaml` et `app.openapi()` ; `SecretStatus` reste limité à `vaulte`/`rote`. | `tests/contracts/test_vault_openapi.py`, `tests/test_vault_integration_testclient.py` |

## 5. Résultats locaux

Environnement : Linux, Python 3.14.7, venv local.

```sh
.venv/bin/python -m pytest tests/test_vault_transitions_api.py -o addopts="" -q
# 54 passed

.venv/bin/python -m pytest tests/test_vault_transitions_api.py tests/contracts -o addopts="" -q
# suite verte

.venv/bin/ruff check heimdall tests
# All checks passed!

.venv/bin/mypy heimdall tests/contracts/fastapi_contract_fixture.py
# Success: no issues found

./node_modules/.bin/spectral lint openapi.yaml --fail-severity warn
# No results with a severity of 'warn' or higher found!
```

Temps passé reporté sur le ticket : `Temps: 1h30`.
