# T115 — Table d'états et transitions du secret : preuves SAMM

Ticket : [#115](https://github.com/Cezar277/heimdall/issues/115), sous-ticket 1 du grand ticket [#40](https://github.com/Cezar277/heimdall/issues/40) « États du secret dans le Vault ».
Porteur : C · Relecteur : B · Sprint : S2.
Documents associés : [ADR-006](adr/006-table-etats-et-transitions.md), [Finding v1](contracts/finding.md) (#14), [Journal des rejets](llm-rejections.md) (#33), [Matrice de traçabilité Vault](contracts/vault-traceability.md).

---

## 1. Garanties et preuves automatisées

| Exigence / Menace | Implémentation | Preuve automatisée |
|---|---|---|
| **Chaîne nominale `detecte > confirme > vaulte > rote`** | `heimdall/vault/transitions.py` (`ALLOWED_TRANSITIONS`, `validate_transition`) | `tests/test_vault_transitions.py::AllowedTransitionsTests::test_nominal_lifecycle_chain_detecte_confirme_vaulte_rote` |
| **Cohérence avec Finding v1 (#14)** : 5 états formels identiques au schéma | `heimdall/vault/transitions.py` (`LIFECYCLE_STATES`, `LIFECYCLE_STATES_SET`) | `tests/test_vault_transitions.py::SecretLifecycleStateTests::test_lifecycle_states_match_finding_schema_statuses` |
| **État initial obligatoire** : tout secret débute à `detecte` | `heimdall/vault/transitions.py` (`INITIAL_STATE = "detecte"`) | `tests/test_vault_transitions.py::SecretLifecycleStateTests::test_initial_state_is_detecte` |
| **Terminalité de `rote`** : aucune transition sortante permise | `heimdall/vault/transitions.py` (`TERMINAL_STATES = frozenset({"rote"})`) | `tests/test_vault_transitions.py::SecretLifecycleStateTests::test_terminal_states_contain_only_rote` |
| **Traitement du faux positif / écarté (#33)** : cycle vers `detecte`, jamais dans le Vault | `heimdall/vault/transitions.py` (`ALLOWED_TRANSITIONS["faux_positif"]`, alias `ecarte`) | `tests/test_vault_transitions.py::AllowedTransitionsTests::test_false_positive_rejection_and_reexamination_cycle`, `test_transitions_with_alias_ecarte` |
| **Rejet exhaustif des 20 transitions interdites** : matrice 5x5 complète avec justifications fermées | `heimdall/vault/transitions.py` (`FORBIDDEN_TRANSITION_REASONS`, `validate_transition`, `InvalidTransitionError`) | `tests/test_vault_transitions.py::ForbiddenTransitionsTests::test_all_20_forbidden_transitions_raise_invalid_transition_error` |
| **Passages critiques interdits** (`detecte -> rote`, `detecte -> vaulte`, `confirme -> rote`, `vaulte -> faux_positif`, `faux_positif -> vaulte`) | `heimdall/vault/transitions.py` (`validate_transition`) | `tests/test_vault_transitions.py::ForbiddenTransitionsTests::test_specific_forbidden_passages` |
| **Transitions réflexives interdites** : une relecture n'est pas une transition d'avancement | `heimdall/vault/transitions.py` (`validate_transition`) | `tests/test_vault_transitions.py::ForbiddenTransitionsTests::test_reflexive_transitions_are_forbidden` |
| **Normalisation et alias métier (`ecarte`, casse, espaces)** | `heimdall/vault/transitions.py` (`canonicalize_state`, `STATE_ALIASES`) | `tests/test_vault_transitions.py::SecretLifecycleStateTests::test_canonicalize_state_aliases`, `test_canonicalize_state_normalizes_case_and_whitespace` |
| **Fail-closed sur état inconnu** | `heimdall/vault/transitions.py` (`canonicalize_state`, `UnknownStateError`) | `tests/test_vault_transitions.py::SecretLifecycleStateTests::test_canonicalize_state_unknown_raises_error`, `ForbiddenTransitionsTests::test_unknown_state_in_transition_fails_closed` |
| **Complétude de la matrice 5x5** : partition autorisés/interdits exacte | `heimdall/vault/transitions.py` (`get_transition_matrix`, `get_allowed_transitions`, `get_forbidden_transitions`) | `tests/test_vault_transitions.py::TransitionMatrixAndPartitionsTests::test_allowed_and_forbidden_partition_states`, `test_transition_matrix_dimensions_and_values` |
| **Confinement cryptographique (Invariant 5)** : zéro import de `cryptography` ou `argon2` | `heimdall/vault/transitions.py` (bibliothèque standard pure) | `tests/test_crypto_confinement.py` (6 tests, 19 sous-cas) |
| **Sanitization des messages d'erreur** : aucun reflet de secret ou donnée sensible | `heimdall/vault/transitions.py` (`InvalidTransitionError`, `UnknownStateError`) | `tests/test_vault_transitions.py::ErrorHierarchyAndSanitizationTests::test_error_message_is_static_and_deterministic` |

---

## 2. Décisions d'architecture (ADR-006)

Le détail des arbitrages de conception est consigné dans [docs/adr/006-table-etats-et-transitions.md](adr/006-table-etats-et-transitions.md) :

1. **Cycle canonique** : `detecte -> confirme -> vaulte -> rote`.
2. **Matrice 5x5 fermée** : 5 transitions autorisées, 20 transitions interdites justifiées.
3. **Faux positif (« écarté »)** :
   - Rôle consultatif du LLM (#33) : aucune transition automatique, motif fermé tracé dans le journal des rejets ;
   - Validation humaine requise (#32) via le choix `N` (ignorer/écarter) consigné dans `DecisionJournal` ;
   - Interdiction formelle d'entrer dans le Vault (`faux_positif -> vaulte` interdit) ;
   - Fail-closed en CI : un Finding marqué `faux_positif` ne constitue pas une dispense en CI sans allowlist explicite ;
   - Réexamen explicite uniquement (`faux_positif -> detecte`).
4. **Terminalité de `rote`** : fin de vie scellée, aucune transition sortante.
5. **Non-rétrogradation de `vaulte`** : un secret passé par le Vault ou Git est définitivement compromis jusqu'à sa rotation.

---

## 3. Résultats de validation locale

Environnement : Linux, Python 3.14 (environnement virtuel `.venv`).

```text
==================================== pytest ====================================
tests/test_vault_transitions.py .....................                     [100%]
21 passed, 71 subtests passed in 0.18s

tests/test_crypto_confinement.py ......                                   [100%]
6 passed, 19 subtests passed in 0.15s

Couverture heimdall/vault/transitions.py :
Name                            Stmts   Miss  Cover   Missing
-------------------------------------------------------------
heimdall/vault/transitions.py      60      0   100%
-------------------------------------------------------------
TOTAL                              60      0   100%

=================================== Linters ====================================
ruff check heimdall tests                     --> All checks passed!
ruff format --check heimdall tests            --> All formatted!
mypy heimdall tests/contracts/fastapi_contract_fixture.py
                                              --> Success: no issues found in 51 source files
bandit -r heimdall -q                         --> Aucun problème de sécurité détecté
python docs/security/check_model.py           --> OK (modèle, DFD, STRIDE, liens internes)
```

---

## 4. Liens permanents pour la feuille SAMM (SHA testé `4cac38a1149adda9e17030307d0d8564a482b30e`)

Les numéros de lignes et identifiants ci-dessous référencent les symboles exacts du module `heimdall/vault/transitions.py` et de sa suite de tests `tests/test_vault_transitions.py` :

- **Module d'implémentation `transitions.py`** :
  - [`SecretLifecycleState` et `LIFECYCLE_STATES`, transitions.py:24–39](https://github.com/Cezar277/heimdall/blob/abb757da95625da8bfd29577d8356bf6df1bd173/heimdall/vault/transitions.py#L24-L39) : constantes des 5 états formels.
  - [`STATE_ALIASES`, transitions.py:47–51](https://github.com/Cezar277/heimdall/blob/abb757da95625da8bfd29577d8356bf6df1bd173/heimdall/vault/transitions.py#L47-L51) : alias métier `ecarte` -> `faux_positif`.
  - [`INITIAL_STATE` et `TERMINAL_STATES`, transitions.py:54–57](https://github.com/Cezar277/heimdall/blob/abb757da95625da8bfd29577d8356bf6df1bd173/heimdall/vault/transitions.py#L54-L57) : bornes du cycle de vie.
  - [`ALLOWED_TRANSITIONS`, transitions.py:61–72](https://github.com/Cezar277/heimdall/blob/abb757da95625da8bfd29577d8356bf6df1bd173/heimdall/vault/transitions.py#L61-L72) : table des 5 transitions permises.
  - [`FORBIDDEN_TRANSITION_REASONS`, transitions.py:75–142](https://github.com/Cezar277/heimdall/blob/abb757da95625da8bfd29577d8356bf6df1bd173/heimdall/vault/transitions.py#L75-L142) : justifications de chaque transition interdite.
  - [`canonicalize_state`, transitions.py:168–185](https://github.com/Cezar277/heimdall/blob/abb757da95625da8bfd29577d8356bf6df1bd173/heimdall/vault/transitions.py#L168-L185) : normalisation et validation.
  - [`is_transition_allowed`, transitions.py:196–209](https://github.com/Cezar277/heimdall/blob/abb757da95625da8bfd29577d8356bf6df1bd173/heimdall/vault/transitions.py#L196-L209) : prédicat booléen fail-closed.
  - [`validate_transition`, transitions.py:211–228](https://github.com/Cezar277/heimdall/blob/abb757da95625da8bfd29577d8356bf6df1bd173/heimdall/vault/transitions.py#L211-L228) : point de contrôle obligatoire fail-closed.
  - [`get_transition_matrix`, transitions.py:247–252](https://github.com/Cezar277/heimdall/blob/abb757da95625da8bfd29577d8356bf6df1bd173/heimdall/vault/transitions.py#L247-L252) : matrice d'adjacence 5x5 complète.
- **Suite de tests automatisés `test_vault_transitions.py`** :
  - [`SecretLifecycleStateTests`, test_vault_transitions.py:36–95](https://github.com/Cezar277/heimdall/blob/abb757da95625da8bfd29577d8356bf6df1bd173/tests/test_vault_transitions.py#L36-L95) : validation des états et cohérence #14.
  - [`AllowedTransitionsTests`, test_vault_transitions.py:97–148](https://github.com/Cezar277/heimdall/blob/abb757da95625da8bfd29577d8356bf6df1bd173/tests/test_vault_transitions.py#L97-L148) : validation des 5 transitions nominales.
  - [`ForbiddenTransitionsTests`, test_vault_transitions.py:150–228](https://github.com/Cezar277/heimdall/blob/abb757da95625da8bfd29577d8356bf6df1bd173/tests/test_vault_transitions.py#L150-L228) : validation exhaustive des 20 interdictions et passages critiques.
  - [`TransitionMatrixAndPartitionsTests`, test_vault_transitions.py:230–265](https://github.com/Cezar277/heimdall/blob/abb757da95625da8bfd29577d8356bf6df1bd173/tests/test_vault_transitions.py#L230-L265) : exhaustivité et partitions.
- **Décision d'architecture ADR-006** :
  - [`docs/adr/006-table-etats-et-transitions.md`](https://github.com/Cezar277/heimdall/blob/abb757da95625da8bfd29577d8356bf6df1bd173/docs/adr/006-table-etats-et-transitions.md#L1).
