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
| **Invariant 8 — Non-reflet strict des entrées dans les erreurs** | `heimdall/vault/transitions.py` (`UnknownStateError`, message statique sans interpolation ni attribut, constructeur sans argument) | `tests/test_vault_transitions.py::SecretLifecycleStateTests::test_unknown_state_error_has_no_parameters`, `test_unknown_state_error_never_reflects_input`, `ErrorHierarchyAndSanitizationTests::test_error_message_is_static_and_deterministic` |
| **Immuabilité des tables de transitions** : protection contre altération mémoire / monkey-patch et aucun backing dict exposé | `heimdall/vault/transitions.py` (`MappingProxyType`, sans dictionnaire mutable exposé au module) | `tests/test_vault_transitions.py::SecretLifecycleStateTests::test_immutability_of_transition_tables` |
| **Canonique persisté & interdiction de persister les alias** : sortie de `canonicalize_state` toujours dans `LIFECYCLE_STATES_SET` | `heimdall/vault/transitions.py` (`canonicalize_state`, ADR-006 §6) | `tests/test_vault_transitions.py::SecretLifecycleStateTests::test_canonical_state_persisted_invariants` |
| **Robustesse & bornage mémoire (DoS)** : rejet immédiat si longueur > 64 chars | `heimdall/vault/transitions.py` (`MAX_STATE_CHARS = 64`) | `tests/test_vault_transitions.py::SecretLifecycleStateTests::test_canonicalize_state_robustness` |
| **Complétude de la matrice 5x5** : partition autorisés/interdits exacte | `heimdall/vault/transitions.py` (`get_transition_matrix`, `get_allowed_transitions`, `get_forbidden_transitions`) | `tests/test_vault_transitions.py::TransitionMatrixAndPartitionsTests::test_allowed_and_forbidden_partition_states`, `test_transition_matrix_dimensions_and_values` |
| **Confinement cryptographique (Invariant 5)** : zéro import de `cryptography` ou `argon2` | `heimdall/vault/transitions.py` (bibliothèque standard pure) | `tests/test_crypto_confinement.py` (6 tests, 19 sous-cas) |

> **Note de périmètre architectural (DoD & SAMM)** :
> Ce ticket #115 établit le **socle contractuel formel et la bibliothèque de validation logicielle** (`validate_transition`, `canonicalize_state`, tables immuables).
> L'**application opérationnelle obligatoire** (branchement dans les routes FastAPI du Vault `/api/v1/secrets/.../transition` et blocage des écritures directes en base de données) est portée et prouvée en intégration par le sous-ticket **#117 (« API de transition »)**.

---

## 2. Décisions d'architecture (ADR-006)

Le détail des arbitrages de conception est consigné dans [docs/adr/006-table-etats-et-transitions.md](adr/006-table-etats-et-transitions.md) :

1. **Cycle canonique** : `detecte -> confirme -> vaulte -> rote`.
2. **Matrice 5x5 fermée** : 5 transitions autorisées, 20 transitions interdites justifiées, encapsulées en `MappingProxyType`.
3. **Faux positif (« écarté »)** :
   - Rôle consultatif du LLM (#33) : aucune transition automatique, motif fermé tracé dans le journal des rejets ;
   - Validation humaine requise (#32) via le choix `N` (ignorer/écarter) consigné dans `DecisionJournal` ;
   - Interdiction formelle d'entrer dans le Vault (`faux_positif -> vaulte` interdit) ;
   - Fail-closed en CI : un Finding marqué `faux_positif` ne constitue pas une dispense en CI sans allowlist explicite ;
   - Réexamen explicite uniquement (`faux_positif -> detecte`).
4. **Terminalité de `rote`** : fin de vie scellée, aucune transition sortante.
5. **Non-rétrogradation de `vaulte`** : un secret passé par le Vault ou Git est définitivement compromis jusqu'à sa rotation.
6. **Canonicalisation obligatoire** : seuls les 5 états canoniques peuvent être persistés ; les alias ne sont acceptés qu'aux frontières d'interface.
7. **Invariant 8** : aucun reflet d'entrée dans `UnknownStateError`, message statique, bornage à 64 caractères.

---

## 3. Résultats de validation locale

Environnement : Linux, Python 3.14 (environnement virtuel `.venv`).

```text
==================================== pytest ====================================
tests/test_vault_transitions.py ..........................                 [100%]
26 passed, 81 subtests passed in 0.30s

tests/test_crypto_confinement.py ......                                   [100%]
6 passed, 19 subtests passed in 0.24s

Couverture heimdall/vault/transitions.py :
Name                            Stmts   Miss  Cover   Missing
-------------------------------------------------------------
heimdall/vault/transitions.py      65      0   100%
-------------------------------------------------------------
TOTAL                              65      0   100%

=================================== Linters ====================================
ruff check heimdall tests                     --> All checks passed!
ruff format --check (fichiers modifiés)       --> All formatted!
mypy heimdall tests/contracts/fastapi_contract_fixture.py
                                              --> Success: no issues found in 51 source files
bandit -r heimdall -q                         --> Aucun problème de sécurité détecté
python docs/security/check_model.py           --> OK (48 scénarios STRIDE, DFD, liens internes)
```

---

## 4. Liens permanents pour la feuille SAMM (SHA testé `fe7529dc3d3c786be8209ffeb8eb9a8ec1bc04a3`)

Les numéros de lignes et identifiants ci-dessous référencent les symboles exacts du module `heimdall/vault/transitions.py` et de sa suite de tests `tests/test_vault_transitions.py` :

- **Module d'implémentation `transitions.py`** :
  - [`SecretLifecycleState` et `LIFECYCLE_STATES`, transitions.py:32–47](https://github.com/Cezar277/heimdall/blob/fe7529dc3d3c786be8209ffeb8eb9a8ec1bc04a3/heimdall/vault/transitions.py#L32-L47) : constantes des 5 états formels.
  - [`STATE_ALIASES`, transitions.py:57–63](https://github.com/Cezar277/heimdall/blob/fe7529dc3d3c786be8209ffeb8eb9a8ec1bc04a3/heimdall/vault/transitions.py#L57-L63) : alias métier immuables `ecarte` -> `faux_positif`.
  - [`INITIAL_STATE` et `TERMINAL_STATES`, transitions.py:66–69](https://github.com/Cezar277/heimdall/blob/fe7529dc3d3c786be8209ffeb8eb9a8ec1bc04a3/heimdall/vault/transitions.py#L66-L69) : bornes du cycle de vie.
  - [`ALLOWED_TRANSITIONS`, transitions.py:93–95](https://github.com/Cezar277/heimdall/blob/fe7529dc3d3c786be8209ffeb8eb9a8ec1bc04a3/heimdall/vault/transitions.py#L93-L95) : table immuable (`MappingProxyType`) des 5 transitions permises sans backing dict exposé.
  - [`FORBIDDEN_TRANSITION_REASONS`, transitions.py:179–181](https://github.com/Cezar277/heimdall/blob/fe7529dc3d3c786be8209ffeb8eb9a8ec1bc04a3/heimdall/vault/transitions.py#L179-L181) : justifications immuables de chaque transition interdite.
  - [`UnknownStateError`, transitions.py:188–196](https://github.com/Cezar277/heimdall/blob/fe7529dc3d3c786be8209ffeb8eb9a8ec1bc04a3/heimdall/vault/transitions.py#L188-L196) : exception sans argument ni reflet (Invariant 8).
  - [`canonicalize_state`, transitions.py:210–230](https://github.com/Cezar277/heimdall/blob/fe7529dc3d3c786be8209ffeb8eb9a8ec1bc04a3/heimdall/vault/transitions.py#L210-L230) : normalisation, bornage mémoire et validation.
  - [`is_transition_allowed`, transitions.py:241–254](https://github.com/Cezar277/heimdall/blob/fe7529dc3d3c786be8209ffeb8eb9a8ec1bc04a3/heimdall/vault/transitions.py#L241-L254) : prédicat booléen fail-closed.
  - [`validate_transition`, transitions.py:256–274](https://github.com/Cezar277/heimdall/blob/fe7529dc3d3c786be8209ffeb8eb9a8ec1bc04a3/heimdall/vault/transitions.py#L256-L274) : point de contrôle obligatoire fail-closed.
  - [`get_transition_matrix`, transitions.py:292–297](https://github.com/Cezar277/heimdall/blob/fe7529dc3d3c786be8209ffeb8eb9a8ec1bc04a3/heimdall/vault/transitions.py#L292-L297) : matrice d'adjacence 5x5 complète.
- **Suite de tests automatisés `test_vault_transitions.py`** :
  - [`SecretLifecycleStateTests`, test_vault_transitions.py:39–187](https://github.com/Cezar277/heimdall/blob/fe7529dc3d3c786be8209ffeb8eb9a8ec1bc04a3/tests/test_vault_transitions.py#L39-L187) : validation des états, non-reflet Invariant 8, signature sans argument, robustesse et immuabilité.
  - [`AllowedTransitionsTests`, test_vault_transitions.py:190–241](https://github.com/Cezar277/heimdall/blob/fe7529dc3d3c786be8209ffeb8eb9a8ec1bc04a3/tests/test_vault_transitions.py#L190-L241) : validation des 5 transitions nominales.
  - [`ForbiddenTransitionsTests`, test_vault_transitions.py:243–324](https://github.com/Cezar277/heimdall/blob/fe7529dc3d3c786be8209ffeb8eb9a8ec1bc04a3/tests/test_vault_transitions.py#L243-L324) : validation exhaustive des 20 interdictions et passages critiques.
  - [`TransitionMatrixAndPartitionsTests`, test_vault_transitions.py:326–361](https://github.com/Cezar277/heimdall/blob/fe7529dc3d3c786be8209ffeb8eb9a8ec1bc04a3/tests/test_vault_transitions.py#L326-L361) : exhaustivité et partitions.
  - [`ErrorHierarchyAndSanitizationTests`, test_vault_transitions.py:363–393](https://github.com/Cezar277/heimdall/blob/fe7529dc3d3c786be8209ffeb8eb9a8ec1bc04a3/tests/test_vault_transitions.py#L363-L393) : hiérarchie d'erreurs et messages déterministes.
- **Décision d'architecture ADR-006** :
  - [`docs/adr/006-table-etats-et-transitions.md`](https://github.com/Cezar277/heimdall/blob/fe7529dc3d3c786be8209ffeb8eb9a8ec1bc04a3/docs/adr/006-table-etats-et-transitions.md#L1).
