# T33 — preuves SAMM

Ticket : [#33](https://github.com/Cezar277/heimdall/issues/33).

| Exigence / menace | Implémentation | Preuve hors ligne |
| --- | --- | --- |
| Traçabilité d'un rejet : date, fichier, ligne, modèle, prompt, justification | `heimdall/llm/rejections.py`, `RejectionJournal.append` | `test_rejection_is_durable_visible_and_never_removes_finding`, `test_chain_survives_reopening` |
| Altération / répudiation | `_entries`, `_locked`, chaîne SHA-256 et append durable | `test_tampering_refuses_read_and_append`, `test_concurrent_access_refuses_instead_of_forking_chain` |
| Injection de prompt / fuite dans les logs | Motif fermé, aucun texte du LLM, rendu JSON échappé | `test_invalid_model_response_is_not_a_rejection`, `test_cli_summary_and_escaped_details` |
| Fail-closed si le journal échoue | `qualify_finding`, propagation `JournalError` | `test_io_failure_never_returns_rejection`, `test_cli_corruption_exit_two` |
| Visibilité des rejets | `rejection_summary`, commande `rejections` dans `heimdall/cli/main.py` | `test_cli_summary_and_escaped_details` |
| Aucun rejet LLM en CI | Court-circuit `qualify_finding(ci=True)` ; scan CI déterministe inchangé | `test_ci_never_calls_model_or_journal`, suite `tests/test_cli_scan.py` |
| Consultation sans effet de bord | `_prepare_path(create=False)`, `_locked(create=False)`, `RejectionJournal.read` | `test_read_absent_journal_creates_nothing`, `test_existing_journal_read_never_creates_or_writes`, `test_read_in_unwritable_state_never_creates_files` |
| Entrée non masquée ou surdimensionnée | Garde avant appel dans `qualify_finding` | `test_masking_guard_precedes_model_and_journal` |
| Concurrence lecture / lecture | Verrou exclusif non bloquant conservé | `test_two_reads_refuse_concurrency_explicitly` |

Les limites du chaînage et le raccordement au dialogue #32 sont documentés
dans [llm-rejections.md](llm-rejections.md). Aucun test ne contacte Ollama.

## Liens permanents pour la feuille SAMM

Commit d'implémentation après revue : `c16fd01d2b8e5cbba8f62dd8cbfe40e561f13e3b`.

- [Append durable et champs de preuve, rejections.py:202](https://github.com/Cezar277/heimdall/blob/c16fd01d2b8e5cbba8f62dd8cbfe40e561f13e3b/heimdall/llm/rejections.py#L202).
- [Vérification de chaîne, rejections.py:143](https://github.com/Cezar277/heimdall/blob/c16fd01d2b8e5cbba8f62dd8cbfe40e561f13e3b/heimdall/llm/rejections.py#L143).
- [Verrou et permissions, rejections.py:105](https://github.com/Cezar277/heimdall/blob/c16fd01d2b8e5cbba8f62dd8cbfe40e561f13e3b/heimdall/llm/rejections.py#L105).
- [Consultation sans création, rejections.py:194](https://github.com/Cezar277/heimdall/blob/c16fd01d2b8e5cbba8f62dd8cbfe40e561f13e3b/heimdall/llm/rejections.py#L194).
- [Orchestration, garde de masquage et politique CI, rejections.py:239](https://github.com/Cezar277/heimdall/blob/c16fd01d2b8e5cbba8f62dd8cbfe40e561f13e3b/heimdall/llm/rejections.py#L239).
- [Consultation CLI, main.py:193](https://github.com/Cezar277/heimdall/blob/c16fd01d2b8e5cbba8f62dd8cbfe40e561f13e3b/heimdall/cli/main.py#L193).
- [Consultation sans création, test_llm_rejections.py:234](https://github.com/Cezar277/heimdall/blob/c16fd01d2b8e5cbba8f62dd8cbfe40e561f13e3b/tests/test_llm_rejections.py#L234).
- [Concurrence lecture / lecture, test_llm_rejections.py:330](https://github.com/Cezar277/heimdall/blob/c16fd01d2b8e5cbba8f62dd8cbfe40e561f13e3b/tests/test_llm_rejections.py#L330).
- [Gardes de masquage, test_llm_rejections.py:364](https://github.com/Cezar277/heimdall/blob/c16fd01d2b8e5cbba8f62dd8cbfe40e561f13e3b/tests/test_llm_rejections.py#L364).

## Résultats locaux — 25 octobre 2026

Environnement de référence : Debian / WSL, Python 3.13.5, installation
éditable avec les dépendances `.[dev]` épinglées du projet.

| Contrôle | Résultat |
| --- | --- |
| `ruff check heimdall tests` | Succès |
| `ruff format --check heimdall/llm/rejections.py heimdall/cli/main.py tests/test_llm_rejections.py` | 3 fichiers conformes |
| `mypy heimdall tests/contracts/fastapi_contract_fixture.py` | 45 fichiers, aucune erreur |
| `bandit -r heimdall -q` | Succès |
| `pytest --cov=heimdall --cov-branch --cov-report=term-missing --cov-fail-under=85` | 2189 passed, 16 skipped, 4480 subtests passed ; couverture globale 91,28 % après corrections de revue |
| `pytest tests/test_llm_rejections.py --cov=heimdall.llm.rejections --cov-branch --cov-report=term-missing --cov-fail-under=85` | 45 passed ; couverture du module 90,78 % après corrections de revue |

Les tests Ollama réels restent désactivés par défaut ; les tests T33 utilisent
un transport factice, y compris pour les cas d'injection. La suite complète
Windows a rencontré des limitations de plateforme (notamment les privilèges
de création de liens symboliques) : la validation complète ci-dessus est
effectuée sous Linux, comme la CI du projet.

La relecture croisée, la PR liée à #33 et la CI distante restent à valider
avant merge ; aucun merge sur main n'est effectué par ce ticket.
