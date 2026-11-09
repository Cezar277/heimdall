# T37 — Mode CI headless : preuves SAMM

Ticket : #37 (épic #6 « CLI, hook et CI headless »).

SHA de référence du code : `d3785510262b77a606bb94b64931ce8c1bde3782`
(le commit de documentation qui suit ne modifie que ce fichier).

## Garanties et preuves

| Garantie | Implémentation | Preuve automatisée |
| --- | --- | --- |
| Analyse **différentielle** à trois points : seuls les changements de la branche courante sont jugés | [`gitdiff.py:680`](https://github.com/Cezar277/heimdall/blob/d3785510262b77a606bb94b64931ce8c1bde3782/heimdall/mcp/gitdiff.py#L680) (`diff_changes`, `base...head`), [`scan.py:815`](https://github.com/Cezar277/heimdall/blob/d3785510262b77a606bb94b64931ce8c1bde3782/heimdall/cli/scan.py#L815) (`_collect_diff`) | [`test_cli_scan_diff.py:114`](https://github.com/Cezar277/heimdall/blob/d3785510262b77a606bb94b64931ce8c1bde3782/tests/test_cli_scan_diff.py#L114) (secret de la branche cible absent), [`195`](https://github.com/Cezar277/heimdall/blob/d3785510262b77a606bb94b64931ce8c1bde3782/tests/test_cli_scan_diff.py#L195) (secret hors diff), [`212`](https://github.com/Cezar277/heimdall/blob/d3785510262b77a606bb94b64931ce8c1bde3782/tests/test_cli_scan_diff.py#L212) (secret supprimé) |
| Référence validée avant tout appel git, puis résolue en SHA complet | [`gitdiff.py:871`](https://github.com/Cezar277/heimdall/blob/d3785510262b77a606bb94b64931ce8c1bde3782/heimdall/mcp/gitdiff.py#L871) (`_checked_ref`), [`gitdiff.py:649`](https://github.com/Cezar277/heimdall/blob/d3785510262b77a606bb94b64931ce8c1bde3782/heimdall/mcp/gitdiff.py#L649) (`resolve_commit`), [`gitdiff.py:123`](https://github.com/Cezar277/heimdall/blob/d3785510262b77a606bb94b64931ce8c1bde3782/heimdall/mcp/gitdiff.py#L123) (`DIFF_RAW_ARGUMENTS`) | [`test_cli_scan_diff.py:69`](https://github.com/Cezar277/heimdall/blob/d3785510262b77a606bb94b64931ce8c1bde3782/tests/test_cli_scan_diff.py#L69), [`78`](https://github.com/Cezar277/heimdall/blob/d3785510262b77a606bb94b64931ce8c1bde3782/tests/test_cli_scan_diff.py#L78), [`85`](https://github.com/Cezar277/heimdall/blob/d3785510262b77a606bb94b64931ce8c1bde3782/tests/test_cli_scan_diff.py#L85) (`-x`, `--help`, `..`, `@{1}`, espaces, `//`, `.hidden`, `.lock`, `~`, `^`, `:`, `?`, `*`, `[`, `\`) |
| `HEAD` figé en SHA et re-résolu après l'analyse : un commit déplacé refuse le verdict | [`scan.py:848`](https://github.com/Cezar277/heimdall/blob/d3785510262b77a606bb94b64931ce8c1bde3782/heimdall/cli/scan.py#L848), [`scan.py:876`](https://github.com/Cezar277/heimdall/blob/d3785510262b77a606bb94b64931ce8c1bde3782/heimdall/cli/scan.py#L876) | [`test_cli_scan_diff.py:348`](https://github.com/Cezar277/heimdall/blob/d3785510262b77a606bb94b64931ce8c1bde3782/tests/test_cli_scan_diff.py#L348) |
| Clone superficiel sans ancêtre commun : code 2, jamais un faux vert | [`gitdiff.py:680`](https://github.com/Cezar277/heimdall/blob/d3785510262b77a606bb94b64931ce8c1bde3782/heimdall/mcp/gitdiff.py#L680) (git échoue sur `base...head`), [`scan.py:847`](https://github.com/Cezar277/heimdall/blob/d3785510262b77a606bb94b64931ce8c1bde3782/heimdall/cli/scan.py#L847) | [`test_cli_scan_diff.py:312`](https://github.com/Cezar277/heimdall/blob/d3785510262b77a606bb94b64931ce8c1bde3782/tests/test_cli_scan_diff.py#L312) (vrai `git clone --depth 1 --no-single-branch`) ; modèles [`github-actions.yml:30`](https://github.com/Cezar277/heimdall/blob/d3785510262b77a606bb94b64931ce8c1bde3782/docs/ci/github-actions.yml#L30) (`fetch-depth: 0`) et [`gitlab-ci.yml:16`](https://github.com/Cezar277/heimdall/blob/d3785510262b77a606bb94b64931ce8c1bde3782/docs/ci/gitlab-ci.yml#L16) (`GIT_DEPTH: "0"`) |
| Mode strictement **headless** : `--diff` exige `--ci`, aucun LLM, aucun réseau | [`main.py:129`](https://github.com/Cezar277/heimdall/blob/d3785510262b77a606bb94b64931ce8c1bde3782/heimdall/cli/main.py#L129) (`--diff`), [`main.py:177`](https://github.com/Cezar277/heimdall/blob/d3785510262b77a606bb94b64931ce8c1bde3782/heimdall/cli/main.py#L177) (exige `--ci`), [`scan.py:815`](https://github.com/Cezar277/heimdall/blob/d3785510262b77a606bb94b64931ce8c1bde3782/heimdall/cli/scan.py#L815) | [`test_cli_scan_diff.py:245`](https://github.com/Cezar277/heimdall/blob/d3785510262b77a606bb94b64931ce8c1bde3782/tests/test_cli_scan_diff.py#L245) (`--diff` sans `--ci` → 2) ; le module `scan` n'importe aucun client LLM |
| Verdict par code de sortie : 0 propre, 1 secret, 2 outillage | [`main.py:177`](https://github.com/Cezar277/heimdall/blob/d3785510262b77a606bb94b64931ce8c1bde3782/heimdall/cli/main.py#L177), [`scan.py:883`](https://github.com/Cezar277/heimdall/blob/d3785510262b77a606bb94b64931ce8c1bde3782/heimdall/cli/scan.py#L883) | [`test_cli_scan_diff.py:167`](https://github.com/Cezar277/heimdall/blob/d3785510262b77a606bb94b64931ce8c1bde3782/tests/test_cli_scan_diff.py#L167) (1), [`182`](https://github.com/Cezar277/heimdall/blob/d3785510262b77a606bb94b64931ce8c1bde3782/tests/test_cli_scan_diff.py#L182) (0), [`261`](https://github.com/Cezar277/heimdall/blob/d3785510262b77a606bb94b64931ce8c1bde3782/tests/test_cli_scan_diff.py#L261) (2) |
| Sortie machine JSON `heimdall.scan.v1`, `scope: "diff"`, sans secret | [`scan.py:80`](https://github.com/Cezar277/heimdall/blob/d3785510262b77a606bb94b64931ce8c1bde3782/heimdall/cli/scan.py#L80) (`SCOPE_DIFF`), [`scan.py:883`](https://github.com/Cezar277/heimdall/blob/d3785510262b77a606bb94b64931ce8c1bde3782/heimdall/cli/scan.py#L883), [`schemas/scan.schema.json`](https://github.com/Cezar277/heimdall/blob/d3785510262b77a606bb94b64931ce8c1bde3782/schemas/scan.schema.json) (enum `diff`) | [`test_cli_scan_diff.py:270`](https://github.com/Cezar277/heimdall/blob/d3785510262b77a606bb94b64931ce8c1bde3782/tests/test_cli_scan_diff.py#L270), [`test_cli_scan.py:2170`](https://github.com/Cezar277/heimdall/blob/d3785510262b77a606bb94b64931ce8c1bde3782/tests/test_cli_scan.py#L2170) (validation du schéma) |
| Mêmes bornes que `--staged` : 1 000 fichiers, 32 Mio, 10 000 Findings, 120 s | [`scan.py:657`](https://github.com/Cezar277/heimdall/blob/d3785510262b77a606bb94b64931ce8c1bde3782/heimdall/cli/scan.py#L657) (`_scan_changes`), [`scan.py:850`](https://github.com/Cezar277/heimdall/blob/d3785510262b77a606bb94b64931ce8c1bde3782/heimdall/cli/scan.py#L850) (`MAX_STAGED_FILES`), [`scan.py:875`](https://github.com/Cezar277/heimdall/blob/d3785510262b77a606bb94b64931ce8c1bde3782/heimdall/cli/scan.py#L875) | [`test_cli_scan_diff.py:387`](https://github.com/Cezar277/heimdall/blob/d3785510262b77a606bb94b64931ce8c1bde3782/tests/test_cli_scan_diff.py#L387) (trop de fichiers → 2), [`375`](https://github.com/Cezar277/heimdall/blob/d3785510262b77a606bb94b64931ce8c1bde3782/tests/test_cli_scan_diff.py#L375) (binaire → 2) |
| Aucune exclusion de chemin ; suppressions et gitlinks ignorés ; blob entier analysé | [`gitdiff.py:680`](https://github.com/Cezar277/heimdall/blob/d3785510262b77a606bb94b64931ce8c1bde3782/heimdall/mcp/gitdiff.py#L680) (`diff_changes` → `parse_staged_raw`), [`gitdiff.py:950`](https://github.com/Cezar277/heimdall/blob/d3785510262b77a606bb94b64931ce8c1bde3782/heimdall/mcp/gitdiff.py#L950) (`_staged_change`) | [`test_cli_scan_diff.py:133`](https://github.com/Cezar277/heimdall/blob/d3785510262b77a606bb94b64931ce8c1bde3782/tests/test_cli_scan_diff.py#L133) (suppression), [`228`](https://github.com/Cezar277/heimdall/blob/d3785510262b77a606bb94b64931ce8c1bde3782/tests/test_cli_scan_diff.py#L228) (blob entier, ligne 2) |
| Anti auto-attestation : en `--ci`, une configuration du dépôt est refusée ; `--config` externe ou `--no-allowlist` | [`scan.py:857`](https://github.com/Cezar277/heimdall/blob/d3785510262b77a606bb94b64931ce8c1bde3782/heimdall/cli/scan.py#L857) (`_guard_anti_self_attestation`, `ci=True`), [`scan.py:866`](https://github.com/Cezar277/heimdall/blob/d3785510262b77a606bb94b64931ce8c1bde3782/heimdall/cli/scan.py#L866) (`load_allowlist`, `allow_external=True`) | [`test_cli_scan_diff.py:295`](https://github.com/Cezar277/heimdall/blob/d3785510262b77a606bb94b64931ce8c1bde3782/tests/test_cli_scan_diff.py#L295) (`heimdall.toml` interne → 2 ; `--no-allowlist` → 1) |
| Modèles GitHub Actions et GitLab CI avec historique complet et commande différentielle | [`github-actions.yml:30`](https://github.com/Cezar277/heimdall/blob/d3785510262b77a606bb94b64931ce8c1bde3782/docs/ci/github-actions.yml#L30), [`github-actions.yml:44`](https://github.com/Cezar277/heimdall/blob/d3785510262b77a606bb94b64931ce8c1bde3782/docs/ci/github-actions.yml#L44), [`gitlab-ci.yml:16`](https://github.com/Cezar277/heimdall/blob/d3785510262b77a606bb94b64931ce8c1bde3782/docs/ci/gitlab-ci.yml#L16), [`gitlab-ci.yml:27`](https://github.com/Cezar277/heimdall/blob/d3785510262b77a606bb94b64931ce8c1bde3782/docs/ci/gitlab-ci.yml#L27) | [`test_ci_templates.py:24`](https://github.com/Cezar277/heimdall/blob/d3785510262b77a606bb94b64931ce8c1bde3782/tests/test_ci_templates.py#L24), [`40`](https://github.com/Cezar277/heimdall/blob/d3785510262b77a606bb94b64931ce8c1bde3782/tests/test_ci_templates.py#L40) |

## Critères d'acceptation

| Critère | Preuve |
| --- | --- |
| Job rouge sur un dépôt piégé | `test_scan_diff_detects_a_secret_added_on_the_branch` : secret AWS synthétique ajouté sur la branche → code 1, Finding `new.py:1`, secret absent de stdout/stderr. |
| Job vert sur un dépôt propre | `test_scan_diff_clean_branch_exits_zero` : branche sans secret → code 0. |
| Différentiel réel (pas un scan d'arbre) | `test_scan_diff_ignores_a_secret_outside_the_diff` : secret présent dans la base, absent du diff → code 0. |
| Clone superficiel | `test_scan_diff_shallow_clone_exits_two` : clone `--depth 1`, merge-base absent → code 2. |
| JSON | `test_scan_diff_json_contract` + `test_scan_ci_json_diff_matches_the_schema` : `scope: "diff"`, `count` cohérent, schéma validé. |

## Résultat local

```text
3096 passed, 17 skipped, 6006 subtests passed
TOTAL coverage: 91.08 % (seuil 85 %)
ruff check heimdall tests scripts : OK
mypy heimdall tests/contracts/fastapi_contract_fixture.py scripts/regen_lock.py : OK
bandit -r heimdall -q : OK
```

## Limite de périmètre

La sortie machine livrée est le **JSON** `heimdall.scan.v1` (déjà le contrat
de #29) : le ticket demande « JSON ou SARIF », et le JSON suffit pour le
verdict CI et l'archivage. SARIF n'est pas ajouté ici ; il pourra l'être
dans un ticket dédié si un outil de code scanning l'exige, sans changer le
verdict ni les codes de sortie.

Les modèles `docs/ci/` sont des modèles à copier : ils ne sont pas exécutés
par la CI de ce dépôt (qui utilise ses propres workflows). Leur contenu est
figé par `tests/test_ci_templates.py` (historique complet, commande
`--ci --diff`, `--no-allowlist`, permissions minimales).
