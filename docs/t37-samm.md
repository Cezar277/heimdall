# T37 — Mode CI headless : preuves SAMM

Ticket : #37 (épic #6 « CLI, hook et CI headless »).

SHA de référence du code : `ec2ec49bdc11be279c060b46f18cd5c137b15289`
(le commit de documentation qui suit ne modifie que ce fichier).

## Garanties et preuves

| Garantie | Implémentation | Preuve automatisée |
| --- | --- | --- |
| Analyse **différentielle** à trois points : seuls les changements de la branche courante sont jugés | [`gitdiff.py:680`](https://github.com/Cezar277/heimdall/blob/ec2ec49bdc11be279c060b46f18cd5c137b15289/heimdall/mcp/gitdiff.py#L680) (`diff_changes`, `base...head`), [`scan.py:826`](https://github.com/Cezar277/heimdall/blob/ec2ec49bdc11be279c060b46f18cd5c137b15289/heimdall/cli/scan.py#L826) (`_collect_diff`) | [`test_cli_scan_diff.py:136`](https://github.com/Cezar277/heimdall/blob/ec2ec49bdc11be279c060b46f18cd5c137b15289/tests/test_cli_scan_diff.py#L136) (secret de la branche cible absent), [`230`](https://github.com/Cezar277/heimdall/blob/ec2ec49bdc11be279c060b46f18cd5c137b15289/tests/test_cli_scan_diff.py#L230) (secret hors diff), [`247`](https://github.com/Cezar277/heimdall/blob/ec2ec49bdc11be279c060b46f18cd5c137b15289/tests/test_cli_scan_diff.py#L247) (secret supprimé) |
| Référence validée avant tout appel git, puis résolue en SHA complet | [`gitdiff.py:871`](https://github.com/Cezar277/heimdall/blob/ec2ec49bdc11be279c060b46f18cd5c137b15289/heimdall/mcp/gitdiff.py#L871) (`_checked_ref`), [`gitdiff.py:649`](https://github.com/Cezar277/heimdall/blob/ec2ec49bdc11be279c060b46f18cd5c137b15289/heimdall/mcp/gitdiff.py#L649) (`resolve_commit`), [`gitdiff.py:123`](https://github.com/Cezar277/heimdall/blob/ec2ec49bdc11be279c060b46f18cd5c137b15289/heimdall/mcp/gitdiff.py#L123) (`DIFF_RAW_ARGUMENTS`), [`gitdiff.py:864`](https://github.com/Cezar277/heimdall/blob/ec2ec49bdc11be279c060b46f18cd5c137b15289/heimdall/mcp/gitdiff.py#L864) (`MAX_REF_BYTES` = 256) | [`test_cli_scan_diff.py:76`](https://github.com/Cezar277/heimdall/blob/ec2ec49bdc11be279c060b46f18cd5c137b15289/tests/test_cli_scan_diff.py#L76), [`100`](https://github.com/Cezar277/heimdall/blob/ec2ec49bdc11be279c060b46f18cd5c137b15289/tests/test_cli_scan_diff.py#L100), [`121`](https://github.com/Cezar277/heimdall/blob/ec2ec49bdc11be279c060b46f18cd5c137b15289/tests/test_cli_scan_diff.py#L121) (`-x`, `--help`, `..`, `@{1}`, espaces, `//`, `.hidden`, `.lock`, `~`, `^`, `:`, `?`, `*`, `[`, `\`) ; [`85`](https://github.com/Cezar277/heimdall/blob/ec2ec49bdc11be279c060b46f18cd5c137b15289/tests/test_cli_scan_diff.py#L85) (`@` = `HEAD`, accepté), [`92`](https://github.com/Cezar277/heimdall/blob/ec2ec49bdc11be279c060b46f18cd5c137b15289/tests/test_cli_scan_diff.py#L92) (référence > 256 octets refusée) |
| `HEAD` figé en SHA et re-résolu après l'analyse : un commit déplacé refuse le verdict | [`scan.py:859`](https://github.com/Cezar277/heimdall/blob/ec2ec49bdc11be279c060b46f18cd5c137b15289/heimdall/cli/scan.py#L859), [`scan.py:887`](https://github.com/Cezar277/heimdall/blob/ec2ec49bdc11be279c060b46f18cd5c137b15289/heimdall/cli/scan.py#L887) | [`test_cli_scan_diff.py:439`](https://github.com/Cezar277/heimdall/blob/ec2ec49bdc11be279c060b46f18cd5c137b15289/tests/test_cli_scan_diff.py#L439) |
| Clone superficiel sans ancêtre commun : code 2, jamais un faux vert | [`gitdiff.py:680`](https://github.com/Cezar277/heimdall/blob/ec2ec49bdc11be279c060b46f18cd5c137b15289/heimdall/mcp/gitdiff.py#L680) (git échoue sur `base...head`), [`scan.py:858`](https://github.com/Cezar277/heimdall/blob/ec2ec49bdc11be279c060b46f18cd5c137b15289/heimdall/cli/scan.py#L858) | [`test_cli_scan_diff.py:403`](https://github.com/Cezar277/heimdall/blob/ec2ec49bdc11be279c060b46f18cd5c137b15289/tests/test_cli_scan_diff.py#L403) (vrai `git clone --depth 1 --no-single-branch`) ; modèles [`github-actions.yml:30`](https://github.com/Cezar277/heimdall/blob/ec2ec49bdc11be279c060b46f18cd5c137b15289/docs/ci/github-actions.yml#L30) (`fetch-depth: 0`) et [`gitlab-ci.yml:16`](https://github.com/Cezar277/heimdall/blob/ec2ec49bdc11be279c060b46f18cd5c137b15289/docs/ci/gitlab-ci.yml#L16) (`GIT_DEPTH: "0"`) |
| Mode strictement **headless** : `--diff` exige `--ci`, aucun LLM, aucun réseau | [`main.py:129`](https://github.com/Cezar277/heimdall/blob/ec2ec49bdc11be279c060b46f18cd5c137b15289/heimdall/cli/main.py#L129) (`--diff`), [`main.py:177`](https://github.com/Cezar277/heimdall/blob/ec2ec49bdc11be279c060b46f18cd5c137b15289/heimdall/cli/main.py#L177) (exige `--ci`), [`scan.py:826`](https://github.com/Cezar277/heimdall/blob/ec2ec49bdc11be279c060b46f18cd5c137b15289/heimdall/cli/scan.py#L826) | [`test_cli_scan_diff.py:259`](https://github.com/Cezar277/heimdall/blob/ec2ec49bdc11be279c060b46f18cd5c137b15289/tests/test_cli_scan_diff.py#L259) (`--diff` sans `--ci` → 2) ; le module `scan` n'importe aucun client LLM |
| Verdict par code de sortie : 0 propre, 1 secret, 2 outillage | [`main.py:177`](https://github.com/Cezar277/heimdall/blob/ec2ec49bdc11be279c060b46f18cd5c137b15289/heimdall/cli/main.py#L177), [`scan.py:894`](https://github.com/Cezar277/heimdall/blob/ec2ec49bdc11be279c060b46f18cd5c137b15289/heimdall/cli/scan.py#L894) | [`test_cli_scan_diff.py:189`](https://github.com/Cezar277/heimdall/blob/ec2ec49bdc11be279c060b46f18cd5c137b15289/tests/test_cli_scan_diff.py#L189) (1), [`204`](https://github.com/Cezar277/heimdall/blob/ec2ec49bdc11be279c060b46f18cd5c137b15289/tests/test_cli_scan_diff.py#L204) (0), [`296`](https://github.com/Cezar277/heimdall/blob/ec2ec49bdc11be279c060b46f18cd5c137b15289/tests/test_cli_scan_diff.py#L296) (2) |
| Sortie machine JSON `heimdall.scan.v1`, `scope: "diff"`, sans secret | [`scan.py:80`](https://github.com/Cezar277/heimdall/blob/ec2ec49bdc11be279c060b46f18cd5c137b15289/heimdall/cli/scan.py#L80) (`SCOPE_DIFF`), [`scan.py:894`](https://github.com/Cezar277/heimdall/blob/ec2ec49bdc11be279c060b46f18cd5c137b15289/heimdall/cli/scan.py#L894), [`schemas/scan.schema.json`](https://github.com/Cezar277/heimdall/blob/ec2ec49bdc11be279c060b46f18cd5c137b15289/schemas/scan.schema.json) (enum `diff`) | [`test_cli_scan_diff.py:305`](https://github.com/Cezar277/heimdall/blob/ec2ec49bdc11be279c060b46f18cd5c137b15289/tests/test_cli_scan_diff.py#L305), [`test_cli_scan.py:2173`](https://github.com/Cezar277/heimdall/blob/ec2ec49bdc11be279c060b46f18cd5c137b15289/tests/test_cli_scan.py#L2173) (validation du schéma) |
| Mêmes bornes que `--staged` : 1 000 fichiers, 32 Mio, 10 000 Findings, 120 s | [`scan.py:667`](https://github.com/Cezar277/heimdall/blob/ec2ec49bdc11be279c060b46f18cd5c137b15289/heimdall/cli/scan.py#L667) (`_scan_changes`), [`scan.py:861`](https://github.com/Cezar277/heimdall/blob/ec2ec49bdc11be279c060b46f18cd5c137b15289/heimdall/cli/scan.py#L861) (`MAX_STAGED_FILES`), [`scan.py:886`](https://github.com/Cezar277/heimdall/blob/ec2ec49bdc11be279c060b46f18cd5c137b15289/heimdall/cli/scan.py#L886) | [`test_cli_scan_diff.py:478`](https://github.com/Cezar277/heimdall/blob/ec2ec49bdc11be279c060b46f18cd5c137b15289/tests/test_cli_scan_diff.py#L478) (trop de fichiers → 2), [`466`](https://github.com/Cezar277/heimdall/blob/ec2ec49bdc11be279c060b46f18cd5c137b15289/tests/test_cli_scan_diff.py#L466) (binaire → 2) |
| Aucune exclusion de chemin ; suppressions et gitlinks ignorés ; blob entier analysé | [`gitdiff.py:680`](https://github.com/Cezar277/heimdall/blob/ec2ec49bdc11be279c060b46f18cd5c137b15289/heimdall/mcp/gitdiff.py#L680) (`diff_changes` → `parse_staged_raw`), [`gitdiff.py:950`](https://github.com/Cezar277/heimdall/blob/ec2ec49bdc11be279c060b46f18cd5c137b15289/heimdall/mcp/gitdiff.py#L950) (`_staged_change`) | [`test_cli_scan_diff.py:155`](https://github.com/Cezar277/heimdall/blob/ec2ec49bdc11be279c060b46f18cd5c137b15289/tests/test_cli_scan_diff.py#L155) (suppression), [`263`](https://github.com/Cezar277/heimdall/blob/ec2ec49bdc11be279c060b46f18cd5c137b15289/tests/test_cli_scan_diff.py#L263) (blob entier, ligne 2) |
| Anti auto-attestation : en `--ci`, une configuration du dépôt est refusée ; `--config` externe ou `--no-allowlist` | [`scan.py:868`](https://github.com/Cezar277/heimdall/blob/ec2ec49bdc11be279c060b46f18cd5c137b15289/heimdall/cli/scan.py#L868) (`_guard_anti_self_attestation`, `ci=True`), [`scan.py:880`](https://github.com/Cezar277/heimdall/blob/ec2ec49bdc11be279c060b46f18cd5c137b15289/heimdall/cli/scan.py#L880) (`load_allowlist`, `allow_external=True`) | [`test_cli_scan_diff.py:330`](https://github.com/Cezar277/heimdall/blob/ec2ec49bdc11be279c060b46f18cd5c137b15289/tests/test_cli_scan_diff.py#L330) (`heimdall.toml` interne → 2 ; `--no-allowlist` → 1), [`347`](https://github.com/Cezar277/heimdall/blob/ec2ec49bdc11be279c060b46f18cd5c137b15289/tests/test_cli_scan_diff.py#L347) (`--config` externe → verdict normal), [`378`](https://github.com/Cezar277/heimdall/blob/ec2ec49bdc11be279c060b46f18cd5c137b15289/tests/test_cli_scan_diff.py#L378) et [`393`](https://github.com/Cezar277/heimdall/blob/ec2ec49bdc11be279c060b46f18cd5c137b15289/tests/test_cli_scan_diff.py#L393) (contrat API `collect(diff=...)`, y compris `diff=""`) |
| Modèles GitHub Actions et GitLab CI avec historique complet et commande différentielle | [`github-actions.yml:30`](https://github.com/Cezar277/heimdall/blob/ec2ec49bdc11be279c060b46f18cd5c137b15289/docs/ci/github-actions.yml#L30), [`github-actions.yml:50`](https://github.com/Cezar277/heimdall/blob/ec2ec49bdc11be279c060b46f18cd5c137b15289/docs/ci/github-actions.yml#L50), [`gitlab-ci.yml:16`](https://github.com/Cezar277/heimdall/blob/ec2ec49bdc11be279c060b46f18cd5c137b15289/docs/ci/gitlab-ci.yml#L16), [`gitlab-ci.yml:25`](https://github.com/Cezar277/heimdall/blob/ec2ec49bdc11be279c060b46f18cd5c137b15289/docs/ci/gitlab-ci.yml#L25) (`git fetch ... -- <ref>`) ; [`github-actions.yml:45`](https://github.com/Cezar277/heimdall/blob/ec2ec49bdc11be279c060b46f18cd5c137b15289/docs/ci/github-actions.yml#L45) (`BASE_REF` via env, pas d'interpolation GHA dans le script) ; [`gitlab-ci.yml:27`](https://github.com/Cezar277/heimdall/blob/ec2ec49bdc11be279c060b46f18cd5c137b15289/docs/ci/gitlab-ci.yml#L27) | [`test_ci_templates.py:24`](https://github.com/Cezar277/heimdall/blob/ec2ec49bdc11be279c060b46f18cd5c137b15289/tests/test_ci_templates.py#L24), [`43`](https://github.com/Cezar277/heimdall/blob/ec2ec49bdc11be279c060b46f18cd5c137b15289/tests/test_ci_templates.py#L43) |

| Plage vide observable : `--diff HEAD` affiche 0 fichier analysé, distinct d'un diff propre | [`scan.py:170`](https://github.com/Cezar277/heimdall/blob/ec2ec49bdc11be279c060b46f18cd5c137b15289/heimdall/cli/scan.py#L170) (`ScanReport.scanned_files`, hors JSON v1), [`main.py:209`](https://github.com/Cezar277/heimdall/blob/ec2ec49bdc11be279c060b46f18cd5c137b15289/heimdall/cli/main.py#L209) (résumé `--ci`) | [`test_cli_scan_diff.py:218`](https://github.com/Cezar277/heimdall/blob/ec2ec49bdc11be279c060b46f18cd5c137b15289/tests/test_cli_scan_diff.py#L218) (plage vide → 0 fichier), [`204`](https://github.com/Cezar277/heimdall/blob/ec2ec49bdc11be279c060b46f18cd5c137b15289/tests/test_cli_scan_diff.py#L204) (diff propre → 1 fichier) |

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
3103 passed, 17 skipped, 6006 subtests passed
TOTAL coverage: 91.13 % (seuil 85 %)
ruff check heimdall tests scripts : OK
mypy heimdall tests/contracts/fastapi_contract_fixture.py scripts/regen_lock.py : OK
bandit -r heimdall -q : OK
```

## Limites connues

- **Tip-only** : `--diff` compare `merge-base...HEAD`, donc l'état **final**
  de la branche. Un secret introduit puis supprimé ou réécrit dans un commit
  intermédiaire n'est pas dans le diff final ; il reste dans l'historique de
  la branche et peut atterrir dans `main` si le merge n'est pas un squash.
  Mitigation : squash-merge ou `heimdall deep-scan` (#108–#110). Le hook
  local `--staged` voit chaque commit, mais il est contournable
  (`--no-verify`) : la CI reste la barrière. Voir `docs/cli.md` « Limites
  connues » et `docs/ci/README.md` « Merge non-squash ».

## Limite de périmètre

La sortie machine livrée est le **JSON** `heimdall.scan.v1` (déjà le contrat
de #29) : le ticket demande « JSON ou SARIF », et le JSON suffit pour le
verdict CI et l'archivage. SARIF n'est pas ajouté ici ; il pourra l'être
dans un ticket dédié si un outil de code scanning l'exige, sans changer le
verdict ni les codes de sortie.

Les modèles `docs/ci/` sont des modèles à copier : ils ne sont pas exécutés
par la CI de ce dépôt (qui utilise ses propres workflows). Leur contenu est
figé par `tests/test_ci_templates.py` (historique complet, commande
`--ci --diff`, `--no-allowlist`, permissions minimales, `BASE_REF` via
`env` et absence d'interpolation GHA dans le script).

`--diff HEAD` (ou une référence égale à `HEAD`) produit une **plage vide**
et donc un verdict 0 : c'est une misconfiguration, pas un scan complet.
C'est documenté dans `docs/cli.md` et `docs/ci/README.md` ; les modèles CI
utilisent toujours la branche cible.
