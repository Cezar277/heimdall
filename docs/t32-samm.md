# Preuves T32 — validation humaine

## T32.1 / #87 : rendu avant/après

- Validation des chemins et exclusion des fichiers privés :
  [TextChange](https://github.com/Cezar277/heimdall/blob/702883d/heimdall/cli/review.py#L48).
- Valeurs exclues des représentations et proposition bornée :
  [Proposal](https://github.com/Cezar277/heimdall/blob/702883d/heimdall/cli/review.py#L77).
- Masquage avant diff et échappement des contrôles terminal :
  [render_diff](https://github.com/Cezar277/heimdall/blob/702883d/heimdall/cli/review.py#L134).
- Validation locale : `python -m pytest tests/test_cli_review.py` : **16 passed**.
- `ruff check` : OK. `mypy` sur Windows rencontre deux erreurs préexistantes
  dans `heimdall/mcp/server.py:491` (`O_NOFOLLOW`, `O_CLOEXEC`).
- Menaces : divulgation de secrets et falsification de l'affichage terminal.
- Documentation : `docs/interactive-review.md`. CI non déclenchée, sur demande.
