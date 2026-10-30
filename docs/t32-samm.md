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

## T32.2 / #88 : boucle Y/N/E

- Trois actions fermées, aucune par défaut :
  [Choice et parse_choice](https://github.com/Cezar277/heimdall/blob/baa75960a4a81363c0aff1b8eacab6e8dde9b77e/heimdall/cli/review.py#L186).
- Boucle bornée, journal avant application, backend T30 injecté :
  [review_proposal](https://github.com/Cezar277/heimdall/blob/baa75960a4a81363c0aff1b8eacab6e8dde9b77e/heimdall/cli/review.py#L460).
- Choix journalisé (fichier, ligne, action, date), jamais la valeur :
  [Decision](https://github.com/Cezar277/heimdall/blob/baa75960a4a81363c0aff1b8eacab6e8dde9b77e/heimdall/cli/review.py#L231),
  [DecisionJournal](https://github.com/Cezar277/heimdall/blob/baa75960a4a81363c0aff1b8eacab6e8dde9b77e/heimdall/cli/review.py#L320).
- Preuves : [Y applique après journalisation](https://github.com/Cezar277/heimdall/blob/baa75960a4a81363c0aff1b8eacab6e8dde9b77e/tests/test_cli_review.py#L149),
  [N n'appelle jamais le backend](https://github.com/Cezar277/heimdall/blob/baa75960a4a81363c0aff1b8eacab6e8dde9b77e/tests/test_cli_review.py#L167),
  [E réaffiche puis valide](https://github.com/Cezar277/heimdall/blob/baa75960a4a81363c0aff1b8eacab6e8dde9b77e/tests/test_cli_review.py#L176),
  [entrée invalide redemandée](https://github.com/Cezar277/heimdall/blob/baa75960a4a81363c0aff1b8eacab6e8dde9b77e/tests/test_cli_review.py#L195),
  [épuisement borné](https://github.com/Cezar277/heimdall/blob/baa75960a4a81363c0aff1b8eacab6e8dde9b77e/tests/test_cli_review.py#L213),
  [refus sans backend](https://github.com/Cezar277/heimdall/blob/baa75960a4a81363c0aff1b8eacab6e8dde9b77e/tests/test_cli_review.py#L229),
  [édition annulée](https://github.com/Cezar277/heimdall/blob/baa75960a4a81363c0aff1b8eacab6e8dde9b77e/tests/test_cli_review.py#L248),
  [boucle d'édition bornée](https://github.com/Cezar277/heimdall/blob/baa75960a4a81363c0aff1b8eacab6e8dde9b77e/tests/test_cli_review.py#L266),
  [journal falsifié détecté](https://github.com/Cezar277/heimdall/blob/baa75960a4a81363c0aff1b8eacab6e8dde9b77e/tests/test_cli_review.py#L345),
  [permissions 0600](https://github.com/Cezar277/heimdall/blob/baa75960a4a81363c0aff1b8eacab6e8dde9b77e/tests/test_cli_review.py#L358),
  [EOF interrompt sans journal](https://github.com/Cezar277/heimdall/blob/baa75960a4a81363c0aff1b8eacab6e8dde9b77e/tests/test_cli_review.py#L462).
- Menaces : auto-validation implicite (STRIDE Elevation of Privilege),
  écriture non traçable (Repudiation), fuite de valeur dans le journal ou
  l'affichage (Information Disclosure).
- Limite assumée : `apply`/`edit` restent à livrer par T30 (#83–#86) ; sans
  backend, `Y`/`E` échouent en code 2 au lieu d'écrire.

## T32.3 / #89 : mode non interactif

- `ci` prioritaire et refus par défaut de tout TTY douteux :
  [is_interactive](https://github.com/Cezar277/heimdall/blob/baa75960a4a81363c0aff1b8eacab6e8dde9b77e/heimdall/cli/review.py#L386),
  [review_proposals](https://github.com/Cezar277/heimdall/blob/baa75960a4a81363c0aff1b8eacab6e8dde9b77e/heimdall/cli/review.py#L524).
- Rapport seul, décompte et statut sans écriture :
  [ReviewReport](https://github.com/Cezar277/heimdall/blob/baa75960a4a81363c0aff1b8eacab6e8dde9b77e/heimdall/cli/review.py#L422),
  [_status](https://github.com/Cezar277/heimdall/blob/baa75960a4a81363c0aff1b8eacab6e8dde9b77e/heimdall/cli/review.py#L450).
- Preuves : [aucun appel backend/journal](https://github.com/Cezar277/heimdall/blob/baa75960a4a81363c0aff1b8eacab6e8dde9b77e/tests/test_cli_review.py#L280),
  [ci gagne sur interactive](https://github.com/Cezar277/heimdall/blob/baa75960a4a81363c0aff1b8eacab6e8dde9b77e/tests/test_cli_review.py#L297),
  [TTY absent/faux/en erreur](https://github.com/Cezar277/heimdall/blob/baa75960a4a81363c0aff1b8eacab6e8dde9b77e/tests/test_cli_review.py#L316),
  [`scan --ci` laisse `git status` propre](https://github.com/Cezar277/heimdall/blob/baa75960a4a81363c0aff1b8eacab6e8dde9b77e/tests/test_cli_review.py#L384).
- Menace : auto-validation sans humain (STRIDE Elevation of Privilege).
- Code de sortie attendu : 0 si `remaining == 0`, 1 si des propositions
  restent, 2 sur erreur d'outillage.

## T32.4 / #90 : tests du flux interactif

- Clavier simulé par injection de `ask` (alternative documentée au
  `CliRunner(input=...)`), un test par action plus les cas d'erreur :
  [tests/test_cli_review.py](https://github.com/Cezar277/heimdall/blob/baa75960a4a81363c0aff1b8eacab6e8dde9b77e/tests/test_cli_review.py#L149).
- Un test `CliRunner` réel couvre le mode CI sans écriture :
  [scan --ci](https://github.com/Cezar277/heimdall/blob/baa75960a4a81363c0aff1b8eacab6e8dde9b77e/tests/test_cli_review.py#L384).
- Validation locale : `python -m pytest tests/test_cli_review.py` :
  **67 passed** ; couverture `heimdall/cli/review.py` **96 %**.
- `ruff check`, `mypy` strict (47 fichiers) et `bandit -r heimdall` : OK.
- Suite complète : **2279 passed**, **15 skipped**, **4480 subtests passed**.
- Documentation : `docs/interactive-review.md`. CI non déclenchée, sur demande.
