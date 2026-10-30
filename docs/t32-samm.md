# Preuves T32 — validation humaine

Snapshot vérifié : `aedcc87`. Chaque lien ci-dessous a été résolu sur ce
commit (module + ligne), pas sur une branche mouvante.

## T32.1 / #87 : rendu avant/après

- Validation des chemins et exclusion des fichiers privés, **insensible à la
  casse** (`.Git/config`, `.ENV`, `.Env.local`) :
  [TextChange](https://github.com/Cezar277/heimdall/blob/aedcc8725483620b6957a63d9e7efb553f1edc6b/heimdall/cli/review.py#L77).
- Valeurs exclues des représentations, proposition bornée et total des
  valeurs borné (`MAX_SECRET_BYTES`) :
  [Proposal](https://github.com/Cezar277/heimdall/blob/aedcc8725483620b6957a63d9e7efb553f1edc6b/heimdall/cli/review.py#L105).
- Masquage avant diff, motif compilé une fois, `re.error` convertie en
  erreur statique, échappement des contrôles terminal :
  [_secret_pattern](https://github.com/Cezar277/heimdall/blob/aedcc8725483620b6957a63d9e7efb553f1edc6b/heimdall/cli/review.py#L150),
  [_masked](https://github.com/Cezar277/heimdall/blob/aedcc8725483620b6957a63d9e7efb553f1edc6b/heimdall/cli/review.py#L166),
  [render_diff](https://github.com/Cezar277/heimdall/blob/aedcc8725483620b6957a63d9e7efb553f1edc6b/heimdall/cli/review.py#L183).
- Preuves : [masquage de tous les fichiers](https://github.com/Cezar277/heimdall/blob/aedcc8725483620b6957a63d9e7efb553f1edc6b/tests/test_cli_review.py#L67),
  [valeurs courtes et chevauchantes](https://github.com/Cezar277/heimdall/blob/aedcc8725483620b6957a63d9e7efb553f1edc6b/tests/test_cli_review.py#L122),
  [chemins refusés](https://github.com/Cezar277/heimdall/blob/aedcc8725483620b6957a63d9e7efb553f1edc6b/tests/test_cli_review.py#L105),
  [chemins privés insensibles à la casse](https://github.com/Cezar277/heimdall/blob/aedcc8725483620b6957a63d9e7efb553f1edc6b/tests/test_cli_review.py#L733),
  [motif de masquage borné](https://github.com/Cezar277/heimdall/blob/aedcc8725483620b6957a63d9e7efb553f1edc6b/tests/test_cli_review.py#L696),
  [256 valeurs longues acceptées](https://github.com/Cezar277/heimdall/blob/aedcc8725483620b6957a63d9e7efb553f1edc6b/tests/test_cli_review.py#L701).
- Menaces : divulgation de secrets et falsification de l'affichage terminal.
- Documentation : `docs/interactive-review.md`.

## T32.2 / #88 : boucle Y/N/E

- Trois actions fermées, aucune par défaut :
  [Choice et parse_choice](https://github.com/Cezar277/heimdall/blob/aedcc8725483620b6957a63d9e7efb553f1edc6b/heimdall/cli/review.py#L210).
- Boucle bornée, backend T30 injecté, exceptions backend converties en
  `ReviewError` statique, journal écrit **après** l'action avec `applied` :
  [review_proposal](https://github.com/Cezar277/heimdall/blob/aedcc8725483620b6957a63d9e7efb553f1edc6b/heimdall/cli/review.py#L532).
- Choix journalisé (fichier, ligne, action, date, résultat), jamais la
  valeur : [Decision](https://github.com/Cezar277/heimdall/blob/aedcc8725483620b6957a63d9e7efb553f1edc6b/heimdall/cli/review.py#L255),
  [DecisionJournal](https://github.com/Cezar277/heimdall/blob/aedcc8725483620b6957a63d9e7efb553f1edc6b/heimdall/cli/review.py#L356).
- Preuves : [Y applique puis journalise applied=true](https://github.com/Cezar277/heimdall/blob/aedcc8725483620b6957a63d9e7efb553f1edc6b/tests/test_cli_review.py#L660),
  [N n'appelle jamais le backend](https://github.com/Cezar277/heimdall/blob/aedcc8725483620b6957a63d9e7efb553f1edc6b/tests/test_cli_review.py#L180),
  [E réaffiche puis valide](https://github.com/Cezar277/heimdall/blob/aedcc8725483620b6957a63d9e7efb553f1edc6b/tests/test_cli_review.py#L196),
  [entrée invalide redemandée](https://github.com/Cezar277/heimdall/blob/aedcc8725483620b6957a63d9e7efb553f1edc6b/tests/test_cli_review.py#L220),
  [épuisement borné](https://github.com/Cezar277/heimdall/blob/aedcc8725483620b6957a63d9e7efb553f1edc6b/tests/test_cli_review.py#L239),
  [refus sans backend](https://github.com/Cezar277/heimdall/blob/aedcc8725483620b6957a63d9e7efb553f1edc6b/tests/test_cli_review.py#L256),
  [échec apply : erreur statique + journal applied=false](https://github.com/Cezar277/heimdall/blob/aedcc8725483620b6957a63d9e7efb553f1edc6b/tests/test_cli_review.py#L623),
  [échec edit : erreur statique + journal applied=false](https://github.com/Cezar277/heimdall/blob/aedcc8725483620b6957a63d9e7efb553f1edc6b/tests/test_cli_review.py#L643),
  [édition annulée](https://github.com/Cezar277/heimdall/blob/aedcc8725483620b6957a63d9e7efb553f1edc6b/tests/test_cli_review.py#L275),
  [boucle d'édition bornée](https://github.com/Cezar277/heimdall/blob/aedcc8725483620b6957a63d9e7efb553f1edc6b/tests/test_cli_review.py#L294),
  [journal falsifié détecté](https://github.com/Cezar277/heimdall/blob/aedcc8725483620b6957a63d9e7efb553f1edc6b/tests/test_cli_review.py#L381),
  [applied incohérent refusé](https://github.com/Cezar277/heimdall/blob/aedcc8725483620b6957a63d9e7efb553f1edc6b/tests/test_cli_review.py#L742),
  [permissions 0600](https://github.com/Cezar277/heimdall/blob/aedcc8725483620b6957a63d9e7efb553f1edc6b/tests/test_cli_review.py#L394),
  [EOF interrompt sans journal](https://github.com/Cezar277/heimdall/blob/aedcc8725483620b6957a63d9e7efb553f1edc6b/tests/test_cli_review.py#L506).
- Menaces : auto-validation implicite (STRIDE Elevation of Privilege),
  écriture non traçable ou audit mensonger (Repudiation), fuite de valeur
  par le message d'une exception backend (Information Disclosure).
- Limite assumée : `apply`/`edit` restent à livrer par T30 (#83–#86) ; sans
  backend, `Y`/`E` échouent en code 2 au lieu d'écrire.

## T32.3 / #89 : mode non interactif

- `ci` prioritaire, `interactive=True` **insuffisant** sans TTY, refus par
  défaut de tout TTY douteux (dont `BaseException`) :
  [is_interactive](https://github.com/Cezar277/heimdall/blob/aedcc8725483620b6957a63d9e7efb553f1edc6b/heimdall/cli/review.py#L455),
  [review_proposals](https://github.com/Cezar277/heimdall/blob/aedcc8725483620b6957a63d9e7efb553f1edc6b/heimdall/cli/review.py#L613).
- Rapport seul, décompte et statut sans écriture :
  [ReviewReport](https://github.com/Cezar277/heimdall/blob/aedcc8725483620b6957a63d9e7efb553f1edc6b/heimdall/cli/review.py#L494),
  [_status](https://github.com/Cezar277/heimdall/blob/aedcc8725483620b6957a63d9e7efb553f1edc6b/heimdall/cli/review.py#L522).
- Preuves : [aucun appel backend/journal](https://github.com/Cezar277/heimdall/blob/aedcc8725483620b6957a63d9e7efb553f1edc6b/tests/test_cli_review.py#L316),
  [ci gagne sur interactive](https://github.com/Cezar277/heimdall/blob/aedcc8725483620b6957a63d9e7efb553f1edc6b/tests/test_cli_review.py#L333),
  [interactive=True sur stdin pipé](https://github.com/Cezar277/heimdall/blob/aedcc8725483620b6957a63d9e7efb553f1edc6b/tests/test_cli_review.py#L575),
  [review_proposal seul sans TTY](https://github.com/Cezar277/heimdall/blob/aedcc8725483620b6957a63d9e7efb553f1edc6b/tests/test_cli_review.py#L606),
  [stdin par défaut sans TTY](https://github.com/Cezar277/heimdall/blob/aedcc8725483620b6957a63d9e7efb553f1edc6b/tests/test_cli_review.py#L594),
  [TTY absent/faux/en erreur](https://github.com/Cezar277/heimdall/blob/aedcc8725483620b6957a63d9e7efb553f1edc6b/tests/test_cli_review.py#L352),
  [isatty en RuntimeError](https://github.com/Cezar277/heimdall/blob/aedcc8725483620b6957a63d9e7efb553f1edc6b/tests/test_cli_review.py#L688),
  [isatty en KeyboardInterrupt/SystemExit](https://github.com/Cezar277/heimdall/blob/aedcc8725483620b6957a63d9e7efb553f1edc6b/tests/test_cli_review.py#L819),
  [OSError/KeyboardInterrupt statiques](https://github.com/Cezar277/heimdall/blob/aedcc8725483620b6957a63d9e7efb553f1edc6b/tests/test_cli_review.py#L671),
  [scan --ci laisse git status propre](https://github.com/Cezar277/heimdall/blob/aedcc8725483620b6957a63d9e7efb553f1edc6b/tests/test_cli_review.py#L420).
- Menace : auto-validation sans humain (STRIDE Elevation of Privilege).
- Code de sortie attendu : 0 si `remaining == 0`, 1 si des propositions
  restent, 2 sur erreur d'outillage.

## T32.4 / #90 : tests du flux interactif

- Clavier simulé par injection de `ask` (alternative documentée au
  `CliRunner(input=...)`), un test par action plus les cas d'erreur :
  [tests/test_cli_review.py](https://github.com/Cezar277/heimdall/blob/aedcc8725483620b6957a63d9e7efb553f1edc6b/tests/test_cli_review.py#L162).
- Un test `CliRunner` réel couvre le mode CI sans écriture :
  [scan --ci](https://github.com/Cezar277/heimdall/blob/aedcc8725483620b6957a63d9e7efb553f1edc6b/tests/test_cli_review.py#L420).
- Validation locale : `python -m pytest tests/test_cli_review.py` :
  **98 passed** ; couverture `heimdall/cli/review.py` **95 %**.
- `ruff check`, `mypy` strict (47 fichiers) et `bandit -r heimdall` : OK.
- Suite complète : **2310 passed**, **15 skipped**, **4480 subtests passed**.
- Documentation : `docs/interactive-review.md`. CI non déclenchée, sur demande.

## Correctifs des revues de code

### Revue 1 — HIGH et MEDIUM (`50536ec`)

| Constat | Correctif | Preuve |
| --- | --- | --- |
| [HIGH] `interactive=True` contournait le TTY | `is_interactive` exigé en plus du drapeau | [stdin pipé](https://github.com/Cezar277/heimdall/blob/aedcc8725483620b6957a63d9e7efb553f1edc6b/tests/test_cli_review.py#L575), [review_proposal seul](https://github.com/Cezar277/heimdall/blob/aedcc8725483620b6957a63d9e7efb553f1edc6b/tests/test_cli_review.py#L606) |
| [HIGH] exceptions backend brutes + journal mensonger | `ReviewError from None` + `applied: bool` écrit après l'action | [échec apply](https://github.com/Cezar277/heimdall/blob/aedcc8725483620b6957a63d9e7efb553f1edc6b/tests/test_cli_review.py#L623), [échec edit](https://github.com/Cezar277/heimdall/blob/aedcc8725483620b6957a63d9e7efb553f1edc6b/tests/test_cli_review.py#L643), [applied incohérent](https://github.com/Cezar277/heimdall/blob/aedcc8725483620b6957a63d9e7efb553f1edc6b/tests/test_cli_review.py#L742) |
| [MEDIUM] motif de masquage géant | total borné, compilation unique, `re.error` statique | [motif borné](https://github.com/Cezar277/heimdall/blob/aedcc8725483620b6957a63d9e7efb553f1edc6b/tests/test_cli_review.py#L696), [256 valeurs](https://github.com/Cezar277/heimdall/blob/aedcc8725483620b6957a63d9e7efb553f1edc6b/tests/test_cli_review.py#L701) |
| [MEDIUM] grammaire de variable trop lâche | `[A-Z][A-Z0-9_]{1,63}` pour `_VARIABLE` et `_ENV_REFERENCE` | [grammaire invariant 2](https://github.com/Cezar277/heimdall/blob/aedcc8725483620b6957a63d9e7efb553f1edc6b/tests/test_cli_review.py#L716), [références d'environnement](https://github.com/Cezar277/heimdall/blob/aedcc8725483620b6957a63d9e7efb553f1edc6b/tests/test_cli_review.py#L721) |
| [LOW] casse des gardes `.env`/`.git` | comparaison `lower()` | [chemins privés insensibles à la casse](https://github.com/Cezar277/heimdall/blob/aedcc8725483620b6957a63d9e7efb553f1edc6b/tests/test_cli_review.py#L733) |
| [LOW] exceptions `input`/`isatty` trop étroites | `OSError`/`ValueError`/`KeyboardInterrupt` → statique ; `isatty` en erreur → non interactif | [OSError/KeyboardInterrupt](https://github.com/Cezar277/heimdall/blob/aedcc8725483620b6957a63d9e7efb553f1edc6b/tests/test_cli_review.py#L671), [RuntimeError](https://github.com/Cezar277/heimdall/blob/aedcc8725483620b6957a63d9e7efb553f1edc6b/tests/test_cli_review.py#L688) |

### Revue 2 — LOW sur les points d'injection (`aedcc87`)

| Constat | Correctif | Preuve |
| --- | --- | --- |
| [LOW] exceptions d'un `ask`/`notify` injecté non normalisées | [_ask](https://github.com/Cezar277/heimdall/blob/aedcc8725483620b6957a63d9e7efb553f1edc6b/heimdall/cli/review.py#L426) convertit toute exception (hors `ReviewError`) en erreur statique ; [_notify](https://github.com/Cezar277/heimdall/blob/aedcc8725483620b6957a63d9e7efb553f1edc6b/heimdall/cli/review.py#L441) reste best-effort et ne laisse rien ressortir | [ask en OSError](https://github.com/Cezar277/heimdall/blob/aedcc8725483620b6957a63d9e7efb553f1edc6b/tests/test_cli_review.py#L765), [ReviewError préservée](https://github.com/Cezar277/heimdall/blob/aedcc8725483620b6957a63d9e7efb553f1edc6b/tests/test_cli_review.py#L783), [notify en OSError](https://github.com/Cezar277/heimdall/blob/aedcc8725483620b6957a63d9e7efb553f1edc6b/tests/test_cli_review.py#L795) |
| [LOW] `is_interactive` laissait passer `BaseException` | `except BaseException` → refus par défaut | [KeyboardInterrupt/SystemExit](https://github.com/Cezar277/heimdall/blob/aedcc8725483620b6957a63d9e7efb553f1edc6b/tests/test_cli_review.py#L819) |
| Garde de chemin du journal non couverte pour ce journal | `_prepare_path` de T33 refusé aussi ici | [relatif et `..`](https://github.com/Cezar277/heimdall/blob/aedcc8725483620b6957a63d9e7efb553f1edc6b/tests/test_cli_review.py#L828) |

Hors périmètre, signalé et non corrigé ici : le câblage CLI `heimdall review`
et ses codes de sortie 0/1/2 arrivent avec le backend T30 (#83–#86) ; le
regroupement de #87–#90 dans une seule PR est une exception demandée par
l'utilisateur, tracée dans la PR #192.
