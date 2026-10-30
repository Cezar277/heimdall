# Preuves T32 — validation humaine

Snapshot vérifié : `5ed7cf6`. Chaque lien ci-dessous a été résolu sur ce
commit (module + ligne), pas sur une branche mouvante.

## T32.1 / #87 : rendu avant/après

- Validation des chemins et exclusion des fichiers privés, **insensible à la
  casse** (`.Git/config`, `.ENV`, `.Env.local`) :
  [TextChange](https://github.com/Cezar277/heimdall/blob/5ed7cf661d88c77821cb2b158ca39f96ebf323e1/heimdall/cli/review.py#L79).
- Valeurs exclues des représentations, proposition bornée et total des
  valeurs borné (`MAX_SECRET_BYTES`) :
  [Proposal](https://github.com/Cezar277/heimdall/blob/5ed7cf661d88c77821cb2b158ca39f96ebf323e1/heimdall/cli/review.py#L107).
- Masquage avant diff, motif compilé une fois, `re.error` convertie en
  erreur statique, échappement des contrôles terminal :
  [_secret_pattern](https://github.com/Cezar277/heimdall/blob/5ed7cf661d88c77821cb2b158ca39f96ebf323e1/heimdall/cli/review.py#L152),
  [_masked](https://github.com/Cezar277/heimdall/blob/5ed7cf661d88c77821cb2b158ca39f96ebf323e1/heimdall/cli/review.py#L168),
  [render_diff](https://github.com/Cezar277/heimdall/blob/5ed7cf661d88c77821cb2b158ca39f96ebf323e1/heimdall/cli/review.py#L185).
- Preuves : [masquage de tous les fichiers](https://github.com/Cezar277/heimdall/blob/5ed7cf661d88c77821cb2b158ca39f96ebf323e1/tests/test_cli_review.py#L69),
  [valeurs courtes et chevauchantes](https://github.com/Cezar277/heimdall/blob/5ed7cf661d88c77821cb2b158ca39f96ebf323e1/tests/test_cli_review.py#L124),
  [chemins refusés](https://github.com/Cezar277/heimdall/blob/5ed7cf661d88c77821cb2b158ca39f96ebf323e1/tests/test_cli_review.py#L107),
  [chemins privés insensibles à la casse](https://github.com/Cezar277/heimdall/blob/5ed7cf661d88c77821cb2b158ca39f96ebf323e1/tests/test_cli_review.py#L735),
  [motif de masquage borné](https://github.com/Cezar277/heimdall/blob/5ed7cf661d88c77821cb2b158ca39f96ebf323e1/tests/test_cli_review.py#L698),
  [256 valeurs longues acceptées](https://github.com/Cezar277/heimdall/blob/5ed7cf661d88c77821cb2b158ca39f96ebf323e1/tests/test_cli_review.py#L703).
- Menaces : divulgation de secrets et falsification de l'affichage terminal.
- Documentation : `docs/interactive-review.md`.

## T32.2 / #88 : boucle Y/N/E

- Trois actions fermées, aucune par défaut :
  [Choice et parse_choice](https://github.com/Cezar277/heimdall/blob/5ed7cf661d88c77821cb2b158ca39f96ebf323e1/heimdall/cli/review.py#L212).
- Boucle bornée, backend T30 injecté, exceptions backend converties en
  `ReviewError` statique, journal écrit **après** l'action avec `applied` :
  [review_proposal](https://github.com/Cezar277/heimdall/blob/5ed7cf661d88c77821cb2b158ca39f96ebf323e1/heimdall/cli/review.py#L559).
- Points d'injection normalisés : `ask` et `apply`/`edit` capturent
  `BaseException` (donc `SystemExit("<valeur>")` et `KeyboardInterrupt`),
  le journal injecté est encadré :
  [_ask](https://github.com/Cezar277/heimdall/blob/5ed7cf661d88c77821cb2b158ca39f96ebf323e1/heimdall/cli/review.py#L428), [_journal](https://github.com/Cezar277/heimdall/blob/5ed7cf661d88c77821cb2b158ca39f96ebf323e1/heimdall/cli/review.py#L448).
- Choix journalisé (fichier, ligne, action, date, résultat), jamais la
  valeur : [Decision](https://github.com/Cezar277/heimdall/blob/5ed7cf661d88c77821cb2b158ca39f96ebf323e1/heimdall/cli/review.py#L257),
  [DecisionJournal](https://github.com/Cezar277/heimdall/blob/5ed7cf661d88c77821cb2b158ca39f96ebf323e1/heimdall/cli/review.py#L358).
- Preuves : [Y applique puis journalise applied=true](https://github.com/Cezar277/heimdall/blob/5ed7cf661d88c77821cb2b158ca39f96ebf323e1/tests/test_cli_review.py#L662),
  [N n'appelle jamais le backend](https://github.com/Cezar277/heimdall/blob/5ed7cf661d88c77821cb2b158ca39f96ebf323e1/tests/test_cli_review.py#L182),
  [E réaffiche puis valide](https://github.com/Cezar277/heimdall/blob/5ed7cf661d88c77821cb2b158ca39f96ebf323e1/tests/test_cli_review.py#L198),
  [entrée invalide redemandée](https://github.com/Cezar277/heimdall/blob/5ed7cf661d88c77821cb2b158ca39f96ebf323e1/tests/test_cli_review.py#L222),
  [épuisement borné](https://github.com/Cezar277/heimdall/blob/5ed7cf661d88c77821cb2b158ca39f96ebf323e1/tests/test_cli_review.py#L241),
  [refus sans backend](https://github.com/Cezar277/heimdall/blob/5ed7cf661d88c77821cb2b158ca39f96ebf323e1/tests/test_cli_review.py#L258),
  [échec apply : erreur statique + journal applied=false](https://github.com/Cezar277/heimdall/blob/5ed7cf661d88c77821cb2b158ca39f96ebf323e1/tests/test_cli_review.py#L625),
  [échec edit : erreur statique + journal applied=false](https://github.com/Cezar277/heimdall/blob/5ed7cf661d88c77821cb2b158ca39f96ebf323e1/tests/test_cli_review.py#L645),
  [apply en SystemExit/KeyboardInterrupt](https://github.com/Cezar277/heimdall/blob/5ed7cf661d88c77821cb2b158ca39f96ebf323e1/tests/test_cli_review.py#L866),
  [edit en SystemExit/KeyboardInterrupt](https://github.com/Cezar277/heimdall/blob/5ed7cf661d88c77821cb2b158ca39f96ebf323e1/tests/test_cli_review.py#L887),
  [journal injecté en OSError](https://github.com/Cezar277/heimdall/blob/5ed7cf661d88c77821cb2b158ca39f96ebf323e1/tests/test_cli_review.py#L906),
  [journal sans append](https://github.com/Cezar277/heimdall/blob/5ed7cf661d88c77821cb2b158ca39f96ebf323e1/tests/test_cli_review.py#L928),
  [erreurs statiques du journal préservées](https://github.com/Cezar277/heimdall/blob/5ed7cf661d88c77821cb2b158ca39f96ebf323e1/tests/test_cli_review.py#L962),
  [édition annulée](https://github.com/Cezar277/heimdall/blob/5ed7cf661d88c77821cb2b158ca39f96ebf323e1/tests/test_cli_review.py#L277),
  [boucle d'édition bornée](https://github.com/Cezar277/heimdall/blob/5ed7cf661d88c77821cb2b158ca39f96ebf323e1/tests/test_cli_review.py#L296),
  [journal falsifié détecté](https://github.com/Cezar277/heimdall/blob/5ed7cf661d88c77821cb2b158ca39f96ebf323e1/tests/test_cli_review.py#L383),
  [applied incohérent refusé](https://github.com/Cezar277/heimdall/blob/5ed7cf661d88c77821cb2b158ca39f96ebf323e1/tests/test_cli_review.py#L744),
  [permissions 0600](https://github.com/Cezar277/heimdall/blob/5ed7cf661d88c77821cb2b158ca39f96ebf323e1/tests/test_cli_review.py#L396),
  [EOF interrompt sans journal](https://github.com/Cezar277/heimdall/blob/5ed7cf661d88c77821cb2b158ca39f96ebf323e1/tests/test_cli_review.py#L508).
- Menaces : auto-validation implicite (STRIDE Elevation of Privilege),
  écriture non traçable ou audit mensonger (Repudiation), fuite de valeur
  par le message d'une exception backend (Information Disclosure).
- Limite assumée : `apply`/`edit` restent à livrer par T30 (#83–#86) ; sans
  backend, `Y`/`E` échouent en code 2 au lieu d'écrire.

## T32.3 / #89 : mode non interactif

- `ci` prioritaire, `interactive=True` **insuffisant** sans TTY, refus par
  défaut de tout TTY douteux (dont `BaseException`) :
  [is_interactive](https://github.com/Cezar277/heimdall/blob/5ed7cf661d88c77821cb2b158ca39f96ebf323e1/heimdall/cli/review.py#L482),
  [review_proposals](https://github.com/Cezar277/heimdall/blob/5ed7cf661d88c77821cb2b158ca39f96ebf323e1/heimdall/cli/review.py#L641).
- Session bornée et paresseuse (`MAX_PROPOSALS`, jamais de troncature
  silencieuse) : [review_proposals](https://github.com/Cezar277/heimdall/blob/5ed7cf661d88c77821cb2b158ca39f96ebf323e1/heimdall/cli/review.py#L641).
- Rapport seul, décompte et statut sans écriture :
  [ReviewReport](https://github.com/Cezar277/heimdall/blob/5ed7cf661d88c77821cb2b158ca39f96ebf323e1/heimdall/cli/review.py#L521),
  [_status](https://github.com/Cezar277/heimdall/blob/5ed7cf661d88c77821cb2b158ca39f96ebf323e1/heimdall/cli/review.py#L549).
- Preuves : [aucun appel backend/journal](https://github.com/Cezar277/heimdall/blob/5ed7cf661d88c77821cb2b158ca39f96ebf323e1/tests/test_cli_review.py#L318),
  [ci gagne sur interactive](https://github.com/Cezar277/heimdall/blob/5ed7cf661d88c77821cb2b158ca39f96ebf323e1/tests/test_cli_review.py#L335),
  [interactive=True sur stdin pipé](https://github.com/Cezar277/heimdall/blob/5ed7cf661d88c77821cb2b158ca39f96ebf323e1/tests/test_cli_review.py#L577),
  [review_proposal seul sans TTY](https://github.com/Cezar277/heimdall/blob/5ed7cf661d88c77821cb2b158ca39f96ebf323e1/tests/test_cli_review.py#L608),
  [stdin par défaut sans TTY](https://github.com/Cezar277/heimdall/blob/5ed7cf661d88c77821cb2b158ca39f96ebf323e1/tests/test_cli_review.py#L596),
  [TTY absent/faux/en erreur](https://github.com/Cezar277/heimdall/blob/5ed7cf661d88c77821cb2b158ca39f96ebf323e1/tests/test_cli_review.py#L354),
  [isatty en RuntimeError](https://github.com/Cezar277/heimdall/blob/5ed7cf661d88c77821cb2b158ca39f96ebf323e1/tests/test_cli_review.py#L690),
  [isatty en KeyboardInterrupt/SystemExit](https://github.com/Cezar277/heimdall/blob/5ed7cf661d88c77821cb2b158ca39f96ebf323e1/tests/test_cli_review.py#L821),
  [OSError/KeyboardInterrupt statiques](https://github.com/Cezar277/heimdall/blob/5ed7cf661d88c77821cb2b158ca39f96ebf323e1/tests/test_cli_review.py#L673),
  [générateur infini borné](https://github.com/Cezar277/heimdall/blob/5ed7cf661d88c77821cb2b158ca39f96ebf323e1/tests/test_cli_review.py#L935),
  [borne exacte acceptée](https://github.com/Cezar277/heimdall/blob/5ed7cf661d88c77821cb2b158ca39f96ebf323e1/tests/test_cli_review.py#L952),
  [scan --ci laisse git status propre](https://github.com/Cezar277/heimdall/blob/5ed7cf661d88c77821cb2b158ca39f96ebf323e1/tests/test_cli_review.py#L422).
- Menace : auto-validation sans humain (STRIDE Elevation of Privilege) et
  épuisement de disponibilité par un producteur non borné.
- Code de sortie attendu : 0 si `remaining == 0`, 1 si des propositions
  restent, 2 sur erreur d'outillage.

## T32.4 / #90 : tests du flux interactif

- Clavier simulé par injection de `ask` (alternative documentée au
  `CliRunner(input=...)`), un test par action plus les cas d'erreur :
  [tests/test_cli_review.py](https://github.com/Cezar277/heimdall/blob/5ed7cf661d88c77821cb2b158ca39f96ebf323e1/tests/test_cli_review.py#L164).
- Un test `CliRunner` réel couvre le mode CI sans écriture :
  [scan --ci](https://github.com/Cezar277/heimdall/blob/5ed7cf661d88c77821cb2b158ca39f96ebf323e1/tests/test_cli_review.py#L422).
- Validation locale : `python -m pytest tests/test_cli_review.py` :
  **109 passed** ; couverture `heimdall/cli/review.py` **96 %**.
- `ruff check`, `mypy` strict (47 fichiers) et `bandit -r heimdall` : OK.
- Suite complète : **2321 passed**, **15 skipped**, **4480 subtests passed**.
- Documentation : `docs/interactive-review.md`. CI non déclenchée, sur demande.

## Correctifs des revues de code

### Revue 1 — HIGH et MEDIUM (`50536ec`)

| Constat | Correctif | Preuve |
| --- | --- | --- |
| [HIGH] `interactive=True` contournait le TTY | `is_interactive` exigé en plus du drapeau | [stdin pipé](https://github.com/Cezar277/heimdall/blob/5ed7cf661d88c77821cb2b158ca39f96ebf323e1/tests/test_cli_review.py#L577), [review_proposal seul](https://github.com/Cezar277/heimdall/blob/5ed7cf661d88c77821cb2b158ca39f96ebf323e1/tests/test_cli_review.py#L608) |
| [HIGH] exceptions backend brutes + journal mensonger | `ReviewError from None` + `applied: bool` écrit après l'action | [échec apply](https://github.com/Cezar277/heimdall/blob/5ed7cf661d88c77821cb2b158ca39f96ebf323e1/tests/test_cli_review.py#L625), [échec edit](https://github.com/Cezar277/heimdall/blob/5ed7cf661d88c77821cb2b158ca39f96ebf323e1/tests/test_cli_review.py#L645), [applied incohérent](https://github.com/Cezar277/heimdall/blob/5ed7cf661d88c77821cb2b158ca39f96ebf323e1/tests/test_cli_review.py#L744) |
| [MEDIUM] motif de masquage géant | total borné, compilation unique, `re.error` statique | [motif borné](https://github.com/Cezar277/heimdall/blob/5ed7cf661d88c77821cb2b158ca39f96ebf323e1/tests/test_cli_review.py#L698), [256 valeurs](https://github.com/Cezar277/heimdall/blob/5ed7cf661d88c77821cb2b158ca39f96ebf323e1/tests/test_cli_review.py#L703) |
| [MEDIUM] grammaire de variable trop lâche | `[A-Z][A-Z0-9_]{1,63}` pour `_VARIABLE` et `_ENV_REFERENCE` | [grammaire invariant 2](https://github.com/Cezar277/heimdall/blob/5ed7cf661d88c77821cb2b158ca39f96ebf323e1/tests/test_cli_review.py#L718), [références d'environnement](https://github.com/Cezar277/heimdall/blob/5ed7cf661d88c77821cb2b158ca39f96ebf323e1/tests/test_cli_review.py#L723) |
| [LOW] casse des gardes `.env`/`.git` | comparaison `lower()` | [chemins privés insensibles à la casse](https://github.com/Cezar277/heimdall/blob/5ed7cf661d88c77821cb2b158ca39f96ebf323e1/tests/test_cli_review.py#L735) |
| [LOW] exceptions `input`/`isatty` trop étroites | `OSError`/`ValueError`/`KeyboardInterrupt` → statique ; `isatty` en erreur → non interactif | [OSError/KeyboardInterrupt](https://github.com/Cezar277/heimdall/blob/5ed7cf661d88c77821cb2b158ca39f96ebf323e1/tests/test_cli_review.py#L673), [RuntimeError](https://github.com/Cezar277/heimdall/blob/5ed7cf661d88c77821cb2b158ca39f96ebf323e1/tests/test_cli_review.py#L690) |

### Revue 2 — LOW sur les points d'injection (`aedcc87`)

| Constat | Correctif | Preuve |
| --- | --- | --- |
| [LOW] exceptions d'un `ask`/`notify` injecté non normalisées | [_ask](https://github.com/Cezar277/heimdall/blob/5ed7cf661d88c77821cb2b158ca39f96ebf323e1/heimdall/cli/review.py#L428) convertit toute exception en erreur statique ; [_notify](https://github.com/Cezar277/heimdall/blob/5ed7cf661d88c77821cb2b158ca39f96ebf323e1/heimdall/cli/review.py#L464) reste best-effort et ne laisse rien ressortir | [ask en OSError](https://github.com/Cezar277/heimdall/blob/5ed7cf661d88c77821cb2b158ca39f96ebf323e1/tests/test_cli_review.py#L767), [ReviewError préservée](https://github.com/Cezar277/heimdall/blob/5ed7cf661d88c77821cb2b158ca39f96ebf323e1/tests/test_cli_review.py#L785), [notify en OSError](https://github.com/Cezar277/heimdall/blob/5ed7cf661d88c77821cb2b158ca39f96ebf323e1/tests/test_cli_review.py#L797) |
| [LOW] `is_interactive` laissait passer `BaseException` | `except BaseException` → refus par défaut | [KeyboardInterrupt/SystemExit](https://github.com/Cezar277/heimdall/blob/5ed7cf661d88c77821cb2b158ca39f96ebf323e1/tests/test_cli_review.py#L821) |
| Garde de chemin du journal non couverte pour ce journal | `_prepare_path` de T33 refusé aussi ici | [relatif et `..`](https://github.com/Cezar277/heimdall/blob/5ed7cf661d88c77821cb2b158ca39f96ebf323e1/tests/test_cli_review.py#L830) |

### Revue 3 — LOW `SystemExit` d'un `ask` injecté (`5e9617d`)

| Constat | Correctif | Preuve |
| --- | --- | --- |
| [LOW] `_ask` laissait passer `SystemExit("<valeur>")`, que l'interpréteur imprime sur stderr | [_ask](https://github.com/Cezar277/heimdall/blob/5ed7cf661d88c77821cb2b158ca39f96ebf323e1/heimdall/cli/review.py#L428) capture `BaseException` | [SystemExit portant une valeur](https://github.com/Cezar277/heimdall/blob/5ed7cf661d88c77821cb2b158ca39f96ebf323e1/tests/test_cli_review.py#L842) |
| Choix `_notify` à documenter | `_notify` garde `Exception` seul, volontairement : il ne lit aucune entrée, donc `Ctrl-C`/`SystemExit` peuvent interrompre entre deux propositions | [_notify](https://github.com/Cezar277/heimdall/blob/5ed7cf661d88c77821cb2b158ca39f96ebf323e1/heimdall/cli/review.py#L464) |

### Revue 4 — LOW `apply`/`edit`, journal et borne de session (`5ed7cf6`)

| Constat | Correctif | Preuve |
| --- | --- | --- |
| [LOW] `apply`/`edit` ne capturaient que `Exception` | `BaseException` → journal `applied:false` puis `ReviewError` statique | [apply en SystemExit/KeyboardInterrupt](https://github.com/Cezar277/heimdall/blob/5ed7cf661d88c77821cb2b158ca39f96ebf323e1/tests/test_cli_review.py#L866), [edit idem](https://github.com/Cezar277/heimdall/blob/5ed7cf661d88c77821cb2b158ca39f96ebf323e1/tests/test_cli_review.py#L887) |
| [LOW] journal injecté non normalisé | [_journal](https://github.com/Cezar277/heimdall/blob/5ed7cf661d88c77821cb2b158ca39f96ebf323e1/heimdall/cli/review.py#L448) réémet `JournalError`/`ReviewError` et convertit tout le reste en `JournalError from None` | [journal en OSError](https://github.com/Cezar277/heimdall/blob/5ed7cf661d88c77821cb2b158ca39f96ebf323e1/tests/test_cli_review.py#L906), [sans append](https://github.com/Cezar277/heimdall/blob/5ed7cf661d88c77821cb2b158ca39f96ebf323e1/tests/test_cli_review.py#L928), [statiques préservées](https://github.com/Cezar277/heimdall/blob/5ed7cf661d88c77821cb2b158ca39f96ebf323e1/tests/test_cli_review.py#L962) |
| [LOW] `review_proposals` matérialisait tout sans borne | consommation paresseuse bornée par `MAX_PROPOSALS` (1024), `ReviewError` au-delà | [générateur infini borné](https://github.com/Cezar277/heimdall/blob/5ed7cf661d88c77821cb2b158ca39f96ebf323e1/tests/test_cli_review.py#L935), [borne exacte](https://github.com/Cezar277/heimdall/blob/5ed7cf661d88c77821cb2b158ca39f96ebf323e1/tests/test_cli_review.py#L952) |

Hors périmètre, signalé et non corrigé ici : le câblage CLI `heimdall review`
et ses codes de sortie 0/1/2 arrivent avec le backend T30 (#83–#86) ; le
regroupement de #87–#90 dans une seule PR est une exception demandée par
l'utilisateur, tracée dans la PR #192.
