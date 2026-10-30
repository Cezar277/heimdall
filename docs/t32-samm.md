# Preuves T32 — validation humaine

Snapshot vérifié : `9cece36`. Chaque lien ci-dessous a été résolu sur ce
commit (module + ligne), pas sur une branche mouvante.

## T32.1 / #87 : rendu avant/après

- Validation des chemins et exclusion des fichiers privés, **insensible à la
  casse** (`.Git/config`, `.ENV`, `.Env.local`) :
  [TextChange](https://github.com/Cezar277/heimdall/blob/9cece366696bd99327ed30ec2df396c2ecacc08d/heimdall/cli/review.py#L79).
- Valeurs exclues des représentations, proposition bornée et total des
  valeurs borné (`MAX_SECRET_BYTES`) :
  [Proposal](https://github.com/Cezar277/heimdall/blob/9cece366696bd99327ed30ec2df396c2ecacc08d/heimdall/cli/review.py#L107).
- Masquage avant diff, motif compilé une fois, `re.error` convertie en
  erreur statique, échappement des contrôles terminal :
  [_secret_pattern](https://github.com/Cezar277/heimdall/blob/9cece366696bd99327ed30ec2df396c2ecacc08d/heimdall/cli/review.py#L152),
  [_masked](https://github.com/Cezar277/heimdall/blob/9cece366696bd99327ed30ec2df396c2ecacc08d/heimdall/cli/review.py#L168),
  [render_diff](https://github.com/Cezar277/heimdall/blob/9cece366696bd99327ed30ec2df396c2ecacc08d/heimdall/cli/review.py#L185).
- Rendu défensif (masquage/`difflib` en `MemoryError`/`KeyboardInterrupt`) :
  [_render](https://github.com/Cezar277/heimdall/blob/9cece366696bd99327ed30ec2df396c2ecacc08d/heimdall/cli/review.py#L212).
- Preuves : [masquage de tous les fichiers](https://github.com/Cezar277/heimdall/blob/9cece366696bd99327ed30ec2df396c2ecacc08d/tests/test_cli_review.py#L70),
  [valeurs courtes et chevauchantes](https://github.com/Cezar277/heimdall/blob/9cece366696bd99327ed30ec2df396c2ecacc08d/tests/test_cli_review.py#L125),
  [chemins refusés](https://github.com/Cezar277/heimdall/blob/9cece366696bd99327ed30ec2df396c2ecacc08d/tests/test_cli_review.py#L108),
  [chemins privés insensibles à la casse](https://github.com/Cezar277/heimdall/blob/9cece366696bd99327ed30ec2df396c2ecacc08d/tests/test_cli_review.py#L736),
  [motif de masquage borné](https://github.com/Cezar277/heimdall/blob/9cece366696bd99327ed30ec2df396c2ecacc08d/tests/test_cli_review.py#L699),
  [256 valeurs longues acceptées](https://github.com/Cezar277/heimdall/blob/9cece366696bd99327ed30ec2df396c2ecacc08d/tests/test_cli_review.py#L704),
  [rendu en MemoryError/KeyboardInterrupt](https://github.com/Cezar277/heimdall/blob/9cece366696bd99327ed30ec2df396c2ecacc08d/tests/test_cli_review.py#L1036).
- Menaces : divulgation de secrets et falsification de l'affichage terminal.
- Documentation : `docs/interactive-review.md`.

## T32.2 / #88 : boucle Y/N/E

- Trois actions fermées, aucune par défaut :
  [Choice et parse_choice](https://github.com/Cezar277/heimdall/blob/9cece366696bd99327ed30ec2df396c2ecacc08d/heimdall/cli/review.py#L228).
- Boucle bornée, backend T30 injecté, exceptions backend converties en
  `ReviewError` statique, journal écrit **après** l'action avec `applied` :
  [review_proposal](https://github.com/Cezar277/heimdall/blob/9cece366696bd99327ed30ec2df396c2ecacc08d/heimdall/cli/review.py#L613).
- Points d'injection normalisés : `ask`, `apply`/`edit` et rendu capturent
  `BaseException` (donc `SystemExit("<valeur>")` et `KeyboardInterrupt`),
  le journal injecté et sa résolution sont encadrés :
  [_ask](https://github.com/Cezar277/heimdall/blob/9cece366696bd99327ed30ec2df396c2ecacc08d/heimdall/cli/review.py#L466), [_journal](https://github.com/Cezar277/heimdall/blob/9cece366696bd99327ed30ec2df396c2ecacc08d/heimdall/cli/review.py#L496),
  [_resolve_journal](https://github.com/Cezar277/heimdall/blob/9cece366696bd99327ed30ec2df396c2ecacc08d/heimdall/cli/review.py#L486).
- Choix journalisé (fichier, ligne, action, date, résultat), jamais la
  valeur : [Decision](https://github.com/Cezar277/heimdall/blob/9cece366696bd99327ed30ec2df396c2ecacc08d/heimdall/cli/review.py#L273),
  [DecisionJournal](https://github.com/Cezar277/heimdall/blob/9cece366696bd99327ed30ec2df396c2ecacc08d/heimdall/cli/review.py#L389).
- Preuves : [Y applique puis journalise applied=true](https://github.com/Cezar277/heimdall/blob/9cece366696bd99327ed30ec2df396c2ecacc08d/tests/test_cli_review.py#L663),
  [N n'appelle jamais le backend](https://github.com/Cezar277/heimdall/blob/9cece366696bd99327ed30ec2df396c2ecacc08d/tests/test_cli_review.py#L183),
  [E réaffiche puis valide](https://github.com/Cezar277/heimdall/blob/9cece366696bd99327ed30ec2df396c2ecacc08d/tests/test_cli_review.py#L199),
  [entrée invalide redemandée](https://github.com/Cezar277/heimdall/blob/9cece366696bd99327ed30ec2df396c2ecacc08d/tests/test_cli_review.py#L223),
  [épuisement borné](https://github.com/Cezar277/heimdall/blob/9cece366696bd99327ed30ec2df396c2ecacc08d/tests/test_cli_review.py#L242),
  [refus sans backend](https://github.com/Cezar277/heimdall/blob/9cece366696bd99327ed30ec2df396c2ecacc08d/tests/test_cli_review.py#L259),
  [échec apply : erreur statique + journal applied=false](https://github.com/Cezar277/heimdall/blob/9cece366696bd99327ed30ec2df396c2ecacc08d/tests/test_cli_review.py#L626),
  [échec edit : erreur statique + journal applied=false](https://github.com/Cezar277/heimdall/blob/9cece366696bd99327ed30ec2df396c2ecacc08d/tests/test_cli_review.py#L646),
  [apply en SystemExit/KeyboardInterrupt](https://github.com/Cezar277/heimdall/blob/9cece366696bd99327ed30ec2df396c2ecacc08d/tests/test_cli_review.py#L867),
  [edit en SystemExit/KeyboardInterrupt](https://github.com/Cezar277/heimdall/blob/9cece366696bd99327ed30ec2df396c2ecacc08d/tests/test_cli_review.py#L888),
  [journal injecté en OSError](https://github.com/Cezar277/heimdall/blob/9cece366696bd99327ed30ec2df396c2ecacc08d/tests/test_cli_review.py#L907),
  [journal sans append](https://github.com/Cezar277/heimdall/blob/9cece366696bd99327ed30ec2df396c2ecacc08d/tests/test_cli_review.py#L929),
  [erreurs statiques du journal préservées](https://github.com/Cezar277/heimdall/blob/9cece366696bd99327ed30ec2df396c2ecacc08d/tests/test_cli_review.py#L963),
  [journal par défaut cassé](https://github.com/Cezar277/heimdall/blob/9cece366696bd99327ed30ec2df396c2ecacc08d/tests/test_cli_review.py#L1003),
  [édition annulée](https://github.com/Cezar277/heimdall/blob/9cece366696bd99327ed30ec2df396c2ecacc08d/tests/test_cli_review.py#L278),
  [boucle d'édition bornée](https://github.com/Cezar277/heimdall/blob/9cece366696bd99327ed30ec2df396c2ecacc08d/tests/test_cli_review.py#L297),
  [journal falsifié détecté](https://github.com/Cezar277/heimdall/blob/9cece366696bd99327ed30ec2df396c2ecacc08d/tests/test_cli_review.py#L384),
  [applied incohérent refusé](https://github.com/Cezar277/heimdall/blob/9cece366696bd99327ed30ec2df396c2ecacc08d/tests/test_cli_review.py#L745),
  [permissions 0600](https://github.com/Cezar277/heimdall/blob/9cece366696bd99327ed30ec2df396c2ecacc08d/tests/test_cli_review.py#L397),
  [EOF interrompt sans journal](https://github.com/Cezar277/heimdall/blob/9cece366696bd99327ed30ec2df396c2ecacc08d/tests/test_cli_review.py#L509).
- Menaces : auto-validation implicite (STRIDE Elevation of Privilege),
  écriture non traçable ou audit mensonger (Repudiation), fuite de valeur
  par le message d'une exception backend (Information Disclosure).
- Limite assumée : `apply`/`edit` restent à livrer par T30 (#83–#86) ; sans
  backend, `Y`/`E` échouent en code 2 au lieu d'écrire.

## T32.3 / #89 : mode non interactif

- `ci` prioritaire, `interactive=True` **insuffisant** sans TTY, refus par
  défaut de tout TTY douteux (dont `BaseException`) :
  [is_interactive](https://github.com/Cezar277/heimdall/blob/9cece366696bd99327ed30ec2df396c2ecacc08d/heimdall/cli/review.py#L530),
  [review_proposals](https://github.com/Cezar277/heimdall/blob/9cece366696bd99327ed30ec2df396c2ecacc08d/heimdall/cli/review.py#L712).
- Session bornée et paresseuse, producteur non itérable normalisé :
  [_bounded_proposals](https://github.com/Cezar277/heimdall/blob/9cece366696bd99327ed30ec2df396c2ecacc08d/heimdall/cli/review.py#L695).
- Rapport seul, décompte et statut sans écriture, rendu défensif :
  [ReviewReport](https://github.com/Cezar277/heimdall/blob/9cece366696bd99327ed30ec2df396c2ecacc08d/heimdall/cli/review.py#L569),
  [_status](https://github.com/Cezar277/heimdall/blob/9cece366696bd99327ed30ec2df396c2ecacc08d/heimdall/cli/review.py#L603).
- Preuves : [aucun appel backend/journal](https://github.com/Cezar277/heimdall/blob/9cece366696bd99327ed30ec2df396c2ecacc08d/tests/test_cli_review.py#L319),
  [ci gagne sur interactive](https://github.com/Cezar277/heimdall/blob/9cece366696bd99327ed30ec2df396c2ecacc08d/tests/test_cli_review.py#L336),
  [interactive=True sur stdin pipé](https://github.com/Cezar277/heimdall/blob/9cece366696bd99327ed30ec2df396c2ecacc08d/tests/test_cli_review.py#L578),
  [review_proposal seul sans TTY](https://github.com/Cezar277/heimdall/blob/9cece366696bd99327ed30ec2df396c2ecacc08d/tests/test_cli_review.py#L609),
  [stdin par défaut sans TTY](https://github.com/Cezar277/heimdall/blob/9cece366696bd99327ed30ec2df396c2ecacc08d/tests/test_cli_review.py#L597),
  [TTY absent/faux/en erreur](https://github.com/Cezar277/heimdall/blob/9cece366696bd99327ed30ec2df396c2ecacc08d/tests/test_cli_review.py#L355),
  [isatty en RuntimeError](https://github.com/Cezar277/heimdall/blob/9cece366696bd99327ed30ec2df396c2ecacc08d/tests/test_cli_review.py#L691),
  [isatty en KeyboardInterrupt/SystemExit](https://github.com/Cezar277/heimdall/blob/9cece366696bd99327ed30ec2df396c2ecacc08d/tests/test_cli_review.py#L822),
  [OSError/KeyboardInterrupt statiques](https://github.com/Cezar277/heimdall/blob/9cece366696bd99327ed30ec2df396c2ecacc08d/tests/test_cli_review.py#L674),
  [générateur infini borné](https://github.com/Cezar277/heimdall/blob/9cece366696bd99327ed30ec2df396c2ecacc08d/tests/test_cli_review.py#L936),
  [borne exacte acceptée](https://github.com/Cezar277/heimdall/blob/9cece366696bd99327ed30ec2df396c2ecacc08d/tests/test_cli_review.py#L953),
  [producteur non itérable](https://github.com/Cezar277/heimdall/blob/9cece366696bd99327ed30ec2df396c2ecacc08d/tests/test_cli_review.py#L1018),
  [producteur qui lève](https://github.com/Cezar277/heimdall/blob/9cece366696bd99327ed30ec2df396c2ecacc08d/tests/test_cli_review.py#L1023),
  [rendu du rapport en échec](https://github.com/Cezar277/heimdall/blob/9cece366696bd99327ed30ec2df396c2ecacc08d/tests/test_cli_review.py#L1056),
  [scan --ci laisse git status propre](https://github.com/Cezar277/heimdall/blob/9cece366696bd99327ed30ec2df396c2ecacc08d/tests/test_cli_review.py#L423).
- Menace : auto-validation sans humain (STRIDE Elevation of Privilege) et
  épuisement de disponibilité par un producteur non borné.
- Code de sortie attendu : 0 si `remaining == 0`, 1 si des propositions
  restent, 2 sur erreur d'outillage.

## T32.4 / #90 : tests du flux interactif

- Clavier simulé par injection de `ask` (alternative documentée au
  `CliRunner(input=...)`), un test par action plus les cas d'erreur :
  [tests/test_cli_review.py](https://github.com/Cezar277/heimdall/blob/9cece366696bd99327ed30ec2df396c2ecacc08d/tests/test_cli_review.py#L165).
- Un test `CliRunner` réel couvre le mode CI sans écriture :
  [scan --ci](https://github.com/Cezar277/heimdall/blob/9cece366696bd99327ed30ec2df396c2ecacc08d/tests/test_cli_review.py#L423).
- Validation locale : `python -m pytest tests/test_cli_review.py` :
  **122 passed** ; couverture `heimdall/cli/review.py` **94 %**.
- `ruff check`, `mypy` strict (47 fichiers) et `bandit -r heimdall` : OK.
- Suite complète : **2334 passed**, **15 skipped**, **4480 subtests passed**.
- Documentation : `docs/interactive-review.md`. CI non déclenchée, sur demande.

## Correctifs des revues de code

### Revue 1 — HIGH et MEDIUM (`50536ec`)

| Constat | Correctif | Preuve |
| --- | --- | --- |
| [HIGH] `interactive=True` contournait le TTY | `is_interactive` exigé en plus du drapeau | [stdin pipé](https://github.com/Cezar277/heimdall/blob/9cece366696bd99327ed30ec2df396c2ecacc08d/tests/test_cli_review.py#L578), [review_proposal seul](https://github.com/Cezar277/heimdall/blob/9cece366696bd99327ed30ec2df396c2ecacc08d/tests/test_cli_review.py#L609) |
| [HIGH] exceptions backend brutes + journal mensonger | `ReviewError from None` + `applied: bool` écrit après l'action | [échec apply](https://github.com/Cezar277/heimdall/blob/9cece366696bd99327ed30ec2df396c2ecacc08d/tests/test_cli_review.py#L626), [échec edit](https://github.com/Cezar277/heimdall/blob/9cece366696bd99327ed30ec2df396c2ecacc08d/tests/test_cli_review.py#L646), [applied incohérent](https://github.com/Cezar277/heimdall/blob/9cece366696bd99327ed30ec2df396c2ecacc08d/tests/test_cli_review.py#L745) |
| [MEDIUM] motif de masquage géant | total borné, compilation unique, `re.error` statique | [motif borné](https://github.com/Cezar277/heimdall/blob/9cece366696bd99327ed30ec2df396c2ecacc08d/tests/test_cli_review.py#L699), [256 valeurs](https://github.com/Cezar277/heimdall/blob/9cece366696bd99327ed30ec2df396c2ecacc08d/tests/test_cli_review.py#L704) |
| [MEDIUM] grammaire de variable trop lâche | `[A-Z][A-Z0-9_]{1,63}` pour `_VARIABLE` et `_ENV_REFERENCE` | [grammaire invariant 2](https://github.com/Cezar277/heimdall/blob/9cece366696bd99327ed30ec2df396c2ecacc08d/tests/test_cli_review.py#L719), [références d'environnement](https://github.com/Cezar277/heimdall/blob/9cece366696bd99327ed30ec2df396c2ecacc08d/tests/test_cli_review.py#L724) |
| [LOW] casse des gardes `.env`/`.git` | comparaison `lower()` | [chemins privés insensibles à la casse](https://github.com/Cezar277/heimdall/blob/9cece366696bd99327ed30ec2df396c2ecacc08d/tests/test_cli_review.py#L736) |
| [LOW] exceptions `input`/`isatty` trop étroites | `OSError`/`ValueError`/`KeyboardInterrupt` → statique ; `isatty` en erreur → non interactif | [OSError/KeyboardInterrupt](https://github.com/Cezar277/heimdall/blob/9cece366696bd99327ed30ec2df396c2ecacc08d/tests/test_cli_review.py#L674), [RuntimeError](https://github.com/Cezar277/heimdall/blob/9cece366696bd99327ed30ec2df396c2ecacc08d/tests/test_cli_review.py#L691) |

### Revue 2 — LOW sur les points d'injection (`aedcc87`)

| Constat | Correctif | Preuve |
| --- | --- | --- |
| [LOW] exceptions d'un `ask`/`notify` injecté non normalisées | [_ask](https://github.com/Cezar277/heimdall/blob/9cece366696bd99327ed30ec2df396c2ecacc08d/heimdall/cli/review.py#L466) convertit toute exception en erreur statique ; [_notify](https://github.com/Cezar277/heimdall/blob/9cece366696bd99327ed30ec2df396c2ecacc08d/heimdall/cli/review.py#L512) reste best-effort et ne laisse rien ressortir | [ask en OSError](https://github.com/Cezar277/heimdall/blob/9cece366696bd99327ed30ec2df396c2ecacc08d/tests/test_cli_review.py#L768), [ReviewError préservée](https://github.com/Cezar277/heimdall/blob/9cece366696bd99327ed30ec2df396c2ecacc08d/tests/test_cli_review.py#L786), [notify en OSError](https://github.com/Cezar277/heimdall/blob/9cece366696bd99327ed30ec2df396c2ecacc08d/tests/test_cli_review.py#L798) |
| [LOW] `is_interactive` laissait passer `BaseException` | `except BaseException` → refus par défaut | [KeyboardInterrupt/SystemExit](https://github.com/Cezar277/heimdall/blob/9cece366696bd99327ed30ec2df396c2ecacc08d/tests/test_cli_review.py#L822) |
| Garde de chemin du journal non couverte pour ce journal | `_prepare_path` de T33 refusé aussi ici | [relatif et `..`](https://github.com/Cezar277/heimdall/blob/9cece366696bd99327ed30ec2df396c2ecacc08d/tests/test_cli_review.py#L831) |

### Revue 3 — LOW `SystemExit` d'un `ask` injecté (`5e9617d`)

| Constat | Correctif | Preuve |
| --- | --- | --- |
| [LOW] `_ask` laissait passer `SystemExit("<valeur>")`, que l'interpréteur imprime sur stderr | [_ask](https://github.com/Cezar277/heimdall/blob/9cece366696bd99327ed30ec2df396c2ecacc08d/heimdall/cli/review.py#L466) capture `BaseException` | [SystemExit portant une valeur](https://github.com/Cezar277/heimdall/blob/9cece366696bd99327ed30ec2df396c2ecacc08d/tests/test_cli_review.py#L843) |
| Choix `_notify` à documenter | `_notify` garde `Exception` seul, volontairement : il ne lit aucune entrée, donc `Ctrl-C`/`SystemExit` peuvent interrompre entre deux propositions | [_notify](https://github.com/Cezar277/heimdall/blob/9cece366696bd99327ed30ec2df396c2ecacc08d/heimdall/cli/review.py#L512) |

### Revue 4 — LOW `apply`/`edit`, journal et borne de session (`5ed7cf6`)

| Constat | Correctif | Preuve |
| --- | --- | --- |
| [LOW] `apply`/`edit` ne capturaient que `Exception` | `BaseException` → journal `applied:false` puis `ReviewError` statique | [apply en SystemExit/KeyboardInterrupt](https://github.com/Cezar277/heimdall/blob/9cece366696bd99327ed30ec2df396c2ecacc08d/tests/test_cli_review.py#L867), [edit idem](https://github.com/Cezar277/heimdall/blob/9cece366696bd99327ed30ec2df396c2ecacc08d/tests/test_cli_review.py#L888) |
| [LOW] journal injecté non normalisé | [_journal](https://github.com/Cezar277/heimdall/blob/9cece366696bd99327ed30ec2df396c2ecacc08d/heimdall/cli/review.py#L496) réémet `JournalError`/`ReviewError` et convertit tout le reste en `JournalError from None` | [journal en OSError](https://github.com/Cezar277/heimdall/blob/9cece366696bd99327ed30ec2df396c2ecacc08d/tests/test_cli_review.py#L907), [sans append](https://github.com/Cezar277/heimdall/blob/9cece366696bd99327ed30ec2df396c2ecacc08d/tests/test_cli_review.py#L929), [statiques préservées](https://github.com/Cezar277/heimdall/blob/9cece366696bd99327ed30ec2df396c2ecacc08d/tests/test_cli_review.py#L963) |
| [LOW] `review_proposals` matérialisait tout sans borne | consommation paresseuse bornée par `MAX_PROPOSALS` (1024), `ReviewError` au-delà | [générateur infini borné](https://github.com/Cezar277/heimdall/blob/9cece366696bd99327ed30ec2df396c2ecacc08d/tests/test_cli_review.py#L936), [borne exacte](https://github.com/Cezar277/heimdall/blob/9cece366696bd99327ed30ec2df396c2ecacc08d/tests/test_cli_review.py#L953) |

### Revue 5 — LOW environnement, producteur et rendu (`9cece36`)

| Constat | Correctif | Preuve |
| --- | --- | --- |
| [LOW] résolution du journal hors contrat (`Path.home()` en `RuntimeError`, `Path` acceptant NUL) | [decision_journal_path](https://github.com/Cezar277/heimdall/blob/9cece366696bd99327ed30ec2df396c2ecacc08d/heimdall/cli/review.py#L310) et [DecisionJournal](https://github.com/Cezar277/heimdall/blob/9cece366696bd99327ed30ec2df396c2ecacc08d/heimdall/cli/review.py#L389) encadrent la résolution ; chemin non-`Path` ou contenant NUL refusé ; [_resolve_journal](https://github.com/Cezar277/heimdall/blob/9cece366696bd99327ed30ec2df396c2ecacc08d/heimdall/cli/review.py#L486) garantit un `JournalError` statique | [chemin NUL](https://github.com/Cezar277/heimdall/blob/9cece366696bd99327ed30ec2df396c2ecacc08d/tests/test_cli_review.py#L980), [HOME indisponible](https://github.com/Cezar277/heimdall/blob/9cece366696bd99327ed30ec2df396c2ecacc08d/tests/test_cli_review.py#L987), [argument non-Path](https://github.com/Cezar277/heimdall/blob/9cece366696bd99327ed30ec2df396c2ecacc08d/tests/test_cli_review.py#L998), [journal par défaut cassé](https://github.com/Cezar277/heimdall/blob/9cece366696bd99327ed30ec2df396c2ecacc08d/tests/test_cli_review.py#L1003), [JournalError préservée](https://github.com/Cezar277/heimdall/blob/9cece366696bd99327ed30ec2df396c2ecacc08d/tests/test_cli_review.py#L1071) |
| [LOW] `review_proposals` avec producteur non itérable (`TypeError` brut) | [_bounded_proposals](https://github.com/Cezar277/heimdall/blob/9cece366696bd99327ed30ec2df396c2ecacc08d/heimdall/cli/review.py#L695) encadre l'itération et rend une `ReviewError` statique | [None/entier/objet](https://github.com/Cezar277/heimdall/blob/9cece366696bd99327ed30ec2df396c2ecacc08d/tests/test_cli_review.py#L1018), [générateur qui lève](https://github.com/Cezar277/heimdall/blob/9cece366696bd99327ed30ec2df396c2ecacc08d/tests/test_cli_review.py#L1023) |
| [LOW] rendu non gardé (`MemoryError`, `KeyboardInterrupt`) | [_render](https://github.com/Cezar277/heimdall/blob/9cece366696bd99327ed30ec2df396c2ecacc08d/heimdall/cli/review.py#L212) encadre `render_diff`, [ReviewReport](https://github.com/Cezar277/heimdall/blob/9cece366696bd99327ed30ec2df396c2ecacc08d/heimdall/cli/review.py#L569) encadre le rapport | [boucle](https://github.com/Cezar277/heimdall/blob/9cece366696bd99327ed30ec2df396c2ecacc08d/tests/test_cli_review.py#L1036), [rapport](https://github.com/Cezar277/heimdall/blob/9cece366696bd99327ed30ec2df396c2ecacc08d/tests/test_cli_review.py#L1056) |

Hors périmètre, signalé et non corrigé ici : le câblage CLI `heimdall review`
et ses codes de sortie 0/1/2 arrivent avec le backend T30 (#83–#86) ; le
regroupement de #87–#90 dans une seule PR est une exception demandée par
l'utilisateur, tracée dans la PR #192.
