# Preuves T32 — validation humaine

Snapshot vérifié : `a4a4fe1`. Chaque lien ci-dessous a été résolu sur ce
commit (module + ligne), pas sur une branche mouvante.

## T32.1 / #87 : rendu avant/après

- Validation des chemins et exclusion des fichiers privés, **insensible à la
  casse** (`.Git/config`, `.ENV`, `.Env.local`) :
  [TextChange](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/heimdall/cli/review.py#L87).
- Valeurs exclues des représentations, proposition bornée et total des
  valeurs borné (`MAX_SECRET_BYTES`) :
  [Proposal](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/heimdall/cli/review.py#L115).
- Masquage avant diff, motif compilé une fois, marqueur **constant**
  `<MASKED>` pour les valeurs connues **et** pour le filet MCP (aucun oracle
  de longueur ni de type), `re.error` convertie en erreur statique,
  échappement des contrôles terminal :
  [_secret_pattern](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/heimdall/cli/review.py#L176),
  [_net](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/heimdall/cli/review.py#L160),
  [_masked](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/heimdall/cli/review.py#L192),
  [render_diff](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/heimdall/cli/review.py#L212).
- Rendu défensif (masquage/`difflib` en `MemoryError`/`KeyboardInterrupt`) :
  [_render](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/heimdall/cli/review.py#L239).
- Preuves : [masquage de tous les fichiers](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/tests/test_cli_review.py#L78),
  [valeurs courtes et chevauchantes](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/tests/test_cli_review.py#L133),
  [marqueur sans longueur](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/tests/test_cli_review.py#L1282),
  [filet heuristique sans type ni len](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/tests/test_cli_review.py#L1393),
  [marqueurs réécrits](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/tests/test_cli_review.py#L1502),
  [marqueurs malformés refusés](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/tests/test_cli_review.py#L1515),
  [chemins refusés](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/tests/test_cli_review.py#L116),
  [chemins privés insensibles à la casse](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/tests/test_cli_review.py#L744),
  [motif de masquage borné](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/tests/test_cli_review.py#L707),
  [256 valeurs longues acceptées](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/tests/test_cli_review.py#L712),
  [rendu au plafond MAX_CHANGES/MAX_TEXT_CHARS](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/tests/test_cli_review.py#L1255),
  [rendu en MemoryError/KeyboardInterrupt](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/tests/test_cli_review.py#L1044).
- Menaces : divulgation de secrets (valeur, type et longueur) et
  falsification de l'affichage terminal.
- Documentation : `docs/interactive-review.md`.

## T32.2 / #88 : boucle Y/N/E

- Trois actions fermées, aucune par défaut :
  [Choice et parse_choice](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/heimdall/cli/review.py#L255).
- Boucle bornée, backend T30 injecté, exceptions backend converties en
  `ReviewError` statique, journal écrit **après** l'action avec `applied` :
  [review_proposal](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/heimdall/cli/review.py#L730).
- Points d'injection normalisés : `ask`, `apply`/`edit` et rendu capturent
  `BaseException` (donc `SystemExit("<valeur>")` et `KeyboardInterrupt`),
  le journal injecté et sa résolution sont encadrés :
  [_ask](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/heimdall/cli/review.py#L546), [_journal](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/heimdall/cli/review.py#L611),
  [_journal_failure](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/heimdall/cli/review.py#L598),
  [_journal_applied](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/heimdall/cli/review.py#L576),
  [_resolve_journal](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/heimdall/cli/review.py#L566).
- Lecture clavier bornée **sur le flux vérifié** :
  [_stdin_ask](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/heimdall/cli/review.py#L516).
- Double faute backend + journal : l'erreur statique est levée hors du
  `except`, donc sans `__context__` backend (valeur, chemin).
- Ré-ancrage après édition : `edited.finding` identique et
  `current.secrets ⊆ edited.secrets` (ajout permis, retrait refusé).
- Choix journalisé (fichier, ligne, action, date, résultat), jamais la
  valeur : [Decision](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/heimdall/cli/review.py#L300),
  [DecisionJournal](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/heimdall/cli/review.py#L445).
- Preuves : [Y applique puis journalise applied=true](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/tests/test_cli_review.py#L671),
  [N n'appelle jamais le backend](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/tests/test_cli_review.py#L191),
  [E réaffiche puis valide](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/tests/test_cli_review.py#L207),
  [E ne déplace pas le finding](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/tests/test_cli_review.py#L1213),
  [E ne retire aucune valeur connue](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/tests/test_cli_review.py#L1226),
  [E peut ajouter une valeur connue](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/tests/test_cli_review.py#L1237),
  [entrée invalide redemandée](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/tests/test_cli_review.py#L231),
  [épuisement borné](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/tests/test_cli_review.py#L250),
  [refus sans backend](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/tests/test_cli_review.py#L267),
  [échec apply : erreur statique + journal applied=false](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/tests/test_cli_review.py#L634),
  [échec edit : erreur statique + journal applied=false](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/tests/test_cli_review.py#L654),
  [apply en SystemExit/KeyboardInterrupt](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/tests/test_cli_review.py#L875),
  [edit en SystemExit/KeyboardInterrupt](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/tests/test_cli_review.py#L896),
  [double faute apply + journal](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/tests/test_cli_review.py#L1106),
  [double faute edit + journal](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/tests/test_cli_review.py#L1134),
  [apply réussi puis journal en panne](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/tests/test_cli_review.py#L1409),
  [journal injecté en OSError](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/tests/test_cli_review.py#L915),
  [journal sans append](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/tests/test_cli_review.py#L937),
  [erreurs statiques du journal préservées](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/tests/test_cli_review.py#L971),
  [journal par défaut cassé](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/tests/test_cli_review.py#L1011),
  [lecture bornée](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/tests/test_cli_review.py#L1306),
  [flux absents](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/tests/test_cli_review.py#L1333),
  [EOF](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/tests/test_cli_review.py#L1339),
  [lecture sur le flux vérifié](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/tests/test_cli_review.py#L1458),
  [édition annulée](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/tests/test_cli_review.py#L286),
  [boucle d'édition bornée](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/tests/test_cli_review.py#L305),
  [journal falsifié détecté](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/tests/test_cli_review.py#L392),
  [applied incohérent refusé](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/tests/test_cli_review.py#L753),
  [champs de types étrangers](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/tests/test_cli_review.py#L1369),
  [permissions 0600](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/tests/test_cli_review.py#L405),
  [EOF interrompt sans journal](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/tests/test_cli_review.py#L517).
- Menaces : auto-validation implicite (STRIDE Elevation of Privilege),
  écriture non traçable ou audit mensonger (Repudiation), fuite de valeur,
  de type ou de longueur (Information Disclosure), affaiblissement du
  masquage par une édition.
- Limite assumée : `apply`/`edit` restent à livrer par T30 (#83–#86) ; sans
  backend, `Y`/`E` échouent en code 2 au lieu d'écrire.
- Limite assumée : l'atomicité **patch + journal** n'est pas garantie. Si
  `apply` réussit puis que le journal échoue, le fichier est modifié, un
  avertissement statique `UNAPPLIED_TRACE` est émis et `JournalError` sort
  en code 2 : la trace d'audit est incomplète, jamais silencieuse.

## T32.3 / #89 : mode non interactif

- `ci` prioritaire, `interactive=True` **insuffisant** sans TTY, refus par
  défaut de tout TTY douteux (`getattr` et `isatty` compris), et **le flux
  vérifié est celui qui est lu** :
  [is_interactive](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/heimdall/cli/review.py#L645),
  [review_proposals](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/heimdall/cli/review.py#L891).
- Session traitée **en flux**, options validées avant consommation, bornée
  en nombre (`MAX_PROPOSALS`) et en volume **UTF-8** (`MAX_SESSION_BYTES`) :
  [_review_all](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/heimdall/cli/review.py#L842),
  [_proposal_bytes](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/heimdall/cli/review.py#L827).
- Rapport seul, décompte et statut sans écriture, rendu défensif :
  [ReviewReport](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/heimdall/cli/review.py#L686),
  [_status](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/heimdall/cli/review.py#L720).
- Preuves : [aucun appel backend/journal](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/tests/test_cli_review.py#L327),
  [ci gagne sur interactive](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/tests/test_cli_review.py#L344),
  [interactive=True sur stdin pipé](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/tests/test_cli_review.py#L586),
  [review_proposal seul sans TTY](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/tests/test_cli_review.py#L617),
  [stdin par défaut sans TTY](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/tests/test_cli_review.py#L605),
  [TTY absent/faux/en erreur](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/tests/test_cli_review.py#L363),
  [isatty en RuntimeError](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/tests/test_cli_review.py#L699),
  [isatty en KeyboardInterrupt/SystemExit](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/tests/test_cli_review.py#L830),
  [__getattr__ hostile](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/tests/test_cli_review.py#L1095),
  [OSError/KeyboardInterrupt statiques](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/tests/test_cli_review.py#L682),
  [générateur infini borné](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/tests/test_cli_review.py#L944),
  [borne exacte acceptée](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/tests/test_cli_review.py#L961),
  [producteur non itérable](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/tests/test_cli_review.py#L1026),
  [producteur qui lève](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/tests/test_cli_review.py#L1031),
  [options invalides sans consommation](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/tests/test_cli_review.py#L1158),
  [volume dépassé](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/tests/test_cli_review.py#L1438),
  [volume normal](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/tests/test_cli_review.py#L1447),
  [volume en octets UTF-8](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/tests/test_cli_review.py#L1521),
  [rendu du rapport en échec](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/tests/test_cli_review.py#L1064),
  [scan --ci laisse git status propre](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/tests/test_cli_review.py#L431).
- Menace : auto-validation sans humain (STRIDE Elevation of Privilege) et
  épuisement de disponibilité par un producteur non borné.
- Code de sortie attendu : 0 si `remaining == 0`, 1 si des propositions
  restent, 2 sur erreur d'outillage.
- Limite assumée : le volume total produit reste la responsabilité du
  producteur T30 ; la session le plafonne (`MAX_SESSION_BYTES`, octets
  UTF-8) et refuse au-delà plutôt que de tronquer.

## T32.4 / #90 : tests du flux interactif

- Clavier simulé par injection de `ask` (alternative documentée au
  `CliRunner(input=...)`), un test par action plus les cas d'erreur :
  [tests/test_cli_review.py](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/tests/test_cli_review.py#L173).
- Un test `CliRunner` réel couvre le mode CI sans écriture :
  [scan --ci](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/tests/test_cli_review.py#L431).
- Validation locale : `python -m pytest tests/test_cli_review.py` :
  **159 passed** ; couverture `heimdall/cli/review.py` **95 %**.
- `ruff check`, `mypy` strict (47 fichiers) et `bandit -r heimdall` : OK.
- Suite complète : **2371 passed**, **15 skipped**, **4480 subtests passed**.
- Documentation : `docs/interactive-review.md`. CI non déclenchée, sur demande.

## Correctifs des revues de code

### Revue 1 — HIGH et MEDIUM (`50536ec`)

| Constat | Correctif | Preuve |
| --- | --- | --- |
| [HIGH] `interactive=True` contournait le TTY | `is_interactive` exigé en plus du drapeau | [stdin pipé](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/tests/test_cli_review.py#L586), [review_proposal seul](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/tests/test_cli_review.py#L617) |
| [HIGH] exceptions backend brutes + journal mensonger | `ReviewError from None` + `applied: bool` écrit après l'action | [échec apply](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/tests/test_cli_review.py#L634), [échec edit](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/tests/test_cli_review.py#L654), [applied incohérent](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/tests/test_cli_review.py#L753) |
| [MEDIUM] motif de masquage géant | total borné, compilation unique, `re.error` statique | [motif borné](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/tests/test_cli_review.py#L707), [256 valeurs](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/tests/test_cli_review.py#L712) |
| [MEDIUM] grammaire de variable trop lâche | `[A-Z][A-Z0-9_]{1,63}` pour `_VARIABLE` et `_ENV_REFERENCE` | [grammaire invariant 2](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/tests/test_cli_review.py#L727), [références d'environnement](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/tests/test_cli_review.py#L732) |
| [LOW] casse des gardes `.env`/`.git` | comparaison `lower()` | [chemins privés insensibles à la casse](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/tests/test_cli_review.py#L744) |
| [LOW] exceptions `input`/`isatty` trop étroites | `OSError`/`ValueError`/`KeyboardInterrupt` → statique ; `isatty` en erreur → non interactif | [OSError/KeyboardInterrupt](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/tests/test_cli_review.py#L682), [RuntimeError](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/tests/test_cli_review.py#L699) |

### Revue 2 — LOW sur les points d'injection (`aedcc87`)

| Constat | Correctif | Preuve |
| --- | --- | --- |
| [LOW] exceptions d'un `ask`/`notify` injecté non normalisées | [_ask](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/heimdall/cli/review.py#L546) convertit toute exception en erreur statique ; [_notify](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/heimdall/cli/review.py#L627) reste best-effort | [ask en OSError](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/tests/test_cli_review.py#L776), [ReviewError préservée](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/tests/test_cli_review.py#L794), [notify en OSError](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/tests/test_cli_review.py#L806) |
| [LOW] `is_interactive` laissait passer `BaseException` | `except BaseException` → refus par défaut | [KeyboardInterrupt/SystemExit](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/tests/test_cli_review.py#L830) |
| Garde de chemin du journal non couverte | `_prepare_path` de T33 refusé aussi ici | [relatif et `..`](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/tests/test_cli_review.py#L839) |

### Revue 3 — LOW `SystemExit` d'un `ask` injecté (`5e9617d`)

| Constat | Correctif | Preuve |
| --- | --- | --- |
| [LOW] `_ask` laissait passer `SystemExit("<valeur>")` | [_ask](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/heimdall/cli/review.py#L546) capture `BaseException` | [SystemExit portant une valeur](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/tests/test_cli_review.py#L851) |
| Choix `_notify` à documenter | `_notify` garde `Exception` seul, volontairement (aucune entrée lue) | [_notify](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/heimdall/cli/review.py#L627) |

### Revue 4 — LOW `apply`/`edit`, journal et borne de session (`5ed7cf6`)

| Constat | Correctif | Preuve |
| --- | --- | --- |
| [LOW] `apply`/`edit` ne capturaient que `Exception` | `BaseException` → journal `applied:false` puis `ReviewError` statique | [apply](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/tests/test_cli_review.py#L875), [edit](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/tests/test_cli_review.py#L896) |
| [LOW] journal injecté non normalisé | [_journal](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/heimdall/cli/review.py#L611) réémet les erreurs statiques et convertit le reste | [journal en OSError](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/tests/test_cli_review.py#L915), [sans append](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/tests/test_cli_review.py#L937), [statiques préservées](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/tests/test_cli_review.py#L971) |
| [LOW] `review_proposals` sans borne | consommation bornée par `MAX_PROPOSALS` (1024) | [générateur infini borné](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/tests/test_cli_review.py#L944), [borne exacte](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/tests/test_cli_review.py#L961) |

### Revue 5 — LOW environnement, producteur et rendu (`9cece36`)

| Constat | Correctif | Preuve |
| --- | --- | --- |
| [LOW] résolution du journal hors contrat (`Path.home()`, NUL) | [decision_journal_path](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/heimdall/cli/review.py#L337), [DecisionJournal](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/heimdall/cli/review.py#L445), [_resolve_journal](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/heimdall/cli/review.py#L566) | [chemin NUL](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/tests/test_cli_review.py#L988), [HOME indisponible](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/tests/test_cli_review.py#L995), [argument non-Path](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/tests/test_cli_review.py#L1006), [journal par défaut cassé](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/tests/test_cli_review.py#L1011), [JournalError préservée](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/tests/test_cli_review.py#L1079) |
| [LOW] producteur non itérable (`TypeError` brut) | [_review_all](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/heimdall/cli/review.py#L842) | [None/entier/objet](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/tests/test_cli_review.py#L1026), [générateur qui lève](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/tests/test_cli_review.py#L1031) |
| [LOW] rendu non gardé (`MemoryError`, `KeyboardInterrupt`) | [_render](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/heimdall/cli/review.py#L239), [ReviewReport](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/heimdall/cli/review.py#L686) | [boucle](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/tests/test_cli_review.py#L1044), [rapport](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/tests/test_cli_review.py#L1064) |

### Revue 6 — LOW `getattr`, double faute, ordre, journal (`56e71c5`)

| Constat | Correctif | Preuve |
| --- | --- | --- |
| [LOW] `getattr` hors `try` dans `is_interactive` | `getattr` déplacé dans le `try` | [__getattr__ hostile](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/tests/test_cli_review.py#L1095) |
| [LOW] `__context__` backend conservée sur double faute | drapeau + erreur statique levée **hors** du `except` ; [_journal_failure](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/heimdall/cli/review.py#L598) absorbe la panne du journal | [double faute apply](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/tests/test_cli_review.py#L1106), [double faute edit](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/tests/test_cli_review.py#L1134) |
| [LOW] options validées après consommation du producteur | validation `ci`/`interactive` avant [_review_all](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/heimdall/cli/review.py#L842) | [aucune consommation](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/tests/test_cli_review.py#L1158) |
| [LOW] `read`/`append` ne capturaient pas `MemoryError`/`KeyboardInterrupt` | `BaseException` capturé, `JournalError` réémis ou converti | [read](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/tests/test_cli_review.py#L1177), [append](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/tests/test_cli_review.py#L1195) |

### Revue 7 — LOW ré-ancrage de l'édition (`bdfe3d8`)

| Constat | Correctif | Preuve |
| --- | --- | --- |
| [LOW] `edit` pouvait changer le `finding` ou réduire `secrets` | [review_proposal](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/heimdall/cli/review.py#L730) exige `edited.finding == current.finding` et `current.secrets ⊆ edited.secrets` | [finding déplacé refusé](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/tests/test_cli_review.py#L1213), [secrets réduits refusés](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/tests/test_cli_review.py#L1226), [ajout accepté](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/tests/test_cli_review.py#L1237) |
| Volume de session à documenter | borne sur le nombre et par texte ; volume total = responsabilité du producteur T30 | [rendu au plafond](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/tests/test_cli_review.py#L1255) |

### Revue 8 — LOW marqueur, lecture, journal (`fd65e37`)

| Constat | Correctif | Preuve |
| --- | --- | --- |
| [LOW] marqueur `<MASKED_N>` révélait `len(valeur)` | marqueur **constant** (`MASKED_MARKER` = `<MASKED>`) | [marqueur sans longueur](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/tests/test_cli_review.py#L1282) |
| [LOW] `input()` lisait une réponse non bornée | [_stdin_ask](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/heimdall/cli/review.py#L516) lit via `readline(MAX_ANSWER_CHARS + 2)` | [lecture bornée](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/tests/test_cli_review.py#L1306), [flux absents](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/tests/test_cli_review.py#L1333), [EOF](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/tests/test_cli_review.py#L1339) |
| [LOW] relecture du journal sans contrôle de types | [_valid_target](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/heimdall/cli/review.py#L388) : chemin conforme Finding, entier ≥ 1, empreinte hex 64 | [champs étrangers](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/tests/test_cli_review.py#L1369) |

### Revue 9 — LOW filet MCP, trace après apply, volume (`e1b968e`)

| Constat | Correctif | Preuve |
| --- | --- | --- |
| [LOW] le filet MCP `mask_text` révélait `type` + `len` exacte | [_net](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/heimdall/cli/review.py#L160) réécrit le marqueur en `<MASKED>` | [filet heuristique constant](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/tests/test_cli_review.py#L1393) |
| [LOW] patch appliqué sans trace si le journal échoue après `apply` | [_journal_applied](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/heimdall/cli/review.py#L576) : avertissement statique puis `JournalError` | [apply réussi + journal en panne](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/tests/test_cli_review.py#L1409) |
| [LOW] session matérialisée (1024 × 32 × 100 Ko) | traitement **en flux** + borne `MAX_SESSION_BYTES` | [volume dépassé](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/tests/test_cli_review.py#L1438), [volume normal](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/tests/test_cli_review.py#L1447) |

### Revue 10 — LOW flux lu, filet large, octets, stderr (`a4a4fe1`)

| Constat | Correctif | Preuve |
| --- | --- | --- |
| [LOW] TTY vérifié sur `stream` mais lecture sur `sys.stdin` | [_stdin_ask](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/heimdall/cli/review.py#L516) lit **le même objet** que celui contrôlé | [flux vérifié lu](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/tests/test_cli_review.py#L1458) |
| [LOW] `_REDACTION` trop étroit (type hors `[a-z_]`) | motif large `<REDACTED:[^<>]*>` + post-condition fail-closed | [marqueurs réécrits](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/tests/test_cli_review.py#L1502), [malformés refusés](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/tests/test_cli_review.py#L1515) |
| [LOW] volume compté en caractères | [_proposal_bytes](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/heimdall/cli/review.py#L827) compte les **octets UTF-8** | [octets UTF-8](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/tests/test_cli_review.py#L1521) |
| [LOW] `_stderr_notify` laissait passer `BaseException` | `except BaseException` : silence | [stderr hostile](https://github.com/Cezar277/heimdall/blob/a4a4fe16502e9ac932fd40bb98e3f2f51f4f38cb/tests/test_cli_review.py#L1536) |

Hors périmètre, signalé et non corrigé ici : le câblage CLI `heimdall review`
et ses codes de sortie 0/1/2 arrivent avec le backend T30 (#83–#86) ; le
regroupement de #87–#90 dans une seule PR est une exception demandée par
l'utilisateur, tracée dans la PR #192.
