# Validation humaine T32

## Rendu (#87)

`heimdall.cli.review.Proposal` reçoit un `Finding`, le nom de variable,
les snapshots `TextChange` avant/après et **toutes les valeurs sensibles
connues**, y compris dans le contexte. Le producteur T30 fournit ces données
en mémoire : aucun manifeste contenant des secrets n'est écrit sur disque.
Les contenus et valeurs sont exclus de `repr`.

`render_diff` utilise `difflib.unified_diff`. Les valeurs connues sont entièrement
masquées avant le calcul du diff ; le masque conservateur MCP ajoute un filet
pour les autres candidats. Les références `os.getenv`, `os.environ` et
`process.env` restent lisibles. Le diff comprend les fichiers de code,
`.env.example` et `.gitignore` fournis par le producteur. Le contenu des `.env`
et de `.git` est refusé. Les contrôles terminal et caractères directionnels
sont échappés ; aucune séquence ANSI issue d'un fichier n'est exécutée.

Le producteur doit refuser les patches approximatifs et inclure tous les
changements dans la proposition affichée. Le moteur de remplacement T30
(#83–#86) n'est pas encore livré sur cette branche : cette interface ne
génère pas de remplacements et n'ouvre aucun fichier source.

Preuve locale : `python -m pytest tests/test_cli_review.py` (98 tests pour #87–#90).

## Boucle Y/N/E (#88)

`heimdall.cli.review.review_proposal` affiche le diff masqué puis lit une
réponse. Trois actions seulement, aucune n'est un défaut implicite :

| Réponse | Action | Effet |
| --- | --- | --- |
| `Y` (`yes`, `o`, `oui`) | `Choice.VALIDATE` | appelle le backend, puis journalise le résultat réel |
| `N` (`no`, `non`) | `Choice.IGNORE` | journalise, laisse le secret en place |
| `E` (`edit`) | `Choice.EDIT` | appelle l'éditeur, journalise, réaffiche le nouveau diff et redemande |

`parse_choice` refuse tout le reste (chaîne vide, Entrée seule, valeur
inconnue, réponse de plus de 16 caractères) : la boucle réaffiche
l'avertissement statique et **redemande**, sans jamais deviner. Deux bornes
évitent une boucle infinie : `MAX_PROMPTS` (16 réponses, invalides comprises)
et `MAX_EDITS` (8 éditions successives). Les dépasser est une
`ReviewError`, donc une erreur d'outillage côté CLI (code 2), jamais une
validation implicite.

`apply` et `edit` sont **injectés** : c'est le backend T30 (#83–#86) qui
calcule et pose le patch atomique, cette interface ne touche aucun fichier.
Sans backend, `Y` et `E` sont refusés (`ReviewError`) **avant** toute
écriture au journal : aucune trace ne prétend qu'une action a eu lieu.

Toute exception du backend est convertie en `ReviewError` **statique**
(`raise ... from None`) : le message, le chemin ou la valeur portés par
l'exception T30 ne sortent jamais sur stderr ni dans un journal. Le journal
est ensuite écrit **après** l'action, avec le champ `applied` qui reflète ce
qui s'est réellement passé : `true` seulement si `apply` a rendu la main
sans erreur, `false` pour `N`, `E`, une édition annulée ou un échec. Un
audit ne prétend donc jamais qu'une tentative a abouti.

Une édition annulée (éditeur fermé sans sauvegarde, `edit` rendant `None`)
réaffiche le diff et redemande.

Chaque choix est journalisé dans `$XDG_STATE_HOME/heimdall/review-decisions.jsonl`
(par défaut `~/.local/state/...`), **hors dépôt**, avec un contrat fermé :
`schema`, `sequence`, `date`, `action`, `applied`, `file`, `line`,
`snippet_hash`, `previous_hash` et `hash`. Un `applied: true` avec une action
autre que `Y` est refusé à la construction **et** à la relecture. La chaîne de hachage réutilise les primitives
durcies de T33 (verrou exclusif, permissions `0600`, append + `fsync`,
relecture intégrale vérifiée) : une entrée modifiée ou réordonnée fait
échouer `DecisionJournal.read()`. Le journal ne contient **jamais** la
valeur du secret : uniquement l'empreinte `snippet_hash` du Finding.

## Mode non interactif (#89)

`is_interactive(ci=..., stream=...)` applique un refus par défaut :

- `ci=True` force le mode non interactif, même si l'appelant demande
  l'inverse (`review_proposals(ci=True, interactive=True)`) ;
- `interactive=True` **ne suffit jamais** : il faut aussi un TTY sûr. Un
  appelant qui force l'interactif sur un stdin pipé
  (`echo y | heimdall review`) retombe en mode non interactif au lieu d'y
  voir une validation humaine ;
- sans TTY sûr (`sys.stdin.isatty()` absent, faux ou en erreur), le mode
  est non interactif ;
- toute ambiguïté (flux sans `isatty`, `OSError`, `ValueError`,
  `RuntimeError` d'un flux exotique) est traitée comme « pas de terminal » ;
- une lecture clavier impossible (`EOFError`, `OSError`, `ValueError`,
  `KeyboardInterrupt`) devient une `ReviewError` statique : jamais de
  traceback, et jamais le code 1 réservé aux secrets avérés.

Dans ce mode, `review_proposal` rend un `ReviewOutcome` sans action
(`action=None`, `applied=False`) et n'appelle **ni** `ask`, **ni** `apply`,
**ni** `edit`, **ni** le journal : rapport seul, aucune écriture. C'est
l'inverse du piège « auto-valider quand personne ne répond ».

`ReviewReport.render()` produit alors le rapport masqué et le décompte
(`N proposition(s), M appliquée(s), K restante(s)`). Le code de sortie
attendu pour l'appelant suit le contrat de `scan` : 0 si `remaining == 0`,
1 si des propositions restent, 2 sur erreur d'outillage.

Preuve opérateur : `heimdall scan --ci` ne modifie rien dans le dépôt
(`git status` propre, ni `.env`, ni `.env.example`, ni `.gitignore`).

## Tests du flux interactif (#90)

`tests/test_cli_review.py` simule le clavier en injectant `ask` (alternative
documentée au `CliRunner(input=...)` de Typer) et couvre :

- `Y` : application puis journal `applied: true`, diff masqué dans le prompt ;
- `N` : backend jamais appelé, secret laissé en place, `applied: false` ;
- `E` : réaffichage du nouveau diff, puis validation de la proposition éditée ;
- entrée invalide : redemande, puis épuisement borné (`MAX_PROMPTS`) ;
- `Y`/`E` sans backend : refus avant journal ;
- échec du backend `apply`/`edit` (message contenant la valeur et un chemin) :
  `ReviewError` statique, `__cause__` nulle, journal `applied: false`, aucune
  valeur écrite ;
- édition annulée ou édition rendant un objet étranger : refus sans écriture ;
- mode non interactif : aucun appel à `ask`/`apply`/`edit`/journal ;
- `ci=True` gagnant sur `interactive=True` ;
- `interactive=True` sur un stdin pipé : reste non interactif ;
- détection TTY (absent, faux, en erreur, `RuntimeError`) ;
- lecture clavier en échec (`OSError`, `KeyboardInterrupt`) : erreur statique ;
- `ask`/`notify` injectés qui lèvent avec une valeur dans le message : rien
  sur stderr, `ReviewError` statique, journal vide ou intact ;
- `isatty` levant `KeyboardInterrupt`/`SystemExit` : non interactif ;
- `XDG_STATE_HOME` relatif ou contenant `..` : `JournalError` statique ;
- masquage borné : total des valeurs > `MAX_SECRET_BYTES` refusé, 256 valeurs
  longues acceptées et masquées ;
- grammaires alignées sur l'invariant 2 (`_`, `A`, `_APP` refusés) ;
- chemins privés insensibles à la casse (`.Git/config`, `.ENV`, `.Env.local`) ;
- journal chaîné : falsification détectée, `applied` incohérent refusé,
  permissions `0600`, aucune valeur ;
- `scan --ci` : `git status` propre (CliRunner, dépôt jetable).

```sh
python -m pytest tests/test_cli_review.py -v
ruff check heimdall/cli/review.py tests/test_cli_review.py
mypy heimdall tests/test_cli_review.py
```

## Durcissements après revue de code

| Constat | Correctif |
| --- | --- |
| [HIGH] `interactive=True` contournait le garde TTY (auto-validation sur stdin pipé) | `review_proposal` exige `is_interactive(stream=...)` en plus de `interactive=True` ; `review_proposals` combine `ci`, `interactive is False` et TTY |
| [HIGH] exceptions `apply`/`edit` brutes et journal déjà écrit | `raise ReviewError from None` autour du backend ; journal écrit **après** l'action avec `applied: bool` |
| [MEDIUM] motif de masquage géant recompilé par ligne, `re.error` fuyante | total borné par `MAX_SECRET_BYTES` dans `Proposal`, motif compilé **une fois** par `render_diff`, `re.error` convertie en `ReviewError` |
| [MEDIUM] grammaire de variable plus lâche que l'invariant 2 | `[A-Z][A-Z0-9_]{1,63}` pour `_VARIABLE` **et** `_ENV_REFERENCE` |
| [LOW] garde `.env`/`.git` sensible à la casse | comparaison `lower()` sur tous les segments |
| [LOW] `_stdin_ask`/`is_interactive` trop étroits | `EOFError`/`OSError`/`ValueError`/`KeyboardInterrupt` → `ReviewError` ; `isatty` en erreur → non interactif |
| [LOW] exceptions d'un `ask`/`notify` injecté non normalisées | `_ask` convertit toute exception (hors `ReviewError`) en erreur statique ; `_notify` reste best-effort et ne laisse jamais ressortir son exception |
| [LOW] `is_interactive` laissait passer `BaseException` | `except BaseException` → refus par défaut (non interactif), sans traceback |
