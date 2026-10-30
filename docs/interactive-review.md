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

Preuve locale : `python -m pytest tests/test_cli_review.py` (16 tests pour #87).

## Boucle Y/N/E (#88)

`heimdall.cli.review.review_proposal` affiche le diff masqué puis lit une
réponse. Trois actions seulement, aucune n'est un défaut implicite :

| Réponse | Action | Effet |
| --- | --- | --- |
| `Y` (`yes`, `o`, `oui`) | `Choice.VALIDATE` | journalise, puis appelle le backend d'application |
| `N` (`no`, `non`) | `Choice.IGNORE` | journalise, laisse le secret en place |
| `E` (`edit`) | `Choice.EDIT` | journalise, appelle l'éditeur, réaffiche le nouveau diff et redemande |

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

Ordre volontaire : le journal est écrit **avant** l'application. Un journal
indisponible (`JournalError`) bloque donc la modification : pas de
changement sans trace. Une édition annulée (éditeur fermé sans sauvegarde,
`edit` rendant `None`) réaffiche le diff et redemande.

Chaque choix est journalisé dans `$XDG_STATE_HOME/heimdall/review-decisions.jsonl`
(par défaut `~/.local/state/...`), **hors dépôt**, avec un contrat fermé :
`schema`, `sequence`, `date`, `action`, `file`, `line`, `snippet_hash`,
`previous_hash` et `hash`. La chaîne de hachage réutilise les primitives
durcies de T33 (verrou exclusif, permissions `0600`, append + `fsync`,
relecture intégrale vérifiée) : une entrée modifiée ou réordonnée fait
échouer `DecisionJournal.read()`. Le journal ne contient **jamais** la
valeur du secret : uniquement l'empreinte `snippet_hash` du Finding.

## Mode non interactif (#89)

`is_interactive(ci=..., stream=...)` applique un refus par défaut :

- `ci=True` force le mode non interactif, même si l'appelant demande
  l'inverse (`review_proposals(ci=True, interactive=True)`) ;
- sans TTY sûr (`sys.stdin.isatty()` absent, faux ou en erreur), le mode
  est non interactif ;
- toute ambiguïté (flux sans `isatty`, `OSError`, `ValueError`) est traitée
  comme « pas de terminal ».

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

- `Y` : application après journalisation, diff masqué dans le prompt ;
- `N` : backend jamais appelé, secret laissé en place ;
- `E` : réaffichage du nouveau diff, puis validation de la proposition éditée ;
- entrée invalide : redemande, puis épuisement borné (`MAX_PROMPTS`) ;
- `Y`/`E` sans backend : refus avant journal ;
- édition annulée ou édition rendant un objet étranger : refus sans écriture ;
- mode non interactif : aucun appel à `ask`/`apply`/`edit`/journal ;
- `ci=True` gagnant sur `interactive=True` ;
- détection TTY (absent, faux, en erreur) ;
- journal chaîné : falsification détectée, permissions `0600`, aucune valeur ;
- `scan --ci` : `git status` propre (CliRunner, dépôt jetable).

```sh
python -m pytest tests/test_cli_review.py -v
ruff check heimdall/cli/review.py tests/test_cli_review.py
mypy heimdall tests/test_cli_review.py
```
