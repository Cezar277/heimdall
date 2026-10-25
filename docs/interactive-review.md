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
