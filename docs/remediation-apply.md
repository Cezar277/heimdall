# Validation, application atomique et garde de chemin — T30.2/T30.3/T30.4 (#84/#85/#86)

Tickets : [#84](https://github.com/Cezar277/heimdall/issues/84),
[#85](https://github.com/Cezar277/heimdall/issues/85),
[#86](https://github.com/Cezar277/heimdall/issues/86), parent
[#30](https://github.com/Cezar277/heimdall/issues/30).

> **Exception validée au contrat « un sous-ticket par PR » (ticket parent #30)** :
> Le regroupement de #84 (validation des noms), #85 (application atomique) et
> #86 (garde de chemin et tests) au sein d'une seule PR est une exception validée
> sous le ticket parent #30. Elle est justifiée techniquement par le partage
> direct du module `heimdall.remediation`, de la garde de chemin unique `confine`
> et des structures de données partagées, évitant du code mort intermédiaire ou
> des bifurcations transitoires. Cette exception est circonscrite à ce triptyque
> et ne constitue pas un précédent pour les autres sous-tickets.

`heimdall.remediation.naming` valide les noms de variables proposés par le
LLM (entrée non fiable) et dédoublonne (`_2`, `_3`…). `heimdall.remediation.apply`
applique un `ReplacementPlan` sur disque de façon atomique, sous garde de
chemin anti-traversée.

## Validation des noms (T30.2, #84)

```python
from heimdall.remediation import deduplicate_variable_name, validate_variable_name

name = validate_variable_name(proposal)  # lève TemplateError si invalide
final = deduplicate_variable_name(name, taken)  # {"APP_KEY"} -> "APP_KEY_2"
```

- Grammaire fermée `^[A-Z][A-Z0-9_]{1,63}$` (identique aux grammaires
  historiques de `templates`, de la CLI `review` et du client Vault —
  un test fige leur équivalence) : pas de retour à la ligne, donc pas
  d'injection de lignes dans le `.env`.
- Denylist système (`PATH`, `LD_PRELOAD`, `PYTHONPATH`, préfixes `LD_`,
  `PYTHON`, `HEIMDALL_`…) : source unique ici, réutilisée par
  `heimdall vault` (`cli/vault_client.py` délègue à ce module, sans copie
  qui divergerait).
- `deduplicate_variable_name` refuse (`TemplateError`) plutôt que tronquer
  quand aucun suffixe ne tient dans 64 caractères.

## Application atomique (T30.3, #85)

```python
from pathlib import Path
from heimdall.remediation import apply_replacement, undo_apply

receipt = apply_replacement(Path("dépôt"), plan)  # lève ApplyError sinon
# ...
undo_apply(Path("dépôt"), receipt)  # restaure la sauvegarde
```

- Le fichier courant est relu par la garde unique `vault.atomic` (parents
  ouverts composant par composant avec `O_NOFOLLOW`, cible en `O_NONBLOCK`,
  fichier régulier, borne 1 Mio, UTF-8 strict) puis comparé à `plan.before` :
  un fichier modifié depuis le plan (**STALE**) n'est jamais écrasé.
- Sauvegarde préalable (`<fichier>.bak`, mode `0600` — elle contient le
  secret en clair), puis écriture via `vault.atomic.write_file_atomic`
  (temporaire + `fsync` + `os.replace` atomique, aucun fichier à moitié écrit).
- **Garde Git et nettoyage obligatoire** : `apply_replacement` contrôle à
  l'exécution le statut Git de `<fichier>.bak` via `is_git_tracked` et
  `is_git_ignored` (politique alignée sur `heimdall vault pull --backup`) :
  avertissement immédiat sur `stderr` si le `.bak` est suivi par Git, s'il
  n'est pas ignoré ou si le statut est indéterminé, sans écrire de règle
  `.gitignore` silencieuse. Avant tout commit, supprimer les `.bak` créés (ou
  `undo_apply`, puis suppression) et vérifier `git status` ; ne jamais
  committer un `*.bak` contenant un secret.
- `AppliedPatch.backup` est relatif à la racine (jamais de chemin absolu dans
  les logs). `undo_apply` valide le reçu (`backup` attendu, `mode` entier
  `0..0o777`) avant toute écriture.
- Les permissions d'origine sont conservées (`fchmod` explicite, pas le
  `0600` par défaut des secrets du Vault).
- `undo_apply` ne restaure que si le fichier vaut encore `receipt.after`
  (sinon `ApplyError`, sans toucher au fichier) ; la sauvegarde est
  conservée, un second `undo` échoue donc sur le contrôle snapshot.
- `AppliedPatch` n'embarque ni `before` (secret) ni contenu sensible :
  `repr()` sûr, comme `ReplacementPlan`.

## Garde de chemin (T30.4, #86)

`apply_replacement` / `undo_apply` confinent `plan.file` avec
`mcp.paths.confine` (la garde unique du ticket #27.3.1 : `resolve()` +
`is_relative_to`, refus des absolus et des liens sortants), réutilisée
telle quelle, jamais recopiée. Sont refusés (`ApplyError`, rien n'est
écrit) : `../`, chemins absolus, liens symboliques sortants.

## Sécurité

- **Aucune exécution** du code scanné, aucun réseau, aucun shell.
- **Aucune fuite** : messages d'erreur statiques (`ApplyError` unique, sans
  reflet de l'entrée), `repr()` sans secret, sauvegarde en `0600`.
- **Fail-closed partout** : plan manuel, fichier absent/modifié/déjà
  restauré, garde de chemin, écriture impossible → `ApplyError`, le
  fichier d'origine reste intact (vérifié : pas de `.tmp.*` résiduel).

## Tests

```bash
.venv/bin/pytest -q tests/test_remediation_naming.py tests/test_remediation_apply.py
```

`tests/test_remediation_naming.py` (T30.2) et
`tests/test_remediation_apply.py` (T30.3/#86) travaillent sur `tmp_path`
uniquement ; valeurs toutes synthétiques.
