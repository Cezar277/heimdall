# Templates de remplacement par langage — T30.1 (#83)

Ticket : [#83](https://github.com/Cezar277/heimdall/issues/83), parent
[#30](https://github.com/Cezar277/heimdall/issues/30).

`heimdall.remediation.templates` transforme **en mémoire** une ligne source
contenant un secret en lecture de variable d'environnement. Il n'écrit aucun
fichier : l'application atomique du patch est le ticket #85 et la garde de
chemin runtime le ticket #86.

## API

```python
from heimdall.remediation import build_replacement, detect_language

plan = build_replacement(
    file="app.py",          # chemin relatif au dépôt (contrat Finding v1)
    source=source,          # texte complet du fichier
    line=42,                # ligne du Finding
    secret=valeur,          # valeur exacte du littéral
    variable="APP_KEY",     # nom validé [A-Z][A-Z0-9_]{1,63}
)

plan.manual_remediation      # False = patch proposé
plan.after                   # source complète après substitution
plan.expression              # os.environ["APP_KEY"]
plan.import_added            # True si « import os » a été ajouté
plan.line_after              # nouvelle ligne du remplacement
```

`detect_language` rend `Language.PYTHON`, `Language.JAVASCRIPT` ou `None`.
Un chemin hors contrat Finding lève `TemplateError` ; une extension inconnue
n'est **pas** une erreur, mais une remédiation manuelle.

## Templates

| Langage | Extensions | Expression |
| --- | --- | --- |
| Python | `.py`, `.pyw` | `os.environ["NOM"]` |
| JavaScript | `.js`, `.mjs`, `.cjs` | `process.env.NOM` |

- Python : `os.environ[...]` échoue clairement au démarrage si la variable
  manque, contrairement à `os.getenv`.
- JavaScript : `process.env.NOM`.
- `.pyi`, `.jsx`, `.ts` et les extensions inconnues sont refusés : un stub,
  un attribut JSX ou une annotation TypeScript ne sont pas des littéraux JS
  remplaçables par un identifiant sans changer la grammaire.

## Substitution

Seul le **littéral de chaîne** est remplacé, jamais la ligne :

```python
API_KEY = "valeur-synthetique"      # avant
API_KEY = os.environ["API_KEY"]     # après
```

En JavaScript :

```javascript
const apiKey = "valeur-synthetique";    // avant
const apiKey = process.env.API_KEY;     // après
```

La valeur passée doit être la valeur **exacte** du littéral. Une sous-chaîne
(par exemple l'en-tête d'une PEM dans un littéral plus long) est refusée :
le moteur ne devine pas quelles autres données du littéral doivent survivre.

### Import Python

`import os` est ajouté seulement s'il n'existe pas déjà au niveau module :

- après le docstring de module et les imports `from __future__` (sinon le
  fichier ne parse plus) ;
- avant les décorateurs de la première instruction ;
- en conservant shebang, commentaire d'encodage et style CRLF.

`import os.path`, `import os as autre_nom`, `from os import environ` et
`import os` sont reconnus. Toute autre liaison du nom `os` (affectation,
paramètre, `import sys as os`, `from x import os`) provoque une remédiation
manuelle : `os.environ` serait ambigu dans ce fichier.

## Refus fail-closed

Un résultat `manual_remediation=True` a toujours `after == before`, aucune
expression et une raison stable (`ManualReason`) :

| Cas | Raison |
| --- | --- |
| Extension non prise en charge | `UNSUPPORTED_LANGUAGE` |
| Fichier non parsable / chaîne non fermée | `INVALID_SYNTAX` |
| Ligne absente du fichier | `STALE_LINE` |
| Valeur absente de la ligne | `SECRET_NOT_FOUND` |
| Valeur présente mais pas dans un littéral simple exact | `NO_SIMPLE_LITERAL` |
| Plusieurs littéraux identiques sur la ligne | `MULTIPLE_LITERALS` |
| F-string ou template literal | `AMBIGUOUS_STRING` |
| Concaténation explicite (`+`/`-`) ou implicite (chaîne adjacente, non reconnue par le tokenizer JS) | `AMBIGUOUS_CONCATENATION` |
| Docstring, annotation, `match`, clé/méthode d'objet, import statique | `AMBIGUOUS_CONTEXT` |
| Clé déjà assainie lue via `os.environ[...]`/`os.getenv(...)`, `getattr(os, ...)`/`operator.getitem(os.environ, ...)`, `os.environ.get(...)`, ou via `process.env[...]`, `process.env.get(...)`, `process["env"][...]`, `Reflect.get(process.env, ...)`, `process?.env[...]`, `process?.[...]` | `AMBIGUOUS_CONTEXT` |
| Accès `os.environ` indirect (curryfication `getattr(os.environ, "get")`, sous-référence `vars(os.environ)`/`getattr(os, "environ")`) | `AMBIGUOUS_CONTEXT` |
| Accès indirect par import dynamique (`__import__("os")`, `importlib.import_module("os")`) : le module léger serait contourné | `AMBIGUOUS_CONTEXT` |
| Littéral passé à `eval`/`exec`/`compile`/`__import__` (Python : `eval`, `exec`, `compile`, `__import__`, y compris par attribut `builtins.eval`, `__builtins__.exec` et curryfié `getattr(__builtins__, "eval")(...)` ; JavaScript : `eval`, `Function`, `compile`, `setTimeout`/`setInterval` à premier argument chaîne, y compris optionnel `eval?.(...)` et indirect `(0, eval)(...)`) : la valeur d'environnement serait ré-évaluée comme du code | `AMBIGUOUS_CONTEXT` |
| Littéral nommant une entrée d'espace de noms (`vars()["NOM"]`, `locals()["NOM"]`, `globals()["NOM"]`) : le patch lirait la valeur d'environnement à la place de l'entrée locale | `AMBIGUOUS_CONTEXT` |
| Clé de propriété calculée hors fenêtre littérale bornée (`process["en" + "v"]...`, `process["env"][...]`, `process["env"][(a0, ..., a14, "SECRET")]`, `process?.[...]`) : la fenêtre est désormais bornée par le délimiteur ouvrant englobant le littéral | `AMBIGUOUS_CONTEXT` |
| Directive prologue JavaScript (`"use strict"`) | `AMBIGUOUS_CONTEXT` |
| Nom `os` masqué côté Python ou `process` masqué côté JavaScript | `SHADOWED_MODULE` |

Cas particuliers refusés côté JavaScript : clé d'objet littérale
(`{"secret": 1}`), nom de méthode ou champ de classe, spécificateur
`import`/`from`, `require(...)`. Un nom `process` lié localement (paramètre,
`var`/`let`/`const`, fonction/classe, import, déstructuration, `catch`,
affectation) provoque aussi `SHADOWED_MODULE` : le patch ne doit jamais lire un
objet qui n'est pas le global Node. Côté Python : f-string, concaténation,
docstring, annotation, motif `case`, littéral multiligne.

JSX et TypeScript sont hors périmètre : leurs extensions (`.jsx`, `.tsx`,
`.ts`) sont refusées en remédiation manuelle. Un fichier `.js` qui contient
du JSX doit également être revu manuellement, car un attribut JSX n'est pas
une chaîne JavaScript ordinaire.

## Sécurité

- **Aucune exécution** du code analysé : `ast.parse` et `tokenize` lisent, la
  valeur d'un littéral vient de l'AST, jamais d'un `eval`/`exec`.
- **Aucune I/O, aucun réseau**, aucune dépendance hors bibliothèque standard
  et `heimdall.scanner.finding` (validation lexicale du chemin).
- **Injection de code impossible** : le nom de variable doit satisfaire
  `^[A-Z][A-Z0-9_]{1,63}$` avant d'entrer dans le template.
- **Bornes** : source 1 Mio UTF-8, secret 100 000 caractères, chemin 4096
  caractères. Toute erreur d'API est statique et ne reflète jamais l'entrée.
- **Pas de fuite par `repr`** : `before` et `after` sont exclus de la
  représentation du plan, et la valeur décodée d'un jeton JavaScript
  (`_JsToken.value`) est également masquée. Un journal de session n'y verra
  pas le secret.
- **Patch vérifié** : après substitution et ajout éventuel de l'import, le
  texte Python final doit reparser ; sinon aucun patch n'est rendu. Côté
  JavaScript, aucun patch n'est rendu sur un contexte ambigu (concaténation
  implicite, clé dynamique, directive prologue, `os`/`process` masqué…) : la
  substitution n'est appliquée qu'à un littéral dont le contexte lexical est
  sûr, et le tokenizer ne fait pas de reparsing JS (hors bibliothèque standard
  du projet).

La denylist sémantique (`PATH`, `LD_PRELOAD`, `PYTHONPATH`…) et le
dédoublonnage `_2`/`_3` restent dans #84. L'écriture atomique et la
vérification de chemin à l'usage restent dans #85/#86.

## Tests

```bash
.venv/bin/pytest -q tests/test_remediation_templates.py
```

La preuve d'acceptation
[`test_replacement_is_correct_on_every_plain_leak_of_the_trap_repo`](../tests/test_remediation_templates.py)
matérialise le corpus T21 et remplace les 10 fuites simples (5 Python,
5 JavaScript) sans jamais modifier `tests/fixtures/trap_repo` lui-même.
