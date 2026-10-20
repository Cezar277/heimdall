# Interface du scanner et sortie Finding (#53)

Statut : livré par le ticket #53 (sous-ticket de l'épic #22). Ce document fixe
la **surface** du scanner et la **forme** de sa sortie. Il ne décrit aucune
détection : les signatures (#54) et les exclusions (#59) restent des tickets
séparés, tout comme la mesure sur le jeu piège (#60).

Références :

- contrat de sortie : [Finding v1](contracts/finding.md) et
  [`schemas/finding.schema.json`](../schemas/finding.schema.json) (ticket #14) ;
- machine d'états et choix d'empreinte : [ADR-001](adr/001-finding-et-etats.md) ;
- implémentation : [`heimdall/scanner/finding.py`](../heimdall/scanner/finding.py)
  (sortie) et [`heimdall/scanner/interface.py`](../heimdall/scanner/interface.py)
  (cible + façade) ;
- tests : [`tests/test_scanner_interface.py`](../tests/test_scanner_interface.py).

## En une phrase

Le scanner expose **une** méthode, `scan(cible) -> list[Finding]`, et rend des
Findings qui sont conformes au schéma #14 **par construction**.

```python
from heimdall.scanner import DiffTarget, FileTarget, Finding, Scanner

scanner = Scanner(moteur)  # moteur de détection injecté (signatures, entropie)

# Cible 1 : les lignes ajoutées du diff indexé (numéros de ligne réels).
diff = DiffTarget(path="src/app.py", lines=((12, "TOKEN = ..."),))
# Cible 2 : un fichier entier (démarrage à froid).
fichier = FileTarget(path="src/app.py", text=open("src/app.py").read())

findings: list[Finding] = scanner.scan(diff)
```

## La cible

| Cible | Quand | Contenu |
| --- | --- | --- |
| `DiffTarget` | flux nominal : le commit en cours | les lignes **ajoutées**, avec le numéro de ligne réel de chacune dans le fichier |
| `FileTarget` | démarrage à froid : premier scan du dépôt | le fichier entier, numéroté à partir de 1 |

Les deux cibles sont figées (immuables) et validées à la construction :

- le chemin est **relatif au dépôt**, avec `/` comme séparateur, sans segment
  vide, sans segment `.` ou `..`, sans caractère de contrôle : c'est la
  grammaire lexicale du contrat #14, appliquée avant toute lecture ;
- les numéros de ligne d'un `DiffTarget` sont des entiers ≥ 1 **strictement
  croissants** (le parseur de diff du MCP produit déjà cette forme :
  `DiffEntry.lines`) ;
- un conteneur de lignes ou une ligne malformée est refusé : `lines` doit
  être une suite de couples `(entier, texte)`, et le résultat est normalisé
  en tuple de couples.

Un chemin refusé est une **erreur** (`InvalidTarget`), pas un fichier ignoré
en silence : une cible illisible ne doit jamais devenir « aucun secret ».

### Le contenu analysé n'apparaît jamais dans un `repr`

Les lignes ajoutées du diff et le contenu du fichier sont **exactement là où
vivent les secrets**. Un `log.debug("%r", cible)`, un `print` de débogage ou
une traceback future ne doivent pas les écrire en clair (invariant 8).

Les deux cibles excluent donc leur contenu du `repr` (`field(repr=False)`) et
exposent un `repr` résumé : `DiffTarget(path='src/app.py', lignes=3)` et
`FileTarget(path='src/app.py', caracteres=812)`. Le chemin et la taille
restent visibles, le contenu jamais. Le `Finding`, lui, ne porte qu'une
empreinte : son `repr` est sûr et n'a pas besoin d'être masqué.

## La sortie

`Finding` est une dataclass figée (`frozen=True`, `slots=True`) avec
**exactement** les sept champs du schéma #14 :

| Champ | Type | Règle |
| --- | --- | --- |
| `file` | `str` | chemin relatif au dépôt, 1 à 4096 caractères |
| `line` | `int` | ≥ 1, indexée à partir de 1 |
| `type` | `str` | catégorie en `snake_case` ASCII, 1 à 64 caractères |
| `entropy` | `float` | 0 à 8 bits par octet (Shannon sur les octets UTF-8) |
| `snippet_hash` | `str` | HMAC-SHA-256 en hexadécimal minuscule (64 caractères) |
| `status` | `str` | `detecte`, `confirme`, `vaulte`, `rote`, `faux_positif` |
| `source` | `str` | `regex`, `entropy`, `llm` |

Points de vigilance :

- **aucune valeur de secret** dans un Finding : ni champ, ni extrait, ni
  message d'erreur. `snippet_hash` est une empreinte (ADR-001), `entropy` une
  métadonnée ;
- les messages d'erreur sont **statiques** : la valeur refusée n'est jamais
  reflétée (invariant 8) ;
- un Finding non conforme **n'existe pas** : la validation est faite à la
  construction, pas au moment de l'affichage ;
- `as_dict()` rend exactement les sept champs (ce que le MCP sérialise, que la
  CLI affiche, que le Vault relit) et `from_dict()` relit un Finding sérialisé
  en refusant toute propriété inconnue ou manquante.

## Les invariants de la façade

`Scanner` n'implémente aucune détection : elle délègue au moteur injecté et
**garantit la sortie**. Elle refuse (`ScanError`, fail-closed) toute sortie qui

1. n'est pas un `Finding` ;
2. ne porte pas le chemin de la cible analysée ;
3. n'est pas dans l'état initial `detecte` ;
4. n'a pas une origine déterministe (`regex` ou `entropy`).

Le point 3 est la traduction directe de la machine d'états du contrat #14 : le
LLM propose, il ne décide pas. Le trieur travaille sur une copie du candidat
et rend son avis à l'humain ; il ne fait jamais passer un Finding de
`detecte` à `confirme` ou `faux_positif` tout seul. Le point 4 exclut donc
`source: llm` **de la sortie du scanner** (le champ reste autorisé par le
schéma pour les autres couches).

L'ordre de sortie est stable : `scan()` trie par `(ligne, type, empreinte)` et
`scan_all()` par `(fichier, ligne, type, empreinte)`. Deux scans de la même
cible rendent donc la même liste, dans le même ordre.

## Le contrat d'erreur : un seul type

Tout ce qui entre dans le scanner vient d'une frontière non fiable (parseur
MCP, CLI, données relues du Vault ou d'un cache). Le contrat d'erreur est donc
**unique et typé** :

| Erreur | Lever par | Sens |
| --- | --- | --- |
| `InvalidFinding` | `Finding(...)`, `Finding.from_dict(...)` | la donnée ne respecte pas le contrat #14 |
| `InvalidTarget` | `DiffTarget(...)`, `FileTarget(...)`, `Scanner.scan(cible)` | la cible est inexploitable |
| `ScanError` | `Scanner(moteur)`, `Scanner.scan(...)` | moteur ou sortie inexploitables |

Les trois dérivent de `ScanError`, lui-même de `Exception` ; `InvalidFinding`
et `InvalidTarget` dérivent aussi de `ValueError`, pour les appelants qui
traitent les erreurs de contrat comme des valeurs invalides.

Aucune `TypeError` ni `AttributeError` brute ne doit sortir de l'interface :
un `status` non hashable, un conteneur de lignes malformé, une cible qui
n'est pas une cible ou un moteur sans méthode `analyser` sont refusés par
l'erreur de contrat, que l'appelant (Vault, CLI) sait catcher. Le refus
reste fail-closed dans tous les cas : il bloque, il ne rend jamais la main
sur une liste partielle.

## Ce que ce ticket ne fait pas

- **Aucune I/O.** L'interface ne lit aucun fichier et n'ouvre aucun
  descripteur : elle ne fait que valider et transporter. La lecture du
  fichier appartient au moteur (#54/#59), qui doit appliquer le confinement
  complet.
- **La garde de chemin est lexicale, et ce n'est pas assez.** `..`, un chemin
  absolu, `C:/` ou un caractère de contrôle sont refusés *avant* toute
  lecture, mais cette garde **ne protège pas contre les liens symboliques ni
  contre le TOCTOU**. Conformément à l'invariant 3, le consommateur doit, sur
  une racine fixée au démarrage, résoudre le chemin
  (`resolve` + `is_relative_to(racine)`), refuser les liens sortants et
  revérifier l'identité du descripteur à l'usage. C'est le cas de
  `heimdall/mcp/gitdiff.py` et de la lecture de fichier par #54/#59 ; la garde
  lexicale de ce ticket ne doit pas être considérée comme suffisante.

## Le code est au moins aussi strict que le schéma

La validation locale reproduit la grammaire du schéma #14, et le test
`tests/test_scanner_interface.py` compare les deux sur un corpus de cas
valides et invalides : **accord sur tous les cas**, sauf deux écarts assumés,
où le code est plus strict que le schéma (il refuse, il ne répare pas) :

| Cas | Schéma | Code |
| --- | --- | --- |
| `line: 1.0` | accepté (le draft 6 considère un flottant entier comme un entier) | refusé : une ligne de fichier est un entier |
| `entropy: NaN` | accepté (les comparaisons de `jsonschema` sont fausses pour NaN) | refusé : NaN n'est pas du JSON |

## Branches avec le reste du projet

- Le serveur MCP (`heimdall/mcp/gitdiff.py`) produit déjà les lignes ajoutées
  du diff indexé : `DiffTarget(entry.path, entry.lines)` est direct.
- La CLI (`heimdall scan --ci`) consumera `scan_all()` sur les cibles du diff,
  puis `as_dict()` pour la sortie JSON.
- Le Vault relira un Finding avec `Finding.from_dict()`.

## Relation avec l'épic #22

La branche de l'épic (#22) contient une implémentation complète du scanner
(signatures, exclusions, empreintes) qui définit **sa propre** classe `Finding`
et **son propre** `Scanner(root)`. Ce ticket fixe l'interface ; l'épic fournit
le moteur. Pour éviter deux définitions concurrentes de la sortie, la
réconciliation proposée au relecteur est :

1. l'épic importe `Finding` depuis `heimdall.scanner.finding` (source de
   vérité unique) au lieu de le redéclarer ;
2. le moteur de l'épic est appelé par la façade `Scanner` de ce ticket, qui
   ajoute la cible (diff ou fichier) et les invariants de sortie.

Ce ticket ne modifie pas l'épic : il fournit l'interface et le contrat, sans
toucher aux signatures ni aux exclusions.

## Contraintes pour le moteur (#54 / #59)

Le moteur injecté doit :

- rendre des `Finding` **déjà conformes** (la façade les revalide de toute
  façon, et refuse un objet qui ne l'est pas) ;
- ne rendre **que** des Findings de la cible analysée, dans l'état `detecte`,
  avec une origine `regex` ou `entropy` ;
- ne jamais rendre la valeur brute d'un candidat : la façade ne manipule que
  des empreintes ;
- appliquer, avant toute lecture, le confinement complet de l'invariant 3
  (`resolve` + `is_relative_to` sur une racine fixée, refus des liens
  sortants, identité de descripteur revérifiée à l'usage) : la garde lexicale
  des cibles ne suffit pas.

## Preuves locales

```sh
.venv/bin/python -m pytest tests/test_scanner_interface.py -v
.venv/bin/python -m pytest --cov=heimdall.scanner --cov-branch \
  --cov-report=term-missing --cov-fail-under=85
.venv/bin/ruff check heimdall tests
.venv/bin/mypy heimdall
```

Les couples module + ligne et les liens permanents sont dans
[t53-samm.md](t53-samm.md).
