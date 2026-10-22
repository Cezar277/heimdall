# CLI `heimdall scan` (#29)

Statut : livré par le ticket #29 (sous-ticket de l'épic #6 « CLI, hook et CI
headless »). La commande est **branchée** sur le scanner déterministe #22 et
sur l'accès git confiné #27. Elle est **en lecture seule** : elle signale, elle
ne répare rien (la remédiation et la validation Y/N/E arrivent avec #32).

Références :

- contrat de sortie : [Finding v1](contracts/finding.md) et
  [`schemas/finding.schema.json`](../schemas/finding.schema.json) (#14) ;
- scanner : [scanner.md](scanner.md) (#22) et
  [scanner-interface.md](scanner-interface.md) (#53) ;
- accès git confiné : [`heimdall/mcp/gitdiff.py`](../heimdall/mcp/gitdiff.py) ;
- implémentation : [`heimdall/cli/scan.py`](../heimdall/cli/scan.py) (logique)
  et [`heimdall/cli/main.py`](../heimdall/cli/main.py) (codes de sortie) ;
- preuves : [`docs/t29-samm.md`](t29-samm.md).

## En une phrase

`heimdall scan` analyse un dépôt à la recherche de secrets et rend un verdict
**déterministe**, porté par son **code de sortie** : 0 (aucun secret), 1
(secrets détectés), 2 (erreur d'outillage — jamais 0 après une erreur).

## Utilisation

```sh
heimdall scan [CHEMIN]              # arbre de travail (mode strict)
heimdall scan --staged [CHEMIN]     # blobs ajoutés ou modifiés dans l'index
heimdall scan --ci [CHEMIN]         # mode CI headless (verdict = code de sortie)
heimdall scan --json [CHEMIN]       # rapport JSON sur stdout
```

| Option | Effet |
| --- | --- |
| `--staged` | change le **périmètre** : les blobs **ajoutés ou modifiés** de l'index git, lus blob par blob, **sans aucune exclusion de chemin** |
| `--ci` | mode **headless** : aucun dialogue, aucun LLM, aucun réseau ; le verdict est le code de sortie, et un résumé déterministe est écrit sur stderr |
| `--json` | le rapport humain est remplacé par le document JSON `heimdall.scan.v1` (stdout) ; les erreurs restent sur stderr |

`CHEMIN` vaut `.` par défaut. Il doit être la **racine** d'un dépôt git en
mode `--staged` (sinon : erreur, code 2).

## Les deux périmètres

| Périmètre | Ce qui est analysé | Exclusions |
| --- | --- | --- |
| `working-tree` (défaut) | l'arbre de travail, en **mode strict** | **techniques** seulement : binaires, répertoires générés (`.git`, `node_modules`, `.venv`, `build`, `dist`…) |
| `staged` (`--staged`) | le contenu **indexé** de chaque fichier ajouté ou modifié | **aucune** : `vendor/`, `third_party/`, `package-lock.json`, `.gitignore`… sont analysés |

Le mode strict est une correction issue de la revue de #165 (point HIGH) :
la politique #59 excluait `vendor/` et les lockfiles, donc un secret posé
dans `vendor/evil.py` n'était **jamais** signalé. Un secret y est un secret :
seules les exclusions *techniques* (contenu binaire ou généré) restent, car
les scanner n'y gagnerait rien et lèverait parfois une erreur de décodage.

En mode `--staged`, c'est le **blob indexé** qui est lu, pas la copie de
travail : c'est ce que le commit va contenir qui est jugé. Le blob entier est
analysé, pas seulement les lignes modifiées — un secret déjà présent dans le
fichier et laissé tel quel reste signalé.

## Codes de sortie

| Code | Signification |
| --- | --- |
| `0` | aucun secret détecté — **le périmètre a été analysé en entier** |
| `1` | au moins un secret détecté |
| `2` | erreur d'outillage : le périmètre n'a **pas** pu être analysé en entier |

Le code 2 est le refus par défaut : racine absente ou illisible, index en
conflit de fusion, blob illisible ou trop gros, clé d'empreinte indisponible,
git absent, erreur inattendue. **Jamais 0 après une erreur** : en CI, un scan
raté ne doit pas laisser passer le pipeline (REQ-SEC-07, invariant 11). Le
code 1 est réservé aux secrets avérés : une panne d'outillage ne sort jamais
en 1.

## Sortie

### Humain (stdout)

```text
heimdall scan : périmètre index git (blobs ajoutés ou modifiés, aucune exclusion de chemin)
1 secret(s) détecté(s) :
  vendor/evil.py:1  type=aws  entropie=3.6842  empreinte=6bf349c39402…  source=regex
Codes de sortie : 0 = aucun secret, 1 = secrets détectés, 2 = erreur d'outillage.
```

**Aucun secret n'est affiché**, jamais en entier, jamais en extrait : un
Finding ne porte qu'une empreinte HMAC-SHA-256 et une entropie. L'empreinte
affiche un préfixe de 12 caractères (le JSON porte la valeur complète) : elle
permet de rapprocher deux scans du même candidat sans le révéler.

### JSON (`--json`, stdout)

```json
{
  "count": 1,
  "findings": [
    {
      "entropy": 3.6842,
      "file": "vendor/evil.py",
      "line": 1,
      "snippet_hash": "6bf349c394023ce70c4a8e37c9a5fba3aefb17df8e20eaa0683da8c980f48852",
      "source": "regex",
      "status": "detecte",
      "type": "aws"
    }
  ],
  "schema": "heimdall.scan.v1",
  "scope": "staged"
}
```

Le document porte le périmètre (`scope`), le nombre de Findings (`count`) et
les Findings eux-mêmes, avec **exactement les sept champs** du contrat
Finding v1 (#14). Il n'y a rien d'autre : pas de valeur de secret, pas de
champ libre, pas d'extrait de ligne.

## Invariants

- **Lecture seule** : un scan n'écrit rien (ni dans le dépôt, ni à côté). La
  clé d'empreinte locale vit hors dépôt (`$XDG_DATA_HOME/heimd/`), comme
  documenté dans [scanner.md](scanner.md#empreinte-et-entropie).
- **Aucun secret en clair** : ni dans la sortie, ni dans un message d'erreur,
  ni dans une traceback (invariant 8).
- **Messages d'erreur statiques** : le chemin fourni n'est jamais reflété.
- **100 % local** : aucun appel réseau. En mode `--staged`, `git cat-file`
  est appelé avec `GIT_NO_LAZY_FETCH=1` : dans un clone partiel, l'objet
  manquant est une erreur, jamais un download.
- **Aucune exécution du contenu analysé** : le dépôt scanné ne peut pas
  faire exécuter une commande (les options git `--no-ext-diff` et
  `--no-textconv` neutralisent `diff.external` et les filtres `textconv`).

## Limites connues (honnêtes)

- Les exclusions **techniques** restent : un secret dans `node_modules/`,
  `build/`, `dist/`, `.venv/` ou dans un fichier binaire n'est pas signalé.
  C'est un choix assumé (contenu généré, lecture binaire), pas un oubli.
- La fenêtre multi-ligne reste bornée à 4 Kio : un secret coupé par un
  retour à la ligne au-delà de cette borne n'est pas recherché.
- Le mode `--staged` analyse l'**index**, pas l'historique : un secret déjà
  commité n'est pas re-detecté par `--staged` (c'est le rôle de
  `heimdall scan` sur l'arbre de travail, et du job de CI de #37).
- Le scanner de signatures ne décode ni base64 ni concaténation de chaînes :
  ces obfuscations restent des `limite_connue` (#23/#24), comme documenté dans
  [scanner.md](scanner.md#limites-connues-honnêtes).
- La validation humaine (Y/N/E) et le remplacement du secret ne sont pas
  dans ce ticket : `scan` signale, il ne répare pas (#32).

## Preuves locales

```sh
.venv/bin/python -m pytest tests/test_cli_scan.py -v
.venv/bin/python -m pytest tests/test_cli_scan.py \
  --cov=heimdall.cli --cov-branch --cov-report=term-missing
.venv/bin/ruff check heimdall tests
.venv/bin/mypy heimdall
```
