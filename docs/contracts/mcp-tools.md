# Contrat des outils MCP (v1)

> Ticket #16 · Porteur : B · Relecteur : D · Sprint S1
> Fichier de référence machine : [`mcp-tools.schema.json`](../../schemas/mcp-tools.schema.json) (JSON Schema 2020-12)
> Tests : `tests/contracts/test_mcp_tools_schema.py`

## 1. Pourquoi ce document

Le LLM local (Ollama) n'agit sur le dépôt que par l'intermédiaire du serveur MCP. **Chaque outil est une porte** : plus il y en a, plus la surface d'attaque (prompt injection, path traversal) est grande. Ce contrat liste donc ce que le LLM **peut** faire (4 outils, tous en lecture seule) et surtout ce qu'il **ne peut pas** faire.

Règle d'or du projet : **le LLM propose, le programme vérifie, l'humain valide.**

Ce contrat est consommé par :

| Ticket | Usage |
|---|---|
| #27 Serveur MCP minimal | implémente `read_diff` et `sanitize_file`, garde de chemin |
| #28 Intégration Ollama | prompt et validation de la sortie du LLM |
| #30 Remplacement par variable d'env. | implémente `propose_patch` côté remédiation |
| #34 Défense injection de prompt | moindre privilège, corpus de payloads |
| #18 / #19 Menaces et exigences | chaque outil est une frontière de confiance du DFD |

## 1 bis. Ce que ce document prouve, et ce qu'il ne prouve pas

Un JSON Schema décrit des **formes de données**. Il ne prouve pas qu'un outil n'écrit rien sur le disque, ni qu'une garde de chemin résout correctement un lien symbolique sortant. Présenter « 4 outils en lecture seule » comme une démonstration falsifierait la preuve pour le rapport et pour l'audit croisé.

| Affirmation | Statut |
|---|---|
| Surface fermée : 4 outils, aucun autre nom appelable | **prouvé statiquement** |
| Entrées/sorties strictes, invariants conditionnels, erreurs exclusives du succès | **prouvé statiquement** |
| Aucune valeur de secret en clair | **forme minimale prouvée** (`PatchPreview`, `SnippetHash`, filets `redactions` ⇒ marqueur) ; masquage ligne à ligne et champs libres à prouver en revue de #27 |
| Aucun outil n'écrit, ni dans le dépôt ni dans `.git/` | **exigence, non preuve** (revue #27) |
| Le diff réel ne quitte pas le processus | **exigence, non preuve** (revue #27, ADR) |
| La garde de chemin bloque `..` et les liens sortants | **grammaire prouvée** ; résolution réelle à prouver en revue de #27.3.1 |

Tests associés : `test_exactly_four_tools_all_read_only`, `test_no_forbidden_tool_in_the_registry`, `test_conditional_invariants_reject_violations`, `test_success_and_error_forms_are_mutually_exclusive`, `test_relpath_pattern_rejects_traversal`.

## 2. Principes (invariants)

1. **Lecture seule.** Aucun outil n'écrit sur le disque. `propose_patch` renvoie un **aperçu**, jamais le diff ; seule la CLI applique le diff réel, après validation humaine Y/N/E (#32).
2. **Racine fixée au démarrage.** La racine du dépôt est passée au serveur par la CLI. Le LLM ne la fournit jamais et ne peut pas la changer.
3. **Une seule garde de chemin** (#27.3.1) appelée par tous les outils qui reçoivent un chemin : `resolve()` + `is_relative_to(racine)`, refus des chemins absolus, refus des liens symboliques sortants. Le schéma JSON n'est qu'un premier filtre : `RelPath` reprend la grammaire du champ `file` du contrat Finding, donc `..`, `/etc/passwd`, `C:/…`, `a//b` et `a/` sont déjà refusés avant d'atteindre Python.
4. **Aucun secret en clair.** Les valeurs candidates sont remplacées par `<REDACTED:type:len=N>` dans **toutes** les sorties, y compris dans l'aperçu de diff de `propose_patch` (4.4.1). Un candidat ne porte qu'un `snippet_hash` (HMAC-SHA-256, ADR-001), jamais l'extrait.
5. **Entrées et sorties strictes.** `additionalProperties: false` partout : un champ en plus pourrait transporter une consigne détournée.
6. **Fail-closed.** Doute ou erreur → réponse `ErrorResponse`, jamais un résultat partiel silencieux. Un résultat tronqué est marqué `truncated: true`.
7. **Transport stdio uniquement.** Le serveur est un sous-processus de la CLI ; il n'ouvre aucun port.
8. **Contenu scanné = non fiable.** Tout texte renvoyé par un outil provient du dépôt et ne doit jamais être interprété comme une consigne (isolation dans le prompt : #34.2).
9. **Chaque proposition est liée à une empreinte du périmètre analysé.** Un candidat ou un diff calculé sur un périmètre qui a changé est refusé (`STALE_CANDIDATE`) plutôt que appliqué (4.4.2).

## 3. Vue d'ensemble

| Outil | Rôle | Entrée (résumé) | Sortie (résumé) | Écrit ? |
|---|---|---|---|---|
| `read_diff` | Voir ce qui va être commité | `max_bytes?` | fichiers + lignes ajoutées (masquées) | Non |
| `sanitize_file` | Lire un extrait de fichier, secrets masqués | `path`, `start_line?`, `max_lines?` | extrait masqué | Non |
| `list_candidates` | Lister les Findings du scanner déterministe | `scope?`, `file?`, `offset?`, `limit?` | candidats + contexte masqué | Non |
| `propose_patch` | Proposer le remplacement par une variable d'env. | `candidate_id`, `env_var_name`, `rationale?` | aperçu (jamais appliqué) + ligne `.env.example` | Non |

### 3.1 Forme des réponses

Chaque outil renvoie **exactement une** des deux formes suivantes :

```jsonc
// succès                                    // échec
{"files": [...], "truncated": false}         {"error": {"code": "PATH_ESCAPE", "message": "..."}}
```

Dans le schéma, `x-tools[<outil>].output` pointe vers un `oneOf` succès / erreur **propre à l'outil** (`ReadDiffResult`, `SanitizeFileResult`, `ListCandidatesResult`, `ProposePatchResult`). Chaque enveloppe d'échec (`ReadDiffErrorResponse` et les 3 autres) reprend la forme commune `{error: {code, message}}` mais restreint `code` au sous-ensemble de l'outil (section 6) : `read_diff` ne peut pas renvoyer `UNKNOWN_CANDIDATE`, `propose_patch` ne peut pas renvoyer `PATH_ESCAPE`. Un code hors sous-ensemble échoue la validation au lieu de passer — c'est une erreur du serveur, pas une réponse. Les deux formes restent exclusives (chacune est rejetée par l'autre schéma), donc un message hybridant succès et erreur est refusé plutôt que résolu au hasard.

### 3.2 Correspondance `$defs` ↔ sections

Chaque outil a un `<Outil>Input`, un `<Outil>Output` et un `<Outil>Result` (le `oneOf` de 3.1), plus une enveloppe d'échec `<Outil>ErrorResponse` avec son sous-ensemble de codes. Les `$defs` transverses : `RelPath` (chemin confiné), `CandidateId` (identifiant opaque de session), `SnapshotId` (empreinte du périmètre, 4.4.2), `EnvVarName` et `EnvExampleLine` (4.4), `ErrorResponse` / `ToolError` / `ErrorMessage` / `ErrorCode` (forme commune et vocabulaire global, section 6), et `SecretType` / `SecretStatus` / `SnippetHash` / `Source` repris du contrat Finding (#14, section 8).

## 4. Détail des outils

### 4.1 `read_diff`

Fenêtre du LLM sur le commit en cours, via `subprocess.run([...], cwd=racine)`, **sans `shell=True`** et sans `PATH` hérité (liste d'argv minimale, `#27.4`).

**Les options de diff ne sont pas négociables** :

```sh
git -C <racine> diff --cached --unified=0 --no-color --no-ext-diff --no-textconv
```

| Option | Raison |
|---|---|
| `--no-ext-diff` | sans elle, git exécute le `diff.external` configuré dans le dépôt. C'est de l'exécution de commande arbitraire pilotée par le contenu du dépôt : exactement l'interdit I5, contourné par la configuration. |
| `--no-textconv` | sans elle, git applique les filtres `textconv` des `.gitattributes`, qui sont eux aussi des commandes. Même risque, même chemin. |
| `--unified=0` | le LLM n'a besoin que des lignes ajoutées ; le contexte élargit la surface d'injection sans rien apporter. |
| `--no-color` | des séquences ANSI dans la sortie sont du bruit qui casse le comptage d'octets de `max_bytes`. |

- **Entrée** : `{ "max_bytes": 1024..65536 }` (défaut 32768). Aucun chemin, aucune racine.
- **Sortie** : `{ "files": [{ "file", "binary", "redactions", "added_lines": [{ "line", "text" }] }], "truncated": bool }`.
- Limites : 200 fichiers, 5000 lignes ajoutées par fichier, 2000 caractères par ligne. Ces trois plafonds sont des garde-fous d'affichage : au-delà, `truncated: true` est le comportement attendu, et le LLM ne doit pas conclure « rien à signaler » sur la foi d'un diff tronqué.
- Un fichier binaire est listé avec `binary: true` et **zéro ligne**. Invariant `if/then` : `binary: true` ⇒ `added_lines` vide. Sans lui, le LLM lirait des octets comme du texte et traiterait une image comme du code.
- Chaque fichier porte `redactions`, le nombre de valeurs masquées dans ses lignes. Filet structurel (`if/then` avec `contains`) : `redactions >= 1` ⇒ au moins une ligne porte `<REDACTED:`. Cela détecte un masquage **oublié**, pas un masquage **partiel** : exiger un marqueur sur chaque ligne serait faux, car la plupart des lignes n'ont légitimement aucun secret. Le masquage de chaque valeur, avant sérialisation, est une obligation de #27 (`x-obligations.masking_before_serialization`).
- `truncated: true` signifie **information incomplète**, jamais « diff vide ». Si la sortie git dépasse `max_bytes`, le parseur tronque **et** pose le drapeau : ne jamais renvoyer un diff partiel en le présentant comme complet.
- **Piège d'implémentation** : `git diff` affiche `/dev/null` pour un fichier ajouté ou supprimé, et `git diff -M` nomme un renommage `old.py{old => new}.py`. `/dev/null` est un chemin absolu, donc `RelPath` le refuse : le parseur doit l'écarter **avant** de valider, sinon il renvoie `INVALID_INPUT` sur une sortie qu'il a lui-même fabriquée. La forme `{...}` passe en revanche `RelPath` (pas de `/`, pas de segment `..`) : responsabilité du parseur, pas du schéma.


### 4.2 `sanitize_file`

Lit un extrait d'un fichier du dépôt pour donner du contexte au LLM, avec les valeurs candidates masquées.

- **Entrée** : `{ "path": RelPath, "start_line": >=1 (défaut 1), "max_lines": 1..400 (défaut 200) }`.
- **Sortie** : `{ "path", "start_line", "end_line", "total_lines", "content", "redactions", "truncated" }`. `content` est plafonné à 100 000 caractères (le nombre de lignes est borné par `max_lines`, pas la longueur d'une ligne : fichier minifié, fichier de données). Filet structurel : `redactions >= 1` ⇒ `content` porte au moins un marqueur (masquage oublié détecté ; masquage partiel : obligation #27, comme en 4.1).
- Refus (`FORBIDDEN_PATH`) : `.git/`, `.env*`, fichiers ignorés par `.gitignore`, tout ce qui est hors racine (`PATH_ESCAPE`).
- Refus (`BINARY_FILE`) : fichiers binaires. Refus (`TOO_LARGE`) : fichier de plus de 1 Mo.
- Ouverture avec `O_NOFOLLOW` (limite TOCTOU à consigner dans l'ADR).

### 4.3 `list_candidates`

Expose les résultats du scanner déterministe (regex + entropie). C'est le LLM qui trie ces candidats, pas lui qui les invente.

- **Entrée** : `{ "scope": "staged" | "working_tree" (défaut staged), "file"?: RelPath, "offset": >=0, "limit": 1..200 (défaut 50) }`.
- **Sortie** : `{ "snapshot_id", "candidates": [Candidate], "total", "truncated" }`.
- `snapshot_id` est l'empreinte du périmètre analysé (4.4.2). Elle est **obligatoire** : sans elle, aucune proposition ultérieure ne peut être datée.
- `Candidate` = **exactement** les champs du #14 (`file`, `line`, `type`, `entropy`, `snippet_hash`, `status`, `source`, tous obligatoires, mêmes bornes et mêmes grammaires) + `candidate_id` (opaque, attribué par le serveur), `masked_snippet` et `context_before` / `context_after` (5 lignes max, masquées). La synchronisation avec `finding.schema.json` est vérifiée par un test : si #14 bouge, ce contrat casse en CI.
- `masked_snippet` et les contextes sont masqués **avant sérialisation** par le programme (obligation #27) : le schéma ne peut pas y exiger de marqueur, car une ligne de contexte sans secret n'en porte légitimement aucun. Même régime que `AddedLine.text` (4.1).
- Le LLM ne peut référencer qu'un `candidate_id` renvoyé par cet outil (sinon `UNKNOWN_CANDIDATE`).

### 4.4 `propose_patch`

Le LLM fournit **uniquement** un identifiant de candidat et un nom de variable. Le **patch est calculé par le programme**.

- **Entrée** : `{ "candidate_id": opaque, "env_var_name": ^[A-Z][A-Z0-9_]{1,63}$, "rationale"?: <=500 caractères }`. Le LLM ne fournit **ni diff, ni ligne d'origine, ni valeur** : il n'a rien d'autre à dire que le nom de la variable.
- **Sortie** : `{ "candidate_id", "snapshot_id", "proposal_id", "applied": false, "manual_remediation", "patch_preview", "env_var_name", "env_example_line" }`.
- `applied` vaut **toujours** `false` (le schéma l'impose avec `const`).
- Le nom est re-validé côté programme (#30.2) : refus de `PATH`, `LD_PRELOAD`, `PYTHONPATH`…, dédoublonnage `_2`, `_3`. D'où `env_var_name` dans la sortie : c'est le nom **final**.
- `env_example_line` est de la forme `NOM=` : **jamais de valeur**.
- Cas ambigu (f-string, concaténation) : `manual_remediation: true` et `patch_preview` vide. Mieux vaut refuser que corrompre le code.

La CLI applique le **diff réel**, résolu côté serveur via `proposal_id`, après le Y/N/E. `patch_preview` ne quitte jamais le processus et n'est jamais écrit sur disque : c'est un affichage pour le LLM, pas une entrée de l'application.

#### 4.4.1 `patch_preview` : un aperçu, pas un diff

Un diff unifié contient la ligne d'origine, donc la valeur du secret en clair. Renvoyer ce diff au LLM contredit l'invariant 4 : il relirait le secret, pourrait le recopier dans un autre patch, le glisser dans une décision, ou le laisser dans l'historique de conversation Ollama. La sortie est donc un aperçu :

```diff
--- a/src/app/config.py
+++ b/src/app/config.py
@@ -12 +12 @@
-KEY = "AKIA<REDACTED:aws:len=20>"
+KEY = os.environ["AWS_KEY"]
```

| Règle | Qui l'applique |
|---|---|
| Les lignes `-` portent `<REDACTED:type:len=N>` | #27, masquage avant sérialisation |
| Une ligne `+` ne contient jamais la valeur d'origine | #27 |
| Un aperçu non vide contient au moins un marqueur | `PatchPreview.anyOf` |
| `manual_remediation: true` ⇒ aperçu vide | invariant `if/then` |
| Le diff réel ne quitte jamais le processus | `proposal_id` opaque côté serveur |
| Seul le développeur voit le diff réel | terminal de confiance, au Y/N/E (#32) |

`proposal_id` est le seul chemin vers le diff complet : il vit en mémoire côté serveur, expire avec la session, et n'est jamais journalisé avec son contenu.

**Ce que le schéma prouve, et pas davantage.** `PatchPreview` exige qu'un aperçu non vide contienne au moins un marqueur. Il ne vérifie ni que chaque ligne `-` est masquée, ni qu'aucune valeur en clair ne subsiste à côté de ce marqueur : `-KEY = "sk_live_abc"` à côté d'une ligne masquée passerait la validation. Le masquage ligne à ligne est donc une **obligation de #27** (`x-obligations.every_removed_line_is_masked`), à prouver par un test qui cherche une valeur en clair dans chaque ligne `-`, pas par ce schéma. Dans le rapport, cette ligne s'écrit « forme minimale vérifiée », jamais « le secret ne sort pas ».

#### 4.4.2 Périmé (`STALE_CANDIDATE`)

Le LLM raisonne en plusieurs tours : il liste les candidats, en choisit un, puis propose. Entre les deux, le fichier a pu changer. Sans garde, le programme patcherait une ligne qui n'est plus celle validée par le développeur.

`snapshot_id` est une empreinte du périmètre analysé, **calculée en mémoire** et préfixée par `heimdall-snapshot-v1\x00` (domaine séparé par `\x00` entre chaque champ) :

- `scope: staged` : SHA-256 sur le préfixe + les octets de `git diff --cached --raw --no-ext-diff --no-textconv` (les OID de blob y figurent déjà, pas besoin de les relire).
- `scope: working_tree` : SHA-256 sur le préfixe + pour chaque fichier **effectivement ouvert par le scanner pendant cet appel**, trié par octets du chemin (filtre `file` inclus s'il est fourni), `path + \x00 + sha256(octets lus)`. Sans filtre `file`, c'est l'ensemble des fichiers suivis non ignorés qui ont été ouverts — pas une sélection des seuls fichiers contenant un candidat, sinon deux implémentations (l'une qui hache tout ce qu'elle lit, l'autre seulement les fichiers à candidats) donneraient des empreintes différentes pour la même liste.
- `truncated: true` : l'empreinte couvre uniquement le préfixe examiné et inclut un marqueur `truncated`. Une proposition issue d'une liste tronquée est donc liée à un périmètre partiel ; la CLI recalcule au moment de l'application sur le périmètre complet du même scope/filtre, les empreintes divergent, la proposition est refusée (`STALE_CANDIDATE`) — il faut relister sans troncature avant de proposer.

Le calcul se fait **sans écrire dans `.git/`**. `git write-tree` est interdit : il crée des objets dans `.git/objects`, ce qui violerait l'invariant « aucun outil n'écrit » et rendrait le serveur dépendant d'un état git persistant. Les commandes `write-tree`, `add`, `stash` et `commit` sont donc exclues par construction (#27.4).

La CLI recalcule l'empreinte **au moment de l'application**, pas à celui de l'appel de l'outil. Divergence ⇒ la proposition est abandonnée avec `STALE_CANDIDATE`, l'aperçu reste affiché, et le développeur relance `list_candidates`.

Le `candidate_id` n'est valable que dans le snapshot qui l'a produit : `UNKNOWN_CANDIDATE` s'il est inconnu, `STALE_CANDIDATE` s'il est connu mais périmé.

Le cas ambigu (f-string, concaténation) n'est **pas** une erreur : c'est un succès avec `manual_remediation: true`. Reconnaître qu'on ne sait pas remplacer est le comportement correct de l'outil, pas un échec. `AMBIGUOUS_CASE` n'existe donc pas dans l'énumération, pour ne pas laisser croire qu'un cas ambigu doit remonter en échec.

## 5. Ce que le LLM ne peut PAS faire (liste des interdits)

| # | Interdit | Comment c'est garanti | Prouvé par |
|---|---|---|---|
| I1 | Écrire, modifier, supprimer ou renommer un fichier | Aucun outil d'écriture ; `propose_patch` renvoie un aperçu | statique + revue #27 |
| I2 | Lire ou écrire hors de la racine du dépôt | Garde de chemin unique (#27.3.1), liens symboliques sortants et chemins absolus refusés | grammaire prouvée ; résolution : revue #27.3.1 |
| I3 | Choisir ou changer la racine du dépôt | Fixée au démarrage, absente de tous les schémas | statique |
| I4 | Accéder au réseau (Internet, localhost, Vault) | Aucun outil réseau ; serveur en stdio ; aucun outil Vault | statique + revue #27 |
| I5 | Exécuter une commande arbitraire | Aucun outil `exec` / `shell` ; git codé en dur, sans `shell=True`, avec `--no-ext-diff --no-textconv` | statique + revue #27 |
| I6 | Lire les fichiers ignorés, `.git/`, `.env*` | `FORBIDDEN_PATH` dans `sanitize_file` | revue #27 (le schéma ne connaît pas `.gitignore`) |
| I7 | Voir un secret en clair | Masquage `<REDACTED:…>` avant sérialisation ; aperçu ; `snippet_hash` seulement | forme minimale prouvée ; masquage ligne à ligne : revue #27 |
| I8 | Appeler un outil qui n'existe pas | Registre fermé de 4 outils ; outil inconnu → erreur | statique |
| I9 | Appliquer un patch lui-même | `applied: false` en `const` ; application par la CLI après Y/N/E | statique |
| I10 | Inventer un candidat | `candidate_id` opaque, vérifié côté serveur, valable dans un seul périmètre | statique + revue #27 |
| I11 | Ajouter des champs « bonus » dans une requête ou une réponse | `additionalProperties: false` | statique |
| I12 | Modifier ses propres permissions ou la liste des outils | Contrat gelé, modification par PR + ADR relue par les 4 | statique (registre fermé) |
| I13 | Décider seul en CI | En CI le LLM n'a aucun pouvoir ; seule l'allowlist déterministe s'applique (#33, #37) | revue #33, #37 |
| I14 | Faire appliquer un diff qui ne correspond plus au fichier | `snapshot_id` dans la sortie ; `STALE_CANDIDATE` à l'application | schéma + revue #30 |
| I15 | Faire appliquer le diff complet qu'il a lui-même produit | `proposal_id` opaque, diff réel côté serveur, seul l'aperçu est renvoyé | schéma + revue #27 (opacité = exigence) |

La colonne « Prouvé par » sépare ce que le schéma démontre de ce qui devra l'être à la relecture de #27. Elle a servi à remplir la section 1 bis.

## 6. Codes d'erreur

`ErrorCode` est le vocabulaire global ; chaque outil n'accepte que son sous-ensemble (enveloppes `ReadDiffError`, `SanitizeFileError`, `ListCandidatesError`, `ProposePatchError`). Un code hors sous-ensemble échoue la validation : c'est une erreur du serveur, pas une réponse.

| Code | Quand | Outils |
|---|---|---|
| `INVALID_INPUT` | L'entrée ne respecte pas le schéma | les 4 |
| `PATH_ESCAPE` | Le chemin sort de la racine (`..`, absolu, lien symbolique sortant) | `sanitize_file`, `list_candidates` (filtre `file`) |
| `NOT_FOUND` | Le fichier n'existe pas (y compris le filtre `file` de `list_candidates`) | `sanitize_file`, `list_candidates` |
| `FORBIDDEN_PATH` | `.git/`, `.env*`, fichier ignoré (y compris le filtre `file` de `list_candidates`) | `sanitize_file`, `list_candidates` |
| `BINARY_FILE` | Fichier binaire | `sanitize_file` (`read_diff` liste les binaires au lieu d'échouer) |
| `TOO_LARGE` | Fichier ou diff dépassant les limites | `read_diff`, `sanitize_file` |
| `UNKNOWN_CANDIDATE` | `candidate_id` inconnu du serveur ou d'un autre snapshot | `propose_patch` (`list_candidates` produit les identifiants, il n'en consomme pas) |
| `STALE_CANDIDATE` | Le candidat ou la proposition date d'un périmètre qui a changé (4.4.2) | `propose_patch` |
| `NOT_A_GIT_REPO` | La racine n'est pas un dépôt Git | les 4 |
| `INTERNAL` | Erreur interne ; message générique, sans chemin absolu ni contenu | les 4 |

Les messages d'erreur ne contiennent **jamais** de chemin absolu, de contenu de fichier ni de valeur de secret. Ils refusent aussi les caractères de contrôle (`ErrorMessage`) : le LLM les relit, donc un message ne doit pas pouvoir lui glisser une consigne sur une nouvelle ligne.

Un code d'erreur est le seul canal d'échec des 4 outils (3.1) : il n'existe pas de « résultat partiel silencieux ». En particulier, `read_diff` qui tronque renvoie un succès avec `truncated: true`, tandis qu'une panne renvoie `INTERNAL` — les deux cas sont distinguables, ce qui est le but.

Le cas ambigu n'est pas dans cette table : c'est un succès (`manual_remediation: true`), voir 4.4.2.

## 7. Décisions prises en v1.1 (à confirmer en PR)

1. **Masquage dans `read_diff` aussi**, pas seulement dans `sanitize_file` : le LLM juge avec la forme (type, longueur, entropie, contexte), pas avec la valeur. Impact possible sur la qualité du tri, à mesurer avec la mesure du #21.4.
2. **`propose_patch` ne prend pas de patch en entrée** : le LLM propose un nom, le programme construit le diff.
3. **Pas de 5e outil de « verdict »** (vrai secret / faux positif) : la décision du LLM est la sortie JSON contrainte de #28, pas un outil.
4. **Valeurs de limites** (32 Ko, 400 lignes, 200 candidats, 20 000 caractères d'aperçu) : points de départ, à ajuster avec les mesures du #28.4 et #38.
5. **Aperçu expurgé plutôt que diff complet** (4.4.1). C'est le choix structurant de la v1.1. L'alternative « renvoyer le diff complet » était écartée parce qu'elle contredit l'invariant 4 ; l'ADR du #27 doit acter que le diff réel reste en mémoire côté serveur.
6. **`snapshot_id` dans les deux sens** (4.4.2). Refuser une proposition périmée coûte une relance de `list_candidates` ; l'appliquer à un fichier modifié coûte un secret écrit au mauvais endroit. Le refus est le bon échange.
7. **`--no-ext-diff --no-textconv` imposés** (4.1). Sans eux, `read_diff` exécuterait une commande arbitraire configurée dans le dépôt : l'interdit I5 serait contournable par la configuration, pas seulement par le code.

## 8. Alignement avec les autres contrats

- **#14 (fait)** : `SecretStatus` reprend les 5 états du contrat Finding (`detecte`, `confirme`, `vaulte`, `rote`, `faux_positif`), `type` et `snippet_hash` en reprennent la grammaire, `entropy` ses bornes 0..8, `file` celle de `RelPath`. Le test `test_candidate_matches_finding_contract` compare les deux schémas champ par champ : toute divergence future est visible immédiatement.
- **Écart assumé** : `RelPath` borne la longueur à 1024 caractères là où `file` du Finding en accepte 4096. Un chemin de plus d'un kilo-octet dans un dépôt est un signal d'attaque, pas un cas d'usage ; le Finding reste plus permissif car il est stocké, pas choisi par le LLM. `entropy` est obligatoire ici (le LLM classe sur ce critère), et borné à 0..8 comme dans le Finding.
- **#15** : aucun lien direct (le LLM n'accède pas au Vault).
- **#18** : chaque outil apparaît sur le DFD comme une flèche LLM → serveur MCP ; les frontières (1) code scanné → LLM et (2) LLM → outils MCP s'appuient sur ce contrat.

## 9. Ce que le schéma prouve, et ce qu'il ne prouve pas

Le schéma est une barrière faible : il décrit des formes, il n'empêche rien. Le bloc `x-obligations` du `.json` porte les mêmes obligations que la section 9.2, pour que #27 et #30 les aient sous les yeux au moment d'écrire le code.

### 9.1 Vérifié par le schéma

1. **Ancre de fin de chaîne.** Les `pattern` se terminent par `(?![\s\S])` et non par `$` : `$` ancre la fin *avant* un saut de ligne final, donc `KEY_X=` + `\n` passerait le contrôle et ajouterait une ligne dans un futur `.env.example`. Testé **par comportement** (`test_patterns_reject_trailing_line_terminators`) : `\n`, `\r`, `\r\n`, U+2028, U+2029, `\x0b` et `\x0c` sont ajoutés à une valeur valide, et le rejet est exigé.
2. **Messages d'erreur sans caractères de contrôle.** `ErrorMessage` refuse `\n`, `\r`, U+2028 et U+2029 : le LLM relit ces messages, il ne doit pas pouvoir y glisser une consigne sur une nouvelle ligne.
3. **Le masquage précède la sortie.** Masquer après sérialisation laisserait la valeur dans un buffer ou une trace : le masquage doit précéder l'appel à `json.dumps`.
4. **Shape stable.** Un champ de sortie ajouté à côté du `oneOf` au lieu du `…Output` correspondant produirait une réponse que le schéma refuse alors que le programme la produit. `binary` est obligatoire dans `DiffFile` pour la même raison que `applied` en `const`.
5. **`$defs` hors de portée du LLM.** Le LLM voit le schéma résolu d'un seul outil (`input` / `output`), jamais le document entier.
6. **Compteurs de masquage.** `DiffFile.redactions >= 1` ⇒ au moins une ligne porte un marqueur (`contains`) ; `SanitizeFileOutput.redactions >= 1` ⇒ `content` porte un marqueur. Testé par `test_conditional_invariants_reject_violations`. Filet contre l'oubli, pas contre le partiel (voir 4.4.1).
7. **Erreurs par outil.** Chaque enveloppe d'échec restreint `code` à son sous-ensemble (section 6). Testé par `test_each_tool_accepts_only_its_error_codes` : les 10 codes × les 4 outils, acceptés ou refusés selon le sous-ensemble.

### 9.2 Obligation du programme (`x-obligations`)

Ces règles ne sont **pas** exprimables en JSON Schema. Elles sont la cible des tests de #27 et #30.

| Obligation | Pourquoi le schéma ne peut pas |
|---|---|
| Chaque ligne `-` de `patch_preview` est masquée | Le schéma voit une chaîne, pas ses lignes. `-KEY = "sk_live_abc"` à côté d'un marqueur passe la validation (4.4.1). |
| Tous les champs texte lus par le LLM sont masqués avant `json.dumps` | `AddedLine.text`, `masked_snippet`, contextes : exiger un marqueur y serait faux, la plupart des lignes n'ont légitimement aucun secret. Le schéma ne distingue pas « ligne sans secret » de « secret non masqué ». |
| `env_example_line` vaut exactement `env_var_name` + `=` | Un schéma ne compare pas deux champs distincts : `OTHER=` passerait. |
| `proposal_id` reste présent même si `manual_remediation` | Déjà le cas ici ; l'obligation est de ne pas le rendre optionnel, pour que la forme de la réponse ne dépende pas du contenu du fichier. |
| `snapshot_id` calculé en mémoire, sans écriture dans `.git/` | Le schéma ne voit aucun effet de bord (4.4.2). |
| `truncated` et `manual_remediation` restent deux marqueurs distincts | Les confondre ferait conclure « rien à signaler » sur une information incomplète. |

## 10. Vérification

Le contrat se valide hors ligne, sans appel réseau (comme le contrat Finding #14) :

```sh
python3 -m venv .venv
.venv/bin/python -m pip install --require-hashes -r tests/contracts/requirements.txt
.venv/bin/python -m unittest discover -s tests/contracts -v
```

Sous Windows PowerShell, remplacer `.venv/bin/python` par `.venv\Scripts\python.exe` (voir `docs/contracts/finding.md`).

`unittest` est le seul besoin : `pytest` est un confort local, absent de `requirements.txt`. Le `.json` est validé contre le méta-schéma draft 2020-12 (`check_schema`), pas seulement contre des exemples.

Les tests ne prouvent que ce qui est **statique** (voir 1 bis et 9). Les garanties comportementales — pas d'écriture dans `.git/`, masquage ligne à ligne, résolution de la garde de chemin, opacité de `proposal_id` — devront être prouvées par les tests de #27 et #30, avec module + ligne, pour la partie 2 du rapport.

## 11. Critères d'acceptation du ticket

- [x] Schémas JSON valides (méta-schéma inclus), suite verte
- [x] Liste des interdits documentée (section 5), avec pour chacun ce qui est prouvé statiquement et ce qui reste à prouver en revue
- [x] Entrées et sorties typées pour les 4 outils, `additionalProperties: false` sur tout objet
- [x] Contrat Finding (#14) aligné champ par champ, vérifié par test
- [x] Invariants conditionnels dans le schéma, pas seulement dans le `.md`
- [x] Codes d'erreur rattachés à chaque outil (`oneOf` succès / erreur)
- [ ] Relu par D (relecteur) puis par les 4 membres avant gel
- [ ] Temps passé noté en commentaire du ticket (« Temps: … »)

## 12. Preuve pour le rapport et le SAMM

Partie 1 du rapport (spécifications) : citer ce fichier, `schemas/mcp-tools.schema.json` et `tests/contracts/test_mcp_tools_schema.py` avec un **lien permanent GitHub (SHA du commit)**. Jamais un lien de branche : les numéros de ligne changent.

Ligne SAMM concernée : *Surface d'attaque minimale / moindre privilège*.

| Preuve | Où | Nature |
|---|---|---|
| Surface fermée : 4 outils, aucun outil d'écriture ni réseau | `x-tools` + `::test_exactly_four_tools_all_read_only`, `::test_no_forbidden_tool_in_the_registry` | statique |
| Erreurs rattachées à chaque outil, sous-ensemble par outil, exclusives du succès | `ReadDiffResult` et les 3 autres + `::test_success_and_error_forms_are_mutually_exclusive`, `::test_each_tool_accepts_only_its_error_codes` | statique |
| Un diff n'est jamais appliqué par l'outil | `ProposePatchOutput.applied` en `const: false` | statique (contrainte sur la réponse ; effet réel : revue #27) |
| **Forme minimale** de l'aperçu : au moins un marqueur de masquage, et rien de plus | `PatchPreview` + `::test_patch_preview_never_carries_a_clear_value`, `::test_patch_preview_check_is_minimal_and_we_say_so` | statique |
| Filets de masquage `DiffFile` / `SanitizeFileOutput` (`redactions` ⇒ marqueur) | `::test_conditional_invariants_reject_violations` | statique |
| Champs texte libres sans filet structurel, masquage déclaré en obligation | `x-obligations.masking_before_serialization` + `::test_free_text_fields_have_no_structural_redaction_check` | statique + revue #27 |
| Interdits I1 à I15, avec colonne « Prouvé par » | section 5 | mixte |
| Ce qui n'est **pas** démontré | sections 1 bis et 9.2 | — |

La troisième ligne est volontairement formulée de façon restrictive. Un audit croisé qui lirait « le secret ne sort pas » vérifierait la ligne `-` d'un aperçu, verrait qu'une valeur en clair à côté d'un marqueur passe la validation du schéma, et conclurait à une fausse déclaration. Le test `test_patch_preview_check_is_minimal_and_we_say_so` fixe cette limite par un test, pour qu'elle reste visible.

Les autres tests (traversée de répertoire, terminateurs de ligne, `$ref`, alignement Finding, codes d'erreur) sont listés avec leur ligne dans le fichier de tests. Coller dans la PR la sortie réelle de :

```sh
.venv/bin/python -m unittest discover -s tests/contracts -v
git diff --check
```

Rappel du ticket : le temps passé se commente sur le ticket avec `Temps: XhY` (grille d'évaluation du cours).
