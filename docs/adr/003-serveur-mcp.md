# ADR-003 — Serveur MCP : décisions, limites et écarts assumés

Statut : proposé. Ticket : #27 (sous-tickets #73, #74, #75, #76, #77, #78).
Porteur : D · Relecteur : B · Sprint S1.
Précédents : [ADR-002](002-stack-python.md) (stack, inchangé),
[contrat des outils #16](../contracts/mcp-tools.md) (exigences, inchangé).

## Contexte

Le serveur MCP est la seule interface entre le LLM local (non fiable, comme
tout le contenu scanné) et le dépôt. Une autre équipe va pentester ce code
(2 exploits minimum) : chaque décision ci-dessous est testée et pointée par
une preuve module + ligne. Ce qui n'est **pas** prouvé est écrit comme tel —
un audit croisé pardonne une limite documentée, jamais une affirmation
fausse.

Contraintes : 100 % local, stdio uniquement, lecture seule, racine fixée au
démarrage, masquage avant sérialisation, fail-closed partout, réponses
conformes au contrat #16 (validées contre `ReadDiffResult` /
`SanitizeFileResult`, succès comme échecs).

## Décisions

### 1. SDK officiel `mcp` 2.3.0, classe `MCPServer`

Écarté : protocole maison (surface à prouver, contre l'invariant « surface
minimale »). Écart de version assumé : en v2, `FastMCP` a été renommé
`MCPServer` (guide de migration du SDK) — le ticket #73 disait `FastMCP`,
le code importe `MCPServer`. Transport `stdio` : aucun port, aucun appel
réseau (invariant 7). Preuve comportementale : inspection `/proc` + recoupe
`ss -anp` (`tests/test_mcp_client.py::NoNetworkTests`, avec contrôle négatif
sur un `http.server` témoin) ; preuve statique : aucun import réseau dans
`heimdall/mcp/` (`NoTrafficTests`, analyse AST).

`asyncio` crée au démarrage une paire de sockets UNIX **anonymes**
(auto-réveil de boucle) : ni des ports, ni des connexions, ni des chemins.
Le test les autorise explicitement et interdit tout le reste (TCP/UDP,
écoute, socket nommée) — interdire toute présence de `socket:` les
signalait à tort (faux positif documenté dans `docs/mcp-server.md`).

### 2. `ping` : sonde de vie hors contrat

Écart assumé au contrat #16 : `ping` n'en fait pas partie. Il répond
`{"pong": true}`, aucune donnée du dépôt, et ne sera ni intégré au contrat
ni retiré en passant — par PR dédiée relue, **sans réutiliser cette
dérogation comme précédent** (rappel de revue : la PR #27 porte 7 tickets
en une, et `ping` reste hors schéma). Preuve : `SERVER_TOOLS` dans
`heimdall/mcp/server.py` (`SERVER_TOOLS`, `ping`), test de registre fermé,
et `tests/test_mcp_server.py::ContractGapTests` qui **verrouille** l'écart :
tant que `ping` n'est pas dans `x-tools`, aucun autre nom hors contrat ne
peut être exposé — donc l'ajout d'un cinquième outil hors contrat échoue au
lieu de se glisser.

### 3. Frontière d'entrée : le contrat appliqué pour de vrai

Le SDK 2.3.0 écarte **en silence** les clés sans paramètre déclaré, et répond
aux types invalides par une exception pydantic qui **recopie la valeur**
(`input_value=…`), et aux paramètres manquants par « Field required » —
trois textes hors de notre enveloppe `{"error": …}` (contrat 3.1).
`_ToolBoundary` valide donc elle-même, avant exécution : clé inconnue
refusée (`additionalProperties: false` comportemental, invariant 11),
**type exact** (`bool` n'est pas un `int`), paramètres **requis** déduits de
la signature (source unique : un paramètre ajouté devient acceptable — et
requis s'il est sans défaut). `_meta` (protocole) est la seule clé
tolérée. Preuve : `heimdall/mcp/server.py` (`_ToolBoundary`) + `ArgumentGateTests` +
tests unitaires de la frontière.

### 4. Échecs en enveloppe close, jamais en exception, jamais libres

`tool_handler` traduit `ToolFailure` (code du contrat), `PathEscape`
(`PATH_ESCAPE`) et toute autre exception (`INTERNAL` statique) en
`{"error": {"code", "message"}}`. Seules les exceptions inattendues sont
journalisées avec trace (sur stderr, jamais sur stdout) ; un refus de
chemin est un fonctionnement normal. Les échecs sont marqués `isError` de
façon centrale (`_mark_failure`) : les deux formes du contrat étant
exclusives, un succès ne peut pas être pris pour un échec. Le message
libre a été **supprimé** de `ToolFailure`/`failure()` : un futur `raise
ToolFailure("INTERNAL", valeur)` refléterait un secret au LLM, donc l'API
ne le permet plus. La `_meta` protocole est tolérée mais bornée à 1 Kio.
Preuve : `heimdall/mcp/server.py` (`tool_handler`, `_ToolBoundary`),
module `heimdall/mcp/errors.py` (messages statiques ASCII,
`allow_nan=False`, `ensure_ascii=True`).

### 5. Racine fixée au démarrage, absente des signatures

`build_server` résout la racine une fois ; les outils sont des closures
dessus. Aucun outil ne prend de paramètre `root` (vérifié par test) : le
piège du #27 (« laisser le LLM fournir la racine ») est impossible par
construction, pas par vigilance. Preuve : `heimdall/mcp/server.py` (`_tools`, closures sur la racine).

### 6. Git : argv figé, environnement reconstruit, config locale neutralisée

`git -C <racine> diff --cached --unified=0 --no-color --no-ext-diff
--no-textconv`, sans `shell=True`, binaire résolu hors PATH hérité
(`shutil.which("git", path=os.defpath)` : un PATH compromis ne détourne
pas l'exécutable ; absent du défaut système = panne, jamais de repli),
délai 30 s. L'environnement est **reconstruit** (`PATH` vide, `HOME` =
racine, `GIT_CONFIG_*` neutralisées) : `GIT_DIR`/`GIT_INDEX_FILE` hérités
ne peuvent pas rediriger le dépôt analysé, et `--no-ext-diff
--no-textconv` rendent inopérants `diff.external` et les filtres `textconv`
(exécution de commande pilotée par le contenu scanné, interdit I5).
Chaque appel passe aussi **`stdin=subprocess.DEVNULL`** : sans lui le
sous-processus hérite du pipe JSON-RPC du serveur, donc une sous-commande
future qui lirait stdin (`apply`, `hash-object --stdin`, un `textconv` si
l'option sautait) consommerait des octets du protocole ou s'y bloquerait —
interférence pilotable par le dépôt scanné. Garde **statique**, pas
seulement la ligne de code : `tests/security/test_prompt_injection.py`
refuse tout appel git sans `stdin=subprocess.DEVNULL` (avec témoin négatif
qui prouve que la garde mord).

**Plafond de découverte = le PARENT de la racine**
(`GIT_CEILING_DIRECTORIES`), parce que git n'exclut que l'**entrée** dans
un dossier plafond, et que le premier dossier qu'il ascendererait depuis la
racine est son parent. Prouvé par exécution (racine = `repo/sous`, dépôt en
`repo`) : `rev-parse --show-toplevel` répond **rc=128** « not a git
repository » — le dépôt parent est inatteignable, et **le refus vient de
git**, pas de `is_repository()`. Un outil futur qui oublierait ce test
n'hériterait de rien non plus (`staged_diff` et `is_ignored` lèvent
`INTERNAL` sur une racine non-dépôt). Corollaire documenté pour éviter
une « correction » involontaire : mettre **la racine** comme plafond est
plus **faible** (rc=0, `toplevel` = dépôt parent), pas plus fort — la
découverte retomberait sur chaque appelant. Preuve de non-régression :
`tests/test_mcp_units.py::RepositoryCeilingTests` échoue si le plafond
redevenait la racine.
Prouvé par des tests hostiles (`GIT_DIR` piégé, `diff.external` piégé,
hook `core.fsmonitor` piégé, pager piégé, binaire `git` piégé en tête de
PATH).

Le `.git/config` du dépôt scanné reste lu par git : `core.fsmonitor` y
exécute une commande à chaque `diff`/`check-ignore` (prouvé par exécution
avec hook planté : canari écrit). Chaque appel est donc préfixé de
`-c core.fsmonitor=false` — `-c` gagne sur tous les fichiers, `false`
désactive vraiment (vérifié avec un binaire `false` piégé dans le PATH :
jamais exécuté). Le pager hostile est prouvé inopérant (sorties toujours
pipées) : aucun override pager, aucune surface ajoutée.

Le flux du diff indexé est lu en streaming borné (`proc.stdout.read(max_bytes + 1)`
puis arrêt immédiat par kill si le plafond est dépassé) : aucun buffering
intégral préalable en mémoire, immunisant contre les OOM sur dépôts piégés par
des blobs géants stagés.
La commande est entièrement construite par le programme : suppressions
`noqa`/`nosec` justifiées en place. Preuve : `heimdall/mcp/gitdiff.py`
(`DIFF_ARGUMENTS`, `GIT_CONFIG_OVERRIDES`, `confined_environment`,
`GitAccess.execute`, `GitAccess.staged_diff`).

### 7. Masquage conservateur avant `json.dumps`, règles nues incluses

En cas de doute on masque (le LLM juge sur la forme, l'humain valide ; un
faux positif de masquage coûte un marqueur, un oubli coûte un secret relu
et recopié dans l'historique Ollama). Règles : affectations citées/non
citées, en-têtes `Authorization`, `user:pass@` d'URI, balises PEM **et**
jetons nus (préfixe connu, ou ≥ 32 caractères denses à entropie ≥ 3,9 —
`_BARE_KNOWN_TOKEN`, `_BARE_DENSE_TOKEN`). La fusion est par
**spécificité** (le mot de passe d'une URI part seul, l'hôte reste lisible)
puis par position. **Vocabulaire unique** : `_KNOWN_PREFIXES` (typage et
`_looks_like_secret`) est DÉRIVÉ de `_BARE_PREFIXES` (détection), donc un
préfixe ajouté au masquage est automatiquement connu partout — la liste
recopiée à la main avait laissé `pk_test_` masqué mais typé
`generic_secret` (pas de fuite, tri LLM dégradé), et l'invariant
`prefix_vocabulary_is_fully_mapped` ne le voyait pas puisqu'il ne parcourait
que la liste de typage. `rk_test_` (clé restreinte Stripe en mode test)
ajouté au même moment. Les motifs sont linéaires (aucun quantificateur
imbriqué) : garde-fou temporel anti-ReDoS en test. Le jour où #22 arrive,
ses règles remplacent `_looks_like_secret` sans changer `mask_text`.
Limites honnêtes : un jeton **sans préfixe connu, noyé dans 100 Ko de
remplissage**, reste indétectable par fenêtre ; un SHA de commit copié en
clair est masqué (faux positif bénin assumé) ; une valeur courte (< 16
caractères) à nom neutre (`MY_DATA="motdepasse12"`) N'EST PAS masquée —
l'alternative (masquer toute valeur affectée dès 8 caractères) noierait
le tri (`name="production"`, indiscernable par entropie) et apprendrait
au LLM à ignorer les marqueurs ; **une affectation non quotée à nom évocateur est masquée dès 6 caractères**
(`_UNQUOTED_ASSIGNMENT` bornée à `{6,4096}` et filtrée par `_looks_like_secret`, protégeant `PASSWORD=hunter2`
ou `SECRET=abc12345`) ; **une valeur quotée dépassant 20 000
caractères sur une seule ligne n'est pas masquée** (borne anti-ReDoS
assumée : `_QUOTED_ASSIGNMENT` bornée à `{4,20000}`, un credential réel
ne fait pas plus de 20 Ko et les lignes sont de toute façon plafonnées
par le contrat) ; **coût masquage ≤ 1 Mo/ligne, masquer-puis-tronquer assumé** : dans
`read_diff` comme dans `sanitize_file`, `mask_text` passe sur la ligne
**complète**, la troncature à 2 000 caractères (`MAX_LINE_CHARS`) vient
**après** — garantit qu'aucune valeur n'est sectionnée avant détection
(coût CPU borné : 1 Mo par fichier, `max_bytes` par diff, regex linéaires
sans ReDoS). L'ordre inverse était une régression de masquage **prouvée
par exécution en revue** : la fenêtre `MAX_LINE_CHARS + 500` appliquée
avant masquage faisait échouer `_QUOTED_ASSIGNMENT` sur toute valeur citée
dont le guillemet fermant tombait au-delà (donc au-delà de ~2,5 Ko), et le
préfixe de 2 000 caractères partait en clair au LLM — la borne des 20 Ko
annoncée ici était donc fausse en pratique. Corrigé, épinglé par
`tests/test_mcp_units.py::MaskedFilesTests`,
`tests/test_mcp_read_diff.py::ReadDiffToolTests` et
`tests/test_mcp_sanitize_file.py::SanitizeFileToolTests`. La détection de
précision appartient au scanner #22 mesuré en #21. Preuve :
`heimdall/mcp/masking.py`, `tests/test_mcp_hardening.py::BareTokenMaskingTests`,
`tests/test_mcp_hardening.py::MaskingPerformanceTests`.

### 8. Compteurs recomptés, budgets vérifiés après sérialisation

`redactions` compte les marqueurs **de la réponse** (recompté après coupe),
jamais une promesse : une coupe à 2000 caractères (ligne dans `read_diff` et `sanitize_file`) ou 100 000
(caractères, `sanitize_file`) qui emporterait le seul marqueur violerait
sinon l'invariant structurel du schéma — faille réelle trouvée par audit
et corrigée, avec tests. Dans `sanitize_file`, chaque ligne est bornée à 2 000 caractères
(`MAX_LINE_CHARS`) après masquage (`truncated: true`), immunisant le canal contre le DoS CPU
face à des fichiers piégés à ligne unique géante (jusqu'à 1 Mo). Le budget `max_bytes` est vérifié sur la réponse
sérialisée (fichiers retirés en dernier, `truncated: true`). **Coût de
`_fit_budget` : une seule sérialisation par fichier** (les tailles sont
cumulées, l'additivité de `errors.dumps` compact vérifiée par test contre
la taille réelle, à l'octet près) — l'ancienne version resérialisait toute
la liste à chaque `pop`, jusqu'à 200 `dumps` complets, sur le canal stdio
synchrone, avec un `max_bytes` choisi par le LLM sur un contenu piloté par
le dépôt. Test : 200 fichiers au plafond + `max_bytes=1024` borné en temps
ET la réponse sérialisée réellement ≤ 1024 (donc des fichiers retirés, pas
seulement comptés). Preuve :
`heimdall/mcp/server.py` (`_masked_files`, `_masked_line`, `_fit_budget`, `_file_sizes`, `_prefix_size`, `sanitize_file`),
`tests/test_mcp_hardening.py::TruncationInvariantTests`,
`tests/test_mcp_hardening.py::MaskingPerformanceTests`,
`tests/test_mcp_units.py::MaskedFilesTests`.

### 8 bis. Coupe sur lignes complètes, FIFO refusés, binaires innommables

- `staged_diff` lit la sortie de `git diff` en streaming borné (`proc.stdout.read(max_bytes + 1)`
  puis interruption immédiate par `kill` si le budget est dépassé) au lieu de bufferiser
  l'intégralité du diff : immunité DoS mémoire / OOM face à des dépôts piégés par des blobs géants stagés.
- `staged_diff` coupe `raw[:max_bytes]` sur le dernier `\n` complet : une
  ligne tronquée à cheval (guillemet fermant manquant, `max_bytes` choisi
  par le LLM + remplissage attaquant) fuyait son préfixe en clair. La
  ligne incomplète est abandonnée, `truncated: true`.
- `sanitize_file` refuse tout non-régulier **avant** ouverture (FIFO =
  `BINARY_FILE` : ouvrir un FIFO en lecture bloque pour toujours, DoS du
  canal stdio sans timeout possible) et revérifie **après** (`INTERNAL`
  si le type a changé). Ouverture `O_NONBLOCK` : sans effet sur les
  réguliers, indispensable contre le swap régulier→FIFO entre `lstat` et
  `open` (le blocage aurait lieu AVANT le contrôle).
- Binaire innommable (jamais vu sans `--binary`, que nous ne passons pas)
  : abandonné avec `truncated: true`, jamais escamoté en silence — et
  sans tuer toute la réponse pour un nom (un binaire ne porte aucune
  ligne ; tuer la réponse serait un DoS par fichier bizarre).

### 8 ter. Formats de diff non reconnus : fail-closed, jamais du silence

Règle unique : **ce que le parseur ne comprend pas, il le signale**
(`truncated: true`) au lieu de le jeter. Trois cas trouvés en revue :

- **Hunk combiné `@@@ -1,2 -1,2 +1,3 @@@`** (diff de fusion, N parents) :
  il ne matchait pas `"@@ "`, donc le hunk ne s'ouvrait pas et les lignes
  `+` suivantes étaient relues comme des en-têtes puis jetées, **sans**
  `truncated`. Il est maintenant reconnu (`_COMBINED_HUNK_HEADER`) et son
  corps décodé : un caractère de préfixe par parent (`+` ajouté, `-`
  absent, espace contexte), seule ligne ajoutée côté **tous** les parents
  étant reportée. L'argv figé `diff --cached` n'en émet pas sur les
  versions actuelles de git (vérifié : `* Unmerged path …`), on ne laisse
  donc pas la grammaire devenir un angle mort.
- **En-tête de hunk illisible** (`@@ garbage`) : `truncated: true`.
- **`* Unmerged path x`** : c'est ce que `git diff --cached` renvoie pour
  un chemin d'index non résolu (merge en cours) — **aucune ligne**. La
  réponse valait alors « aucun changement indexé » avec
  `truncated: false`, sur un dépôt en cours de fusion. Drapeau posé,
  les autres fichiers du diff restant montrés.

Preuve : `heimdall/mcp/gitdiff.py` (`_COMBINED_HUNK_HEADER`, `_DiffParser._hunk_header`,
`_DiffParser._hunk_line`), `tests/test_mcp_units.py::ParserStateTests`,
`tests/test_mcp_read_diff.py::GitEnvironmentTests` (merge conflictuel réel).

### 9. Garde de chemin unique + TOCTOU et hardlinks documentés (exigence #76)

`confine` : refus de forme (grammaire `RelPath` du contrat, chemins absolus
toutes familles), `resolve()` (suit les liens sortants), `is_relative_to`
sur chemins résolus (jamais `startswith` : `/repo-evil` commence par
`/repo`). Le chemin renvoyé est **reconstruit** depuis le résolu, pas
recopié (aucune entrée reflétée). Ouverture `O_NOFOLLOW` + comparaison
dev/ino entre `lstat` et `fstat` (ELOOP refusé). **Limite TOCTOU connue** : entre
la résolution et l'ouverture, un fichier peut être remplacé — la fenêtre
est réduite à deux appels système, mais un attaquant avec écriture sur le
dépôt entre les deux reste hors de portée. **Limite des hardlinks locaux** :
`is_forbidden_path` et `is_ignored` contrôlent le nom canonique ; un alias hardlink
(`os.link(".env", "innocent.txt")`) pointerait vers le même inode sous un nom innocent.
Git ne conservant pas les liens physiques au clone, cette exploitation requiert un attaquant
local concurrent écrivant sur le système hôte, ce qui est hors du modèle de menace Git
(analogue à la fenêtre TOCTOU). `check-ignore` répond dès
qu'une règle couvre le chemin, même suivi : lecture stricte et prudente
du contrat 4.2 (un suivi-mais-ignoré est refusé). Preuve :
`heimdall/mcp/paths.py` (`confine`), `heimdall/mcp/server.py` (`_read_extract`, `is_forbidden_path`).

### 10. Noms git décodés en octets, irreprésentable = panne

Le guillemetage C est décodé en **octets** puis en UTF-8 (décoder par
caractère produisait du mojibake : `café.py` → `cafÃ©.py`, aller-retour
`read_diff` → `sanitize_file` cassé). `/dev/null` ne nomme rien, les
préfixes `a/`/`b/` ne sont retirés que si le reste reste valide, `Binary
files … and …` traite `/dev/null` en priorité (nom avec `and` dedans
correct). Un nom non représentable dans le contrat (contrôle, `..`,
UTF-8 invalide) est une **panne** (`INTERNAL`), pas un fichier sauté en
silence : mieux vaut refuser que cacher des lignes au LLM (fail-closed
délibéré, épinglé par test). Preuve : `heimdall/mcp/gitdiff.py`
(`parse_diff`, `DiffEntry`, `staged_diff`).

### 11. `.git`/`.env` insensibles à la casse, binaires et tailles

Segments comparés en minuscules (`.GIT` ouvre le même dossier sur FS
insensible à la casse). Binaire (octet nul dans les 8 premiers Kio),
> 1 Mo (`TOO_LARGE`, double garde : avant **et** après lecture),
absent/dossier (`NOT_FOUND`), `start_line` hors bornes (extrait vide,
`end_line: 0`, rien d'inventé).

## Alternatives écartées

- Transport HTTP/SSE : un port à garder, contre l'invariant 7.
- Écriture par l'outil (cf. question du #75) : l'outil lit et renvoie,
  la CLI appliquera après Y/N/E (#32). Interdit I1 intact.
- Renvoi du diff complet : la ligne d'origine contient la valeur en clair
  (invariant 4) — aperçu expurgé uniquement (contrat 4.4.1).
- Saut silencieux des fichiers illisibles : cacherait des lignes au LLM
  sans le dire — refus `INTERNAL` à la place.
- Validation des sorties par `jsonschema` à l'exécution : dépendance
  superflue, refus au moment de la fabrication au lieu d'une relecture.

## Conséquences

- Couverture mesurée **100 % instructions / 100 % branches** sur
  `heimdall/mcp` (`coverage run --branch --source=heimdall/mcp -m pytest
  tests/test_mcp_*.py`), + 26 fonctions de test qui passent par un vrai
  client MCP en sous-processus (`tests/support/mcp_client.py`). La
  transmission de `COVERAGE_PROCESS_START` est câblée dans
  `tests/support/mcp_client.py` pour que la CI du #20 mesure aussi les
  sous-processus.
- Risque : masquage conservateur → marqueurs parfois superflus (hashes
  d'intégrité, SHA copiés) ; à mesurer avec #21, jamais à « optimiser »
  en passant.
- Tout écart au contrat (#16) vit dans `docs/mcp-server.md` et ici, pas
  dans le code seul : `ping` hors contrat, `FastMCP`→`MCPServer`.

## Preuve pour le rapport (partie 2 : comportement)

Lier la PR (`Closes #27` + sous-tickets), coller la sortie `pytest` et
renseigner la feuille SAMM avec liens permanents au SHA :

| Garantie | Module + ligne (au SHA du merge) |
|---|---|
| stdio, racine fixée, registre fermé | `heimdall/mcp/server.py` (`run_stdio`, `build_server`, `SERVER_TOOLS`) |
| entrées refusées, échecs en enveloppe | `heimdall/mcp/server.py` (`_ToolBoundary`, `tool_handler`), `heimdall/mcp/errors.py` |
| git confiné, diff typé | `heimdall/mcp/gitdiff.py` (`DIFF_ARGUMENTS`, `confined_environment`, `parse_diff`) |
| canal stdio jamais hérité par git, plafond de découverte | `heimdall/mcp/gitdiff.py` (`GitAccess.execute`, `GitAccess.staged_diff`, `confined_environment`), `tests/security/test_prompt_injection.py` (`_fixed_argv_violations`) |
| masquage avant sérialisation, compteurs vrais | `heimdall/mcp/masking.py` (`mask_text`, `_KNOWN_PREFIXES`), `heimdall/mcp/server.py` (`_masked_files`, `_masked_line`) |
| garde unique, TOCTOU réduite, FIFO refusés | `heimdall/mcp/paths.py` (`confine`), `heimdall/mcp/server.py` (`_read_extract`) |
| coupe sur lignes complètes | `heimdall/mcp/gitdiff.py` (`staged_diff`) |
| format de diff non compris → `truncated`, jamais du silence | `heimdall/mcp/gitdiff.py` (`_COMBINED_HUNK_HEADER`, `_DiffParser._hunk_header`) |
| aucun réseau | `tests/test_mcp_client.py` (`NoNetworkTests`, `NoTrafficTests`) |
| 100 % / 100 % mesuré | `tests/test_mcp_units.py` + sortie `coverage report` |
