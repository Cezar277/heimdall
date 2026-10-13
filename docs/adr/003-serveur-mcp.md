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
ni retiré en passant — par PR dédiée relue. Preuve : `SERVER_TOOLS` dans
`heimdall/mcp/server.py:57`, test de registre fermé.

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
tolérée. Preuve : `heimdall/mcp/server.py:106` + `ArgumentGateTests` +
tests unitaires de la frontière.

### 4. Échecs en enveloppe, jamais en exception

`tool_handler` traduit `ToolFailure` (code du contrat), `PathEscape`
(`PATH_ESCAPE`) et toute autre exception (`INTERNAL` statique) en
`{"error": {"code", "message"}}`. Seules les exceptions inattendues sont
journalisées avec trace (sur stderr, jamais sur stdout) ; un refus de
chemin est un fonctionnement normal. Les échecs sont marqués `isError` de
façon centrale (`_mark_failure`) : les deux formes du contrat étant
exclusives, un succès ne peut pas être pris pour un échec. Preuve :
`heimdall/mcp/server.py:164`, `198`, module `heimdall/mcp/errors.py`
(messages statiques ASCII, `allow_nan=False`, `ensure_ascii=True`).

### 5. Racine fixée au démarrage, absente des signatures

`build_server` résout la racine une fois ; les outils sont des closures
dessus. Aucun outil ne prend de paramètre `root` (vérifié par test) : le
piège du #27 (« laisser le LLM fournir la racine ») est impossible par
construction, pas par vigilance. Preuve : `heimdall/mcp/server.py:482`.

### 6. Git : argv figé, environnement reconstruit, options imposées

`git -C <racine> diff --cached --unified=0 --no-color --no-ext-diff
--no-textconv`, sans `shell=True`, binaire résolu par `shutil.which`,
délai 30 s. L'environnement est **reconstruit** (`PATH` vide, `HOME` =
racine, `GIT_CONFIG_*` neutralisées) : `GIT_DIR`/`GIT_INDEX_FILE` hérités
ne peuvent pas rediriger le dépôt analysé, et `--no-ext-diff
--no-textconv` rendent inopérants `diff.external` et les filtres `textconv`
(exécution de commande pilotée par le contenu scanné, interdit I5).
Prouvé par des tests hostiles (`GIT_DIR` piégé, `diff.external` piégé).
La commande est entièrement construite par le programme : suppressions
`noqa`/`nosec` justifiées en place. Preuve : `heimdall/mcp/gitdiff.py:38`,
`:53`, `:94`.

### 7. Masquage conservateur avant `json.dumps`, règles nues incluses

En cas de doute on masque (le LLM juge sur la forme, l'humain valide ; un
faux positif de masquage coûte un marqueur, un oubli coûte un secret relu
et recopié dans l'historique Ollama). Règles : affectations citées/non
citées, en-têtes `Authorization`, `user:pass@` d'URI, balises PEM **et**
jetons nus (préfixe connu, ou ≥ 32 caractères denses à entropie ≥ 3,9 —
`_BARE_KNOWN_TOKEN`, `_BARE_DENSE_TOKEN`). La fusion est par
**spécificité** (le mot de passe d'une URI part seul, l'hôte reste lisible)
puis par position. Les motifs sont linéaires (aucun quantificateur
imbriqué) : garde-fou temporel anti-ReDoS en test. Le jour où #22 arrive,
ses règles remplacent `_looks_like_secret` sans changer `mask_text`.
Limites honnêtes : un jeton **sans préfixe connu, noyé dans 100 Ko de
remplissage**, reste indétectable par fenêtre ; un SHA de commit copié en
clair est masqué (faux positif bénin assumé). Preuve :
`heimdall/mcp/masking.py`, `tests/test_mcp_hardening.py::BareTokenMaskingTests`.

### 8. Compteurs recomptés, budgets vérifiés après sérialisation

`redactions` compte les marqueurs **de la réponse** (recompté après coupe),
jamais une promesse : une coupe à 2000 caractères (ligne) ou 100 000
(caractères, `sanitize_file`) qui emporterait le seul marqueur violerait
sinon l'invariant structurel du schéma — faille réelle trouvée par audit
et corrigée, avec tests. Le budget `max_bytes` est vérifié sur la réponse
sérialisée (fichiers retirés en dernier, `truncated: true`). Preuve :
`heimdall/mcp/server.py:441` (`_masked_files`), `:408` (`_fit_budget`),
`tests/test_mcp_hardening.py::TruncationInvariantTests`.

### 9. Garde de chemin unique + TOCTOU documentée (exigence #76)

`confine` : refus de forme (grammaire `RelPath` du contrat, chemins absolus
toutes familles), `resolve()` (suit les liens sortants), `is_relative_to`
sur chemins résolus (jamais `startswith` : `/repo-evil` commence par
`/repo`). Le chemin renvoyé est **reconstruit** depuis le résolu, pas
recopié (aucune entrée reflétée). Ouverture `O_NOFOLLOW` + comparaison
dev/ino entre `lstat` et `fstat` (ELOOP refusé). **Limite connue** : entre
la résolution et l'ouverture, un fichier peut être remplacé — la fenêtre
est réduite à deux appels système, mais un attaquant avec écriture sur le
dépôt entre les deux reste hors de portée. `check-ignore` répond dès
qu'une règle couvre le chemin, même suivi : lecture stricte et prudente
du contrat 4.2 (un suivi-mais-ignoré est refusé). Preuve :
`heimdall/mcp/paths.py:114`, `heimdall/mcp/server.py:343`.

### 10. Noms git décodés en octets, irreprésentable = panne

Le guillemetage C est décodé en **octets** puis en UTF-8 (décoder par
caractère produisait du mojibake : `café.py` → `cafÃ©.py`, aller-retour
`read_diff` → `sanitize_file` cassé). `/dev/null` ne nomme rien, les
préfixes `a/`/`b/` ne sont retirés que si le reste reste valide, `Binary
files … and …` traite `/dev/null` en priorité (nom avec `and` dedans
correct). Un nom non représentable dans le contrat (contrôle, `..`,
UTF-8 invalide) est une **panne** (`INTERNAL`), pas un fichier sauté en
silence : mieux vaut refuser que cacher des lignes au LLM (fail-closed
délibéré, épinglé par test). Preuve : `heimdall/mcp/gitdiff.py:196`,
`:219`, `:360`.

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
  `heimdall/mcp` (tests unitaires in-process, déterministes) + 96 tests de
  bout en bout en sous-processus (vrai client MCP). La transmission de
  `COVERAGE_PROCESS_START` est câblée dans `tests/support/mcp_client.py`
  pour que la CI du #20 mesure aussi les sous-processus.
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
| masquage avant sérialisation, compteurs vrais | `heimdall/mcp/masking.py` (`mask_text`), `heimdall/mcp/server.py` (`_masked_files`) |
| garde unique, TOCTOU réduite | `heimdall/mcp/paths.py` (`confine`), `heimdall/mcp/server.py` (`_read_extract`) |
| aucun réseau | `tests/test_mcp_client.py` (`NoNetworkTests`, `NoTrafficTests`) |
| 100 % / 100 % mesuré | `tests/test_mcp_units.py` + sortie `coverage report` |
