# Serveur MCP stdio — lancement, outils, invariants

> Ticket #27 (sous-tickets #73, #74, #75, #78) · Contrat : [#16](contracts/mcp-tools.md)
> Porteur : D · Relecteur : B · Sprint S1

Ce document décrit **comment lancer** le serveur MCP d'Heimdall et ce qu'il
expose. Le contrat de ce qu'il ne peut pas faire (invariants I1 à I15) est dans
`contracts/mcp-tools.md` et `schemas/mcp-tools.schema.json` ; ce fichier dit
comment le faire tourner et comment le vérifier.

## 1. Lancer le serveur

```sh
# voie 1 — par la CLI (recommandée)
.venv/bin/heimdall mcp --root .

# voie 2 — module Python, utile pour un client de test
.venv/bin/python -m heimdall.mcp --root .
```

Le serveur parle MCP **sur stdio** : le client le démarre en sous-processus et
lui écrit des requêtes JSON-RPC sur stdin. Il n'ouvre aucun port (invariant 7)
et ne fait aucun appel réseau.

- `--root` est la racine du dépôt. Elle est **fixée au démarrage** et n'apparaît
  dans aucune entrée d'outil : le LLM ne peut pas la choisir ni la changer
  (invariant 2). Une racine absente fait sortir en code 2 (panne d'outillage),
  jamais 1 (réservé aux secrets avérés).
- `stdout` ne porte **que** le protocole. Tout diagnostic va sur stderr
  (`logging`). Un `print()` sur stdout corromprait le canal (piège du #73) ; le
  test `tests/test_mcp_server.py::StdoutIsProtocolOnlyTests` l'interdit.

## 2. Outils exposés

| Outil | Rôle | Livré par |
|---|---|---|
| `ping` | sonde de vie : répond `pong`, aucune donnée du dépôt | #73 |
| `read_diff` | lignes ajoutées du diff indexé, valeurs masquées | #74 |
| `sanitize_file` | extrait d'un fichier du dépôt, valeurs masquées | #75 |
| `list_candidates` | Findings du scanner déterministe | ticket dédié (dépend de #22) |
| `propose_patch` | aperçu d'un remplacement par variable d'env. | ticket dédié (dépend de #30) |

Les deux derniers outils du contrat #16 ne sont **pas** encore exposés : ce
livrable couvre `ping`, `read_diff` et `sanitize_file`. Le registre est fermé
(`SERVER_TOOLS` dans `heimdall/mcp/server.py`) : un nom hors liste est refusé par
le SDK, et la garde d'entrée refuse tout argument hors contrat.

**Écart assumé au contrat : `ping`.** `ping` n'est pas l'un des 4 outils du
contrat #16. Il est la sonde de vie demandée par le #73 : il ne renvoie aucune
donnée du dépôt (juste `{"pong": true}`), donc il n'élargit pas la surface de
fuite. Son intégration au contrat (ou son retrait) se fait par PR dédiée, avec
relecture — pas en passant, conformément aux règles de gel du contrat, et sans
réutiliser cette dérogation comme précédent. L'écart est **verrouillé par un
test** (`tests/test_mcp_server.py::ContractGapTests`) : tant que `ping` n'est
pas dans `x-tools`, aucun autre nom hors contrat ne peut être exposé.

## 2 bis. Ce que `read_diff` garantit

L'outil est la seule fenêtre du LLM sur le commit en cours
(`heimdall/mcp/gitdiff.py`).

| Garantie | Comment | Preuve |
|---|---|---|
| commande git figée, `shell=True` proscrit | argv constant, binaire résolu hors PATH hérité (`os.defpath`) | `tests/test_mcp_read_diff.py` |
| binaire git jamais sous la racine ni sous le cwd | sur win32 `shutil.which` préfixe le cwd d'office : un `git.exe` piégé serait exécuté (RCE) → refus `INTERNAL` avant usage | `test_git_binary_under_the_root_is_refused_never_executed` |
| config locale neutralisée | `-c core.fsmonitor=false` sur chaque appel (hook prouvé exécuté sans) | `test_fsmonitor_hook_is_never_executed` |
| pager hostile inopérant | sorties toujours pipées, prouvé sans override | `test_hostile_pager_is_never_executed` |
| `diff.external` / `textconv` inopérants (interdit I5) | `--no-ext-diff --no-textconv` imposés | `GitEnvironmentTests` |
| l'environnement hérité ne redirige pas le dépôt | `GIT_DIR`, `GIT_INDEX_FILE`, `HOME`, `PATH` reconstruits à zéro | `GitEnvironmentTests` |
| le canal stdio MCP n'est jamais hérité par git | `stdin=subprocess.DEVNULL` sur chaque appel, garde statique dans `tests/security/test_prompt_injection.py` | `test_no_git_call_inherits_the_server_stdin_pipe` |
| aucun dépôt parent découvert | `GIT_CEILING_DIRECTORIES` = parent de la racine : git refuse lui-même de remonter (rc=128), sans dépendre de `is_repository()` | `RepositoryCeilingTests` |
| aucune valeur en clair renvoyée | masquage `<REDACTED:type:len=N>` **avant** `json.dumps`, sur la ligne entière puis troncature | `test_secret_values_are_masked_before_serialization` |
| une valeur citée longue n'est jamais sectionnée avant masquage | pas de fenêtre préalable : `mask_text` voit le guillemet fermant (régression de revue fermée) | `test_long_quoted_value_is_masked_not_windowed` |
| valeur quotée masquée en entier, sans borne haute | `SECRET="` + 50000 car : plus de préfixe en clair (borne `{4,}` sans borne haute) | `test_quoted_assignment_above_20k_chars_is_masked_whole` |
| binaire modifié avec `" and "` dans le nom : nom entier | découpe retenue = celle où les deux côtés concordent, jamais un nom tronqué | `test_modified_binary_with_and_in_its_name_keeps_the_whole_name` |
| réponse bornée par `max_bytes` | budget vérifié **après** sérialisation, fichiers retirés en dernier (une seule sérialisation par fichier) | `test_response_never_exceeds_max_bytes` |
| limite atteinte = information incomplète | `truncated: true`, jamais « diff vide » | tests de troncature |
| format de diff non compris → rien n'est jeté en silence | hunk combiné `@@@ ` décodé, en-tête illisible ou `* Unmerged path` → `truncated: true` | `test_unmerged_path_is_never_a_silent_empty_diff` |
| en-tête combiné hostile sans ReDoS | garde-fou 512 car. avant regex + motif mesuré linéaire, les deux chemins épinglés en temps borné | `test_hostile_combined_hunk_header_is_fast_and_flagged` |
| nom irreprésentable → fichier sauté + `truncated` | comme tout plafond : autres fichiers triés, nom à octet de contrôle non montrable | `test_newline_path_is_skipped_without_partial_silence` |
| compteur `redactions` toujours vrai | recompté sur les lignes finales : une coupe n'y laisse jamais un compteur sans marqueur | `TruncationInvariantTests` |
| coupe `max_bytes` sur lignes complètes | la ligne à cheval est abandonnée (aucun préfixe en clair) | `test_secret_never_straddles_any_budget` |
| FIFO/socket/device refusés, `O_NONBLOCK` | pas de blocage infini (DoS), revérifié après ouverture | `test_fifo_does_not_hang_the_server` |
| noms git décodés en octets puis UTF-8 | pas de mojibake (`café.py`), irreprésentable = `INTERNAL` (fail-closed) | `UnquoteTests` |
| réponse conforme au contrat #16 | validée contre `ReadDiffResult` (oneOf succès / échec) | `ReadDiffConformanceTests` |

Masquage (`heimdall/mcp/masking.py`) : volontairement conservateur — en cas de
doute on masque. Le LLM juge sur la forme (type, longueur, contexte), pas sur
la valeur. Le scanner déterministe (#22) ne remplace pas ces règles sans
changer l'interface `mask_text` : le masquage couvre aussi les champs que le
scanner ne produit pas.

## 2 ter. Ce que `sanitize_file` garantit

Le chemin vient du LLM : il est traité comme une entrée piégée
(`heimdall/mcp/paths.py` + l'outil dans `heimdall/mcp/server.py`).

| Garantie | Comment | Preuve |
|---|---|---|
| une seule garde, appelée par tout outil qui reçoit un chemin | `paths.confine` : refus de forme, `resolve()`, `is_relative_to` | `tests/test_mcp_paths.py` |
| refus de `..`, des chemins absolus, des liens sortants | résolution réelle + confinement sur `Path` résolus | `RefusalTests` |
| `.git/`, `.env*`, fichiers ignorés interdits | segments interdits (`.env-backup` inclus, `.envelope` sur-bloqué assumé) + `git check-ignore` | `tests/test_mcp_sanitize_file.py` |
| fichiers de credentials interdits (F-09) | `.netrc`, `.pgpass`, `id_rsa*`, `id_ed25519*`, `*.pem`, `*.key`, `.npmrc`, `.pypirc`, `credentials`, `.docker/config.json`, `.kube/config`, casse ignorée, **variantes de sauvegarde incluses** (`.netrc.backup`, `.pgpass~`, `credentials.json`, `credentials-backup`, `server.pem.bak`, `private.key.old`, `.docker/config.json.bak`…) | `test_credential_backup_variants_are_forbidden`, `test_pem_key_backup_variants_are_forbidden`, `test_credential_files_are_forbidden` |
| binaire, > 1 Mo, absent, dossier | codes dédiés (`BINARY_FILE`, `TOO_LARGE`, `NOT_FOUND`) | idem |
| `NOT_FOUND` réservé à l'absence, droits refusés en `INTERNAL` | `EACCES`/`EPERM` (et `lstat` refusé) = panne d'intégrité, pas « introuvable » | `test_unreadable_file_is_internal_not_not_found` |
| codes stables, liens jugés par leur cible | FIFO avant garde `BINARY_FILE` / après garde `INTERNAL` ; lien sortant `PATH_ESCAPE` | `test_non_regular_files_keep_a_stable_code` |
| ouverture sans suivre un lien | `O_NOFOLLOW` + comparaison dev/ino (TOCTOU) | `GuardWiringTests` |
| extrait masqué avant sérialisation | `masking.mask_text` sur la ligne entière, puis borne 100 000 caractères | `test_no_clear_value_ever_reaches_the_llm` |
| coupe à 100 000 sans fragment de marqueur | `_clean_trailing_marker` après la coupe, compteur recompté : jamais `<REDACTED:` sans `>` | `test_redaction_marker_straddling_100000_char_boundary_is_cleaned` |
| valeur citée > 2,5 Ko jamais sectionnée avant masquage | masquage avant troncature, sans fenêtre préalable | `test_long_quoted_value_is_masked_not_windowed` |
| jetons nus et corps PEM masqués | préfixe connu ou ≥ 32 caractères denses, fusion par spécificité | `BareTokenMaskingTests` |
| valeur courte sous un nom évocateur masquée | `SECRET=abc12`, `PASSWORD=1234` — règle à fenêtre séparée (sinon ombrage), filtres anti-bruit mesurés | `test_short_evocative_value_is_masked` |
| valeur courte quotée masquée | `TOKEN="x1"`, `SECRET="ab1"` — guillemets symétriques optionnels, même jugement | `test_short_quoted_value_is_masked_end_to_end` |
| clés JSON/YAML/dict et formes piégées masquées (E-03) | guillemets de clé optionnels, quotes croisées, `=>`, phrase de passe avec espaces, valeur quotée non refermée, XML, `define` (nom/valeur nus), `.netrc`, `-u user:pass`, `--password` | `tests/test_mcp_masking.py`, `test_unclosed_quoted_password_is_masked_end_to_end` |
| directive `diff --*` inconnue signalée | `diff --combined` ou futur format → `truncated`, fichiers voisins montrés | `test_unknown_diff_directive_is_flagged_never_silent` |
| noms génériques masqués | `KEY=hunter2`, `PASS=abc12345`, `AWS_KEY=`, `MYKEY=` (second rang : nom faible + valeur alphanumérique), `keyboard`/`key: "name"` laissés lisibles | `test_generic_key_names_are_masked_end_to_end` |
| valeur non citée masquée en entier | `SECRET=` + 5000 caractères : plus de queue en clair après le marqueur (borne `{6,}` sans borne haute) | `test_long_unquoted_value_is_masked_whole_end_to_end` |
| jeton dans un userinfo sans mot de passe masqué | `https://<jeton>@hôte`, type `url_userinfo`, seuil ≥ 8 car. et ≥ 3,0 bits | `test_url_token_without_password_is_masked` |
| secret en position user d'une URL à deux champs masqué | `https://<jeton>:pwd@h` : user (`url_userinfo`) + password, `admin`/`alice` restant lisibles | `test_url_with_secret_user_is_masked_end_to_end` |
| paramètre `path` manquant refusé | enveloppe `INVALID_INPUT`, pas « Field required » du SDK | `RequiredParametersTests` |
| réponse conforme au contrat #16 | validée contre `SanitizeFileResult` | `test_response_conforms_to_the_contract` |

**Choix fail-closed assumé** : un fichier **suivi** mais couvert par une règle
`.gitignore` est refusé. `check-ignore` répond dès qu'une règle couvre le chemin,
même si le fichier est déjà dans l'index ; c'est la lecture stricte du contrat
4.2. La remédiation (#30) lira ce cas par son propre canal, pas par cet outil.

**Limite connue (TOCTOU)** : entre la résolution du chemin et l'ouverture, un
fichier peut être remplacé. L'ouverture utilise `O_NOFOLLOW` et vérifie que
dev/ino n'a pas changé, mais un attaquant capable d'écrire dans le dépôt entre
les deux appels reste hors de portée de cette garde — à consigner dans l'ADR du
#27.

## 3. Vérifier le canal avec un client MCP

Voie vérifiée : petit client Python, hors ligne, aucune dépendance réseau
(utilisé par `tests/support/mcp_client.py`, partagé par tous les tests du serveur).

```python
import asyncio, sys
from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

params = StdioServerParameters(
    command=sys.executable, args=["-m", "heimdall.mcp", "--root", "."]
)

async def main() -> None:
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools = await session.list_tools()
            print([t.name for t in tools.tools])
            result = await session.call_tool("ping", {})
            print(result.content[0].text)

asyncio.run(main())
```

L'inspecteur officiel (`npx @modelcontextprotocol/inspector`) reste utilisable
pour une démo manuelle, mais il **télécharge** des paquets npm : hors ligne, lui
préférer le client Python ci-dessus (règle « 100 % local »).

## 3 bis. Ce que les tests client prouvent (#78)

`tests/test_mcp_client.py` ne teste plus un client poli mais un **client
adverse** (donc ce que le LLM tentera) :

| Preuve | Comment |
|---|---|
| session complète comme celle de l'agent Ollama (#28) | `initialize` → `tools/list` → `read_diff` + `sanitize_file`, chaque réponse validée contre le contrat #16 |
| injection de prompt renvoyée comme une donnée | une consigne piégée dans le diff revient telle quelle (jamais exécutée), seule la valeur est masquée |
| aucun outil hors registre n'est appelable | `exec`, `shell`, `write_file`, `propose_patch`… refusés |
| contrebande d'arguments sans effet | champ `root`/`cwd` bonus → `INVALID_INPUT`, types jamais convertis en silence |
| aucun message ne fuit un chemin ou une valeur | messages statiques, sans `\n` (le LLM les relit) |
| aucun outil n'écrit | l'arborescence du dépôt est identique avant/après tous les appels |
| aucun port, aucun socket INET, aucun socket nommé | inspection `/proc` + recoupe `ss -anp` (voir ci-dessous) |

**Pourquoi « aucun socket » demandait un correctif.** Le serveur tourne sur
asyncio, qui crée au démarrage une paire de sockets UNIX **anonymes**
(auto-réveil de la boucle). Elles ne sont ni des ports, ni des connexions,
ni des chemins vers un tiers : interdire toute présence de `socket:` les
signalait à tort. Le test autorise donc exactement cette paire anonyme et
interdit tout le reste — avec un contrôle négatif (un `http.server` témoin
est bien signalé, par `/proc/net/tcp` **et** par `ss`). Sans `ss` sur la
machine, le recoupe des pairs distants est sauté ; les tables `/proc` et la
preuve statique (aucun import réseau dans `heimdall/mcp/`, `NoTrafficTests`)
restent vérifiées.

## 4. Ce que le serveur garantit, et comment c'est prouvé

| Garantie | Où | Preuve |
|---|---|---|
| stdio seul, aucun port, aucun appel réseau | `heimdall/mcp/server.py` (`run_stdio`) | tests client stdio |
| racine fixée au démarrage, absente des entrées | `build_server` / `_tools` (closures) | pas de paramètre `root` dans les signatures |
| champ d'entrée hors contrat refusé | `_ToolBoundary` | `ArgumentGateTests` |
| échecs dans l'enveloppe `{"error": …}`, jamais en exception | `tool_handler`, `heimdall/mcp/errors.py` | tests de chaque outil |
| échec marqué `isError`, succès jamais | `_ToolBoundary._mark_failure` | `test_failure_envelopes_are_flagged` |
| enveloppe close, `_meta` bornée | pas de message libre (`TypeError` sinon), `_meta` > 1 Kio refusée | `test_tool_failure_has_no_free_message_channel` |
| aucune entrée reflétée au LLM | messages statiques d'`errors.py` | `test_refusal_message_is_static` |
| stdout = protocole uniquement | aucun `print` dans `heimdall/mcp/` | `StdoutIsProtocolOnlyTests` |
| registre fermé | `SERVER_TOOLS` + garde d'entrée | `test_ping_is_declared_to_the_client` |
| outil inconnu dans l'enveloppe, jamais le texte du SDK | `_ToolBoundary` refuse en `INVALID_INPUT` sans refléter le nom | `test_unknown_tool_is_refused` |
| décisions et limites (ADR) | SDK v2, `ping` hors contrat, TOCTOU, écarts | `docs/adr/003-serveur-mcp.md` |
| 100 % instructions / branches mesuré | tests unitaires in-process déterministes (+ 26 e2e stdio) | `tests/test_mcp_units.py` + `coverage report` |
| session adverse conforme au contrat | vrai client stdio, réponses validées | `tests/test_mcp_client.py::EndToEndSessionTests` |
| aucun port / INET / socket nommé | `/proc` + `ss`, paire anonyme asyncio seule autorisée | `NoNetworkTests` (+ contrôle négatif `http.server`) |
| aucun import réseau dans le serveur | analyse AST de `heimdall/mcp/` | `NoTrafficTests` |

## 5. Lancement en CI / debug

Le serveur n'a pas de mode interactif : en CI, le LLM n'a aucun pouvoir et seul
`heimdall scan --ci` décide (#33, #37). Lancer `heimdall mcp` en CI n'aurait
donc aucun sens ; la commande existe pour le poste du développeur et pour les
tests.
