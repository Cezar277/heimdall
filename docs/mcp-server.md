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
relecture — pas en passant, conformément aux règles de gel du contrat.

## 2 bis. Ce que `read_diff` garantit

L'outil est la seule fenêtre du LLM sur le commit en cours
(`heimdall/mcp/gitdiff.py`).

| Garantie | Comment | Preuve |
|---|---|---|
| commande git figée, `shell=True` proscrit | argv constant, binaire résolu par `shutil.which` | `tests/test_mcp_read_diff.py` |
| `diff.external` / `textconv` inopérants (interdit I5) | `--no-ext-diff --no-textconv` imposés | `GitEnvironmentTests` |
| l'environnement hérité ne redirige pas le dépôt | `GIT_DIR`, `GIT_INDEX_FILE`, `HOME`, `PATH` reconstruits à zéro | `GitEnvironmentTests` |
| aucune valeur en clair renvoyée | masquage `<REDACTED:type:len=N>` **avant** `json.dumps` | `test_secret_values_are_masked_before_serialization` |
| réponse bornée par `max_bytes` | budget vérifié **après** sérialisation, fichiers retirés en dernier | `test_response_never_exceeds_max_bytes` |
| limite atteinte = information incomplète | `truncated: true`, jamais « diff vide » | tests de troncature |
| réponse conforme au contrat #16 | validée contre `ReadDiffResult` (oneOf succès / échec) | `ReadDiffConformanceTests` |

Masquage (`heimdall/mcp/masking.py`) : volontairement conservateur — en cas de
doute on masque. Le LLM juge sur la forme (type, longueur, contexte), pas sur
la valeur. Ces règles seront remplacées par celles du scanner déterministe
(#22) sans changer l'interface `mask_text`.

## 2 ter. Ce que `sanitize_file` garantit

Le chemin vient du LLM : il est traité comme une entrée piégée
(`heimdall/mcp/paths.py` + l'outil dans `heimdall/mcp/server.py`).

| Garantie | Comment | Preuve |
|---|---|---|
| une seule garde, appelée par tout outil qui reçoit un chemin | `paths.confine` : refus de forme, `resolve()`, `is_relative_to` | `tests/test_mcp_paths.py` |
| refus de `..`, des chemins absolus, des liens sortants | résolution réelle + confinement sur `Path` résolus | `RefusalTests` |
| `.git/`, `.env*`, fichiers ignorés interdits | segments interdits + `git check-ignore` | `tests/test_mcp_sanitize_file.py` |
| binaire, > 1 Mo, absent, dossier | codes dédiés (`BINARY_FILE`, `TOO_LARGE`, `NOT_FOUND`) | idem |
| ouverture sans suivre un lien | `O_NOFOLLOW` + comparaison dev/ino (TOCTOU) | `GuardWiringTests` |
| extrait masqué avant sérialisation | `masking.mask_text`, puis borne 100 000 caractères | `test_no_clear_value_ever_reaches_the_llm` |
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

## 4. Ce que le serveur garantit, et comment c'est prouvé

| Garantie | Où | Preuve |
|---|---|---|
| stdio seul, aucun port, aucun appel réseau | `heimdall/mcp/server.py` (`run_stdio`) | tests client stdio |
| racine fixée au démarrage, absente des entrées | `build_server` / `_tools` (closures) | pas de paramètre `root` dans les signatures |
| champ d'entrée hors contrat refusé | `_ToolBoundary` | `ArgumentGateTests` |
| échecs dans l'enveloppe `{"error": …}`, jamais en exception | `tool_handler`, `heimdall/mcp/errors.py` | tests de chaque outil |
| échec marqué `isError`, succès jamais | `_ToolBoundary._mark_failure` | `test_failure_envelopes_are_flagged` |
| aucune entrée reflétée au LLM | messages statiques d'`errors.py` | `test_refusal_message_is_static` |
| stdout = protocole uniquement | aucun `print` dans `heimdall/mcp/` | `StdoutIsProtocolOnlyTests` |
| registre fermé | `SERVER_TOOLS` + garde d'entrée | `test_ping_is_declared_to_the_client` |

## 5. Lancement en CI / debug

Le serveur n'a pas de mode interactif : en CI, le LLM n'a aucun pouvoir et seul
`heimdall scan --ci` décide (#33, #37). Lancer `heimdall mcp` en CI n'aurait
donc aucun sens ; la commande existe pour le poste du développeur et pour les
tests.
