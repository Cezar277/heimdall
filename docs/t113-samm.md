# T113 — preuves pour la ligne SAMM (journal d'audit)

Périmètre : sous-ticket **#113** du ticket parent `#39 « Auth durcie,
rate-limiting et audit log »`.

Révision du code testé : `8a766707b1818738dd91dffddedea06d697ec032`
(`fix(vault): corrèle la cle fournie sur health sans consommer son budget (#39)`).

## 1. Exigences du ticket et preuves

| Exigence vérifiée | Implémentation (module + ligne) | Test et preuve permanente | Résultat local |
|---|---|---|---|
| Table `audit_events` : date, identifiant de clé, IP, action, cible, résultat | [heimdall/vault/database.py:187–212](https://github.com/Cezar277/heimdall/blob/8a766707b1818738dd91dffddedea06d697ec032/heimdall/vault/database.py#L187-L212), [heimdall/vault/audit.py:60–73](https://github.com/Cezar277/heimdall/blob/8a766707b1818738dd91dffddedea06d697ec032/heimdall/vault/audit.py#L60-L73) | [tests/test_vault_audit.py:90–128](https://github.com/Cezar277/heimdall/blob/8a766707b1818738dd91dffddedea06d697ec032/tests/test_vault_audit.py#L90-L128) | Réussi |
| Health avec clé : empreinte corrélée, budget clé non consommé | [heimdall/vault/app.py:1202–1206](https://github.com/Cezar277/heimdall/blob/8a766707b1818738dd91dffddedea06d697ec032/heimdall/vault/app.py#L1202-L1206) | [tests/test_vault_audit.py:130–153](https://github.com/Cezar277/heimdall/blob/8a766707b1818738dd91dffddedea06d697ec032/tests/test_vault_audit.py#L130-L153) | Réussi |
| Un événement par accès, **401/403 inclus** | [heimdall/vault/audit.py:617–731](https://github.com/Cezar277/heimdall/blob/8a766707b1818738dd91dffddedea06d697ec032/heimdall/vault/audit.py#L617-L731), [heimdall/vault/app.py:1833](https://github.com/Cezar277/heimdall/blob/8a766707b1818738dd91dffddedea06d697ec032/heimdall/vault/app.py#L1833) | [tests/test_vault_audit.py:90–128](https://github.com/Cezar277/heimdall/blob/8a766707b1818738dd91dffddedea06d697ec032/tests/test_vault_audit.py#L90-L128) | Réussi |
| Cible d'audit renseignée sur la liste (200 et 403 cross-projet) | [heimdall/vault/app.py:1444–1452](https://github.com/Cezar277/heimdall/blob/8a766707b1818738dd91dffddedea06d697ec032/heimdall/vault/app.py#L1444-L1452) | [tests/test_vault_audit.py:62–88](https://github.com/Cezar277/heimdall/blob/8a766707b1818738dd91dffddedea06d697ec032/tests/test_vault_audit.py#L62-L88) | Réussi |
| Les 429 de débit sont aussi journalisés | [heimdall/vault/audit.py:629–680](https://github.com/Cezar277/heimdall/blob/8a766707b1818738dd91dffddedea06d697ec032/heimdall/vault/audit.py#L629-L680) | [tests/test_vault_audit.py:155–180](https://github.com/Cezar277/heimdall/blob/8a766707b1818738dd91dffddedea06d697ec032/tests/test_vault_audit.py#L155-L180), [tests/test_vault_abuse_runtime.py:57–86](https://github.com/Cezar277/heimdall/blob/8a766707b1818738dd91dffddedea06d697ec032/tests/test_vault_abuse_runtime.py#L57-L86) | Réussi |
| Aucune valeur de secret, aucun corps de requête, aucune clé complète | [heimdall/vault/audit.py:98–133](https://github.com/Cezar277/heimdall/blob/8a766707b1818738dd91dffddedea06d697ec032/heimdall/vault/audit.py#L98-L133), [heimdall/vault/audit.py:682–717](https://github.com/Cezar277/heimdall/blob/8a766707b1818738dd91dffddedea06d697ec032/heimdall/vault/audit.py#L682-L717) | [tests/test_vault_audit.py:182–208](https://github.com/Cezar277/heimdall/blob/8a766707b1818738dd91dffddedea06d697ec032/tests/test_vault_audit.py#L182-L208) | Réussi |
| Identifiant de clé (`key_id`) et empreinte tronquée, jamais la clé | [heimdall/vault/auth.py:645–662](https://github.com/Cezar277/heimdall/blob/8a766707b1818738dd91dffddedea06d697ec032/heimdall/vault/auth.py#L645-L662), [heimdall/vault/audit.py:117–133](https://github.com/Cezar277/heimdall/blob/8a766707b1818738dd91dffddedea06d697ec032/heimdall/vault/audit.py#L117-L133) | [tests/test_vault_audit.py:90–128](https://github.com/Cezar277/heimdall/blob/8a766707b1818738dd91dffddedea06d697ec032/tests/test_vault_audit.py#L90-L128) | Réussi |
| Chaînage par hash et détection d'altération | [heimdall/vault/audit.py:151–181](https://github.com/Cezar277/heimdall/blob/8a766707b1818738dd91dffddedea06d697ec032/heimdall/vault/audit.py#L151-L181), [heimdall/vault/audit.py:570–594](https://github.com/Cezar277/heimdall/blob/8a766707b1818738dd91dffddedea06d697ec032/heimdall/vault/audit.py#L570-L594) | [tests/test_vault_audit.py:210–221](https://github.com/Cezar277/heimdall/blob/8a766707b1818738dd91dffddedea06d697ec032/tests/test_vault_audit.py#L210-L221), [tests/test_vault_audit.py:545–553](https://github.com/Cezar277/heimdall/blob/8a766707b1818738dd91dffddedea06d697ec032/tests/test_vault_audit.py#L545-L553) | Réussi |
| Journal consultable et testé (CLI `list` / `verify`) | [heimdall/cli/vault_keys.py:233–320](https://github.com/Cezar277/heimdall/blob/8a766707b1818738dd91dffddedea06d697ec032/heimdall/cli/vault_keys.py#L233-L320) | [tests/test_vault_audit.py:509–602](https://github.com/Cezar277/heimdall/blob/8a766707b1818738dd91dffddedea06d697ec032/tests/test_vault_audit.py#L509-L602) | Réussi |
| Fail-closed si l'audit échoue | [heimdall/vault/audit.py:629–680](https://github.com/Cezar277/heimdall/blob/8a766707b1818738dd91dffddedea06d697ec032/heimdall/vault/audit.py#L629-L680), [heimdall/vault/audit.py:720–731](https://github.com/Cezar277/heimdall/blob/8a766707b1818738dd91dffddedea06d697ec032/heimdall/vault/audit.py#L720-L731) | [tests/test_vault_audit.py:223–240](https://github.com/Cezar277/heimdall/blob/8a766707b1818738dd91dffddedea06d697ec032/tests/test_vault_audit.py#L223-L240) | Réussi |
| Backend SQLite partagé entre workers | [heimdall/vault/audit.py:383–614](https://github.com/Cezar277/heimdall/blob/8a766707b1818738dd91dffddedea06d697ec032/heimdall/vault/audit.py#L383-L614) | [tests/test_vault_audit.py:277–288](https://github.com/Cezar277/heimdall/blob/8a766707b1818738dd91dffddedea06d697ec032/tests/test_vault_audit.py#L277-L288) | Réussi |
| **Bornage du listage** : mémoire et SQLite partagent `max(1, min(MAX_LIST_LIMIT, int(limit)))` | [heimdall/vault/audit.py:333–344](https://github.com/Cezar277/heimdall/blob/8a766707b1818738dd91dffddedea06d697ec032/heimdall/vault/audit.py#L333-L344), [heimdall/vault/audit.py:546–568](https://github.com/Cezar277/heimdall/blob/8a766707b1818738dd91dffddedea06d697ec032/heimdall/vault/audit.py#L546-L568) | [tests/test_vault_audit.py:326–367](https://github.com/Cezar277/heimdall/blob/8a766707b1818738dd91dffddedea06d697ec032/tests/test_vault_audit.py#L326-L367) | Réussi |
| **Rétention bornée** : purge des plus anciens et point de contrôle de chaîne | [heimdall/vault/audit.py:57](https://github.com/Cezar277/heimdall/blob/8a766707b1818738dd91dffddedea06d697ec032/heimdall/vault/audit.py#L57), [heimdall/vault/audit.py:415–447](https://github.com/Cezar277/heimdall/blob/8a766707b1818738dd91dffddedea06d697ec032/heimdall/vault/audit.py#L415-L447), [heimdall/vault/database.py:204–212](https://github.com/Cezar277/heimdall/blob/8a766707b1818738dd91dffddedea06d697ec032/heimdall/vault/database.py#L204-L212) | [tests/test_vault_audit.py:371–386](https://github.com/Cezar277/heimdall/blob/8a766707b1818738dd91dffddedea06d697ec032/tests/test_vault_audit.py#L371-L386) | Réussi |
| Panne SQLite du journal ou du débit → **503**, jamais 500 | [heimdall/vault/audit.py:629–680](https://github.com/Cezar277/heimdall/blob/8a766707b1818738dd91dffddedea06d697ec032/heimdall/vault/audit.py#L629-L680), [heimdall/vault/audit.py:720–731](https://github.com/Cezar277/heimdall/blob/8a766707b1818738dd91dffddedea06d697ec032/heimdall/vault/audit.py#L720-L731) | [tests/test_vault_audit.py:242–275](https://github.com/Cezar277/heimdall/blob/8a766707b1818738dd91dffddedea06d697ec032/tests/test_vault_audit.py#L242-L275), [tests/test_vault_availability.py](https://github.com/Cezar277/heimdall/blob/8a766707b1818738dd91dffddedea06d697ec032/tests/test_vault_availability.py) | Réussi |
| Migration d'une base antérieure à #39 : `init_db` recrée les tables | [heimdall/vault/database.py:187–212](https://github.com/Cezar277/heimdall/blob/8a766707b1818738dd91dffddedea06d697ec032/heimdall/vault/database.py#L187-L212), [heimdall/vault/database.py:827–835](https://github.com/Cezar277/heimdall/blob/8a766707b1818738dd91dffddedea06d697ec032/heimdall/vault/database.py#L827-L835) | [tests/test_vault_audit.py:460–479](https://github.com/Cezar277/heimdall/blob/8a766707b1818738dd91dffddedea06d697ec032/tests/test_vault_audit.py#L460-L479) | Réussi |
| Ids d'audit uniques et monotones après purge (mémoire) | [heimdall/vault/audit.py:266](https://github.com/Cezar277/heimdall/blob/8a766707b1818738dd91dffddedea06d697ec032/heimdall/vault/audit.py#L266), [heimdall/vault/audit.py:315](https://github.com/Cezar277/heimdall/blob/8a766707b1818738dd91dffddedea06d697ec032/heimdall/vault/audit.py#L315), [heimdall/vault/audit.py:328](https://github.com/Cezar277/heimdall/blob/8a766707b1818738dd91dffddedea06d697ec032/heimdall/vault/audit.py#L328) | [tests/test_vault_audit.py:388–401](https://github.com/Cezar277/heimdall/blob/8a766707b1818738dd91dffddedea06d697ec032/tests/test_vault_audit.py#L388-L401) | Réussi |
| Concurrence SQLite : requêtes parallèles sans 500, 503 générique + `Retry-After: 1` seulement | [heimdall/vault/audit.py:449–469](https://github.com/Cezar277/heimdall/blob/8a766707b1818738dd91dffddedea06d697ec032/heimdall/vault/audit.py#L449-L469) | [tests/test_vault_availability.py:206–235](https://github.com/Cezar277/heimdall/blob/8a766707b1818738dd91dffddedea06d697ec032/tests/test_vault_availability.py#L206-L235), [tests/test_vault_availability.py:311–336](https://github.com/Cezar277/heimdall/blob/8a766707b1818738dd91dffddedea06d697ec032/tests/test_vault_availability.py#L311-L336) | Réussi |
| Chemin prod authentifié (limiteur SQLite réel + audit SQLite, clé valide) : aucun 500, 503 générique seul | [heimdall/vault/ratelimit.py:261–439](https://github.com/Cezar277/heimdall/blob/8a766707b1818738dd91dffddedea06d697ec032/heimdall/vault/ratelimit.py#L261-L439), [heimdall/vault/audit.py:449–469](https://github.com/Cezar277/heimdall/blob/8a766707b1818738dd91dffddedea06d697ec032/heimdall/vault/audit.py#L449-L469) | [tests/test_vault_availability.py:236–274](https://github.com/Cezar277/heimdall/blob/8a766707b1818738dd91dffddedea06d697ec032/tests/test_vault_availability.py#L236-L274), [tests/test_vault_availability.py:275–310](https://github.com/Cezar277/heimdall/blob/8a766707b1818738dd91dffddedea06d697ec032/tests/test_vault_availability.py#L275-L310) | Réussi |
| Verrou pair tenu par un écrivain externe : 503 générique à toutes les requêtes concurrentes | [heimdall/vault/audit.py:629–680](https://github.com/Cezar277/heimdall/blob/8a766707b1818738dd91dffddedea06d697ec032/heimdall/vault/audit.py#L629-L680) | [tests/test_vault_availability.py:311–336](https://github.com/Cezar277/heimdall/blob/8a766707b1818738dd91dffddedea06d697ec032/tests/test_vault_availability.py#L311-L336) | Réussi |
| `verify` CLI sur base absente ou corrompue : sortie 1 générique, base non créée, sans fuite | [heimdall/cli/vault_keys.py:291–320](https://github.com/Cezar277/heimdall/blob/8a766707b1818738dd91dffddedea06d697ec032/heimdall/cli/vault_keys.py#L291-L320) | [tests/test_vault_audit.py:555–587](https://github.com/Cezar277/heimdall/blob/8a766707b1818738dd91dffddedea06d697ec032/tests/test_vault_audit.py#L555-L587) | Réussi |
| Rétention SQLite : altération du premier événement retenu localisée via le point de contrôle | [heimdall/vault/audit.py:415–447](https://github.com/Cezar277/heimdall/blob/8a766707b1818738dd91dffddedea06d697ec032/heimdall/vault/audit.py#L415-L447) | [tests/test_vault_audit.py:403–427](https://github.com/Cezar277/heimdall/blob/8a766707b1818738dd91dffddedea06d697ec032/tests/test_vault_audit.py#L403-L427) | Réussi |

## 2. Format et chaînage

Chaque événement contient `occurred_at`, `key_id`, `key_fingerprint`,
`project`, `peer`, `action`, `target`, `status_code`, `outcome`,
`previous_hash` et `entry_hash`.

- `entry_hash = SHA-256(charge canonique JSON)` ; `previous_hash` référence
  l'événement précédent (`GENESIS` pour le premier).
- La table est **bornée** par `MAX_AUDIT_EVENTS` (100 000). Au-delà, les plus
  anciens événements sont purgés et leur dernier `entry_hash` est conservé dans
  `audit_chain_state.checkpoint_hash` : le premier événement retenu pointe
  dessus, donc la chaîne reste vérifiable sans charger tout l'historique.
- `verify_chain()` démarre au point de contrôle, reparcourt la table dans
  l'ordre des `id` (curseur, pas `fetchall`), vérifie le lien `previous_hash`
  puis recalcule `entry_hash`. Il retourne `(False, id)` au premier événement
  invalide.
- Le journal est **résistant à l'altération**, pas « inviolable » : un
  attaquant qui contrôle toute la base peut recalculer la chaîne ou le point
  de contrôle. La protection contre la suppression totale relève de la
  sauvegarde externe.
- Les champs texte sont tronqués au premier caractère non imprimable et bornés
  (`peer` 64, `action` 160, `target`/`project` 256, `key_id` 64). Une route
  inconnue est journalisée `UNMATCHED`, jamais avec le chemin brut du client.
- `list_events` borne `limit` à `1..MAX_LIST_LIMIT` pour les deux backends :
  une limite négative ou nulle retombe sur 1, une limite > 1000 est plafonnée,
  donc un appel direct ne charge jamais tout l'historique mémoire.

## 3. STRIDE et contrat

| Menace / exigence | Traitement | Preuve |
|---|---|---|
| Repudiation (qui a lu quoi) | `key_id`, empreinte, projet, pair, action, cible, résultat | `heimdall/vault/audit.py:190`, `:679` ; tests d'audit |
| Information disclosure (secret dans le journal) | Aucun corps/en-tête lu, `key_fingerprint` tronquée, `key_id` public | `heimdall/vault/audit.py:98`, `:117`, `:679` ; test `test_audit_never_contains_a_secret_value_or_raw_key` |
| Tampering (altération du journal) | Chaînage SHA-256 + `verify_chain` + CLI `verify` | `heimdall/vault/audit.py:151`, `:571` ; tests de falsification |
| Denial of service (journal indisponible) | Fail-closed 503 générique, pas de fuite interne | `heimdall/vault/audit.py:625`, `:717` ; test `test_audit_failure_is_fail_closed` |
| Denial of service (croissance disque) | Rétention bornée + point de contrôle, purge testée | `heimdall/vault/audit.py:57`, `:422` ; tests de rétention |
| Log injection | Troncature au premier non-imprimable, longueurs bornées | `heimdall/vault/audit.py:98` ; test `test_audit_sanitizes_control_characters` |
| Denial of service (saturation du verrou par 429 répétés) | Résiduel **accepté et documenté** : fail-closed 503 tenu, table bornée ; coût mesuré localement (~1,6 ms par écriture à 100 000 lignes, un processus) | `heimdall/vault/audit.py:629`, `docs/contracts/vault-api.md:388` |
| Corrélation health / clé API | La clé fournie sur health n'est pas consommée mais son empreinte est mémoïsée pour l'audit ; un health anonyme reste sans empreinte | `heimdall/vault/app.py:1202`, `docs/contracts/vault-api.md:401` |
| Contrat openapi.yaml | Aucune route HTTP ajoutée : le journal est consulté par la CLI, pas exposé sur le réseau | `heimdall/cli/vault_keys.py:203`, `docs/contracts/vault-api.md:330` |

## 4. Résultats locaux

```sh
python -m pytest tests/test_vault_audit.py -q
# 27 passed
python -m pytest tests/test_vault_abuse_runtime.py -q
# 6 passed
ruff check heimdall tests scripts      # All checks passed!
mypy heimdall tests/contracts/fastapi_contract_fixture.py scripts/regen_lock.py
# Success: no issues found
```

La réussite de la CI Linux sur le SHA final et l'accord explicite du relecteur
sont requis avant fusion.
