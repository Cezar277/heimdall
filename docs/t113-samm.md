# T113 — preuves pour la ligne SAMM (journal d'audit)

Périmètre : sous-ticket **#113** du ticket parent `#39 « Auth durcie,
rate-limiting et audit log »`.

Révision du code testé : `bdaf21767366e93a74a677cb25c21458cb0b67d5`
(`fix(vault): purge les admissions expirees sur tout chemin de rejet (#39)`).

## 1. Exigences du ticket et preuves

| Exigence vérifiée | Implémentation (module + ligne) | Test et preuve permanente | Résultat local |
|---|---|---|---|
| Table `audit_events` : date, identifiant de clé, IP, action, cible, résultat | [heimdall/vault/database.py:187–212](https://github.com/Cezar277/heimdall/blob/bdaf21767366e93a74a677cb25c21458cb0b67d5/heimdall/vault/database.py#L187-L212), [heimdall/vault/audit.py:60–73](https://github.com/Cezar277/heimdall/blob/bdaf21767366e93a74a677cb25c21458cb0b67d5/heimdall/vault/audit.py#L60-L73) | [tests/test_vault_audit.py:62–100](https://github.com/Cezar277/heimdall/blob/bdaf21767366e93a74a677cb25c21458cb0b67d5/tests/test_vault_audit.py#L62-L100) | Réussi |
| Un événement par accès, **401/403 inclus** | [heimdall/vault/audit.py:616–730](https://github.com/Cezar277/heimdall/blob/bdaf21767366e93a74a677cb25c21458cb0b67d5/heimdall/vault/audit.py#L616-L730), [heimdall/vault/app.py:1824](https://github.com/Cezar277/heimdall/blob/bdaf21767366e93a74a677cb25c21458cb0b67d5/heimdall/vault/app.py#L1824) | [tests/test_vault_audit.py:62–100](https://github.com/Cezar277/heimdall/blob/bdaf21767366e93a74a677cb25c21458cb0b67d5/tests/test_vault_audit.py#L62-L100) | Réussi |
| Les 429 de débit sont aussi journalisés | [heimdall/vault/audit.py:628–679](https://github.com/Cezar277/heimdall/blob/bdaf21767366e93a74a677cb25c21458cb0b67d5/heimdall/vault/audit.py#L628-L679) | [tests/test_vault_audit.py:102–127](https://github.com/Cezar277/heimdall/blob/bdaf21767366e93a74a677cb25c21458cb0b67d5/tests/test_vault_audit.py#L102-L127), [tests/test_vault_abuse_runtime.py:57–86](https://github.com/Cezar277/heimdall/blob/bdaf21767366e93a74a677cb25c21458cb0b67d5/tests/test_vault_abuse_runtime.py#L57-L86) | Réussi |
| Aucune valeur de secret, aucun corps de requête, aucune clé complète | [heimdall/vault/audit.py:98–133](https://github.com/Cezar277/heimdall/blob/bdaf21767366e93a74a677cb25c21458cb0b67d5/heimdall/vault/audit.py#L98-L133), [heimdall/vault/audit.py:681–717](https://github.com/Cezar277/heimdall/blob/bdaf21767366e93a74a677cb25c21458cb0b67d5/heimdall/vault/audit.py#L681-L717) | [tests/test_vault_audit.py:129–155](https://github.com/Cezar277/heimdall/blob/bdaf21767366e93a74a677cb25c21458cb0b67d5/tests/test_vault_audit.py#L129-L155) | Réussi |
| Identifiant de clé (`key_id`) et empreinte tronquée, jamais la clé | [heimdall/vault/auth.py:645–662](https://github.com/Cezar277/heimdall/blob/bdaf21767366e93a74a677cb25c21458cb0b67d5/heimdall/vault/auth.py#L645-L662), [heimdall/vault/audit.py:117–133](https://github.com/Cezar277/heimdall/blob/bdaf21767366e93a74a677cb25c21458cb0b67d5/heimdall/vault/audit.py#L117-L133) | [tests/test_vault_audit.py:62–100](https://github.com/Cezar277/heimdall/blob/bdaf21767366e93a74a677cb25c21458cb0b67d5/tests/test_vault_audit.py#L62-L100) | Réussi |
| Chaînage par hash et détection d'altération | [heimdall/vault/audit.py:151–181](https://github.com/Cezar277/heimdall/blob/bdaf21767366e93a74a677cb25c21458cb0b67d5/heimdall/vault/audit.py#L151-L181), [heimdall/vault/audit.py:569–593](https://github.com/Cezar277/heimdall/blob/bdaf21767366e93a74a677cb25c21458cb0b67d5/heimdall/vault/audit.py#L569-L593) | [tests/test_vault_audit.py:157–168](https://github.com/Cezar277/heimdall/blob/bdaf21767366e93a74a677cb25c21458cb0b67d5/tests/test_vault_audit.py#L157-L168), [tests/test_vault_audit.py:449–457](https://github.com/Cezar277/heimdall/blob/bdaf21767366e93a74a677cb25c21458cb0b67d5/tests/test_vault_audit.py#L449-L457) | Réussi |
| Journal consultable et testé (CLI `list` / `verify`) | [heimdall/cli/vault_keys.py:233–320](https://github.com/Cezar277/heimdall/blob/bdaf21767366e93a74a677cb25c21458cb0b67d5/heimdall/cli/vault_keys.py#L233-L320) | [tests/test_vault_audit.py:413–501](https://github.com/Cezar277/heimdall/blob/bdaf21767366e93a74a677cb25c21458cb0b67d5/tests/test_vault_audit.py#L413-L501) | Réussi |
| Fail-closed si l'audit échoue | [heimdall/vault/audit.py:628–679](https://github.com/Cezar277/heimdall/blob/bdaf21767366e93a74a677cb25c21458cb0b67d5/heimdall/vault/audit.py#L628-L679), [heimdall/vault/audit.py:719–730](https://github.com/Cezar277/heimdall/blob/bdaf21767366e93a74a677cb25c21458cb0b67d5/heimdall/vault/audit.py#L719-L730) | [tests/test_vault_audit.py:170–187](https://github.com/Cezar277/heimdall/blob/bdaf21767366e93a74a677cb25c21458cb0b67d5/tests/test_vault_audit.py#L170-L187) | Réussi |
| Backend SQLite partagé entre workers | [heimdall/vault/audit.py:382–614](https://github.com/Cezar277/heimdall/blob/bdaf21767366e93a74a677cb25c21458cb0b67d5/heimdall/vault/audit.py#L382-L614) | [tests/test_vault_audit.py:224–235](https://github.com/Cezar277/heimdall/blob/bdaf21767366e93a74a677cb25c21458cb0b67d5/tests/test_vault_audit.py#L224-L235) | Réussi |
| **Rétention bornée** : purge des plus anciens et point de contrôle de chaîne | [heimdall/vault/audit.py:57](https://github.com/Cezar277/heimdall/blob/bdaf21767366e93a74a677cb25c21458cb0b67d5/heimdall/vault/audit.py#L57), [heimdall/vault/audit.py:404–446](https://github.com/Cezar277/heimdall/blob/bdaf21767366e93a74a677cb25c21458cb0b67d5/heimdall/vault/audit.py#L404-L446), [heimdall/vault/database.py:204–212](https://github.com/Cezar277/heimdall/blob/bdaf21767366e93a74a677cb25c21458cb0b67d5/heimdall/vault/database.py#L204-L212) | [tests/test_vault_audit.py:275–331](https://github.com/Cezar277/heimdall/blob/bdaf21767366e93a74a677cb25c21458cb0b67d5/tests/test_vault_audit.py#L275-L331) | Réussi |
| Panne SQLite du journal ou du débit → **503**, jamais 500 | [heimdall/vault/audit.py:628–679](https://github.com/Cezar277/heimdall/blob/bdaf21767366e93a74a677cb25c21458cb0b67d5/heimdall/vault/audit.py#L628-L679), [heimdall/vault/audit.py:719–730](https://github.com/Cezar277/heimdall/blob/bdaf21767366e93a74a677cb25c21458cb0b67d5/heimdall/vault/audit.py#L719-L730) | [tests/test_vault_audit.py:189–222](https://github.com/Cezar277/heimdall/blob/bdaf21767366e93a74a677cb25c21458cb0b67d5/tests/test_vault_audit.py#L189-L222), [tests/test_vault_availability.py](https://github.com/Cezar277/heimdall/blob/bdaf21767366e93a74a677cb25c21458cb0b67d5/tests/test_vault_availability.py) | Réussi |
| Migration d'une base antérieure à #39 : `init_db` recrée les tables | [heimdall/vault/database.py:187–212](https://github.com/Cezar277/heimdall/blob/bdaf21767366e93a74a677cb25c21458cb0b67d5/heimdall/vault/database.py#L187-L212), [heimdall/vault/database.py:827–835](https://github.com/Cezar277/heimdall/blob/bdaf21767366e93a74a677cb25c21458cb0b67d5/heimdall/vault/database.py#L827-L835) | [tests/test_vault_audit.py:364–383](https://github.com/Cezar277/heimdall/blob/bdaf21767366e93a74a677cb25c21458cb0b67d5/tests/test_vault_audit.py#L364-L383) | Réussi |
| Ids d'audit uniques et monotones après purge (mémoire) | [heimdall/vault/audit.py:266](https://github.com/Cezar277/heimdall/blob/bdaf21767366e93a74a677cb25c21458cb0b67d5/heimdall/vault/audit.py#L266), [heimdall/vault/audit.py:315](https://github.com/Cezar277/heimdall/blob/bdaf21767366e93a74a677cb25c21458cb0b67d5/heimdall/vault/audit.py#L315), [heimdall/vault/audit.py:328](https://github.com/Cezar277/heimdall/blob/bdaf21767366e93a74a677cb25c21458cb0b67d5/heimdall/vault/audit.py#L328) | [tests/test_vault_audit.py:292–306](https://github.com/Cezar277/heimdall/blob/bdaf21767366e93a74a677cb25c21458cb0b67d5/tests/test_vault_audit.py#L292-L306) | Réussi |
| Concurrence SQLite : requêtes parallèles sans 500, 503 générique + `Retry-After: 1` seulement | [heimdall/vault/audit.py:448–469](https://github.com/Cezar277/heimdall/blob/bdaf21767366e93a74a677cb25c21458cb0b67d5/heimdall/vault/audit.py#L448-L469) | [tests/test_vault_availability.py:206–235](https://github.com/Cezar277/heimdall/blob/bdaf21767366e93a74a677cb25c21458cb0b67d5/tests/test_vault_availability.py#L206-L235), [tests/test_vault_availability.py:311–336](https://github.com/Cezar277/heimdall/blob/bdaf21767366e93a74a677cb25c21458cb0b67d5/tests/test_vault_availability.py#L311-L336) | Réussi |
| Chemin prod authentifié (limiteur SQLite réel + audit SQLite, clé valide) : aucun 500, 503 générique seul | [heimdall/vault/ratelimit.py:241–413](https://github.com/Cezar277/heimdall/blob/bdaf21767366e93a74a677cb25c21458cb0b67d5/heimdall/vault/ratelimit.py#L241-L413), [heimdall/vault/audit.py:448–469](https://github.com/Cezar277/heimdall/blob/bdaf21767366e93a74a677cb25c21458cb0b67d5/heimdall/vault/audit.py#L448-L469) | [tests/test_vault_availability.py:236–274](https://github.com/Cezar277/heimdall/blob/bdaf21767366e93a74a677cb25c21458cb0b67d5/tests/test_vault_availability.py#L236-L274), [tests/test_vault_availability.py:275–310](https://github.com/Cezar277/heimdall/blob/bdaf21767366e93a74a677cb25c21458cb0b67d5/tests/test_vault_availability.py#L275-L310) | Réussi |
| Verrou pair tenu par un écrivain externe : 503 générique à toutes les requêtes concurrentes | [heimdall/vault/audit.py:628–679](https://github.com/Cezar277/heimdall/blob/bdaf21767366e93a74a677cb25c21458cb0b67d5/heimdall/vault/audit.py#L628-L679) | [tests/test_vault_availability.py:311–336](https://github.com/Cezar277/heimdall/blob/bdaf21767366e93a74a677cb25c21458cb0b67d5/tests/test_vault_availability.py#L311-L336) | Réussi |
| `verify` CLI sur base absente ou corrompue : sortie 1 générique, base non créée, sans fuite | [heimdall/cli/vault_keys.py:291–320](https://github.com/Cezar277/heimdall/blob/bdaf21767366e93a74a677cb25c21458cb0b67d5/heimdall/cli/vault_keys.py#L291-L320) | [tests/test_vault_audit.py:469–491](https://github.com/Cezar277/heimdall/blob/bdaf21767366e93a74a677cb25c21458cb0b67d5/tests/test_vault_audit.py#L469-L491) | Réussi |
| Rétention SQLite : altération du premier événement retenu localisée via le point de contrôle | [heimdall/vault/audit.py:404–446](https://github.com/Cezar277/heimdall/blob/bdaf21767366e93a74a677cb25c21458cb0b67d5/heimdall/vault/audit.py#L404-L446) | [tests/test_vault_audit.py:333–362](https://github.com/Cezar277/heimdall/blob/bdaf21767366e93a74a677cb25c21458cb0b67d5/tests/test_vault_audit.py#L333-L362) | Réussi |

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

## 3. STRIDE et contrat

| Menace / exigence | Traitement | Preuve |
|---|---|---|
| Repudiation (qui a lu quoi) | `key_id`, empreinte, projet, pair, action, cible, résultat | `heimdall/vault/audit.py:190`, `:678` ; tests d'audit |
| Information disclosure (secret dans le journal) | Aucun corps/en-tête lu, `key_fingerprint` tronquée, `key_id` public | `heimdall/vault/audit.py:98`, `:117`, `:678` ; test `test_audit_never_contains_a_secret_value_or_raw_key` |
| Tampering (altération du journal) | Chaînage SHA-256 + `verify_chain` + CLI `verify` | `heimdall/vault/audit.py:151`, `:566` ; tests de falsification |
| Denial of service (journal indisponible) | Fail-closed 503 générique, pas de fuite interne | `heimdall/vault/audit.py:625`, `:716` ; test `test_audit_failure_is_fail_closed` |
| Denial of service (croissance disque) | Rétention bornée + point de contrôle, purge testée | `heimdall/vault/audit.py:57`, `:411` ; tests de rétention |
| Log injection | Troncature au premier non-imprimable, longueurs bornées | `heimdall/vault/audit.py:98` ; test `test_audit_sanitizes_control_characters` |
| Denial of service (saturation du verrou par 429 répétés) | Résiduel **accepté et documenté** : fail-closed 503 tenu, table bornée ; coût en charge non mesuré | `heimdall/vault/audit.py:628`, `docs/contracts/vault-api.md:327` |
| Corrélation health / clé API | Résiduel **documenté** : `/api/v1/health` ignore la clé, événement d'audit sans `key_id` ni empreinte | `heimdall/vault/app.py:1168`, `docs/contracts/vault-api.md:337` |
| Contrat openapi.yaml | Aucune route HTTP ajoutée : le journal est consulté par la CLI, pas exposé sur le réseau | `heimdall/cli/vault_keys.py:203`, `docs/contracts/vault-api.md:285` |

## 4. Résultats locaux

```sh
python -m pytest tests/test_vault_audit.py -q
# 23 passed
python -m pytest tests/test_vault_abuse_runtime.py -q
# 6 passed
ruff check heimdall tests scripts      # All checks passed!
mypy heimdall tests/contracts/fastapi_contract_fixture.py scripts/regen_lock.py
# Success: no issues found
```

La réussite de la CI Linux sur le SHA final et l'accord explicite du relecteur
sont requis avant fusion.
