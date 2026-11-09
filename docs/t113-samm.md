# T113 — preuves pour la ligne SAMM (journal d'audit)

Périmètre : sous-ticket **#113** du ticket parent `#39 « Auth durcie,
rate-limiting et audit log »`.

Révision du code testé : `a686d037c2be1474d0c3dca2ebacfe04e42e525d`
(`test(vault): borne le flot de rejets authentifies dans rate_limit_hits (#39)`).

## 1. Exigences du ticket et preuves

| Exigence vérifiée | Implémentation (module + ligne) | Test et preuve permanente | Résultat local |
|---|---|---|---|
| Table `audit_events` : date, identifiant de clé, IP, action, cible, résultat | [heimdall/vault/database.py:187–212](https://github.com/Cezar277/heimdall/blob/a686d037c2be1474d0c3dca2ebacfe04e42e525d/heimdall/vault/database.py#L187-L212), [heimdall/vault/audit.py:63–76](https://github.com/Cezar277/heimdall/blob/a686d037c2be1474d0c3dca2ebacfe04e42e525d/heimdall/vault/audit.py#L63-L76) | [tests/test_vault_audit.py:99–137](https://github.com/Cezar277/heimdall/blob/a686d037c2be1474d0c3dca2ebacfe04e42e525d/tests/test_vault_audit.py#L99-L137) | Réussi |
| Health avec clé : empreinte corrélée, budget clé non consommé | [heimdall/vault/app.py:1202–1206](https://github.com/Cezar277/heimdall/blob/a686d037c2be1474d0c3dca2ebacfe04e42e525d/heimdall/vault/app.py#L1202-L1206) | [tests/test_vault_audit.py:139–162](https://github.com/Cezar277/heimdall/blob/a686d037c2be1474d0c3dca2ebacfe04e42e525d/tests/test_vault_audit.py#L139-L162) | Réussi |
| Un événement par accès, **401/403 inclus** | [heimdall/vault/audit.py:641–768](https://github.com/Cezar277/heimdall/blob/a686d037c2be1474d0c3dca2ebacfe04e42e525d/heimdall/vault/audit.py#L641-L768), [heimdall/vault/app.py:1833](https://github.com/Cezar277/heimdall/blob/a686d037c2be1474d0c3dca2ebacfe04e42e525d/heimdall/vault/app.py#L1833) | [tests/test_vault_audit.py:99–137](https://github.com/Cezar277/heimdall/blob/a686d037c2be1474d0c3dca2ebacfe04e42e525d/tests/test_vault_audit.py#L99-L137) | Réussi |
| Cible d'audit renseignée sur la liste (200, 401 et 403 cross-projet) | [heimdall/vault/app.py:1444–1452](https://github.com/Cezar277/heimdall/blob/a686d037c2be1474d0c3dca2ebacfe04e42e525d/heimdall/vault/app.py#L1444-L1452), [heimdall/vault/audit.py:706–754](https://github.com/Cezar277/heimdall/blob/a686d037c2be1474d0c3dca2ebacfe04e42e525d/heimdall/vault/audit.py#L706-L754) | [tests/test_vault_audit.py:62–97](https://github.com/Cezar277/heimdall/blob/a686d037c2be1474d0c3dca2ebacfe04e42e525d/tests/test_vault_audit.py#L62-L97) | Réussi |
| Les 429 de débit sont aussi journalisés | [heimdall/vault/audit.py:653–704](https://github.com/Cezar277/heimdall/blob/a686d037c2be1474d0c3dca2ebacfe04e42e525d/heimdall/vault/audit.py#L653-L704) | [tests/test_vault_audit.py:164–189](https://github.com/Cezar277/heimdall/blob/a686d037c2be1474d0c3dca2ebacfe04e42e525d/tests/test_vault_audit.py#L164-L189), [tests/test_vault_abuse_runtime.py:57–86](https://github.com/Cezar277/heimdall/blob/a686d037c2be1474d0c3dca2ebacfe04e42e525d/tests/test_vault_abuse_runtime.py#L57-L86) | Réussi |
| Aucune valeur de secret, aucun corps de requête, aucune clé complète | [heimdall/vault/audit.py:102–137](https://github.com/Cezar277/heimdall/blob/a686d037c2be1474d0c3dca2ebacfe04e42e525d/heimdall/vault/audit.py#L102-L137), [heimdall/vault/audit.py:706–754](https://github.com/Cezar277/heimdall/blob/a686d037c2be1474d0c3dca2ebacfe04e42e525d/heimdall/vault/audit.py#L706-L754) | [tests/test_vault_audit.py:191–217](https://github.com/Cezar277/heimdall/blob/a686d037c2be1474d0c3dca2ebacfe04e42e525d/tests/test_vault_audit.py#L191-L217) | Réussi |
| Identifiant de clé (`key_id`) et empreinte tronquée, jamais la clé | [heimdall/vault/auth.py:645–662](https://github.com/Cezar277/heimdall/blob/a686d037c2be1474d0c3dca2ebacfe04e42e525d/heimdall/vault/auth.py#L645-L662), [heimdall/vault/audit.py:121–137](https://github.com/Cezar277/heimdall/blob/a686d037c2be1474d0c3dca2ebacfe04e42e525d/heimdall/vault/audit.py#L121-L137) | [tests/test_vault_audit.py:99–137](https://github.com/Cezar277/heimdall/blob/a686d037c2be1474d0c3dca2ebacfe04e42e525d/tests/test_vault_audit.py#L99-L137) | Réussi |
| Chaînage par hash et détection d'altération | [heimdall/vault/audit.py:155–185](https://github.com/Cezar277/heimdall/blob/a686d037c2be1474d0c3dca2ebacfe04e42e525d/heimdall/vault/audit.py#L155-L185), [heimdall/vault/audit.py:594–618](https://github.com/Cezar277/heimdall/blob/a686d037c2be1474d0c3dca2ebacfe04e42e525d/heimdall/vault/audit.py#L594-L618) | [tests/test_vault_audit.py:219–230](https://github.com/Cezar277/heimdall/blob/a686d037c2be1474d0c3dca2ebacfe04e42e525d/tests/test_vault_audit.py#L219-L230), [tests/test_vault_audit.py:579–587](https://github.com/Cezar277/heimdall/blob/a686d037c2be1474d0c3dca2ebacfe04e42e525d/tests/test_vault_audit.py#L579-L587) | Réussi |
| Journal consultable et testé (CLI `list` / `verify`) | [heimdall/cli/vault_keys.py:233–320](https://github.com/Cezar277/heimdall/blob/a686d037c2be1474d0c3dca2ebacfe04e42e525d/heimdall/cli/vault_keys.py#L233-L320) | [tests/test_vault_audit.py:543–636](https://github.com/Cezar277/heimdall/blob/a686d037c2be1474d0c3dca2ebacfe04e42e525d/tests/test_vault_audit.py#L543-L636) | Réussi |
| Fail-closed si l'audit échoue | [heimdall/vault/audit.py:653–704](https://github.com/Cezar277/heimdall/blob/a686d037c2be1474d0c3dca2ebacfe04e42e525d/heimdall/vault/audit.py#L653-L704), [heimdall/vault/audit.py:757–768](https://github.com/Cezar277/heimdall/blob/a686d037c2be1474d0c3dca2ebacfe04e42e525d/heimdall/vault/audit.py#L757-L768) | [tests/test_vault_audit.py:232–249](https://github.com/Cezar277/heimdall/blob/a686d037c2be1474d0c3dca2ebacfe04e42e525d/tests/test_vault_audit.py#L232-L249) | Réussi |
| Backend SQLite partagé entre workers | [heimdall/vault/audit.py:387–638](https://github.com/Cezar277/heimdall/blob/a686d037c2be1474d0c3dca2ebacfe04e42e525d/heimdall/vault/audit.py#L387-L638) | [tests/test_vault_audit.py:286–297](https://github.com/Cezar277/heimdall/blob/a686d037c2be1474d0c3dca2ebacfe04e42e525d/tests/test_vault_audit.py#L286-L297) | Réussi |
| **Bornage du listage** : mémoire et SQLite partagent `max(1, min(MAX_LIST_LIMIT, int(limit)))` | [heimdall/vault/audit.py:337–348](https://github.com/Cezar277/heimdall/blob/a686d037c2be1474d0c3dca2ebacfe04e42e525d/heimdall/vault/audit.py#L337-L348), [heimdall/vault/audit.py:570–592](https://github.com/Cezar277/heimdall/blob/a686d037c2be1474d0c3dca2ebacfe04e42e525d/heimdall/vault/audit.py#L570-L592) | [tests/test_vault_audit.py:335–376](https://github.com/Cezar277/heimdall/blob/a686d037c2be1474d0c3dca2ebacfe04e42e525d/tests/test_vault_audit.py#L335-L376) | Réussi |
| **Rétention bornée** : purge des plus anciens et point de contrôle de chaîne | [heimdall/vault/audit.py:58](https://github.com/Cezar277/heimdall/blob/a686d037c2be1474d0c3dca2ebacfe04e42e525d/heimdall/vault/audit.py#L58), [heimdall/vault/audit.py:419–453](https://github.com/Cezar277/heimdall/blob/a686d037c2be1474d0c3dca2ebacfe04e42e525d/heimdall/vault/audit.py#L419-L453), [heimdall/vault/database.py:204–212](https://github.com/Cezar277/heimdall/blob/a686d037c2be1474d0c3dca2ebacfe04e42e525d/heimdall/vault/database.py#L204-L212) | [tests/test_vault_audit.py:380–395](https://github.com/Cezar277/heimdall/blob/a686d037c2be1474d0c3dca2ebacfe04e42e525d/tests/test_vault_audit.py#L380-L395) | Réussi |
| Purge SQLite par lots : un excès massif ne tient pas le verrou d'écriture | [heimdall/vault/audit.py:419–466](https://github.com/Cezar277/heimdall/blob/a686d037c2be1474d0c3dca2ebacfe04e42e525d/heimdall/vault/audit.py#L419-L466) | [tests/test_vault_audit.py:438–461](https://github.com/Cezar277/heimdall/blob/a686d037c2be1474d0c3dca2ebacfe04e42e525d/tests/test_vault_audit.py#L438-L461) | Réussi |
| Panne SQLite du journal ou du débit → **503**, jamais 500 | [heimdall/vault/audit.py:653–704](https://github.com/Cezar277/heimdall/blob/a686d037c2be1474d0c3dca2ebacfe04e42e525d/heimdall/vault/audit.py#L653-L704), [heimdall/vault/audit.py:757–768](https://github.com/Cezar277/heimdall/blob/a686d037c2be1474d0c3dca2ebacfe04e42e525d/heimdall/vault/audit.py#L757-L768) | [tests/test_vault_audit.py:251–284](https://github.com/Cezar277/heimdall/blob/a686d037c2be1474d0c3dca2ebacfe04e42e525d/tests/test_vault_audit.py#L251-L284), [tests/test_vault_availability.py](https://github.com/Cezar277/heimdall/blob/a686d037c2be1474d0c3dca2ebacfe04e42e525d/tests/test_vault_availability.py) | Réussi |
| Migration d'une base antérieure à #39 : `init_db` recrée les tables | [heimdall/vault/database.py:187–212](https://github.com/Cezar277/heimdall/blob/a686d037c2be1474d0c3dca2ebacfe04e42e525d/heimdall/vault/database.py#L187-L212), [heimdall/vault/database.py:827–835](https://github.com/Cezar277/heimdall/blob/a686d037c2be1474d0c3dca2ebacfe04e42e525d/heimdall/vault/database.py#L827-L835) | [tests/test_vault_audit.py:494–513](https://github.com/Cezar277/heimdall/blob/a686d037c2be1474d0c3dca2ebacfe04e42e525d/tests/test_vault_audit.py#L494-L513) | Réussi |
| Ids d'audit uniques et monotones après purge (mémoire) | [heimdall/vault/audit.py:270](https://github.com/Cezar277/heimdall/blob/a686d037c2be1474d0c3dca2ebacfe04e42e525d/heimdall/vault/audit.py#L270), [heimdall/vault/audit.py:319](https://github.com/Cezar277/heimdall/blob/a686d037c2be1474d0c3dca2ebacfe04e42e525d/heimdall/vault/audit.py#L319), [heimdall/vault/audit.py:332](https://github.com/Cezar277/heimdall/blob/a686d037c2be1474d0c3dca2ebacfe04e42e525d/heimdall/vault/audit.py#L332) | [tests/test_vault_audit.py:397–410](https://github.com/Cezar277/heimdall/blob/a686d037c2be1474d0c3dca2ebacfe04e42e525d/tests/test_vault_audit.py#L397-L410) | Réussi |
| Concurrence SQLite : requêtes parallèles sans 500, 503 générique + `Retry-After: 1` seulement | [heimdall/vault/audit.py:468–488](https://github.com/Cezar277/heimdall/blob/a686d037c2be1474d0c3dca2ebacfe04e42e525d/heimdall/vault/audit.py#L468-L488) | [tests/test_vault_availability.py:206–235](https://github.com/Cezar277/heimdall/blob/a686d037c2be1474d0c3dca2ebacfe04e42e525d/tests/test_vault_availability.py#L206-L235), [tests/test_vault_availability.py:311–336](https://github.com/Cezar277/heimdall/blob/a686d037c2be1474d0c3dca2ebacfe04e42e525d/tests/test_vault_availability.py#L311-L336) | Réussi |
| Chemin prod authentifié (limiteur SQLite réel + audit SQLite, clé valide) : aucun 500, 503 générique seul | [heimdall/vault/ratelimit.py:261–443](https://github.com/Cezar277/heimdall/blob/a686d037c2be1474d0c3dca2ebacfe04e42e525d/heimdall/vault/ratelimit.py#L261-L443), [heimdall/vault/audit.py:468–488](https://github.com/Cezar277/heimdall/blob/a686d037c2be1474d0c3dca2ebacfe04e42e525d/heimdall/vault/audit.py#L468-L488) | [tests/test_vault_availability.py:236–274](https://github.com/Cezar277/heimdall/blob/a686d037c2be1474d0c3dca2ebacfe04e42e525d/tests/test_vault_availability.py#L236-L274), [tests/test_vault_availability.py:275–310](https://github.com/Cezar277/heimdall/blob/a686d037c2be1474d0c3dca2ebacfe04e42e525d/tests/test_vault_availability.py#L275-L310) | Réussi |
| Verrou pair tenu par un écrivain externe : 503 générique à toutes les requêtes concurrentes | [heimdall/vault/audit.py:653–704](https://github.com/Cezar277/heimdall/blob/a686d037c2be1474d0c3dca2ebacfe04e42e525d/heimdall/vault/audit.py#L653-L704) | [tests/test_vault_availability.py:311–336](https://github.com/Cezar277/heimdall/blob/a686d037c2be1474d0c3dca2ebacfe04e42e525d/tests/test_vault_availability.py#L311-L336) | Réussi |
| `verify` CLI sur base absente ou corrompue : sortie 1 générique, base non créée, sans fuite | [heimdall/cli/vault_keys.py:291–320](https://github.com/Cezar277/heimdall/blob/a686d037c2be1474d0c3dca2ebacfe04e42e525d/heimdall/cli/vault_keys.py#L291-L320) | [tests/test_vault_audit.py:589–621](https://github.com/Cezar277/heimdall/blob/a686d037c2be1474d0c3dca2ebacfe04e42e525d/tests/test_vault_audit.py#L589-L621) | Réussi |
| Rétention SQLite : altération du premier événement retenu localisée via le point de contrôle | [heimdall/vault/audit.py:419–453](https://github.com/Cezar277/heimdall/blob/a686d037c2be1474d0c3dca2ebacfe04e42e525d/heimdall/vault/audit.py#L419-L453) | [tests/test_vault_audit.py:412–436](https://github.com/Cezar277/heimdall/blob/a686d037c2be1474d0c3dca2ebacfe04e42e525d/tests/test_vault_audit.py#L412-L436), [tests/test_vault_audit.py:463–492](https://github.com/Cezar277/heimdall/blob/a686d037c2be1474d0c3dca2ebacfe04e42e525d/tests/test_vault_audit.py#L463-L492) | Réussi |

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
| Repudiation (qui a lu quoi) | `key_id`, empreinte, projet, pair, action, cible, résultat | `heimdall/vault/audit.py:194`, `:706` ; tests d'audit |
| Information disclosure (secret dans le journal) | Aucun corps/en-tête lu, `key_fingerprint` tronquée, `key_id` public | `heimdall/vault/audit.py:102`, `:121`, `:706` ; test `test_audit_never_contains_a_secret_value_or_raw_key` |
| Tampering (altération du journal) | Chaînage SHA-256 + `verify_chain` + CLI `verify` | `heimdall/vault/audit.py:155`, `:594` ; tests de falsification |
| Denial of service (journal indisponible) | Fail-closed 503 générique, pas de fuite interne | `heimdall/vault/audit.py:649`, `:757` ; test `test_audit_failure_is_fail_closed` |
| Denial of service (croissance disque) | Rétention bornée + point de contrôle, purge testée | `heimdall/vault/audit.py:58`, `:419` ; tests de rétention |
| Log injection | Troncature au premier non-imprimable, longueurs bornées | `heimdall/vault/audit.py:102` ; test `test_audit_sanitizes_control_characters` |
| Denial of service (saturation du verrou par 429 répétés) | Résiduel **accepté et documenté** : fail-closed 503 tenu, table bornée ; coût mesuré localement (~1,6 ms par écriture à 100 000 lignes, un processus) | `heimdall/vault/audit.py:653`, `docs/contracts/vault-api.md:388` |
| Corrélation health / clé API | La clé fournie sur health n'est pas consommée mais son empreinte est mémoïsée pour l'audit ; un health anonyme reste sans empreinte | `heimdall/vault/app.py:1202`, `docs/contracts/vault-api.md:401` |
| Contrat openapi.yaml | Aucune route HTTP ajoutée : le journal est consulté par la CLI, pas exposé sur le réseau | `heimdall/cli/vault_keys.py:203`, `docs/contracts/vault-api.md:330` |

## 4. Résultats locaux

```sh
python -m pytest tests/test_vault_audit.py -q
# 28 passed
python -m pytest tests/test_vault_abuse_runtime.py -q
# 6 passed
ruff check heimdall tests scripts      # All checks passed!
mypy heimdall tests/contracts/fastapi_contract_fixture.py scripts/regen_lock.py
# Success: no issues found
```

La réussite de la CI Linux sur le SHA final et l'accord explicite du relecteur
sont requis avant fusion.
