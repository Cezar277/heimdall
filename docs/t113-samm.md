# T113 — preuves pour la ligne SAMM (journal d'audit)

Périmètre : sous-ticket **#113** du ticket parent `#39 « Auth durcie,
rate-limiting et audit log »`.

Révision du code testé : `ea8acece62245c77f2a9afb2618202fc505a7032`
(`feat(vault): durcit auth, rate-limiting et journal d'audit (#39)`).

## 1. Exigences du ticket et preuves

| Exigence vérifiée | Implémentation (module + ligne) | Test et preuve permanente | Résultat local |
|---|---|---|---|
| Table `audit_events` : date, identifiant de clé, IP, action, cible, résultat | [heimdall/vault/database.py:143–158](https://github.com/Cezar277/heimdall/blob/ea8acece62245c77f2a9afb2618202fc505a7032/heimdall/vault/database.py#L143-L158), [heimdall/vault/audit.py:56–72](https://github.com/Cezar277/heimdall/blob/ea8acece62245c77f2a9afb2618202fc505a7032/heimdall/vault/audit.py#L56-L72) | [tests/test_vault_audit.py:61–99](https://github.com/Cezar277/heimdall/blob/ea8acece62245c77f2a9afb2618202fc505a7032/tests/test_vault_audit.py#L61-L99) | Réussi |
| Un événement par accès, **401/403 inclus** | [heimdall/vault/audit.py:524–627](https://github.com/Cezar277/heimdall/blob/ea8acece62245c77f2a9afb2618202fc505a7032/heimdall/vault/audit.py#L524-L627), [heimdall/vault/app.py:1723](https://github.com/Cezar277/heimdall/blob/ea8acece62245c77f2a9afb2618202fc505a7032/heimdall/vault/app.py#L1723) | [tests/test_vault_audit.py:61–99](https://github.com/Cezar277/heimdall/blob/ea8acece62245c77f2a9afb2618202fc505a7032/tests/test_vault_audit.py#L61-L99) | Réussi |
| Les 429 de débit sont aussi journalisés | [heimdall/vault/audit.py:536–576](https://github.com/Cezar277/heimdall/blob/ea8acece62245c77f2a9afb2618202fc505a7032/heimdall/vault/audit.py#L536-L576) | [tests/test_vault_audit.py:101–126](https://github.com/Cezar277/heimdall/blob/ea8acece62245c77f2a9afb2618202fc505a7032/tests/test_vault_audit.py#L101-L126), [tests/security/test_vault_abuse_runtime.py:57–86](https://github.com/Cezar277/heimdall/blob/ea8acece62245c77f2a9afb2618202fc505a7032/tests/security/test_vault_abuse_runtime.py#L57-L86) | Réussi |
| Aucune valeur de secret, aucun corps de requête, aucune clé complète | [heimdall/vault/audit.py:86–124](https://github.com/Cezar277/heimdall/blob/ea8acece62245c77f2a9afb2618202fc505a7032/heimdall/vault/audit.py#L86-L124), [heimdall/vault/audit.py:578–614](https://github.com/Cezar277/heimdall/blob/ea8acece62245c77f2a9afb2618202fc505a7032/heimdall/vault/audit.py#L578-L614) | [tests/test_vault_audit.py:128–154](https://github.com/Cezar277/heimdall/blob/ea8acece62245c77f2a9afb2618202fc505a7032/tests/test_vault_audit.py#L128-L154) | Réussi |
| Identifiant de clé (`key_id`) et empreinte tronquée, jamais la clé | [heimdall/vault/auth.py:638–655](https://github.com/Cezar277/heimdall/blob/ea8acece62245c77f2a9afb2618202fc505a7032/heimdall/vault/auth.py#L638-L655), [heimdall/vault/audit.py:105–124](https://github.com/Cezar277/heimdall/blob/ea8acece62245c77f2a9afb2618202fc505a7032/heimdall/vault/audit.py#L105-L124) | [tests/test_vault_audit.py:61–99](https://github.com/Cezar277/heimdall/blob/ea8acece62245c77f2a9afb2618202fc505a7032/tests/test_vault_audit.py#L61-L99) | Réussi |
| Chaînage par hash et détection d'altération | [heimdall/vault/audit.py:133–165](https://github.com/Cezar277/heimdall/blob/ea8acece62245c77f2a9afb2618202fc505a7032/heimdall/vault/audit.py#L133-L165), [heimdall/vault/audit.py:484–509](https://github.com/Cezar277/heimdall/blob/ea8acece62245c77f2a9afb2618202fc505a7032/heimdall/vault/audit.py#L484-L509) | [tests/test_vault_audit.py:156–167](https://github.com/Cezar277/heimdall/blob/ea8acece62245c77f2a9afb2618202fc505a7032/tests/test_vault_audit.py#L156-L167), [tests/test_vault_audit.py:301–309](https://github.com/Cezar277/heimdall/blob/ea8acece62245c77f2a9afb2618202fc505a7032/tests/test_vault_audit.py#L301-L309) | Réussi |
| Journal consultable et testé (CLI `list` / `verify`) | [heimdall/cli/vault_keys.py:203–290](https://github.com/Cezar277/heimdall/blob/ea8acece62245c77f2a9afb2618202fc505a7032/heimdall/cli/vault_keys.py#L203-L290) | [tests/test_vault_audit.py:265–329](https://github.com/Cezar277/heimdall/blob/ea8acece62245c77f2a9afb2618202fc505a7032/tests/test_vault_audit.py#L265-L329) | Réussi |
| Fail-closed si l'audit échoue | [heimdall/vault/audit.py:536–576](https://github.com/Cezar277/heimdall/blob/ea8acece62245c77f2a9afb2618202fc505a7032/heimdall/vault/audit.py#L536-L576), [heimdall/vault/audit.py:616–627](https://github.com/Cezar277/heimdall/blob/ea8acece62245c77f2a9afb2618202fc505a7032/heimdall/vault/audit.py#L616-L627) | [tests/test_vault_audit.py:169–186](https://github.com/Cezar277/heimdall/blob/ea8acece62245c77f2a9afb2618202fc505a7032/tests/test_vault_audit.py#L169-L186) | Réussi |
| Backend SQLite partagé entre workers | [heimdall/vault/audit.py:345–521](https://github.com/Cezar277/heimdall/blob/ea8acece62245c77f2a9afb2618202fc505a7032/heimdall/vault/audit.py#L345-L521) | [tests/test_vault_audit.py:188–199](https://github.com/Cezar277/heimdall/blob/ea8acece62245c77f2a9afb2618202fc505a7032/tests/test_vault_audit.py#L188-L199) | Réussi |

## 2. Format et chaînage

Chaque événement contient `occurred_at`, `key_id`, `key_fingerprint`,
`project`, `peer`, `action`, `target`, `status_code`, `outcome`,
`previous_hash` et `entry_hash`.

- `entry_hash = SHA-256(charge canonique JSON)` ; `previous_hash` référence
  l'événement précédent (`GENESIS` pour le premier).
- `verify_chain()` reparcourt la table dans l'ordre des `id`, vérifie le lien
  `previous_hash` puis recalcule `entry_hash`. Il retourne
  `(False, id)` au premier événement invalide.
- Le journal est **résistant à l'altération**, pas « inviolable » : un
  attaquant qui contrôle toute la base peut recalculer la chaîne. La
  protection contre la suppression totale relève de la sauvegarde externe.
- Les champs texte sont tronqués au premier caractère non imprimable et bornés
  (`peer` 64, `action` 160, `target`/`project` 256, `key_id` 64). Une route
  inconnue est journalisée `UNMATCHED`, jamais avec le chemin brut du client.

## 3. STRIDE et contrat

| Menace / exigence | Traitement | Preuve |
|---|---|---|
| Repudiation (qui a lu quoi) | `key_id`, empreinte, projet, pair, action, cible, résultat | `heimdall/vault/audit.py:178`, `:578` ; tests d'audit |
| Information disclosure (secret dans le journal) | Aucun corps/en-tête lu, `key_fingerprint` tronquée, `key_id` public | `heimdall/vault/audit.py:86`, `:105`, `:578` ; test `test_audit_never_contains_a_secret_value_or_raw_key` |
| Tampering (altération du journal) | Chaînage SHA-256 + `verify_chain` + CLI `verify` | `heimdall/vault/audit.py:133`, `:484` ; tests de falsification |
| Denial of service (journal indisponible) | Fail-closed 503 générique, pas de fuite interne | `heimdall/vault/audit.py:536`, `:616` ; test `test_audit_failure_is_fail_closed` |
| Log injection | Troncature au premier non-imprimable, longueurs bornées | `heimdall/vault/audit.py:86` ; test `test_audit_sanitizes_control_characters` |
| Contrat openapi.yaml | Aucune route HTTP ajoutée : le journal est consulté par la CLI, pas exposé sur le réseau | `heimdall/cli/vault_keys.py:203`, `docs/contracts/vault-api.md:285` |

## 4. Résultats locaux

```sh
python -m pytest tests/test_vault_audit.py -q
# 14 passed
python -m pytest tests/security/test_vault_abuse_runtime.py -q
# 6 passed
ruff check heimdall tests scripts      # All checks passed!
mypy heimdall tests/contracts/fastapi_contract_fixture.py scripts/regen_lock.py
# Success: no issues found
```

La réussite de la CI Linux sur le SHA final et l'accord explicite du relecteur
sont requis avant fusion.
