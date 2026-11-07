# T265 — preuves pour la ligne SAMM (Chasse aux fuites de clés)

Sous-ticket **T26.5** (ticket GitHub **#72**) du grand ticket `#26 « Clé
maîtresse et chiffrement par enveloppe »`, branche
`72-t265-chasse-aux-fuites-de-cles`. Cette fiche fournit les couples
**module + ligne** et les tests qui prouvent qu'aucune clé (maîtresse, KEK,
pepper, clé API) ni valeur de secret ne fuit dans les logs, les exceptions ou
les `repr()`.

## 1. Exigences du ticket et preuves

> **Permaliens** : les liens ci-dessous sont épinglés à la révision du code
> [`13a58bb`](https://github.com/Cezar277/heimdall/commit/13a58bb662d301d543e1e7cbd02ac166f19623a1),
> qui contient le test de chasse et le `__repr__` expurgé du registre. Cette
> fiche est le commit suivant : elle ne modifie que de la documentation. Les
> permaliens épinglent la révision du code, pas le commit de documentation.

| Exigence du ticket | Implémentation (module + ligne) | Test et preuve permanente | Résultat local |
|---|---|---|---|
| **Vérifier les logs** : aucune clé maîtresse, KEK, pepper, clé API ou valeur de secret dans les logs | Logs `heimdall.vault.*` : `auth.py:583` (projet seulement), `auth.py:629` (key_id seulement), `database.py:1653` (compteur/versions seulement), `app.py:239` (avertissement sans valeur), `app.py:1538`/`app.py:1612` (backend et nom de fichier seulement) | `tests/test_vault_key_leak_hunt.py::VaultKeyLeakHuntTests::test_runtime_logs_do_not_contain_master_key_or_secret_values` (capture DEBUG autour de settings, app, CLI `vault key create` et rotation KEK, puis grep des canaris) ; garde statique `::test_static_logging_calls_do_not_reference_sensitive_names` ; garde existante `tests/test_vault_review_regressions.py::VaultSecretValueHygieneTests::test_secret_value_is_never_logged` | Réussi — aucun canari dans `caplog`/`assertLogs` |
| **Vérifier les exceptions** : pas d'écho de clé/valeur dans les messages | `VaultSettings` : `hide_input_in_errors=True` (`app.py:570`) + validateurs génériques (`app.py:595-650`) ; `VaultCipher` : erreurs génériques (`crypto.py:383-412`) ; handlers FastAPI génériques 400/500 (`app.py:1285-1338`) | `tests/test_vault_key_leak_hunt.py::VaultKeyLeakHuntTests::test_settings_validation_errors_do_not_echo_secret_inputs`, `::test_cipher_repr_and_errors_redact_keys`, `::test_client_repr_and_errors_redact_api_key`, `::test_runtime_logs_do_not_contain_master_key_or_secret_values` (réponses 400/401) | Réussi — messages génériques, aucune valeur réfléchie |
| **Vérifier les `repr()`** des objets porteurs de clés | `VaultCipher.__repr__` (`crypto.py:525-526`), `VaultClient.__repr__`/`__str__` (`client.py:854-858`), `IssuedApiKey.__repr__` (`auth.py:440-445`), `ApiKeyRegistry.__repr__` (`auth.py:491-496`), `VaultSettings` champs `repr=False, exclude=True` (`app.py:595-650`) | `tests/test_vault_key_leak_hunt.py::VaultKeyLeakHuntTests::test_settings_repr_and_serialization_redact_secrets`, `::test_cipher_repr_and_errors_redact_keys`, `::test_client_repr_and_errors_redact_api_key`, `::test_issued_key_and_registry_repr_redact_raw_key` ; tests existants `tests/test_vault_kek_derivation.py:521`, `:785`, `tests/test_vault_client.py:82`, `tests/test_vault_auth.py:69` | Réussi — `repr`, `model_dump` et `model_dump_json` expurgés |
| **Test qui grep les logs pour la clé maîtresse** | Canaris uniques `_MASTER_KEY`, `_PEPPER`, `_SECRET_VALUE` + clés générées à l'exécution | `tests/test_vault_key_leak_hunt.py::VaultKeyLeakHuntTests::test_runtime_logs_do_not_contain_master_key_or_secret_values` | Réussi — 0 occurrence dans les logs capturés |
| **Aucune clé dans les logs** (Fait quand) | Voir ci-dessus | `pytest tests/test_vault_key_leak_hunt.py -q` → **8 passed** | Réussi |

## 2. Scénarios couverts par le test runtime

Le test `test_runtime_logs_do_not_contain_master_key_or_secret_values` exécute,
sous `assertLogs("heimdall", level="DEBUG")` :

1. construction de `VaultSettings` avec clé maîtresse, sel Argon2id et pepper ;
2. `create_app` + `register_api_key` ;
3. création et lecture d'un secret via `TestClient` (200/201) ;
4. refus 401 avec une mauvaise clé API ;
5. refus 400 avec un corps invalide contenant le secret canari ;
6. `heimdall vault key create` (la clé brute est affichée sur **stdout**, jamais
   dans les logs) ;
7. rotation KEK (`rotate_secrets_kek`) sur la base, qui journalise uniquement
   le nombre de secrets et les versions.

À la sortie, le test vérifie l'absence de la clé maîtresse, du sel, du pepper,
de la valeur du secret, de la clé API, de la clé brute émise par la CLI et de
la KEK dans l'intégralité des enregistrements de logs.

## 3. Garde statique

`test_static_logging_calls_do_not_reference_sensitive_names` parse l'AST de
`heimdall/vault/*.py` et `heimdall/cli/vault_keys.py` et refuse tout appel de
log (`logger.*`, `log.*`, `logging.*`, `getLogger(...).*`), `print(...)` et
`raise ...` qui référence une variable sensible dans ses arguments **ou ses
keywords** (`extra=`, `exc_info=`, etc.), y compris via un **accès attribut**
(`registry._pepper`, `settings.master_key`, `cipher._key`, `cipher.key`) ou un
**subscript `model_dump()`** (`settings.model_dump()["master_key"]`). La
détection est conservatrice par sous-chaîne (`secret`, `plaintext`, `password`,
`private_key`, `master_key`, `master`, `api_key`, `raw_key`, `pepper`, `kek`,
`dek`, `salt`, `seed`, `token`, `value`, `key`), avec une allowlist pour les
métadonnées et constantes publiques (`kek_version`, `new_version`,
`current_max`, `key_id`, `key_hash`, `env_master`, `env_salt`, …) et les blobs
chiffrés (`encrypted_value`). Les noms de classes d'exception (`ValueError`,
`VaultCipherError`, …) et les constantes `UPPER_CASE` sont ignorés pour éviter
les faux positifs. `encrypted_dek` reste marqué sensible par défense en
profondeur. Un test négatif
(`test_static_logging_guard_detects_known_violations`) prouve que la garde
détecte les douze formes testées : argument direct, `extra=`, alias `log`,
`getLogger(...).info`, `registry._pepper`, `settings.master_key`, `cipher._key`,
`settings.model_dump()["master_key"]`, `key` nu, `cipher.key`, `print(...)` et
`raise ValueError(f"…{secret_value}…")`.

## 4. Résultats locaux

Environnement : Linux, Python 3.13, venv du dépôt.

```sh
.venv/bin/python -m pytest tests/test_vault_key_leak_hunt.py -q
# 8 passed

.venv/bin/python -m pytest tests/test_vault_auth.py tests/test_vault_client.py \
  tests/test_vault_kek_derivation.py tests/test_vault_key_leak_hunt.py -q
# passed

.venv/bin/ruff check heimdall/vault/auth.py tests/test_vault_key_leak_hunt.py
# All checks passed!

.venv/bin/mypy heimdall tests/contracts/fastapi_contract_fixture.py scripts/regen_lock.py
# Success: no issues found
```

## 5. Limites et notes

- Le test runtime capture le logger `heimdall` ; les logs d'`uvicorn`/`httpx`
  ne sont pas sollicités par `TestClient` et ne reçoivent jamais les secrets
  dans ce flux.
- Les canaris sont des valeurs factices uniques, jamais de vrais secrets.
- La clé brute émise par `heimdall vault key create` est volontairement affichée
  **une seule fois sur stdout** ; elle n'est ni journalisée ni persistée en
  clair (seul son HMAC est en base).
