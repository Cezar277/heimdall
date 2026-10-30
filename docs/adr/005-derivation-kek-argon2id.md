# ADR-005 — Dérivation de la KEK avec Argon2id

Statut : proposé. Ticket : #262, sous-ticket de #26 « Clé maîtresse et
chiffrement par enveloppe ». Porteur : C · Relecteur : A · Sprint S1.
Précédents : [ADR-002](002-stack-python.md) (stack, `argon2-cffi` déjà épinglé).

## Contexte

Le Vault Heimdall chiffre les secrets au repos avec AES-256-GCM. Dans le
chiffrement par enveloppe du grand ticket #26, la **KEK** protège les DEK de
chaque secret : sa compromission compromet tout le Vault. Jusqu'ici la KEK
était fournie directement par l'exploitant (`HEIMDALL_VAULT_KEK`, 32 octets
aléatoires encodés base64).

Le ticket #262 demande de fabriquer cette KEK à partir de la **clé maîtresse du
serveur** avec **Argon2id**, afin de ralentir une attaque par force brute hors
ligne si l'attaquant obtient un vérificateur ou devine une phrase de passe.

Contraintes :

- 100 % local, aucune primitive maison, bibliothèques `argon2-cffi` et
  `cryptography` confinées à `heimdall/vault/crypto.py` (invariant 5 / #17) ;
- aucune régression : les blobs déjà chiffrés avec `HEIMDALL_VAULT_KEK` doivent
  rester lisibles ;
- dérivation **une seule fois au démarrage**, jamais à chaque requête ;
- paramètres au moins égaux aux minimums OWASP, documentés et testés.

## Décision

### 1. Argon2id, avec les paramètres suivants

La KEK est dérivée avec `argon2.low_level.hash_secret_raw`, type
`argon2.low_level.Type.ID` (Argon2id), sur la clé maîtresse encodée en UTF-8
(ou fournie en octets bruts) :

| Paramètre | Valeur Heimdall | Minimum OWASP (2024) | Justification |
|---|---:|---:|---|
| Mémoire (`memory_cost`) | 65 536 Kio = **64 Mio** | 19 456 Kio = 19 Mio | Coût mémoire élevé : une attaque GPU/ASIC doit allouer 64 Mio par essai, ce qui réduit fortement le parallélisme utile. |
| Itérations (`time_cost`) | **3** | 2 | Marge au-dessus du minimum, coût mesuré ≈ 90 ms sur la machine de développement. |
| Parallélisme (`parallelism`) | **4** | 1 | Utilise les cœurs disponibles sans multiplier la mémoire totale (Argon2 compte la mémoire globalement). |
| Longueur de sortie (`hash_len`) | **32 octets** | — | Clé AES-256 directement utilisable, sans troncature ni re-dérivation. |
| Sel (`salt`) | **16 octets** publics | ≥ 8 octets | 128 bits : collision de sel négligeable, sel unique par déploiement. |

Ces valeurs sont des **constantes de format** (`ARGON2ID_*` dans
`heimdall/vault/crypto.py`), pas des réglages d'environnement : les changer
change la KEK produite pour un même couple (clé maîtresse, sel), donc rend les
secrets existants illisibles. Toute évolution devra passer par le ticket de
rotation #71 et une procédure de re-chiffrement.

### 2. Le sel est public, persisté à côté de la clé maîtresse

Le sel n'est pas un secret : il est stocké à côté de la clé maîtresse dans la
configuration d'exploitation, via `HEIMDALL_VAULT_KEK_SALT` (16 octets encodés
base64 URL-safe). `HEIMDALL_VAULT_MASTER_KEY` et `HEIMDALL_VAULT_KEK_SALT`
doivent être fournis **ensemble** ; une moitié de paire est refusée au
démarrage (fail-closed). Un sel perdu ou modifié ne permet pas de retrouver la
KEK : les secrets existants deviennent illisibles. Le sel et la clé maîtresse
doivent donc être sauvegardés ensemble, séparément de la base SQLite.

Alternative écartée : un fichier sidecar `vault.db.kdf-salt` créé
automatiquement à côté de la base. Le sel n'étant pas secret, ce fichier
n'apporte aucune confidentialité supplémentaire et ajoute une surface
TOCTOU/permissions (ouverture, symlinks, course entre workers) sans bénéfice
démontrable. La variable d'environnement est explicite, testable et déjà
persistée par l'exploitant comme la clé maîtresse.

### 3. Argon2id plutôt que HKDF : le piège du ticket

Le ticket signale lui-même le piège : si la clé maîtresse est **déjà** 32
octets aléatoires, HKDF-SHA256 suffirait — il n'y a pas d'entropie à étirer.
Argon2id se justifie lorsque la clé maîtresse peut être une **phrase de
passe** : sa mémoire dure et son coût CPU rendent chaque essai hors ligne
beaucoup plus cher, alors que HKDF (rapide et déterministe) ne ralentit pas
une attaque par dictionnaire.

Décision : Heimdall accepte une clé maîtresse sous forme de phrase de passe
(minimum 16 octets / 128 bits) **et** utilise Argon2id dans tous les cas. Ce
choix est défendable à l'oral :

- il couvre le cas faible (phrase de passe) sans exiger de l'exploitant qu'il
  choisisse le bon mode ;
- il ne dégrade pas le cas fort (32 octets aléatoires) : le coût est payé une
  seule fois au démarrage ;
- il garde un seul chemin de code et un seul format de KEK, donc une surface
  d'audit réduite.

Alternatives écartées : HKDF seul (insuffisant pour une phrase de passe),
PBKDF2 (moins mémoire-dur), scrypt (acceptable mais Argon2id est le choix
OWASP recommandé et déjà disponible via `argon2-cffi`).

### 4. Une seule dérivation, au démarrage

`VaultSettings` porte la configuration ; `_resolve_vault_cipher` dérive la KEK
**une seule fois** à la construction de l'application, puis la KEK dérivée est
conservée en mémoire dans `VaultCipher`. Les routes et le store ne rappellent
jamais la KDF. Le test
`tests/test_vault_kek_derivation.py::StartupDerivationTests::test_derivation_happens_once_at_startup_not_per_request`
compte les appels : un `create_app` ⇒ 1 dérivation, puis une requête HTTP ⇒
toujours 1. La KEK n'est jamais écrite dans SQLite (test
`test_sqlite_secret_survives_a_restart_with_the_same_master_key_and_salt` :
recherche des octets de la KEK et de son hexadécimal dans le fichier de base).

### 5. Durée de vie de la clé maîtresse

La clé maîtresse n'est **pas effacée** après la dérivation : `VaultSettings`
et `os.environ` la conservent pendant toute la vie du processus, tandis que
`VaultCipher` ne garde que la KEK dérivée. Aucun log, `repr` ou `model_dump`
des settings n'est émis, et `hide_input_in_errors` empêche pydantic de la
refléter dans un `ValidationError`. Python ne garantit pas une zeroization
fiable des chaînes immuables (copies internes, GC) : cette limite est assumée
et documentée, pas revendiquée comme une protection supplémentaire.

### 6. Forme canonique NFC de la clé maîtresse

La clé maîtresse (chemin `str`) est **canonisée NFC** avant l'encodage UTF-8,
à la fois dans `_normalize_master_key` (`crypto.py`) et dans le validateur
`VaultSettings.validate_master_key` (`app.py`). Deux formes Unicode
canoniquement équivalentes — « é » précomposé et « e » + accent combinant,
typiques d'un copier-coller entre OS ou outils — encodent donc en octets
identiques et **dérivent la même KEK**. Sans cette normalisation, la même
phrase de passe ressaisie sous une autre forme rendrait les secrets existants
illisibles (échec de re-démarrage, piège d'une migration #71). C'est cohérent
avec la canonisation NFC des **valeurs** de secrets (décision #62) : la KEK
chiffre des octets NFC ; la matière qui la produit est NFC elle aussi.
Les octets bruts (`bytes`) ne subissent aucune normalisation : ils sont
utilisés tels quels (appellants qui détiennent déjà une clé aléatoire).

## Compatibilité et non-régression

- **Mode historique conservé** : `HEIMDALL_VAULT_KEK` (32 octets base64) reste
  accepté et utilisé directement, sans dérivation. Les blobs existants restent
  donc déchiffrables. Ce mode est documenté comme historique ; les nouveaux
  déploiements utilisent la paire maître/sel.
- **Exclusivité** : fournir `HEIMDALL_VAULT_KEK` **et**
  `HEIMDALL_VAULT_MASTER_KEY` est refusé au démarrage. Deux sources de KEK
  concurrentes rendraient le choix implicite et le diagnostic dangereux.
- **Backend SQLite** : aucune KEK éphémère. Il faut soit `HEIMDALL_VAULT_KEK`,
  soit la paire `HEIMDALL_VAULT_MASTER_KEY` + `HEIMDALL_VAULT_KEK_SALT`.
- **Backend mémoire** : conserve son comportement de test (KEK éphémère si
  aucune clé n'est fournie) ; si la paire maître/sel est fournie, la KEK est
  dérivée comme en production.
- **Invariant 5** : la KEK dérivée est comparée en temps constant au pepper
  d'authentification ; une collision est refusée. La clé maîtresse et le pepper
  restent deux secrets distincts.

## Conséquences

- Le démarrage paie ≈ 90 ms de KDF (mesure locale) : c'est le prix assumé du
  ralentissement des attaques hors ligne. Aucun impact sur le débit des
  requêtes.
- Une sauvegarde doit contenir **clé maîtresse + sel** ; perdre l'un ou l'autre
  rend les secrets illisibles. C'est un risque de disponibilité documenté
  (STRIDE STO-D) et couvert par la procédure de sauvegarde du Vault.
- Les paramètres sont figés dans le code et vérifiés par test : une baisse
  accidentelle serait détectée par la CI.
- Le chiffrement par enveloppe complet (DEK par secret, rotation de la KEK en
  transaction) reste porté par #70 et #71. Cet ADR ne livre que la dérivation
  de la KEK et son branchement au démarrage.

## Preuves

- Implémentation : `heimdall/vault/crypto.py` (`ARGON2ID_*`,
  `derive_kek_from_master_key`, `VaultCipher.from_master_key`),
  `heimdall/vault/app.py` (`VaultSettings.master_key`, `VaultSettings.kek_salt`,
  `_resolve_vault_cipher`).
- Tests : `tests/test_vault_kek_derivation.py` (32 tests), dont le critère
  « Fait quand » (`test_same_master_key_and_same_salt_derive_the_same_kek`),
  l'égalité NFC/NFD (`test_nfc_and_nfd_master_keys_derive_the_same_kek`) et le
  verrou « KDF en panne ⇒ démarrage refusé »
  (`test_kdf_failure_is_fail_closed_at_startup`).
- Fiche SAMM : [`docs/t262-samm.md`](../t262-samm.md).
