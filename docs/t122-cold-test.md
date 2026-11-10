# T122 — test à froid de l'installation

Objectif : vérifier qu'une personne qui n'a pas écrit le code peut installer
et lancer Heimdall **avec la seule documentation** `docs/install.md`.

## 1. Protocole

1. Partir d'un répertoire vide et d'un clone frais du dépôt.
2. Ne lire que `docs/install.md` (pas de commande copiée depuis un autre
   document, pas d'aide de l'auteur).
3. Exécuter les étapes 1 à 7 du guide, dans l'ordre.
4. Noter chaque hésitation, commande ambiguë, erreur ou résultat inattendu.
5. Corriger `docs/install.md` et recommencer si un blocage est reproductible.
6. Signer la section « Validation par une personne externe » ci-dessous.

## 2. Résultats du test automatisé (environnement neuf)

- Date : 2026-11-10
- Environnement : Linux, Docker Engine 29.9.3, Docker Compose v5.7.0,
  Python 3.14, répertoire temporaire sans historique Git.
- Opérateur : agent automate, à partir de `docs/install.md` uniquement.

| Étape | Commande | Résultat attendu | Résultat observé |
|---|---|---|---|
| Build | `docker compose build --pull` | image construite | OK |
| Démarrage | `docker compose up -d --build` | conteneur `healthy` | OK |
| Santé | `curl --cacert secrets/vault_tls_cert.pem https://127.0.0.1:8443/api/v1/health` | `{"status":"ok"}` | OK |
| Clé API | `docker compose exec -T vault heimdall vault key create --project demo` | clé affichée une fois | OK |
| Création secret | `POST /api/v1/secrets` | `201` | OK |
| Lecture secret | `GET /api/v1/secrets/demo/dev/DEMO_PASSWORD` | `200` + valeur | OK |
| Audit | `docker compose exec -T vault heimdall vault audit list --limit 5` | événements 201/200, aucune valeur | OK |
| Scan propre | `heimdall scan .` dans un dépôt Git vide | exit `0` | OK |
| Scan positif | faux secret AWS dans un dépôt Git | exit `1`, valeur masquée | OK |

## 3. Points de friction corrigés pendant le test

| Friction | Correction apportée |
|---|---|
| Le scan échoue hors dépôt Git (exit 2) | Le guide impose `git init -q` avant le premier scan |
| Le Vault refuse un port mapping Docker (403 loopback) | Le guide et le compose imposent `network_mode: host` |
| Les secrets TLS montés en `0600` root ne sont pas lisibles par l'utilisateur du conteneur | Le compose utilise l'UID/GID hôte (`HEIMDALL_UID`/`HEIMDALL_GID`) et un bind mount `./secrets` |
| Le healthcheck doit vérifier TLS | `docker/healthcheck.py` vérifie le certificat local, sans désactiver la validation |
| Le scan n'est pas dans l'image Vault minimale | Le guide installe la CLI locale dans un venv dédié |
| Clé API visible dans `ps`/historique avec `curl -H` | Le guide utilise `read -rsp`, valide le charset, `mktemp`, un fichier d'en-tête `600`, `curl -K` et supprime le fichier après usage |
| Image de base mutable (`python:3.12-slim`) | Digest `@sha256:...` épinglé dans le Dockerfile |
| `HEIMDALL_UID=0` pouvait relancer le conteneur en root | Entrypoint refusant `euid == 0`, testé |
| Sauvegarde non chiffrée de `.env`/`secrets` | Archive chiffrée authentifiée `gpg --symmetric --cipher-algo AES256` |
| Sauvegarde SQLite à chaud | Le guide arrête le Vault (`docker compose stop vault`), refuse un WAL/SHM résiduel, archive puis redémarre |
| Permissions de `data/`/`secrets/` dépendantes de l'umask | `chmod 700 data secrets` et `chmod 600` explicites |
| `.env` écrit en place, race possible | Écriture atomique via `mktemp` + `mv -f` |
| Nom de sauvegarde recalculé entre `gpg` et `chmod` | Nom figé dans `F` avant l'écriture |
| Archive de sauvegarde laissée dans le dépôt | Écriture dans `$HOME`, motifs `heimdall-backup-*.tgz.gpg` ajoutés à `.gitignore` et `.dockerignore` |
| Secrets `.env` visibles via `docker inspect` | Avertissement explicite dans la section Sécurité |
| `data/`/`secrets/` pouvaient être des symlinks préexistants | Garde `test ! -L data && test ! -L secrets` avant **et après** `mkdir` (fenêtre TOCTOU) |

## 4. Validation par une personne externe

À compléter par une personne qui n'a pas participé à l'implémentation :

- Nom / rôle :
- Date :
- Environnement (OS, Docker, Python) :
- A suivi uniquement `docs/install.md` : oui / non
- Installation réussie sans aide : oui / non
- Blocages rencontrés :
- Corrections proposées :
- Signature :

> Tant que cette section n'est pas signée, le ticket #122 reste une preuve
> automatisée et non une validation humaine externe. Le protocole ci-dessus
> est prêt à être rejoué par l'équipe d'audit.
