# Installation de Heimdall — Vault Docker et CLI locale

Ce guide est le chemin d'installation testé pour l'audit croisé. Il couvre :

1. le **Vault** dans un conteneur durci, lancé par `docker compose` ;
2. la **CLI locale** pour le premier scan et les commandes `heimdall vault`.

> **Périmètre réseau.** Le Vault est volontairement **loopback-only** : il
> n'accepte que les requêtes dont l'IP source est `127.0.0.1`, `::1` ou
> `localhost`, et refuse les autres en `403`. C'est une protection de
> sécurité, pas un défaut de configuration. Le compose utilise donc
> `network_mode: host` : le conteneur partage la boucle locale de l'hôte.
> Conséquence : **Linux uniquement** pour le Vault Docker (Docker Desktop
> macOS/Windows ne partage pas la loopback hôte). Ne jamais remplacer par un
> `ports: "8443:8443"` : la requête arriverait depuis le bridge Docker et
> serait rejetée en `403`.

## 1. Prérequis

- Linux x86_64 ou arm64.
- Docker Engine 24+ et Docker Compose v2 (`docker compose version`).
- `git`, `openssl`, `curl`, `gpg`.
- Python 3.10+ pour la CLI locale.
- Le port **8443** libre sur `127.0.0.1`.
- Environ 1 Go d'espace disque pour l'image et les données.

Vérification rapide :

```sh
docker --version
docker compose version
git --version
openssl version
python3 --version
```

## 2. Récupérer le dépôt

```sh
git clone https://github.com/Cezar277/heimdall.git
cd heimdall
# Révision auditée (voir docs/t41-samm.md) : installation reproductible.
git checkout 49bb5ccce63a102e1f00a075f1cd6c83dfbe366e
git rev-parse --short HEAD
```

## 3. Générer les secrets et le certificat TLS

Les secrets ne sont **jamais** commités : `.env` et `secrets/` sont ignorés
par Git. Les commandes ci-dessous créent des valeurs aléatoires et les
écrivent avec des permissions restrictives.

```sh
umask 077
test ! -L data && test ! -L secrets || {
  echo "data/ et secrets/ ne doivent pas être des liens symboliques" >&2
  exit 1
}
mkdir -p data secrets
# Re-vérification après création : ferme la fenêtre TOCTOU test -> mkdir.
test ! -L data && test ! -L secrets || {
  echo "data/ et secrets/ ne doivent pas être des liens symboliques" >&2
  exit 1
}
chmod 700 data secrets

ENV_TMP="$(mktemp .env.XXXXXX)"
trap 'rm -f "$ENV_TMP"' EXIT INT TERM HUP
chmod 600 "$ENV_TMP"
cat > "$ENV_TMP" <<ENV_FILE
HEIMDALL_VAULT_MASTER_KEY=$(openssl rand -base64 32)
HEIMDALL_VAULT_API_KEY_PEPPER=$(openssl rand -base64 32)
HEIMDALL_VAULT_KEK_SALT=$(openssl rand -base64 16)
HEIMDALL_UID=$(id -u)
HEIMDALL_GID=$(id -g)
ENV_FILE
mv -f "$ENV_TMP" .env
trap - EXIT INT TERM HUP

openssl req -x509 -newkey rsa:4096 -sha256 -days 365 -nodes \
  -keyout secrets/vault_tls_key.pem \
  -out secrets/vault_tls_cert.pem \
  -subj "/CN=127.0.0.1" \
  -addext "subjectAltName=IP:127.0.0.1" \
  -addext "keyUsage=digitalSignature,keyEncipherment" \
  -addext "extendedKeyUsage=serverAuth" \
  -addext "basicConstraints=critical,CA:FALSE"
chmod 600 secrets/vault_tls_cert.pem secrets/vault_tls_key.pem
```

- `HEIMDALL_VAULT_MASTER_KEY` : phrase de passe longue et unique, **sans
  espaces de bord**. Elle dérive la KEK par Argon2id au démarrage.
- `HEIMDALL_VAULT_KEK_SALT` : sel public de 16 octets, à conserver avec la clé
  maîtresse. Le perdre rend les secrets existants illisibles.
- `HEIMDALL_VAULT_API_KEY_PEPPER` : pepper d'authentification, distinct de la
  clé maîtresse et de la KEK.
- `HEIMDALL_UID` / `HEIMDALL_GID` : UID/GID de l'utilisateur hôte qui possède
  `data/` et `secrets/`. Le conteneur tourne avec cet UID, jamais en root.
  **Ne jamais mettre `0`** : l'entrypoint refuse explicitement `euid == 0`.

> **Sauvegarde.** Sauvegardez `.env` et `secrets/` dans un coffre séparé. Sans
> eux, la base `data/vault.db` est définitivement illisible.

## 4. Démarrer le Vault

Refuser explicitement une installation lancée en root : le conteneur doit
tourner avec l'UID de l'utilisateur hôte, jamais `0`.

```sh
[[ "$(id -u)" != 0 ]] || {
  echo "installation en root refusée : utiliser un compte non privilégié" >&2
  exit 1
}
grep -Eq "^[[:space:]]*(export[[:space:]]+)?HEIMDALL_(UID|GID)[[:space:]]*=[[:space:]]*['\"]?0+['\"]?([[:space:]#]|$)" .env && {
  echo "HEIMDALL_UID/HEIMDALL_GID=0 interdit dans .env" >&2
  exit 1
}
for f in .env.??????; do
  [ -e "$f" ] && { echo "fichier .env temporaire résiduel : $f" >&2; exit 1; }
done
docker compose up -d --build
docker compose ps
```

Attendu : le service `vault` est `Up ... (healthy)`. Les logs ne doivent
contenir aucun secret :

```sh
docker compose logs --tail=50 vault
```

Le premier démarrage crée `data/vault.db` et applique les migrations
additives. Le conteneur tourne en lecture seule (hors `data/` et `/tmp`),
sans privilèges (`cap_drop: ALL`, `no-new-privileges`), avec un utilisateur
non root.

## 5. Vérifier la santé

```sh
curl --cacert secrets/vault_tls_cert.pem \
  https://127.0.0.1:8443/api/v1/health
# {"status":"ok"}
```

Le healthcheck du conteneur vérifie le certificat local et le endpoint
`/api/v1/health`. En cas d'échec, voir la section Dépannage.

## 6. Créer une clé API et un premier secret

La clé API est affichée **une seule fois**. Copiez-la immédiatement dans un
gestionnaire de secrets ou une variable d'environnement de votre shell.

```sh
docker compose exec -T vault heimdall vault key create --project demo
```

Exemple de sortie (la clé réelle sera différente) :

```text
Clé API de projet émise — affichée UNE SEULE FOIS, à copier maintenant :
<cle-api-a-copier>
Identifiant : key_...
Projet      : demo
```

Puis, depuis l'hôte. La clé ne doit **jamais** apparaître dans `argv`
(`ps aux`, `/proc/<pid>/cmdline`) ni dans l'historique shell : on la lit sans
écho, on écrit un fichier d'en-tête `600`, puis `curl -K` lit ce fichier.

```sh
read -rsp "Clé API: " HEIMDALL_API_KEY; echo
[[ "$HEIMDALL_API_KEY" =~ ^[A-Za-z0-9_-]{43,}$ ]] || {
  echo "clé API invalide" >&2
  exit 1
}
umask 077
AUTH_HEADER="$(mktemp /tmp/heimdall-auth.XXXXXX)"
trap 'rm -f "$AUTH_HEADER"' EXIT INT TERM HUP
chmod 600 "$AUTH_HEADER"
printf 'header = "X-Heimdall-API-Key: %s"\n' "$HEIMDALL_API_KEY" \
  > "$AUTH_HEADER"
unset HEIMDALL_API_KEY

curl --cacert secrets/vault_tls_cert.pem \
  -K "$AUTH_HEADER" \
  -H 'Content-Type: application/json' \
  -d '{"project":"demo","env":"dev","name":"DEMO_PASSWORD","value":"valeur-de-demonstration"}' \
  https://127.0.0.1:8443/api/v1/secrets

curl --cacert secrets/vault_tls_cert.pem \
  -K "$AUTH_HEADER" \
  https://127.0.0.1:8443/api/v1/secrets/demo/dev/DEMO_PASSWORD

rm -f "$AUTH_HEADER"
trap - EXIT INT TERM HUP
```

Attendu : `201` puis `200` avec la valeur. Le journal d'audit est consultable
sans exposer les valeurs :

```sh
docker compose exec -T vault heimdall vault audit list --limit 5
```

## 7. Premier scan avec la CLI locale

Le scan est une opération de la CLI locale : il n'est pas exposé par le
conteneur Vault. Installez la CLI dans un venv dédié, avec le lock runtime
hashé :

```sh
python3 -m venv .venv
.venv/bin/pip install --require-hashes -r requirements-runtime.lock
.venv/bin/pip install -e . --no-deps --no-build-isolation
.venv/bin/heimdall --version
```

Test sur un dépôt propre (le scanner exige une base Git) :

```sh
D="$(mktemp -d /tmp/heimdall-clean.XXXXXX)"
trap 'rm -rf "$D"' EXIT
cd "$D"
git init -q
/path/vers/heimdall/.venv/bin/heimdall scan .
# exit 0 : aucun secret détecté
```

Test positif avec un faux secret clairement factice :

```sh
printf 'AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n' > demo.txt
git add demo.txt
/path/vers/heimdall/.venv/bin/heimdall scan .
# exit 1 : 1 secret détecté, valeur jamais affichée en clair
```

Le scan est en lecture seule sur le dépôt. La seule écriture est la clé
d'empreinte locale, hors dépôt, sous `$XDG_DATA_HOME/heimdall/`.

## 8. Opérations courantes

### Logs et état

```sh
docker compose ps
docker compose logs --tail=100 vault
docker compose exec -T vault heimdall vault audit verify
```

### Arrêt / redémarrage

```sh
docker compose stop
docker compose start
```

### Mise à jour

```sh
git fetch origin
git checkout 49bb5ccce63a102e1f00a075f1cd6c83dfbe366e   # même révision auditée qu'au §2
git rev-parse --short HEAD
docker compose build --pull
docker compose up -d
```

Les migrations de base sont additives ; sauvegardez `data/` avant une mise à
jour importante. L'image de base est épinglée par digest dans le `Dockerfile` :
pour la mettre à jour, relever le digest avec
`docker buildx imagetools inspect python:3.12-slim`, remplacer les deux
`FROM ...@sha256:...`, puis reconstruire et rejouer le test à froid.

### Sauvegarde chiffrée

La sauvegarde contient la clé maîtresse, le pepper et la clé TLS : elle doit
être chiffrée avant d'être écrite sur disque.

La base SQLite doit être **quiescente** : arrêter le Vault avant la copie,
sinon une sauvegarde à chaud peut être déchirée ou exclure des transactions.

```sh
docker compose stop vault || exit 1
if ls data/vault.db-* >/dev/null 2>&1; then
  echo "WAL/SHM résiduel : arrêt incomplet, sauvegarde refusée" >&2
  docker compose start vault
  exit 1
fi
umask 077
F="${HOME}/heimdall-backup-$(date +%F).tgz.gpg"
tar --exclude='data/vault.db-*' -czf - data .env secrets \
  | gpg --symmetric --cipher-algo AES256 --output "$F"
chmod 600 "$F"
docker compose start vault
```

Restauration (après `docker compose down`) :

```sh
gpg --decrypt "${HOME}/heimdall-backup-AAAA-MM-JJ.tgz.gpg" | tar -xzf -
```

`gpg --symmetric` utilise un chiffrement authentifié (MDC) : une archive
altérée est refusée au déchiffrement. Le nom de fichier est figé dans `F` pour
que le `chmod` porte sur exactement le fichier écrit, même à cheval sur minuit.
L'archive est écrite dans `$HOME`, **jamais dans le dépôt** : même chiffrée,
elle contient la clé maîtresse, le pepper et la clé TLS. Ne jamais conserver
l'archive `.tgz` en clair.

### Réinitialisation (destructif)

```sh
docker compose down
rm -rf data
docker compose up -d --build
```

Cette commande supprime la base et les secrets qu'elle contient. Les clés API
et les valeurs sont perdues.

## 9. Dépannage

| Symptôme | Cause probable | Correction |
|---|---|---|
| `403` sur `https://127.0.0.1:8443` | Le conteneur n'est pas en `network_mode: host` ou un port mapping a été ajouté | Garder `network_mode: host`, supprimer `ports` |
| `Connection refused` | Conteneur arrêté ou port 8443 occupé | `docker compose ps`, `ss -ltnp \| grep 8443`, `docker compose logs vault` |
| `TLS obligatoire en production` | `secrets/vault_tls_cert.pem` ou `vault_tls_key.pem` absent | Régénérer les fichiers de l'étape 3 |
| `HEIMDALL_VAULT_API_KEY_PEPPER est obligatoire` | `.env` absent, vide ou non chargé | `install -m 600 .env.example .env`, remplir via §3, `docker compose up -d` |
| `Permission denied` sur `/data` | UID/GID du conteneur différent du propriétaire de `data/` | Renseigner `HEIMDALL_UID`/`HEIMDALL_GID` avec `id -u`/`id -g`, `chown -R` sur `data/`, `chmod 700 data secrets` |
| `refus: le conteneur Vault ne doit pas tourner en root` | `HEIMDALL_UID=0` ou `user: "0:0"` | Remettre l'UID/GID de l'hôte (`id -u`/`id -g`), jamais `0` |
| `data/ et secrets/ ne doivent pas être des liens symboliques` | Un lien a été créé avant l'installation | Supprimer le lien et recréer un répertoire réel (`rm data && mkdir data`, idem `secrets`) |
| `docker compose config --quiet` échoue | `.env` ou secrets manquants | Créer les fichiers de l'étape 3 |
| Le healthcheck reste `unhealthy` | Certificat sans SAN `127.0.0.1` ou service pas prêt | Vérifier `openssl x509 -in secrets/vault_tls_cert.pem -text -noout`, logs |
| `scan impossible` (exit 2) | Répertoire sans base Git ou fichier illisible | `git init` dans le répertoire de test, vérifier les permissions |

Commandes de diagnostic utiles :

```sh
docker compose config --quiet   # valide sans imprimer les secrets de .env
docker compose logs --tail=100 vault
docker compose exec -T vault id
docker compose exec -T vault ls -ld /data /run/secrets
```

> N'utilisez **pas** `docker compose config` sans `--quiet` dans un terminal
> partagé ou un log : il imprime les valeurs de `.env`, donc les secrets.

## 10. Sécurité

- Le Vault n'écoute que sur `127.0.0.1:8443`. Ne jamais l'exposer sur une
  interface réseau publique.
- Le conteneur est non root, en lecture seule, avec `cap_drop: ALL`,
  `no-new-privileges` et des limites de processus/mémoire.
- Les secrets arrivent par `.env` (permissions `600`) et `secrets/`
  (permissions restrictives), jamais dans l'image ni dans un commit.
- Le certificat fourni est auto-signé pour un usage local. Pour un déploiement
  réel, fournissez un certificat émis par votre autorité interne, toujours
  avec le SAN `IP:127.0.0.1`.
- Les dépendances runtime sont installées depuis
  `requirements-runtime.lock` avec vérification de hashes SHA-256.
- Le scan ne transmet aucun contenu à un service externe : tout est local.
- **`network_mode: host` élargit le blast radius** : une compromission du
  Vault donne accès au loopback de l'hôte (par exemple Ollama sur
  `127.0.0.1`). Restreindre le groupe `docker` (équivalent root) et ne
  colocaliser aucun service sensible sur la loopback de la même machine.
- **`docker inspect` expose les secrets** : les variables de `.env` sont
  lisibles par tout membre du groupe `docker` via `docker inspect
  heimdall-vault` ou `/proc/<pid>/environ`, même si `.env` est en `600`.
  Réserver l'accès Docker aux administrateurs ; une évolution future pourra
  passer par des fichiers `/run/secrets` plutôt que par l'environnement.

## 11. Preuves et test à froid

- Preuves SAMM et commandes vérifiées : [`docs/t41-samm.md`](t41-samm.md).
- Protocole et résultats du test à froid : [`docs/t122-cold-test.md`](t122-cold-test.md).
- En cas de blocage, ouvrez un ticket avec la sortie de
  `docker compose logs --tail=100 vault` et la commande exacte utilisée.
