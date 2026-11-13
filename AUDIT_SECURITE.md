# Audit sécurité et qualité — Heimdall

> **Document de sécurité interne, versionné depuis le ticket #231.** Il liste des vulnérabilités,
> dont certaines non corrigées : à manipuler et diffuser avec les précautions d'usage.

- **Date** : 13 novembre 2026 — commit audité : `c35df09` (branche `main`)
- **Périmètre lu** : `heimdall/` (Vault, CLI, MCP, LLM, scanner), `docker/`, `Dockerfile`, `docker-compose.yml`, `.github/workflows/`, fichiers de configuration et de verrouillage.
- **Hors périmètre** : `docs/` (à ta demande).
- **Lu en diagonale seulement** (recherche de motifs, pas ligne à ligne) : `heimdall/remediation/templates.py`, `heimdall/remediation/env.py`, `heimdall/scanner/gitignore.py`, la seconde moitié de `heimdall/scanner/allowlist.py`, `scripts/`, `tests/`, `openapi.yaml`, `schemas/`, `vendor/`. Des défauts peuvent y subsister.
- **Non fait** : build et exécution de l'image Docker (Docker absent de la machine), `npm audit`, test dynamique contre un Vault démarré, fuzzing.

Ce document ne garantit pas « zéro constat » au pentest : il donne ce que j'ai trouvé, classé, avec la preuve et le correctif. Les constats marqués **Testé** ont été reproduits sur cette machine dans des dépôts jetables ; **Lu** = établi par lecture du code ; **À vérifier** = dépend d'un réglage que je ne peux pas voir d'ici.

---

## 1. Synthèse

| Sévérité | Nombre | Identifiants |
|---|---|---|
| Critique | 1 | C-01 |
| Élevée | 6 | E-01 à E-06 |
| Moyenne | 13 | M-01 à M-13 |
| Faible / info | 20 | F-01 à F-20 |

Le Vault (crypto, SQL, authentification, permissions de fichiers) est la partie la plus solide : je n'y ai trouvé aucune faille directe de lecture de secret ou de contournement d'authentification. Les problèmes graves sont ailleurs : **le hook pre-commit se contourne sans le vouloir**, **le scanner rate la majorité des secrets courants et plante sur des fichiers banals**, et **la CI exécute du code non fiable sur le runner self-hosted**.

### À corriger en premier

1. **C-01** — le hook laisse passer les secrets avec `git commit -a` et `git commit <fichier>`.
2. **E-01** — le scan sort en erreur dès qu'il y a une image, un fichier Latin-1 ou un fichier de plus de 1 Mio ; Heimdall ne peut pas scanner son propre dépôt.
3. **E-02** — 0 % de détection sur les mots de passe, les URL avec identifiants et les jetons de moins de 24 caractères.
4. **E-04 / E-05** — workflows `pull_request` et agent de revue IA sur runner self-hosted.
5. **E-06** — le correctif de CVE du dernier commit n'a pas été reporté dans le lock de l'image Docker.

---

## 2. Critique

### C-01 — Le hook pre-commit est contourné par `git commit -a` et `git commit <chemin>` — Testé

- **Où** : `heimdall/mcp/gitdiff.py:148-193` (`confined_environment`), `heimdall/cli/hook.py:439` (script du hook), `heimdall/cli/scan.py:751-823` (`_collect_staged`).
- **Constat** : pour `commit -a`, `commit <chemin>`, `commit -p`, `--only`, `--include`, Git construit un index temporaire (`.git/index.lock` ou `.git/next-index-<pid>.lock`) et le transmet au hook par `GIT_INDEX_FILE`. Le scan reconstruit un environnement Git vide, donc lit `.git/index`, qui ne contient pas encore les changements. Il analyse l'ancien index et répond « Aucun secret détecté ».
- **Preuve** (dépôt jetable, hook installé par `heimdall hook install`) :

  | Commande | Résultat |
  |---|---|
  | `git add app.py && git commit` (clé AWS + jeton GitHub) | bloqué, code 1 — attendu |
  | `git commit -am ...` (mêmes secrets) | **commit créé**, hook : « Aucun secret détecté » |
  | `git commit -m ... pay.py` (clé Stripe) | **commit créé** |

- **Impact** : la promesse centrale du produit ne tient pas pour l'une des façons les plus courantes de committer. Aucun message n'alerte l'utilisateur.
- **Correctif** :
  - En mode hook, lire `GIT_INDEX_FILE`, le valider (chemin résolu situé dans le répertoire Git du dépôt, fichier régulier, nom `index`, `index.lock` ou `next-index-*.lock`), puis l'injecter dans l'environnement confiné pour `diff --cached`, `ls-files` et le contrôle anti-auto-attestation. `_run_git` sait déjà valider un `GIT_INDEX_FILE` (`hook.py:163-179`).
  - Ajouter des tests d'intégration qui passent par un vrai `git commit` : `-a`, `<chemin>`, `-p`, `--amend`, `--only`.
  - Garder la CI (`scan --ci --diff`) comme barrière d'autorité : un hook client reste contournable par `--no-verify`.

---

## 3. Élevée

### E-01 — Le scan échoue sur du contenu banal, sans dire quel fichier — Testé

- **Où** : `heimdall/cli/scan.py:700-727`, `heimdall/scanner/exclusions.py:252-264`, `heimdall/scanner/detect.py:164-169`, `691-698`, `859-861`, `heimdall/scanner/entropy_detection.py:72-73`.
- **Constat** : chacun des cas suivants fait sortir tout le scan en code 2 avec le seul message « scan impossible (erreur d'outillage) » :

  | Contenu du dépôt | `scan --staged` | `scan --ci` |
  |---|---|---|
  | une image PNG | 2 | 2 |
  | un binaire sans signature connue (police TTF) | 2 | 2 |
  | un fichier texte en Latin-1 (`café`) | 2 | — |
  | un fichier de plus de 1 Mio | 2 | — |
  | une ligne avec un bloc base64 de plus de 4096 caractères (notebook Jupyter) | 2 | — |
  | un lien symbolique dans l'arbre (lu, `detect.py:691-698`) | — | 2 |

  `heimdall scan --ci --no-allowlist .` sur ce dépôt renvoie 2, à cause de `docs/security/dfd.png`.
- **Impact** : le hook bloque tout commit contenant une image ; la CI ne peut pas tourner sur un dépôt réel. Les équipes passeront par `--no-verify`, ce qui annule la protection. Le message ne nomme pas le fichier fautif.
- **Correctif** : ne pas confondre « non analysable » et « erreur ». Ignorer les binaires en les comptant et en les listant dans le rapport ; décoder les textes non UTF-8 avec repli (Latin-1 ou `errors="replace"`) et les analyser quand même ; pour les fichiers trop gros ou les lignes géantes, analyser ce qui est possible et signaler le reste ; ne pas suivre les liens symboliques mais continuer ; nommer le fichier dans l'erreur. Garder le comportement strict derrière une option.

### E-02 — Le scanner rate la plupart des secrets courants — Testé

- **Où** : `heimdall/scanner/signatures/` (10 règles : AWS, Stripe `sk`/`rk`, Slack, GitHub, JWT, en-tête PEM), `heimdall/scanner/entropy_detection.py:20`, `30-32`.
- **Constat** : hors de ces 10 préfixes, seule l'entropie décide, avec un seuil de 4,5 bits sur des jetons limités à `[A-Za-z0-9_+/-]`. Un jeton de 20 à 22 caractères ne peut pas atteindre 4,5 bits, même parfaitement aléatoire. Un mot de passe contenant `!`, `@`, `#` est découpé en morceaux trop courts.
- **Preuve** (200 secrets synthétiques par forme) :

  | Forme | Détection |
  |---|---|
  | `DB_PASSWORD = "Summer2024!Prod"` | 0 % |
  | mot de passe fort de 16 caractères avec symboles | 0 % |
  | `postgres://admin:motdepasse@hôte/base` | 0 % |
  | jeton aléatoire de 20 caractères | 0 % |
  | jeton aléatoire de 24 caractères | 5 % |
  | secret JWT HS256 de 16 caractères | 0 % |
  | `Authorization: Basic …` | 0 % |
  | jeton GitLab `glpat-…` | 15 % |
  | jeton aléatoire de 32 caractères | 68 % |
  | clé AWS encodée en base64 dans le code | 0 % |

  Les formes longues (40 caractères et plus, hex 32, OpenAI, SendGrid, npm) sont détectées à 95-100 %.
- **Impact** : un pentesteur committera un mot de passe de base de données sans déclencher quoi que ce soit.
- **Correctif** : ajouter une règle générique « nom évocateur + valeur » (`password`, `passwd`, `secret`, `token`, `api_key`, `auth`…), une règle pour les identifiants dans les URL, et les préfixes déjà connus de `heimdall/mcp/masking.py:140-165` (`glpat-`, `AIza`, `npm_`, `whsec_`, `ya29.`…) que le scanner ignore. Baisser le seuil d'entropie quand le nom de variable est évocateur. Mesurer le taux de détection en CI sur un corpus de référence.

### E-03 — Le masquage avant envoi au LLM laisse passer des secrets en clair — Testé

- **Où** : `heimdall/mcp/masking.py:37-89`.
- **Constat** : les trois expressions d'affectation exigent `clé` immédiatement suivie de `:` ou `=`. Une clé entre guillemets (JSON, YAML, dictionnaire Python) n'est donc jamais reconnue.
- **Preuve** : ces lignes ressortent de `mask_text` inchangées :

  ```
  {"password": "hunter2!hunter"}
  'api_key': 'abcd1234efgh'
  password = "it's-secret-123"
  password = my secret pass phrase 42
  password=abc,defghijk99
  DB_PASSWORD: p@ss;word1234
  <password>Sup3rS3cret</password>
  define('DB_PASSWORD', 'S3cr3tValue99');
  machine github.com login bob password S3cretP4ss
  curl -u admin:Sup3rS3cret https://x
  --password Sup3rS3cret99
  ```

- **Impact** : `sanitize_file`, `read_diff` et le contexte de qualification (`heimdall/cli/cold_start.py:76`) envoient ces valeurs au modèle, alors que le prompt et le contrat affirment que l'extrait est « déjà masqué ». Le modèle est local, donc l'exposition reste sur la machine (mémoire et journaux d'Ollama), mais l'invariant « aucun secret hors du scanner » est faux.
- **Correctif** : accepter un guillemet fermant optionnel entre la clé et le séparateur ; traiter `=>`, les balises XML, les arguments `--password X` et `-u user:pass` ; pour une clé évocatrice, masquer jusqu'à la fin de la valeur, y compris après `,` `;` et une apostrophe interne. Ajouter ces cas aux tests.

### E-04 — Des workflows `pull_request` exécutent le code de la PR sur le runner self-hosted — À vérifier

- **Où** : `.github/workflows/prompt-injection.yml:4,14`, `security-model.yml:5,16`, `vault-contract.yml:4,37`.
- **Constat** : `ci.yml` prend soin de ne jamais exécuter une PR de fork sur le runner. Ces trois workflows se déclenchent sur `pull_request` sans filtre, installent les dépendances et lancent `pytest`, `npm ci`, `npm run test:js` sur le code de la PR. Le commentaire de `security-model.yml:15` dit l'inverse de ce que fait la ligne 16.
- **Impact** : si le dépôt est public (ou si l'approbation des PR de fork n'est pas exigée), une PR externe exécute du code arbitraire sur ta machine de build. Si le runner n'est pas éphémère, ce code peut aussi modifier ce que les jobs privilégiés exécuteront ensuite : `~/.opencode/bin` (lancé avec `OPENCODE_API_KEY`), `python3`, la configuration Git. La séparation de privilèges décrite dans `ci.yml:26-31` ne tient alors plus.
- **À vérifier** : visibilité du dépôt, réglage « Require approval for all outside collaborators », runner éphémère ou non.
- **Correctif** : ajouter `if: github.event.pull_request.head.repo.fork == false` à ces jobs, ou les passer sur des runners hébergés par GitHub ; rendre le runner éphémère ; ne partager aucun répertoire personnel entre jobs fiables et non fiables.

### E-05 — La revue par agent IA tourne avec tous les droits sur le runner — Lu

- **Où** : `.github/workflows/opencode-review.yml:11-19`, `61`, `67-72`, `opencode.json:3-8`.
- **Constat** :
  - `opencode.json` accorde `"*": "allow"` et `external_directory: allow` : l'agent peut lancer n'importe quelle commande sans confirmation.
  - Il reçoit `OPENCODE_API_KEY`, un `GITHUB_TOKEN` avec écriture sur les PR et les issues, et `id-token: write`.
  - Il lit le contenu de la PR, que n'importe quel contributeur contrôle. La consigne « ignore les instructions de la PR » dans le prompt n'est pas une barrière technique.
  - Aucun filtre sur les forks : un collaborateur qui commente `/oc` sur une PR externe déclenche l'agent sur ce contenu.
  - `opencode.json` est lu dans l'arbre de travail : une PR peut le modifier.
  - `contains(body, '/oc')` se déclenche sur tout commentaire contenant cette suite de caractères.
  - L'installation se fait par `curl … | bash` sans vérification d'empreinte.
  - Ni `timeout-minutes` ni `concurrency`.
- **Impact** : une injection de prompt dans une PR donne l'exécution de commandes sur le runner et l'accès aux secrets du job.
- **Correctif** : passer les permissions de l'agent en lecture seule (`bash: deny`, `edit: deny`), charger sa configuration depuis la branche de base, retirer `id-token: write`, refuser les forks, exiger une commande exacte en début de commentaire, vérifier le SHA-256 du binaire, ajouter un délai maximal.

### E-06 — Le correctif de CVE n'est pas dans le lock de l'image Docker — Testé

- **Où** : `requirements-runtime.lock:361`, `requirements.lock:654`, `.github/workflows/ci.yml:255-256`.
- **Constat** :
  - Le commit `8d9a8e3` passe `opentelemetry-api` à 1.45.2 dans `requirements.lock`, mais `requirements-runtime.lock` — celui que le `Dockerfile` installe — est resté en **1.45.1** (CVE-2026-126360).
  - `requirements.lock` épingle `filelock==4.1.0` pour Python < 3.11 : `pip-audit -r requirements.lock` remonte 12 CVE corrigées en 4.2.1. Python 3.10 est une version supportée (`pyproject.toml:10`).
  - La CI n'audite que l'environnement installé sur le runner. Ni `requirements-runtime.lock`, ni `tests/contracts/requirements.txt`, ni `tests/security/requirements.txt` ne sont audités.
- **Correctif** : régénérer le lock runtime (`scripts/regen_runtime_lock.py`), monter `filelock`, et faire tourner `pip-audit -r <fichier> --require-hashes` sur chaque fichier de verrouillage. Ajouter un test qui compare les versions communes aux deux locks.

---

## 4. Moyenne

### M-01 — `HEIMDALL_IN_HOOK=1` désactive le scan avec un code 0 — Testé
- **Où** : `heimdall/cli/hook.py:412-415`.
- **Constat** : `HEIMDALL_IN_HOOK=1 git commit` affiche « scan ignoré » et laisse passer. La variable est aussi posée dans l'environnement du processus par `apply_and_restage` (`hook.py:1067-1068`) et peut être héritée d'un shell parent.
- **Correctif** : faire porter l'anti-récursion par un jeton à usage unique (valeur aléatoire créée par le processus parent et vérifiée par le hook) plutôt que par une valeur fixe, ou sortir en erreur quand la variable vient de l'extérieur.

### M-02 — Un processus local non authentifié peut bloquer tous les clients du Vault — Lu
- **Où** : `heimdall/vault/app.py:1415`, `heimdall/vault/ratelimit.py:196-209`.
- **Constat** : le Vault n'accepte que la boucle locale, donc tous les clients ont le pair `127.0.0.1`. Le budget « par pair » (1 200 requêtes par minute) est en réalité partagé par tous, et les requêtes sans clé le consomment.
- **Impact** : n'importe quel processus de la machine maintient le budget plein ; les clients légitimes reçoivent des 429.
- **Correctif** : ne faire consommer le budget commun qu'aux requêtes non authentifiées et donner aux requêtes authentifiées leur budget par clé, vérifié en premier.

### M-03 — Le journal d'audit peut être vidé par inondation et réécrit — Lu
- **Où** : `heimdall/vault/audit.py:58`, `419-453`, `662-675`, `188-190`.
- **Constat** :
  - La rétention garde 100 000 événements. Chaque requête, y compris non authentifiée et y compris les 429, écrit un événement. 100 000 requêtes locales font disparaître l'historique utile.
  - La chaîne utilise SHA-256 sans clé : quiconque écrit dans la base recalcule une chaîne valide. La suppression des derniers événements n'est pas détectée. Le module le reconnaît en commentaire, mais un pentesteur le relèvera.
- **Correctif** : agréger ou échantillonner les rejets non authentifiés et les 429 ; séparer leur rétention de celle des accès réussis ; chaîner avec un HMAC sous une clé dédiée ; exporter régulièrement le dernier hash hors de la machine.

### M-04 — Le client Vault honore les proxys et certificats de l'environnement — Lu
- **Où** : `heimdall/vault/client.py:876-885`.
- **Constat** : `httpx.Client` est créé sans `trust_env=False`. `HTTPS_PROXY`, `ALL_PROXY` et `SSL_CERT_FILE` sont pris en compte. Le client Ollama (`heimdall/llm/qualify.py:201`) et le healthcheck (`docker/healthcheck.py:40`) les désactivent explicitement.
- **Impact** : derrière un proxy d'entreprise, les requêtes vers `127.0.0.1` partent vers le proxy (panne, et métadonnées envoyées hors de la machine, contraire à « 100 % local ») ; `SSL_CERT_FILE` élargit les autorités de confiance quand `--ca-cert` n'est pas fourni.
- **Correctif** : `trust_env=False`.

### M-05 — Des appels Git non confinés permettent l'exécution de commandes par un dépôt piégé — Lu
- **Où** : `heimdall/vault/atomic.py:707-812` (`_get_git_toplevel`, `is_git_tracked`, `is_git_ignored`), `heimdall/vault/client.py:327-351` (`_detect_from_git`).
- **Constat** : ces fonctions prennent `git` dans le `PATH` de l'utilisateur, héritent de tout l'environnement et n'imposent pas `core.fsmonitor=false`. Le reste du projet passe par `GitAccess`, qui confine tout cela (`heimdall/mcp/gitdiff.py:89`, `148-193`). `git ls-files` dans un dépôt dont `.git/config` définit `core.fsmonitor` exécute la commande indiquée.
- **Impact** : `heimdall vault pull`, `push` ou `run` lancé dans un dépôt reçu en archive exécute du code. C'est le scénario contre lequel `GitAccess` a été écrit.
- **Correctif** : faire passer ces quatre fonctions par `GitAccess`.

### M-06 — `heimdall run` transmet la clé API du Vault à la commande lancée — Lu
- **Où** : `heimdall/cli/vault_client.py:819`.
- **Constat** : `child_env = {**os.environ, **injected_secrets}` conserve `HEIMDALL_API_KEY`, `HEIMDALL_API_KEY_FILE` et toutes les variables `HEIMDALL_VAULT_*`.
- **Impact** : la commande reçoit de quoi lire, créer et supprimer tous les secrets du projet, pas seulement ceux injectés.
- **Correctif** : retirer les variables `HEIMDALL_*` de l'environnement de l'enfant.

### M-07 — Rotation de KEK : impossible avec une clé HMAC serveur, dangereuse à chaud, non auditée — Lu
- **Où** : `heimdall/cli/vault_keys.py:332-373`, `425-435` ; `heimdall/vault/database.py:1835-1845` ; `heimdall/vault/store.py:793-798`, `853-858`.
- **Constat** :
  - La commande construit ses chiffreurs sans clé HMAC serveur. Si la base porte un canari (déploiement avec `HEIMDALL_VAULT_SERVER_HMAC_KEY`), la rotation est refusée, et le message affiché est « échec du déchiffrement avec l'ancienne KEK », ce qui est faux.
  - Lancée pendant que le serveur tourne, elle laisse le serveur avec l'ancienne KEK : toutes les lectures échouent en 500 et toutes les créations sont refusées jusqu'au redémarrage. Rien ne l'empêche ni ne prévient.
  - Ni la rotation ni `key create` / `key revoke` n'écrivent dans le journal d'audit.
- **Correctif** : lire la clé HMAC serveur dans la commande ; distinguer les causes dans les messages ; refuser la rotation si le serveur répond sur son port, ou faire recharger la clé au serveur ; journaliser les opérations d'administration.

### M-08 — La liste noire de noms de variables bloque les secrets les plus courants et reste incomplète — Lu
- **Où** : `heimdall/remediation/naming.py:30-159`, `heimdall/cli/vault_client.py:229-240`, `263-272`, `508-514`.
- **Constat** :
  - Les préfixes `AWS_`, `DOCKER_`, `NPM_`, `GIT_`, `PIP_`, `TF_`, `KUBE_`, `NODE_`… sont refusés. Un `.env` contenant `AWS_SECRET_ACCESS_KEY` fait échouer **tout** `heimdall vault push` (code 2), et ces secrets ne peuvent être ni tirés ni injectés.
  - À l'inverse, `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, `NO_PROXY`, `SSLKEYLOGFILE`, `CLASSPATH`, `PHPRC`, `PHP_INI_SCAN_DIR`, `CURL_HOME`, `WGETRC`, `GNUPGHOME`, `ELECTRON_RUN_AS_NODE` passent.
- **Correctif** : séparer les deux usages. Pour le stockage (`push`, `pull`), ne rien refuser d'autre que le format du nom. Pour l'injection (`run`), garder une liste ciblée sur ce qui détourne l'exécution ou le trafic (`LD_*`, `PYTHON*`, `NODE_OPTIONS`, `BASH_ENV`, `*_PROXY`, `SSLKEYLOGFILE`…), complétée, avec une option explicite pour passer outre.

### M-09 — La remédiation et la revue interactive ne sont reliées à aucune commande — Lu
- **Où** : `heimdall/cli/main.py` (commandes : `scan`, `cold-start`, `deep-scan`, `rejections`, `mcp`, `hook`, `vault`, `run`) ; `heimdall/cli/review.py`, `heimdall/remediation/`, `heimdall/cli/hook.py:1054` n'ont aucun appelant hors des tests.
- **Impact** : environ 6 000 lignes de code sensible (écriture de fichiers, réindexation Git) non atteignables par l'utilisateur, alors que le README annonce une « local agentic remediation ». Du code non exercé en conditions réelles est du code dont les défauts restent invisibles.
- **Correctif** : brancher une commande (`heimdall fix` ou équivalent) et la tester de bout en bout, ou retirer l'annonce.

### M-10 — `pip` reste probablement dans l'image de production — À vérifier
- **Où** : `Dockerfile:29`, `32`, `54`.
- **Constat** : `pip uninstall` s'exécute dans l'étape `builder`. L'étape `runtime` repart de `python:3.12-slim`, qui contient déjà `pip`, et `COPY --from=builder …/site-packages` fusionne les répertoires sans rien supprimer. Le commentaire `Dockerfile:43-44` et le test `tests/test_docker_assets.py:60` ne vérifient que le texte du Dockerfile.
- **Vérification** : `docker run --rm --entrypoint python heimdall-vault:local -m pip --version`.
- **Correctif** : `rm -rf` de `pip` et de `/usr/local/bin/pip*` dans l'étape `runtime`, et un test qui interroge l'image construite.

### M-11 — La clé maîtresse n'a qu'un contrôle de longueur — Lu
- **Où** : `heimdall/vault/crypto.py:235`, `782-820` ; `heimdall/vault/app.py:908-938`.
- **Constat** : 16 octets suffisent ; `aaaaaaaaaaaaaaaa` est accepté. La clé HMAC serveur, moins sensible, subit six contrôles (`crypto.py:323-361`).
- **Correctif** : appliquer les mêmes contrôles à la clé maîtresse, ou exiger 32 octets issus d'un générateur et fournir la commande qui la produit.

### M-12 — Trous dans la CI de sécurité — Lu
- **Où** : `.github/workflows/ci.yml:224-256`, `.github/dependabot.yml`.
- **Constat** :
  - Aucun scan de secrets du dépôt lui-même (ni Heimdall, ni un autre outil).
  - `bandit` ne couvre que `heimdall/` ; `scripts/` et `docker/` donnent 10 alertes faibles non examinées.
  - `ruff` ne couvre pas `docker/` (2 erreurs dans `docker/healthcheck.py:48`).
  - Dependabot ne suit ni npm, ni l'image de base Docker, ni les `requirements.txt` des sous-dossiers de `tests/`.
- **Correctif** : étendre les cibles, ajouter les écosystèmes `npm` et `docker` et les répertoires manquants.

### M-13 — Sans `HEIMDALL_ENV`, le Vault démarre en mode développement — Lu
- **Où** : `heimdall/vault/auth.py:137-139`, `heimdall/vault/app.py:266-274`, `836-843`, `856`, `2107-2114`.
- **Constat** : variable absente ou mal orthographiée ⇒ HTTP en clair, stockage en mémoire, pepper éphémère, authentification désactivable, `/docs` activable.
- **Correctif** : inverser le défaut (production sauf `HEIMDALL_ENV=dev` ou `test` explicite) et refuser toute valeur inconnue.

---

## 5. Faible et informatif

| ID | Où | Constat | Correctif |
|---|---|---|---|
| F-01 | `vault/client.py:103-105`, `169` | `pattern.match` avec `$` accepte un saut de ligne final (`"proj\n"`). Le serveur utilise la bonne forme. | `fullmatch`. |
| F-02 | `vault/client.py:735` | Le client accepte les statuts `actif` et `revoque`, que le serveur n'émet jamais. | Aligner sur `vaulte`. |
| F-03 | `vault/store.py:100-133`, `vault/crypto.py:1115-1123` | Un secret passé à `rote` garde sa valeur chiffrée et sa DEK ; le statut n'est pas dans l'AAD, donc une écriture en base le repasse à `vaulte`. | Effacer `encrypted_value` et `encrypted_dek` à la transition ; inclure le statut dans l'AAD. |
| F-04 | `vault/database.py:1860-1979` | La rotation de KEK ne renouvelle pas les DEK : KEK compromise + ancienne copie de la base = valeurs actuelles lisibles. | Documenter, et proposer un rechiffrement complet après compromission. |
| F-05 | `vault/database.py:151-153` | Pas de `PRAGMA secure_delete` : les lignes supprimées restent dans les pages libres. | `PRAGMA secure_delete = ON`. |
| F-06 | `vault/app.py:2115-2129` | Pas de contrôle de l'en-tête `Host` (rebinding DNS en mode HTTP), pas de `limit_concurrency` ni `timeout_keep_alive`. | `TrustedHostMiddleware` et limites uvicorn. |
| F-07 | `vault/auth.py:724-742`, `vault/database.py:142` | Chaque requête parcourt toutes les clés, révoquées comprises, et ouvre environ six connexions SQLite ; délai de verrou de 0,25 s ⇒ 503 sous charge. | Purger les clés révoquées anciennes ; une connexion par requête. |
| F-08 | `vault/auth.py` | Clés API sans expiration ni portée (lecture seule / écriture). Pas de commande CLI pour supprimer ou faire transiter un secret. | Ajouter expiration et portées. |
| F-09 | `mcp/server.py:432-455`, `471-521`, `mcp/paths.py:134` | `sanitize_file` n'interdit que `.git` et `.env*` : `.netrc`, `.pgpass`, `id_rsa`, `*.pem`, `.npmrc`, `.docker/config.json` sont lisibles, avec le masquage partiel de E-03. Les noms de fichiers ne sont pas masqués. `O_NOFOLLOW` ne protège que le dernier composant du chemin. | Étendre la liste ; masquer les chemins ; ouvrir composant par composant. |
| F-10 | `remediation/apply.py:168-174`, `vault/atomic.py:597` | La sauvegarde `<fichier>.bak` contient le secret en clair, n'est jamais supprimée et n'est pas ignorée par Git (simple avertissement). | La placer hors du dépôt ou la supprimer après validation. |
| F-11 | `vault/atomic.py:653-674` | `parse_env_file` ne gère ni `export X=…` ni les commentaires en fin de ligne : la valeur poussée au Vault peut être fausse. | Analyseur conforme au format `.env`. |
| F-12 | `docker-compose.yml:30-31`, `vault/app.py:1969` | Clé maîtresse et pepper passés par variables d'environnement (lisibles par `docker inspect` et `/proc/<pid>/environ`) et gardés en mémoire toute la vie du processus. | Fichiers de secrets en lecture seule ; retirer les variables après chargement. |
| F-13 | `docker-compose.yml`, `.dockerignore` | Pas de limite CPU ; `.venv-ci` absent de `.dockerignore`. | Compléter. |
| F-14 | `vault-contract.yml:47`, `opencode-review.yml` | `pip install --upgrade pip` non épinglé ; pas de `permissions` au niveau du workflow. | Épingler ; `permissions: {}` par défaut. |
| F-15 | `vault/ratelimit.py:291` | Le limiteur SQLite utilise l'horloge murale : un recul d'horloge prolonge un blocage. | Borner les horodatages futurs. |
| F-16 | `vault/audit.py:666-674` | Si l'écriture d'audit échoue après une suppression ou une transition, l'action est faite mais non tracée. | Écrire l'intention avant l'action pour les mutations. |
| F-17 | `heimdall.toml:57-66`, `cli/scan.py:497-502` | Sous `tests/`, toute valeur contenant `fake`, `mock`, `dummy`… est ignorée (clémence documentée). Le hook refuse tout commit qui modifie `heimdall.toml`, ce qui pousse à `--no-verify`. | Prévoir un chemin d'approbation pour modifier l'allowlist. |
| F-18 | `vault/client.py:374-403` | L'identifiant de projet vient du nom du dossier, avec repli sur `default` : deux dépôts homonymes partagent un espace de noms. | Exiger un identifiant explicite. |
| F-19 | `mcp/gitdiff.py:336`, `cli/hook.py:131` | `git` n'est cherché que dans `/bin:/usr/bin` : hook et MCP inutilisables avec Homebrew ou Nix. | Liste de chemins sûrs configurable. |
| F-20 | `vault/crypto.py:1397-1408`, global | Deux fonctions publiques lèvent `NotImplementedError` ; 24 `nosec` et 38 `noqa: S` à justifier un par un pour une revue de code. | Supprimer le code mort ; documenter chaque exemption. |

---

## 6. Ce qui a été vérifié et tient

- **SQL** : toutes les requêtes sont paramétrées ; `foreign_keys=ON` sur chaque connexion.
- **Chiffrement** : AES-256-GCM, nonce aléatoire par chiffrement, AAD lié à `projet/env/nom`, une DEK par secret, Argon2id (64 Mio, 3 passes, 4 voies), bibliothèques standard uniquement.
- **Authentification** : clés de 256 bits, stockées en HMAC avec pepper, comparaison en temps constant, parcours complet sans sortie anticipée, réponses 401 identiques, 403 avant toute recherche de ressource.
- **Fuites** : messages d'erreur génériques, pas d'écho des entrées, `repr` expurgés, `Cache-Control: no-store`.
- **Fichiers** : base en `0600`, ouverture sans suivi de liens, écritures atomiques. J'ai testé l'ouverture SQLite par `/dev/fd` : elle vise bien l'inode validé.
- **Processus** : aucun `shell=True`, `eval`, `pickle` ni `yaml.load` ; Git appelé avec un environnement reconstruit dans `GitAccess` (sauf M-05).
- **LLM** : sortie validée par schéma strict, délimiteurs aléatoires, verdict consultatif uniquement, mode CI sans appel au modèle.
- **Conteneur** : utilisateur non root, racine en lecture seule, capacités retirées, image de base épinglée par empreinte.

## 7. Suite de tests

`pytest` sur ce commit : **3 805 réussis, 18 ignorés, 0 échec** (2 min 30).

La suite est verte alors que C-01, E-01, E-02 et E-03 sont reproductibles : aucun test ne passe par un vrai `git commit -a`, ne scanne un dépôt contenant une image, ni ne mesure un taux de détection sur des secrets réalistes. Ce sont les tests à ajouter en même temps que les correctifs.
