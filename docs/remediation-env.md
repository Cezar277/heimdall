# Génération et sécurisation des fichiers d'environnement — T31 (#31)

Ticket : [#31](https://github.com/Cezar277/heimdall/issues/31),
parent [#4](https://github.com/Cezar277/heimdall/issues/4) ([EPIC] Agent MCP et Ollama).
Dépend de : [#30](https://github.com/Cezar277/heimdall/issues/30) (Remplacement par variable d'environnement).

`heimdall.remediation.env` génère et met à jour les fichiers de configuration
locaux nécessaires suite au remplacement d'un secret par une variable d'environnement :
`.env.example`, `.env` et `.gitignore`.

**Règle d'or : un secret ne doit jamais rester dans l'arbre Git.**

---

## 1. Fonctionnalités et responsabilités

### 1.1. `.env.example` sans valeurs (T31.1)
- **Modèle versionnable** : destiné à être committé dans le dépôt (non ignoré).
- **Valeurs strictement vides** : chaque variable est inscrite sous la forme `NOM=\n`.
- **Zéro fuite** : même si un dictionnaire complet `{nom: valeur}` est fourni en entrée,
  les valeurs sont **systématiquement ignorées**. Seuls les noms validés sont écrits.
- **Idempotence** : une variable déjà déclarée n'est pas dupliquée.
- **Préservation et purge des commentaires** : les commentaires `#` respectant la liste
  blanche documentaire stricte (prose multi-mots, URL sans userinfo, versions) sont
  préservés, mais toute affectation ou valeur après `=` dans un commentaire (ex.
  `# APP_KEY=h****k`) et tout commentaire nu non allowlisté (jeton isolé comme
  `# hunter2`, mot-clé évocateur suivi d'une valeur, motif reconnu par le masquage
  central #16/#22, jeton dense ou valeur à haute entropie) est **systématiquement
  purgé et masqué** par `***` sur disque et dans les diffs `plan_env_example_change`
  (before et after), garantissant l'invariant 8 strict (zéro secret dans
  `.env.example` versionné ni dans les diffs affichés).

### 1.2. `.env` avec permissions strictes 0600 (T31.2)
- **Secrets locaux en clair** : contient les associations `NOM="valeur"`.
- **Droits POSIX 0600** : créé et maintenu avec les permissions `0600`
  (`os.open(..., 0o600)` et `os.fchmod`), interdisant la lecture aux autres
  utilisateurs de la machine hôte.
- **Échappement shell sécurisé** : les valeurs sont échappées via `format_env_value`
  (échappement de `"`, `$`, `` ` `` et `\`) pour parer tout risque d'injection ou
  d'exécution arbitraire si le fichier est sourcé.
- **Écriture atomique** : passage par `vault.atomic.write_file_atomic`
  (fichier temporaire + `fsync` + `os.replace` atomique) garantissant qu'aucun
  fichier partiel n'est créé en cas d'interruption.
- **Validation fail-closed du `.env` pré-existant** : toute ligne non vide et non commentée
  sans caractère `=` (ex. `HELLO WORLD`, payload altéré) ou avec clé vide est rejetée
  avec `EnvRemediationError`, interdisant tout abandon silencieux lors de la fusion.
- **Lecture unique anti-TOCTOU** : le `.env` existant est lu **une seule fois** puis parsé
  strictement en mémoire (`_parse_env_strict`) ; aucune seconde lecture disque ne peut
  fusionner un snapshot divergent.
- **Syntaxe stricte dotenv (rejet de `export`)** : la syntaxe shell bash `export VAR=val`
  est explicitement rejetée fail-closed (`EnvRemediationError`) sur `.env` et `.env.example`.

### 1.3. Ajout idempotent au `.gitignore` (T31.3)
- **Protection anti-commit** : s'assure que `.env` ne sera pas indexé par Git.
- **Idempotence stricte (piège évité)** : l'appel répété n'ajoute pas la règle
  en plusieurs exemplaires. Les motifs existants (`.env`, `/.env`, `*.env`, `.env*`)
  sont détectés avant toute écriture.
- **Propreté du format** : insertion propre sur une nouvelle ligne, même si le
  fichier existant ne se termine pas par un saut de ligne.

### 1.4. Contrôle du suivi Git et garde-fou (T31.4)
- **Détection de suivi** : si `.env` est déjà suivi dans l'index ou l'historique Git
  (`is_git_tracked`), un avertissement fort est émis sur `stderr` et consigné dans le reçu.
- **Recommandation de remédiation** : proposition immédiate de la commande
  `git rm --cached .env` pour retirer le fichier de l'index sans détruire sa version sur disque.
- **Critère d'acceptation validé** : `git status` ne montre jamais `.env`.

### 1.5. Grammaire stricte des chemins d'environnement et rejet des faux positifs
Pour éviter tout élargissement de surface d'écriture ou écrasement de fichiers hors cible :
- **Formes acceptées strictement** :
  - Le nom exact `.env`
  - Les préfixes normalisés `.env.` (ex. `.env.example`, `.env.local`, `.env.production`)
  - Les préfixes normalisés `.env_` (ex. `.env_local`, `.env_test`)
  - Les suffixes d'environnement `.env` (ex. `prod.env`, `config/staging.env`, `a.env`)
- **Rejets fail-closed (lèvent `EnvRemediationError`)** :
  - Extensions de sauvegarde et fichiers temporaires : `.env.bak`, `.env.old`, `.env.backup`, `.env~`, `.env.swp`, `.env.tmp`, `prod.env.bak`
  - Faux positifs de préfixe : `.environment`, `.envstuff`
  - Fichiers source ou arbitraires : `src/app.py`, `main.rs`, `.gitignore`
  - Métacaractères de globbing gitignore : `*`, `?`, `[`, `]`, `{`, `}`, `\` (chemins littéraux stricts exigés)
  - Syntaxe bash `export VAR=val` : rejetée au profit de la syntaxe dotenv standard `VAR=val`

---

## 2. Guide d'utilisation

### 2.1. Remédiation complète orchestrée

```python
from pathlib import Path
from heimdall.remediation import remediate_environment

root = Path("/chemin/vers/depot")
secrets = {
    "APP_API_KEY": "EXAMPLE_SYNTHETIC_VALUE_123",
    "DB_PASSWORD": "synthetic_password_456",
}

receipt = remediate_environment(root, secrets)

# receipt est un objet immutable sans secret dans son repr()
print(receipt.example_file)         # ".env.example"
print(receipt.env_file)             # ".env"
print(receipt.variables)            # ('APP_API_KEY', 'DB_PASSWORD')
print(receipt.gitignore_updated)    # True (si la règle a été ajoutée)
```

### 2.2. Opérations unitaires

```python
from pathlib import Path
from heimdall.remediation import (
    update_env_example,
    update_env_file,
    ensure_gitignore_ignores_env,
    check_env_git_status,
)

root = Path(".")

# 1. Mise à jour du gabarit .env.example (valeurs vides uniquement)
added_vars = update_env_example(root, ["JWT_SECRET", "REDIS_HOST"])

# 2. Mise à jour sécurisée du fichier .env en 0600
env_path = update_env_file(root, {"JWT_SECRET": "secret_token"})

# 3. Ajout idempotent à .gitignore
modified = ensure_gitignore_ignores_env(root)

# 4. Vérification de l'état Git
is_tracked, is_ignored, warning, rm_cmd = check_env_git_status(root)
if is_tracked:
    print(f"Action requise : {rm_cmd}")
```

### 2.3. Intégration avec la validation interactive humaine (CLI review / T32)

```python
from pathlib import Path
from heimdall.cli.review import TextChange
from heimdall.remediation import plan_env_example_change, plan_gitignore_change

root = Path(".")

# Préparation des diffs sans écriture sur disque
example_diff = plan_env_example_change(root, ["APP_KEY"])
if example_diff:
    change_example = TextChange(*example_diff)

gitignore_diff = plan_gitignore_change(root)
if gitignore_diff:
    change_gitignore = TextChange(*gitignore_diff)
```

---

## 3. Sécurité et modèle de menaces (STRIDE)

| Menace | Risque | Atténuation Heimdall |
| --- | --- | --- |
| **Information Disclosure** | Fuite de secret dans `.env.example` committé dans Git | `update_env_example` n'écrit jamais de valeur, uniquement `NOM=\n`. Les valeurs d'entrée sont ignorées, les commentaires pollués (`# NOM=val`) sont purgés (`# NOM=`) et les commentaires libres contenant un secret ou une haute entropie sont purgés et masqués (`***`) sur disque et dans les diffs (invariant 8). |
| **Information Disclosure** | Lecture locale de `.env` par un utilisateur non privilégié | `.env` créé avec `os.open(..., 0o600)` et `os.fchmod`. Mode 0600 vérifié par `check_file_mode_600`. |
| **Information Disclosure** | Commit accidentel du secret via `git add .` | `.env` ajouté à `.gitignore`. Alerte et suggestion `git rm --cached .env` si le fichier était déjà suivi. |
| **Tampering** | Injection de variables ou corruption via retours à la ligne | Validation stricte des noms via `validate_variable_name` (`^[A-Z][A-Z0-9_]{1,63}$`, denylist système, rejet de `export`). |
| **Tampering** | Perte silencieuse de lignes ou payload altéré dans `.env` | Contrôle strict de la syntaxe du `.env` pré-existant : rejet fail-closed (`EnvRemediationError`) de toute ligne sans `=` ou à clé vide, sur une lecture unique en mémoire (anti-TOCTOU, aucun second snapshot fusionné). |
| **Tampering** | Exécution de commande shell si `.env` est sourcé | Échappement des caractères spéciaux (`\`, `"`, `$`, `` ` ``) via `format_env_value`. |
| **Elevation of Privilege** | Path traversal (`../`, chemin absolu, symlink sortant) | Confinement de tous les chemins via `mcp.paths.confine`. Liens symboliques refusés fail-closed. |
| **Elevation of Privilege** | Élargissement de surface sur fichiers arbitraires ou de sauvegarde | Grammaire d'environnement stricte (`_is_env_like_path`) rejetant `.environment`, `.env.bak`, `.env.old`, `src/app.py`, et refus des métacaractères `[]/{}` dans gitignore. |
| **Denial of Service** | DoS mémoire par passage d'un volume démesuré | Bornes strictes : 1024 variables max, volume cumulé plafonné à 1 Mio, lecture bornée à 1 Mio. |
| **Denial of Service** | Inflation infinie du fichier `.gitignore` | Idempotence stricte : contrôle des motifs avant tout ajout, aucun doublon. |

---

## 4. Tests et vérification

```bash
.venv/bin/pytest -v tests/test_remediation_env.py
.venv/bin/pytest --cov=heimdall.remediation.env --cov-fail-under=70 tests/test_remediation_env.py
.venv/bin/ruff check heimdall/remediation/ tests/test_remediation_env.py
.venv/bin/mypy heimdall/remediation/env.py tests/test_remediation_env.py
.venv/bin/bandit -q heimdall/remediation/env.py
```
