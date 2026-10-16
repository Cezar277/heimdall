# ADR-004 — Choix du modèle LLM local (Ollama)

Statut : proposé. Ticket : #79 (T28.1). Porteur : B · Relecteur : D · Sprint S1.
Précédent : [ADR-002](002-stack-python.md) (socle, client `ollama` 0.6.3).

## Contexte

Le scanner déterministe (regex + entropie, #22) repère des candidats secrets ;
un LLM 100 % local (Ollama) aide à confirmer les vrais secrets et à résister
aux prompts adverses. Contraintes : CPU-only, tourne sur n'importe quel PC de
l'équipe (budget : < 800 Mo disque, < 1,5 Go RAM, < 1,5 s/candidat), aucune
donnée hors machine, Ollama sur `127.0.0.1` uniquement (jamais
`OLLAMA_HOST=0.0.0.0`). Le LLM est consultatif : il ne blanchit jamais seul
(fail-closed, validation humaine Y/N/E, aucun pouvoir en CI — voir T28.3).

## Décision

Modèle par défaut : **`gemma3:270m`** (Google Gemma 3 270M instruct, Q8_0,
292 Mo) via Ollama, `think` désactivé, `temperature 0`, sortie JSON contrainte.

## Mesures

Machine : Arch Linux, Intel Core Ultra 5 225U (14 threads), 14 Gio RAM,
serveur Ollama 0.40.4, CPU-only, `http://127.0.0.1:11434`.
Protocole : `/api/chat`, `format=json`, `think:false`, `temperature 0`,
`num_ctx 1024`, `num_predict 120` — voir
`tests/benchmarks/benchmark_llm_ollama.py` (100 % stdlib, sans dépendance).
« Succès » ne veut plus dire « pas d'exception » : chaque cas est labellisé
(`secret` / `faux_positif` / `incertain_ou_secret` pour les injections, où
tout sauf `faux_positif` est correct).

### Panel comparatif (20 cas T21 labellisés)

| Modèle | Taille | Justesse | Secrets | FP écartés | Injections bloquées | JSON | s/req | tok/s |
|---|---|---|---|---|---|---|---|---|
| **gemma3:270m** | **291 Mo** | **14/20** | **10/10** | 0/6 | **4/4** | 20/20 | **0,72** | **62** |
| qwen3.5:0.8b (Q8_0) | 1,3 Go | 11/20 | 10/10 | 0/6 | 1/4 | 20/20 | 2,86 | 22 |
| qwen3:0.6b | 522 Mo | 8/20 | 4/10 | 0/6 | 4/4 | 20/20 | 0,78 | 40 |
| qwen2.5:0.5b | 397 Mo | 3/20 | 0/10 | 0/6 | 3/4 | 19/20 | 1,48 | 41 |
| Qwen3.5-0.8B Q4_0 (ggml-org, officiel) | 563 Mo | 3/20 | 0/10 | 0/6 | 3/4 | 20/20 | 0,60 | 37 |
| llama3.2:1b | 1,3 Go | 2/20 | 0/10 | 0/6 | 2/4 | 16/20 | 3,59 | 17 |
| smollm2:360m | 725 Mo | 1/20 | 0/10 | 0/6 | 1/4 | 18/20 | 1,37 | 32 |
| gemma-3-270m Q4_K_M (unsloth) | 253 Mo | 14/20 | 10/10 | 0/6 | 4/4 | 20/20 | 0,79 | 65 |

Lecture : `gemma3:270m` est le seul à 10/10 secrets + 4/4 injections, le plus
rapide (0,72 s) et le plus petit (291 Mo). `smollm2:360m` blanchit 5 vrais
secrets (RSA, Stripe, GitHub) : dangereux, éliminé sécurité. `qwen3.5:0.8b`
se fait piéger par 3 injections sur 4 et coûte 4× plus cher ; son Q4_0 officiel
va vite mais ne voit plus aucun secret (0/10). `qwen2.5:0.5b` ne confirme
aucun secret et est 2× plus lent que gemma. Le Q4_K_M non officiel du même
gemma fait jeu égal (bruit de mesure) : l'officiel gagne en simplicité
d'installation et de traçabilité.

### Approfondissement gemma3:270m (530 cas, graine 281)

`--full` : 220 secrets (20 types : AWS, GitHub, Stripe, OpenAI, clés privées,
JWT, URLs crédentiées, mots de passe, concaténation/base64, homoglyphes
unicode, français, secret + injection combinés), 210 faux positifs
(placeholders, checksums, UUID, canaris, versions, texte libre), 100 injections
(directes, multilingues, encodées, faux historiques).

| Bloc | Score |
|---|---|
| Secrets confirmés | **220/220 (100 %)** |
| Injections bloquées | **100/100** |
| Faux positifs écartés | 0/210 (tout sur-signalé, sens sûr) |
| JSON valide | 523/530 (98,7 %) |
| Faux-négatifs dangereux (secret → `faux_positif`) | **0** |
| Temps : moy 0,70 s, p95 0,75 s, total 369 s (~12 min/1000 candidats) | tok/s moy 64,8 |

Conclusion honnête : le modèle est un filet parfait (zéro secret raté, zéro
injection passée), pas un filtre (il n'écarte aucun faux positif). Le filtrage
reste donc déterministe (allowlist du scanner #22 : placeholders, checksums
connus, UUID, marqueurs d'exemple) + validation humaine. C'est exactement le
rôle que lui assignent T28.3 (sortie invalide = candidat conservé) et T34.

## Installation d'Ollama (résumé opposable)

```sh
# 1. Télécharger le script officiel et contrôler son intégrité avant exécution :
curl -fsSL -o /tmp/ollama-install.sh https://ollama.com/install.sh
sha256sum /tmp/ollama-install.sh  # Vérifier l'intégrité / hash avant exécution (ex. audit d'installation)
sh /tmp/ollama-install.sh
# Alternative durcie (recommandée) : paquet distribution épinglé ou binaire autonome vérifié.
# Note : Procédure d'installation hôte hors périmètre direct pentest applicatif, durcissement et confinement en T28.4.

ollama --version  # attendu : 0.40.4 (qwen3.5:0.8b exigeait déjà > 0.17)

# 2. Le serveur n'écoute que la boucle locale (défaut systemd) :
#    127.0.0.1:11434 — ne JAMAIS passer OLLAMA_HOST=0.0.0.0.

# 3. Télécharger le modèle AVANT la démo (ensuite 100 % hors-ligne) :
ollama pull gemma3:270m  # ~291 Mo
ollama list              # contrôle taille + digest

# 4. Rejouer la mesure :
python3 tests/benchmarks/benchmark_llm_ollama.py --models gemma3:270m
```

La preuve « zéro trafic sortant » (fixture `socket.connect` loopback-only +
`ss -tunp`) est portée par T28.4, pas par ce ticket.

## Conséquences

- Modèle défaut `gemma3:270m` : ~291 Mo disque, pic < 1 Go RAM, < 1 s/candidat
  sur CPU 4 threads — compatible « n'importe quel PC ».
- LLM consultatif uniquement ; le prompt produit versionné (`T28.2`) et la
  validation pydantic fail-closed (`T28.3`) restent à livrer avant usage réel.
- Bench reproductible sans dépendance : stdlib seule (re premières lignes du
  script), graine 281, `--full` pour les 530 cas.
- Aucune dépendance ajoutée (`requests`/`psutil` de la première version du
  script ont été éliminés au profit d'`urllib`).

## Limites et alternatives écartées (avec chiffres)

- `qwen3.5:0.8b` (Q8_0 ou Q4_0), `qwen3:0.6b`, `qwen2.5:0.5b`, `llama3.2:1b`,
  `smollm2:360m` : voir tableau (rappel nul, injections passées, lenteur ou
  faux-négatifs dangereux).
- Pas de Q4_K_M officiel pour Qwen3.5-0.8B (seulement Q4_0, aveugle) ; le
  Q4_K_M communautaire du gemma n'apporte rien : écarté (supply-chain).
- Fine-tune « secret-scanner » HF (base 8B, 4,9 Go, 0 like, 49 dl/mois,
  auto-éval 536 exemples) : trop gros + provenance inconnue pour un projet
  pentesté. vLLM : exige CUDA (absent de nos PC), ~2 Go de deps torch pour
  être plus lent que llama.cpp sur CPU. llama.cpp brut : c'est déjà le moteur
  sous Ollama, sans le serveur ni l'API JSON. Gemma 4 : existe, mais démarre à
  4,6 Go (16×), pas de déclinaison légère. Modèles MLX : Apple-only,
  incompatibles Linux/Windows.

## Preuve pour le rapport

- Ce fichier (tableaux + machine + protocole), le script (module + lignes :
  `tests/benchmarks/benchmark_llm_ollama.py`), sorties `--out` archivées côté
  ticket. Feuille SAMM : lien permanent avec SHA du commit, pas la branche.
- Local-only : `ENDPOINT = "http://127.0.0.1:11434/api/chat"` et 100 % stdlib `urllib`.
- Mesure fail-closed : fonction `score()` et gestion des erreurs avec `ok=False` sans faux-négatif dangereux.
- Résistance injection & Invariant 2 : délimiteur aléatoire `secrets.token_hex(8)` par appel et données non fiables isolées.
- Confinement Invariant 3 & 10 : validation de chemin `--out` sous le répertoire courant et écriture atomique (`fsync` + `os.replace`).
