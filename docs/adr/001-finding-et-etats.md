# ADR-001 — Finding v1 et états du secret

Statut : proposé, à relire par les quatre membres. Ticket : #14.

## Contexte

Le scanner, le MCP, la CLI et le Vault partagent un contrat sans valeur de
secret. Le scanner reste déterministe ; une suggestion du LLM n'est pas une
décision. La CI doit bloquer un secret en clair, indépendamment de son état.

## Décisions

- Les sept champs du ticket sont obligatoires. Aucune propriété supplémentaire
  n'est acceptée. `type` reste un identifiant extensible pour ne pas figer les
  détecteurs avant leur implémentation.
- `entropy` mesure les octets UTF-8 du candidat, entre 0 et 8 bits par octet.
- `snippet_hash` est un HMAC-SHA-256 du candidat avec une clé locale aléatoire
  de 32 octets, stockée hors dépôt. Un simple SHA-256 exposerait les secrets de
  faible entropie aux attaques par dictionnaire. Ne jamais transmettre la clé
  dans un Finding ni la journaliser. Ce hash est une empreinte, pas un secret
  récupérable, un identifiant global ou une preuve d'autorisation.
- Cette empreinte est calculée avec `hmac`/`hashlib` de la bibliothèque
  standard, dans `heimdall/scanner/hashing.py`. Ce n'est pas la crypto du Vault :
  l'invariant 5 confine `cryptography`/`argon2` à `heimdall/vault/crypto.py` et
  reste intact (ADR-002, clarification T22). La clé de signature est locale,
  distincte de la KEK et des clés API ; un stockage indisponible fait lever
  `ScanError` au lieu d'une clé éphémère.
- L'empreinte est stable pour une même clé locale. Un autre poste ou une
  rotation de clé donne une autre empreinte : aucune déduplication interposte
  n'est garantie. L'identité du Vault sera définie dans son propre contrat.
- Le faux positif devient `faux_positif`, uniquement après validation humaine.
  Il peut revenir à `detecte` lors d'un réexamen. Son état seul ne constitue
  pas une exemption CI : une éventuelle politique d'exemption doit être
  explicitement approuvée et définie dans le ticket concerné.
- Le schéma valide un instantané. Les transitions et leur autorisation doivent
  être contrôlées par le code consommateur ; changer `status` dans un JSON ne
  prouve pas qu'une transition a eu lieu.

## Conséquences et limites

Le contrat ne contient ni valeur brute, ni extrait de code libre. Un consommateur
doit aussi empêcher les secrets dans les champs textuels autorisés : le schéma
ne peut pas reconnaître toute valeur secrète. Les journaux doivent suivre la
même règle. L'empreinte reste une métadonnée corrélable à protéger.

La validation du chemin est lexicale. Avant toute lecture ou écriture, le
consommateur doit résoudre le chemin et les liens symboliques, puis vérifier
qu'il reste dans le dépôt. `source: llm` décrit un signal consultatif local ;
il ne remplace jamais le résultat du scanner en CI.

Cette décision propose les états partagés à #40 ; la rotation effective,
l'authentification, la concurrence et la persistance du Vault restent dans
ses tickets d'implémentation.
