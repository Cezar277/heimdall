# Modèle de menaces Heimdall — T18

Version de travail du 12 octobre 2026, à relire par l'équipe. Périmètre :
[#18](https://github.com/Cezar277/heimdall/issues/18), sous-tickets #45 à #48.
Les quatre volets sont regroupés sur la branche du parent à la demande du
porteur ; cette exception au découpage habituel doit être signalée dans la PR.

## Parcours de lecture

1. [DFD niveau 1 et registre des flux](dfd.md) — #45 ; [source draw.io](dfd.drawio), [image PNG](dfd.png).
2. [Actifs et frontières de confiance](assets-and-boundaries.md) — #46.
3. [Matrice STRIDE et scénarios](stride.md) — #47.
4. [Priorisation et exigences proposées pour #19](risks.md) — #48.
5. [Relecture et preuves SAMM](review-and-evidence.md).

## Ce qui a été examiné

Référence de l'analyse : commit
[`1d1b8ff7caa8343a99830485e3bf7c0565da4fd1`](https://github.com/Cezar277/heimdall/tree/1d1b8ff7caa8343a99830485e3bf7c0565da4fd1).
Les liens relatifs ci-dessous servent à maintenir le modèle ; le SHA fixe
l'état observé. Les évolutions après ce commit nécessitent une nouvelle revue.

| Source | Observation, et limite de la preuve |
| --- | --- |
| [CLI](../../heimdall/cli/main.py) | `scan`, y compris `--ci`, refuse actuellement avec le code 2 ; pas de scan opérationnel. |
| [Scanner](../../heimdall/scanner/detect.py) | Squelette ; `find_candidates` lève `NotImplementedError`. |
| [MCP](../../heimdall/mcp/server.py) | Registre de quatre outils ; démarrage stdio non implémenté. |
| [Client Vault](../../heimdall/vault/client.py) | Validation d'URL HTTPS loopback et de credential ; pas de client HTTP opérationnel. |
| [Crypto Vault](../../heimdall/vault/crypto.py) | Chiffrement/déchiffrement non implémentés. |
| [Finding](../contracts/finding.md), [ADR-001](../adr/001-finding-et-etats.md) | Contrat sans secret brut, empreinte HMAC, états et validation humaine ; pas de preuve d'exécution. |
| [MCP v1](../contracts/mcp-tools.md) | Masquage, racine fixe, outils en lecture seule, snapshots et limites sont des exigences à implémenter. |
| [Vault v1](../contracts/vault-api.md), [OpenAPI](../../openapi.yaml) | Contrat TLS, auth, erreurs et données ; la fixture de tests n'est pas un serveur de production. |
| [ADR-002](../adr/002-stack-python.md) | Stack et confinement du code cryptographique. |
| [CI contrats](../../.github/workflows/vault-contract.yml) | Runner `self-hosted`, exécution de tests du dépôt, téléchargements de dépendances à l'installation. |

Le DFD décrit les **flux prévus par les contrats**, pas des flux runtime déjà
observés. Les risques sont évalués avant mitigation. Aucune mesure proposée
ci-dessous ne devient « implémentée » grâce à sa seule présence dans ce document.

## Hypothèses et désaccords à résoudre

| ID | Constat | Décision attendue / suivi |
| --- | --- | --- |
| H1 | Le contrat Vault autorise un serveur sur réseau privé ; le client actuel accepte exclusivement `127.0.0.1`, `::1`, `localhost`. | #25/#26 et #19 : choisir le déploiement autorisé et aligner client, contrat, certificats et DFD. F09 reste loopback dans la base actuelle ; réseau privé distant conditionnel. Aucun accès Internet runtime. |
| H2 | Le parcours produit prévoit récupération des secrets et `.env` ; la docstring crypto dit que la CLI ne manipule que des références. | #25/#26/#32 : désigner le processus destinataire du GET et responsable de l'écriture protégée. Le DFD expose le flux sensible envisagé F09/F10, sans affirmer cette décision acquise. |
| H3 | `propose_patch` ne retourne qu'un aperçu masqué et un `proposal_id` ; la remise du patch réel à la CLI n'est pas définie comme canal implémenté. | #27/#30/#32 : définir le canal interne, la liaison au snapshot et le propriétaire du patch. Aucun cinquième outil MCP ajouté ici ; aucune valeur brute dans F05/F06. |
| H4 | L'énoncé #45 mentionne CI → Vault, mais le scan CI déterministe n'en a pas besoin et aucun appel n'existe. | #19/#25/#26 : F14 est un usage conditionnel pour un job autorisé distinct. Décider droits et injection du credential ; jamais dans un job de PR non fiable. |
| H5 | Ollama ne communique pas directement avec stdio MCP ; le squelette n'a pas encore d'orchestrateur. | #27/#28 : orchestration proposée dans le processus CLI ; valider avant implémentation. |
| H6 | Le Finding exige un HMAC local ; ADR-002 confine la crypto au Vault. | Interface précisée par #22 : HMAC-SHA-256 de la bibliothèque standard, clé locale `0600` hors dépôt, propriétaire vérifié, `ScanError` si le stockage est indisponible. La KEK et les clés API restent l'affaire du Vault ; l'invariant 5 (`cryptography`/`argon2` confinés à `vault/crypto.py`) est inchangé. |
| H7 | SQLite et les journaux sont prévus, sans implémentation de stockage ni politique complète de sauvegarde/rétention. | #25/#33 et #19 : formaliser droits, reprise, conservation et audit. D4 agrège des journaux locaux distincts, pas un collecteur réseau. |

Ces points restent ouverts : ils ne justifient ni un contournement TLS, ni
un accès direct du LLM au Vault, ni l'acceptation d'un scan incomplet.

**Condition de fusion H1/H4 :** obtenir dans #19 un engagement écrit du
porteur : tant que ces décisions ne sont pas arbitrées, seules les cibles
`127.0.0.1`, `::1` et `localhost` avec TLS vérifié sont autorisées pour le
client. Les flux distants représentés restent hypothétiques et n'autorisent
aucun déploiement. Toute ouverture distante exige une PR dédiée alignant
contrat, client, TLS/SAN, authentification/droits, quotas, tests et DFD.
L'engagement dans #19 reste à publier et à faire valider avant fusion.

## Maintenir ce modèle

À chaque modification de contrat, outil MCP, endpoint, droit, stockage,
transport, hook ou runner, le porteur met à jour les flux Fxx, frontières
Bxx, scénarios et scores concernés dans la même PR. Conserver les identifiants
existants ; ne pas recycler un risque retiré. Le relecteur d'un autre domaine
vérifie ces changements. Refaire la revue d'équipe avant l'audit croisé et
après résolution de H1–H7. Le risque résiduel n'est accepté qu'avec décideur,
justification, date et preuve : aucun risque n'est accepté par défaut ici.
