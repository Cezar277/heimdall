# Actifs et frontières de confiance — #46

Référence : [DFD et flux](dfd.md), [hypothèses H1–H7](README.md).
Les protections décrites sont des exigences ou propositions ; leur présence
dans un contrat ne prouve ni droits OS ni masquage ni chiffrement effectifs.

## Actifs

| ID | Actif / emplacement | Pourquoi le protéger | Propriété prioritaire / responsabilité prévue |
| --- | --- | --- | --- |
| A01 | Secrets bruts : D1, mémoire P2/P3/P4/P5, réponse GET, `.env` D2 | Un vol donne accès au service tiers ; une copie Git persiste. | Confidentialité/intégrité ; #22/#25/#26/#27/#32. |
| A02 | Clé maîtresse / KEK, hôte Vault hors D3 | Permet de déchiffrer de multiples secrets ; sa perte bloque la récupération. | Confidentialité/disponibilité ; séparation, sauvegarde et rotation #25/#40, exigence #19. |
| A03 | Credentials API clients D2 / job autorisé ; vérificateurs D3 | Autorisent des accès projet/environnement/opération ; le serveur ne stocke pas le credential brut. | Confidentialité/authenticité ; #25/#26. |
| A04 | Clé HMAC locale, hors dépôt ; empreintes Finding | Sa fuite rend les attaques sur candidats faibles plus faciles ; sa perte invalide la corrélation locale. | Confidentialité/intégrité ; ADR-001 ; interface et durcissement précisés par #22 (clé `0600`, propriétaire vérifié, parent `0700`, `ScanError` si indisponible). |
| A05 | SQLite, métadonnées, ciphertext, backups D3 | Chiffrement seul n'empêche pas substitution, rollback ou destruction. | Intégrité/disponibilité/confidentialité ; #25/#40. |
| A06 | Dépôt, index, historique et configuration Git D1 | Historique irréversible partagé ; injection, chemins et index peuvent tromper le scan. | Intégrité/confidentialité ; #22/#27/#30 et #19. |
| A07 | `.env` et fichiers privés D2, historique shell/terminal | Droits trop larges, sauvegardes et commandes peuvent exposer les credentials. | Confidentialité ; droits OS restreints, pas d'arguments sensibles #26/#32 et #19. |
| A08 | Logs D4, preuve de décisions et accès | Absence/modification empêche l'audit ; contenu libre peut fuiter ou forger des lignes. | Intégrité/confidentialité/disponibilité ; #33/#25 et #19. |
| A09 | Findings, snapshots et propositions P2/P3/P4 | Lier verdict, fichier et approbation évite faux négatifs et patch obsolète. | Intégrité/authenticité ; #14/#27/#30/#32. |
| A10 | Configuration, dépendances, hook et runner E3 | Un binaire ou un job modifié obtient les droits du développeur/runner. | Intégrité/moindre privilège ; #17 et exigences #19. |
| A11 | Budget CPU/RAM/disque, disponibilité Ollama/Vault/CI | Gros diff, regex coûteuse, génération ou requêtes saturent le poste/service. | Disponibilité ; #22/#27/#28/#25 et #19. |

## Frontières rouges du DFD

| ID | Séparation et flux | Vérifications au franchissement | Suivi |
| --- | --- | --- | --- |
| B1 | D1 non fiable → scanner/MCP (F04/F07), puis contexte vers LLM (F05/F06) ; écriture inverse F11 | Fixer racine et snapshot ; valider types/tailles/chemins, résoudre symlinks sans course exploitable, désactiver exécution Git ; masquer avant sérialisation ; ne pas exécuter le code analysé. | #22/#27/#30/#34. |
| B2 | Réponses et demandes Ollama → orchestrateur → outils MCP (F06/F05) | Allowlist exacte de quatre outils, arguments stricts, racine non modifiable, quotas/délais, aucune écriture/réseau/exec ; refuser sorties malformées ; validation humaine hors LLM. | #27/#28/#32/#34. |
| B3 | Poste → service Vault (F09) et Vault → client | TLS chaîne/SAN vérifiés ; auth puis droits projet/env/opération avant recherche ; schémas, tailles et quotas ; réponses constantes sans reflet et `no-store` ; vérifier les réponses côté client. Existe même en loopback. | #25/#26 ; H1/H2. |
| B4 | Runner → Vault (F14 conditionnel) ; runner → son checkout/CLI (F15) | Job et provenance approuvés, runner isolé, clé dédiée minimale hors PR non fiable ; mêmes contrôles serveur que B3. `scan --ci` sans LLM, sans bypass et sans credential Vault nécessaire. | #19/#25/#26 ; H4. |
| B5 | Processus → stockages OS (D2/D3/D4), F10/F12/F13 | Permissions minimales (ACL Windows ou modes POSIX équivalents), absence de symlinks sortants aux écritures, écritures atomiques, chiffrement authentifié et séparation des clés, logs sans secrets, backups/restauration testés. | #25/#26/#30/#33/#40 et exigences #19. |

B2 est une frontière **d'autorité**, pas une simple séparation de processus :
un modèle local reste non fiable. B3/B4 sont distinctes car les identités et
la confiance dans le job ne sont pas celles du développeur. B5 regroupe
plusieurs stockages locaux ; elle ne crée pas un disque partagé entre hôtes.
Le contrôle de chemin est réévalué lors de l'utilisation, pas seulement à
la réception de la chaîne JSON.

## Adversaires et limites

Un contributeur peut fournir du code, des noms et configurations Git hostiles ;
un modèle peut retourner une instruction malveillante ; un utilisateur local
ou réseau non autorisé peut joindre un service ; un projet légitime peut
tenter d'accéder à un autre ; un mainteneur peut exposer/perdre une clé par
erreur ; un job de PR peut tenter de persister sur le runner partagé.

On n'assume pas de compromission préalable du noyau, de l'administrateur
du poste ou de l'hyperviseur : elle permet de lire la mémoire autorisée et
sort du pouvoir de protection de l'outil. Ce risque résiduel doit être
signalé au déploiement. Les symlinks, permissions faibles et erreurs humaines
ordinaires restent dans le périmètre. « Local » n'implique ni absence
d'attaquant ni absence d'authentification.
