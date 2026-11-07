# Functional_and_security_Acceptance_Testing_Case — v1

Exécution : **2026-10-25**, Debian/WSL, Python 3.13.5, code
`ad54f025e224c5d3cdfa824a1117b5c616cc6e13`. Consolidation : [SAMM v1](samm-v1.md).
Cette matrice versionnée documente le périmètre du dépôt ; la feuille externe
est exclue à la demande du porteur.

**Pass** : tous les tests du groupe ont réussi sans skip. **Fail** : un seuil
ou critère n'est pas satisfait. **Partiel** : preuve limitée ou sous-cas ignorés.
**Non exécuté** : aucune preuve d'exécution de ce critère. Un skip ne vaut
jamais Pass. Les résultats ne remplacent pas la revue humaine avant fusion.

Les groupes automatisés ci-dessous sont une ventilation de **la même exécution
complète**, pas des exécutions indépendantes : **2 211 passed, 16 skipped,
4 480 subtests passed, 7 warnings**, couverture branches incluse **91,29 %**
(seuil 85 % atteint). Les sous-tests ne sont pas ajoutés aux 2 211 tests.
Les comptes et les sélecteurs par module sont dans [results.json](acceptance/results.json),
la sortie complète dans [pytest.log](acceptance/pytest.log).
Le rejeu de revue verse un [XML expurgé](acceptance/junit.xml) et un
[vérificateur indépendant](acceptance/recount_junit.py) pour recalculer les
comptes par module et groupe ; sa provenance est distincte du relevé initial.
Tous les cas ci-dessous ont été relevés le **2026-10-25**.

## Matrice et verdicts

| Cas | Fonction / sécurité et résultat attendu | Résultat observé | Verdict | Limite / suivi |
| --- | --- | --- | --- | --- |
| AC-01 | Contrats Finding, Vault et MCP | 70 réussis | **Pass** | Voir le périmètre ci-dessous. |
| AC-02 | Paquet, stack et confinement crypto | 38 réussis | **Pass** | Voir le périmètre ci-dessous. |
| AC-03 | Scanner signatures et interface | 408 réussis | **Pass** | Voir le périmètre ci-dessous. |
| AC-04 | Entropie de Shannon | 148 réussis | **Pass** | Voir le périmètre ci-dessous. |
| AC-05 | Allowlist explicite | 101 réussis | **Pass** | Voir le périmètre ci-dessous. |
| AC-06 | Oracle du corpus piège | 30 réussis | **Pass** | Voir le périmètre ci-dessous. |
| AC-07 | Précision ET rappel core >= 90 % | VP=10, FP=8, FN=0 ; précision **55,56 %**, rappel 100 % ; mesure **code 1** | **Fail** | Limite connue #21/#23/#24 ; conserver oracle/seuils et traiter les faux positifs via règles explicites auditées. |
| AC-08 | CLI scan et CI déterministe | 137 réussis | **Pass** | Voir le périmètre ci-dessous. |
| AC-09 | Serveur MCP en lecture seule | 294 réussis | **Pass** | Voir le périmètre ci-dessous. |
| AC-10 | Qualification LLM sans modèle réel | 154 réussis | **Pass** | Voir le périmètre ci-dessous. |
| AC-11 | Corpus injection | 100 réussis, 15 ignorés | **Partiel** | 15 preuves avec modèle réel ignorées : suivre #34/#97 ; pas de garantie sur un vrai modèle. |
| AC-12 | Journal des rejets LLM | 45 réussis | **Pass** | Voir le périmètre ci-dessous. |
| AC-13 | Vault API et intégration TestClient | 161 réussis | **Pass** | Voir le périmètre ci-dessous. |
| AC-14 | Clés API et isolation des projets | 31 réussis | **Pass** | Voir le périmètre ci-dessous. |
| AC-15 | Disponibilité et régressions Vault | 25 réussis | **Pass** | Voir le périmètre ci-dessous. |
| AC-16 | Chiffrement et stockage | 102 réussis | **Pass** | Voir le périmètre ci-dessous. |
| AC-17 | Client Vault push/pull/run et TLS | 203 réussis | **Pass** | Voir le périmètre ci-dessous. |
| AC-18 | Zéro egress, garde Python | 50 réussis | **Pass** | Voir le périmètre ci-dessous. |
| AC-19 | Modèle de menaces et exigences | 114 réussis | **Pass** | Voir le périmètre ci-dessous. |
| AC-20 | Ollama réel | 0 réussi, 1 ignoré | **Non exécuté** | Ollama local/modèle indisponible lors de ce relevé ; suivre #28/#80 et #97. |
| AC-21 | T39 : auth durcie, quotas, audit de tous les accès et abus/rejeu | Auth et quotas couverts en AC-13/14/15 ; pas de journal structuré de chaque accès 401/403 ni de campagne complète T39 attestée. | **Partiel** | #39/#111–114 : livrer et exécuter les preuves manquantes ; les tests statiques AC-19 ne suffisent pas. |
| AC-22 | Parcours hook → qualification → Y/N/E → remplacement | Aucun scénario intégré livré et exécuté ici ; scan en lecture seule et client Vault ne prouvent pas le remplacement. | **Non exécuté** | #30/#31/#32 : implémenter/raccorder le parcours puis archiver un scénario bout en bout. |
| AC-23 | Zéro egress au niveau OS / application intégrée | AC-18 couvre les wrappers Python ; aucune nouvelle trace strace ni modèle réel dans ce relevé. | **Non exécuté** | #82 et docs/security/zero-egress.md : rejouer strace -f avec filtre étendu, archiver trace et inspection humaine. |
| AC-24 | Revue croisée, CI distante et runner jetable | Qualité locale verte ; aucune approbation D, exécution distante CI (/ci) ni attestation runner éphémère produite ici. | **Non exécuté** | #20/#42 : obtenir revue D, check distant sur la PR et preuve du runner avant merge ; rendu #43/#125. |
| AC-25 | Gestion des clés par identifiant et enveloppe complète | Inspection : encrypt_at_rest et decrypt_for_recipient lèvent NotImplementedError ; VaultCipher AES-GCM est testé séparément. | **Fail** | #26 : livrer le chemin KEK/DEK et les tests ; ne pas déduire sa livraison d’AC-16. |

## Sélecteurs et portée exacte des preuves automatisées

Pour reproduire un groupe : `python -m pytest <sélecteurs> -q` depuis la racine
avec les dépendances du projet. Les résultats archivés proviennent cependant
de la suite complète, dans l'environnement décrit dans [t42-validation.md](t42-validation.md).

| Cas | Sélecteurs pytest | Portée / limite |
| --- | --- | --- |
| AC-01 | `tests/contracts/*.py` | Schemas valides, erreurs et surface fermee ; aucune preuve de deploiement. |
| AC-02 | `tests/test_package.py tests/test_ticket17_acceptance.py tests/test_crypto_confinement.py` | Installation et frontiere crypto ; pas de preuve supply-chain par ce seul test. |
| AC-03 | `tests/test_scanner_detect.py tests/test_scanner_signatures.py tests/test_scanner_interface.py` | Signatures, chemins, exclusions, erreurs et contrat Finding. |
| AC-04 | `tests/test_scanner_entropy.py` | Seuils et contexte ; la precision globale est jugee separement en AC-07. |
| AC-05 | `tests/test_scanner_allowlist.py` | Configuration auditable, refus des regles aveugles et fail-closed. |
| AC-06 | `tests/test_trap_acceptance.py` | 34 cas synthetiques ; le test valide aussi les faux positifs connus, pas le seuil de 90 %. |
| AC-08 | `tests/test_cli_scan.py` | Worktree/index, JSON masque, codes 0/1/2 et configurations non fiables. |
| AC-09 | `tests/test_mcp_*.py` | Stdio, registre borne, chemins confines, diff et fichiers masques. |
| AC-10 | `tests/test_llm_qualify.py tests/test_benchmark_llm_ollama.py` | JSON ferme, reponses malformees et erreurs avec transports factices. |
| AC-11 | `tests/test_prompt_injection_corpus.py` | Separations de roles, delimitateurs et requetes MCP hostiles ; skips reels exclus du Pass. |
| AC-12 | `tests/test_llm_rejections.py` | Append durable, chaine, concurrence, consultation et aucun pouvoir en CI. |
| AC-13 | `tests/test_vault_app.py tests/test_vault_early_rejections.py tests/test_vault_integration_testclient.py` | POST/GET, 400/401/403/409/429, limites et absence de valeur dans les reponses de creation. |
| AC-14 | `tests/test_vault_auth.py` | Emission, revocation, HMAC et autorisation avant recherche de ressource. |
| AC-15 | `tests/test_vault_review_regressions.py tests/test_vault_availability.py` | Pannes fail-closed, quotas inter-workers, garde des buckets ; pas de campagne de charge T39. |
| AC-16 | `tests/test_vault_crypto.py tests/test_vault_falsification.py tests/test_vault_db.py` | AES-GCM, nonce, AAD, falsification et contraintes SQLite ; pas de chiffrement par enveloppe complet. |
| AC-17 | `tests/test_vault_client.py tests/test_vault_cli.py tests/test_vault_tls.py tests/test_vault_integration_client_server.py` | Echanges ASGI et TLS local, ecritures atomiques et garde des variables ; pas de deploiement reel. |
| AC-18 | `tests/test_network_isolation.py` | Scan CI reel sous garde Python ; limites aliases precoces, natif et AF_UNIX documentees. |
| AC-19 | `tests/security/*.py tests/test_check_model.py` | Coherence documentaire et assertions statiques ; ne suffit pas a prouver les defenses runtime. |
| AC-20 | `tests/test_llm_qualify_ollama.py` | Modele local absent ou non active : aucun Pass sur une preuve ignoree. |

## Détail de la mesure et limites connues

[trap-report.json](acceptance/trap-report.json) est la sortie de
`python tests/measure_trap.py` (code 1, journal dans [checks.log](acceptance/checks.log)).
Sur les 34 cas synthétiques, 10 secrets en clair sont détectés, 8 des 18
non-secrets sont signalés, 2 des 6 secrets obfusqués sont détectés et 4 restent
manqués. Les faux positifs sont les formes UUID, SHA-256, commit et intégrité
dans les deux langages. Sur **all** : VP=12, FP=8, FN=4,
précision 60 %, rappel 75 %. Les quatre positions manquées sont listées dans
le JSON. Les 34 cas ne sont pas une mesure de qualité sur du code arbitraire.

Cet échec est déjà documenté dans [T23](t23-samm.md) et figé par
`test_scanner_precision_and_recall_without_implicit_allowlist` : ce test
**passe parce qu'il vérifie les comptes réels**, alors que le critère produit
AC-07 **échoue**. Aucun seuil n'a été abaissé et aucune allowlist implicite
n'a été ajoutée. La limite est reportée ici plutôt que créer un doublon de ticket.

Les 16 skips se décomposent en 15 cas d'injection avec modèle réel (#97) et
1 test de qualification Ollama (#80). Les raisons exactes figurent dans
`results.json` (`skipped`). Pour réévaluer ces cas, fournir Ollama et le modèle
local conformes à ADR-004 ; activer les injections avec
`HEIMDALL_RUN_LLM_TESTS=1 python -m pytest tests/test_prompt_injection_corpus.py -m llm`.
Archiver une nouvelle date, un SHA testé, la version du modèle et les résultats.

## Décision pour le rapport partie 1

**17 Pass, 2 Fail, 2 Partiel, 4 Non exécuté.** La consolidation et l'exécution
sont livrées ; l'acceptation globale du MVP reste **non acquise**.
Chaque échec ou preuve manquante a un ticket de suivi et une action ci-dessus.
Ne cocher ni « toutes les exigences produit passent », ni « CI distante verte »,
ni « revue approuvée » à partir de cette validation locale.
Le [suivi de revue et des conditions de fusion](t42-review.md) conserve AC-24
ouvert tant que la CI distante, la revue D et le runner jetable ne sont pas
tous attestés. Le lancement de `/ci` et son résultat sont consignés dans la PR.
