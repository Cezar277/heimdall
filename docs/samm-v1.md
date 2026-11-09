# Consolidation SAMM v1 — T42

Relevé du **25 octobre 2026**, sur le code `ad54f025e224c5d3cdfa824a1117b5c616cc6e13`
(révision commune à la branche T42 et à `origin/main` lors du fetch).
Ticket : [#42](https://github.com/Cezar277/heimdall/issues/42), épic #7,
rapport partie 1 / #43. Porteur A, relecteur attendu D.

Cette consolidation fournit les réponses, dates et preuves utilisables dans le
rapport. La feuille externe est laissée de côté à la demande du porteur.
Aucun score de maturité SAMM ni validation humaine n'est inventé.
« Oui » vaut seulement pour le périmètre décrit et les tests associés.
Les liens épinglent le SHA **du code testé**, pas un nom de branche.

La [matrice d'acceptation](Functional_and_security_Acceptance_Testing_Case.md)
sépare les tests de régression verts du verdict produit : le seuil de précision
reste en échec. Le [relevé d'exécution](t42-validation.md) archive commandes,
environnement, résultats et limites. Tous les contrôles du tableau sont datés
**2026-10-25** ; les documents historiques gardent leur propre date.

## Réponses consolidées et preuves courantes

| Ticket | Contrôle | Réponse au 2026-10-25 | Module + ligne (SHA testé) | Preuve / test | Acceptation |
| --- | --- | --- | --- | --- | --- |
| #12 | Gouvernance et revue | Oui, documentaire | [CONTRIBUTING.md:1](https://github.com/Cezar277/heimdall/blob/ad54f025e224c5d3cdfa824a1117b5c616cc6e13/CONTRIBUTING.md#L1) | [docs/DEFINITION_OF_DONE.md:1](https://github.com/Cezar277/heimdall/blob/ad54f025e224c5d3cdfa824a1117b5c616cc6e13/docs/DEFINITION_OF_DONE.md#L1) | AC-19 |
| #14 | Finding et états | Oui, contrat | [schemas/finding.schema.json:1](https://github.com/Cezar277/heimdall/blob/ad54f025e224c5d3cdfa824a1117b5c616cc6e13/schemas/finding.schema.json#L1) | [tests/contracts/test_finding_schema.py:1](https://github.com/Cezar277/heimdall/blob/ad54f025e224c5d3cdfa824a1117b5c616cc6e13/tests/contracts/test_finding_schema.py#L1) | AC-01 |
| #15 | API Vault v1 | Oui, contrat | [openapi.yaml:1](https://github.com/Cezar277/heimdall/blob/ad54f025e224c5d3cdfa824a1117b5c616cc6e13/openapi.yaml#L1) | [tests/contracts/test_vault_openapi.py:1](https://github.com/Cezar277/heimdall/blob/ad54f025e224c5d3cdfa824a1117b5c616cc6e13/tests/contracts/test_vault_openapi.py#L1) | AC-01 |
| #16 | Surface MCP déclarée | Oui, contrat | [schemas/mcp-tools.schema.json:1](https://github.com/Cezar277/heimdall/blob/ad54f025e224c5d3cdfa824a1117b5c616cc6e13/schemas/mcp-tools.schema.json#L1) | [tests/contracts/test_mcp_tools_schema.py:1](https://github.com/Cezar277/heimdall/blob/ad54f025e224c5d3cdfa824a1117b5c616cc6e13/tests/contracts/test_mcp_tools_schema.py#L1) | AC-01 |
| #17 | Stack et confinement crypto | Oui | [pyproject.toml:1](https://github.com/Cezar277/heimdall/blob/ad54f025e224c5d3cdfa824a1117b5c616cc6e13/pyproject.toml#L1) | [tests/test_crypto_confinement.py:1](https://github.com/Cezar277/heimdall/blob/ad54f025e224c5d3cdfa824a1117b5c616cc6e13/tests/test_crypto_confinement.py#L1) | AC-02 |
| #18 | DFD, STRIDE et risques | Oui, documentaire | [docs/security/dfd.md:1](https://github.com/Cezar277/heimdall/blob/ad54f025e224c5d3cdfa824a1117b5c616cc6e13/docs/security/dfd.md#L1) | [tests/test_check_model.py:1](https://github.com/Cezar277/heimdall/blob/ad54f025e224c5d3cdfa824a1117b5c616cc6e13/tests/test_check_model.py#L1) | AC-19 |
| #19 | Exigences et abuse cases | Oui, documentaire | [docs/security/requirements.md:1](https://github.com/Cezar277/heimdall/blob/ad54f025e224c5d3cdfa824a1117b5c616cc6e13/docs/security/requirements.md#L1) | [tests/security/test_requirements_traceability.py:1](https://github.com/Cezar277/heimdall/blob/ad54f025e224c5d3cdfa824a1117b5c616cc6e13/tests/security/test_requirements_traceability.py#L1) | AC-19 |
| #20 | Qualite et CI | Partiel : controles locaux ; CI distante non executee | [.github/workflows/ci.yml:1](https://github.com/Cezar277/heimdall/blob/ad54f025e224c5d3cdfa824a1117b5c616cc6e13/.github/workflows/ci.yml#L1) | [tests/security/test_ci_workflow_static.py:1](https://github.com/Cezar277/heimdall/blob/ad54f025e224c5d3cdfa824a1117b5c616cc6e13/tests/security/test_ci_workflow_static.py#L1) | AC-24 |
| #21 | Oracle du corpus piège | Oui pour oracle ; Non pour seuil de precision | [tests/support/trap_corpus.py:81](https://github.com/Cezar277/heimdall/blob/ad54f025e224c5d3cdfa824a1117b5c616cc6e13/tests/support/trap_corpus.py#L81) | [tests/test_trap_acceptance.py:204](https://github.com/Cezar277/heimdall/blob/ad54f025e224c5d3cdfa824a1117b5c616cc6e13/tests/test_trap_acceptance.py#L204) | AC-06/07 |
| #22/#54 | Signatures et exclusions | Oui sur les scenarios testes | [heimdall/scanner/signature_engine.py:62](https://github.com/Cezar277/heimdall/blob/ad54f025e224c5d3cdfa824a1117b5c616cc6e13/heimdall/scanner/signature_engine.py#L62) | [tests/test_scanner_signatures.py:1](https://github.com/Cezar277/heimdall/blob/ad54f025e224c5d3cdfa824a1117b5c616cc6e13/tests/test_scanner_signatures.py#L1) | AC-03 |
| #53 | Interface Scanner/Finding | Oui | [heimdall/scanner/interface.py:287](https://github.com/Cezar277/heimdall/blob/ad54f025e224c5d3cdfa824a1117b5c616cc6e13/heimdall/scanner/interface.py#L287) | [tests/test_scanner_interface.py:1](https://github.com/Cezar277/heimdall/blob/ad54f025e224c5d3cdfa824a1117b5c616cc6e13/tests/test_scanner_interface.py#L1) | AC-03 |
| #23 | Détection par entropie | Oui ; precision globale insuffisante | [heimdall/scanner/entropy_detection.py:161](https://github.com/Cezar277/heimdall/blob/ad54f025e224c5d3cdfa824a1117b5c616cc6e13/heimdall/scanner/entropy_detection.py#L161) | [tests/test_scanner_entropy.py:1](https://github.com/Cezar277/heimdall/blob/ad54f025e224c5d3cdfa824a1117b5c616cc6e13/tests/test_scanner_entropy.py#L1) | AC-04/07 |
| #24 | Allowlist explicite et auditable | Oui | [heimdall/scanner/allowlist.py:944](https://github.com/Cezar277/heimdall/blob/ad54f025e224c5d3cdfa824a1117b5c616cc6e13/heimdall/scanner/allowlist.py#L944) | [tests/test_scanner_allowlist.py:1](https://github.com/Cezar277/heimdall/blob/ad54f025e224c5d3cdfa824a1117b5c616cc6e13/tests/test_scanner_allowlist.py#L1) | AC-05 |
| #25/#62 | SQLite chiffre et integrite | Oui pour le backend livre | [heimdall/vault/database.py:616](https://github.com/Cezar277/heimdall/blob/ad54f025e224c5d3cdfa824a1117b5c616cc6e13/heimdall/vault/database.py#L616) | [tests/test_vault_db.py:1](https://github.com/Cezar277/heimdall/blob/ad54f025e224c5d3cdfa824a1117b5c616cc6e13/tests/test_vault_db.py#L1) | AC-16 |
| #25/#65 | Integration API/TestClient | Oui en ASGI sur bases temporaires | [heimdall/vault/app.py:1128](https://github.com/Cezar277/heimdall/blob/ad54f025e224c5d3cdfa824a1117b5c616cc6e13/heimdall/vault/app.py#L1128) | [tests/test_vault_integration_testclient.py:238](https://github.com/Cezar277/heimdall/blob/ad54f025e224c5d3cdfa824a1117b5c616cc6e13/tests/test_vault_integration_testclient.py#L238) | AC-13 |
| #27 | MCP confine et lecture seule | Oui | [heimdall/mcp/server.py:660](https://github.com/Cezar277/heimdall/blob/ad54f025e224c5d3cdfa824a1117b5c616cc6e13/heimdall/mcp/server.py#L660) | [tests/test_mcp_server.py:1](https://github.com/Cezar277/heimdall/blob/ad54f025e224c5d3cdfa824a1117b5c616cc6e13/tests/test_mcp_server.py#L1) | AC-09 |
| #28/#79-81 | Qualification Ollama locale | Partiel : transports factices valides ; modele reel ignore | [heimdall/llm/qualify.py:112](https://github.com/Cezar277/heimdall/blob/ad54f025e224c5d3cdfa824a1117b5c616cc6e13/heimdall/llm/qualify.py#L112) | [tests/test_llm_qualify.py:1](https://github.com/Cezar277/heimdall/blob/ad54f025e224c5d3cdfa824a1117b5c616cc6e13/tests/test_llm_qualify.py#L1) | AC-10/20 |
| #29 | Scan deterministe et fail-closed | Oui | [heimdall/cli/scan.py:169](https://github.com/Cezar277/heimdall/blob/ad54f025e224c5d3cdfa824a1117b5c616cc6e13/heimdall/cli/scan.py#L169) | [tests/test_cli_scan.py:1](https://github.com/Cezar277/heimdall/blob/ad54f025e224c5d3cdfa824a1117b5c616cc6e13/tests/test_cli_scan.py#L1) | AC-08 |
| #33 | Journal des rejets et CI sans pouvoir LLM | Oui sur la fonction livree ; dialogue humain reste #32 | [heimdall/llm/rejections.py:239](https://github.com/Cezar277/heimdall/blob/ad54f025e224c5d3cdfa824a1117b5c616cc6e13/heimdall/llm/rejections.py#L239) | [tests/test_llm_rejections.py:135](https://github.com/Cezar277/heimdall/blob/ad54f025e224c5d3cdfa824a1117b5c616cc6e13/tests/test_llm_rejections.py#L135) | AC-12 |
| #34 | Defense contre injection | Partiel : 100 tests deterministes ; 15 preuves reelles ignorees | [heimdall/mcp/prompts/__init__.py:111](https://github.com/Cezar277/heimdall/blob/ad54f025e224c5d3cdfa824a1117b5c616cc6e13/heimdall/mcp/prompts/__init__.py#L111) | [tests/test_prompt_injection_corpus.py:1](https://github.com/Cezar277/heimdall/blob/ad54f025e224c5d3cdfa824a1117b5c616cc6e13/tests/test_prompt_injection_corpus.py#L1) | AC-11 |
| #35 | Client push/pull/run | Oui dans le perimetre teste | [heimdall/vault/client.py:108](https://github.com/Cezar277/heimdall/blob/ad54f025e224c5d3cdfa824a1117b5c616cc6e13/heimdall/vault/client.py#L108) | [tests/test_vault_integration_client_server.py:1](https://github.com/Cezar277/heimdall/blob/ad54f025e224c5d3cdfa824a1117b5c616cc6e13/tests/test_vault_integration_client_server.py#L1) | AC-17 |
| #64 | Clés API et autorisation par projet | Oui | [heimdall/vault/auth.py:856](https://github.com/Cezar277/heimdall/blob/ad54f025e224c5d3cdfa824a1117b5c616cc6e13/heimdall/vault/auth.py#L856) | [tests/test_vault_auth.py:1](https://github.com/Cezar277/heimdall/blob/ad54f025e224c5d3cdfa824a1117b5c616cc6e13/tests/test_vault_auth.py#L1) | AC-14 |
| #67 | AES-256-GCM, nonce et AAD | Oui pour VaultCipher ; enveloppe complete non attestee | [heimdall/vault/crypto.py:206](https://github.com/Cezar277/heimdall/blob/ad54f025e224c5d3cdfa824a1117b5c616cc6e13/heimdall/vault/crypto.py#L206) | [tests/test_vault_crypto.py:1](https://github.com/Cezar277/heimdall/blob/ad54f025e224c5d3cdfa824a1117b5c616cc6e13/tests/test_vault_crypto.py#L1) | AC-16 |
| #68 | Refus des falsifications | Oui | [heimdall/vault/crypto.py:281](https://github.com/Cezar277/heimdall/blob/ad54f025e224c5d3cdfa824a1117b5c616cc6e13/heimdall/vault/crypto.py#L281) | [tests/test_vault_falsification.py:1](https://github.com/Cezar277/heimdall/blob/ad54f025e224c5d3cdfa824a1117b5c616cc6e13/tests/test_vault_falsification.py#L1) | AC-16 |
| #82 | Absence de trafic externe | Partiel : garde Python ; trace OS non rejouee | [tests/test_network_isolation.py:530](https://github.com/Cezar277/heimdall/blob/ad54f025e224c5d3cdfa824a1117b5c616cc6e13/tests/test_network_isolation.py#L530) | [docs/security/zero-egress.md:1](https://github.com/Cezar277/heimdall/blob/ad54f025e224c5d3cdfa824a1117b5c616cc6e13/docs/security/zero-egress.md#L1) | AC-18/23 |
| #39/#111-114 | Auth durcie, quotas et audit de chaque acces | Partiel : auth/quotas testes ; audit complet et campagne de rejeu/charge non attestes | [heimdall/vault/ratelimit.py:186](https://github.com/Cezar277/heimdall/blob/ad54f025e224c5d3cdfa824a1117b5c616cc6e13/heimdall/vault/ratelimit.py#L186) | [tests/test_vault_review_regressions.py:1](https://github.com/Cezar277/heimdall/blob/ad54f025e224c5d3cdfa824a1117b5c616cc6e13/tests/test_vault_review_regressions.py#L1) | AC-15/21 |
| #26 | Chiffrement par enveloppe / clés par identifiant | Non : API historique non implementee | [heimdall/vault/crypto.py:322](https://github.com/Cezar277/heimdall/blob/ad54f025e224c5d3cdfa824a1117b5c616cc6e13/heimdall/vault/crypto.py#L322) | [heimdall/vault/crypto.py:331](https://github.com/Cezar277/heimdall/blob/ad54f025e224c5d3cdfa824a1117b5c616cc6e13/heimdall/vault/crypto.py#L331) | AC-25 |
| #30-32 | Hook, remplacement et validation Y/N/E integres | Non atteste de bout en bout ; ne pas deduire des tests scan/client | [heimdall/cli/main.py:1](https://github.com/Cezar277/heimdall/blob/ad54f025e224c5d3cdfa824a1117b5c616cc6e13/heimdall/cli/main.py#L1) | [docs/llm-rejections.md:1](https://github.com/Cezar277/heimdall/blob/ad54f025e224c5d3cdfa824a1117b5c616cc6e13/docs/llm-rejections.md#L1) | AC-22 |

## Vérification des fiches historiques

Les **14 fiches** existantes ont été relues comme sources historiques. Leurs
**744 occurrences de permaliens** GitHub `/blob/<SHA>/...` ont été contrôlées
sur les objets Git locaux : révision immuable, fichier présent et bornes de
ligne valides. Ce contrôle ne certifie ni la sémantique de chaque affirmation,
ni la disponibilité HTTP, ni une exécution récente de leurs tests.

Une plage invalide a été corrigée dans T22 : `entropy.py#L16-L33` devient
`entropy.py#L15-L32`, sur le même SHA historique. Après correction :
**744 valides, 0 objet absent, 0 plage invalide, 0 référence de branche**.
Pour **466 occurrences**, le fichier de preuve diffère du fichier au SHA T42 :
ces résultats restent historiques et les preuves courantes figurent ci-dessus.
La mesure T22 « précision 100 % » est ainsi supersédée par T23 et AC-07,
sans réécrire le résultat de l'ancienne exécution.

| Source historique | Périmètre et relecture actuelle |
| --- | --- |
| [t21-samm.md](t21-samm.md) | Oracle et tests écrits avant scanner ; xfail historique non transposable à la version courante (AC-06/07). |
| [t22-samm.md](t22-samm.md) | Signatures et exclusions ; précision historique supersédée par T23 ; plage entropie corrigée (AC-03/07). |
| [t23-samm.md](t23-samm.md) | Entropie et mesure honnête : 8 faux positifs connus, seuil de 90 % inchangé (AC-04/07). |
| [t24-samm.md](t24-samm.md) | Allowlist explicite ; aucune suppression implicite des faux positifs dans la mesure (AC-05). |
| [t255-samm.md](t255-samm.md) | Contrats et intégration TestClient ; assertions comportementales sur API réelle en mémoire (AC-13). |
| [t29-samm.md](t29-samm.md) | Scan CI, anti-auto-attestation et codes de sortie ; pas de dialogue Y/N/E (AC-08/22). |
| [t33-samm.md](t33-samm.md) | Journal durable et consultation ; limites du chaînage et raccordement au dialogue conservés (AC-12). |
| [t34-samm.md](t34-samm.md) | Injection déterministe et MCP ; preuves avec modèle réel toujours ignorées (AC-11/20). |
| [t35-samm.md](t35-samm.md) | Client, écritures atomiques et transport ; cible POSIX, pas une garantie Windows (AC-17). |
| [t53-samm.md](t53-samm.md) | Contrat Scanner/Finding et validation des entrées (AC-03). |
| [t54-samm.md](t54-samm.md) | Paquet de signatures et tests synthétiques (AC-03). |
| [t64-samm.md](t64-samm.md) | Empreintes de clés API, révocation et autorisation projet (AC-14). |
| [t67-samm.md](t67-samm.md) | AES-GCM nonce/AAD livré ; ne vaut pas gestion complète KEK/DEK par enveloppe (AC-16/25). |
| [t68-samm.md](t68-samm.md) | Falsification de chaque octet, mauvais AAD/clé, formats invalides (AC-16). |

Le [compte rendu machine](acceptance/samm-link-audit.json) conserve les comptes
par fiche et l'empreinte de chaque source contrôlée. Vérification élémentaire
reproductible : `git show <SHA>:<module>`, puis vérifier que chaque ancre
`#Ldébut-Lfin` vérifie `1 <= début <= fin <= nombre de lignes` ; comparer
`git diff <SHA> ad54f025e224c5d3cdfa824a1117b5c616cc6e13 -- <module>` avant
réutilisation comme preuve courante. Les liens relatifs et les liens PR/issues
ne font pas partie des 744 permaliens de code.

Cas T35 vérifié manuellement : `t35-samm.md` ne contient aucun lien HTTP(S),
seulement des références de modules, symboles et tests ; ses **0 occurrences**
sont donc attendues. Le motif d'extraction est
`https://github\.com/Cezar277/heimdall/blob/[^\s)<>]+`, puis la révision est
contrôlée comme SHA hexadécimal de 7 à 40 caractères. L'absence de lien dans
cette fiche n'est pas un Pass de preuve permanente ; la ligne T35 du tableau
consolidé fournit les permaliens courants. L'audit ne prétend pas vérifier
les références textuelles que ce motif ne sélectionne pas.

La ventilation JUnit est vérifiable depuis les pièces versées :
[XML expurgé](acceptance/junit.xml), [résultats JSON](acceptance/results.json)
et [vérificateur](acceptance/recount_junit.py).
L'ancien XML temporaire n'est pas récupérable depuis son seul hash et le log
pytest initial ne suffit pas à reconstruire les comptes par module : le XML
versé provient d'un rejeu identifié séparément, comparé au relevé initial.
Ces pièces restent des preuves locales de l'auteur ; elles ne remplacent
ni la CI distante, ni la revue D, ni une attestation de runner éphémère (AC-24).

## Décision de consolidation

Les preuves du dépôt sont consolidées et la matrice est exécutée ; le verdict
**MVP entièrement accepté n'est pas acquis**. AC-07 échoue ; les réserves
AC-20 à AC-25 restent attribuées aux tickets existants. Chaque réserve possède
une action de suivi dans la matrice. Aucun changement de comportement runtime,
aucun abaissement de seuil et aucun merge sur `main` ne sont inclus.
La revue croisée D et le check distant `CI (/ci)` restent à obtenir avant merge.
