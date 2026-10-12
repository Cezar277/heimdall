# Priorisation et lien avec #19 — #48

[STRIDE complet](stride.md) · [DFD](dfd.md) · [Actifs](assets-and-boundaries.md).

## Méthode

Évaluation qualitative **avant mitigation**, au 12 octobre 2026. Elle n’est
ni une mesure statistique ni un score CVSS. Hypothèses de déploiement : README H1–H7.

| Note | Impact | Probabilité / accessibilité |
| --- | --- | --- |
| 1 | Gêne locale, réversible, sans secret ni verdict compromis. | Prérequis rares, hors parcours normal, plusieurs protections indépendantes à franchir. |
| 2 | Audit/integrité dégradé ou indisponibilité limitée, récupérable. | Accès local/authentifié, erreur de configuration ou course/panne particulière nécessaire. |
| 3 | Fuite de secret/credential, exécution avec droits indus, contournement du verdict ou perte durable de secrets. | Entrée directement contrôlable dans le parcours courant ou erreur humaine ordinaire répétable. |

Score = impact × probabilité : 6–9 prioritaire ; 3–4 à planifier ; 1–2 à
surveiller. Chaque scénario a ses deux notes et sa justification dans STRIDE.
Tri : score décroissant ; les neuf scores 9 sont tous retenus. Pour la
dixième place parmi les scores 6, STO-D est retenu pour l’irréversibilité
de la perte de clés. Les autres scores 6 restent prioritaires : ce top 10
n’autorise pas leur abandon. L’ordre interne des scores 9 est un ordre de
travail du flux, pas une précision supplémentaire de gravité.

## Top 10 et traçabilité

Les exigences REQ-T19-01 à 10 sont **proposées pour #19**, en attente de
validation par son porteur. Les tests ci-dessous sont des critères futurs,
pas des tests serveur exécutés dans cette PR documentaire. Aucun risque
résiduel n’est encore accepté ; les protections runtime restent à démontrer.

| Risque | Scénario STRIDE | Imp × P | Flux / frontières / actifs | Justification du classement | Exigence / suivi |
| --- | --- | --- | --- | --- | --- |
| R1 — Fuite par faux négatif | [SCN-T](stride.md#scn-t) | 3 × 3 = 9 | F03/F04, B1, A01/A06 | Le contenu hostile atteint directement le scan, dernier contrôle déterministe. | [REQ-T19-01](#req-t19-01) ; #22/#19 |
| R2 — Sortie du périmètre MCP | [MCP-E](stride.md#mcp-e) | 3 × 3 = 9 | F05/F07, B1/B2, A01/A03 | Une lecture hors dépôt peut exposer immédiatement les credentials du poste. | [REQ-T19-02](#req-t19-02) ; #27/#34 |
| R3 — Rejet induit par prompt injection | [LLM-T](stride.md#llm-t) | 3 × 3 = 9 | F05/F06/F08, B2, A09 | Le code non fiable est une entrée normale du modèle, même après masquage. | [REQ-T19-03](#req-t19-03) ; #28/#32/#33/#34 |
| R4 — Patch approuvé appliqué à une autre cible | [CLI-T](stride.md#cli-t) | 3 × 3 = 9 | F08/F11, B1/B5, A06/A09 | Le changement entre aperçu et écriture invalide l’autorisation humaine. | [REQ-T19-04](#req-t19-04) ; #30/#32 |
| R5 — Contournement du hook | [HOOK-T](stride.md#hook-t) | 3 × 3 = 9 | F01/F02/F15, B4, A06/A10 | Le hook est délibérément désactivable ; seule une barrière indépendante protège le dépôt partagé. | [REQ-T19-05](#req-t19-05) ; #22/#19 |
| R6 — Accès interprojets | [VLT-E](stride.md#vlt-e) | 3 × 3 = 9 | F09/F14, B3/B4, A01/A03 | Une simple variation du chemin suffit à solliciter les secrets d’autrui. | [REQ-T19-06](#req-t19-06) ; #25 |
| R7 — Exposition de clé maîtresse ou credential | [STO-I](stride.md#sto-i) | 3 × 3 = 9 | F10/F12, B5, A02/A03 | Une erreur de sauvegarde ou de partage peut compromettre plusieurs secrets à la fois. | [REQ-T19-07](#req-t19-07) ; #25/#26/#19 |
| R8 — Compromission persistante du runner | [CI-E](stride.md#ci-e) | 3 × 3 = 9 | F15/F14, B4, A03/A10 | Le checkout exécute du code sur self-hosted ; la séparation de jobs ne prouve pas l’isolation de machine. | [REQ-T19-08](#req-t19-08) ; #19 |
| R9 — Fuite locale pendant la remédiation | [CLI-I](stride.md#cli-i) | 3 × 3 = 9 | F08/F09/F10/F11, B3/B5, A01/A07 | La manipulation normale d’un secret multiplie les copies et sorties possibles. | [REQ-T19-09](#req-t19-09) ; #26/#32/#19 |
| R10 — Perte de clé et irrécupérabilité | [STO-D](stride.md#sto-d) | 3 × 2 = 6 | F12, B5, A02/A05 | À score 6, priorité à une perte irréversible de tous les secrets ; la disponibilité ne se répare pas sans clé. | [REQ-T19-10](#req-t19-10) ; #25/#19 |

## Exigences testables proposées

### REQ-T19-01

- Risque : **R1** (SCN-T). Suivi : #22/#19.
- Exigence : Un scan incomplet, une erreur de décodage ou une entrée non supportée ne DOIT jamais produire un verdict propre.
- Preuve attendue : Corpus synthétique d’obfuscations, erreurs et limites : secret connu → 1 ; analyse impossible → 2 ; ensemble réellement propre → 0.
- Statut : proposée ; preuve runtime et acceptation à obtenir.

### REQ-T19-02

- Risque : **R2** (MCP-E). Suivi : #27/#34.
- Exigence : Chaque outil DOIT rester dans la racine fixée, y compris au moment de l’accès, sans capacité exec, écriture ou réseau.
- Preuve attendue : Tester chemins absolus, traversée, liens sortants et échange de lien concurrent ; aucun octet extérieur ni écriture ; seuls quatre outils accessibles.
- Statut : proposée ; preuve runtime et acceptation à obtenir.

### REQ-T19-03

- Risque : **R3** (LLM-T). Suivi : #28/#32/#33/#34.
- Exigence : Un rejet du modèle DOIT rester une proposition visible et journalisée ; seul l’humain peut valider en interactif ; le LLM DOIT être absent du verdict CI.
- Preuve attendue : Commentaire hostile demandant d’ignorer un candidat : pas de suppression silencieuse ; trace sans secret ; en CI aucun appel Ollama/MCP agentique.
- Statut : proposée ; preuve runtime et acceptation à obtenir.

### REQ-T19-04

- Risque : **R4** (CLI-T). Suivi : #30/#32.
- Exigence : L’application DOIT vérifier snapshot et cible réelle à l’usage, préserver les fichiers sur erreur et rescanner avant succès.
- Preuve attendue : Modifier index/fichier/lien après Y : refus sans écriture hors racine ; simuler panne durant remplacement ; jamais d’état vaulte local prématuré.
- Statut : proposée ; preuve runtime et acceptation à obtenir.

### REQ-T19-05

- Risque : **R5** (HOOK-T). Suivi : #22/#19.
- Exigence : La branche protégée DOIT exiger un scan déterministe de confiance du SHA à fusionner, indépendant du hook et de la configuration fournie par une PR.
- Preuve attendue : Commit de fixture via --no-verify : job requis refuse ; modifier le workflow/règles dans la PR ne produit pas un statut de confiance propre.
- Statut : proposée ; preuve runtime et acceptation à obtenir.

### REQ-T19-06

- Risque : **R6** (VLT-E). Suivi : #25.
- Exigence : Le Vault DOIT autoriser projet, environnement et opération avant la recherche de ressource.
- Preuve attendue : Clé A → projet B existant ou absent : même 403 constant ; clé valide autorisée → absent : 404 ; cas sans/invalide/révoquée : même 401 sans oracle exploitable.
- Statut : proposée ; preuve runtime et acceptation à obtenir.

### REQ-T19-07

- Risque : **R7** (STO-I). Suivi : #25/#26/#19.
- Exigence : KEK et credentials DOIVENT être absents de Git/logs/base de secrets en clair ; stockage et sauvegarde des clés DOIVENT être séparés et restreints.
- Preuve attendue : Avec marqueurs synthétiques, inspecter logs/exports/backup base ; compte local non autorisé refusé ; exercer procédure de révocation après exposition simulée.
- Statut : proposée ; preuve runtime et acceptation à obtenir.

### REQ-T19-08

- Risque : **R8** (CI-E). Suivi : #19.
- Exigence : Le code de PR non fiable DOIT être exécuté sans secrets, sans accès Vault et dans un environnement isolé détruit avant le job suivant.
- Preuve attendue : Sur VM de test dédiée : marqueur de persistance et tentative d’accès réseau/credential ; job suivant ne voit aucun marqueur et accès sensibles refusés.
- Statut : proposée ; preuve runtime et acceptation à obtenir.

### REQ-T19-09

- Risque : **R9** (CLI-I). Suivi : #26/#32/#19.
- Exigence : Le destinataire autorisé DOIT protéger les fichiers privés et exclure les valeurs de stdout/logs/arguments et .env.example ; le masquage DOIT précéder toute sortie LLM.
- Preuve attendue : Valeur marqueur synthétique : présente uniquement dans destination autorisée ; absente des traces/arguments/exemple/contextes ; droits refusent un autre compte. Résoudre H2 avant ce test.
- Statut : proposée ; preuve runtime et acceptation à obtenir.

### REQ-T19-10

- Risque : **R10** (STO-D). Suivi : #25/#19.
- Exigence : Une procédure contrôlée DOIT permettre de restaurer données et clés séparées après perte de l’instance, sans réintroduire une version révoquée.
- Preuve attendue : Exercice sur VM avec données synthétiques : reconstruire instance perdue depuis sauvegardes séparées, vérifier droits/intégrité/version et accès ; documenter délai et responsable.
- Statut : proposée ; preuve runtime et acceptation à obtenir.

## Hors top 10 ne signifie pas accepté

Les 38 autres scénarios restent dans le registre STRIDE avec score et suivi.
En particulier TLS, erreurs sans reflet, masquage MCP, limites de ressources,
anti-rejeu et intégrité des sauvegardes restent des obligations des contrats
ou des exigences à reprendre dans #19. Avant MVP, le porteur A et le
relecteur C réévaluent chaque score avec la preuve disponible ; tout report
doit nommer un responsable, une échéance et le risque résiduel accepté.
Le présent document ne promet pas que les dix seuls risques suffiront au MVP.

## Transmission au ticket #19

À copier dans #19 après revue (non publié automatiquement) :

> Le modèle T18 propose R1–R10 et REQ-T19-01–10, avec scénarios et critères
> de vérification dans `docs/security/risks.md`. Chaque exigence de #19 doit
> conserver le lien vers son Rn, son scénario STRIDE et son ticket
> d’implémentation. Ajouter le permalink au SHA final de cette PR avant de
> publier ce commentaire. Les hypothèses H1–H7 restent à arbitrer ; les
> mesures sont prévues et leurs preuves runtime restent à fournir.

La checklist « risques référencés dans #19 » reste ouverte jusqu’à la
publication effective et à la reprise par son porteur.
