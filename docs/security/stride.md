# STRIDE par composant — #47

[DFD](dfd.md) · [Actifs/frontières](assets-and-boundaries.md) · [Priorisation](risks.md).

S = usurpation ; T = altération ; R = répudiation ; I = divulgation ;
D = déni de service ; E = élévation de privilèges. Cette classification
reprend la [méthode STRIDE de Microsoft](https://learn.microsoft.com/en-us/archive/msdn-magazine/2006/november/uncover-security-design-flaws-using-the-stride-approach).
Les scénarios ci-dessous sont propres aux flux Heimdall. Aucun N/A : les
48 combinaisons ont un scénario, y compris les opérations qui manipulent
les stockages. Les cellules décrivent des menaces possibles, pas des exploits
démontrés dans les stubs actuels.

Les mesures sont **à implémenter/à vérifier** dans les tickets cités. Un renvoi
à #19 signifie « exigence proposée à reprendre », pas une exigence déjà acceptée.
Les numéros de tickets renvoient au dépôt
[Cezar277/heimdall](https://github.com/Cezar277/heimdall/issues).
Impact (Imp), probabilité (P) et score **inhérents** sont définis dans risks.md.
La justification précise l’exposition ; l’impact découle du dommage décrit.

## Matrice de couverture

| Composant | S | T | R | I | D | E |
| --- | --- | --- | --- | --- | --- | --- |
| Scanner P3 | [SCN-S](#scn-s) | [SCN-T](#scn-t) | [SCN-R](#scn-r) | [SCN-I](#scn-i) | [SCN-D](#scn-d) | [SCN-E](#scn-e) |
| Serveur MCP P4 | [MCP-S](#mcp-s) | [MCP-T](#mcp-t) | [MCP-R](#mcp-r) | [MCP-I](#mcp-i) | [MCP-D](#mcp-d) | [MCP-E](#mcp-e) |
| Ollama E2 / orchestration P2 | [LLM-S](#llm-s) | [LLM-T](#llm-t) | [LLM-R](#llm-r) | [LLM-I](#llm-i) | [LLM-D](#llm-d) | [LLM-E](#llm-e) |
| CLI P2 | [CLI-S](#cli-s) | [CLI-T](#cli-t) | [CLI-R](#cli-r) | [CLI-I](#cli-i) | [CLI-D](#cli-d) | [CLI-E](#cli-e) |
| Hook P1 | [HOOK-S](#hook-s) | [HOOK-T](#hook-t) | [HOOK-R](#hook-r) | [HOOK-I](#hook-i) | [HOOK-D](#hook-d) | [HOOK-E](#hook-e) |
| API Vault P5 | [VLT-S](#vlt-s) | [VLT-T](#vlt-t) | [VLT-R](#vlt-r) | [VLT-I](#vlt-i) | [VLT-D](#vlt-d) | [VLT-E](#vlt-e) |
| Stockages D1–D4 / clés | [STO-S](#sto-s) | [STO-T](#sto-t) | [STO-R](#sto-r) | [STO-I](#sto-i) | [STO-D](#sto-d) | [STO-E](#sto-e) |
| Runner CI E3 | [CI-S](#ci-s) | [CI-T](#ci-t) | [CI-R](#ci-r) | [CI-I](#ci-i) | [CI-D](#ci-d) | [CI-E](#ci-e) |

## Scanner P3

| ID | Scénario | Mesure prévue / ticket | Imp | P | Score | Justification de P |
| --- | --- | --- | --- | --- | --- | --- |
| <a id="scn-s"></a>SCN-S | Un auteur substitue le périmètre scanné à l’index réellement commité. | Fixer racine et snapshot, vérifier à la décision ; #22/#19. | 3 | 2 | 6 | Course ou invocation trompeuse nécessaire. |
| <a id="scn-t"></a>SCN-T | Un secret obfusqué ou une erreur de décodage est traité comme un scan propre. | Corpus de régressions, couverture explicite, erreur/troncature bloquante ; #22/#19. | 3 | 3 | 9 | Entrée contrôlée par tout contributeur ; risque de fuite durable. |
| <a id="scn-r"></a>SCN-R | Un auteur conteste le verdict car le rapport ne désigne pas le snapshot scanné. | Tracer empreinte du périmètre, version et verdict sans contenu sensible ; #22/#19. | 2 | 2 | 4 | Litige plausible après modification de l’index. |
| <a id="scn-i"></a>SCN-I | Une exception du scanner imprime la ligne contenant un secret. | Finding sans valeur brute, erreurs statiques et masquage avant sortie ; #14/#22. | 3 | 2 | 6 | Nécessite un chemin d’erreur ou une trace trop détaillée. |
| <a id="scn-d"></a>SCN-D | Un diff géant ou une regex à coût excessif épuise CPU et RAM. | Bornes de lecture, budget de temps et détection déterministe bornée, sortie 2 si incomplet ; #22/#19. | 2 | 3 | 6 | Le contributeur contrôle taille et contenu. |
| <a id="scn-e"></a>SCN-E | Un attribut Git déclenche un textconv pendant l’extraction du diff. | Argv fixe, pas de shell, pas de external diff/textconv, environnement contrôlé ; #22/#27/#19. | 3 | 2 | 6 | Exige une configuration ou un filtre accepté par le lecteur Git. |

## Serveur MCP P4

| ID | Scénario | Mesure prévue / ticket | Imp | P | Score | Justification de P |
| --- | --- | --- | --- | --- | --- | --- |
| <a id="mcp-s"></a>MCP-S | Un autre processus est lancé à la place du serveur stdio attendu. | Chemin du programme et environnement maîtrisés, dépendances vérifiées ; #27/#19. | 3 | 2 | 6 | Nécessite altération de configuration ou de résolution du binaire. |
| <a id="mcp-t"></a>MCP-T | Une proposition calculée avant une modification de fichier est réutilisée. | Lier candidate_id et proposal_id au snapshot, refuser STALE_CANDIDATE ; #27/#30. | 3 | 2 | 6 | La course nécessite une modification entre analyse et application. |
| <a id="mcp-r"></a>MCP-R | Une demande d’outil hostile est refusée sans trace exploitable. | Journaliser outil, résultat, ID opaque de session sans arguments libres ; #33/#19. | 2 | 2 | 4 | Possible quand les rejets ne sont pas corrélés. |
| <a id="mcp-i"></a>MCP-I | sanitize_file laisse une valeur brute dans un extrait ou une erreur. | Masquage avant sérialisation de tous champs, erreurs closes, corpus de fuite ; #27/#34. | 3 | 2 | 6 | Chemin de masquage incomplet nécessaire ; le schéma seul ne suffit pas. |
| <a id="mcp-d"></a>MCP-D | Le modèle multiplie les appels et les pages de candidats sans fin. | Budget par session, pagination bornée, délais et interruption fail-closed ; #27/#28/#19. | 2 | 3 | 6 | Une boucle du modèle suffit sans privilège supplémentaire. |
| <a id="mcp-e"></a>MCP-E | Une demande issue du code pousse MCP à lire hors racine via un lien symbolique. | Allowlist de quatre outils, garde de chemin à l’usage, aucun exec/écriture/réseau ; #27/#34. | 3 | 3 | 9 | Chemins et liens du dépôt sont contrôlables ; lecture de credentials possible. |

## Ollama E2 / orchestration P2

| ID | Scénario | Mesure prévue / ticket | Imp | P | Score | Justification de P |
| --- | --- | --- | --- | --- | --- | --- |
| <a id="llm-s"></a>LLM-S | Un service local imposteur répond sur l’adresse Ollama configurée. | Endpoint loopback fixé et contrôle du processus/configuration ; sortie toujours non fiable ; #28/#19. | 3 | 2 | 6 | Nécessite un processus local ou une configuration modifiée. |
| <a id="llm-t"></a>LLM-T | Un commentaire ordonne au modèle de masquer un candidat réel. | Séparer données et instructions, refus proposés visibles/journalisés, décision humaine ; en CI aucun LLM ; #28/#33/#34. | 3 | 3 | 9 | Tout code scanné peut porter une instruction hostile. |
| <a id="llm-r"></a>LLM-R | Un rejet suggéré par le modèle ne peut pas être relié à la décision humaine. | Corréler candidat/snapshot, version modèle et décision sans prompt brut ; #33/#32. | 2 | 2 | 4 | Diagnostic perdu si seule la réponse finale est conservée. |
| <a id="llm-i"></a>LLM-I | Le prompt, l’historique Ollama ou ses traces contient une valeur sensible. | Contexte masqué minimal, pas de logs de prompt brut, rétention bornée ; #27/#28/#19. | 3 | 2 | 6 | Exige une fuite de masquage ou une collecte de contexte excessive. |
| <a id="llm-d"></a>LLM-D | Un texte hostile entraîne une génération interminable ou une boucle d’outils. | Bornes tokens/temps/tours ; panne explicite, jamais de verdict propre par défaut ; #28/#19. | 2 | 3 | 6 | Le texte fourni ou une réponse du modèle suffit. |
| <a id="llm-e"></a>LLM-E | Une sortie du modèle tente d’autoriser seule un patch ou un accès Vault. | Aucun credential ni outil Vault/exec, validation stricte et Y/N/E hors modèle ; #27/#32/#34. | 3 | 2 | 6 | Nécessite que l’orchestrateur délègue indûment une autorité. |

## CLI P2

| ID | Scénario | Mesure prévue / ticket | Imp | P | Score | Justification de P |
| --- | --- | --- | --- | --- | --- | --- |
| <a id="cli-s"></a>CLI-S | Des séquences terminal imitent une validation ou dissimulent le fichier présenté. | Échapper contrôles/ANSI, présenter chemins et aperçu sûrs, lire la décision sur canal dédié ; #32/#19. | 3 | 2 | 6 | Nécessite un affichage non neutralisé et une action humaine. |
| <a id="cli-t"></a>CLI-T | Un lien ou un index changé après Y remplace la cible de l’écriture. | Recontrôle du snapshot et confinement à l’usage, écriture atomique, rescanner avant succès ; #30/#32. | 3 | 3 | 9 | Dépôt contrôlable et fenêtre entre aperçu et écriture. |
| <a id="cli-r"></a>CLI-R | Une remédiation est attribuée au développeur sans lien avec sa décision. | Tracer décision, proposition, snapshot et résultat sans valeur ni saisie libre ; #32/#33/#19. | 2 | 2 | 4 | Possible dans un journal incomplet ou partagé. |
| <a id="cli-i"></a>CLI-I | La CLI expose la valeur récupérée dans stdout, .env trop ouvert ou historique shell. | Droits privés, absence d’arguments/logs sensibles, exemple vide, décision H2 explicite ; #26/#32/#19. | 3 | 3 | 9 | Chemins de sortie usuels et risque d’erreur humaine répétée. |
| <a id="cli-d"></a>CLI-D | Une panne Vault laisse les fichiers partiellement remédiés et inutilisables. | Opérations récupérables, écriture atomique, erreur bloquante, état conservé tant que résultat incomplet ; #30/#32/#40. | 2 | 2 | 4 | Une interruption au mauvais moment est nécessaire. |
| <a id="cli-e"></a>CLI-E | Le nom de variable proposé est LD_PRELOAD ou PYTHONPATH et modifie une exécution future. | Valider EnvVarName et denylist des noms dangereux, aucune exécution de proposition ; #30/#32. | 3 | 2 | 6 | Exige nom accepté puis consommé par un processus ultérieur. |

## Hook P1

| ID | Scénario | Mesure prévue / ticket | Imp | P | Score | Justification de P |
| --- | --- | --- | --- | --- | --- | --- |
| <a id="hook-s"></a>HOOK-S | Un hook imposteur affiche « propre » sans lancer Heimdall. | Installation/chemin maîtrisés et contrôle CI indépendant obligatoire ; #19. | 3 | 2 | 6 | Accès au hook local requis ; il ne constitue pas une autorité distante. |
| <a id="hook-t"></a>HOOK-T | Un commit avec --no-verify saute le scan et introduit un secret. | Contrôle CI déterministe obligatoire avec protection de branche, hook seulement aide locale ; #22/#19. | 3 | 3 | 9 | Contournement accessible directement au contributeur. |
| <a id="hook-r"></a>HOOK-R | Le développeur affirme que le hook a été exécuté sans preuve du commit contrôlé. | Associer verdict CI au SHA et conserver résultat minimal ; #19. | 2 | 2 | 4 | Absence de preuve indépendante plausible. |
| <a id="hook-i"></a>HOOK-I | Le hook recopie la sortie sensible de la CLI dans le terminal ou un log Git. | Sorties CLI masquées/statique, propagation du code uniquement si nécessaire ; #32/#19. | 3 | 2 | 6 | Nécessite une sortie sensible en amont ou une capture excessive. |
| <a id="hook-d"></a>HOOK-D | Un hook reste bloqué sur Ollama et empêche les commits. | Délai d’exécution et erreur explicite, scan déterministe disponible, pas de succès sur timeout ; #28/#19. | 2 | 2 | 4 | Dépend d’une panne ou réponse lente du service. |
| <a id="hook-e"></a>HOOK-E | Un hook construit une commande shell à partir d’un nom de fichier hostile. | Argv fixe, aucune interpolation shell de données du dépôt, exécution sans privilège accru ; #19. | 3 | 2 | 6 | Implémentation de hook vulnérable nécessaire. |

## API Vault P5

| ID | Scénario | Mesure prévue / ticket | Imp | P | Score | Justification de P |
| --- | --- | --- | --- | --- | --- | --- |
| <a id="vlt-s"></a>VLT-S | Un attaquant réutilise une clé volée ou distingue les clés existantes par latence. | Clés aléatoires, hachés seuls serveur, compare_digest et coût comparable, révocation ; #25/#26. | 3 | 2 | 6 | Vol préalable ou oracle de traitement nécessaire. |
| <a id="vlt-t"></a>VLT-T | Un POST rejoué écrase une valeur ou impose un état choisi par le client. | Création sans écrasement, 409 conflit, schéma fermé, état serveur ; rotation séparée ; #15/#25/#40. | 3 | 2 | 6 | Accès authentifié et contrôles métier absents nécessaires. |
| <a id="vlt-r"></a>VLT-R | Un accès autorisé à une valeur n’est pas attribuable à une identité et une opération. | Événements d’accès avec identifiant non sensible, droits de logs et rétention ; #25/#19. | 2 | 2 | 4 | Dépend d’une journalisation insuffisante. |
| <a id="vlt-i"></a>VLT-I | Un proxy, cache, erreur ou certificat non vérifié expose une réponse GET. | TLS vérifié, no-store obligatoire, erreurs constantes, aucun corps sensible en trace ; #15/#25/#26. | 3 | 2 | 6 | Interception ou mauvaise configuration requise. |
| <a id="vlt-d"></a>VLT-D | Des corps volumineux ou des clés invalides tournantes contournent les quotas. | 1 Mio avant parsing avec/sans longueur annoncée, quotas globaux/auth, Retry-After borné, XFF ignoré ; #25. | 3 | 2 | 6 | Service partagé joignable ; nécessite pression soutenue. |
| <a id="vlt-e"></a>VLT-E | Une clé du projet A lit le secret du projet B en changeant l’URL. | Autoriser projet/env/opération avant recherche, 403 indépendant de l’existence, tests interprojets ; #25. | 3 | 3 | 9 | Paramètres directement contrôlables par tout client autorisé. |

## Stockages D1–D4 / clés

| ID | Scénario | Mesure prévue / ticket | Imp | P | Score | Justification de P |
| --- | --- | --- | --- | --- | --- | --- |
| <a id="sto-s"></a>STO-S | Un fichier base ou sauvegarde substitué est pris pour le Vault légitime. | Chemins/ACL contrôlés, origine des sauvegardes et intégrité authentifiée vérifiées ; #25/#19. | 3 | 2 | 6 | Accès au stockage ou au canal de restauration nécessaire. |
| <a id="sto-t"></a>STO-T | Un attaquant remplace des ciphertexts ou restaure une version révoquée. | Chiffrement authentifié lié au contexte, intégrité version/identité et reprise vérifiée ; #25/#40/#19. | 3 | 2 | 6 | Droits d’écriture ou sauvegarde compromise requis. |
| <a id="sto-r"></a>STO-R | Des lignes d’audit sont supprimées ou forgées pour nier un accès. | Journal structuré sans entrées libres, permissions/rotation, détection d’altération et limites explicites ; #33/#25/#19. | 2 | 2 | 4 | Accès aux journaux ou injection de texte requis. |
| <a id="sto-i"></a>STO-I | Un mainteneur partage la KEK avec un backup ou commite un fichier de credentials. | Clés hors Git/base/logs, sauvegarde séparée protégée, procédure de manipulation et révocation ; #25/#26/#19. | 3 | 3 | 9 | Erreur humaine plausible sur fichiers de travail et sauvegardes. |
| <a id="sto-d"></a>STO-D | La perte de la KEK ou la destruction de la seule sauvegarde rend les secrets irrécupérables. | Sauvegarde séparée de clés/données, restauration testée, procédure d’accès de secours ; #25/#19. | 3 | 2 | 6 | Incident matériel ou manipulation erronée, sans adversaire sophistiqué. |
| <a id="sto-e"></a>STO-E | Un autre utilisateur lit .env ou la KEK grâce à des permissions trop larges. | ACL minimales, identité de service dédiée, contrôles à création et restauration ; #25/#26/#19. | 3 | 2 | 6 | Compte local distinct et permissions faibles nécessaires. |

## Runner CI E3

| ID | Scénario | Mesure prévue / ticket | Imp | P | Score | Justification de P |
| --- | --- | --- | --- | --- | --- | --- |
| <a id="ci-s"></a>CI-S | Un statut produit par un job modifié est pris pour une preuve de scan du bon SHA. | Workflow de confiance protégé, contrôle requis lié au SHA et à son producteur ; #19. | 3 | 2 | 6 | Modification de workflow ou mauvaise protection requise. |
| <a id="ci-t"></a>CI-T | Une PR modifie les règles/tests pour rendre propre un checkout contenant un secret. | Configuration de scan de confiance, revue des workflows, test du commit exact ; #22/#19. | 3 | 2 | 6 | Nécessite que la PR puisse contrôler le garde-fou appliqué. |
| <a id="ci-r"></a>CI-R | Un résultat de pipeline disparaît avant l’audit ou vise un ancien commit. | Archiver verdict/version/SHA et lien de run avec politique de rétention ; #19. | 2 | 2 | 4 | Rétention ou corrélation insuffisante plausible. |
| <a id="ci-i"></a>CI-I | Un job non fiable récupère une clé Vault ou une valeur via artifacts/cache/logs. | Aucun credential sur PR non fiable ; job autorisé isolé, clé minimale, pas d’artefact sensible ; #25/#26/#19. | 3 | 2 | 6 | Dépend de l’injection de credentials ou du partage de cache. |
| <a id="ci-d"></a>CI-D | Des PR répétées ou un job bloqué saturent le runner auto-hébergé. | Temps, concurrence et ressources bornés ; annulation, nettoyage isolé et aucune réussite sur erreur ; #19. | 2 | 3 | 6 | Déclenchement de jobs et entrée volumineuse accessibles aux contributeurs. |
| <a id="ci-e"></a>CI-E | Le code d’une PR exécuté sur le runner self-hosted persiste et vole les droits d’un job suivant. | Runner éphémère isolé pour code non fiable, aucun secret ni réseau Vault, permissions minimales ; #19. | 3 | 3 | 9 | Le workflow actuel exécute les tests du checkout sur self-hosted ; isolation non prouvée. |
