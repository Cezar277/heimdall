# Journal des rejets du LLM (T33)

Un rejet signifie ici une **proposition de faux positif**, jamais une
autorisation de retirer un Finding ou de committer. La qualification
structurée v1 ne contient pas de justification libre : le journal conserve
le motif fermé `faux_positif_propose_par_llm_validation_humaine_requise`.
Cela évite de recopier un secret ou une instruction injectée dans une
explication du modèle. Le contrat `qualify_v1` reste inchangé.

## Utilisation

```sh
heimdall rejections           # vérifie la chaîne et affiche le nombre de propositions
heimdall rejections --details # ajoute les entrées JSONL vérifiées
```

Le résumé affiche « N candidat(s) écarté(s) par le LLM (propositions
uniquement) ; voir le détail… Validation humaine requise. » Le nombre
porte sur l'historique local complet, pas sur le dernier scan. Les détails
utilisent l'échappement JSON ASCII : les noms de fichiers contenant des
contrôles ou des caractères directionnels ne peuvent pas modifier le terminal.
Un journal absent donne zéro ; la lecture initialise un fichier vide.
Une erreur de lecture, d'intégrité ou de rendu sort en **2**, avec un message
statique et sans afficher de données provenant du journal corrompu.

## Intégration avec la validation humaine (#32)

La frontière d'orchestration est
`heimdall.llm.rejections.qualify_finding(finding, masked_candidate, ...)`.
L'appelant fournit le Finding déterministe et un extrait **déjà masqué** par
le MCP (contrat #16), jamais la valeur du secret. Le modèle et le chemin du
journal appartiennent à la configuration de l'opérateur, pas à la sortie du LLM.

```python
from heimdall.llm.rejections import qualify_finding

avis = qualify_finding(finding, masked_candidate, ci=is_ci)
# finding reste inchangé et avis.status reste "detecte".
# Seule la validation humaine #32 peut décider de la suite.
```

Hors CI, un verdict `faux_positif` n'est rendu qu'après l'append durable
(`fsync`) et un résumé d'avertissement visible sur stderr via `logging`.
Un avis `secret`, `incertain`, une réponse malformée ou une panne Ollama ne
produisent pas d'entrée de rejet ; les refus de qualification restent
tracés par les codes fermés de `qualify_candidate` (#81).
Si le journal échoue, `JournalError` remonte : l'appelant doit conserver
le Finding et produire une erreur d'outillage **2**, jamais accepter le rejet.
Les primitives `qualify` et `qualify_candidate` restent des clients de bas
niveau, sans localisation de fichier ; le flux humain doit passer par
`qualify_finding` pour obtenir un avis audité.

Avec `ci=True`, le retour est immédiatement `detecte`, sans verdict :
**aucun appel au LLM, aucune ouverture du journal**. Le code `unavailable`
indique un avis indisponible par politique, sans impliquer une panne Ollama.
`heimdall scan --ci` conserve son chemin déterministe existant (#29/#24) :
seule l'allowlist déterministe peut ignorer des Findings. Le journal n'est
jamais relu comme une allowlist ou une décision de scan.

Le dialogue Y/N/E et le branchement de cette frontière dans le dialogue
restent au ticket #32 : T33 n'active pas le LLM dans `scan` et ne crée pas
de nouvelle voie de suppression automatique des Findings.

## Stockage et intégrité

Emplacement par défaut :
`$XDG_STATE_HOME/heimdall/llm-rejections.jsonl`, ou
`~/.local/state/heimdall/llm-rejections.jsonl`. C'est un état utilisateur,
indépendant du répertoire courant ; ne pas configurer `XDG_STATE_HOME`
dans un dépôt. L'historique agrège les projets de l'utilisateur : les
chemins sont ceux des Findings, relatifs à leur dépôt, sans identifiant
de projet. Conserver des états XDG distincts pour isoler les projets.

Chaque entrée porte : version du schéma, numéro séquentiel, date UTC,
fichier, ligne, empreinte HMAC du candidat, modèle, version et SHA-256 du
prompt effectivement chargé, justification fermée, empreinte précédente
et SHA-256 de l'entrée canonique. Aucun extrait, prompt brut ou réponse
brute du modèle n'est stocké. Le journal contient des métadonnées de
projet : il reste local et ne doit pas être ajouté à Git.

La chaîne entière est vérifiée avant chaque append et chaque consultation.
Un verrou système non bloquant sur un fichier `.lock` stable sérialise
lecteurs et rédacteurs ; un accès concurrent échoue explicitement au lieu
de créer deux branches de chaîne. Une écriture courte est poursuivie ; une
écriture interrompue reste détectable et n'est jamais réparée silencieusement.
Les limites sont 32 Kio par entrée et 16 Mio par journal : au-delà, refus,
sans troncature ni rotation automatique. Archiver le journal vérifié avant
de réinitialiser explicitement l'état local.

Les chemins relatifs, `..`, liens symboliques, fichiers non réguliers et
liens physiques multiples sont refusés. Sous POSIX : parent en 0700,
fichiers en 0600 et propriétaire courant vérifié. Sous Windows, les ACL
du profil utilisateur s'appliquent ; les contrôles de liens restent en
check-then-use, sans garantie contre une course menée par le même utilisateur.

Le chaînage répond à la menace de modification interne d'une entrée,
suppression au milieu ou réordonnancement. **Il ne prouve pas l'absence
de suppression de fin, de suppression totale ou de réécriture complète
par le propriétaire du processus.** Une preuve contre cet adversaire exige
un point d'ancrage externe de la tête de chaîne ou un collecteur sous un
autre compte, hors périmètre du MVP 100 % local. Le LLM ne reçoit aucun
outil permettant d'écrire le journal.

## Validation

`tests/test_llm_rejections.py` couvre l'append et la relecture, les champs
de preuve, la non-fuite, les altérations, les réponses hostiles, les erreurs
I/O, les écritures courtes, la concurrence, les plafonds, les permissions
POSIX, le résumé et les détails CLI, ainsi que le court-circuit CI.
Tous les appels de modèle sont factices et hors ligne.
