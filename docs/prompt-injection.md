# Défense contre l'injection de prompt — T34

Périmètre : #34 et tous ses sous-tickets #91–#97, regroupés sur la branche
T34 à la demande du porteur. Menace : un commentaire, une chaîne ou un nom
de fichier tente de blanchir un secret ou de détourner un outil (STRIDE :
tampering, elevation of privilege ; REQ-SEC-01 et REQ-SEC-02).

`heimdall.mcp.prompts.build_messages` conserve le système versionné
`qualify_v1` sans interpolation. Le code déjà masqué est envoyé uniquement
dans le message utilisateur. Chaque requête utilise un nonce aléatoire de
64 bits ; les séquences `<data_…>` et `</data_…>` issues du dépôt sont
échappées avant insertion, sans distinction de casse et même si la balise
est incomplète. Une collision du nonce ne permet donc pas de
fermer le bloc. Les marqueurs `<REDACTED:…>` restent lisibles. Le prompt
système et son schéma sont inchangés ; son nom et le SHA-256 de la chaîne
effectivement envoyée restent journalisés.

`heimdall.llm.qualify` ne transmet aucun outil à Ollama. Son unique sortie
autorisée est un avis `{verdict, confidence}` validé par Pydantic : enum
fermé, nombre strict entre 0 et 1, aucun champ supplémentaire. Les demandes
de chemin, variable, commande, outil ou application de patch sont donc
rejetées, sans tenter de les réparer ou de les exécuter. Les appels d'outils
natifs Ollama sont également refusés, même accompagnés d'un JSON valide.
Le champ `tool_calls` n'accepte que `None` ou une liste vide ; tout autre
type est refusé, y compris un objet faux en contexte booléen.
Les clés JSON dupliquées sont rejetées pour éviter toute interprétation
ambiguë du verdict. Les réponses restent bornées avant parsing.

`qualify_candidate` conserve toujours le statut `detecte`, y compris après
un avis valide `faux_positif`. Un résultat invalide donne une raison fermée
et un journal statique ; aucune entrée ni réponse brute ne figure dans les
logs. Le passage à un autre état exige la validation humaine. En CI, le
scanner reste déterministe : aucun avis du LLM ne décide du résultat.

Le serveur MCP garde son registre fermé (`ping`, `read_diff`,
`sanitize_file`), ses arguments stricts et son confinement des chemins.
Il ne fournit aucune écriture ni commande shell. Le corpus vérifie aussi
par un vrai échange MCP stdio que les outils inconnus et les chemins
absolus ou traversants sont refusés. Les outils futurs du contrat ne sont
pas implémentés par ce ticket.

Le corpus [tests/fixtures/injection](../tests/fixtures/injection/README.md)
contient 15 cas répartis entre les trois familles demandées. Chaque extrait
est matérialisé avec un jeton synthétique dérivé à l'exécution, reconnu par
le vrai scanner et masqué avant qualification. Un faux LLM hostile est
rejoué avec trois réponses par cas ; le fichier et les Findings sont
comparés avant/après. Les noms de fixtures suivent la liste blanche ASCII
`[A-Za-z0-9_.-]{1,64}` (hors `.` et `..`) : aucun espace ni caractère de
contrôle n'est admis. La résolution du chemin refuse également un lien symbolique
sortant du dossier temporaire avant toute écriture. Ces tests prouvent le
maintien de l'alerte, même
quand le modèle obéit à l'injection ; ils ne prétendent pas que le modèle
comprend toujours les instructions de sécurité.

Rejouer sans Ollama :

```sh
python -m pytest tests/test_prompt_injection_corpus.py -m 'not llm' -v
```

Le workflow `Prompt injection corpus` lance cette suite sur chaque PR vers
`main`, sur le runner Linux self-hosted du projet, sans secrets injectés
ni identifiants Git persistés. Il utilise le `python3` préinstallé et recrée
un environnement isolé `.venv-injection`, sans `actions/setup-python` ni
installation globale de paquets. La CI complète existante la collecte également. Les tests
`@pytest.mark.llm` sont désactivés par défaut ; voir le README du corpus
pour la commande manuelle avec Ollama local. Une absence du serveur lors
de cette exécution explicite échoue plutôt que de produire une fausse preuve.

La revue du prompt par un autre membre et l'approbation de la PR restent
des vérifications humaines à réaliser avant fusion.
