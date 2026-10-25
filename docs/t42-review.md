# T42 — traitement de la revue documentaire

Revue du 25 octobre 2026 : **APPROVE WITH COMMENTS**.
PR : [#190](https://github.com/Cezar277/heimdall/pull/190), **Closes #42**.
Les corrections concernent la provenance et la confidentialité des preuves ;
elles ne modifient aucun module runtime ni aucun seuil d'acceptation.

| Remarque | Traitement | Preuve |
| --- | --- | --- |
| Chemins locaux dans les documents et logs | Chemins du dépôt et de la venv anonymisés ; rejeu avec TMPDIR générique puis expurgation des pièces publiées | `t42-validation.md`, `acceptance/pytest.log`, `acceptance/pytest-replay.log`, `acceptance/junit.xml` |
| Ventilation JUnit non recalculable | XML expurgé versé, SHA-256 et provenance du rejeu conservés ; vérificateur stdlib comparant les 46 modules et 19 groupes | `python docs/acceptance/recount_junit.py` |
| Lien de clôture absent | Sections manquantes du modèle ajoutées à la description et `Closes #42` explicite | Corps de la PR #190 |
| Zéro permalink T35 ambigu | Absence de tout lien HTTP(S) confirmée manuellement ; références textuelles uniquement, motif d'extraction explicité | `samm-v1.md`, entrée T35 de `acceptance/samm-link-audit.json` |
| AC-24 : validation indépendante | Condition de fusion maintenue ; état courant des checks et liens de lancement/résultat à consigner dans la PR | PR #190, onglet Checks et historique des commentaires `/ci` |

## Conditions avant fusion

- **CI distante** : exiger `CI (/ci)` vert sur le commit de merge correspondant
  au dernier SHA de la branche. Un check `Security model` ou `corpus` vert
  n'est pas ce check. Le suivi du lancement et le lien du résultat figurent
  dans la PR pour éviter qu'un commit documentaire d'archivage invalide
  lui-même le check dont il consigne le résultat.
- **Revue D** : aucune approbation humaine D disponible lors de la préparation
  des corrections. Le verdict automatique cité ne remplace pas cette revue.
- **Runner jetable** : aucune attestation d'enregistrement `--ephemeral`, de
  restauration de snapshot ou de destruction après job n'est disponible.
  L'API des runners du dépôt n'est pas accessible avec l'authentification
  disponible (réponse 404) ; cela ne prouve rien sur leur configuration.
  Le label `self-hosted`, un job réussi et la déclaration de principe dans
  CONTRIBUTING ne suffisent pas. L'opérateur doit fournir la configuration
  expurgée et la preuve de cycle de vie avant fusion.

AC-24 reste **Non exécuté** dans l'instantané local de la matrice : la CI,
la revue et l'attestation doivent toutes être démontrées avant de le valider.
Aucun merge ni approbation humaine n'est réalisé par ces corrections.
Les autres réserves AC-20/21/22/23/25 restent suivies dans leurs tickets
existants et ne sont pas étendues au périmètre T42.
