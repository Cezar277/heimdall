# T42 — traitement de la revue documentaire

Revue initiale du 25 octobre 2026 : **APPROVE WITH COMMENTS**.
La revue complémentaire **DEMANDER DES MODIFICATIONS** a été suivie d'une
nouvelle revue **APPROVE WITH COMMENTS**, transmise le 4 novembre 2026 et
consignée ci-dessous. Ce verdict ne constitue pas une attestation de revue D.
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

## Corrections de la revue complémentaire — 4 novembre 2026

- **Empreinte JUnit** : `junit_sha256` corrigé avec le SHA-256 des octets LF
  versionnés, `c021dbc113a53f02b498c1541266a06cc6d0bb3dd8394685adbcfa38d03ebaed`.
  L'ancienne valeur correspondait à la conversion CRLF du fichier sous Windows.
  `.gitattributes` impose désormais LF pour cette pièce après clonage.
- **Expurgation** : les documents et le JSON précisent que les identifiants
  synthétiques `case-XXXX` des tests paramétrés sont conservés, y compris pour
  les 15 cas d'injection ignorés ; le nom
  d'hôte est retiré et les chemins et adresses mémoire sont anonymisés.
- **Diagnostic** : un `classname` absent ou sans composant `test_*` provoque
  un `ValueError` indiquant la classe et le cas concernés.
- **Validation locale** : sortie et code de retour du vérificateur archivés dans
  [`acceptance/recount-junit.log`](acceptance/recount-junit.log). Les cas de
  `classname` absent et atypique ont aussi été vérifiés sur des copies temporaires.
  Les comptes et verdicts produit restent inchangés ; cette preuve locale ne
  satisfait pas les conditions AC-24.

## Nouvelle revue — APPROVE WITH COMMENTS

La revue transmise confirme la correction de l'empreinte JUnit, la sortie verte
du vérificateur, la description de l'expurgation et le diagnostic contextualisé.
Elle ne demande aucun changement technique supplémentaire ni test runtime.

| Remarque | Traitement |
| --- | --- |
| MEDIUM — AC-24 toujours Non exécuté | Condition avant fusion maintenue : liens vers `CI (/ci)` vert sur le SHA de merge correspondant au dernier SHA de branche, revue D et attestation du cycle de vie du runner jetable à archiver dans la PR. La validation locale ne satisfait pas cette condition. |
| LOW — XML JUnit volumineux | Pièce conservée pour permettre le recalcul indépendant de la ventilation SAMM : 2 227 éléments `testcase`, dont 16 skips (1 Ollama et 15 injections). Aucune réduction ni suppression demandée. |

Le bilan de l'instantané du 25 octobre reste **17 Pass, 2 Fail, 2 Partiel,
4 Non exécuté**, et l'acceptation du MVP reste **non acquise**. Les réserves
Ollama et KEK/DEK de cet instantané ne sont pas requalifiées par cette revue
documentaire ni par l'intégration des évolutions ultérieures de `main`.

## Complément de revue — cohérence et confinement du vérificateur

- `junit_note` est aligné sur `junit_replay.redaction` : les paramètres sont
  remplacés par des identifiants synthétiques conservés, le hostname est retiré,
  les chemins et adresses mémoire sont anonymisés.
- Le chemin JUnit doit être relatif et rester dans `docs/acceptance/` après
  résolution, y compris pour un lien symbolique. Le refus précède la lecture
  du XML et le calcul de son empreinte.
- Un document JSON qui n'est pas un objet, un chemin ou une empreinte absent
  ou invalide, ainsi que les principaux champs de comptage absents ou de type
  incorrect, produisent un `ValueError` explicite.
- Validation ciblée sur copies temporaires : chemins parent, absolu et lien
  symbolique sortant refusés ; métadonnées invalides refusées ; archive valide
  toujours recalculable. Aucun changement des verdicts ni des conditions AC-24.

### Rejeu versionné des cas invalides

Le [harnais stdlib](acceptance/test_recount_junit.py) remplace la vérification
sur copies temporaires non archivées. Depuis la racine du dépôt, sous POSIX
(pour créer le lien symbolique sortant), lancer :

```sh
python3 docs/acceptance/recount_junit.py
python3 docs/acceptance/test_recount_junit.py
```

Les 24 cas de métadonnées et chemins invalides sont rejoués en sous-tests,
avec une garde qui fait échouer le test si le XML est lu avant leur rejet.
Le harnais vérifie aussi les champs de groupe absents ou mal typés,
`testsuite.tests` absent ou invalide, les `classname` atypiques, le refus d'une
empreinte incorrecte avant parsing et le succès de l'archive valide. Toutes les
mutations se font dans un répertoire temporaire, sans modifier les pièces versées.
Les sorties sont archivées dans [le journal](acceptance/recount-junit.log).
Le vérificateur contrôle les chemins absolus avant la jointure et signale les
champs de suite et de groupe invalides par un `ValueError` contextualisé.

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
