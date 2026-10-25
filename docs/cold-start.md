# Cold start et historique (T38)

## Entonnoir (#107)

```console
heimdall cold-start .
heimdall cold-start . --no-llm --json
heimdall cold-start . --ci --json
```

Le premier scan d'un dépôt existant passe par le scanner déterministe complet
(regex, entropie, allowlist et ses garde-fous). Seuls les findings résultants
sont qualifiés par Ollama local : cinq lignes de contexte de chaque côté,
128 caractères au plus par ligne après masquage, moins de 2000 caractères
par appel. Les lignes portant des candidats sont entièrement masquées.
Le fichier est relu sans suivre de lien et les candidats sont revérifiés
avant la qualification. Aucun fichier entier n'est envoyé au modèle.

Un avis `faux_positif` est une proposition, affichée et journalisée via T33.
Il ne retire jamais un finding et ne change pas le code de sortie : 0 propre,
1 candidats présents, 2 erreur d'outillage. Un modèle indisponible conserve
le candidat. `--ci` interdit le modèle et son journal, même avec `--llm`.
Le dépôt reste en lecture seule ; le journal éventuel est un état opérateur
hors dépôt. Le mode LLM est plafonné à 256 candidats (au-delà : code 2).

La phase de qualification dispose d'une échéance globale de **300 secondes**,
vérifiée entre fichiers et avant/après chaque candidat, y compris dans un même
fichier. Le re-scan reçoit cette échéance. Un appel Ollama déjà en cours garde
le timeout réseau de T28 (**60 secondes**) : l'échéance peut donc être dépassée
par cet appel, mais aucun candidat suivant ne démarre après expiration.
Le dépassement produit une erreur d'outillage (code 2), jamais un rapport propre.

L'identité de la racine est figée avant la première passe, puis revérifiée
entre les passes, avant les relectures et en fin de qualification. Une substitution
de la racine est refusée même avec un contenu identique. Une garde de chemin
échouée devient une `ScanError` au message statique pour les appelants bibliothèque.
Le re-scan est volontairement sans allowlist : c'est un sur-ensemble ; seuls les
findings conservés par la première passe doivent y figurer. Les deux moteurs
partagent la configuration d'entropie par défaut et la même clé HMAC locale.

Preuves et mapping SAMM : [t38-samm.md](t38-samm.md).

Tests : `python -m pytest tests/test_cold_start.py`.
Sous Windows, si Git n'est pas dans `os.defpath`, le produit refuse de prendre
un exécutable dans le PATH hérité. Pour les tests de cette machine uniquement :

```powershell
.venv\Scripts\python.exe -c "import os,pytest; os.defpath += os.pathsep + r'C:\Program Files\Git\cmd'; raise SystemExit(pytest.main(['tests/test_cold_start.py','-q']))"
```

Ce réglage désigne l'installation système de Git, jamais un binaire du dépôt.
