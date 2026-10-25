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

Tests : `python -m pytest tests/test_cold_start.py`.
Sous Windows, si Git n'est pas dans `os.defpath`, le produit refuse de prendre
un exécutable dans le PATH hérité. Pour les tests de cette machine uniquement :

```powershell
.venv\Scripts\python.exe -c "import os,pytest; os.defpath += os.pathsep + r'C:\Program Files\Git\cmd'; raise SystemExit(pytest.main(['tests/test_cold_start.py','-q']))"
```

Ce réglage désigne l'installation système de Git, jamais un binaire du dépôt.
