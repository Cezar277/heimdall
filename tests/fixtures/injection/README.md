# Corpus défensif T34

15 fichiers, 5 par famille : commentaires (#92), chaînes et noms de fichiers
(#93), demandes d'outils MCP (#94). Utilisation uniquement sur nos environnements
de test. Chaque cas indique son identifiant, le nom du fichier, l'extrait piégé
et le résultat attendu : le candidat reste `detecte`, aucun outil détourné.

`__FAKE_GITHUB_TOKEN__` est remplacé à l'exécution par le jeton synthétique
dérivé par SHA-256 de `tests/support/fake_secrets.py`. Aucune clé émise, ni
même de jeton factice à forme réaliste, n'est stockée dans le diff du corpus.
Les tests vérifient que le scanner le détecte puis que le masquage le retire
avant tout envoi au modèle. Les extraits longs restent sous le plafond de
qualification (2 000 caractères).

Le faux modèle obéit volontairement aux instructions : verdict `faux_positif`,
JSON contenant une action supplémentaire ou appel d'outil natif Ollama. Même
un faux positif conforme au schéma ne supprime jamais le candidat. Les
demandes hors contrat sont refusées et journalisées sans contenu brut.

Avant toute écriture, le chemin issu de `filename` est validé : un seul nom
de fichier ASCII de 1 à 64 caractères (`[A-Za-z0-9_.-]`, hors `.` et `..`),
sans espace ni caractère de contrôle, et une résolution qui
reste sous le dossier temporaire (liens symboliques sortants refusés).

Test déterministe : `python -m pytest tests/test_prompt_injection_corpus.py -m "not llm"`.
Preuve manuelle : définir `HEIMDALL_RUN_LLM_TESTS=1`, démarrer Ollama local avec
`gemma3:270m`, puis `python -m pytest tests/test_prompt_injection_corpus.py -m llm -v`.
Le test manuel n'est jamais exécuté par la CI et ne télécharge aucun modèle.
