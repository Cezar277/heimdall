# ADR 004 : Choix du modèle LLM local (Ollama)

## Contexte
Le projet Heimdall nécessite un modèle LLM local pour trier les candidats secrets identifiés par le scanner déterministe. Le modèle doit offrir un compromis optimal entre la vitesse d'inférence (utilisation CPU-only sur nos machines) et l'empreinte mémoire, tout en garantissant aucune fuite de données (100% local). Une première évaluation sur des modèles classiques (Mistral, Llama 3.1) a révélé des temps de réponse trop élevés pour une utilisation fluide en ligne de commande (plus de 13 secondes par requête).

## Décision
Nous avons décidé d'utiliser le Small Language Model (SLM) **Qwen2.5:0.5b** via Ollama.

## Mesures et Justification
Un benchmark exhaustif a été réalisé sur 20 candidats pièges (faux positifs, prompt injections, tokens factices) du jeu de données DevSecOps. Nous avons évalué un panel étendu de SLMs (de 270 millions à 3 milliards de paramètres) pour maximiser les performances sur processeur.

| Modèle                | Succès | Tps moyen | Tps total | RAM Ollama (Pic) | RAM Script |
|-----------------------|--------|-----------|-----------|------------------|------------|
| qwen2.5:0.5b          | 20/20  | 0.75 s    | 15.0 s    | 6,059.6 Mo       | 19.4 Mo    |
| functiongemma:270m    | 20/20  | 1.33 s    | 26.6 s    | 3,913.9 Mo       | 36.1 Mo    |
| qwen2.5:1.5b          | 20/20  | 1.86 s    | 37.2 s    | 6,702.3 Mo       | 19.4 Mo    |
| tinyllama:latest      | 20/20  | 2.26 s    | 45.2 s    | 3,742.6 Mo       | 34.9 Mo    |
| smollm2:360m          | 20/20  | 1.29 s    | 25.9 s    | 3,892.5 Mo       | 34.9 Mo    |
| minicpm-v4.6:1b       | 20/20  | 2.61 s    | 52.2 s    | 2,617.5 Mo       | 36.0 Mo    |
| lfm2.5-thinking:1.2b  | 20/20  | 3.72 s    | 74.4 s    | 3,469.7 Mo       | 36.1 Mo    |
| qwen3.5:0.8b          | 20/20  | 5.33 s    | 106.6 s   | 3,020.9 Mo       | 35.9 Mo    |
| llama3.2:1b           | 20/20  | 2.30 s    | 46.0 s    | 5,722.5 Mo       | 19.6 Mo    |
| gemma2:2b             | 20/20  | 5.64 s    | 112.8 s   | 5,224.7 Mo       | 34.9 Mo    |
| phi3.5:latest         | 20/20  | 7.31 s    | 146.1 s   | 8,284.3 Mo       | 21.9 Mo    |
| llama3.1:latest       | 20/20  | 8.82 s    | 176.4 s   | 9,131.9 Mo       | 19.6 Mo    |
| mistral:latest        | 20/20  | 13.59 s   | 271.8 s   | 5,043.8 Mo       | 17.3 Mo    |
| tev1:0.8b             | 0/20   | 0.00 s    | 0.0 s     | 68.4 Mo          | 35.6 Mo    |

**Justification :**
Le modèle **Qwen2.5:0.5b** s'impose comme le leader incontesté de ce comparatif pour notre cas d'usage.

1. **Vélocité extrême :** Avec un temps moyen de 0,75 seconde par requête (et un pic à 0,44 s), il surclasse tous les autres modèles testés et garantit une validation quasi-instantanée dans le terminal, évitant toute friction pour le développeur.
2. **Fiabilité :** Il obtient un score parfait de 20/20 en traitant l'ensemble des pièges et prompt injections sans erreur d'exécution (contrairement à des modèles inadaptés comme `tev1`).
3. **Efficacité globale :** Son temps cumulé total est le plus bas du panel (15 secondes pour tout le jeu de test), confirmant son adéquation parfaite pour un usage local en environnement CPU-only.