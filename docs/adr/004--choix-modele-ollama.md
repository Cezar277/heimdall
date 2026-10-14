# ADR 003 : Choix du modèle LLM local (Ollama)

## Contexte
Le projet Heimdall nécessite un modèle LLM local pour trier les candidats secrets identifiés par le scanner déterministe. Le modèle doit offrir un compromis optimal entre la vitesse d'inférence (utilisation CPU-only sur nos machines) et l'empreinte mémoire, tout en garantissant aucune fuite de données (100% local). Une première évaluation sur des modèles classiques (Mistral, Llama 3.1) a révélé des temps de réponse trop élevés pour une utilisation fluide en ligne de commande (plus de 11 secondes par requête).

## Décision
Nous avons décidé d'utiliser le Small Language Model (SLM) **Qwen2.5:0.5b** via Ollama.

## Mesures et Justification
Un benchmark exhaustif a été réalisé sur 20 candidats pièges (faux positifs, prompt injections, tokens factices) du jeu de données DevSecOps. Nous avons évalué un panel complet de SLMs de 360 millions à 3.8 milliards de paramètres pour maximiser les performances sur processeur.

| Modèle         | Succès | Tps moyen | Tps total | RAM Ollama (Pic) | RAM Script |
|----------------|--------|-----------|-----------|------------------|------------|
| qwen2.5:0.5b   | 20/20  | 0.51 s    | 10.2 s    | 2,062.2 Mo       | 36.0 Mo    |
| smollm2:360m   | 20/20  | 0.91 s    | 18.2 s    | 8,065.6 Mo       | 36.1 Mo    |
| qwen2.5:1.5b   | 20/20  | 1.14 s    | 22.8 s    | 3,204.1 Mo       | 36.0 Mo    |
| llama3.2:1b    | 20/20  | 1.49 s    | 29.8 s    | 1,557.4 Mo       | 35.9 Mo    |
| tinyllama      | 20/20  | 1.67 s    | 33.4 s    | 6,444.6 Mo       | 36.1 Mo    |
| gemma2:2b      | 20/20  | 4.09 s    | 81.7 s    | 7,148.0 Mo       | 36.1 Mo    |
| phi3.5         | 20/20  | 5.22 s    | 104.3 s   | 4,759.7 Mo       | 36.1 Mo    |

**Justification :**
Le modèle **Qwen2.5:0.5b** s'impose comme le leader incontesté de ce comparatif pour notre cas d'usage. 

1. **Vélocité extrême :** Avec un temps moyen de 0,51 seconde par requête, il est presque deux fois plus rapide que son concurrent direct (`smollm2:360m`) et garantit une validation quasi-instantanée dans le terminal, évitant toute friction pour le développeur.
2. **Efficacité mémoire :** Son empreinte mémoire culmine à environ 2 Go. Bien que `llama3.2:1b` soit légèrement plus économe (1,5 Go), `Qwen2.5:0.5b` évite l'explosion de RAM observée sur d'autres micro-modèles (comme `smollm2` ou `tinyllama` qui font gonfler le processus serveur d'Ollama à plus de 6 Go).
3. **Fiabilité :** Il a traité les 20 pièges sans erreur d'exécution.

Il offre ainsi le meilleur ratio vitesse/mémoire pour tourner en arrière-plan (fail-closed) sans pénaliser les ressources de la machine hôte.