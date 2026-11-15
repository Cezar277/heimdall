# Politique de sécurité

Heimdall manipule des secrets (scanner, remédiation, Vault) : un signalement
de vulnérabilité est toujours le bienvenu, et traité en priorité.

## Versions prises en charge

Le projet est en phase MVP (`0.1.x`, *Pre-Alpha*). Seule la branche `main`
reçoit des correctifs de sécurité.

| Version        | Correctifs de sécurité |
| -------------- | ---------------------- |
| `main` (0.1.x) | oui                    |
| autres         | non                    |

## Signaler une vulnérabilité

**N'ouvrez pas d'issue publique ni de PR** pour une vulnérabilité : elle
serait visible de tous avant correction.

Utilisez le signalement privé de GitHub : onglet **Security** du dépôt →
**Report a vulnerability** (*Private vulnerability reporting*). Seuls les
mainteneurs voient le rapport.

Merci d'indiquer :

- le composant concerné (CLI / hook pre-commit, scanner, remédiation, serveur
  MCP, Vault client ou serveur, CI) et la version ou le commit ;
- les étapes de reproduction minimales et l'impact observé ;
- si possible, une piste de correction.

**N'incluez jamais de vrai secret** (clé, jeton, mot de passe) dans le
rapport : utilisez des valeurs factices.

## Délais (indicatifs)

Projet étudiant maintenu au mieux de nos disponibilités :

- accusé de réception sous **7 jours** ;
- première évaluation (confirmé / non reproductible / hors périmètre) sous
  **14 jours** ;
- correctif et avis de sécurité (*GitHub Security Advisory*) dès que
  possible ; la personne qui signale est créditée si elle le souhaite.

Merci de laisser **90 jours** au plus avant toute divulgation publique, ou
moins si un correctif est publié avant.

## Périmètre

Dans le périmètre : le code de ce dépôt (`heimdall/`, `scripts/`, `docker/`),
les workflows `.github/workflows/*.yml` et la documentation de déploiement
(`docs/install.md`).

Hors périmètre :

- les vulnérabilités des dépendances tierces déjà publiques (signalez-les en
  amont ; Dependabot et `pip-audit` les suivent ici) ;
- les faux secrets volontaires des tests (`tests/`) et du jeu de benchmark :
  ce sont des fixtures factices ;
- les attaques qui exigent déjà un accès root ou au compte de l'utilisateur
  sur la machine qui exécute Heimdall ;
- le déni de service par volume sur une instance Vault exposée hors loopback
  contre la documentation.

## Recherche de bonne foi

Nous ne poursuivrons pas une recherche menée de bonne foi qui respecte cette
politique : tests uniquement sur vos propres installations, aucun accès aux
données d'autrui, signalement privé et délai de divulgation respecté.
