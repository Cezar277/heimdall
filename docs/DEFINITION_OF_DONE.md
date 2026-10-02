# Definition of Done (DoD)

Un ticket est considéré comme terminé uniquement si tous les points applicables sont vrais. Le relecteur les vérifie avant d'approuver.

## Tous les tickets

- [ ] Les critères d'acceptation du ticket sont tous cochés.
- [ ] La PR est liée au ticket (`Closes #N`, ou `Refs #N` si récurrent).
- [ ] Relecture faite par un membre d'un autre domaine, au moins 1 approbation.
- [ ] Doc à jour (README, CONTRIBUTING, ADR si choix technique).
- [ ] Aucun secret en clair dans le dépôt, y compris dans l'historique.
- [ ] Ligne SAMM remplie avec preuve: module + ligne, lien permanent avec SHA du commit.
- [ ] Preuve archivée pour le rapport (lien PR, résultat des tests ou capture).
- [ ] Temps passé commenté sur le ticket (`Temps: XhY`).

## Tickets de code

- [ ] Tests unitaires ajoutés ou mis à jour, tous verts en local.
- [ ] CI verte (quand elle sera active).
- [ ] Couverture minimale de 70 % sur les modules critiques: scanner, Vault/crypto, serveur MCP, remplacement des secrets (valeur à réviser en réunion).
- [ ] Cas d'erreur couverts, avec comportement fail-closed.
- [ ] Entrées non fiables traitées: path traversal, prompt injection, fichiers binaires ou énormes.
- [ ] Aucun appel réseau sortant dans l'outil (100 % local).
- [ ] Le LLM ne décide jamais seul: ses rejets sont affichés et journalisés.

## Tickets de sécurité / crypto

- [ ] Menace identifiée (STRIDE), mitigation décrite, preuve (module + ligne).
- [ ] Pas de nonce réutilisé, AAD utilisée, clés jamais journalisées.
- [ ] Test d'attaque réalisé uniquement sur nos propres VMs.

## Tickets de documentation / gouvernance

- [ ] Fichier mergé sur `main` via PR (sauf bootstrap initial, voir CONTRIBUTING).
- [ ] Liens et chemins vérifiés.
- [ ] Format validé par l'équipe en réunion.
