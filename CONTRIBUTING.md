# Contribuer à Heimdall

Heimdall est un outil 100 % local qui empêche les secrets (mots de passe, clés API, clés privées) de finir dans Git. Ce document fixe les règles de travail de l'équipe. Il s'applique à tout le monde, sans exception, y compris au porteur du ticket.

## 1. Principes

- Un ticket = une branche = une PR.
- Jamais de commit direct sur `main` (la branche est protégée à partir du 3 Octobre 2026).
- Toute PR est relue par un membre d'un autre domaine.
- Tout ce qu'on livre doit être testé, documenté et prouvé (module + ligne), car une autre équipe va auditer et pentester notre code.

## 2. Rôles

Les lettres A à D correspondent aux labels `role-A` à `role-D` sur les tickets.

- **Porteur**: la personne qui réalise le ticket.
- **Relecteur**: une personne d'un autre domaine, qui relit la PR et valide la DoD.
- Un ticket bloqué ou une dérive de temps se signale dans un commentaire du ticket, en taguant le porteur du grand ticket (l'épic).

## 3. Workflow d'un ticket

1. Prends un ticket (assigne-le à toi) ou laisse-toi assigner.
2. Crée ta branche depuis `main` à jour: `git switch main && git pull && git switch -c feature/<n>-slug`
3. Code par petits commits (voir section 5).
4. Pousse et ouvre une PR. Remplis entièrement le template de PR.
5. Lie le ticket dans la PR avec `Closes #<n>`. Pour un ticket récurrent (ex. #13), utilise `Refs #<n>` pour ne pas le fermer.
6. Le relecteur relit (voir section 6). Corrige les remarques sur la même branche.
7. Une fois approuvée et la CI verte, la PR est mergée (squash merge conseillé).
8. Commente le ticket avec le temps passé: `Temps: 1h30`.

## 4. Nommage des branches

Format: `<type>/<n>-slug`, où `<n>` est le numéro du ticket.

- `feature/14-scanner`: nouvelle fonctionnalité.
- `fix/27-regex-aws`: correction de bug.
- `docs/12-contributing`: documentation seule.
- `chore/30-ci-lint`: outillage, CI, dépendances.
- `test/35-faux-positifs`: tests seuls.

Le slug est en minuscules, en ASCII, avec des tirets.

## 5. Format des commits

On suit Conventional Commits: `<type>(<scope>): <résumé à l'impératif> (#<n>)`

Types: `feat`, `fix`, `docs`, `test`, `refactor`, `chore`, `ci`, `security`.

Exemples:
- `feat(scanner): add shannon entropy detection (#14)`
- `fix(vault): reject nonce reuse on AES-GCM (#22)`
- `docs(contributing): add branch naming rules (#12)`

Règles: résumé de 72 caractères maximum, une seule idée par commit, jamais de vrai secret dans un commit, même supprimé ensuite (il reste dans l'historique).

## 6. Revue de code

- Un relecteur d'un autre domaine, au minimum 1 approbation.
- Délai cible: 48 h ouvrées. Au-delà, relance dans le ticket.
- Le relecteur vérifie: la Definition of Done (voir `docs/DEFINITION_OF_DONE.md`), l'impact sécurité, la lisibilité, les tests.
- Le porteur ne merge pas une PR qui n'a pas été approuvée.
- Une remarque bloquante se résout par une discussion dans la PR, pas par un contournement.

## 7. Protection de `main`

Dans Settings > Branches, la règle sur `main` impose:
- une PR avant merge,
- au moins 1 approbation,
- les status checks requis (une fois la CI en place),
- pas de force-push.

La CI lourde (`.github/workflows/ci.yml`, #20) ne se déclenche **pas** à chaque
push : elle démarre quand un collaborateur de confiance commente **`/ci`** (en
début de commentaire) sur la PR (le plus simple, modèle de `/oc review`) ou
approuve la review. Les PR de forks sont refusées par la CI self-hosted ;
`workflow_dispatch` est limité à `main`. Le check exigé par la protection de
`main` est `CI (/ci)` (publié sur la PR par ces deux déclencheurs). Après un
nouveau commit sur la branche (y compris « Update branch »), relancer `/ci`
(ou ré-approuver) : le check doit être re-signalé.

## 8. Règles de sécurité (non négociables)

- Jamais de vrai secret dans le dépôt, même expiré. Les jeux de test utilisent des faux secrets clairement factices.
- Le runner CI est jetable : il exécute du code de PR (après `/ci` ou approbation), ne porte aucun secret ni donnée personnelle, et est considéré comme compromis après chaque run.
- Les tests d'attaque (pentest, exploits) se font uniquement sur nos propres VMs.
- Heimdall est 100 % local: aucun appel vers Internet depuis le code de l'outil.
- Le LLM ne décide jamais seul. En CI, il n'a aucun pouvoir.
- En cas de doute, le comportement par défaut est fail-closed: on bloque.
- Si tu découvres une faille ou un secret commité par erreur, préviens l'équipe immédiatement dans le ticket concerné.

## 9. Temps et estimations

- À la fin de chaque ticket, commente `Temps: XhY` (la grille d'évaluation demande le temps par ticket).
- Si tu dépasses le double de l'estimation, préviens l'équipe dans le ticket. Ce n'est pas grave, mais il faut le dire.

## 10. Hors périmètre

Si tu trouves quelque chose qui sort du ticket, ouvre un nouveau ticket ou note-le au compte rendu de réunion. Ne l'ajoute pas dans la PR en cours.

## 11. Preuves pour le rapport

Pour chaque ticket livré, garde:
- le lien de la PR,
- le résultat des tests (ou une capture),
- la ligne correspondante dans la feuille SAMM, avec module + ligne.

Utilise toujours un lien permanent GitHub avec le SHA du commit (touche `y` sur GitHub), jamais un lien vers la branche, car les numéros de ligne changent.
