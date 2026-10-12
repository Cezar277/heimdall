# Relecture et preuves — T18

Les documents couvrent #45–#48, regroupés sur la branche #18 à la demande
du porteur. La relecture d'équipe et la preuve de fonctionnement du produit
restent des étapes séparées. Les validations ci-dessous ne sont jamais
cochées automatiquement.

## Acceptation humaine

| Rôle | Pseudo | DFD et flux | Actifs/frontières | STRIDE et priorités | Lien d'approbation / date |
| --- | --- | --- | --- | --- | --- |
| A | À renseigner | En attente | En attente | En attente | À renseigner |
| B | À renseigner | En attente | En attente | En attente | À renseigner |
| C (autre domaine) | À renseigner | En attente | En attente | En attente | À renseigner |
| D | À renseigner | En attente | En attente | En attente | À renseigner |

- [ ] H1–H7 arbitrés ou reconnus explicitement comme décisions ouvertes par l'équipe.
- [ ] Engagement H1/H4 écrit et validé dans #19 : loopback + TLS vérifié uniquement avant une PR dédiée pour tout accès distant.
- [ ] Relecteur C : comparaison draw.io ↔ PNG, capture datée, SHA et empreintes des deux fichiers renseignés ci-dessous.
- [ ] Document et DFD relus par les quatre membres.
- [ ] R1–R10 et exigences proposées effectivement référencés dans #19.
- [ ] Lien de PR et SHA final renseignés.
- [ ] Ligne SAMM complétée dans la feuille de l'équipe.
- [ ] Preuve archivée dans le rapport avec résultat de vérification et PNG.
- [ ] Temps réellement passé renseigné et commenté sur le ticket.

## Vérification documentaire reproductible

Depuis la racine, Python 3.10 ou supérieur, sans dépendance ni réseau :

```sh
python docs/security/check_model.py
git diff --check
```

Pour rejouer les régressions et mesurer la couverture de branches :

```sh
python -m venv .venv-security
.venv-security/bin/python -m pip install --require-hashes -r tests/security/requirements.txt
.venv-security/bin/python -m pytest tests/test_check_model.py --cov=docs/security --cov-branch --cov-report=term-missing --cov-fail-under=95
```

PowerShell : remplacer `.venv-security/bin/python` par
`.venv-security/Scripts/python.exe`. Les dépendances sont épinglées et leurs
hashes vérifiés ; seule leur installation nécessite un accès réseau.
Les tests utilisent des copies temporaires, sans Git global ni réseau.

Le workflow [Security model](../../.github/workflows/security-model.yml)
exécute ces contrôles sur chaque PR, dans un runner GitHub éphémère, sans
credential Vault. Il vérifie également les blancs du diff de PR et imprime
le SHA ainsi que les SHA-256 du draw.io et du PNG. Un administrateur doit
encore rendre le check **Security model** obligatoire dans les règles de
protection de `main` ; ce paramétrage n'est pas effectué par le fichier YAML.

La vérification contrôle les 48 scénarios, leurs scores, les dix liens de
risque, les exigences associées, les liens locaux et les identifiants du DFD.
Le XML est borné à 2 Mio, UTF-8 uniquement, sans DTD ni déclaration d'entité.
Le PNG n'est contrôlé que par son en-tête et une plage de dimensions lisibles
(640–8192 × 400–8192, ratio paysage 1–2,2, au maximum 32 mégapixels).
Une signature et des dimensions acceptées **ne prouvent pas le contenu**.
Elle ne vérifie ni la sémantique des menaces ni le rendu graphique : ouvrir
également `dfd.png` et `dfd.drawio` pour vérifier lisibilité et fidélité.
Elle ne remplace ni les tests runtime de #22/#25/#27/etc., ni la validation
humaine. Les tests applicatifs et la CI ne sont pas déclarés verts par ce document.

## Preuve visuelle obligatoire avant fusion

Le relecteur du domaine C doit ouvrir **les deux fichiers**, comparer les
12 éléments, F01–F16, B1–B5, sens des flèches, textes, lisibilité et absence
de coupe, puis joindre une capture datée à son approbation. Tout ré-export
doit mettre à jour conjointement source draw.io, PNG et dimensions consignées
dans cette preuve, même si les tests automatiques restent verts.

| Champ | Valeur à renseigner par le relecteur C |
| --- | --- |
| Pseudo / date et heure avec fuseau | En attente |
| SHA Git examiné / lien PR | En attente |
| Dimensions PNG examinées | Export initial : 2600 × 1680 ; à confirmer sur le SHA relu |
| SHA-256 draw.io / SHA-256 PNG | En attente ; copier les résultats ci-dessous ou du job CI |
| Capture datée / lien d'approbation | En attente |
| Fidélité draw.io ↔ PNG confirmée | En attente |

Calculer les empreintes puis les conserver **dans la preuve archivée** :

```powershell
Get-FileHash docs/security/dfd.drawio, docs/security/dfd.png -Algorithm SHA256
```

Linux : `sha256sum docs/security/dfd.drawio docs/security/dfd.png`.
macOS : `shasum -a 256 docs/security/dfd.drawio docs/security/dfd.png`.
Une empreinte identifie l'image revue ; elle ne remplace pas la comparaison
visuelle et ne protège pas contre une PR modifiant à la fois image et preuve.

## Lignes à reporter dans SAMM

Associer ces éléments à la pratique/ligne de la feuille retenue par l'équipe,
sans inventer un score SAMM ni confondre analyse et contrôle implémenté.

| Élément prouvable dans cette PR | Module | Repère à rechercher après commit |
| --- | --- | --- |
| Périmètre et écarts par rapport à l'implémentation | `docs/security/README.md` | `Ce qui a été examiné`, `Hypothèses` |
| Processus, stockages, acteurs et flux identifiés | `docs/security/dfd.md` + `dfd.drawio` + `dfd.png` | `Registre des flux`, identifiants F01–F16 |
| Inventaire d'actifs et contrôles aux frontières | `docs/security/assets-and-boundaries.md` | A01–A11, B1–B5 |
| Analyse systématique des composants | `docs/security/stride.md` | SCN-S jusqu'à CI-E |
| Cotation et traçabilité vers exigences proposées | `docs/security/risks.md` | R1–R10, REQ-T19-01–10 |

Après le **dernier commit puis le push**, obtenir le SHA avec `git rev-parse HEAD`
et les lignes avec `git grep -n` (ex. `git grep -n '## Registre des flux' -- docs/security/dfd.md`).
Construire pour chaque preuve un lien
`https://github.com/Cezar277/heimdall/blob/<SHA_FINAL>/<module>#L<ligne>`.
Remplacer réellement les marqueurs dans la feuille ; un lien à une branche
ou un marqueur laissé tel quel ne constitue pas la preuve demandée.
Archiver aussi la PR et la sortie des deux commandes ci-dessus.

## Temps et suivi

Estimation parent : **8 h**, détail #45 **2 h**, #46 **1 h**, #47 **3 h**,
#48 **2 h**. Temps effectif : à renseigner par le porteur, jamais déduit de
l'estimation. Commentaire à publier après remplissage : `Temps: XhY`.
Relecture attendue : membre du domaine C, pseudo à confirmer.

Les scénarios et essais futurs restent cantonnés aux environnements de
test autorisés, avec valeurs synthétiques clairement non secrètes.
