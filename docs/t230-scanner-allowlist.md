# Audit E-02 : détection contextualisée et allowlist (#230)

`scan`, `scan --staged`, `scan --ci --diff BASE` et `deep-scan` utilisent
les mêmes familles de signatures. Les valeurs restent internes : les
résultats ne contiennent que type, ligne, entropie et empreinte HMAC.

## Détection ajoutée

- Préfixes `glpat-`, `AIza`, `ya29.`, `npm_`, `whsec_`, `dop_v1_`, `shpat_`
  avec charge de 8 à 256 caractères et frontières explicites.
- URL `scheme://user:password@host` : valeur détectée = mot de passe,
  de 1 à 256 caractères ; aucune connexion au service.
- En-tête Authorization Basic/Bearer : valeur de 4 à 512 caractères,
  sans décodage ni tentative d'authentification.
- Affectations sensibles (`password`, `passwd`, `pwd`, `secret`, `token`,
  `api_key`, `auth` et formes qualifiées) : valeur de 4 à 256 caractères,
  ponctuation comprise, entropie minimale de 1,5 bit/octet UTF-8. Les formes
  citées et non citées sont séparées ; les expressions non citées usuelles,
  booléens et valeurs de template explicites ne sont pas des secrets.
  Un littéral cité comme `"None"` reste candidat. Un mot de passe par défaut
  tel que `changeme` est désormais un candidat, plutôt qu'un faux positif
  supposé au niveau des signatures ; l'allowlist reste une décision distincte.
- Jetons sans contexte de 20 à 22 caractères avec minuscules, majuscules
  et chiffres : correction du seuil Shannon de `short_token_adjustment`
  (0,65 par défaut), soit 3,85 bits au lieu de 4,5. Le seuil 4,5 est
  mathématiquement inaccessible sur 20 caractères distincts (`log2(20)`).
  `EntropyConfig(short_token_adjustment=0)` restaure le seuil uniforme.
  Les valeurs hors de cette bande et l'hexadécimal conservent leurs seuils.

Il s'agit d'heuristiques avec faux positifs et faux négatifs possibles,
pas d'une preuve d'absence de secret. Les formats non couverts, les valeurs
au-delà des bornes et les secrets très courts/faiblement entropiques ne
sont pas tous détectés. Les contraintes de lecture, de durée et de nombre
de findings restent appliquées. Les fenêtres contiguës de deux lignes
sont calculées avant l'entropie des fragments pour éviter les doublons.
La clé d'une affectation contextuelle doit rester sur une même ligne ; la
jointure ne peut pas en fabriquer une à partir d'un commentaire adjacent.

## Allowlist

Chaque chemin d'une regex doit conserver au moins trois marqueurs littéraux
obligatoires. Les assertions (positives ou négatives) ne consomment pas de
texte, les atomes/groupes optionnels ne contribuent pas, et une répétition
ne multiplie pas le nombre de marqueurs. Les alternances imbriquées sont
analysées par groupe, avec le minimum de leurs branches. La longueur de
128 caractères borne la profondeur et le coût de cette analyse ; les
gardes anti-ReDoS existantes restent actives et peuvent refuser des regex
autrement spécifiques. Une configuration invalide sort en 2, sans reflet
de sa valeur. Exemples refusés : `(?!abc).`, `a?b?c?.`, `(abc)?.`.

Les globs de chemin sont sensibles à la casse sur toutes les plateformes :
`*`, `?`, `[...]` restent dans un segment ; seul un segment `**` traverse
zéro ou plusieurs répertoires. Ainsi `tests/*` ne couvre plus
`tests/nested/file.py` ; employer `tests/**` si ce périmètre est voulu.
Une règle exige toujours un critère portant sur la valeur : un chemin ne
suffit pas à supprimer un finding. Les plafonds de chemin et de jokers
restent appliqués.

## Corpus reproductible

`tests/test_issue230_scanner_allowlist.py` construit 75 positifs synthétiques
(préfixes, affectations ponctuées, URL, Authorization et 60 jetons courts)
et 15 négatifs. Aucun jeton n'a été émis par un fournisseur.
Mesure locale : 74 vrais positifs, 1 faux négatif (jeton court), 1 faux positif
(UUID déjà signalé par l'entropie), soit rappel et précision de 98,67 % sur
ce seul corpus. Les seuils de non-régression sont rappel ≥ 90 % et précision
≥ 95 %. Ces taux ne sont pas extrapolables à un dépôt ou à des secrets réels.

L'oracle historique T21 reste inchangé. Sans allowlist implicite, les règles
contextuelles y signalent aussi les deux `changeme` et les deux mocks nommés
comme jetons. Cela porte les faux positifs historiques de 8 à 12 : précision
`core` 10/22 (45,45 %), rappel 100 % ; précision `all` 12/24 (50 %), rappel
75 %. Le script historique garde son seuil de 90 % et retourne donc 1.
Ces résultats sont publiés séparément du corpus E-02 : sa bonne mesure ne
doit pas masquer le coût de triage sur d'autres contenus.

```sh
python -m pytest tests/test_issue230_scanner_allowlist.py tests/test_scanner_allowlist.py tests/test_scanner_signatures.py tests/test_scanner_entropy.py tests/test_scanner_detect.py -o addopts= -q
```
