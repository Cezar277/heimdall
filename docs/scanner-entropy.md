# Scanner par entropie de Shannon — T23

Le scan de fichiers et le moteur des cibles `FileTarget`/`DiffTarget` (donc
`heimdall scan --staged`) détectent les valeurs aléatoires sans signature.
Le calcul suit `H = -Σ p log2(p)`. Les alphabets analysés sont ASCII :
l'entropie par caractère est identique à l'entropie par octet du contrat.

| Paramètre | Défaut | Validation |
| --- | --- | --- |
| `hex_threshold` | 3,0 bits | nombre fini dans ]0 ; 4] |
| `base64_threshold` | 4,5 bits | nombre fini dans ]0 ; 6] |
| `min_length` | 20 caractères | entier dans [16 ; 4096] |

Un seuil est inclusif. Les booléens, NaN et infinis sont refusés. Les valeurs
hexadécimales sont classées avant les valeurs base64/base64url. Dans chaque
jeton lexical borné, les suites hexadécimales maximales sont analysées au
seuil hex, même si un affixe non hexadécimal est collé : `sha256-<hex>`,
`prefix-<hex>`, `x<hex>`, `x_<hex>`, `x+<hex>`, `x/<hex>` et `<hex>-suffix`.
Chaque fragment admissible porte son propre score, son empreinte et sa
position réelle (`token.start + fragment.start`). Plusieurs fragments d'un
même jeton peuvent être signalés ; un signal hex évite un second signal
base64 du même jeton. Il n'y a pas de découpe en fenêtres glissantes.
Tout jeton de plus de 4096 caractères lève `ScanError` avant les regex de
signatures et le calcul Shannon, y compris une longue charge JWT. La lecture
reste bornée à 1 Mio et la deadline est contrôlée à l'intérieur des lignes,
par jeton. Cette limite refuse explicitement le scan au lieu de sauter la valeur.
Les lignes arbitraires ne sont pas concaténées pour augmenter leur entropie.

```python
from heimdall.scanner import EntropyConfig, FileTarget, Scanner, SignatureEngine
from heimdall.scanner.detect import scan

config = EntropyConfig(hex_threshold=3.2, base64_threshold=4.7, min_length=20)
findings = scan(".", entropy_config=config)
engine = Scanner(SignatureEngine(entropy_config=config))
findings = engine.scan(FileTarget("config.py", "contenu à analyser"))
```

Le même paramètre est disponible sur `detect.Scanner` et `find_candidates`.
La CLI utilise ces défauts ; aucun nouveau drapeau CLI n'est introduit.
Un résultat utilise `source="entropy"` et `type="high_entropy_hex"` ou
`"high_entropy_base64"`. Finding v1 conserve exactement ses sept champs et
ne contient jamais la valeur brute : seulement l'empreinte HMAC et le score.
Les signatures gardent la priorité, y compris pour les valeurs multilignes,
afin de ne pas doubler les alertes. Les plafonds Findings et deadlines
existants restent appliqués aux nouveaux candidats.
L'origine vient du champ typé `SignatureMatch.source`, jamais du nom de la
règle : une signature nommée `entropy` reste `source="regex"`. Les deux types
génériques appartiennent à `ALLOWED_SECRET_TYPES`, avec les types fournisseurs.

## Contexte local

`ScanContext` et `context_lines` ont été supprimés après revue : aucun
consommateur de production ne justifiait une nouvelle surface de texte clair.
Le contexte ±5 lignes demandé initialement reste différé jusqu'à son
intégration avec un consommateur et une politique de masquage explicites.
Aucun champ de contexte n'est ajouté au Finding ; sa sérialisation reste
sans valeur brute, vérifiée par `json.dumps(asdict(finding))` dans les tests.

## Faux positifs et limites

Les étiquettes `sha256`, `commit`, `checksum`, `integrity`, les UUID et les
data URI ne constituent jamais une autorisation de taire un candidat.
La recherche de fragments hex est générique : aucun traitement spécial de
`sha512-` n'est requis, et le charset de l'affixe ne force pas le seuil base64
sur un fragment hexadécimal. Les essais locaux de `heimdall scan --ci`
vérifient le code 1 en mode arbre et indexé pour ces affixes, sans valeur
brute dans la sortie. Ces essais n'activent pas la CI GitHub.
Les UUID utilisent le seuil hexadécimal. Seules les valeurs déjà reconnues
par une signature évitent un second signal redondant. Les valeurs publiques
aléatoires peuvent donc produire des faux positifs : l'allowlist explicite
et auditée relève de #24, pas d'une heuristique sur un nom contrôlable.

Mesure reproductible sur le corpus T21, oracle inchangé (34 cas, dont
18 non-secrets), avec `PYTHONPATH=. python tests/measure_trap.py` :

| Périmètre | VP | FP | FN | Précision | Rappel |
| --- | --- | --- | --- | --- | --- |
| `core` (sans obfuscations) | 10 | 8 | 0 | 0,5556 | 1,00 |
| `all` | 12 | 8 | 4 | 0,60 | 0,75 |

Huit fausses alertes sur les 18 non-secrets (UUID, SHA-256, commit et intégrité,
dans chaque langage). Le seuil de précision de 90 % de `measure_trap.py`
reste inchangé : cette commande retourne **1**, car ce critère T21 n'est
plus satisfait sans l'allowlist. L'oracle n'est ni modifié ni filtré et le
test de régression vérifie ces comptes exacts ; une suite pytest verte ne
signifie donc pas que le seuil de précision T21 est atteint.
Les deux chaînes encodées sont
repérées par leur entropie sans décodage. Les quatre cas restants sont les
concaténations et reconstructions de variables Python/JavaScript ; aucun
interpréteur de code ni analyse de flux n'est ajouté. Le rappel global
précédent était de 0,625 (10/16). Ces chiffres portent sur ce corpus, pas
sur tous les dépôts possibles.

## Corrections demandées dans les commentaires de #23

- Fenêtre multiligne dépassant 4096 octets UTF-8 : `ScanError` statique dans
  les deux moteurs dès qu'une des lignes porte `:` ou `=`, ou un jeton de
  longueur candidate. Ce choix conservateur couvre tous les fournisseurs et
  les fragments dont l'entropie isolée est inférieure à celle du secret entier.
  Sans parseur de langage, une affectation complète dans cette situation
  peut aussi être refusée ; le refus est explicite, jamais une liste vide.
  Arbitrage confidentialité/disponibilité assumé : deux lignes de JSON
  bénin dépassant ensemble 4 Kio, avec `:` mais sans candidat, provoquent
  aussi `ScanError` et le code CLI 2 (arbre et index Git). Les tests figent
  ce cas : un bundle ou un fichier minifié peut bloquer la CI sans secret.
- UTF-8 invalide sans BOM : décodage strict, puis `ScanError` statique ;
  un vrai binaire connu reste exclu par la politique existante. Un faux PNG
  non UTF-8 contenant du texte clair fait échouer la CLI en code 2.

Les tests sont dans `tests/test_scanner_entropy.py`,
`tests/test_scanner_detect.py`, `tests/test_scanner_signatures.py` et
`tests/test_cli_scan.py`. Les preuves module + ligne sont archivées dans
`t23-samm.md`.

Les imports directs valident également `preceding_matches` (tuple de
`SignatureMatch`) et `deadline` (nombre fini, hors booléens). Les deux
fonctions de détection/garde refusent une deadline invalide en `ScanError`
statique, même si les lignes sont vides ; la garde valide aussi ses deux
lignes et sa configuration avant toute recherche.
