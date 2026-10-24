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
hexadécimales sont classées avant les valeurs base64/base64url. Les jetons
sont maximaux : aucune découpe d'un long jeton en fenêtres artificielles.
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

## Contexte local

`heimdall.scanner.entropy_detection.context_lines(target, finding.line)`
rend un `ScanContext` avec l'attribut sensible `lines` : couples
`(numéro réel, texte)`, cinq lignes avant et après, tronqués aux bords du
fichier. Pour un diff, seules les lignes disponibles dans la cible sont
rendues ; les lignes absentes ne sont pas inventées. Le `repr` masque le
contenu. Cette API interne est destinée au triage local : aucune écriture,
aucun appel réseau, aucune transmission automatique à un LLM. Le contenu
brut ne doit pas être journalisé ni ajouté au Finding ou à un rapport.

## Faux positifs et limites

Les UUID, les digests explicitement affectés à `sha*`, `md5`, `commit`,
`checksum`, `integrity`, les valeurs préfixées `sha512-` et les charges de
data URI base64 ne produisent pas de signal d'entropie. Une signature connue
reste signalée dans ces contextes. Ces filtres sont des heuristiques : un
secret sans signature déguisé en digest ou data URI peut donc être manqué.
À l'inverse, un hash sans indication de contexte peut produire une alerte.
L'entropie n'est pas une preuve qu'une valeur est un secret. L'allowlist
générale reste le périmètre de #24.

Mesure reproductible sur le corpus T21, oracle inchangé (34 cas, dont
18 non-secrets), avec `PYTHONPATH=. python tests/measure_trap.py` :

| Périmètre | VP | FP | FN | Précision | Rappel |
| --- | --- | --- | --- | --- | --- |
| `core` (sans obfuscations) | 10 | 0 | 0 | 1,00 | 1,00 |
| `all` | 12 | 0 | 4 | 1,00 | 0,75 |

Aucune fausse alerte sur les 18 non-secrets. Les deux chaînes encodées sont
repérées par leur entropie sans décodage. Les quatre cas restants sont les
concaténations et reconstructions de variables Python/JavaScript ; aucun
interpréteur de code ni analyse de flux n'est ajouté. Le rappel global
précédent était de 0,625 (10/16). Ces chiffres portent sur ce corpus, pas
sur tous les dépôts possibles.

## Corrections demandées dans les commentaires de #23

- Affectation AWS sans valeur reconnue et fenêtre multiligne dépassant
  4096 octets UTF-8 : `ScanError` statique, dans les deux moteurs.
- UTF-8 invalide sans BOM : décodage strict, puis `ScanError` statique ;
  un vrai binaire connu reste exclu par la politique existante. Un faux PNG
  non UTF-8 contenant du texte clair fait échouer la CLI en code 2.

Les tests sont dans `tests/test_scanner_entropy.py`,
`tests/test_scanner_detect.py`, `tests/test_scanner_signatures.py` et
`tests/test_cli_scan.py`. Les preuves module + ligne sont archivées dans
`t23-samm.md`.
