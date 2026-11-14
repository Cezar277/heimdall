# T229 — Tolérance du scanner : preuves SAMM

Ticket : #229, audit E-01. Base : `c35df09`.
Révision de code : `7019d78a1c60846598ec5e786ff87efe025fb20c`.
Cette fiche et le complément de transcription sont ajoutés dans un commit
de documentation distinct.

## Menace et choix de politique

STRIDE : déni de service du contrôle local/CI par un contenu normal de dépôt
(image, encodage occidental, notebook, gros fichier ou lien). Le scanner
continuait auparavant à refuser toute l'analyse dès le premier de ces cas.

La tolérance est désormais explicite et observable : un rapport partiel
liste les chemins et motifs d'exclusion, sans secret ni extrait. Le code 0
couvre uniquement le contenu effectivement analysé. Les contenus écartés
peuvent contenir des secrets ; une politique sans ces exclusions doit
utiliser `--strict`. Les erreurs d'accès, incohérences d'objets, conflits et
dépassements de budgets globaux restent des erreurs d'outillage (code 2).

## Garanties et preuves permanentes

| Garantie | Implémentation et témoin |
| --- | --- |
| Exclusions explicites et bornées | [`policy.py:19`](https://github.com/Cezar277/heimdall/blob/7019d78a1c60846598ec5e786ff87efe025fb20c/heimdall/scanner/policy.py#L19) : chemin relatif validé, motif fermé, ligne optionnelle, aucun contenu. [`policy.py:35`](https://github.com/Cezar277/heimdall/blob/7019d78a1c60846598ec5e786ff87efe025fb20c/heimdall/scanner/policy.py#L35) : jetons hors borne remplacés par des espaces, lignes conservées ; une trace par motif/fichier. |
| Binaires et texte non UTF-8 | [`exclusions.py:227`](https://github.com/Cezar277/heimdall/blob/7019d78a1c60846598ec5e786ff87efe025fb20c/heimdall/scanner/exclusions.py#L227) : UTF-8/16/32 et repli CP1252 ; contenu non textuel tracé ou refusé en mode strict. [`test_scanner_tolerance.py:73`](https://github.com/Cezar277/heimdall/blob/7019d78a1c60846598ec5e786ff87efe025fb20c/tests/test_scanner_tolerance.py#L73) : candidat synthétique détecté en Latin-1, CP1252, UTF-16 et UTF-32, dans l'arbre et l'index. |
| Arbre, index et diff | [`scan.py:683`](https://github.com/Cezar277/heimdall/blob/7019d78a1c60846598ec5e786ff87efe025fb20c/heimdall/cli/scan.py#L683) : même politique pour les blobs de l'index et des plages de commits. [`test_scanner_tolerance.py:46`](https://github.com/Cezar277/heimdall/blob/7019d78a1c60846598ec5e786ff87efe025fb20c/tests/test_scanner_tolerance.py#L46) : binaire signalé, candidat dans un autre fichier toujours détecté, schéma JSON validé et strict refusé, sur les trois périmètres. |
| Gros fichiers non lus | [`detect.py:852`](https://github.com/Cezar277/heimdall/blob/7019d78a1c60846598ec5e786ff87efe025fb20c/heimdall/scanner/detect.py#L852) : borne avant lecture, gardes du descripteur et identité conservées. [`test_scanner_tolerance.py:87`](https://github.com/Cezar277/heimdall/blob/7019d78a1c60846598ec5e786ff87efe025fb20c/tests/test_scanner_tolerance.py#L87) : trace `too_large`, lecture du blob interdite ; les tests #59 existants gardent les témoins de lecture bornée. |
| Jetons longs sans masquer les autres candidats | [`test_scanner_tolerance.py:102`](https://github.com/Cezar277/heimdall/blob/7019d78a1c60846598ec5e786ff87efe025fb20c/tests/test_scanner_tolerance.py#L102) : notebook avec jeton de 8192 caractères et candidat distinct sur la même ligne ; candidat détecté, trace avec ligne, aucune valeur brute dans le rapport. |
| Symlinks jamais suivis | [`detect.py:294`](https://github.com/Cezar277/heimdall/blob/7019d78a1c60846598ec5e786ff87efe025fb20c/heimdall/scanner/detect.py#L294) : exclusion tracée ou refus strict. [`test_scanner_tolerance.py:114`](https://github.com/Cezar277/heimdall/blob/7019d78a1c60846598ec5e786ff87efe025fb20c/tests/test_scanner_tolerance.py#L114) : cible externe non résolue et non lue, parcours par descripteur et repli par chemin ; strict refuse. Les racines symlinkées restent refusées. |
| Historique et cache | [`history.py:113`](https://github.com/Cezar277/heimdall/blob/7019d78a1c60846598ec5e786ff87efe025fb20c/heimdall/cli/history.py#L113) : mode tolérant ou strict, motifs conservés dans le cache borné. [`test_scanner_tolerance.py:155`](https://github.com/Cezar277/heimdall/blob/7019d78a1c60846598ec5e786ff87efe025fb20c/tests/test_scanner_tolerance.py#L155) : Findings et exclusions présents pour chaque commit réutilisant le même blob. |
| Pas d'exclusion par suffixe | [`test_scanner_tolerance.py:171`](https://github.com/Cezar277/heimdall/blob/7019d78a1c60846598ec5e786ff87efe025fb20c/tests/test_scanner_tolerance.py#L171) : texte Latin-1 portant un candidat dans un fichier nommé comme une image, toujours analysé. |

## Validation

Transcription : [docs/acceptance/t229-validation.txt](acceptance/t229-validation.txt).

- Suite complète : **3829 passed, 18 skipped, 6911 subtests passed** en
  320,03 secondes ; 14 avertissements existants des tests de remédiation.
- Rejeu sur la révision de code ci-dessus : **30 passed**, comprenant les
  24 cas de tolérance et la garde de sécurité statique de la CI.
- Ruff : succès. MyPy : succès sur 57 fichiers. Bandit : aucune alerte.
- `heimdall scan --ci --no-allowlist --json .` : **code 1**, 3986 candidats,
  321 fichiers analysés, `dfd.png` tracé en `binary` et deux limites de
  fenêtre multiligne ; aucun arrêt en code 2. Les fixtures synthétiques et
  empreintes du dépôt expliquent la présence de candidats sans allowlist ;
  cette commande ne déclare pas le dépôt propre.

Environnement : Debian WSL, Python 3.13, dépendances de l'environnement
de test existant ; la CI aux versions verrouillées n'a pas été déclenchée.
Les rapports JUnit et JSON bruts sont conservés hors dépôt, aux chemins
indiqués dans la transcription. Aucun appel réseau n'a été ajouté au scanner.

## Limites et re-pin

La classification de contenu est heuristique. Le scanner ne décompresse
pas les archives, n'extrait pas le texte des images et n'analyse pas les
cibles des liens. Les exclusions ne prouvent aucune absence de secrets.
Voir la [politique utilisateur](scanner-tolerance.md), notamment les
différences entre rapports de couverture et helpers ne rendant qu'une liste.

Les permaliens deviennent accessibles après push de la branche. Après une
fusion squash, re-pinner sur le SHA final :

```sh
python scripts/repin_samm.py --sha <SHA> --fiche docs/t229-samm.md
python scripts/repin_samm.py --check --fiche docs/t229-samm.md
```
