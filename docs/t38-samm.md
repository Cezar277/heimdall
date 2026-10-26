# T38 / #107–#110 — preuves SAMM après revue

Périmètre de la [PR #193](https://github.com/Cezar277/heimdall/pull/193) :
ensemble du ticket #38, sous-tickets #107, #108, #109 et #110 inclus,
conformément à la demande de compléter tout T38. Le périmètre initial limité
à #107 est remplacé par ce périmètre explicite ; la PR ne permet pas de
fusionner #107 isolément. La relecture croisée reste requise avant fusion.

Code et tests corrigés : `78c7f7f0af1b6565bc91c2c24bfa0c8ffb42dbfe`.
Complément LOW : `7000236ef4e584d3b6604a206da65f95db07c606` (preuves ci-dessous).
Complément d'exhaustivité et d'API : `359155d191fd758431594addbff0a6870213f1d8`
(section dédiée ci-dessous). Les anciens tableaux restent des preuves de leurs
snapshots ; le complément remplace notamment la déduplication globale et
l'exclusion des cibles de liens des premières versions.
Les liens ci-dessous désignent ce snapshot, pas la branche mouvante.

| Ticket / pratique SAMM | Exigence et menace | Implémentation permanente | Preuve permanente |
| --- | --- | --- | --- |
| #107 / Conception, exigences de sécurité | Divulgation : contexte masqué avant troncature, seuls les candidats sont qualifiés | [candidate_context](https://github.com/Cezar277/heimdall/blob/78c7f7f0af1b6565bc91c2c24bfa0c8ffb42dbfe/heimdall/cli/cold_start.py#L62) | [candidats masqués et contexte borné](https://github.com/Cezar277/heimdall/blob/78c7f7f0af1b6565bc91c2c24bfa0c8ffb42dbfe/tests/test_cold_start.py#L53) |
| #107 / Gouvernance, politique et conformité | Aucun pouvoir autonome du LLM, aucun appel/journal en CI | [collect_cold_start](https://github.com/Cezar277/heimdall/blob/78c7f7f0af1b6565bc91c2c24bfa0c8ffb42dbfe/heimdall/cli/cold_start.py#L112) | [rejet conservé et journalisé](https://github.com/Cezar277/heimdall/blob/78c7f7f0af1b6565bc91c2c24bfa0c8ffb42dbfe/tests/test_cold_start.py#L82), [CI explicite sans appel/journal](https://github.com/Cezar277/heimdall/blob/78c7f7f0af1b6565bc91c2c24bfa0c8ffb42dbfe/tests/test_cold_start.py#L236) |
| #107 / Conception, architecture sécurisée | Altération / disponibilité : relecture à la taille configurée, échéance et identité racine | [relecture bornée](https://github.com/Cezar277/heimdall/blob/78c7f7f0af1b6565bc91c2c24bfa0c8ffb42dbfe/heimdall/cli/cold_start.py#L142) | [croissance entre les passes](https://github.com/Cezar277/heimdall/blob/78c7f7f0af1b6565bc91c2c24bfa0c8ffb42dbfe/tests/test_cold_start.py#L188), [deadline](https://github.com/Cezar277/heimdall/blob/78c7f7f0af1b6565bc91c2c24bfa0c8ffb42dbfe/tests/test_cold_start.py#L253), [substitution racine](https://github.com/Cezar277/heimdall/blob/78c7f7f0af1b6565bc91c2c24bfa0c8ffb42dbfe/tests/test_cold_start.py#L286) |
| #108 / Vérification, tests pilotés par les exigences | Retrouver les secrets supprimés, dédoublonner avec tous les commits | [collect_history](https://github.com/Cezar277/heimdall/blob/78c7f7f0af1b6565bc91c2c24bfa0c8ffb42dbfe/heimdall/cli/history.py#L99) | [suppression et dédoublonnage](https://github.com/Cezar277/heimdall/blob/78c7f7f0af1b6565bc91c2c24bfa0c8ffb42dbfe/tests/test_history.py#L35), [merges et renommages](https://github.com/Cezar277/heimdall/blob/78c7f7f0af1b6565bc91c2c24bfa0c8ffb42dbfe/tests/test_history.py#L72) |
| #108 / Conception, exigences de sécurité | Refus par défaut : un suffixe technique ne masque pas un blob inconnu | [décodage et repli avec is_known_binary](https://github.com/Cezar277/heimdall/blob/78c7f7f0af1b6565bc91c2c24bfa0c8ffb42dbfe/heimdall/cli/history.py#L181) | [evil.png / evil.zip / evil.txt : ScanError et code 2](https://github.com/Cezar277/heimdall/blob/78c7f7f0af1b6565bc91c2c24bfa0c8ffb42dbfe/tests/test_history.py#L279) |
| #108 / Vérification, contrat d'erreur | Entrées non fiables : erreurs statiques de parsing, sans UnicodeDecodeError / ValueError bruts | [_entries](https://github.com/Cezar277/heimdall/blob/78c7f7f0af1b6565bc91c2c24bfa0c8ffb42dbfe/heimdall/cli/history.py#L73) | [chemin hors racine, nom et OID non UTF-8, arbres invalides](https://github.com/Cezar277/heimdall/blob/78c7f7f0af1b6565bc91c2c24bfa0c8ffb42dbfe/tests/test_history.py#L254) |
| #108 / Conception, architecture sécurisée | Altération : références figées et revérifiées avant verdict | [snapshot des tips](https://github.com/Cezar277/heimdall/blob/78c7f7f0af1b6565bc91c2c24bfa0c8ffb42dbfe/heimdall/cli/history.py#L60), [vérification finale](https://github.com/Cezar277/heimdall/blob/78c7f7f0af1b6565bc91c2c24bfa0c8ffb42dbfe/heimdall/cli/history.py#L227) | [commit concurrent : refus API et CLI](https://github.com/Cezar277/heimdall/blob/78c7f7f0af1b6565bc91c2c24bfa0c8ffb42dbfe/tests/test_history.py#L290) |
| #109 / Conception, disponibilité | Lots et mémoire bornés ; fichier trop gros signalé et scan incomplet en code 2 | [budgets et cache](https://github.com/Cezar277/heimdall/blob/78c7f7f0af1b6565bc91c2c24bfa0c8ffb42dbfe/heimdall/cli/history.py#L22) | [blob jamais lu au-delà du plafond](https://github.com/Cezar277/heimdall/blob/78c7f7f0af1b6565bc91c2c24bfa0c8ffb42dbfe/tests/test_history.py#L108), [budgets](https://github.com/Cezar277/heimdall/blob/78c7f7f0af1b6565bc91c2c24bfa0c8ffb42dbfe/tests/test_history.py#L156), [mesure 5000 commits](https://github.com/Cezar277/heimdall/blob/78c7f7f0af1b6565bc91c2c24bfa0c8ffb42dbfe/bench-results/t38-synthetic.json#L1) |
| #110 / Vérification, preuve opérateur | Alerte compromis/révocation et mesure du temps | [render_history](https://github.com/Cezar277/heimdall/blob/78c7f7f0af1b6565bc91c2c24bfa0c8ffb42dbfe/heimdall/cli/history.py#L241) | [alerte et absence de secret brut](https://github.com/Cezar277/heimdall/blob/78c7f7f0af1b6565bc91c2c24bfa0c8ffb42dbfe/tests/test_history.py#L35), [mesures et limites](t38-completion.md) |

Tests ciblés après cette correction : **54 passed**, couverture **95,40 %**.
[Journal permanent](https://github.com/Cezar277/heimdall/blob/78c7f7f0af1b6565bc91c2c24bfa0c8ffb42dbfe/bench-results/t38-review-targeted-tests.txt#L1).
Résultats complets après correction : voir [t38-completion.md](t38-completion.md).
Les mesures historiques de performance ne sont pas des mesures du correctif ;
les refus sur Flask/Click restent explicitement consignés. Aucune CI distante
n'est revendiquée ni déclenchée.

## Complément LOW : contrat des SHA et disponibilité de l'affichage

| Pratique SAMM / exigence | Implémentation permanente | Test permanent |
| --- | --- | --- |
| Vérification / contrat d'erreur : références, HEAD et rev-list non ASCII ou SHA invalide → `ScanError` statique | [_history_object](https://github.com/Cezar277/heimdall/blob/7000236ef4e584d3b6604a206da65f95db07c606/heimdall/cli/history.py#L62), utilisé par `_tips` et la boucle des commits | [six cas, bibliothèque et CLI](https://github.com/Cezar277/heimdall/blob/7000236ef4e584d3b6604a206da65f95db07c606/tests/test_history.py#L320) |
| Conception / disponibilité : au plus dix SHA par finding en texte, nombre restant visible ; JSON exhaustif | [rendu borné](https://github.com/Cezar277/heimdall/blob/7000236ef4e584d3b6604a206da65f95db07c606/heimdall/cli/history.py#L275), [JSON exhaustif](https://github.com/Cezar277/heimdall/blob/7000236ef4e584d3b6604a206da65f95db07c606/heimdall/cli/history.py#L258) | [10, 11 et 10 000 commits, SHA-1 et SHA-256 ; texte < 1200 octets dans ces cas et JSON complet](https://github.com/Cezar277/heimdall/blob/7000236ef4e584d3b6604a206da65f95db07c606/tests/test_history.py#L355) |

**66 tests ciblés passent**, couverture cold start + historique **95,54 %**.
[Journal permanent](https://github.com/Cezar277/heimdall/blob/7000236ef4e584d3b6604a206da65f95db07c606/bench-results/t38-low-targeted-tests.txt#L1).
Ruff, Mypy strict (48 fichiers) et Bandit passent. Ce complément ne revendique
pas de nouvelle exécution de la suite complète ni de CI distante ; le dernier
résultat global archivé reste celui du correctif précédent.

## Complément : emplacements multiples et contrats de bibliothèque

| Exigence / menace | Implémentation permanente | Preuve permanente |
| --- | --- | --- |
| #108 / exhaustivité : conserver chaque fichier contenant la même valeur | [records par type/HMAC/fichier](https://github.com/Cezar277/heimdall/blob/359155d191fd758431594addbff0a6870213f1d8/heimdall/cli/history.py#L249) | [copies dans deux fichiers puis suppression, blobs identiques ou distincts, texte et JSON](https://github.com/Cezar277/heimdall/blob/359155d191fd758431594addbff0a6870213f1d8/tests/test_history.py#L377) |
| #108 / contrat d'erreur : racine et appels Git → ScanError statique | [collect_history](https://github.com/Cezar277/heimdall/blob/359155d191fd758431594addbff0a6870213f1d8/heimdall/cli/history.py#L109), [collect_cold_start](https://github.com/Cezar277/heimdall/blob/359155d191fd758431594addbff0a6870213f1d8/heimdall/cli/cold_start.py#L113), [collect](https://github.com/Cezar277/heimdall/blob/359155d191fd758431594addbff0a6870213f1d8/heimdall/cli/scan.py#L169) | [racine absente](https://github.com/Cezar277/heimdall/blob/359155d191fd758431594addbff0a6870213f1d8/tests/test_history.py#L407), [pannes constructeur/execute/read_capped](https://github.com/Cezar277/heimdall/blob/359155d191fd758431594addbff0a6870213f1d8/tests/test_history.py#L420), [blob_size/blob_bytes et taille négative](https://github.com/Cezar277/heimdall/blob/359155d191fd758431594addbff0a6870213f1d8/tests/test_history.py#L447), [limites invalides en arbre et index](https://github.com/Cezar277/heimdall/blob/359155d191fd758431594addbff0a6870213f1d8/tests/test_history.py#L441) |
| Gouvernance / état opérateur : journal injectable, aucune écriture en CI | [propagation journal](https://github.com/Cezar277/heimdall/blob/359155d191fd758431594addbff0a6870213f1d8/heimdall/cli/history.py#L231) | [faux positif dans le journal injecté](https://github.com/Cezar277/heimdall/blob/359155d191fd758431594addbff0a6870213f1d8/tests/test_history.py#L212), [journal CI absent](https://github.com/Cezar277/heimdall/blob/359155d191fd758431594addbff0a6870213f1d8/tests/test_history.py#L472) |
| #108 / confinement : lire le texte des liens sans suivre leur cible | [120000 inclus, 160000 exclu](https://github.com/Cezar277/heimdall/blob/359155d191fd758431594addbff0a6870213f1d8/heimdall/cli/history.py#L95) | [cible contenant le secret, vue par staged et retrouvée après suppression du lien, aucun lien sur disque](https://github.com/Cezar277/heimdall/blob/359155d191fd758431594addbff0a6870213f1d8/tests/test_history.py#L485) |

**93 tests ciblés passent**, couverture cold start + historique **95,69 %**.
[Journal permanent](https://github.com/Cezar277/heimdall/blob/359155d191fd758431594addbff0a6870213f1d8/bench-results/t38-audit-targeted-tests.txt#L1).
Ruff, Mypy strict (48 fichiers) et Bandit passent. Résultat de la suite
complète après ce complément : [t38-completion.md](t38-completion.md).
Le SHA final de merge est encore inconnu : à inscrire ici après la fusion
effective par le relecteur ; aucun SHA de branche n'est présenté comme SHA de merge.

## Complément LOW : lecture de HEAD et erreur de décodage

Snapshot corrigé : `1de5b13dc9790d9836cf27778e2cccdfe03d75e9`.

| Exigence | Implémentation permanente | Test permanent |
| --- | --- | --- |
| Confinement Git : neutralisation explicite des objets remplacés pour HEAD, en plus de l'environnement | [argv HEAD avec --no-replace-objects](https://github.com/Cezar277/heimdall/blob/1de5b13dc9790d9836cf27778e2cccdfe03d75e9/heimdall/cli/history.py#L75) | [les cas HEAD vérifient aussi l'option explicite](https://github.com/Cezar277/heimdall/blob/1de5b13dc9790d9836cf27778e2cccdfe03d75e9/tests/test_history.py#L317) |
| Contrat d'erreur bibliothèque : échec de décodage à la relecture → ScanError « contenu modifié depuis le scan déterministe » | [conversion du décodage](https://github.com/Cezar277/heimdall/blob/1de5b13dc9790d9836cf27778e2cccdfe03d75e9/heimdall/cli/cold_start.py#L166) | [mutation vers un contenu indécodable, message exact en API, code 2 en CLI](https://github.com/Cezar277/heimdall/blob/1de5b13dc9790d9836cf27778e2cccdfe03d75e9/tests/test_cold_start.py#L159) |

**94 tests ciblés passent**, couverture **95,72 %**.
[Journal permanent](https://github.com/Cezar277/heimdall/blob/1de5b13dc9790d9836cf27778e2cccdfe03d75e9/bench-results/t38-head-decode-tests.txt#L1).
Ruff, format des quatre fichiers modifiés, Mypy strict (48 fichiers), Bandit
et `git diff --check` passent. La suite complète n'est pas relancée pour ce
complément de deux chemins ; sa dernière preuve globale reste celle de
`359155d` (**2304 passed**, **91,54 %**). Aucun `/ci` n'est envoyé.
Le SHA de merge reste à renseigner après fusion effective.

## Archive : preuve initiale T38.1 / #107, avant extension du périmètre

Périmètre : entonnoir regex/entropie puis LLM local.
Ticket : [#107](https://github.com/Cezar277/heimdall/issues/107).
PR : [#193](https://github.com/Cezar277/heimdall/pull/193).
Les sous-tickets #108–#110 ne sont pas couverts par cette preuve.
Le complément d'implémentation et les mesures de ces sous-tickets sont dans
[t38-completion.md](t38-completion.md).

Commit de code vérifié : `808ceab1a855cc82fc76020a0e29507c8fec1fe5`.

## Mapping pour la feuille SAMM

| Domaine / pratique SAMM | Exigence concrète et menace | Implémentation (module + ligne permanente) | Preuve de vérification |
| --- | --- | --- | --- |
| Gouvernance / Politique et conformité | Règle locale : aucune décision autonome du LLM, aucun appel ni journal LLM en CI | [cold_start.py:105](https://github.com/Cezar277/heimdall/blob/808ceab1a855cc82fc76020a0e29507c8fec1fe5/heimdall/cli/cold_start.py#L105), [avis consultatif, cold_start.py:155](https://github.com/Cezar277/heimdall/blob/808ceab1a855cc82fc76020a0e29507c8fec1fe5/heimdall/cli/cold_start.py#L155) | [CI avec --llm explicite, test_cold_start.py:206](https://github.com/Cezar277/heimdall/blob/808ceab1a855cc82fc76020a0e29507c8fec1fe5/tests/test_cold_start.py#L206), [faux positif conservé et journalisé, ligne 76](https://github.com/Cezar277/heimdall/blob/808ceab1a855cc82fc76020a0e29507c8fec1fe5/tests/test_cold_start.py#L76) |
| Conception / Exigences de sécurité | Divulgation : ne transmettre que des candidats masqués avec contexte borné | [candidate_context, cold_start.py:61](https://github.com/Cezar277/heimdall/blob/808ceab1a855cc82fc76020a0e29507c8fec1fe5/heimdall/cli/cold_start.py#L61) | [1 appel pour 2001 lignes, test_cold_start.py:47](https://github.com/Cezar277/heimdall/blob/808ceab1a855cc82fc76020a0e29507c8fec1fe5/tests/test_cold_start.py#L47) |
| Conception / Architecture sécurisée | Disponibilité : au plus 256 candidats, échéance partagée de 300 s ; timeout T28 conservé pour l'appel en cours | [limites et échéance, cold_start.py:32](https://github.com/Cezar277/heimdall/blob/808ceab1a855cc82fc76020a0e29507c8fec1fe5/heimdall/cli/cold_start.py#L32), [contrôles entre candidats, ligne 79](https://github.com/Cezar277/heimdall/blob/808ceab1a855cc82fc76020a0e29507c8fec1fe5/heimdall/cli/cold_start.py#L79) | [257 refusés avant appel, test_cold_start.py:125](https://github.com/Cezar277/heimdall/blob/808ceab1a855cc82fc76020a0e29507c8fec1fe5/tests/test_cold_start.py#L125), [256 acceptés, ligne 142](https://github.com/Cezar277/heimdall/blob/808ceab1a855cc82fc76020a0e29507c8fec1fe5/tests/test_cold_start.py#L142), [deadline dans un même fichier, ligne 223](https://github.com/Cezar277/heimdall/blob/808ceab1a855cc82fc76020a0e29507c8fec1fe5/tests/test_cold_start.py#L223) |
| Conception / Architecture sécurisée | Altération : vérifier racine et candidats entre les passes ; refus par défaut sur chemin échappé | [collect_cold_start, cold_start.py:105](https://github.com/Cezar277/heimdall/blob/808ceab1a855cc82fc76020a0e29507c8fec1fe5/heimdall/cli/cold_start.py#L105) | [mutation de contenu, test_cold_start.py:153](https://github.com/Cezar277/heimdall/blob/808ceab1a855cc82fc76020a0e29507c8fec1fe5/tests/test_cold_start.py#L153), [substitution de racine identique, ligne 256](https://github.com/Cezar277/heimdall/blob/808ceab1a855cc82fc76020a0e29507c8fec1fe5/tests/test_cold_start.py#L256), [PathEscape vers ScanError statique, ligne 286](https://github.com/Cezar277/heimdall/blob/808ceab1a855cc82fc76020a0e29507c8fec1fe5/tests/test_cold_start.py#L286) |
| Vérification / Tests pilotés par les exigences | Échec du journal = erreur d'outillage, jamais faux positif silencieux | [propagation de qualify_finding, cold_start.py:79](https://github.com/Cezar277/heimdall/blob/808ceab1a855cc82fc76020a0e29507c8fec1fe5/heimdall/cli/cold_start.py#L79) | [JournalError en API et code 2 en CLI, test_cold_start.py:182](https://github.com/Cezar277/heimdall/blob/808ceab1a855cc82fc76020a0e29507c8fec1fe5/tests/test_cold_start.py#L182) |
| Vérification / Tests pilotés par les exigences | Re-scan sans allowlist : sur-ensemble volontaire, mêmes défauts d'entropie et HMAC | [commentaire et moteur avec deadline, cold_start.py:138](https://github.com/Cezar277/heimdall/blob/808ceab1a855cc82fc76020a0e29507c8fec1fe5/heimdall/cli/cold_start.py#L138) | [parité regex et entropie entre moteurs, test_cold_start.py:303](https://github.com/Cezar277/heimdall/blob/808ceab1a855cc82fc76020a0e29507c8fec1fe5/tests/test_cold_start.py#L303) |

## Résultats locaux — 25 octobre 2026

Environnement : Debian / WSL, Python 3.13.5, dépendances de développement
du projet installées dans `/home/nathan/heimdall-t33-venv`.
Les modèles sont simulés : aucun test ciblé ne contacte Ollama.

| Contrôle | Résultat |
| --- | --- |
| `python -m pytest tests/test_cold_start.py --cov=heimdall.cli.cold_start --cov-branch --cov-report=term-missing --cov-fail-under=85` | **19 passed**, couverture **96,88 %** |
| `ruff check heimdall tests scripts` | Succès |
| `ruff format --check heimdall/cli/cold_start.py tests/test_cold_start.py` | 2 fichiers conformes |
| `mypy heimdall tests/contracts/fastapi_contract_fixture.py scripts/regen_lock.py` | **47 fichiers**, aucune erreur |
| `bandit -r heimdall -q` | Succès |
| `python -m pytest --cov=heimdall --cov-branch --cov-report=term-missing --cov-fail-under=85` | **2230 passed**, **16 skipped**, **4480 subtests passed**, 7 avertissements ; couverture globale **91,22 %**, durée **244,33 s** |

La CI distante reste non déclenchée, conformément à la consigne utilisateur.
Cette preuve ne déclare pas un check CI vert.

## Limite de disponibilité documentée

L'échéance de 300 s est coopérative : une requête Ollama déjà en cours conserve
son timeout réseau T28 de 60 s. Aucun nouveau candidat n'est lancé après
expiration ; le dépassement donne un code 2. Voir
[cold-start.md](cold-start.md) pour le contrat opérateur et les commandes Windows.
