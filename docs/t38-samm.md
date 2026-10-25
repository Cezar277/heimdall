# T38.1 / #107 — preuves SAMM après revue

Périmètre : entonnoir regex/entropie puis LLM local.
Ticket : [#107](https://github.com/Cezar277/heimdall/issues/107).
PR : [#193](https://github.com/Cezar277/heimdall/pull/193).
Les sous-tickets #108–#110 ne sont pas couverts par cette preuve.

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
