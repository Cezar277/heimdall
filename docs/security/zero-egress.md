# Preuve de confinement réseau — T28.4 (#82)

## Contrôle automatisé

`tests/test_network_isolation.py` intercepte `connect`, `connect_ex`,
`send`, `sendall`, `sendto`, `sendmsg`, `getaddrinfo`, `gethostbyname`,
`gethostbyname_ex`, `gethostbyaddr` et `getnameinfo`. Le journal du garde
enregistre aussi les tentatives refusées : les avaler dans une exception
n'empêche pas le test de les détecter. Le test lance `heimdall scan --ci` dans
le processus pytest et vérifie l'absence de tentative Internet. L'API Python
standard n'expose pas `sendmmsg` ; les extensions natives qui appelleraient
directement des syscalls contournent les wrappers et relèvent de la trace OS.

Limites explicites : les sockets `AF_UNIX` sont permises comme IPC local et
pourraient théoriquement servir de relais via un autre processus ; les appels
réseau effectués directement par une extension native contournent les wrappers
Python. Ce garde n'est donc pas un pare-feu. La trace système ci-dessous est
nécessaire en complément.

Commande :

```sh
.venv/bin/python -m pytest tests/test_network_isolation.py -q
```

Résultat observé le 17/10/2026 :

```text
.................                                                        [100%]
```

Suite complète avec la couverture CI : **700 passed**, 3 831 sous-tests,
couverture Heimdall **99,48 %** (seuil CI : 85 %).

## Observation système

Commande exécutée depuis la racine du dépôt (trace des syscalls réseau, y
compris `sendto`/`sendmsg`, et pas seulement `connect`) :

```sh
strace -f -e trace=%network -o docs/security/zero-egress.strace \
  .venv/bin/heimdall scan --ci .
```

Sortie observée :

```text
heimdall scan: scanner non implémenté (voir #22) — refus par défaut.
+++ exited with 2 +++
```

La trace complète archivée est
[`zero-egress.strace`](zero-egress.strace) : elle ne contient aucun syscall
réseau, uniquement la terminaison `exited with 2`. La sortie standard est
`heimdall scan: scanner non implémenté (voir #22) — refus par défaut.` Le code 2
est le refus fail-closed attendu, pas un scan réussi. `unshare --net` a aussi
été essayé pour couper le réseau au niveau du namespace, mais l'environnement
refuse cette opération (`Operation not permitted`).

## Limite de la preuve et suite requise

Le scanner #22 n'est pas encore implémenté et la commande CLI s'arrête avant
tout scan réel. Cette preuve établit donc que le chemin CLI actuel (bloqué) ne
crée pas de connexion, et que le garde CI bloque les destinations externes ;
elle **ne prouve pas** qu'un scan opérationnel complet fonctionne hors ligne.
Après livraison du scanner et de son orchestration, rejouer le test sur un dépôt
de test, puis capturer la sortie complète de `strace -f -e trace=%network` sous
réseau effectivement coupé. Le client Ollama est déjà épinglé à
`127.0.0.1:11434`, sans proxy d'environnement ni redirections
(`heimdall/llm/qualify.py::_loopback_client`).

Un instantané global `ss -tunp` sur la machine de développement contient des
connexions appartenant à d'autres processus ; il ne permet pas d'attribuer ces
flux au scan et n'est pas archivé. Utiliser une trace attachée au seul
processus Heimdall pour la preuve runtime.

## Audit télémétrie

La recherche dans le code applicatif ne trouve pas de client ni d'exporteur de
télémétrie configuré, ni de variable `*_TELEMETRY` / `DO_NOT_TRACK`. Le lock
contient `opentelemetry-api` comme dépendance transitive, mais aucun exporteur
OpenTelemetry n'y est déclaré. L'exception réseau build-time documentée reste
`pip-audit` en CI, qui contacte PyPI ; elle n'est pas appelée par Heimdall au
runtime (voir [README](../../README.md#exception-réseau-documentée--pip-audit)).
