# Preuve de confinement réseau — T28.4 (#82)

## Contrôle automatisé

`tests/test_network_isolation.py` remplace `socket.socket.connect`,
`connect_ex`, `sendto` et `socket.getaddrinfo`. Le garde refuse toute
destination IP non-loopback et tout nom d'hôte avant l'appel système ou le
résolveur DNS. Il lance `heimdall scan --ci` dans le processus pytest et
vérifie que la commande ne tente aucune connexion externe. Des tests vérifient
également que le garde bloque TCP, UDP, IPv6 et la résolution DNS, et laisse
les adresses loopback littérales admises.

Commande :

```sh
.venv/bin/python -m pytest tests/test_network_isolation.py -q
```

Résultat observé le 17/10/2026 :

```text
........                                                                 [100%]
```

Suite complète avec la couverture CI : **691 passed**, 3 831 sous-tests,
couverture Heimdall **99,48 %** (seuil CI : 85 %).

## Observation système

Commande exécutée depuis la racine du dépôt :

```sh
strace -f -e trace=connect .venv/bin/heimdall scan --ci .
```

Sortie observée :

```text
heimdall scan: scanner non implémenté (voir #22) — refus par défaut.
+++ exited with 2 +++
```

Aucun syscall `connect` n'apparaît dans la trace. Le code 2 est le refus
fail-closed attendu, pas un scan réussi. `unshare --net` a aussi été essayé
pour couper le réseau au niveau du namespace, mais l'environnement refuse
cette opération (`Operation not permitted`).

## Limite de la preuve et suite requise

Le scanner #22 n'est pas encore implémenté et la commande CLI s'arrête avant
tout scan réel. Cette preuve établit donc que le chemin CLI actuel (bloqué) ne
crée pas de connexion, et que le garde CI bloque les destinations externes ;
elle **ne prouve pas** qu'un scan opérationnel complet fonctionne hors ligne.
Après livraison du scanner et de son orchestration, rejouer le test sur un dépôt
de test, puis capturer une trace `strace -f -e trace=connect` sous réseau
effectivement coupé. Le client Ollama est déjà épinglé à
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
