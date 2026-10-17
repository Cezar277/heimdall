# Preuve de confinement réseau — T28.4 (#82)

## Contrôle automatisé

`tests/test_network_isolation.py` intercepte `connect`, `connect_ex`,
`send`, `sendall`, `sendto` (adresse positionnelle ou en mot-clé), `sendmsg`,
`sendfile` (méthode `Socket.sendfile` et `os.sendfile` direct par descripteur),
`os.write` / `os.writev` sur un descripteur de socket, ainsi que les **six**
méthodes que `ssl.SSLSocket` surcharge (`send`, `sendall`, `write`, `sendto`,
`sendmsg`, `sendfile` — elles n'appellent pas celles de `socket.socket`), puis
`getaddrinfo`, `gethostbyname`, `gethostbyname_ex`, `gethostbyaddr` et
`getnameinfo`. Le journal du garde enregistre aussi les tentatives refusées :
les avaler dans une exception n'empêche pas le test de les détecter. Le test
lance `heimdall scan --ci` dans le processus pytest et vérifie l'absence de
tentative Internet.

Les alias `from socket import getaddrinfo` sont couverts lorsqu'ils sont
importés **après** le patch : le nom est relu sur le module `socket` à chaque
appel (verrouillé par `test_guard_blocks_dns_through_import_alias`). L'API
Python standard n'expose pas `sendmmsg` ; les extensions natives qui
appelleraient directement des syscalls contournent les wrappers et relèvent de
la trace OS.

Limites explicites : les sockets `AF_UNIX` sont permises comme IPC local et
pourraient théoriquement servir de relais via un autre processus ; toute
**référence capturée avant le patch** (`orig = socket.getaddrinfo`,
`from os import write`, `from os import sendfile`, valeur par défaut liée à
l'import) garde l'original — trou connu, verrouillé pour DNS par
`test_early_bound_dns_alias_runs_unguarded_and_is_documented` et pour `os.*`
par `test_early_bound_os_write_runs_unguarded_and_is_documented` ; les
extensions natives qui appellent directement les syscalls réseau (sans passer
par les méthodes Python) ne sont pas couvertes. Piège vérifié : `strace -e
trace=%network` ne trace **pas** `write`/`writev` génériques — une écriture
directe sur un descripteur de socket déjà connecté n'y apparaîtrait pas ; le
rejeu OS utilise donc `-e trace=%network,write,writev,sendfile`, ce qui couvre
aussi les alias `os.*` précoces. Les écritures par descripteur (`os.write`,
`os.writev`, `os.sendfile`) sont refusées sauf si le descripteur appartient à
une socket loopback épinglée (un descripteur `AF_UNIX` y est donc refusé : plus
strict que le chemin socket, fail-closed). Ce garde n'est donc pas un pare-feu :
la trace système ci-dessous est nécessaire en complément.

Commande :

```sh
.venv/bin/python -m pytest tests/test_network_isolation.py -q
```

Résultat observé le 17/10/2026 :

```text
.............................                                            [100%]
```

Suite complète avec la couverture CI : **712 passed**, 3 831 sous-tests,
couverture Heimdall **99,48 %** (seuil CI : 85 %).

## Observation système

Commande exécutée depuis la racine du dépôt le **2026-10-17 à 21:26:31 +02:00**
(trace des syscalls réseau **et** des écritures — `%network` seul ne couvre pas
`write`/`writev` ; `-yy` affiche les objets associés aux descripteurs, `-ttt`
les horodatages, `-s 256` la taille des chaînes) :

```sh
strace -f -yy -ttt -s 256 -e trace=%network,write,writev,sendfile \
  -o docs/security/zero-egress.strace .venv/bin/heimdall scan --ci .
```

Sortie observée (stderr du scan, code de sortie 2) :

```text
heimdall scan: scanner non implémenté (voir #22) — refus par défaut.
exit=2
```

La trace complète archivée est
[`zero-egress.strace`](zero-egress.strace) — SHA-256
`e8394de48de71a6e8a8662613757166723e44de2f1179d9216fa365286987fd2`. Ses deux
lignes :

```text
326853 1792265191.622802 write(2<UNIX-STREAM:[1261377->1261376]>, "heimdall scan: scanner non implémenté (voir #22) — refus par défaut.\n", 74) = 74
326853 1792265191.727635 +++ exited with 2 +++
```

Même PID `326853` sur les deux lignes (pas de fork), horodatage Unix
`1792265191.622802` = 2026-10-17 21:26:31 +02:00. La **seule** écriture tracée
est le message d'erreur attendu vers le descripteur 2, que `-yy` résout en
socketpair UNIX local (`UNIX-STREAM:[…]`, capture du terminal) — pas une socket
IP. **Aucun `connect`, `sendto`, `sendmsg`, `sendfile` ni résolution DNS n'est
tracé** ; le message observé est inclus dans le syscall, ce qui rattache la
sortie au processus du scan. L'empreinte permet de vérifier que la trace n'a
pas été modifiée après coup, mais elle n'est **pas signée** : elle ne doit pas
être comptabilisée comme preuve runtime avant un artefact CI signé (trace et
stdout/stderr attachés au job, piste de durcissement hors périmètre #82).

La sortie d'erreur du scan (fd 2) est `heimdall scan: scanner non implémenté
(voir #22) — refus par défaut.` Le code 2 est le refus fail-closed attendu, pas
un scan réussi. `unshare --net` a aussi été essayé pour couper le réseau au niveau
du namespace, mais l'environnement refuse cette opération (`Operation not
permitted`).

## Limite de la preuve et suite requise

Le scanner #22 n'est pas encore implémenté et la commande CLI s'arrête avant
tout scan réel. Cette preuve établit donc que le chemin CLI actuel (bloqué) ne
crée pas de connexion, et que le garde CI bloque les destinations externes ;
elle **ne prouve pas** qu'un scan opérationnel complet fonctionne hors ligne.
Après livraison du scanner et de son orchestration, rejouer le test sur un dépôt
de test, puis capturer la sortie complète de
`strace -f -e trace=%network,write,writev,sendfile` sous réseau effectivement
coupé. Le client Ollama est déjà épinglé à
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
