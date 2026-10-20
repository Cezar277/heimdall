# Preuve de confinement réseau — T28.4 (#82)

## Contrôle automatisé

`tests/test_network_isolation.py` intercepte `connect`, `connect_ex`,
`send`, `sendall`, `sendto` (adresse positionnelle ou en mot-clé), `sendmsg`,
`sendfile` (méthode `Socket.sendfile` et `os.sendfile` direct par descripteur),
`os.write` / `os.writev` sur un descripteur de socket, ainsi que les **six**
méthodes que `ssl.SSLSocket` surcharge (`send`, `sendall`, `write`, `sendto`,
`sendmsg`, `sendfile` — elles n'appellent pas celles de `socket.socket`), puis
`getaddrinfo`, `gethostbyname`, `gethostbyname_ex`, `gethostbyaddr` et
`getnameinfo`. Le lancement de processus enfants est refusé et journalisé
pour `subprocess.Popen` **par accès d'attribut** (donc `run`/`call`/`check_*`
qui le résolvent dans le module) et pour `os.system`, `os.fork`/`forkpty`,
`os.posix_spawn(p)`, `os.exec*` : un enfant échapperait aux patchs de sockets.
Le journal du garde enregistre aussi les tentatives refusées : les
avaler dans une exception n'empêche pas le test de les détecter. Le test lance
`heimdall scan --ci` dans le processus pytest et vérifie l'absence de tentative
Internet.

Les alias `from socket import getaddrinfo` sont couverts lorsqu'ils sont
importés **après** le patch : le nom est relu sur le module `socket` à chaque
appel (verrouillé par `test_guard_blocks_dns_through_import_alias`). L'API
Python standard n'expose pas `sendmmsg` ; les extensions natives qui
appelleraient directement des syscalls contournent les wrappers et relèvent de
la trace OS.

Limites explicites : les sockets `AF_UNIX` sont permises comme IPC local et
pourraient théoriquement servir de relais via un autre processus — asymétrie
assumée et verrouillée par
`test_guard_allows_af_unix_send_but_refuses_fd_write` : `socket.send` sur
`AF_UNIX` est autorisé (journalisé comme exception), tandis qu'une écriture par
descripteur (`os.write`/`os.writev`/`os.sendfile`) vers un fd `AF_UNIX` est
refusée (fd jamais épinglé). Toute
**référence capturée avant le patch** (`orig = socket.getaddrinfo`,
`from os import write`, `from os import sendfile`,
`from subprocess import Popen`, valeur par défaut liée à l'import) garde
l'original — trou connu, verrouillé par les trois tests miroirs
`test_early_bound_dns_alias_runs_unguarded_and_is_documented` (DNS),
`test_early_bound_os_write_runs_unguarded_and_is_documented` (`os.*`) et
`test_early_bound_subprocess_popen_runs_unguarded_and_is_documented`
(`subprocess`). Les extensions natives qui appellent directement les syscalls
réseau (sans passer par les méthodes Python) ne sont pas couvertes. Un
processus enfant lancé **hors wrappers Python** — extension native, binaire
appelant `fork(2)`/`execve(2)`, alias `Popen` précoce, méthode de démarrage
`spawn`/`forkserver` de `multiprocessing` (chemin C `_posixsubprocess`) —
reste hors garde : un enfant émet ses propres connexions, non patchées ; le
filet est `strace -f`, qui suit les forks — d'où `execve` dans le filtre du
rejeu. Piège vérifié : `strace -e
trace=%network` ne trace **pas** `write`/`writev` génériques — une écriture
directe sur un descripteur de socket déjà connecté n'y apparaîtrait pas ; le
rejeu OS utilise donc `-e trace=execve,%network,write,writev,sendfile`, ce qui
couvre aussi les alias `os.*` précoces. Un relais inter-processus via socket
Unix reste hors du garde et n'apparaît dans la trace que s'il ressort en IP.
Ce garde n'est donc pas un pare-feu : la trace système ci-dessous est
nécessaire en complément.

Commande :

```sh
.venv/bin/python -m pytest tests/test_network_isolation.py -q
```

Résultat observé le 17/10/2026 :

```text
................................................                         [100%]
```

Suite complète avec la couverture CI : **731 passed**, 3 831 sous-tests,
couverture Heimdall **99,48 %** (seuil CI : 85 %).

## Observation système

Commande exécutée depuis la racine du dépôt le **2026-10-17 à 21:48:51 +02:00**
(trace de l'`execve`, des syscalls réseau **et** des écritures — `%network` seul
ne couvre pas `write`/`writev` ; `-yy` affiche les objets associés aux
descripteurs, `-ttt` les horodatages, `-s 256` la taille des chaînes) :

```sh
strace -f -yy -ttt -s 256 -e trace=execve,%network,write,writev,sendfile \
  -o docs/security/zero-egress.strace .venv/bin/heimdall scan --ci .
```

Sortie observée (stderr du scan, code de sortie 2) :

```text
heimdall scan: scanner non implémenté (voir #22) — refus par défaut.
exit=2
```

La trace complète archivée est
[`zero-egress.strace`](zero-egress.strace) — SHA-256
`5f1177a5c091045a5a370014ca62c72c86d063222f39b217583c35c07ab7bb8d`. Ses trois
lignes :

```text
342078 1792266531.746354 execve(".venv/bin/heimdall", [".venv/bin/heimdall", "scan", "--ci", "."], 0x7fff87da5d60 /* 75 vars */) = 0
342078 1792266532.223944 write(2<UNIX-STREAM:[1286795->1286794]>, "heimdall scan: scanner non impl\303\251ment\303\251 (voir #22) \342\200\224 refus par d\303\251faut.\n", 74) = 74
342078 1792266532.332271 +++ exited with 2 +++
```

Même PID `342078` sur les trois lignes (pas de fork) : l'`execve` montre la
commande exacte et son argv complet, le `write` porte le message d'erreur
attendu (UTF-8 échappé en octal dans le fichier) vers le descripteur 2, que
`-yy` résout en socketpair UNIX local (`UNIX-STREAM:[…]`, capture du terminal)
— pas une socket IP — et la dernière ligne donne la sortie code 2, horodatage
Unix `1792266531.746354` = 2026-10-17 21:48:51 +02:00. **Aucun `connect`,
`sendto`, `sendmsg`, `sendfile` ni résolution DNS n'est tracé.** L'empreinte
permet de vérifier que la trace n'a pas été modifiée après coup, mais elle
n'est **pas signée** : elle ne doit pas être comptabilisée comme preuve runtime
avant un artefact CI signé (trace et stdout/stderr attachés au job, piste de
durcissement hors périmètre #82).

La sortie d'erreur observée alors était `heimdall scan: scanner non implémenté
(voir #22) — refus par défaut.` (message depuis remplacé par `commande non
branchée (voir #29)` sans changer le code de sortie). Le code 2 est le refus
fail-closed attendu, pas un scan réussi. `unshare --net` a aussi été essayé pour couper le réseau au niveau
du namespace, mais l'environnement refuse cette opération (`Operation not
permitted`).

## Limite de la preuve et suite requise

Le module scanner #22 est livré, mais la commande CLI n'est pas encore branchée
(#29) : la commande s'arrête avant tout scan réel. Cette preuve établit donc que
le chemin CLI actuel (bloqué) ne crée pas de connexion, et que le garde CI
bloque les destinations externes ; elle **ne prouve pas** qu'un scan
opérationnel complet fonctionne hors ligne. Après branchement de #29, rejouer
le test sur un dépôt de test, puis capturer la sortie complète de
`strace -f -e trace=execve,%network,write,writev,sendfile` sous réseau
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
