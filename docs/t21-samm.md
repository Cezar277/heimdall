# T21 ? preuves pour la ligne SAMM

P?rim?tre : tests d'acceptation fonctionnels et de s?curit? de T21 (#49?#52).
Cette fiche versionn?e fournit les couples module + ligne et les permaliens
du code test? ; elle ne pr?tend pas modifier une feuille externe.

R?vision des preuves : `7dd72766d48a8c4f56def41b0a81a2555a7b3b26`.

| Exigence v?rifi?e | Impl?mentation (module + ligne) | Test et preuve permanente | R?sultat local |
|---|---|---|---|
| Refuser les sorties scanner non conformes sans exposer leur contenu | [tests/support/trap_corpus.py:102?115](https://github.com/Cezar277/heimdall/blob/7dd72766d48a8c4f56def41b0a81a2555a7b3b26/tests/support/trap_corpus.py#L102-L115) | [tests/test_trap_acceptance.py:70?102](https://github.com/Cezar277/heimdall/blob/7dd72766d48a8c4f56def41b0a81a2555a7b3b26/tests/test_trap_acceptance.py#L70-L102) | R?ussi |
| Comparer les positions, d?dupliquer et conserver les FN des obfuscations | [tests/support/trap_corpus.py:75?99](https://github.com/Cezar277/heimdall/blob/7dd72766d48a8c4f56def41b0a81a2555a7b3b26/tests/support/trap_corpus.py#L75-L99) | [tests/test_trap_acceptance.py:43?67](https://github.com/Cezar277/heimdall/blob/7dd72766d48a8c4f56def41b0a81a2555a7b3b26/tests/test_trap_acceptance.py#L43-L67) | R?ussi |
| 1 = seuils ; 2 = mesure impossible, y compris import absent | [tests/measure_trap.py:9?26](https://github.com/Cezar277/heimdall/blob/7dd72766d48a8c4f56def41b0a81a2555a7b3b26/tests/measure_trap.py#L9-L26) | [tests/test_trap_acceptance.py:211?268](https://github.com/Cezar277/heimdall/blob/7dd72766d48a8c4f56def41b0a81a2555a7b3b26/tests/test_trap_acceptance.py#L211-L268) | R?ussi |
| Confiner les chemins source et destination du corpus | [tests/support/trap_corpus.py:54?72](https://github.com/Cezar277/heimdall/blob/7dd72766d48a8c4f56def41b0a81a2555a7b3b26/tests/support/trap_corpus.py#L54-L72) | [tests/test_trap_acceptance.py:120?172](https://github.com/Cezar277/heimdall/blob/7dd72766d48a8c4f56def41b0a81a2555a7b3b26/tests/test_trap_acceptance.py#L120-L172) | Traversal r?ussi ; deux tests de liens ignor?s sous Windows (WinError 1314) |
| Versionner des gabarits et g?n?rer les valeurs temporairement | [tests/support/trap_corpus.py:54?72](https://github.com/Cezar277/heimdall/blob/7dd72766d48a8c4f56def41b0a81a2555a7b3b26/tests/support/trap_corpus.py#L54-L72) | [tests/test_trap_acceptance.py:271?274](https://github.com/Cezar277/heimdall/blob/7dd72766d48a8c4f56def41b0a81a2555a7b3b26/tests/test_trap_acceptance.py#L271-L274) | R?ussi |

Commande : `python -m pytest tests/test_trap_acceptance.py -s -rx`.
R?sultat apr?s durcissement : **25 passed, 2 skipped, 1 xfailed**.
Les deux tests n?cessitant des liens symboliques sont ignor?s uniquement
sur Windows lorsque leur cr?ation est refus?e (WinError 1314) ; ils restent
ex?cutables sur POSIX. Le XFAIL concerne le scanner T22 non livr?.
Le CLI ex?cut? avec `python -I -S tests/measure_trap.py` (paquets absents)
retourne aussi 2 avec un message fixe et sans traceback.

Cette fiche ne prouve ni les performances du scanner T22 ni la r?ussite de
la CI Linux. La preuve CI du SHA final et l'accord explicite du relecteur
sur l'exception de regroupement restent requis avant fusion de la
[PR #153](https://github.com/Cezar277/heimdall/pull/153).
