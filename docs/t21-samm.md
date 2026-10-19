# T21 — preuves pour la ligne SAMM

Périmètre : tests d'acceptation fonctionnels et de sécurité de T21 (#49–#52).
Cette fiche versionnée fournit les couples module + ligne et les permaliens
du code testé ; elle ne prétend pas modifier une feuille externe.

Révision des preuves : `7dd72766d48a8c4f56def41b0a81a2555a7b3b26`.

| Exigence vérifiée | Implémentation (module + ligne) | Test et preuve permanente | Résultat local |
|---|---|---|---|
| Refuser les sorties scanner non conformes sans exposer leur contenu | [tests/support/trap_corpus.py:102–115](https://github.com/Cezar277/heimdall/blob/7dd72766d48a8c4f56def41b0a81a2555a7b3b26/tests/support/trap_corpus.py#L102-L115) | [tests/test_trap_acceptance.py:70–102](https://github.com/Cezar277/heimdall/blob/7dd72766d48a8c4f56def41b0a81a2555a7b3b26/tests/test_trap_acceptance.py#L70-L102) | Réussi |
| Comparer les positions, dédupliquer et conserver les FN des obfuscations | [tests/support/trap_corpus.py:75–99](https://github.com/Cezar277/heimdall/blob/7dd72766d48a8c4f56def41b0a81a2555a7b3b26/tests/support/trap_corpus.py#L75-L99) | [tests/test_trap_acceptance.py:43–67](https://github.com/Cezar277/heimdall/blob/7dd72766d48a8c4f56def41b0a81a2555a7b3b26/tests/test_trap_acceptance.py#L43-L67) | Réussi |
| 1 = seuils ; 2 = mesure impossible, y compris import absent | [tests/measure_trap.py:9–26](https://github.com/Cezar277/heimdall/blob/7dd72766d48a8c4f56def41b0a81a2555a7b3b26/tests/measure_trap.py#L9-L26) | [tests/test_trap_acceptance.py:211–268](https://github.com/Cezar277/heimdall/blob/7dd72766d48a8c4f56def41b0a81a2555a7b3b26/tests/test_trap_acceptance.py#L211-L268) | Réussi |
| Confiner les chemins source et destination du corpus | [tests/support/trap_corpus.py:54–72](https://github.com/Cezar277/heimdall/blob/7dd72766d48a8c4f56def41b0a81a2555a7b3b26/tests/support/trap_corpus.py#L54-L72) | [tests/test_trap_acceptance.py:120–172](https://github.com/Cezar277/heimdall/blob/7dd72766d48a8c4f56def41b0a81a2555a7b3b26/tests/test_trap_acceptance.py#L120-L172) | Traversal réussi ; deux tests de liens ignorés sous Windows (WinError 1314) |
| Versionner des gabarits et générer les valeurs temporairement | [tests/support/trap_corpus.py:54–72](https://github.com/Cezar277/heimdall/blob/7dd72766d48a8c4f56def41b0a81a2555a7b3b26/tests/support/trap_corpus.py#L54-L72) | [tests/test_trap_acceptance.py:271–274](https://github.com/Cezar277/heimdall/blob/7dd72766d48a8c4f56def41b0a81a2555a7b3b26/tests/test_trap_acceptance.py#L271-L274) | Réussi |

Commande : `python -m pytest tests/test_trap_acceptance.py -s -rx`.
Résultat après durcissement : **25 passed, 2 skipped, 1 xfailed**.
Les deux tests nécessitant des liens symboliques sont ignorés uniquement
sur Windows lorsque leur création est refusée (WinError 1314) ; ils restent
exécutables sur POSIX. Le XFAIL concerne le scanner T22 non livré.
Le CLI exécuté avec `python -I -S tests/measure_trap.py` (paquets absents)
retourne aussi 2 avec un message fixe et sans traceback.

Cette fiche ne prouve ni les performances du scanner T22 ni la réussite de
la CI Linux. La preuve CI du SHA final et l'accord explicite du relecteur
sur l'exception de regroupement restent requis avant fusion de la
[PR #153](https://github.com/Cezar277/heimdall/pull/153).
