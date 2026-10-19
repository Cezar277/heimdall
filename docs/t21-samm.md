# T21 — preuves pour la ligne SAMM

Périmètre : tests d'acceptation fonctionnels et de sécurité de T21 (#49–#52).
Cette fiche versionnée fournit les couples module + ligne et les permaliens
du code testé ; elle ne prétend pas modifier une feuille externe.

Révision des preuves : `c2c2d1df069a40b658176e884b45049bfc5ac191`.

| Exigence vérifiée | Implémentation (module + ligne) | Test et preuve permanente | Résultat local |
|---|---|---|---|
| Refuser toute sortie scanner non conforme sans révéler son contenu | [tests/support/trap_corpus.py:96–109](https://github.com/Cezar277/heimdall/blob/c2c2d1df069a40b658176e884b45049bfc5ac191/tests/support/trap_corpus.py#L96-L109) | [tests/test_trap_acceptance.py:69–101](https://github.com/Cezar277/heimdall/blob/c2c2d1df069a40b658176e884b45049bfc5ac191/tests/test_trap_acceptance.py#L69-L101) : erreurs, sorties invalides, traversal, chemin absolu et séparateur Windows | Réussi |
| Mesurer par position, dédupliquer et conserver les FN des obfuscations | [tests/support/trap_corpus.py:69–93](https://github.com/Cezar277/heimdall/blob/c2c2d1df069a40b658176e884b45049bfc5ac191/tests/support/trap_corpus.py#L69-L93) | [tests/test_trap_acceptance.py:42–66](https://github.com/Cezar277/heimdall/blob/c2c2d1df069a40b658176e884b45049bfc5ac191/tests/test_trap_acceptance.py#L42-L66) : VP/FP/FN calculés à la main, cas vide | Réussi |
| Distinguer seuils insuffisants (1) et mesure impossible (2) sans refléter d'exception | [tests/measure_trap.py:11–26](https://github.com/Cezar277/heimdall/blob/c2c2d1df069a40b658176e884b45049bfc5ac191/tests/measure_trap.py#L11-L26) | [tests/test_trap_acceptance.py:152–195](https://github.com/Cezar277/heimdall/blob/c2c2d1df069a40b658176e884b45049bfc5ac191/tests/test_trap_acceptance.py#L152-L195) : seuils, T22 absent, ValueError/OSError/RuntimeError, dossier temporaire indisponible | Réussi |
| Ne versionner que des gabarits, générer les valeurs synthétiques temporairement | [tests/support/trap_corpus.py:55–66](https://github.com/Cezar277/heimdall/blob/c2c2d1df069a40b658176e884b45049bfc5ac191/tests/support/trap_corpus.py#L55-L66) | [tests/test_trap_acceptance.py:198–201](https://github.com/Cezar277/heimdall/blob/c2c2d1df069a40b658176e884b45049bfc5ac191/tests/test_trap_acceptance.py#L198-L201) ; contrôle du diff de livraison | Réussi |

Commande : `python -m pytest tests/test_trap_acceptance.py -s -rx`.
Résultat après corrections de revue : **23 passed, 1 xfailed**.
Le XFAIL concerne seulement le scanner T22 non livré ; cette fiche ne prouve
ni ses performances ni la réussite de la CI Linux. La preuve CI du SHA final
est suivie dans la [PR #153](https://github.com/Cezar277/heimdall/pull/153).
