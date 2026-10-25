# T21 — preuves pour la ligne SAMM

Périmètre : tests d'acceptation fonctionnels et de sécurité de T21 (#49–#52).
Cette fiche fournit les couples module + ligne et les permaliens du code testé ;
elle ne prétend pas modifier une feuille externe.

Révision du code testé : `0b14b3826e60e5afed3ffc4577a2bf1c9d095c90`.

> Mise à jour #22 : le marqueur `xfail(strict)` de
> `test_scanner_precision_and_recall` a été retiré lorsque le scanner a été
> livré. Le résultat T21 ci-dessous reste l'instantané historique de la
> validation qui a précédé #22 ; la mesure courante est consignée dans
> [t22-samm.md](t22-samm.md).

Les permaliens épinglent la révision du code, pas le commit de documentation
qui archive cette fiche. Le code des trois modules référencés est inchangé
entre cette révision et le HEAD de livraison : contrôle effectué avec
`git diff 0b14b3826e60e5afed3ffc4577a2bf1c9d095c90 HEAD -- tests/support/trap_corpus.py tests/measure_trap.py tests/test_trap_acceptance.py`
(sortie vide). Les commits suivants de cette livraison modifient uniquement
la documentation. Cette distinction conserve des preuves stables sans
présenter une ancienne révision comme le HEAD final de la PR.

| Exigence vérifiée | Implémentation (module + ligne) | Test et preuve permanente | Résultat local |
|---|---|---|---|
| Refuser une sortie scanner invalide sans exposer son contenu | [tests/support/trap_corpus.py:108–121](https://github.com/Cezar277/heimdall/blob/0b14b3826e60e5afed3ffc4577a2bf1c9d095c90/tests/support/trap_corpus.py#L108-L121) | [tests/test_trap_acceptance.py:70–102](https://github.com/Cezar277/heimdall/blob/0b14b3826e60e5afed3ffc4577a2bf1c9d095c90/tests/test_trap_acceptance.py#L70-L102) | Réussi |
| Comparer les positions, dédupliquer et conserver les FN | [tests/support/trap_corpus.py:81–105](https://github.com/Cezar277/heimdall/blob/0b14b3826e60e5afed3ffc4577a2bf1c9d095c90/tests/support/trap_corpus.py#L81-L105) | [tests/test_trap_acceptance.py:43–67](https://github.com/Cezar277/heimdall/blob/0b14b3826e60e5afed3ffc4577a2bf1c9d095c90/tests/test_trap_acceptance.py#L43-L67) | Réussi |
| Codes 0/1/2 et message fixe, import absent inclus | [tests/measure_trap.py:9–26](https://github.com/Cezar277/heimdall/blob/0b14b3826e60e5afed3ffc4577a2bf1c9d095c90/tests/measure_trap.py#L9-L26) | [tests/test_trap_acceptance.py:242–299](https://github.com/Cezar277/heimdall/blob/0b14b3826e60e5afed3ffc4577a2bf1c9d095c90/tests/test_trap_acceptance.py#L242-L299) | Réussi |
| Confiner les gabarits, leur racine et leurs destinations | [tests/support/trap_corpus.py:54–78](https://github.com/Cezar277/heimdall/blob/0b14b3826e60e5afed3ffc4577a2bf1c9d095c90/tests/support/trap_corpus.py#L54-L78) | [tests/test_trap_acceptance.py:120–201](https://github.com/Cezar277/heimdall/blob/0b14b3826e60e5afed3ffc4577a2bf1c9d095c90/tests/test_trap_acceptance.py#L120-L201) | Traversal et erreur relative_to réussis ; trois tests de liens ignorés sous Windows (WinError 1314) |
| Forcer le retrait du XFAIL quand T22 passe | [tests/test_trap_acceptance.py:204–213](https://github.com/Cezar277/heimdall/blob/0b14b3826e60e5afed3ffc4577a2bf1c9d095c90/tests/test_trap_acceptance.py#L204-L213) | [tests/test_trap_acceptance.py:204–213](https://github.com/Cezar277/heimdall/blob/0b14b3826e60e5afed3ffc4577a2bf1c9d095c90/tests/test_trap_acceptance.py#L204-L213) | XFAIL attendu ; simulation conforme => XPASS(strict), code pytest 1 |
| Ne versionner que des gabarits | [tests/support/trap_corpus.py:54–78](https://github.com/Cezar277/heimdall/blob/0b14b3826e60e5afed3ffc4577a2bf1c9d095c90/tests/support/trap_corpus.py#L54-L78) | [tests/test_trap_acceptance.py:302–305](https://github.com/Cezar277/heimdall/blob/0b14b3826e60e5afed3ffc4577a2bf1c9d095c90/tests/test_trap_acceptance.py#L302-L305) | Réussi |

Commande : `python -m pytest tests/test_trap_acceptance.py -s -rx`.
Résultat : **26 passed, 3 skipped, 1 xfailed**. Lint réussi.
Les trois tests de liens réels sont ignorés uniquement si Windows refuse
leur création (WinError 1314) ; ils restent exécutables sur POSIX.
Le XFAIL strict concerne T22 non livré : un scanner conforme provoquera un
échec XPASS(strict), obligeant à retirer le marqueur.
Le CLI isolé sans paquets (`python -I -S tests/measure_trap.py`) retourne 2
avec un message fixe sans traceback.

La réussite de la CI Linux sur le SHA final et l'accord explicite du relecteur
sur l'exception de regroupement restent requis avant fusion de la
[PR #153](https://github.com/Cezar277/heimdall/pull/153).
