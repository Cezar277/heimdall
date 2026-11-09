"""Tests unitaires exhaustifs pour la table d'états et transitions du cycle de vie (#40, #115).

Vérifie formellement le cycle de vie du secret :
détecté -> confirmé -> vaulté -> roté,
la gestion du faux positif (écarté),
la totalité des transitions autorisées et l'interdiction stricte de tous les passages interdits.
"""

from __future__ import annotations

import unittest

from heimdall.scanner.finding import FINDING_STATUSES
from heimdall.vault.transitions import (
    ALLOWED_TRANSITIONS,
    FORBIDDEN_TRANSITION_REASONS,
    INITIAL_STATE,
    LIFECYCLE_STATES,
    LIFECYCLE_STATES_SET,
    STATE_ALIASES,
    TERMINAL_STATES,
    InvalidTransitionError,
    LifecycleTransitionError,
    SecretLifecycleState,
    UnknownStateError,
    canonicalize_state,
    get_allowed_transitions,
    get_forbidden_transitions,
    get_transition_matrix,
    is_transition_allowed,
    is_valid_state,
    validate_transition,
)


class SecretLifecycleStateTests(unittest.TestCase):
    """Vérification des états et de la cohérence avec le contrat Finding (#14)."""

    def test_lifecycle_states_match_finding_schema_statuses(self) -> None:
        """Les états du cycle de vie correspondent exactement aux statuts du contrat #14."""
        self.assertEqual(LIFECYCLE_STATES_SET, FINDING_STATUSES)
        self.assertEqual(
            LIFECYCLE_STATES,
            ("detecte", "confirme", "vaulte", "rote", "faux_positif"),
        )

    def test_initial_state_is_detecte(self) -> None:
        """L'état initial d'un secret est obligatoirement 'detecte'."""
        self.assertEqual(INITIAL_STATE, "detecte")

    def test_terminal_states_contain_only_rote(self) -> None:
        """L'état terminal est uniquement 'rote'."""
        self.assertEqual(TERMINAL_STATES, frozenset({"rote"}))
        self.assertEqual(ALLOWED_TRANSITIONS["rote"], frozenset())

    def test_canonicalize_state_valid(self) -> None:
        """Les états canoniques sont retournés tels quels."""
        for state in LIFECYCLE_STATES:
            with self.subTest(state=state):
                self.assertEqual(canonicalize_state(state), state)

    def test_canonicalize_state_normalizes_case_and_whitespace(self) -> None:
        """La normalisation ignore la casse et les espaces superflus."""
        self.assertEqual(canonicalize_state("  DETECTE  "), "detecte")
        self.assertEqual(canonicalize_state("Confirme"), "confirme")
        self.assertEqual(canonicalize_state("VAULTE"), "vaulte")
        self.assertEqual(canonicalize_state("  rote "), "rote")
        self.assertEqual(canonicalize_state("FAUX_POSITIF"), "faux_positif")

    def test_canonicalize_state_aliases(self) -> None:
        """Les alias métier (notamment 'ecarte') sont convertis vers 'faux_positif'."""
        self.assertEqual(canonicalize_state("ecarte"), "faux_positif")
        self.assertEqual(canonicalize_state("ecarté"), "faux_positif")
        self.assertEqual(canonicalize_state("discarded"), "faux_positif")
        self.assertEqual(canonicalize_state("  ECARTE  "), "faux_positif")

    def test_canonicalize_state_unknown_raises_error(self) -> None:
        """Tout état non reconnu lève UnknownStateError."""
        for invalid in ("inconnu", "pending", "revoked", "active", "", " ", None, 42):
            with self.subTest(invalid=invalid):
                with self.assertRaises(UnknownStateError) as ctx:
                    canonicalize_state(invalid)
                self.assertEqual(ctx.exception.state, invalid)
                self.assertIn("inconnu", str(ctx.exception).lower())

    def test_is_valid_state(self) -> None:
        """is_valid_state retourne True pour les états et alias, False sinon."""
        for valid in (*LIFECYCLE_STATES, *STATE_ALIASES.keys()):
            with self.subTest(valid=valid):
                self.assertTrue(is_valid_state(valid))

        for invalid in ("unknown", "supprime", "", None, 123):
            with self.subTest(invalid=invalid):
                self.assertFalse(is_valid_state(invalid))


class AllowedTransitionsTests(unittest.TestCase):
    """Vérification de toutes les transitions nominales et autorisées."""

    def test_nominal_lifecycle_chain_detecte_confirme_vaulte_rote(self) -> None:
        """La chaîne nominale détecté -> confirmé -> vaulté -> roté est permise."""
        # detecte -> confirme
        self.assertTrue(is_transition_allowed("detecte", "confirme"))
        validate_transition("detecte", "confirme")

        # confirme -> vaulte
        self.assertTrue(is_transition_allowed("confirme", "vaulte"))
        validate_transition("confirme", "vaulte")

        # vaulte -> rote
        self.assertTrue(is_transition_allowed("vaulte", "rote"))
        validate_transition("vaulte", "rote")

    def test_false_positive_rejection_and_reexamination_cycle(self) -> None:
        """Le cycle d'écartement en faux positif et de réexamen vers détecté est permis."""
        # detecte -> faux_positif
        self.assertTrue(is_transition_allowed("detecte", "faux_positif"))
        validate_transition("detecte", "faux_positif")

        # faux_positif -> detecte
        self.assertTrue(is_transition_allowed("faux_positif", "detecte"))
        validate_transition("faux_positif", "detecte")

    def test_transitions_with_alias_ecarte(self) -> None:
        """L'alias 'ecarte' fonctionne de façon transparente dans les transitions."""
        self.assertTrue(is_transition_allowed("detecte", "ecarte"))
        validate_transition("detecte", "ecarte")

        self.assertTrue(is_transition_allowed("ecarte", "detecte"))
        validate_transition("ecarte", "detecte")

    def test_allowed_transitions_exact_count(self) -> None:
        """Il existe exactement 5 transitions autorisées dans le système."""
        total_allowed = sum(len(targets) for targets in ALLOWED_TRANSITIONS.values())
        self.assertEqual(total_allowed, 5)

        expected_allowed: set[tuple[SecretLifecycleState, SecretLifecycleState]] = {
            ("detecte", "confirme"),
            ("detecte", "faux_positif"),
            ("confirme", "vaulte"),
            ("vaulte", "rote"),
            ("faux_positif", "detecte"),
        }
        actual_allowed = {
            (src, dst) for src, targets in ALLOWED_TRANSITIONS.items() for dst in targets
        }
        self.assertEqual(actual_allowed, expected_allowed)


class ForbiddenTransitionsTests(unittest.TestCase):
    """Vérification exhaustive de la totalité des transitions interdites (matrice 5x5)."""

    def test_all_20_forbidden_transitions_raise_invalid_transition_error(self) -> None:
        """Toutes les 20 transitions non autorisées sont strictement rejetées."""
        tested_forbidden_count = 0

        for src in LIFECYCLE_STATES:
            for dst in LIFECYCLE_STATES:
                if dst not in ALLOWED_TRANSITIONS[src]:
                    tested_forbidden_count += 1
                    with self.subTest(source=src, target=dst):
                        self.assertFalse(
                            is_transition_allowed(src, dst),
                            f"La transition {src} -> {dst} ne devrait pas être autorisée",
                        )

                        with self.assertRaises(InvalidTransitionError) as ctx:
                            validate_transition(src, dst)

                        exc = ctx.exception
                        self.assertEqual(exc.source, src)
                        self.assertEqual(exc.target, dst)
                        self.assertTrue(len(exc.reason) > 0)
                        self.assertIn(f"Transition interdite de '{src}' vers '{dst}'", str(exc))

                        # Vérification de la présence d'une justification explicite
                        self.assertIn((src, dst), FORBIDDEN_TRANSITION_REASONS)
                        self.assertEqual(exc.reason, FORBIDDEN_TRANSITION_REASONS[(src, dst)])

        self.assertEqual(tested_forbidden_count, 20)

    def test_specific_forbidden_passages(self) -> None:
        """Passages interdits spécifiquement mentionnés dans le ticket et les règles."""
        forbidden_critical_pairs = [
            ("detecte", "rote"),  # saut direct détecté -> roté interdit
            ("detecte", "vaulte"),  # saut direct détecté -> vaulté interdit
            ("confirme", "rote"),  # saut direct confirmé -> roté interdit
            ("confirme", "detecte"),  # retour arrière confirmé -> détecté interdit
            ("confirme", "faux_positif"),  # confirmé -> faux positif interdit
            ("vaulte", "detecte"),  # régression arrière vaulté -> détecté interdite
            ("vaulte", "confirme"),  # régression arrière vaulté -> confirmé interdite
            ("vaulte", "faux_positif"),  # un secret vaulté ne peut être faux positif
            ("rote", "detecte"),  # état terminal ne peut redevenir détecté
            ("rote", "confirme"),  # état terminal
            ("rote", "vaulte"),  # état terminal
            ("rote", "faux_positif"),  # état terminal
            ("faux_positif", "confirme"),  # faux positif -> confirmé interdit
            ("faux_positif", "vaulte"),  # faux positif -> vaulté strictement interdit
            ("faux_positif", "rote"),  # faux positif -> roté interdit
        ]
        for src, dst in forbidden_critical_pairs:
            with self.subTest(source=src, target=dst):
                self.assertFalse(is_transition_allowed(src, dst))
                with self.assertRaises(InvalidTransitionError):
                    validate_transition(src, dst)

    def test_reflexive_transitions_are_forbidden(self) -> None:
        """Une transition réflexive A -> A n'est pas une transition d'avancement."""
        for state in LIFECYCLE_STATES:
            with self.subTest(state=state):
                self.assertFalse(is_transition_allowed(state, state))
                with self.assertRaises(InvalidTransitionError) as ctx:
                    validate_transition(state, state)
                self.assertIn("inchangé", ctx.exception.reason.lower())

    def test_unknown_state_in_transition_fails_closed(self) -> None:
        """Un état inconnu dans is_transition_allowed retourne False sans lever d'exception."""
        self.assertFalse(is_transition_allowed("detecte", "unknown"))
        self.assertFalse(is_transition_allowed("unknown", "confirme"))
        self.assertFalse(is_transition_allowed("unknown", "unknown"))

    def test_unknown_state_in_validate_transition_raises_unknown_state_error(self) -> None:
        """Un état inconnu dans validate_transition lève UnknownStateError."""
        with self.assertRaises(UnknownStateError):
            validate_transition("detecte", "unknown")
        with self.assertRaises(UnknownStateError):
            validate_transition("unknown", "confirme")


class TransitionMatrixAndPartitionsTests(unittest.TestCase):
    """Vérification des partitions et de la matrice complète 5x5."""

    def test_allowed_and_forbidden_partition_states(self) -> None:
        """Pour tout état, autorisés et interdits forment une partition de LIFECYCLE_STATES."""
        for state in LIFECYCLE_STATES:
            with self.subTest(state=state):
                allowed = get_allowed_transitions(state)
                forbidden = get_forbidden_transitions(state)

                # Intersection vide
                self.assertEqual(allowed & forbidden, frozenset())
                # Union égale à l'ensemble complet des 5 états
                self.assertEqual(allowed | forbidden, LIFECYCLE_STATES_SET)

    def test_transition_matrix_dimensions_and_values(self) -> None:
        """La matrice d'adjacence 5x5 contient exactement 5 True et 20 False."""
        matrix = get_transition_matrix()
        self.assertEqual(set(matrix.keys()), LIFECYCLE_STATES_SET)

        true_count = 0
        false_count = 0

        for src in LIFECYCLE_STATES:
            self.assertEqual(set(matrix[src].keys()), LIFECYCLE_STATES_SET)
            for dst in LIFECYCLE_STATES:
                if matrix[src][dst]:
                    true_count += 1
                    self.assertTrue(is_transition_allowed(src, dst))
                else:
                    false_count += 1
                    self.assertFalse(is_transition_allowed(src, dst))

        self.assertEqual(true_count, 5)
        self.assertEqual(false_count, 20)


class ErrorHierarchyAndSanitizationTests(unittest.TestCase):
    """Vérification des exceptions et de l'absence de fuite d'information sensible."""

    def test_exception_inheritance(self) -> None:
        """Toutes les exceptions dérivent de LifecycleTransitionError et ValueError."""
        self.assertTrue(issubclass(UnknownStateError, LifecycleTransitionError))
        self.assertTrue(issubclass(UnknownStateError, ValueError))
        self.assertTrue(issubclass(InvalidTransitionError, LifecycleTransitionError))
        self.assertTrue(issubclass(InvalidTransitionError, ValueError))

    def test_error_message_is_static_and_deterministic(self) -> None:
        """Le message d'erreur est déterministe et ne contient pas de valeur de secret."""
        try:
            validate_transition("detecte", "rote")
        except InvalidTransitionError as exc:
            msg = str(exc)
            self.assertIn("Transition interdite de 'detecte' vers 'rote'", msg)
            self.assertEqual(exc.source, "detecte")
            self.assertEqual(exc.target, "rote")
            self.assertEqual(exc.reason, FORBIDDEN_TRANSITION_REASONS[("detecte", "rote")])


if __name__ == "__main__":
    unittest.main()
