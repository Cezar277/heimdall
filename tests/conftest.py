"""Configuration commune des tests."""

from __future__ import annotations

import os
from collections.abc import Iterator

import pytest


@pytest.fixture(autouse=True)
def _heimdall_env_test(monkeypatch: pytest.MonkeyPatch) -> None:
    """Défaut de test explicite : ``HEIMDALL_ENV=test``.

    Depuis l'audit M-13, l'absence de ``HEIMDALL_ENV`` vaut production. Les
    tests qui veulent tester ce défaut suppriment la variable explicitement.
    """
    monkeypatch.setenv("HEIMDALL_ENV", "test")


@pytest.fixture(autouse=True)
def _umask_022() -> Iterator[None]:
    """Umask déterministe : un runner peut tourner en 0002 (dossiers 0775).

    Les contrôles de permissions (refus des dossiers accessibles au groupe ou
    aux autres) doivent donc réagir au même comportement sur toute machine.
    Les tests qui ont besoin d'un autre umask le fixent eux-mêmes.
    """
    previous = os.umask(0o022)
    try:
        yield
    finally:
        os.umask(previous)
