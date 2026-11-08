"""Configuration commune des tests."""

from __future__ import annotations

import os
from collections.abc import Iterator

import pytest


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
