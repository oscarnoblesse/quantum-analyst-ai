"""Fixtures partagées : un SI fictif généré une seule fois pour toute la session de tests."""

import pytest

from quantum_ready.si_fictif.generateur import generer


@pytest.fixture(scope="session")
def racine_si(tmp_path_factory):
    """Racine d'un SI v1 fraîchement généré (les outils ne doivent jamais le modifier)."""
    racine = tmp_path_factory.mktemp("si_outils") / "v1"
    generer(racine, racine.parent / "hors_si")
    return racine
