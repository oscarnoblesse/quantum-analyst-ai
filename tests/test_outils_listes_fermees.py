"""Chaque outil d'une liste fermée existe, et un agent inconnu n'a droit à rien."""

import importlib

import pytest

from quantum_ready.outils import LISTES_FERMEES, outils_autorises


@pytest.mark.parametrize("nom", sorted({o for outils in LISTES_FERMEES.values() for o in outils}))
def test_l_outil_existe(nom):
    module = importlib.import_module(f"quantum_ready.outils.{nom}")
    assert callable(getattr(module, nom))


def test_listes_disjointes_et_agent_inconnu():
    tous = [o for outils in LISTES_FERMEES.values() for o in outils]
    assert len(tous) == len(set(tous))
    assert outils_autorises("pirate") == ()
    assert "score_mosca" not in outils_autorises("inventoriste")
