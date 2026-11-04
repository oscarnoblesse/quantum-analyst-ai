"""Chaque outil d'une liste fermée existe dans le serveur MCP, et un agent inconnu n'a droit à rien."""

import pytest

from quantum_ready.outils import LISTES_FERMEES, outils_autorises
from quantum_ready.serveur_mcp.outils_exposes import creer_outils
from quantum_ready.serveur_mcp.session import Session


@pytest.mark.parametrize("nom", sorted({o for outils in LISTES_FERMEES.values() for o in outils}))
def test_l_outil_est_expose(tmp_path, nom):
    assert nom in creer_outils(Session(tmp_path / "s", tmp_path), "test")


def test_listes_disjointes_et_agent_inconnu():
    tous = [o for outils in LISTES_FERMEES.values() for o in outils]
    assert len(tous) == len(set(tous))
    assert outils_autorises("pirate") == ()
    assert "score_mosca" not in outils_autorises("inventoriste")
