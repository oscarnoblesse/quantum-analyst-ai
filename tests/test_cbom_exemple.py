"""Le CBOM d'exemple versionné (results/cbom_exemple.json) reste valide au schéma CycloneDX 1.6."""

import json
from pathlib import Path

from quantum_ready.outils.valider_schema import valider_schema

EXEMPLE = Path(__file__).resolve().parents[1] / "results" / "cbom_exemple.json"


def test_cbom_exemple_valide_au_schema():
    resultat = valider_schema(json.loads(EXEMPLE.read_text(encoding="utf-8")))
    assert resultat.valide, resultat.erreurs[:3]


def test_cbom_exemple_contient_les_actifs_attendus():
    cbom = json.loads(EXEMPLE.read_text(encoding="utf-8"))
    assert cbom["specVersion"] == "1.6"
    assert len(cbom["components"]) == 77
