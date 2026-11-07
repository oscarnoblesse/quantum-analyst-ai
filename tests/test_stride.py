"""Le modèle de menace cite des tests qui existent : une contre-mesure sans test n'est pas une preuve."""

import re
from pathlib import Path

RACINE = Path(__file__).resolve().parents[1]
DOCUMENT = (RACINE / "docs" / "menace_stride.md").read_text(encoding="utf-8")


def test_chaque_fichier_de_test_cite_existe():
    fichiers = set(re.findall(r"`tests/(test_[\w]+\.py)", DOCUMENT))
    assert fichiers, "aucun test cité : le document ne prouve rien"
    manquants = [f for f in fichiers if not (RACINE / "tests" / f).is_file()]
    assert manquants == []


def test_chaque_test_cite_existe():
    citations = re.findall(r"`tests/(test_[\w]+\.py)::(test_[\w]+)`", DOCUMENT)
    assert citations
    manquants = []
    for fichier, nom in citations:
        if f"def {nom}(" not in (RACINE / "tests" / fichier).read_text(encoding="utf-8"):
            manquants.append(f"{fichier}::{nom}")
    assert manquants == []
