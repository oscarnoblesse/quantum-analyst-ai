"""Les artefacts publiés sont écrits en LF sur tous les systèmes.

SHA256SUMS porte sur les octets et git stocke ces fichiers en LF (.gitattributes) : un fichier
écrit en CRLF sous Windows aurait une autre empreinte que celle de l'archive publiée.
"""

from pathlib import Path

from quantum_ready import verite_terrain
from quantum_ready.serveur_mcp.session import Session, ecrire_json

RACINE = Path(__file__).resolve().parents[1]


def test_verite_terrain_json_en_lf(tmp_path):
    actifs = verite_terrain.charger_csv(RACINE / "data/ground_truth/verite_terrain_v1.csv")
    sortie = tmp_path / "si_v1.json"
    verite_terrain.ecrire_json(actifs, sortie)
    assert b"\r" not in sortie.read_bytes()


def test_traces_en_lf(tmp_path):
    ecrire_json(tmp_path / "plan.json", {"etapes": [{"ordre": 1}]})
    session = Session(tmp_path / "session", tmp_path)
    session.journaliser("journal_outils.jsonl", {"outil": "x"})
    session.journaliser("journal_outils.jsonl", {"outil": "y"})
    assert b"\r" not in (tmp_path / "plan.json").read_bytes()
    assert b"\r" not in (tmp_path / "session" / "journal_outils.jsonl").read_bytes()
