"""Page de résultats : tout texte venant des fichiers est échappé, aucune ressource externe ni script."""

import re

from quantum_ready.evaluation import page


def _metriques(avertissement: str) -> dict:
    return {"version": 1, "genere_le": "2026-11-07T00:00:00+00:00", "sources": ["bench_pqc.json"],
            "demonstrateur": {"verification": None, "latence_bench_pqc": None, "signatures": None, "agent": None},
            "crypto_agilite": None,
            "avertissements": [avertissement], "non_mesure": ["débit"]}


def test_texte_venant_des_fichiers_est_echappe():
    piege = "<script>alert('x')</script>"
    html_page = page.construire(_metriques(piege))
    assert "<script>alert" not in html_page
    assert "&lt;script&gt;" in html_page


def test_page_sans_script_ni_ressource_externe():
    html_page = page.construire(_metriques("aucun"))
    assert "<script" not in html_page
    assert not re.search(r'(src|href)="https?://', html_page)


def test_sections_presentes_meme_sans_donnees():
    html_page = page.construire(_metriques("aucun"))
    for titre in ("Vérification du laboratoire", "Latence du handshake", "Signatures", "Agent Démonstrateur", "Ce qui n'est pas encore mesuré"):
        assert titre in html_page
    assert "Pas de mesure de latence" in html_page
