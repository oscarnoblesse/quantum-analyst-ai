"""Agent Démonstrateur : mécanique complète sans Docker (laboratoire simulé), vérifications de fin par le code."""

import asyncio

import pytest

from quantum_ready.agents import demonstrateur as demo
from quantum_ready.agents import politiques
from quantum_ready.agents.communs import lancer
from quantum_ready.llm import ModeleSimule
from quantum_ready.outils import laboratoire
from quantum_ready.outils import scan_tls_lab as tls
from quantum_ready.outils.commun import Resultat, Trouvaille
from quantum_ready.serveur_mcp.session import Session


@pytest.fixture
def laboratoire_simule(monkeypatch):
    """Un laboratoire en mémoire : un seul groupe démarré à la fois, comme le vrai."""
    etat = {"groupe": None}
    chiffres = {
        "X25519MLKEM768": {"mediane_us": 600.0, "p95_us": 900.0, "client_hello_octets": 1397, "server_hello_octets": 1210},
        "X25519": {"mediane_us": 450.0, "p95_us": 500.0, "client_hello_octets": 221, "server_hello_octets": 122},
    }

    def demarrer(groupe):
        laboratoire._groupe(groupe)
        etat["groupe"] = groupe
        return f"laboratoire démarré : groupe {groupe}"

    def arreter(groupe):
        laboratoire._groupe(groupe)
        etat["groupe"] = None
        return f"laboratoire arrêté : groupe {groupe}"

    def mesurer(groupe, mesures=1000):
        assert etat["groupe"] == groupe, "mesure sans laboratoire démarré avec ce groupe"
        return {"groupe": groupe, "mesures": mesures, **chiffres[groupe]}

    def scan(cible, racine):
        trouvailles = [Trouvaille(outil="scan_tls_lab", fichier="", type_actif="algorithm", nom=etat["groupe"],
                                  description="groupe accepté", exposition=tls.exposition(etat["groupe"]))]
        return Resultat(outil="scan_tls_lab", cible=cible, trouvailles=trouvailles)

    monkeypatch.setattr(laboratoire, "demarrer", demarrer)
    monkeypatch.setattr(laboratoire, "arreter", arreter)
    monkeypatch.setattr(laboratoire, "mesurer", mesurer)
    monkeypatch.setattr(laboratoire, "groupe_demarre", lambda: etat["groupe"])
    monkeypatch.setattr(tls, "scan_tls_lab", scan)
    return etat


def test_agent_realise_les_huit_etapes_et_reprend_les_chiffres_des_outils(tmp_path, laboratoire_simule):
    session = Session(tmp_path, tmp_path, "Laboratoire")
    resultat = asyncio.run(lancer(demo.configuration(), ModeleSimule(politiques.demonstrateur), session, transport="memoire"))
    assert resultat.arret == "termine"
    assert demo.etapes_faites(session) == len(demo.PLAN)
    groupes = {r["groupe"]: r for r in resultat.sortie["resultats"]}
    assert groupes["X25519MLKEM768"]["mediane_us"] == 600.0
    assert groupes["X25519"]["client_hello_octets"] == 221
    assert laboratoire_simule["groupe"] is None  # le laboratoire est arrêté à la fin


def test_fin_refusee_tant_que_les_etapes_ne_sont_pas_faites(tmp_path, laboratoire_simule):
    session = Session(tmp_path, tmp_path, "Laboratoire")
    fin = demo.SortieDemonstrateur(resultats=[], resume="rien")
    message = demo.verifier_fin(None, session, fin)
    assert message and "étape" in message


def test_chiffres_inventes_par_le_modele_sont_refuses(tmp_path, laboratoire_simule, monkeypatch):
    session = Session(tmp_path, tmp_path, "Laboratoire")
    asyncio.run(lancer(demo.configuration(), ModeleSimule(politiques.demonstrateur), session, transport="memoire"))
    falsifiee = demo.SortieDemonstrateur(resultats=[
        demo.ResultatGroupe(groupe="X25519MLKEM768", scan_accepte=True, mediane_us=123.0, p95_us=900.0, client_hello_octets=1397),
        demo.ResultatGroupe(groupe="X25519", scan_accepte=True, mediane_us=450.0, p95_us=500.0, client_hello_octets=221),
    ], resume="chiffres modifiés")
    message = demo.verifier_fin(None, session, falsifiee)
    assert message and "ne reprennent pas" in message


def test_groupe_inconnu_refuse_par_le_laboratoire():
    with pytest.raises(laboratoire.ErreurOutil, match="groupe refusé"):
        laboratoire._groupe("RSA-2048")


def test_mesure_refusee_hors_limites():
    with pytest.raises(laboratoire.ErreurOutil, match="hors limites"):
        laboratoire.mesurer("X25519", mesures=5000)


def test_sonde_refuse_si_le_mauvais_laboratoire_tourne(tmp_path, laboratoire_simule):
    from quantum_ready.serveur_mcp.outils_exposes import creer_outils

    session = Session(tmp_path, tmp_path, "Laboratoire")
    outils = creer_outils(session, "demonstrateur")
    laboratoire_simule["groupe"] = "X25519"
    assert outils["scan_tls_lab"]("127.0.0.1:8443", "X25519MLKEM768").startswith("ERREUR")
