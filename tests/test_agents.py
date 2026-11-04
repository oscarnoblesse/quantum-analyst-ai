"""Les trois premiers agents de bout en bout, avec des politiques simulées et le vrai serveur MCP."""

import asyncio
import json

import pytest

from quantum_ready.agents import analyste_risque, cartographe, inventoriste
from quantum_ready.agents.communs import lancer, lire_prompt
from quantum_ready.llm import ModeleSimule
from quantum_ready.serveur_mcp.session import Session
from tests import politiques_simulees


@pytest.fixture(scope="module")
def chaine(racine_si, tmp_path_factory):
    session = Session(tmp_path_factory.mktemp("session"), racine_si, "SI v1")
    inv = asyncio.run(lancer(inventoriste.configuration(), ModeleSimule(politiques_simulees.inventoriste), session, transport="memoire"))
    carto = asyncio.run(lancer(cartographe.configuration(inv.sortie["exclusions"]), ModeleSimule(politiques_simulees.cartographe), session, transport="memoire"))
    analyse = asyncio.run(lancer(analyste_risque.configuration(), ModeleSimule(politiques_simulees.analyste), session, transport="memoire"))
    return session, inv, carto, analyse


def test_inventoriste_couvre_tout_le_si_et_suit_la_piste_pkcs12(chaine):
    session, inv, _, _ = chaine
    assert inv.arret == "termine" and inv.appels_refuses == 0
    appels = [e for e in session.evenements("journal_outils.jsonl") if e["agent"] == "inventoriste"]
    assert any(e["outil"] == "analyser_pkcs12" and e["arguments"].get("variable") == "KEYSTORE_PASS" for e in appels)
    noms = {e["trouvaille"]["nom"] for e in session.trouvailles()}
    assert {"ECDSA P-256", "pbeWithSHA1And3-KeyTripleDES-CBC ; MAC SHA-1", "OpenSSH 9.6p1", "Mersenne Twister (module random)"} <= noms


def test_cartographe_produit_un_cbom_valide(chaine):
    session, _, carto, _ = chaine
    assert carto.arret == "termine" and carto.sortie["cbom_valide"] is True
    assert json.loads(session.fichier_cbom.read_text())["specVersion"] == "1.6"


def test_analyste_evalue_tous_les_actifs(chaine):
    session, _, carto, analyse = chaine
    scores = json.loads(session.fichier_scores.read_text())
    assert analyse.arret == "termine" and len(scores) == carto.sortie["composants"] == analyse.sortie["evalues"]
    assert all(s["z"] == 10 for s in scores.values())


def test_memoire_de_l_inventoriste(chaine):
    session, _, _, _ = chaine
    tours = [e for e in session.evenements("journal_agents.jsonl") if e["agent"] == "inventoriste" and e["evenement"] == "tour"]
    assert tours[0]["appels"][0]["nom"] == "lister_fichiers"


def test_prompts_presents():
    for nom in ("inventoriste", "cartographe", "analyste_risque"):
        assert "Tu es" in lire_prompt(nom) and "toi-même" in lire_prompt(nom)
