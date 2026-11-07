"""Garde-fous du code sur la réponse finale des agents (observés lors des essais avec qwen3)."""

import asyncio

import pytest

from quantum_ready.agents import analyste_risque, inventoriste
from quantum_ready.agents.communs import lancer
from quantum_ready.agents.politiques import POLITIQUES
from quantum_ready.llm import ModeleSimule, appel, texte
from quantum_ready.outils.commun import ErreurOutil, secret_depuis_env
from quantum_ready.serveur_mcp.session import Session


def test_inventoriste_ne_peut_pas_exclure_un_actif_vulnerable(racine_si, tmp_path):
    """Observé : « algorithme Shor détecté, donc à exclure » sur le certificat admin."""
    session = Session(tmp_path / "s", racine_si)
    tours = iter([appel("lister_fichiers", cible="clients/admin/admin.crt"), appel("analyser_x509", cible="clients/admin/admin.crt"),
                  texte({"resume": "fini", "exclusions": [{"id": "T0001", "raison": "algorithme Shor détecté"}]}),
                  texte({"resume": "fini", "exclusions": []})])
    vus = []

    def modele(messages, outils):
        vus.append(" ".join(m["content"] for m in messages[-3:]))
        return next(tours)
    resultat = asyncio.run(lancer(inventoriste.configuration(), ModeleSimule(modele), session, transport="memoire"))
    assert resultat.arret == "termine" and resultat.fins_refusees == 1 and resultat.sortie["exclusions"] == []
    assert "REFUSÉE" in vus[-1] and "T0001" in vus[-1] and "vulnérable" in vus[-1]
    assert any(e["evenement"] == "fin_refusee" for e in session.evenements("journal_agents.jsonl"))


def test_inventoriste_ne_peut_pas_finir_avec_des_fichiers_oublies(racine_si, tmp_path):
    session = Session(tmp_path / "s", racine_si)
    tours = iter([appel("lister_fichiers", cible="scripts"), appel("analyser_cle", cible="scripts/backup.sh"),  # mauvais outil
                  texte({"resume": "fini"}), appel("analyser_configuration", cible="scripts/backup.sh"),
                  appel("analyser_cle", cible="scripts/keys/backup_pub.asc"), appel("scanner_code_crypto", cible="scripts"), texte({"resume": "fini"})])
    vus = []

    def modele(messages, outils):
        vus.append(" ".join(m["content"] for m in messages[-3:]))
        return next(tours)
    resultat = asyncio.run(lancer(inventoriste.configuration(), ModeleSimule(modele), session, transport="memoire"))
    assert resultat.arret == "termine" and resultat.fins_refusees == 1
    refus = next(v for v in vus if "REFUSÉE" in v)
    assert "scripts/backup.sh -> analyser_configuration" in refus


def test_analyste_ne_peut_pas_s_arreter_avant_la_fin(racine_si, tmp_path):
    """Observé : réponse finale après 15 actifs sur 76."""
    session = Session(tmp_path / "s", racine_si)
    from quantum_ready.agents import cartographe

    asyncio.run(lancer(inventoriste.configuration(), ModeleSimule(POLITIQUES["inventoriste"]), session, transport="memoire"))
    asyncio.run(lancer(cartographe.configuration(), ModeleSimule(POLITIQUES["cartographe"]), session, transport="memoire"))
    presse = {"n": 0}

    def modele(messages, outils):
        presse["n"] += 1
        if presse["n"] == 2:
            return texte({"evalues": 5, "critiques": [], "resume": "fini trop tôt"})
        return POLITIQUES["analyste_risque"](messages, outils)
    resultat = asyncio.run(lancer(analyste_risque.configuration(max_etapes=40), ModeleSimule(modele), session, transport="memoire"))
    assert resultat.arret == "termine" and resultat.fins_refusees == 1
    assert analyste_risque.restants(session) == []


def test_fin_acceptee_apres_quatre_refus(racine_si, tmp_path):
    session = Session(tmp_path / "s", racine_si)
    resultat = asyncio.run(lancer(inventoriste.configuration(), ModeleSimule(lambda m, o: texte({"resume": "rien"})), session, transport="memoire"))
    assert resultat.arret == "termine" and resultat.fins_refusees == 4 and "acceptée après 4 refus" in resultat.message


def test_erreur_env_liste_les_fichiers_existants(racine_si):
    with pytest.raises(ErreurOutil, match="Fichiers de variables du SI : api/.env"):
        secret_depuis_env("env/.env", "KEYSTORE_PASS", racine_si)
