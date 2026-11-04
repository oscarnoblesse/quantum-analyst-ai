"""Serveur MCP : session partagée, résultats compacts, liste fermée, journal, chaîne Cartographe -> Analyste."""

import asyncio
import json

import pytest

from quantum_ready.outils.commun import Resultat, Trouvaille
from quantum_ready.serveur_mcp.client import ouvrir_outils
from quantum_ready.serveur_mcp.outils_exposes import MAX_TROUVAILLES_AFFICHEES, resumer
from quantum_ready.serveur_mcp.serveur import creer_serveur
from quantum_ready.serveur_mcp.session import Session


def _trouvaille(nom="RSA-2048", **autres):
    return Trouvaille(outil="t", fichier="a.pem", type_actif="related-crypto-material", nom=nom, description="d", exposition="shor", **autres)


def _appels(session, agent, appels):
    async def executer():
        resultats = []
        async with ouvrir_outils(agent, session, transport="memoire") as outils:
            for nom, arguments in appels:
                resultats.append(await outils.appeler(nom, arguments))
        return resultats
    return asyncio.run(executer())


def test_identifiants_stables_et_sans_doublon(tmp_path):
    session = Session(tmp_path / "s", tmp_path)
    assert session.enregistrer([_trouvaille(), _trouvaille("ECDSA P-256")], "a") == ["T0001", "T0002"]
    assert session.enregistrer([_trouvaille("ECDSA P-256"), _trouvaille("Ed25519")], "b") == ["T0002", "T0003"]
    assert [e["agent"] for e in session.trouvailles()] == ["a", "a", "b"]


def test_resume_compact(tmp_path):
    resultat = Resultat(outil="o", cible="c", trouvailles=[_trouvaille(f"K{i}", proprietes={"faiblesse_classique": "x"}) for i in range(20)], erreurs=["e"])
    texte = resumer(resultat, [f"T{i:04d}" for i in range(20)])
    assert texte.count("\nT0") == MAX_TROUVAILLES_AFFICHEES and "+5 autres" in texte and "faible : x" in texte and "ERREUR : e" in texte


def test_liste_fermee_et_journal(racine_si, tmp_path):
    session = Session(tmp_path / "s", racine_si)
    (texte, erreur), (refus, refuse) = _appels(session, "inventoriste", [("analyser_cle", {"cible": "nginx/ssl/server.key"}), ("valider_schema", {})])
    assert not erreur and "T0001 | related-crypto-material | RSA-2048" in texte
    assert refuse and "Unknown tool" in refus
    (evenement,) = session.evenements("journal_outils.jsonl")
    assert evenement["outil"] == "analyser_cle" and evenement["statut"] == "ok" and evenement["agent"] == "inventoriste"


def test_aucun_secret_dans_le_journal(racine_si, tmp_path):
    from quantum_ready.outils.commun import secret_depuis_env

    session = Session(tmp_path / "s", racine_si)
    _appels(session, "inventoriste", [("analyser_pkcs12", {"cible": "factures/keys/factures.p12", "fichier_env": "api/.env", "variable": "KEYSTORE_PASS"}),
                                      ("analyser_configuration", {"cible": "api/.env"})])
    journal = (session.dossier / "journal_outils.jsonl").read_text()
    assert secret_depuis_env("api/.env", "KEYSTORE_PASS", racine_si) not in journal
    assert secret_depuis_env("api/.env", "JWT_SECRET", racine_si) not in journal


def test_chaine_cartographe_puis_analyste(racine_si, tmp_path):
    session = Session(tmp_path / "s", racine_si, "SI de test")
    _appels(session, "inventoriste", [("analyser_x509", {"cible": "factures/keys/factures.crt"}), ("rechercher_algorithmes", {"cible": "nginx/nginx.conf"})])
    indice = next(e["id"] for e in session.trouvailles() if "confiance" in e["trouvaille"]["proprietes"])
    sorties = _appels(session, "cartographe", [("lister_trouvailles", {}), ("valider_schema", {}), ("construire_cbom", {"exclure": [indice, "T9999"]}), ("valider_schema", {})])
    assert "indice à confirmer" in sorties[0][0]
    assert sorties[1][1] and "construire_cbom d'abord" in sorties[1][0]
    assert "T9999" in sorties[2][0] and "1 exclues" in sorties[2][0]
    assert sorties[3][0] == "CBOM VALIDE (CycloneDX 1.6)"
    cbom = json.loads(session.fichier_cbom.read_text())
    reference = cbom["components"][0]["bom-ref"]
    liste, score = _appels(session, "analyste_risque", [("lister_actifs", {}), ("score_mosca", {"evaluations": [
        {"ref": reference, "x": 10, "y": 3, "justification": "factures conservées 10 ans"}, {"ref": "absente", "x": 1, "y": 1, "justification": "-"}]})])
    assert reference in liste[0]
    assert "score 100 | critique" in score[0] and "absente | ERREUR" in score[0]
    scores = json.loads(session.fichier_scores.read_text())
    assert scores[reference]["justification"] == "factures conservées 10 ans" and scores[reference]["z"] == 10


def test_transport_stdio_reel(racine_si, tmp_path):
    session = Session(tmp_path / "s", racine_si)

    async def executer():
        async with ouvrir_outils("inventoriste", session, transport="stdio") as outils:
            return sorted(outils.noms), await outils.appeler("lister_fichiers", {"cible": "ssh"})
    noms, (texte, erreur) = asyncio.run(executer())
    assert "lister_fichiers" in noms and "score_mosca" not in noms
    assert not erreur and "ssh/server/sshd_config | config_sshd | analyser_configuration" in texte


def test_agent_inconnu(tmp_path):
    with pytest.raises(ValueError):
        creer_serveur("pirate", Session(tmp_path / "s", tmp_path))
