"""Orchestrateur LangGraph : enchaînement, boucle de vérification du CBOM, validation humaine."""

import json

from quantum_ready.agents.politiques import POLITIQUES
from quantum_ready.llm import ModeleSimule, appel, texte
from quantum_ready.orchestrateur import construire_graphe, executer, resume_pour_humain
from quantum_ready.serveur_mcp.session import Session

PARAMETRES = {"orchestrateur": {"tentatives_cartographe": 2}, "mosca": {"horizon_menace_annees": 10}}


def _regles(nom):
    return ModeleSimule(POLITIQUES[nom])


def test_chaine_complete_avec_validation(racine_si, tmp_path):
    session = Session(tmp_path / "s", racine_si)
    vus = []
    etat = construire_graphe(_regles, session, PARAMETRES, "memoire", lambda s: vus.append(resume_pour_humain(s)) or True).invoke({})
    assert etat["arret"] == "termine" and etat["cbom_valide"] and etat["tentatives_cartographe"] == 1
    assert list(etat["resultats"]) == ["inventoriste", "cartographe", "analyste_risque"]
    assert vus and vus[0].startswith("CBOM : 78 composants")


def test_refus_humain(racine_si, tmp_path):
    etat = construire_graphe(_regles, Session(tmp_path / "s", racine_si), PARAMETRES, "memoire", lambda s: False).invoke({})
    assert etat["arret"] == "refuse_par_l_humain"


def test_boucle_de_verification_le_code_ne_croit_pas_le_modele(racine_si, tmp_path):
    """Un Cartographe qui affirme « valide » sans avoir construit de CBOM est renvoyé au travail, puis l'orchestrateur s'arrête."""
    menteur = lambda: ModeleSimule([texte({"cbom_valide": True, "composants": 99, "resume": "tout va bien"})])  # noqa: E731
    modeles = {"cartographe": [menteur(), menteur()]}
    choisir = lambda nom: modeles[nom].pop(0) if nom in modeles else _regles(nom)  # noqa: E731
    etat = construire_graphe(choisir, Session(tmp_path / "s", racine_si), PARAMETRES, "memoire").invoke({})
    assert etat["arret"] == "cbom_invalide" and etat["tentatives_cartographe"] == 2
    assert list(etat["resultats"]) == ["inventoriste", "cartographe", "cartographe_2"]


def test_seconde_tentative_recoit_les_erreurs(racine_si, tmp_path):
    vu = []

    def cartographe_qui_apprend():
        def politique(messages, outils):
            vu.append(messages[1]["content"])
            return POLITIQUES["cartographe"](messages, outils)
        return ModeleSimule(politique)
    modeles = {"cartographe": [ModeleSimule([texte({"cbom_valide": True, "composants": 0, "resume": "-"})]), cartographe_qui_apprend()]}
    choisir = lambda nom: modeles[nom].pop(0) if nom in modeles else _regles(nom)  # noqa: E731
    etat = construire_graphe(choisir, Session(tmp_path / "s", racine_si), PARAMETRES, "memoire").invoke({})
    assert etat["arret"] == "termine" and etat["tentatives_cartographe"] == 2
    assert "CBOM INVALIDE" in vu[0] and "aucun CBOM enregistré" in vu[0]


def test_inventaire_vide(racine_si, tmp_path):
    vide = lambda nom: ModeleSimule([texte({"resume": "rien"})])  # noqa: E731
    etat = construire_graphe(vide, Session(tmp_path / "s", racine_si), PARAMETRES, "memoire").invoke({})
    assert etat["arret"] == "inventaire_vide" and "cartographe" not in etat["resultats"]


def test_executer_en_ligne_de_commande(racine_si, tmp_path, monkeypatch):
    configuration = tmp_path / "experiment.yaml"
    configuration.write_text("orchestrateur:\n  validation_humaine: accepter\nmosca:\n  horizon_menace_annees: 10\n")
    rapport = executer(str(racine_si), str(tmp_path / "trace"), "regles", configuration=configuration, transport="memoire")
    assert rapport["arret"] == "termine" and rapport["validation"] == "acceptee"
    sauve = json.loads((tmp_path / "trace" / "rapport.json").read_text())
    assert sauve["agents"]["inventoriste"]["arret"] == "termine"
    assert (tmp_path / "trace" / "configuration.yaml").is_file()
