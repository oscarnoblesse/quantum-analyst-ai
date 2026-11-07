"""Vérification du plan par démonstration dans l'orchestrateur : un échec revient à l'Architecte."""

import json

from quantum_ready.agents.politiques import POLITIQUES
from quantum_ready.llm import ModeleSimule
from quantum_ready.orchestrateur import construire_graphe
from quantum_ready.outils import laboratoire
from quantum_ready.serveur_mcp.session import Session

PARAMETRES_AVEC_DEMONSTRATION = {"orchestrateur": {"tentatives_cartographe": 2, "verification_demonstration": True},
                                 "mosca": {"horizon_menace_annees": 10}}


def _regles(nom):
    return ModeleSimule(POLITIQUES[nom])


def test_echec_de_demonstration_renvoie_le_plan_a_l_architecte(racine_si, tmp_path, monkeypatch):
    appels = []

    def laboratoire_capricieux(cle):
        appels.append(cle)
        if cle == "certificat-mldsa65" and appels.count("certificat-mldsa65") == 1:
            return False, "le certificat présenté n'est pas en ML-DSA-65 (test)"
        return True, ""
    monkeypatch.setattr(laboratoire, "verifier", laboratoire_capricieux)

    session = Session(tmp_path / "s", racine_si)
    etat = construire_graphe(_regles, session, PARAMETRES_AVEC_DEMONSTRATION, "memoire").invoke({})

    assert etat["tentatives_architecte"] == 2, etat.get("erreurs_plan")
    assert etat["plan_valide"]
    assert appels.count("certificat-mldsa65") == 2  # démontrée une fois en échec, une fois en réussite
    plan = json.loads((session.dossier / "plan.json").read_text(encoding="utf-8"))
    assert plan["demonstration"] is not None
    assert any(v["statut"] == "démontrée" for v in plan["demonstration"])
    assert any(v["statut"] == "non vérifiée" for v in plan["demonstration"])  # une étape ne peut pas être « validée »


def test_sans_le_parametre_aucune_demonstration_n_est_faite(racine_si, tmp_path, monkeypatch):
    def interdit(cle):
        raise AssertionError("la démonstration ne doit pas être lancée sans le paramètre")
    monkeypatch.setattr(laboratoire, "verifier", interdit)
    session = Session(tmp_path / "s", racine_si)
    etat = construire_graphe(_regles, session, {"orchestrateur": {"tentatives_cartographe": 2}, "mosca": {"horizon_menace_annees": 10}},
                             "memoire").invoke({})
    assert etat["plan_valide"]
