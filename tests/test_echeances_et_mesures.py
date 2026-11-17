"""Échéances du plan datées par le code, comptage des erreurs d'outils, noms proches, figures et environnement."""

import json
import xml.etree.ElementTree as ET
from datetime import date
from types import SimpleNamespace

import pytest

from quantum_ready.agents import architecte
from quantum_ready.agents.boucle import Appel, ResultatAgent
from quantum_ready.evaluation import environnement, figures
from quantum_ready.outils.commun import fichiers_proches
from quantum_ready.serveur_mcp.session import Session

JOUR = date(2026, 11, 8)


@pytest.mark.parametrize("echeance, passee", [
    ("2025-06-30", True), ("2026-03-31", True), ("2026-11-07", True),
    ("2026-11-08", False), ("2027-06-30", False), ("avant 2030", False), ("avant 2026", False), ("avant 2025", True),
    ("immédiat", False), ("2026-02-31", False),
])
def test_echeance_passee(echeance, passee):
    assert (architecte.echeance_passee(echeance, JOUR) is not None) == passee


def test_plan_avec_echeance_passee_est_refuse(tmp_path):
    session = Session(tmp_path / "s", tmp_path)
    plan = {"etapes": [{"ordre": 1, "actifs": [], "action": "a", "cible": "ML-DSA-65", "echeance": "2025-06-30",
                        "references": ["NIST-FIPS-204"]}]}
    erreurs = architecte.verifier_plan(plan, session, JOUR)
    assert any("déjà passée" in e and "2026-11-08" in e for e in erreurs)


def test_plan_avec_echeances_futures_est_accepte(tmp_path):
    session = Session(tmp_path / "s", tmp_path)
    plan = {"etapes": [{"ordre": 1, "actifs": [], "action": "a", "cible": "ML-DSA-65", "echeance": "2027-06-30",
                        "references": ["NIST-FIPS-204"]}]}
    assert not any("déjà passée" in e for e in architecte.verifier_plan(plan, session, JOUR))


def test_date_du_jour_rappelee_a_l_architecte(tmp_path):
    session = Session(tmp_path / "s", tmp_path)
    texte = architecte.memoire(SimpleNamespace(appels=[]), session)
    assert f"Date du jour : {architecte.aujourdhui().isoformat()}" in texte


def test_appel_en_double_d_un_echec_n_est_pas_compte_comme_erreur():
    # Le compteur de la boucle : un appel déjà fait ne s'exécute pas, il ne doit pas gonfler les erreurs.
    appel = Appel("outil", {}, "ERREUR : x", erreur=True, double=True)
    compte = ResultatAgent(agent="inventoriste", arret="termine")
    compte.erreurs_outils += appel.erreur and not (appel.refuse or appel.double)
    assert compte.erreurs_outils == 0


def test_fichiers_proches_propose_un_nom_reel(tmp_path):
    (tmp_path / "api").mkdir()
    (tmp_path / "api" / ".env").write_text("A=1\n", encoding="utf-8")
    assert fichiers_proches("config.env", tmp_path) == ["api/.env"]
    assert fichiers_proches("zzz.qqq", tmp_path) == []


def test_figures_sont_du_xml_valide():
    metriques = {"demonstrateur": {
        "latence_bench_pqc": {"configurations": {"a": {"mediane_us": 900.0, "mediane_ecart_type_us": 3.0},
                                                  "b & c": {"mediane_us": 700.0, "mediane_ecart_type_us": None}}},
        "signatures": None}}
    svg = figures.construire(metriques)["latence.svg"]
    ET.fromstring(svg)  # lève une exception si le SVG est mal formé
    assert "b &amp; c" in svg


def test_environnement_contient_les_versions_et_le_modele():
    env = environnement.construire()
    assert env["ollama"]["modele"].startswith("qwen3")
    assert env["ollama"]["empreinte"]
    json.dumps(env)  # sérialisable
