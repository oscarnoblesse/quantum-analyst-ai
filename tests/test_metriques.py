"""Génération de results/metrics.json : agrégation, écarts types, non-mesures explicites."""

import json

import pytest

from quantum_ready.evaluation import metriques as m


@pytest.fixture
def brut(tmp_path, monkeypatch):
    monkeypatch.setattr(m, "BRUT", tmp_path)
    monkeypatch.setattr(m, "SORTIE", tmp_path / "metrics.json")
    return tmp_path


def _run(mediane_h, mediane_c, arret="termine"):
    return {"modele": "qwen3:4b", "arret": arret, "appels_refuses": 0, "appels_en_double": 0, "erreurs_outils": 0,
            "resultats": [{"groupe": "X25519MLKEM768", "mediane_us": mediane_h, "p95_us": 900.0, "client_hello_octets": 1397},
                          {"groupe": "X25519", "mediane_us": mediane_c, "p95_us": 500.0, "client_hello_octets": 221}]}


def test_resume_moyenne_et_ecart_type():
    assert m.resume([600.0, 700.0, 800.0]) == {"n": 3, "moyenne": 700.0, "ecart_type": 100.0}


def test_un_seul_run_n_a_pas_d_ecart_type():
    assert m.resume([600.0]) == {"n": 1, "moyenne": 600.0, "ecart_type": None}


def test_aucune_donnee_ne_produit_pas_de_valeur_inventee(brut):
    document = m.construire()
    assert document["demonstrateur"] == {"verification": None, "latence_bench_pqc": None, "signatures": None, "agent": None}
    assert m.NON_MESURE == document["non_mesure"]


def test_agregation_des_trois_runs_de_l_agent(brut):
    (brut / "demonstrateur_agent.json").write_text(json.dumps([_run(600.0, 460.0), _run(590.0, 466.0), _run(730.0, 548.0)]), encoding="utf-8")
    agent = m.construire()["demonstrateur"]["agent"]
    assert agent["executions"] == 3 and agent["terminees"] == 3
    assert agent["groupes"]["X25519MLKEM768"]["mediane_us"]["n"] == 3
    assert agent["groupes"]["X25519"]["client_hello_octets"]["moyenne"] == 221.0


def test_avertissement_si_moins_de_trois_repetitions(brut):
    (brut / "demonstrateur_agent.json").write_text(json.dumps([_run(600.0, 460.0)]), encoding="utf-8")
    assert any("3" in a for a in m.construire()["avertissements"])


def test_verification_non_conforme_est_signalee(brut):
    (brut / "demonstrateur_verification.json").write_text(json.dumps({"conforme": False}), encoding="utf-8")
    assert any("pas conforme" in a for a in m.construire()["avertissements"])


def _evaluation(session, rappel, manques, arret="termine"):
    return {"session": f"traces/{session}", "cbom_valide": True, "plan": None,
            "qualite": {"rappel": rappel, "rappel_caches": rappel, "precision_stricte": 0.7, "precision_hors_doublons": 0.8,
                        "f1": 0.7, "rappel_par_perimetre": {"connu": {"trouves": 1, "attendus": 2, "rappel": 0.5}},
                        "shor_bien_classes": "1/2", "leurres": {"leurres_touches": ["L2-01"]}, "manques": manques},
            "couts": {"arrets": {"inventoriste": arret}, "appels_outils": 3, "erreurs_outils": 0, "tours_de_modele": 4,
                      "duree_totale_s": 1.0}}


def test_inventaire_v2_repetitions_et_comparaison(brut):
    (brut / "evaluation_v2.json").write_text(json.dumps({"verite_terrain": "v2.json", "leurres": "l.csv", "sessions": [
        _evaluation("v2_reference_outils_seuls", 0.79, ["V2-001"]),
        _evaluation("v2_ollama_run1", 0.57, ["V2-001", "V2-002"], "limite_etapes"),
        _evaluation("v2_ollama_run2", 0.57, ["V2-001", "V2-002"], "limite_etapes"),
        _evaluation("v2_posthoc_budget_run1", 0.79, ["V2-001"]),
        _evaluation("session_inconnue", 0.1, []),
    ]}), encoding="utf-8")
    section = m.construire()["inventaire_v2"]
    modele = section["configurations"]["modele_8go"]
    assert modele["repetitions"]["rappel"] == {"n": 2, "moyenne": 57.0, "ecart_type": 0.0}
    assert modele["repetitions"]["executions_identiques"] and not modele["a_posteriori"]
    assert section["configurations"]["modele_8go_budget_162"]["a_posteriori"]
    assert "session_inconnue" not in json.dumps(section)
    assert section["comparaison_aux_outils_seuls"]["modele_8go"] == {"trouves_en_plus_des_outils": [],
                                                                       "perdus_par_rapport_aux_outils": ["V2-002"]}


def test_inventaire_v2_absent(brut):
    assert m.construire()["inventaire_v2"] is None
