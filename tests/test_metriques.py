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
