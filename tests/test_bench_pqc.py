"""Contrôles du script de mesure bench_pqc (fonction verifier), sans Docker."""

import importlib.util
from pathlib import Path

RACINE = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("bench_pqc", RACINE / "scripts" / "bench_pqc.py")
bench = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(bench)


def _resultats(groupe_hybride="X25519MLKEM768", groupe_classique="X25519", mesures=1000, ch_hybride=1397, ch_classique=221):
    return {
        "hybride": {"groupe": groupe_hybride, "mesures": mesures, "client_hello_octets": ch_hybride},
        "classique": {"groupe": groupe_classique, "mesures": mesures, "client_hello_octets": ch_classique},
    }


def test_resultats_conformes_aucun_probleme():
    assert bench.verifier(_resultats()) == []


def test_groupe_negocie_different_est_signale():
    problemes = bench.verifier(_resultats(groupe_hybride="X25519"))
    assert any("groupe négocié X25519" in p for p in problemes)


def test_nombre_de_mesures_incorrect_est_signale():
    assert any("mesures" in p for p in bench.verifier(_resultats(mesures=999)))


def test_client_hello_trop_proche_est_signale():
    assert any("ClientHello" in p for p in bench.verifier(_resultats(ch_hybride=300)))


def test_nom_de_groupe_compare_sans_la_casse():
    # OpenSSL écrit « x25519 » en minuscules : ce n'est pas un écart.
    assert bench.verifier(_resultats(groupe_classique="x25519")) == []
