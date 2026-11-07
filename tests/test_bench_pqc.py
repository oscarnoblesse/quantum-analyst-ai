"""Contrôles du script de mesure bench_pqc (fonction verifier), sans Docker."""

import importlib.util
from pathlib import Path

RACINE = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("bench_pqc", RACINE / "scripts" / "bench_pqc.py")
bench = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(bench)


def _resultats(groupe_hybride="X25519MLKEM768", groupe_classique="X25519", mesures=1000, ch_hybride=1397, ch_classique=221,
               cert_ecdsa=406, cert_rsa=None):
    resultats = {
        "hybride": {"groupe": groupe_hybride, "mesures": mesures, "client_hello_octets": ch_hybride, "certificat_octets": cert_ecdsa},
        "classique": {"groupe": groupe_classique, "mesures": mesures, "client_hello_octets": ch_classique, "certificat_octets": cert_ecdsa},
    }
    if cert_rsa is not None:
        resultats["classique_rsa2048"] = {"groupe": groupe_classique, "mesures": mesures, "client_hello_octets": ch_classique,
                                          "certificat_octets": cert_rsa}
    return resultats


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


def test_certificat_rsa_trop_proche_du_ecdsa_est_signale():
    problemes = bench.verifier(_resultats(cert_rsa=500))
    assert any("RSA-2048" in p for p in problemes)


def test_certificat_rsa_plus_gros_est_accepte():
    assert bench.verifier(_resultats(cert_rsa=802)) == []


def test_certificat_mldsa_trop_proche_du_ecdsa_est_signale():
    r = _resultats()
    r["classique_mldsa65"] = {"groupe": "X25519", "mesures": 1000, "client_hello_octets": 221, "certificat_octets": 500}
    assert any("ML-DSA-65" in p for p in bench.verifier(r))
