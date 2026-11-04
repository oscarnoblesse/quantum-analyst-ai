"""Évaluation : appariement CBOM / vérité terrain, mesures, référence « outils seuls », tableau comparatif."""

import json

import pytest

from quantum_ready.evaluation.__main__ import main as comparer
from quantum_ready.evaluation.__main__ import tableau
from quantum_ready.evaluation.appariement import Composant, apparier, candidat
from quantum_ready.evaluation.mesures import evaluer
from quantum_ready.evaluation.reference import executer as reference
from quantum_ready.orchestrateur import executer as orchestrer

ACTIF = {"id": "QR-1", "type_cyclonedx": "related-crypto-material", "fichier": "nginx/ssl/server.crt (+ nginx/ssl/fullchain.pem)",
         "actif": "Clé publique du serveur", "algorithme": "RSA-2048", "visibilite": "Visible", "vulnerabilite": "Oui (Shor)"}


def _composant(reference, nom, lieu, type_actif="related-crypto-material"):
    return Composant(reference, type_actif, nom, nom, [lieu])


def test_candidat_par_type_et_emplacement():
    assert candidat(ACTIF, _composant("a", "RSA-2048", "nginx/ssl/fullchain.pem"))
    assert not candidat(ACTIF, _composant("b", "RSA-2048", "nginx/ssl/fullchain.pem", "algorithm"))
    assert not candidat(ACTIF, _composant("c", "RSA-2048", "db/tls/server.crt"))
    implicite = ACTIF | {"fichier": "Aucun (valeur par défaut)"}
    assert candidat(implicite, _composant("d", "x", "implicite : défaut")) and not candidat(implicite, _composant("e", "x", "a/b"))


def test_appariement_un_a_un_doublons_et_en_trop():
    second = ACTIF | {"id": "QR-2", "actif": "Clé publique de l'AC", "algorithme": "ECDSA P-384"}
    composants = [_composant("rsa", "RSA-2048", "nginx/ssl/server.crt"), _composant("ec", "ECDSA P-384", "nginx/ssl/fullchain.pem"),
                  _composant("rsa-bis", "RSA-2048", "nginx/ssl/fullchain.pem"), _composant("autre", "Ed25519", "ssh/k")]
    resultat = apparier([ACTIF, second], composants)
    assert resultat.paires == {"QR-1": "rsa", "QR-2": "ec"}
    assert resultat.doublons == ["rsa-bis"] and resultat.en_trop == ["autre"]


@pytest.fixture(scope="module")
def sessions(racine_si, tmp_path_factory):
    dossier = tmp_path_factory.mktemp("comparaison")
    configuration = dossier / "experiment.yaml"
    configuration.write_text("orchestrateur:\n  validation_humaine: accepter\nmosca:\n  horizon_menace_annees: 10\n")
    reference(str(racine_si), str(dossier / "outils_seuls"))
    orchestrer(str(racine_si), str(dossier / "regles"), "regles", configuration=configuration, transport="memoire")
    return dossier


def test_la_reference_ne_fait_pas_le_lien_pkcs12(sessions):
    resultat = evaluer(sessions / "outils_seuls")
    assert resultat["cbom_valide"] and resultat["qualite"]["manques"] == ["QR-020"]
    assert resultat["couts"]["tours_de_modele"] == 0


def test_les_agents_a_regles_trouvent_tout(sessions):
    resultat = evaluer(sessions / "regles")
    qualite = resultat["qualite"]
    assert qualite["rappel"] == 1.0 and qualite["rappel_caches"] == 1.0 and qualite["precision_hors_doublons"] > 0.95
    assert resultat["couts"]["tours_de_modele"] > 0 and resultat["couts"]["arrets"]["analyste_risque"] == "termine"
    assert resultat["plan"]["conforme"] and resultat["plan"]["etapes"] >= 3 and "IETF-TLS-HYBRIDE" in resultat["plan"]["references"]
    assert evaluer(sessions / "outils_seuls")["plan"] is None


def test_tableau_et_ligne_de_commande(sessions, capsys):
    comparer([str(sessions / "outils_seuls"), str(sessions / "regles")])
    sortie = capsys.readouterr().out
    assert "| Rappel | 98.6% | 100.0% |" in sortie and "actifs manqués : QR-020" in sortie
    assert json.loads((sessions / "regles" / "evaluation.json").read_text())["qualite"]["rappel"] == 1.0


def test_session_sans_cbom(tmp_path):
    resultat = evaluer(tmp_path)
    assert resultat["erreur"].startswith("aucun cbom") and "—" in tableau([resultat])
