"""Architecte : recherche documentaire, outils de l'agent, vérification du plan par le code."""

import asyncio

from quantum_ready.agents.architecte import verifier_plan
from quantum_ready.outils.rechercher_standard import fiches_connues, rechercher_standard, termes
from quantum_ready.serveur_mcp.client import ouvrir_outils
from quantum_ready.serveur_mcp.session import Session, ecrire_json


def test_recherche_pertinente_et_deterministe():
    premier = rechercher_standard("échange de clés TLS hybride nginx", 2)
    assert premier.extraits[0].fiche == "IETF-TLS-HYBRIDE"
    assert rechercher_standard("échange de clés TLS hybride nginx", 2) == premier
    assert rechercher_standard("sshd KexAlgorithms").extraits[0].fiche == "OPENSSH-PQ"
    assert rechercher_standard("signature ML-DSA certificats").extraits[0].fiche == "NIST-FIPS-204"


def test_recherche_vide_ou_sans_resultat(tmp_path):
    assert "Requête vide" in rechercher_standard("le la les").erreurs[0]
    assert "Aucun passage" in rechercher_standard("zzzzzz").erreurs[0]
    assert "introuvable" in rechercher_standard("tls", dossier=tmp_path).erreurs[0]


def test_corpus():
    assert {"NIST-FIPS-203", "NIST-FIPS-204", "NIST-FIPS-205", "NIST-IR-8547", "ANSSI-AVIS-PQ", "MOSCA"} <= fiches_connues()
    assert termes("Échange de CLÉS") == ["echange", "cles"]


def _session_avec_scores(tmp_path):
    session = Session(tmp_path / "s", tmp_path)
    ecrire_json(session.fichier_cbom, {"components": [{"bom-ref": "crypto-a", "name": "RSA-2048", "evidence": {"occurrences": [{"location": "nginx/ssl/server.crt"}]}},
                                                      {"bom-ref": "crypto-b", "name": "MD5", "evidence": {"occurrences": [{"location": "api/cache.py"}]}}]})
    ecrire_json(session.fichier_scores, {"crypto-a": {"score": 100, "priorite": "critique", "justification": "TLS"},
                                         "crypto-b": {"score": 9, "priorite": "faible", "justification": "cache"}})
    return session


def test_verification_du_plan(tmp_path):
    session = _session_avec_scores(tmp_path)
    bon = {"etapes": [{"ordre": 1, "actifs": ["crypto-a"], "references": ["IETF-TLS-HYBRIDE"]}]}
    assert verifier_plan(bon, session) == []
    mauvais = {"etapes": [{"ordre": 1, "actifs": ["crypto-b", "crypto-z"], "references": []}]}
    erreurs = verifier_plan(mauvais, session)
    assert any("aucune référence" in e for e in erreurs) and any("crypto-z" in e for e in erreurs) and any("crypto-a" in e for e in erreurs)
    assert verifier_plan(None, session) == ["aucun plan produit"]
    assert "aucune étape" in verifier_plan({"etapes": []}, session)[-1]


def test_outils_de_l_architecte(tmp_path):
    session = _session_avec_scores(tmp_path)

    async def executer():
        async with ouvrir_outils("architecte", session, transport="memoire") as outils:
            return sorted(outils.noms), await outils.appeler("lister_priorites", {"nombre": 1}), await outils.appeler("rechercher_standard", {"requete": "MD5 mot de passe"})
    noms, (priorites, _), (normes, erreur) = asyncio.run(executer())
    assert noms == ["lister_priorites", "rechercher_standard"]
    assert "crypto-a | 100 | critique | RSA-2048" in priorites and "crypto-b" not in priorites
    assert not erreur and normes.startswith("[SYMETRIQUE-ET-HACHAGE]")
