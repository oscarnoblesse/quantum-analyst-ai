"""analyser_pkcs12 : structure lisible sans mot de passe, contenu avec, secret jamais renvoyé."""

import json

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import pkcs12

from quantum_ready.outils.analyser_pkcs12 import analyser_pkcs12
from quantum_ready.outils.commun import lire_env, secret_depuis_env

P12 = "factures/keys/factures.p12"


def test_structure_sans_mot_de_passe(racine_si):
    resultat = analyser_pkcs12(P12, racine=racine_si)
    assert resultat.erreurs == [] and len(resultat.trouvailles) == 1
    chiffrement = resultat.trouvailles[0]
    assert chiffrement.nom == "pbeWithSHA1And3-KeyTripleDES-CBC ; MAC SHA-1"
    assert chiffrement.proprietes["chiffrement_cle"] == ["pbeWithSHA1And3-KeyTripleDES-CBC"]
    assert "faiblesse_classique" in chiffrement.proprietes
    assert "mot de passe" in resultat.pistes[0].vers


def test_ouverture_avec_le_mot_de_passe_du_env(racine_si):
    resultat = analyser_pkcs12(P12, racine=racine_si, fichier_env="api/.env", variable="KEYSTORE_PASS")
    assert resultat.erreurs == []
    types = [(t.type_actif, t.nom) for t in resultat.trouvailles[1:]]
    assert types == [
        ("related-crypto-material", "ECDSA P-256"),
        ("certificate", "Certificat « Lab Factures »"),
        ("related-crypto-material", "ECDSA P-256"),
        ("algorithm", "ecdsa-with-SHA384"),
    ]
    secret = secret_depuis_env("api/.env", "KEYSTORE_PASS", racine_si)
    assert secret not in resultat.model_dump_json()


def test_mauvais_mot_de_passe_ou_variable_absente(racine_si):
    faux = analyser_pkcs12(P12, racine=racine_si, fichier_env="api/.env", variable="JWT_SECRET")
    assert "Mot de passe refusé" in faux.erreurs[0]
    absente = analyser_pkcs12(P12, racine=racine_si, fichier_env="api/.env", variable="INEXISTANTE")
    assert "absente" in absente.erreurs[0]


def test_conteneur_moderne_sans_faiblesse(tmp_path):
    cle = ec.generate_private_key(ec.SECP384R1())
    (tmp_path / "moderne.p12").write_bytes(
        pkcs12.serialize_key_and_certificates(b"k", cle, None, None, serialization.BestAvailableEncryption(b"mdp"))
    )
    (tmp_path / ".env").write_text('P12_PASS="mdp"\n')
    resultat = analyser_pkcs12("moderne.p12", racine=tmp_path, fichier_env=".env", variable="P12_PASS")
    assert resultat.trouvailles[0].nom.startswith("PBES2 (PBKDF2")
    assert "faiblesse_classique" not in resultat.trouvailles[0].proprietes
    assert resultat.trouvailles[1].nom == "ECDSA P-384"


def test_fichier_qui_n_est_pas_un_pkcs12(racine_si):
    assert "pas un conteneur PKCS#12" in analyser_pkcs12("api/.env", racine=racine_si).erreurs[0]


def test_lire_env():
    texte = "# commentaire\nexport A=1\nB='deux'\n\nC=\"t=rois\"\nligne sans egal\n"
    assert lire_env(texte) == [(2, "A", "1"), (3, "B", "deux"), (5, "C", "t=rois")]
    assert json.dumps(lire_env("")) == "[]"
