"""analyser_x509 : trois actifs par certificat, faiblesses classiques et pistes."""

import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.x509.oid import NameOID

from quantum_ready.outils.analyser_x509 import analyser_x509


def _par_type(resultat):
    return [(t.type_actif, t.nom) for t in resultat.trouvailles]


def test_certificat_de_serveur(racine_si):
    resultat = analyser_x509("nginx/ssl/server.crt", racine=racine_si)
    assert resultat.erreurs == []
    assert _par_type(resultat) == [
        ("certificate", "Certificat « app.lab.local »"),
        ("related-crypto-material", "RSA-2048"),
        ("algorithm", "ecdsa-with-SHA384"),
    ]
    certificat = resultat.trouvailles[0]
    assert certificat.proprietes["autorite"] is False
    assert "api.lab.local" in certificat.proprietes["noms_alternatifs"]
    assert all(t.exposition == "shor" for t in resultat.trouvailles)
    assert any("Lab Intermediate CA" in p.vers for p in resultat.pistes)


def test_le_certificat_oublie_du_magasin_est_signale(racine_si):
    resultat = analyser_x509("api/config/ca_bundle.pem", racine=racine_si)
    noms = [t.nom for t in resultat.trouvailles]
    assert noms.count("RSA-1024") == 1 and "sha1WithRSAEncryption" in noms
    faibles = [t for t in resultat.trouvailles if "faiblesse_classique" in t.proprietes]
    assert {t.nom for t in faibles} == {"RSA-1024", "sha1WithRSAEncryption"}
    assert "certificat 2/2" in faibles[0].description
    assert any("2 certificats" in p.raison for p in resultat.pistes)


def test_racine_auto_signee(racine_si):
    resultat = analyser_x509("certs/ca/racine.crt", racine=racine_si)
    certificat = resultat.trouvailles[0]
    assert certificat.proprietes["auto_signe"] is True and certificat.proprietes["autorite"] is True
    assert resultat.trouvailles[1].nom == "RSA-4096"
    assert resultat.pistes == []


def test_la_meme_racine_a_la_meme_empreinte_partout(racine_si):
    empreintes = {
        analyser_x509(f, racine=racine_si).trouvailles[0].proprietes["empreinte_sha256"]
        for f in ("certs/ca/racine.crt", "nginx/ssl/ca_clients.crt", "db/tls/root.crt")
    }
    assert len(empreintes) == 1


def test_certificat_der_ed25519(tmp_path):
    cle = ed25519.Ed25519PrivateKey.generate()
    nom = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test")])
    maintenant = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder().subject_name(nom).issuer_name(nom).public_key(cle.public_key())
        .serial_number(1).not_valid_before(maintenant - datetime.timedelta(days=10))
        .not_valid_after(maintenant - datetime.timedelta(days=1)).sign(cle, None)
    )
    (tmp_path / "c.der").write_bytes(cert.public_bytes(serialization.Encoding.DER))
    resultat = analyser_x509("c.der", racine=tmp_path)
    assert _par_type(resultat)[1:] == [("related-crypto-material", "Ed25519"), ("algorithm", "ed25519")]
    assert resultat.trouvailles[0].proprietes["expire"] is True


def test_fichier_sans_certificat(racine_si):
    resultat = analyser_x509("ssh/server/sshd_config", racine=racine_si)
    assert resultat.trouvailles == [] and "Aucun certificat" in resultat.erreurs[0]
