"""rechercher_algorithmes : repli textuel pour tout format, secrets masqués."""

import pytest

from quantum_ready.outils.rechercher_algorithmes import masquer, normaliser, rechercher_algorithmes


def _noms(resultat):
    return {t.nom: t for t in resultat.trouvailles}


def test_java(tmp_path):
    (tmp_path / "C.java").write_text('Cipher c = Cipher.getInstance("DES/ECB/PKCS5Padding");\nKeyPairGenerator.getInstance("RSA").initialize(1024);\n')
    noms = _noms(rechercher_algorithmes("C.java", racine=tmp_path))
    assert "faiblesse_classique" in noms["DES-ECB"].proprietes and noms["RSA"].exposition == "shor"
    assert "indice" in noms["RSA"].proprietes["confiance"]


def test_postfix_suites_et_versions(tmp_path):
    (tmp_path / "main.cf").write_text(
        "smtpd_tls_protocols = !SSLv2, !SSLv3, TLSv1.2\n"
        "tls_high_cipherlist = ECDHE-RSA-AES256-GCM-SHA384:DES-CBC3-SHA\n"
        "tls_eecdh_auto_curves = X25519MLKEM768 X25519 prime256v1\n"
    )
    noms = _noms(rechercher_algorithmes("main.cf", racine=tmp_path))
    assert {"SSLv2", "SSLv3", "TLSv1.2", "ECDHE-RSA-AES256-GCM-SHA384", "DES-CBC3-SHA", "X25519MLKEM768", "prime256v1"} <= set(noms)
    assert noms["X25519MLKEM768"].exposition == "resistant"
    assert "AES-256" not in noms  # les morceaux d'une suite ne sont pas comptés à part


def test_pas_de_faux_positif_sur_le_francais_et_les_cles(tmp_path):
    (tmp_path / "notes.txt").write_text("Liste des serveurs et des desktops.\n-----BEGIN CERTIFICATE-----\nMIIRSA\n-----END CERTIFICATE-----\n")
    assert rechercher_algorithmes("notes.txt", racine=tmp_path).trouvailles == []


def test_secrets_masques(tmp_path):
    (tmp_path / "app.yml").write_text("jwt:\n  secret: s3cr3t-tres-long\n  algorithm: HS512\napi_key=ABCDEF123456 # sha256\n")
    resultat = rechercher_algorithmes("app.yml", racine=tmp_path)
    texte = resultat.model_dump_json()
    assert "s3cr3t" not in texte and "ABCDEF123456" not in texte
    assert masquer("password: 'x1'") == "password: '<masqué>'"


def test_dossier_ne_double_pas_les_outils_dedies(racine_si):
    assert rechercher_algorithmes(".", racine=racine_si).trouvailles == []
    assert "TLSv1.2" in _noms(rechercher_algorithmes("nginx", racine=racine_si, tous=True))


def test_binaire(tmp_path):
    (tmp_path / "b.bin").write_bytes(b"\xff\xfe\x00\x01")
    assert "binaire" in rechercher_algorithmes("b.bin", racine=tmp_path).erreurs[0]


@pytest.mark.parametrize(("brut", "canonique"), [("sha256", "SHA-256"), ("tls 1.2", "TLSv1.2"), ("TLSv1", "TLSv1.0"), ("aes_256_gcm", "AES-256-GCM"), ("DESede", "3DES"), ("sslv3", "SSLv3")])
def test_normaliser(brut, canonique):
    assert normaliser(brut) == canonique
