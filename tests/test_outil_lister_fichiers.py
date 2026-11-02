"""lister_fichiers : reconnaissance des fichiers d'après leur contenu."""

import pytest

from quantum_ready.outils.lister_fichiers import lister_fichiers, reconnaitre


@pytest.fixture(scope="module")
def natures(racine_si):
    resultat = lister_fichiers(".", racine=racine_si)
    assert resultat.erreurs == []
    return {f.chemin: f for f in resultat.fichiers}


@pytest.mark.parametrize(
    ("chemin", "nature", "outil"),
    [
        ("api/.env", "variables_env", "analyser_configuration"),
        ("api/config/ca_bundle.pem", "certificats_pem", "analyser_x509"),
        ("factures/keys/factures.p12", "pkcs12", "analyser_pkcs12"),
        ("ssh/server/old/ssh_host_dsa_key", "cle_privee_pem", "analyser_cle"),
        ("clients/admin/.ssh/known_hosts", "cles_publiques_ssh", "analyser_cle"),
        ("nginx/ssl/dhparam.pem", "parametres_dh", "analyser_cle"),
        ("scripts/keys/backup_pub.asc", "cle_openpgp", "analyser_cle"),
        ("nginx/nginx.conf", "config_nginx", "analyser_configuration"),
        ("ssh/server/sshd_config", "config_sshd", "analyser_configuration"),
        ("db/postgresql.conf", "config_postgresql", "analyser_configuration"),
        ("db/pg_hba.conf", "config_pg_hba", "analyser_configuration"),
        ("ssh/Dockerfile", "dockerfile", "analyser_configuration"),
        ("scripts/backup.sh", "script_shell", "analyser_configuration"),
        ("api/uv.lock", "verrou_uv", "analyser_dependances"),
        ("api/pyproject.toml", "pyproject", "analyser_dependances"),
        ("factures/signer.py", "code_python", "scanner_code_crypto"),
    ],
)
def test_nature_reconnue(natures, chemin, nature, outil):
    assert natures[chemin].nature == nature
    assert natures[chemin].outil_conseille == outil


def test_la_nature_ne_depend_pas_du_nom(tmp_path):
    (tmp_path / "notes.txt").write_text("-----BEGIN OPENSSH PRIVATE KEY-----\nxx\n")
    resultat = lister_fichiers(".", racine=tmp_path)
    assert resultat.fichiers[0].nature == "cle_privee_openssh"


def test_un_seul_fichier_et_les_dossiers_ignores(tmp_path):
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "config").write_text("[core]")
    (tmp_path / "a.py").write_text("import os\n")
    assert [f.chemin for f in lister_fichiers(".", racine=tmp_path).fichiers] == ["a.py"]
    assert lister_fichiers("a.py", racine=tmp_path).fichiers[0].nature == "code_python"


@pytest.mark.parametrize(
    ("contenu", "nature"),
    [(b"", "vide"), (b"\xff\xfe\x00", "binaire"), (b"\x30\x82\x00\x01", "binaire_der"), (b"bonjour", "texte")],
)
def test_cas_limites(contenu, nature):
    assert reconnaitre(contenu) == nature


def test_certificat_der_n_est_pas_un_pkcs12(racine_si):
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization

    pem = (racine_si / "certs/ca/racine.crt").read_bytes()
    der = x509.load_pem_x509_certificate(pem).public_bytes(serialization.Encoding.DER)
    assert reconnaitre(der, "a.cer") == "certificat_der"
    assert reconnaitre((racine_si / "factures/keys/factures.p12").read_bytes()) == "pkcs12"


@pytest.mark.parametrize(
    ("nom", "contenu", "nature"),
    [
        ("A.java", "import javax.crypto.Cipher;\npublic class A {}\n", "code_java"),
        ("main.go", "package main\nimport \"crypto/md5\"\n", "code_go"),
        ("outil", "import os\n\ndef f(x):\n    return x\n", "code_python"),
        ("ssl-params.conf", "ssl_protocols TLSv1.3;\nssl_prefer_server_ciphers off;\n", "config_nginx"),
        ("httpd.conf", "<VirtualHost *:443>\n  SSLEngine on\n</VirtualHost>\n", "config_apache"),
        ("compose.yml", "services:\n  db:\n    image: mysql\n", "yaml"),
        ("conf.json", '{"tls": {"enabled": true}}', "json"),
        ("requirements.txt", "requests==2.31.0\ncryptography>=42\n", "requirements"),
        ("sshd_config", "Port 2222\nCiphers aes128-ctr\nUsePAM yes\n", "config_sshd"),
        ("config", "Host routeur\n  HostName 10.0.0.1\n  User admin\n", "config_ssh_client"),
        ("main.cf", "smtpd_tls_security_level = may\nsmtpd_tls_protocols = !SSLv2\nmyhostname mail\n", "texte"),
    ],
)
def test_formats_varies(nom, contenu, nature):
    assert reconnaitre(contenu.encode(), nom) == nature


def test_format_sans_analyseur_signale(tmp_path):
    (tmp_path / "A.java").write_text("public class A {}\n")
    (fichier,) = lister_fichiers(".", racine=tmp_path).fichiers
    assert fichier.outil_conseille == "rechercher_algorithmes" and "java" in fichier.remarque


def test_hors_perimetre(racine_si):
    assert "hors du périmètre" in lister_fichiers("../", racine=racine_si).erreurs[0]
