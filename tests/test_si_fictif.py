"""Tests du générateur du SI fictif."""

import json
import stat

import pytest

from quantum_ready.si_fictif import generer
from quantum_ready.si_fictif.__main__ import main
from quantum_ready.si_fictif.generateur import Contexte, ErreurGenerateur, remplir


@pytest.fixture(scope="module")
def si(tmp_path_factory):
    """Un SI fictif généré une seule fois pour tout le module de tests."""
    racine = tmp_path_factory.mktemp("si") / "v1"
    return generer(racine, racine.parent / "hors_si")


# --- Mécanique du générateur ---


def test_remplir_remplace_les_variables():
    assert remplir("a={{A}} $garde", {"A": "1"}) == "a=1 $garde"


def test_remplir_refuse_une_variable_oubliee():
    with pytest.raises(ErreurGenerateur, match="{{B}}"):
        remplir("{{A}} {{B}}", {"A": "1"})


def test_ecrire_prive_met_les_droits_600(tmp_path):
    ctx = Contexte(racine_si=tmp_path / "si", racine_hors_si=tmp_path / "hors")
    cible = ctx.ecrire("dossier/cle.key", b"x", prive=True)
    assert stat.S_IMODE(cible.stat().st_mode) == 0o600
    assert ctx.fichiers == ["dossier/cle.key"]


def test_refuse_d_ecraser_sans_option(tmp_path):
    (tmp_path / "v1").mkdir()
    with pytest.raises(ErreurGenerateur, match="existe déjà"):
        generer(tmp_path / "v1")


def test_secrets_hors_si(si):
    secrets = json.loads((si.racine_hors_si / "secrets.json").read_text(encoding="utf-8"))
    assert {"MOT_DE_PASSE_BASE", "MOT_DE_PASSE_CONTENEUR_FACTURES"} <= set(secrets)
    assert si.racine_hors_si not in si.racine_si.parents


def test_ligne_de_commande(tmp_path, capsys):
    sortie = tmp_path / "v1"
    assert main(["--sortie", str(sortie), "--hors-si", str(tmp_path / "h")]) == 0
    assert "SI v1 généré" in capsys.readouterr().out
    assert main(["--sortie", str(sortie), "--hors-si", str(tmp_path / "h")]) == 1


# --- Clés SSH (QR-023 à QR-026, QR-032, QR-034, QR-035) ---

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, rsa  # noqa: E402

from quantum_ready.si_fictif.ssh import publique_dsa_openssh  # noqa: E402


def _cle_ssh(si, chemin):
    return serialization.load_ssh_private_key((si.racine_si / chemin).read_bytes(), password=None)


def _ligne_publique(cle):
    return cle.public_key().public_bytes(
        serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH
    ).decode()


@pytest.mark.parametrize(
    "nom, type_attendu, taille",
    [("ed25519", ed25519.Ed25519PrivateKey, None),
     ("rsa", rsa.RSAPrivateKey, 3072),
     ("ecdsa", ec.EllipticCurvePrivateKey, 256)],
)
def test_cles_hote(si, nom, type_attendu, taille):
    chemin = f"ssh/server/ssh_host_{nom}_key"
    cle = _cle_ssh(si, chemin)
    assert isinstance(cle, type_attendu)
    if taille:
        assert cle.key_size == taille
    assert stat.S_IMODE((si.racine_si / chemin).stat().st_mode) == 0o600
    publique = (si.racine_si / (chemin + ".pub")).read_text(encoding="utf-8")
    assert publique.startswith(_ligne_publique(cle))


def test_ancienne_cle_dsa(si):
    privee = (si.racine_si / "ssh/server/old/ssh_host_dsa_key").read_bytes()
    assert privee.startswith(b"-----BEGIN DSA PRIVATE KEY-----")
    cle = serialization.load_pem_private_key(privee, password=None)
    assert isinstance(cle, dsa.DSAPrivateKey) and cle.key_size == 1024
    publique = (si.racine_si / "ssh/server/old/ssh_host_dsa_key.pub").read_text(encoding="utf-8")
    assert publique == publique_dsa_openssh(cle, "root@ssh-lab")


def test_cle_admin_et_authorized_keys(si):
    cle = _cle_ssh(si, "clients/admin/.ssh/id_ed25519")  # chargée sans mot de passe : non chiffrée
    assert isinstance(cle, ed25519.Ed25519PrivateKey)
    autorisees = (si.racine_si / "ssh/server/home/admin/.ssh/authorized_keys").read_text(encoding="utf-8")
    assert autorisees.startswith(_ligne_publique(cle))


def test_known_hosts(si):
    hote = _cle_ssh(si, "ssh/server/ssh_host_ed25519_key")
    ligne = (si.racine_si / "clients/admin/.ssh/known_hosts").read_text(encoding="utf-8").strip()
    assert ligne == "ssh.lab.local " + _ligne_publique(hote)


# --- Configuration SSH (QR-027 à QR-031, QR-033) ---


def directives(chemin, separateur=None):
    """Lit un fichier de configuration « nom valeur » (ou « nom = valeur ») en dictionnaire."""
    resultat = {}
    for ligne in chemin.read_text(encoding="utf-8").splitlines():
        ligne = ligne.split("#", 1)[0].strip()
        if not ligne:
            continue
        nom, _, valeur = ligne.partition(separateur) if separateur else ligne.partition(" ")
        resultat.setdefault(nom.strip(), []).append(valeur.strip().strip(";").strip().strip("'"))
    return resultat


def test_sshd_config(si):
    conf = directives(si.racine_si / "ssh/server/sshd_config")
    assert conf["KexAlgorithms"] == ["curve25519-sha256,diffie-hellman-group14-sha256"]
    assert conf["Ciphers"] == ["chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-ctr"]
    assert conf["MACs"] == ["hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com"]
    assert conf["HostKeyAlgorithms"] == ["ssh-ed25519,rsa-sha2-512,ecdsa-sha2-nistp256"]
    # QR-031 : actif implicite, la directive ne doit pas être écrite.
    assert "PubkeyAcceptedAlgorithms" not in conf and "PubkeyAcceptedKeyTypes" not in conf
    # QR-026 : la vieille clé DSA n'est référencée nulle part.
    assert all("ssh_host_dsa_key" not in cle for cle in conf["HostKey"])
    assert len(conf["HostKey"]) == 3


def test_dockerfile_ssh_fige_openssh_9_6(si):
    texte = (si.racine_si / "ssh/Dockerfile").read_text(encoding="utf-8")
    assert "openssh-server=1:9.6p1" in texte
    assert "old/" not in texte


# --- Configuration nginx (QR-013 à QR-019) ---


def test_nginx_conf(si):
    conf = directives(si.racine_si / "nginx/nginx.conf")
    assert conf["ssl_protocols"] == ["TLSv1.2 TLSv1.3"]
    assert conf["ssl_ciphers"] == ["HIGH:!aNULL:!MD5"]  # QR-014, et QR-015 via HIGH
    assert conf["ssl_ecdh_curve"] == ["X25519:secp256r1"]
    assert conf["ssl_dhparam"] == ["ssl/dhparam.pem"]
    assert conf["ssl_session_tickets"] == ["on"]
    # QR-019 : actif implicite, rien ne fixe les suites TLS 1.3.
    assert "ssl_conf_command" not in conf


def test_dhparam_groupe_14(si):
    import base64

    from quantum_ready.si_fictif.configurations import PREMIER_DH_GROUPE_14, _entier_der

    pem = (si.racine_si / "nginx/ssl/dhparam.pem").read_text(encoding="utf-8").splitlines()
    assert pem[0] == "-----BEGIN DH PARAMETERS-----" and pem[-1] == "-----END DH PARAMETERS-----"
    assert all(len(ligne) <= 64 for ligne in pem)
    der = base64.b64decode("".join(pem[1:-1]))
    attendu = _entier_der(PREMIER_DH_GROUPE_14) + _entier_der(2)
    assert der[0] == 0x30 and der.endswith(attendu)
    assert PREMIER_DH_GROUPE_14.bit_length() == 2048


# --- Configuration PostgreSQL (QR-036 à QR-039) ---


def test_postgresql_conf(si):
    conf = directives(si.racine_si / "db/postgresql.conf", separateur="=")
    assert conf["ssl"] == ["on"]
    assert conf["ssl_min_protocol_version"] == ["TLSv1.2"]
    assert conf["ssl_ecdh_curve"] == ["prime256v1"]
    assert conf["password_encryption"] == ["md5"]
    # QR-037 : actif implicite, la directive ne doit pas être écrite.
    assert "ssl_ciphers" not in conf


def test_pg_hba_md5(si):
    lignes = [l.split() for l in (si.racine_si / "db/pg_hba.conf").read_text(encoding="utf-8").splitlines()
              if l.strip() and not l.startswith("#")]
    assert ["hostssl", "lab_app", "lab_app", "10.0.0.0/8", "md5"] in lignes


# --- API et .env (QR-040 à QR-042, QR-050 à QR-059) ---

import ast  # noqa: E402
import re  # noqa: E402

from quantum_ready.si_fictif.code_applicatif import FICHIERS_API  # noqa: E402


def lire_env(si):
    env = {}
    for ligne in (si.racine_si / "api/.env").read_text(encoding="utf-8").splitlines():
        if ligne and not ligne.startswith("#"):
            nom, _, valeur = ligne.partition("=")
            env[nom] = valeur
    return env


def imports(si, chemin):
    arbre = ast.parse((si.racine_si / chemin).read_text(encoding="utf-8"))
    noms = set()
    for noeud in ast.walk(arbre):
        if isinstance(noeud, ast.Import):
            noms.update(a.name for a in noeud.names)
        elif isinstance(noeud, ast.ImportFrom):
            noms.add(noeud.module or "")
            noms.update(f"{noeud.module}.{a.name}" for a in noeud.names)
    return noms


def test_code_api_est_du_python_valide(si):
    for chemin in FICHIERS_API:
        ast.parse((si.racine_si / chemin).read_text(encoding="utf-8"), filename=chemin)


def test_env(si):
    env = lire_env(si)
    assert set(env) == {"DATABASE_URL", "JWT_ALGORITHM", "JWT_SECRET", "WEBHOOK_SECRET",
                        "FIELD_ENCRYPTION_KEY", "KEYSTORE_PASS"}
    url = env["DATABASE_URL"]
    assert "sslmode=require" in url and "sslrootcert=config/ca_bundle.pem" in url  # QR-040
    assert re.match(r"postgresql://lab_app:[^@]+@db\.lab\.local", url)  # mot de passe de la base
    assert env["JWT_ALGORITHM"] == "HS256" and env["JWT_SECRET"] == "dev-secret-2024"  # QR-052, QR-053
    assert re.fullmatch(r"[0-9a-f]{64}", env["WEBHOOK_SECRET"])  # QR-057 : 256 bits
    from cryptography.fernet import Fernet

    Fernet(env["FIELD_ENCRYPTION_KEY"].encode())  # QR-042 : clé Fernet valide
    assert "FACTURE" not in "".join(env).upper()  # QR-022 : le nom ne trahit pas son usage


def test_algorithme_jwt_absent_du_code(si):
    """QR-052 est caché : l'algorithme n'est écrit que dans le .env."""
    assert "HS256" not in (si.racine_si / "api/tokens.py").read_text(encoding="utf-8")


def test_code_mort_jamais_importe(si):
    """QR-051 : legacy_auth n'est importé par aucun autre fichier."""
    for chemin in FICHIERS_API:
        if chemin != "api/legacy_auth.py":
            assert not any("legacy_auth" in nom for nom in imports(si, chemin)), chemin


@pytest.mark.parametrize(
    "chemin, attendu, interdit",
    [
        ("api/auth.py", "PasswordHasher(time_cost=2, memory_cost=19456, parallelism=1)", None),
        ("api/legacy_auth.py", "hashlib.sha256(", "salt"),
        ("api/reset.py", "random.choice(", "secrets"),
        ("api/utils/codes.py", "random.SystemRandom()", None),
        ("api/webhooks.py", "== signature_recue", "compare_digest"),
        ("api/files.py", "hashlib.sha256(", None),
        ("api/cache.py", "hashlib.md5(", None),
        ("api/crypto_fields.py", "Fernet(", None),
    ],
)
def test_pieges_du_code(si, chemin, attendu, interdit):
    texte = (si.racine_si / chemin).read_text(encoding="utf-8")
    assert attendu in texte
    if interdit:
        assert interdit not in texte


# --- Module de factures (QR-022 côté code, algorithme de signature) ---


def test_module_factures(si):
    texte = (si.racine_si / "factures/signer.py").read_text(encoding="utf-8")
    ast.parse(texte)
    assert "ec.ECDSA(hashes.SHA256())" in texte
    assert 'os.environ["KEYSTORE_PASS"]' in texte
    assert '"keys" / "factures.p12"' in texte
    assert "factures.signer" in imports(si, "api/app.py")
