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


# --- Dépendances (QR-060 à QR-064) ---

import tomllib  # noqa: E402


def test_dependances(si):
    projet = tomllib.loads((si.racine_si / "api/pyproject.toml").read_text(encoding="utf-8"))
    declarees = {re.split(r"[<>=]", d)[0] for d in projet["project"]["dependencies"]}
    assert declarees == {"argon2-cffi", "cryptography", "paramiko", "pycryptodome", "pyjwt"}
    assert "pycryptodome==3.9.9" in projet["project"]["dependencies"]
    verrou = tomllib.loads((si.racine_si / "api/uv.lock").read_text(encoding="utf-8"))
    verrouillees = {p["name"] for p in verrou["package"]}
    # QR-064 : pynacl et bcrypt n'apparaissent que dans le verrou, tirés par paramiko.
    assert {"pynacl", "bcrypt"} <= verrouillees and not {"pynacl", "bcrypt"} & declarees
    assert declarees <= verrouillees


def test_pycryptodome_jamais_importe(si):
    """QR-063 : aucune source Python du SI n'importe pycryptodome (Crypto ou Cryptodome)."""
    for fichier in si.racine_si.rglob("*.py"):
        noms = imports(si, fichier.relative_to(si.racine_si))
        assert not any(n.split(".")[0] in {"Crypto", "Cryptodome"} for n in noms), fichier


def test_paramiko_utilise_par_deploy(si):
    assert "paramiko" in imports(si, "scripts/deploy.py")


# --- Sauvegardes chiffrées (QR-043, QR-044) ---

from quantum_ready.si_fictif.openpgp import _crc24, lire_cle_publique  # noqa: E402


def test_crc24_vecteur_connu():
    assert _crc24(b"") == 0xB704CE


def test_cle_publique_gpg(si):
    infos = lire_cle_publique((si.racine_si / "scripts/keys/backup_pub.asc").read_text(encoding="utf-8"))
    assert infos == {"algorithme": "RSA", "taille": 3072, "identite": "Sauvegardes Lab <backup@lab.local>"}


def test_script_sauvegarde(si):
    script = si.racine_si / "scripts/backup.sh"
    texte = script.read_text(encoding="utf-8")
    assert "--encrypt --recipient backup@lab.local" in texte
    assert "keys/backup_pub.asc" in texte.replace('$CLES/', "keys/")
    assert stat.S_IMODE(script.stat().st_mode) & stat.S_IXUSR


def test_cle_privee_des_sauvegardes_hors_si(si):
    assert (si.racine_hors_si / "sauvegardes/backup_priv.pem").exists()
    assert not list(si.racine_si.rglob("backup_priv*"))


# --- Cohérence SI ↔ vérité terrain (controles.py) ---

import shutil  # noqa: E402
from pathlib import Path  # noqa: E402

from quantum_ready.si_fictif import controles  # noqa: E402
from quantum_ready.verite_terrain import charger_csv  # noqa: E402

CSV_V1 = Path(__file__).resolve().parents[1] / "data" / "ground_truth" / "verite_terrain_v1.csv"
ACTIFS = charger_csv(CSV_V1)
IDS = [a.id for a in ACTIFS]


def test_chaque_actif_a_un_controle():
    assert set(IDS) == set(controles.CONTROLES), "chaque ligne de la vérité terrain doit avoir un contrôle"


@pytest.mark.parametrize("identifiant", IDS)
def test_actif_present_dans_le_si(si, identifiant):
    if identifiant in controles.IDS_PKI and not (si.racine_si / "certs/ca/racine.crt").exists():
        pytest.xfail("étape PKI pas encore écrite")
    assert controles.verifier(si.racine_si, [identifiant]) == {identifiant: None}


def test_aucun_fichier_cryptographique_hors_verite_terrain(si):
    assert controles.fichiers_non_inventories(si.racine_si, [a.fichier for a in ACTIFS]) == []


def test_un_ecart_est_detecte(si, tmp_path):
    """Si le SI s'écarte du tableau, le contrôle doit le voir."""
    copie = tmp_path / "si"
    shutil.copytree(si.racine_si, copie)
    conf = copie / "ssh/server/sshd_config"
    conf.write_text(conf.read_text(encoding="utf-8").replace("curve25519-sha256,", ""), encoding="utf-8")
    (copie / "api/cache.py").unlink()
    (copie / "notes.txt").write_text("-----BEGIN PRIVATE KEY-----\n", encoding="utf-8")
    resultats = controles.verifier(copie, ["QR-027", "QR-059", "QR-999"])
    assert all(resultats.values())
    assert controles.fichiers_non_inventories(copie, [a.fichier for a in ACTIFS]) == ["notes.txt"]


def test_rapport_en_ligne_de_commande(si, capsys):
    code = controles.main([str(si.racine_si), str(CSV_V1)])
    sortie = capsys.readouterr().out
    assert "actifs conformes" in sortie
    pki_ecrite = (si.racine_si / "certs/ca/racine.crt").exists()
    assert code == (0 if pki_ecrite else 1)
