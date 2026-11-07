"""Contrôle de cohérence entre le SI généré et la vérité terrain.

Chaque actif QR-xxx de la vérité terrain a ici un contrôle qui vérifie, dans le SI
généré, qu'il existe bien avec les caractéristiques annoncées (algorithme, taille,
valeur de configuration, absence volontaire d'une directive...). Si le générateur
et le tableau divergent un jour, les mesures de rappel et de précision seraient
faussées sans que personne ne s'en aperçoive : ce module l'empêche.

Utilisation : python -m quantum_ready.si_fictif.controles [dossier_si] [csv]
"""

from __future__ import annotations

import ast
import re
import sys
import tomllib
from collections.abc import Callable
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import ExtendedKeyUsageOID

from quantum_ready.si_fictif.openpgp import lire_cle_publique

CSV_PAR_DEFAUT = "data/ground_truth/verite_terrain_v1.csv"
SI_PAR_DEFAUT = "si/generated/v1"

# Actifs produits par l'étape PKI (pki.py) : leurs contrôles échouent tant qu'elle n'est pas écrite.
IDS_PKI = frozenset(
    [f"QR-{i:03d}" for i in range(1, 13)]
    + ["QR-015", "QR-020", "QR-021"]
    + [f"QR-{i:03d}" for i in range(45, 50)]
    + [f"QR-{i:03d}" for i in range(65, 71)]
)


class EcartSI(AssertionError):
    """Le SI généré ne correspond pas à la vérité terrain."""


Controle = Callable[[Path], None]
CONTROLES: dict[str, Controle] = {}


def controle(*identifiants: str):
    """Enregistre une fonction comme contrôle d'un ou plusieurs actifs."""

    def enregistrer(fonction: Controle) -> Controle:
        for identifiant in identifiants:
            CONTROLES[identifiant] = fonction
        return fonction

    return enregistrer


def exiger(condition: object, message: str) -> None:
    if not condition:
        raise EcartSI(message)


# --- Lecture des fichiers du SI ---


def lire(si: Path, chemin: str) -> str:
    fichier = si / chemin
    exiger(fichier.is_file(), f"fichier absent : {chemin}")
    return fichier.read_text(encoding="utf-8")


def directives(si: Path, chemin: str, separateur: str | None = None) -> dict[str, list[str]]:
    """Configuration « nom valeur » ou « nom = valeur » → {nom: [valeurs]}."""
    resultat: dict[str, list[str]] = {}
    for ligne in lire(si, chemin).splitlines():
        ligne = ligne.split("#", 1)[0].strip()
        if ligne:
            nom, _, valeur = ligne.partition(separateur) if separateur else ligne.partition(" ")
            resultat.setdefault(nom.strip(), []).append(valeur.strip().rstrip(";").strip().strip("'"))
    return resultat


def env(si: Path) -> dict[str, str]:
    valeurs = {}
    for ligne in lire(si, "api/.env").splitlines():
        if ligne and not ligne.startswith("#"):
            nom, _, valeur = ligne.partition("=")
            valeurs[nom] = valeur
    return valeurs


def imports(si: Path, chemin: str) -> set[str]:
    noms: set[str] = set()
    for noeud in ast.walk(ast.parse(lire(si, chemin))):
        if isinstance(noeud, ast.Import):
            noms.update(a.name for a in noeud.names)
        elif isinstance(noeud, ast.ImportFrom) and noeud.module:
            noms.add(noeud.module)
            noms.update(f"{noeud.module}.{a.name}" for a in noeud.names)
    return noms


def certificats(si: Path, chemin: str) -> list[x509.Certificate]:
    fichier = si / chemin
    exiger(fichier.is_file(), f"certificat absent : {chemin}")
    return x509.load_pem_x509_certificates(fichier.read_bytes())


def certificat(si: Path, chemin: str) -> x509.Certificate:
    return certificats(si, chemin)[0]


def description_cle(cle) -> str:
    """« RSA-2048 », « ECDSA P-384 », « Ed25519 » ou « DSA-1024 »."""
    if isinstance(cle, (rsa.RSAPrivateKey, rsa.RSAPublicKey)):
        return f"RSA-{cle.key_size}"
    if isinstance(cle, (ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey)):
        return f"ECDSA P-{cle.curve.key_size}"
    if isinstance(cle, (ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey)):
        return "Ed25519"
    if isinstance(cle, (dsa.DSAPrivateKey, dsa.DSAPublicKey)):
        return f"DSA-{cle.key_size}"
    return type(cle).__name__


def nom_signature(cert: x509.Certificate) -> str:
    return cert.signature_algorithm_oid._name


def cle_privee_pem(si: Path, chemin: str, mot_de_passe: bytes | None = None):
    fichier = si / chemin
    exiger(fichier.is_file(), f"clé absente : {chemin}")
    return serialization.load_pem_private_key(fichier.read_bytes(), password=mot_de_passe)


def meme_cle_publique(cle_a, cle_b) -> bool:
    format_ = (serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return cle_a.public_bytes(*format_) == cle_b.public_bytes(*format_)


def usages_etendus(cert: x509.Certificate) -> list:
    return list(cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value)


def noms_dns(cert: x509.Certificate) -> set[str]:
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    return set(san.get_values_for_type(x509.DNSName))


def duree_ans(cert: x509.Certificate) -> float:
    return (cert.not_valid_after_utc - cert.not_valid_before_utc).days / 365


# --- Certificats et PKI (étape pki.py) ---

RACINE, INTERMEDIAIRE = "certs/ca/racine.crt", "certs/ca/intermediaire.crt"
NGINX_CRT, BASE_CRT = "nginx/ssl/server.crt", "db/tls/server.crt"
FACTURES_CRT, ADMIN_CRT = "factures/keys/factures.crt", "clients/admin/admin.crt"


@controle("QR-001")
def _cle_racine(si):
    racine = certificat(si, RACINE)
    exiger(description_cle(racine.public_key()) == "RSA-4096", "la racine doit avoir une clé RSA-4096")
    for copie in ("nginx/ssl/ca_clients.crt", "db/tls/root.crt"):
        exiger(certificat(si, copie) == racine, f"{copie} doit être une copie de la racine")
    exiger(certificats(si, "api/config/ca_bundle.pem")[0] == racine, "ca_bundle.pem doit commencer par la racine")


@controle("QR-002")
def _signature_racine(si):
    racine = certificat(si, RACINE)
    exiger(racine.issuer == racine.subject, "la racine doit être auto-signée")
    exiger(nom_signature(racine) == "sha256WithRSAEncryption", "signature attendue : sha256WithRSAEncryption")


@controle("QR-003")
def _cle_intermediaire(si):
    inter = certificat(si, INTERMEDIAIRE)
    exiger(description_cle(inter.public_key()) == "ECDSA P-384", "l'intermédiaire doit avoir une clé ECDSA P-384")
    exiger(certificats(si, "nginx/ssl/fullchain.pem")[1:2] == [inter], "fullchain.pem doit contenir l'intermédiaire en 2e position")


def _signe_par(si, chemin, emetteur, algorithme):
    cert = certificat(si, chemin)
    exiger(cert.issuer == certificat(si, emetteur).subject, f"{chemin} doit être émis par {emetteur}")
    exiger(nom_signature(cert) == algorithme, f"{chemin} : signature attendue {algorithme}, trouvée {nom_signature(cert)}")
    cert.verify_directly_issued_by(certificat(si, emetteur))


@controle("QR-004")
def _signature_intermediaire(si):
    _signe_par(si, INTERMEDIAIRE, RACINE, "sha256WithRSAEncryption")


@controle("QR-005")
def _cle_nginx(si):
    cert = certificat(si, NGINX_CRT)
    exiger(description_cle(cert.public_key()) == "RSA-2048", "le certificat nginx doit avoir une clé RSA-2048")
    exiger(certificats(si, "nginx/ssl/fullchain.pem")[0] == cert, "fullchain.pem doit commencer par le certificat nginx")


@controle("QR-006", "QR-008", "QR-010", "QR-012")
def _signatures_feuilles(si):
    for chemin in (NGINX_CRT, BASE_CRT, FACTURES_CRT, ADMIN_CRT):
        _signe_par(si, chemin, INTERMEDIAIRE, "ecdsa-with-SHA384")


@controle("QR-007")
def _cle_base(si):
    exiger(description_cle(certificat(si, BASE_CRT).public_key()) == "RSA-3072", "le certificat de la base doit avoir une clé RSA-3072")


@controle("QR-009", "QR-011")
def _cles_ecdsa_p256(si):
    for chemin in (FACTURES_CRT, ADMIN_CRT):
        exiger(description_cle(certificat(si, chemin).public_key()) == "ECDSA P-256", f"{chemin} : clé ECDSA P-256 attendue")


@controle("QR-015")
def _suite_echange_rsa(si):
    conf = directives(si, "nginx/nginx.conf")
    exiger("TLSv1.2" in conf["ssl_protocols"][0], "TLS 1.2 doit être autorisé")
    exiger(conf["ssl_ciphers"][0].startswith("HIGH") and "kRSA" not in conf["ssl_ciphers"][0], "la macro HIGH ne doit pas exclure kRSA")
    cert = certificat(si, NGINX_CRT)
    exiger(isinstance(cert.public_key(), rsa.RSAPublicKey), "le certificat nginx doit être RSA")
    exiger(cert.extensions.get_extension_for_class(x509.KeyUsage).value.key_encipherment,
           "l'échange de clés RSA exige l'usage keyEncipherment")


# OID DER : pbeWithSHAAnd3-KeyTripleDES-CBC, PBES2 et SHA-1.
_OID_3DES = bytes.fromhex("060a2a864886f70d010c0103")
_OID_PBES2 = bytes.fromhex("06092a864886f70d01050d")
_OID_SHA1 = bytes.fromhex("06052b0e03021a")


@controle("QR-020")
def _cle_factures(si):
    contenu = (si / "factures/keys/factures.p12").read_bytes() if (si / "factures/keys/factures.p12").exists() else None
    exiger(contenu, "conteneur absent : factures/keys/factures.p12")
    cle, cert, _ = pkcs12.load_key_and_certificates(contenu, env(si)["KEYSTORE_PASS"].encode())
    exiger(description_cle(cle) == "ECDSA P-256", "la clé de signature des factures doit être ECDSA P-256")
    exiger(meme_cle_publique(cle.public_key(), certificat(si, FACTURES_CRT).public_key()), "la clé du PKCS#12 doit correspondre à factures.crt")


@controle("QR-021")
def _chiffrement_p12(si):
    exiger((si / "factures/keys/factures.p12").exists(), "conteneur absent : factures/keys/factures.p12")
    contenu = (si / "factures/keys/factures.p12").read_bytes()
    exiger(_OID_3DES in contenu and _OID_PBES2 not in contenu, "le PKCS#12 doit utiliser l'ancien chiffrement 3DES (PBES1)")
    exiger(_OID_SHA1 in contenu, "le PKCS#12 doit avoir un MAC SHA-1")


@controle("QR-045")
def _ancienne_ac(si):
    bundle = certificats(si, "api/config/ca_bundle.pem")
    exiger(len(bundle) >= 2, "ca_bundle.pem doit contenir un 2e certificat (ancienne AC)")
    ancienne = bundle[1]
    exiger(description_cle(ancienne.public_key()) == "RSA-1024", "l'ancienne AC doit être RSA-1024")
    exiger(nom_signature(ancienne) == "sha1WithRSAEncryption", "l'ancienne AC doit être signée en SHA-1")
    exiger(ancienne.not_valid_after_utc.year == 2035, "l'ancienne AC doit être valide jusqu'en 2035")


@controle("QR-046")
def _cle_intermediaire_oubliee(si):
    cle = cle_privee_pem(si, "deploy/old/backup_2024/inter.key")
    exiger(meme_cle_publique(cle.public_key(), certificat(si, INTERMEDIAIRE).public_key()), "inter.key doit être la clé de l'intermédiaire")


@controle("QR-047")
def _cle_privee_nginx(si):
    cle = cle_privee_pem(si, "nginx/ssl/server.key")
    exiger(meme_cle_publique(cle.public_key(), certificat(si, NGINX_CRT).public_key()), "server.key doit correspondre au certificat nginx")


@controle("QR-048")
def _cle_privee_base(si):
    cle = cle_privee_pem(si, "db/tls/server.key")
    exiger(meme_cle_publique(cle.public_key(), certificat(si, BASE_CRT).public_key()), "db/tls/server.key doit correspondre au certificat de la base")


@controle("QR-049")
def _cle_privee_admin(si):
    texte = lire(si, "clients/admin/admin.key")
    exiger("BEGIN ENCRYPTED PRIVATE KEY" in texte, "la clé mTLS de l'admin doit être chiffrée par phrase de passe")


@controle("QR-065", "QR-066")
def _autorites(si):
    for chemin, longueur, ans in ((RACINE, 1, 20), (INTERMEDIAIRE, 0, 10)):
        contraintes = certificat(si, chemin).extensions.get_extension_for_class(x509.BasicConstraints).value
        exiger(contraintes.ca and contraintes.path_length == longueur, f"{chemin} doit être une AC (longueur de chemin {longueur})")
        exiger(abs(duree_ans(certificat(si, chemin)) - ans) < 0.5, f"{chemin} doit être valide {ans} ans")


@controle("QR-067", "QR-068")
def _certificats_serveurs(si):
    for chemin, noms in ((NGINX_CRT, {"app.lab.local", "api.lab.local"}), (BASE_CRT, {"db.lab.local"})):
        cert = certificat(si, chemin)
        exiger(ExtendedKeyUsageOID.SERVER_AUTH in usages_etendus(cert), f"{chemin} : usage serverAuth attendu")
        exiger(noms_dns(cert) == noms, f"{chemin} : noms attendus {sorted(noms)}")


@controle("QR-069")
def _certificat_factures(si):
    usages = certificat(si, FACTURES_CRT).extensions.get_extension_for_class(x509.KeyUsage).value
    exiger(usages.digital_signature and usages.content_commitment, "factures.crt : signature et non-répudiation attendues")


@controle("QR-070")
def _certificat_admin(si):
    exiger(ExtendedKeyUsageOID.CLIENT_AUTH in usages_etendus(certificat(si, ADMIN_CRT)), "admin.crt : usage clientAuth attendu")


# --- nginx (QR-013 à QR-019, sauf QR-015 ci-dessus) ---


def _nginx(si, directive):
    return directives(si, "nginx/nginx.conf").get(directive, [])


@controle("QR-013")
def _nginx_protocoles(si):
    exiger(_nginx(si, "ssl_protocols") == ["TLSv1.2 TLSv1.3"], "ssl_protocols attendu : TLSv1.2 TLSv1.3")


@controle("QR-014")
def _nginx_suites(si):
    exiger(_nginx(si, "ssl_ciphers") == ["HIGH:!aNULL:!MD5"], "ssl_ciphers attendu : HIGH:!aNULL:!MD5")


@controle("QR-016")
def _nginx_groupes(si):
    exiger(_nginx(si, "ssl_ecdh_curve") == ["X25519:secp256r1"], "ssl_ecdh_curve attendu : X25519:secp256r1")


@controle("QR-017")
def _nginx_dhparam(si):
    exiger(_nginx(si, "ssl_dhparam") == ["ssl/dhparam.pem"], "ssl_dhparam doit pointer vers ssl/dhparam.pem")
    exiger("BEGIN DH PARAMETERS" in lire(si, "nginx/ssl/dhparam.pem"), "dhparam.pem doit contenir des paramètres DH")


@controle("QR-018")
def _nginx_tickets(si):
    exiger(_nginx(si, "ssl_session_tickets") == ["on"], "ssl_session_tickets attendu : on")


@controle("QR-019")
def _nginx_tls13_implicite(si):
    exiger(not _nginx(si, "ssl_conf_command"), "les suites TLS 1.3 ne doivent pas être configurées (actif implicite)")


# --- Factures et secrets du .env (QR-022, QR-040, QR-042, QR-053, QR-057, QR-071, QR-073) ---


@controle("QR-022")
def _mot_de_passe_conteneur(si):
    exiger(env(si).get("KEYSTORE_PASS"), "KEYSTORE_PASS absent du .env")
    exiger('os.environ["KEYSTORE_PASS"]' in lire(si, "factures/signer.py"), "signer.py doit lire KEYSTORE_PASS")


@controle("QR-040")
def _sslmode(si):
    url = env(si).get("DATABASE_URL", "")
    exiger("sslmode=require" in url and "sslrootcert=config/ca_bundle.pem" in url, "DATABASE_URL : sslmode=require et sslrootcert attendus")


@controle("QR-041")
def _fernet(si):
    exiger("Fernet(" in lire(si, "api/crypto_fields.py"), "crypto_fields.py doit utiliser Fernet")


@controle("QR-042")
def _cle_fernet(si):
    from cryptography.fernet import Fernet

    Fernet(env(si)["FIELD_ENCRYPTION_KEY"].encode())


@controle("QR-053")
def _secret_jwt(si):
    exiger(env(si).get("JWT_SECRET") == "dev-secret-2024", "JWT_SECRET attendu : dev-secret-2024")


@controle("QR-057")
def _secret_webhook(si):
    exiger(re.fullmatch(r"[0-9a-f]{64}", env(si).get("WEBHOOK_SECRET", "")), "WEBHOOK_SECRET : 256 bits en hexadécimal attendus")


@controle("QR-071")
def _mot_de_passe_base(si):
    exiger(re.match(r"postgresql://lab_app:[^@]+@", env(si).get("DATABASE_URL", "")), "DATABASE_URL doit contenir un mot de passe")


@controle("QR-073")
def _signature_factures(si):
    exiger("ec.ECDSA(hashes.SHA256())" in lire(si, "factures/signer.py"), "signer.py : ECDSA avec SHA-256 attendu")


# --- SSH (QR-023 à QR-035) ---


def _cle_ssh(si, chemin):
    fichier = si / chemin
    exiger(fichier.is_file(), f"clé absente : {chemin}")
    return serialization.load_ssh_private_key(fichier.read_bytes(), password=None)


@controle("QR-023", "QR-024", "QR-025")
def _cles_hote(si):
    for nom, attendu in (("ed25519", "Ed25519"), ("rsa", "RSA-3072"), ("ecdsa", "ECDSA P-256")):
        exiger(description_cle(_cle_ssh(si, f"ssh/server/ssh_host_{nom}_key")) == attendu, f"clé d'hôte {nom} : {attendu} attendu")


@controle("QR-026")
def _cle_dsa(si):
    exiger(description_cle(cle_privee_pem(si, "ssh/server/old/ssh_host_dsa_key")) == "DSA-1024", "ancienne clé DSA-1024 attendue")
    exiger("ssh_host_dsa_key" not in lire(si, "ssh/server/sshd_config"), "la clé DSA ne doit pas être référencée")


def _sshd(si, directive):
    return directives(si, "ssh/server/sshd_config").get(directive, [])


@controle("QR-027")
def _kex(si):
    exiger(_sshd(si, "KexAlgorithms") == ["curve25519-sha256,diffie-hellman-group14-sha256"], "KexAlgorithms inattendu")


@controle("QR-028")
def _ciphers(si):
    exiger(_sshd(si, "Ciphers") == ["chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-ctr"], "Ciphers inattendu")


@controle("QR-029")
def _macs(si):
    exiger(_sshd(si, "MACs") == ["hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com"], "MACs inattendu")


@controle("QR-030")
def _hostkeyalgorithms(si):
    exiger(_sshd(si, "HostKeyAlgorithms") == ["ssh-ed25519,rsa-sha2-512,ecdsa-sha2-nistp256"], "HostKeyAlgorithms inattendu")


@controle("QR-031")
def _pubkey_implicite(si):
    exiger(not _sshd(si, "PubkeyAcceptedAlgorithms") and not _sshd(si, "PubkeyAcceptedKeyTypes"),
           "PubkeyAcceptedAlgorithms ne doit pas être écrit (actif implicite)")


def _ligne_publique(cle) -> str:
    return cle.public_key().public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).decode()


@controle("QR-032", "QR-034")
def _cle_admin(si):
    cle = _cle_ssh(si, "clients/admin/.ssh/id_ed25519")
    exiger(description_cle(cle) == "Ed25519", "clé SSH de l'admin : Ed25519 attendu")
    exiger(_ligne_publique(cle) in lire(si, "ssh/server/home/admin/.ssh/authorized_keys"), "authorized_keys doit contenir la clé de l'admin")


@controle("QR-033")
def _version_openssh(si):
    exiger("openssh-server=1:9.6p1" in lire(si, "ssh/Dockerfile"), "le Dockerfile doit figer OpenSSH 9.6")


@controle("QR-035")
def _known_hosts(si):
    attendu = "ssh.lab.local " + _ligne_publique(_cle_ssh(si, "ssh/server/ssh_host_ed25519_key"))
    exiger(lire(si, "clients/admin/.ssh/known_hosts").strip() == attendu, "known_hosts doit contenir la clé Ed25519 du serveur")


# --- PostgreSQL (QR-036 à QR-039) ---


def _pg(si, directive):
    return directives(si, "db/postgresql.conf", separateur="=").get(directive, [])


@controle("QR-036")
def _pg_version(si):
    exiger(_pg(si, "ssl_min_protocol_version") == ["TLSv1.2"], "ssl_min_protocol_version attendu : TLSv1.2")


@controle("QR-037")
def _pg_suites_implicites(si):
    exiger(_pg(si, "ssl") == ["on"] and not _pg(si, "ssl_ciphers"), "ssl actif sans ssl_ciphers (actif implicite)")


@controle("QR-038")
def _pg_groupe(si):
    exiger(_pg(si, "ssl_ecdh_curve") == ["prime256v1"], "ssl_ecdh_curve attendu : prime256v1")


@controle("QR-039")
def _pg_md5(si):
    exiger(_pg(si, "password_encryption") == ["md5"], "password_encryption attendu : md5")
    exiger(re.search(r"^hostssl\s+\S+\s+\S+\s+\S+\s+md5\s*$", lire(si, "db/pg_hba.conf"), re.M), "pg_hba.conf : méthode md5 attendue")


# --- Sauvegardes (QR-043, QR-044) ---


@controle("QR-043")
def _sauvegardes(si):
    script = lire(si, "scripts/backup.sh")
    exiger("--encrypt --recipient backup@lab.local" in script and "backup_pub.asc" in script, "backup.sh doit chiffrer avec la clé GPG")


@controle("QR-044")
def _cle_gpg(si):
    infos = lire_cle_publique(lire(si, "scripts/keys/backup_pub.asc"))
    exiger(infos.get("algorithme") == "RSA" and infos.get("taille") == 3072, "clé GPG RSA-3072 attendue")


# --- Code de l'API (QR-050 à QR-059) ---


@controle("QR-050")
def _argon2(si):
    exiger("PasswordHasher(time_cost=2, memory_cost=19456, parallelism=1)" in lire(si, "api/auth.py"), "Argon2id aux paramètres OWASP attendu")


@controle("QR-051")
def _code_mort(si):
    exiger("def hash_password_v1" in lire(si, "api/legacy_auth.py"), "hash_password_v1 attendue")
    for fichier in (si / "api").rglob("*.py"):
        if fichier.name != "legacy_auth.py":
            noms = imports(si, str(fichier.relative_to(si)))
            exiger(not any("legacy_auth" in n for n in noms), f"{fichier.name} ne doit pas importer legacy_auth")


@controle("QR-052")
def _jwt(si):
    exiger(env(si).get("JWT_ALGORITHM") == "HS256", "JWT_ALGORITHM attendu : HS256")
    exiger("HS256" not in lire(si, "api/tokens.py"), "l'algorithme JWT ne doit pas être écrit dans le code")


@controle("QR-054")
def _reset(si):
    texte = lire(si, "api/reset.py")
    exiger("random.choice(" in texte and "secrets" not in texte, "reset.py : random.choice attendu")


@controle("QR-055")
def _codes(si):
    exiger("random.SystemRandom()" in lire(si, "api/utils/codes.py"), "codes.py : SystemRandom attendu")


@controle("QR-056")
def _webhooks(si):
    texte = lire(si, "api/webhooks.py")
    exiger("hmac.new(" in texte and "== signature_recue" in texte and "compare_digest" not in texte, "webhooks.py : HMAC comparé avec == attendu")


@controle("QR-058")
def _sha256(si):
    exiger("hashlib.sha256(" in lire(si, "api/files.py"), "files.py : SHA-256 attendu")


@controle("QR-059")
def _md5(si):
    exiger("hashlib.md5(" in lire(si, "api/cache.py"), "cache.py : MD5 attendu")


# --- Dépendances (QR-060 à QR-064, QR-072) ---


def _declarees(si) -> set[str]:
    projet = tomllib.loads(lire(si, "api/pyproject.toml"))
    return {re.split(r"[<>=!~ ]", d)[0] for d in projet["project"]["dependencies"]}


def _verrouillees(si) -> set[str]:
    return {p["name"] for p in tomllib.loads(lire(si, "api/uv.lock"))["package"]}


@controle("QR-060", "QR-061", "QR-062", "QR-072")
def _bibliotheques(si):
    for nom in ("cryptography", "pyjwt", "argon2-cffi", "paramiko"):
        exiger(nom in _declarees(si) and nom in _verrouillees(si), f"{nom} doit être déclarée et verrouillée")
    exiger("paramiko" in imports(si, "scripts/deploy.py"), "deploy.py doit utiliser paramiko")


@controle("QR-063")
def _dependance_morte(si):
    exiger("pycryptodome==3.9.9" in lire(si, "api/pyproject.toml"), "pycryptodome 3.9.9 doit être déclaré")
    for fichier in si.rglob("*.py"):
        noms = imports(si, str(fichier.relative_to(si)))
        exiger(not any(n.split(".")[0] in {"Crypto", "Cryptodome"} for n in noms), f"{fichier.name} ne doit pas importer pycryptodome")


@controle("QR-064")
def _transitives(si):
    exiger({"pynacl", "bcrypt"} <= _verrouillees(si), "pynacl et bcrypt doivent être dans le verrou")
    exiger(not {"pynacl", "bcrypt"} & _declarees(si), "pynacl et bcrypt ne doivent pas être déclarées")


# --- Exécution ---

MARQUEURS_CRYPTO = ("-----BEGIN ", "ssh-ed25519 ", "ssh-rsa ", "ecdsa-sha2-", "ssh-dss ")
EXTENSIONS_CRYPTO = (".p12", ".pfx", ".key")


def verifier(si: Path, identifiants) -> dict[str, str | None]:
    """Applique le contrôle de chaque actif. Renvoie {QR: None si conforme, sinon le problème}."""
    resultats: dict[str, str | None] = {}
    for identifiant in identifiants:
        fonction = CONTROLES.get(identifiant)
        if fonction is None:
            resultats[identifiant] = "aucun contrôle écrit pour cet actif"
            continue
        try:
            fonction(Path(si))
            resultats[identifiant] = None
        except Exception as erreur:  # un contrôle qui plante est un écart, pas un crash
            resultats[identifiant] = f"{type(erreur).__name__} : {erreur}"
    return resultats


def fichiers_non_inventories(si: Path, emplacements: list[str]) -> list[str]:
    """Fichiers du SI contenant du matériel cryptographique mais cités par aucun actif.

    Un tel fichier ferait baisser à tort la précision des agents : ils le trouveraient,
    alors que la vérité terrain ne le connaît pas.
    """
    texte_emplacements = "\n".join(emplacements)
    oublies = []
    for fichier in sorted(Path(si).rglob("*")):
        if not fichier.is_file():
            continue
        relatif = fichier.relative_to(si).as_posix()
        contenu = fichier.read_bytes()
        cryptographique = relatif.endswith(EXTENSIONS_CRYPTO) or any(m.encode() in contenu for m in MARQUEURS_CRYPTO)
        if cryptographique and relatif.removesuffix(".pub") not in texte_emplacements:
            oublies.append(relatif)
    return oublies


def main(argv: list[str] | None = None) -> int:
    from quantum_ready.verite_terrain import charger_csv

    argv = sys.argv[1:] if argv is None else argv
    si = Path(argv[0] if argv else SI_PAR_DEFAUT)
    actifs = charger_csv(argv[1] if len(argv) > 1 else CSV_PAR_DEFAUT)
    resultats = verifier(si, [a.id for a in actifs])
    ecarts = {i: m for i, m in resultats.items() if m}
    for identifiant, message in ecarts.items():
        origine = " (étape PKI)" if identifiant in IDS_PKI else ""
        print(f"✗ {identifiant}{origine} : {message}")
    oublies = fichiers_non_inventories(si, [a.fichier for a in actifs])
    for chemin in oublies:
        print(f"✗ fichier cryptographique absent de la vérité terrain : {chemin}")
    print(f"{len(actifs) - len(ecarts)}/{len(actifs)} actifs conformes, {len(oublies)} fichier(s) en trop")
    return 1 if ecarts or oublies else 0


if __name__ == "__main__":
    raise SystemExit(main())
