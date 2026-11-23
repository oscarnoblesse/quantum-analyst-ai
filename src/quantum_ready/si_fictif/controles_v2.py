"""Contrôle de cohérence entre le SI v2 généré et sa vérité terrain (V2-001 à V2-100).

Même principe que ``controles`` (v1) : chaque actif a un contrôle qui vérifie, dans le SI
généré, que le fichier principal existe et que l'algorithme, la taille ou la valeur
annoncés y sont réellement présents. Les contrôles lisent les fichiers avec des
bibliothèques tierces (cryptography, tomllib, ast) ; ils n'utilisent pas les outils du
système évalué.

Utilisation : python -m quantum_ready.si_fictif.controles_v2 [dossier_si] [csv] [leurres]
"""

from __future__ import annotations

import ast
import base64
import csv
import re
import struct
import sys
import tomllib
import warnings
from collections.abc import Callable
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dh, ec, ed25519, padding, rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import ExtendedKeyUsageOID

from quantum_ready.si_fictif.controles import (
    EcartSI,
    certificat,
    certificats,
    cle_privee_pem,
    description_cle,
    duree_ans,
    exiger,
    imports,
    lire,
    meme_cle_publique,
    nom_signature,
    usages_etendus,
)
from quantum_ready.si_fictif.openpgp import lire_cle_publique

CSV_PAR_DEFAUT = "data/ground_truth/verite_terrain_v2.csv"
LEURRES_PAR_DEFAUT = "data/ground_truth/leurres_v2.csv"
SI_PAR_DEFAUT = "si/generated/v2"
SECRETS_PAR_DEFAUT = "si/generated/hors_si/v2/secrets.json"

Controle = Callable[[Path], None]
CONTROLES: dict[str, Controle] = {}

__all__ = ["CONTROLES", "EcartSI", "verifier", "fichiers_non_inventories", "main"]


def controle(*identifiants: str):
    def enregistrer(fonction: Controle) -> Controle:
        for identifiant in identifiants:
            CONTROLES[identifiant] = fonction
        return fonction

    return enregistrer


# --- Lecture ---


def entete_pem(type_: str) -> str:
    """« -----BEGIN <type>----- », construit ici pour que le code ne contienne aucun bloc
    ressemblant à une clé privée (faux positif de gitleaks)."""
    return "-" * 5 + f"BEGIN {type_}" + "-" * 5


def lignes_actives(si: Path, chemin: str, commentaire: str = "#") -> list[str]:
    """Lignes non vides et hors commentaire, sans espaces de bord."""
    resultat = []
    for ligne in lire(si, chemin).splitlines():
        ligne = ligne.strip()
        if ligne and not ligne.startswith(commentaire):
            resultat.append(ligne)
    return resultat


def directive(si: Path, chemin: str, nom: str, valeur: str, commentaire: str = "#") -> None:
    """Exige une ligne active « nom valeur » (séparateur : espaces, « = » ou « : »)."""
    motif = re.compile(rf"^{re.escape(nom)}\s*[=:]?\s*{re.escape(valeur)}\s*;?$")
    trouvees = [l for l in lignes_actives(si, chemin, commentaire) if l.startswith(nom)]
    exiger(any(motif.match(l) for l in trouvees),
           f"{chemin} : « {nom} {valeur} » attendu, trouvé {trouvees or 'rien'}")


def contient(si: Path, chemin: str, *fragments: str) -> str:
    texte = lire(si, chemin)
    for fragment in fragments:
        exiger(fragment in texte, f"{chemin} : « {fragment} » absent")
    return texte


def appels(si: Path, chemin: str) -> list[str]:
    """Appels de fonction d'un fichier Python, sous la forme « objet.attribut » ou « nom »."""
    noms = []
    for noeud in ast.walk(ast.parse(lire(si, chemin))):
        if isinstance(noeud, ast.Call):
            noms.append(ast.unparse(noeud.func))
    return noms


def secrets_hors_si(si: Path) -> dict[str, str]:
    import json

    chemin = Path(si).parent / "hors_si" / Path(si).name / "secrets.json"
    exiger(chemin.is_file(), f"secrets hors SI absents : {chemin}")
    return json.loads(chemin.read_text(encoding="utf-8"))


def env(si: Path, chemin: str) -> dict[str, str]:
    valeurs = {}
    for ligne in lignes_actives(si, chemin):
        nom, _, valeur = ligne.partition("=")
        valeurs[nom.strip()] = valeur.strip()
    return valeurs


def cle_ssh_publique(ligne: str):
    return serialization.load_ssh_public_key(" ".join(ligne.split()[:2]).encode())


def cle_ssh_privee(si: Path, chemin: str):
    fichier = si / chemin
    exiger(fichier.is_file(), f"clé absente : {chemin}")
    texte = fichier.read_bytes()
    exiger(b"BEGIN OPENSSH PRIVATE KEY" in texte, f"{chemin} : format OpenSSH attendu")
    return serialization.load_ssh_private_key(texte, password=None)


def non_chiffree(si: Path, chemin: str) -> None:
    exiger(b"ENCRYPTED" not in (si / chemin).read_bytes(), f"{chemin} : clé chiffrée, en clair attendu")


def droits_600(si: Path, chemin: str) -> None:
    if sys.platform != "win32":
        exiger(((si / chemin).stat().st_mode & 0o777) == 0o600, f"{chemin} : droits 600 attendus")


# --- PKI : V2-001 à V2-018 ---

RACINE = "pki/racine/ac-racine.pem"
EXPLOITATION = "pki/exploitation/ac-exploitation.pem"
SUIVI_CRT = "portail/tls/suivi.crt"
EDI_DER = "edi/certs/edi-douane.der"
CAMION_CRT = "flotte/certs/camion-0427.crt"
DOUANE_TXT = "edi/certs/procedure_douane.txt"


def edi(si: Path) -> x509.Certificate:
    fichier = si / EDI_DER
    exiger(fichier.is_file(), f"certificat absent : {EDI_DER}")
    exiger(not fichier.read_bytes().startswith(b"-----"), "edi-douane.der doit être en DER")
    return x509.load_der_x509_certificate(fichier.read_bytes())


def signe_par(cert: x509.Certificate, emetteur: x509.Certificate) -> None:
    exiger(cert.issuer == emetteur.subject, f"émetteur inattendu : {cert.issuer.rfc4514_string()}")
    cert.verify_directly_issued_by(emetteur)


@controle("V2-001")
def _cle_racine(si):
    exiger(description_cle(certificat(si, RACINE).public_key()) == "RSA-3072", "racine : RSA-3072 attendu")
    for copie in ("portail/tls/chaine.pem", "edi/certs/ca.pem"):
        exiger(certificat(si, RACINE) in certificats(si, copie), f"racine absente de {copie}")


@controle("V2-002")
def _signature_racine(si):
    racine = certificat(si, RACINE)
    exiger(nom_signature(racine) == "sha384WithRSAEncryption", nom_signature(racine))
    signe_par(racine, racine)


@controle("V2-003")
def _certificat_racine(si):
    racine = certificat(si, RACINE)
    exiger(racine.extensions.get_extension_for_class(x509.BasicConstraints).value.ca, "racine : CA attendue")
    exiger(19.9 < duree_ans(racine) < 20.1, f"racine : validité {duree_ans(racine):.1f} ans")


@controle("V2-004")
def _cle_exploitation(si):
    exiger(description_cle(certificat(si, EXPLOITATION).public_key()) == "ECDSA P-256", "AC exploitation : P-256")
    exiger(certificat(si, EXPLOITATION) in certificats(si, "portail/tls/chaine.pem"), "AC absente de chaine.pem")


@controle("V2-005")
def _signature_exploitation(si):
    ac = certificat(si, EXPLOITATION)
    exiger(nom_signature(ac) == "sha384WithRSAEncryption", nom_signature(ac))
    signe_par(ac, certificat(si, RACINE))


@controle("V2-006")
def _certificat_exploitation(si):
    ac = certificat(si, EXPLOITATION)
    exiger(ac.extensions.get_extension_for_class(x509.BasicConstraints).value.ca, "AC attendue")
    exiger(7.9 < duree_ans(ac) < 8.1, f"validité {duree_ans(ac):.1f} ans")


def _feuille(si, cert, algorithme_cle):
    exiger(description_cle(cert.public_key()) == algorithme_cle, f"{description_cle(cert.public_key())}")
    exiger(nom_signature(cert) == "ecdsa-with-SHA256", nom_signature(cert))
    signe_par(cert, certificat(si, EXPLOITATION))


controle("V2-007")(lambda si: exiger(description_cle(certificat(si, SUIVI_CRT).public_key()) == "RSA-2048",
                                    "portail : RSA-2048"))
controle("V2-008")(lambda si: _feuille(si, certificat(si, SUIVI_CRT), "RSA-2048"))


@controle("V2-009")
def _certificat_suivi(si):
    cert = certificat(si, SUIVI_CRT)
    exiger(cert.not_valid_after_utc - cert.not_valid_before_utc == __import__("datetime").timedelta(days=398),
           "portail : validité 398 jours")
    exiger(ExtendedKeyUsageOID.SERVER_AUTH in usages_etendus(cert), "serverAuth attendu")


controle("V2-010")(lambda si: exiger(description_cle(edi(si).public_key()) == "ECDSA P-384", "EDI : P-384"))
controle("V2-011")(lambda si: _feuille(si, edi(si), "ECDSA P-384"))
controle("V2-012")(lambda si: exiger(edi(si).subject.rfc4514_string().endswith("CN=edi.fret.lab.local")
                                     or "edi.fret.lab.local" in edi(si).subject.rfc4514_string(), "CN EDI"))
controle("V2-013")(lambda si: exiger(description_cle(certificat(si, CAMION_CRT).public_key()) == "Ed25519",
                                     "camion : Ed25519"))
controle("V2-014")(lambda si: _feuille(si, certificat(si, CAMION_CRT), "Ed25519"))


@controle("V2-015")
def _certificat_camion(si):
    cert = certificat(si, CAMION_CRT)
    exiger(ExtendedKeyUsageOID.CLIENT_AUTH in usages_etendus(cert), "clientAuth attendu")
    exiger(1.9 < duree_ans(cert) < 2.1, f"validité {duree_ans(cert):.1f} ans")


def douane(si):
    exiger(not DOUANE_TXT.endswith((".pem", ".crt")), "extension trompeuse attendue")
    texte = contient(si, DOUANE_TXT, "Procédure", "-----BEGIN CERTIFICATE-----")
    exiger(not texte.startswith("-----"), "le certificat doit être noyé dans du texte")
    (cert,) = certificats(si, DOUANE_TXT)
    return cert


controle("V2-016")(lambda si: exiger(description_cle(douane(si).public_key()) == "RSA-1024", "douane : RSA-1024"))


@controle("V2-017")
def _signature_douane(si):
    cert = douane(si)
    exiger(nom_signature(cert) == "sha1WithRSAEncryption", nom_signature(cert))
    # cryptography refuse de vérifier SHA-1 par verify_directly_issued_by : vérification RSA directe.
    exiger(cert.issuer == cert.subject, "auto-signé attendu")
    cert.public_key().verify(cert.signature, cert.tbs_certificate_bytes, padding.PKCS1v15(), hashes.SHA1())


@controle("V2-018")
def _certificat_douane(si):
    cert = douane(si)
    import datetime as dt

    age = (dt.datetime.now(dt.timezone.utc) - cert.not_valid_before_utc).days / 365
    exiger(13.9 < age < 14.2 and 19.9 < duree_ans(cert) < 20.1, f"douane : âge {age:.1f}, durée {duree_ans(cert):.1f}")


# --- nginx : V2-019 à V2-030 (sauf V2-026, SSH) ---

SUIVI_CONF = "portail/nginx/conf.d/suivi.conf"
EDI_CONF = "portail/nginx/conf.d/edi.conf"
COMMUN = "portail/nginx/snippets/tls-commun.conf"
TICKETS = "portail/nginx/snippets/tls-tickets.conf"


def _include_motif(si):
    directive(si, SUIVI_CONF, "include", "snippets/tls-*.conf")
    exiger("tls-commun" not in lire(si, SUIVI_CONF) and "tls-tickets" not in lire(si, SUIVI_CONF),
           "suivi.conf ne doit pas nommer les fichiers inclus")


controle("V2-019")(lambda si: directive(si, SUIVI_CONF, "ssl_protocols", "TLSv1.2 TLSv1.3"))
controle("V2-020")(lambda si: directive(si, SUIVI_CONF, "ssl_ecdh_curve", "X25519MLKEM768:X25519:prime256v1"))


@controle("V2-021")
def _suites_commun(si):
    _include_motif(si)
    directive(si, COMMUN, "ssl_ciphers", "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:DES-CBC3-SHA")


@controle("V2-022")
def _tickets(si):
    _include_motif(si)
    directive(si, TICKETS, "ssl_session_ticket_key", "/etc/nginx/tls/tickets.key")
    exiger(len((si / "portail/tls/tickets.key").read_bytes()) == 48, "tickets.key : 48 octets attendus")


@controle("V2-023")
def _dhparam(si):
    directive(si, SUIVI_CONF, "ssl_dhparam", "/etc/nginx/tls/dhparam-2048.pem")
    with warnings.catch_warnings():  # FFDH déprécié par cryptography : c'est l'actif contrôlé
        warnings.simplefilter("ignore")
        parametres = serialization.load_pem_parameters((si / "portail/tls/dhparam-2048.pem").read_bytes())
        bits = parametres.parameter_numbers().p.bit_length() if isinstance(parametres, dh.DHParameters) else 0
    exiger(bits == 2048, "DH 2048 attendu")


controle("V2-024")(lambda si: directive(si, EDI_CONF, "ssl_protocols", "TLSv1 TLSv1.1 TLSv1.2"))
controle("V2-025")(lambda si: directive(si, EDI_CONF, "ssl_ciphers", "ECDHE-ECDSA-AES128-SHA:ECDHE-ECDSA-RC4-SHA"))
controle("V2-027")(lambda si: directive(si, SUIVI_CONF, "proxy_ssl_ciphers", "ECDHE-ECDSA-AES256-GCM-SHA384"))
controle("V2-028")(lambda si: directive(si, EDI_CONF, "ssl_ecdh_curve", "secp384r1"))


@controle("V2-029")
def _echange_rsa(si):
    _suites_commun(si)
    exiger("TLSv1.2" in lire(si, SUIVI_CONF), "TLS 1.2 attendu")
    exiger(isinstance(certificat(si, SUIVI_CRT).public_key(), rsa.RSAPublicKey), "certificat RSA attendu")


controle("V2-030")(lambda si: directive(si, SUIVI_CONF, "ssl_conf_command",
                                        "Ciphersuites TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256"))


# --- SSH : V2-026, V2-031 à V2-043 ---

SSHD = "bastion/ssh/sshd_config"


def _include_sshd(si):
    directive(si, SSHD, "Include", "/etc/ssh/sshd_config.d/*.conf")


@controle("V2-026")
def _pubkey_rsa(si):
    _include_sshd(si)
    directive(si, "bastion/ssh/sshd_config.d/10-cles.conf", "PubkeyAcceptedAlgorithms", "+ssh-rsa")


controle("V2-031")(lambda si: directive(si, SSHD, "KexAlgorithms", "mlkem768x25519-sha256,sntrup761x25519-sha512"))
controle("V2-032")(lambda si: directive(si, SSHD, "Ciphers", "aes128-ctr,aes256-gcm@openssh.com,3des-cbc"))
controle("V2-033")(lambda si: directive(si, SSHD, "MACs", "hmac-sha1,hmac-sha2-256"))
controle("V2-034")(lambda si: directive(si, SSHD, "HostKeyAlgorithms", "ssh-rsa,ecdsa-sha2-nistp256,ssh-ed25519"))


def _cle_hote(type_, attendu):
    def verifier_cle(si):
        chemin = f"bastion/ssh/ssh_host_{type_}_key"
        cle = cle_ssh_privee(si, chemin)
        exiger(description_cle(cle) == attendu, f"{chemin} : {description_cle(cle)}")
        droits_600(si, chemin)
        exiger(meme_cle_publique(cle.public_key(), cle_ssh_publique(lire(si, chemin + ".pub"))), ".pub différent")

    return verifier_cle


controle("V2-035")(_cle_hote("ecdsa", "ECDSA P-256"))
controle("V2-036")(_cle_hote("rsa", "RSA-3072"))
controle("V2-037")(_cle_hote("ed25519", "Ed25519"))


@controle("V2-038")
def _authorized_keys(si):
    directive(si, SSHD, "AuthorizedKeysFile", "/etc/ssh/authorized_keys.d/%u")
    (ligne,) = lignes_actives(si, "bastion/ssh/authorized_keys.d/exploitation")
    exiger(ligne.startswith("ssh-rsa ") and description_cle(cle_ssh_publique(ligne)) == "RSA-1024", "ssh-rsa 1024")


@controle("V2-039")
def _match_prestataires(si):
    _include_sshd(si)
    lignes = lignes_actives(si, "bastion/ssh/sshd_config.d/50-prestataires.conf")
    exiger(lignes[0] == "Match Group prestataires", "bloc Match attendu en tête")
    exiger("Ciphers aes128-cbc,3des-cbc" in lignes[1:], "Ciphers du bloc Match")


@controle("V2-040")
def _known_hosts(si):
    (ligne,) = lignes_actives(si, "postes/chef-quai/.ssh/known_hosts")
    hotes, type_, cle = ligne.split()
    exiger(type_ == "ecdsa-sha2-nistp256", type_)
    attendue = cle_ssh_privee(si, "bastion/ssh/ssh_host_ecdsa_key").public_key()
    exiger(meme_cle_publique(cle_ssh_publique(f"{type_} {cle}"), attendue), "empreinte différente de V2-035")


@controle("V2-041")
def _cle_chef_quai(si):
    cle = cle_ssh_privee(si, "postes/chef-quai/.ssh/id_ecdsa")
    exiger(description_cle(cle) == "ECDSA P-384", description_cle(cle))


controle("V2-042")(lambda si: exiger(
    "Host routeur-quai" in lignes_actives(si, "depot/ssh/ssh_config")
    and "KexAlgorithms +diffie-hellman-group1-sha1" in lignes_actives(si, "depot/ssh/ssh_config"),
    "bloc Host routeur-quai avec KexAlgorithms +diffie-hellman-group1-sha1"))


@controle("V2-043")
def _dsa(si):
    chemin = "depot/ssh/id_dsa_routeur"
    exiger(lire(si, chemin).startswith(entete_pem("DSA PRIVATE KEY")), "PEM traditionnel DSA attendu")
    exiger(description_cle(cle_privee_pem(si, chemin)) == "DSA-1024", "DSA-1024 attendu")


# --- Code Python : V2-044 à V2-060 ---

SECURITE = "suivi/app/securite/"


@controle("V2-044")
def _pbkdf2(si):
    texte = contient(si, SECURITE + "mots_de_passe.py", 'pbkdf2_hmac("sha256"', "ITERATIONS = 100_000",
                     "os.urandom(16)")
    exiger("hashlib.pbkdf2_hmac" in appels(si, SECURITE + "mots_de_passe.py"), texte[:0] + "appel pbkdf2_hmac")


@controle("V2-045")
def _hs256(si):
    exiger("jwt" in imports(si, SECURITE + "jetons.py"), "import jwt")
    contient(si, SECURITE + "jetons.py", 'algorithm="HS256"')


@controle("V2-046")
def _cle_partenaire(si):
    module = ast.parse(lire(si, SECURITE + "cles_partenaires.py"))
    (affectation,) = [n for n in module.body if isinstance(n, ast.Assign)]
    cle = serialization.load_pem_public_key(ast.literal_eval(affectation.value).encode())
    exiger(description_cle(cle) == "RSA-2048", description_cle(cle))
    contient(si, SECURITE + "jetons.py", 'algorithms=["RS256"]', "CLE_PARTENAIRE_TRANSIT")


@controle("V2-047")
def _code_suivi(si):
    exiger("random.choices" in imports(si, "suivi/app/suivi_colis.py"), "from random import choices")
    contient(si, "suivi/app/suivi_colis.py", "choices as generer_code", "k=8")
    exiger("random" not in " ".join(appels(si, "suivi/app/suivi_colis.py")), "le mot random ne doit pas être appelé")


controle("V2-048")(lambda si: exiger("hashlib.md5" in appels(si, "suivi/app/integrite.py"), "hashlib.md5"))


@controle("V2-049")
def _webhook(si):
    contient(si, "suivi/app/integrite.py", '"empreinte": "sha1"', 'getattr(hashlib, PARAMETRES["empreinte"])')
    exiger("hmac.new" in appels(si, "suivi/app/integrite.py"), "hmac.new")


@controle("V2-050")
def _fernet(si):
    exiger("cryptography.fernet.Fernet" in imports(si, "suivi/app/chiffrement.py"), "Fernet importé")
    contient(si, "suivi/app/chiffrement.py", 'os.environ["CLE_ADRESSES"]')


@controle("V2-051")
def _cle_fernet(si):
    valeur = env(si, "suivi/.env")["CLE_ADRESSES"]
    exiger(len(base64.urlsafe_b64decode(valeur)) == 32, "clé Fernet de 32 octets")
    exiger("FERNET" not in lire(si, "suivi/.env").upper(), "le .env ne doit pas nommer Fernet")


@controle("V2-052")
def _client_tms(si):
    contient(si, "suivi/app/client_tms.py", "ssl.TLSVersion.TLSv1\n", 'set_ciphers("DEFAULT:@SECLEVEL=0")')


@controle("V2-053")
def _triple_des(si):
    contient(si, "suivi/app/anciens/export_v1.py", "algorithms.TripleDES", "modes.CBC")
    for fichier in (si / "suivi").rglob("*.py"):
        exiger("export_v1" not in fichier.read_text(encoding="utf-8") or fichier.name == "export_v1.py",
               f"export_v1 importé par {fichier}")


controle("V2-054")(lambda si: contient(si, SECURITE + "session.py", "secrets.token_urlsafe(32)"))
controle("V2-055")(lambda si: exiger("hashlib.sha384" in appels(si, SECURITE + "session.py"), "hashlib.sha384"))
controle("V2-056")(lambda si: contient(si, "lettres/signature/signer_cmr.py", "ec.ECDSA(hashes.SHA256())",
                                       "DUREE_CONSERVATION_ANS = 10"))
controle("V2-057")(lambda si: contient(si, "lettres/signature/verifier_partenaire.py", "padding.PKCS1v15()",
                                       "hashes.SHA1()"))
controle("V2-058")(lambda si: contient(si, "lettres/signature/horodatage.py", 'ALGOS = {"horodatage": "sha1"}',
                                       'hashlib.new(ALGOS["horodatage"]'))


@controle("V2-059")
def _aes256(si):
    contient(si, "lettres/archivage.py", "algorithms.AES(cle)", "modes.CBC(iv)", "len(cle) != 32")


controle("V2-060")(lambda si: exiger("X25519PrivateKey.generate" in appels(si, "suivi/app/client_tms.py"),
                                     "X25519PrivateKey.generate"))


# --- Dépendances : V2-061 à V2-066 ---


def projet(si):
    return tomllib.loads(lire(si, "suivi/pyproject.toml"))


def verrou(si) -> dict[str, str]:
    donnees = tomllib.loads(lire(si, "suivi/uv.lock"))
    return {p["name"]: p["version"] for p in donnees["package"]}


controle("V2-061")(lambda si: exiger("cryptography==41.0.7" in projet(si)["project"]["dependencies"], "cryptography"))
controle("V2-062")(lambda si: exiger("PyJWT==2.8.0" in projet(si)["project"]["dependencies"], "PyJWT"))
controle("V2-063")(lambda si: exiger("pycryptodome==3.9.9" in lignes_actives(si, "lettres/requirements.txt"), "pycryptodome"))
controle("V2-064")(lambda si: exiger("python-gnupg==0.4.9" in lignes_actives(si, "lettres/requirements.txt"),
                                     "python-gnupg"))


@controle("V2-065")
def _paramiko(si):
    exiger(not any(d.lower().startswith("paramiko") for d in projet(si)["project"]["dependencies"]),
           "paramiko ne doit pas être déclaré")
    exiger(verrou(si).get("paramiko") == "2.12.0", "paramiko 2.12.0 dans uv.lock")
    exiger("fabric==2.7.1" in projet(si)["project"]["dependencies"], "fabric déclaré")


@controle("V2-066")
def _pyopenssl(si):
    donnees = projet(si)
    exiger("pyopenssl" in donnees["project"]["dependencies"], "pyopenssl déclaré sans version")
    exiger(donnees["tool"]["uv"]["constraint-dependencies"] == ["pyopenssl==23.2.0"], "contrainte uv")
    exiger(verrou(si).get("pyopenssl") == "23.2.0", "pyopenssl 23.2.0 dans uv.lock")


# --- PKCS#12 et clés : V2-067 à V2-072 ---


@controle("V2-067")
def _cle_suivi(si):
    chemin = "portail/tls/suivi.key"
    cle = cle_privee_pem(si, chemin)
    exiger(description_cle(cle) == "RSA-2048", description_cle(cle))
    exiger(meme_cle_publique(cle.public_key(), certificat(si, SUIVI_CRT).public_key()), "clé ≠ certificat")
    non_chiffree(si, chemin)
    droits_600(si, chemin)


@controle("V2-068")
def _p12(si):
    donnees = (si / "edi/certs/edi-douane.p12").read_bytes()
    # OID PBES2 (1.2.840.113549.1.5.13) et AES-256-CBC (2.16.840.1.101.3.4.1.42), en DER.
    exiger(bytes.fromhex("06092a864886f70d01050d") in donnees, "PBES2 attendu")
    exiger(bytes.fromhex("060960864801650304012a") in donnees, "AES-256-CBC attendu")
    mot_de_passe = secrets_hors_si(si)["EDI_CONTENEUR_SECRET"].encode()
    cle, cert, _ = pkcs12.load_key_and_certificates(donnees, mot_de_passe)
    exiger(description_cle(cle) == "ECDSA P-384" and cert == edi(si), "contenu du PKCS#12")


@controle("V2-069")
def _mot_de_passe_p12(si):
    valeur = env(si, "edi/.env")["EDI_CONTENEUR_SECRET"]
    pkcs12.load_key_and_certificates((si / "edi/certs/edi-douane.p12").read_bytes(), valeur.encode())
    exiger(".p12" not in lire(si, "edi/.env"), "le .env ne doit pas nommer le conteneur")


@controle("V2-070")
def _cle_camion(si):
    cle = cle_privee_pem(si, "flotte/certs/camion-0427.key")
    exiger(isinstance(cle, ed25519.Ed25519PrivateKey), "Ed25519 attendu")
    exiger(meme_cle_publique(cle.public_key(), certificat(si, CAMION_CRT).public_key()), "clé ≠ certificat")
    contient(si, "flotte/certs/camion-0427.key", entete_pem("PRIVATE KEY"))


@controle("V2-071")
def _cle_cmr(si):
    chemin = "lettres/cles/signature-cmr.pem"
    contient(si, chemin, entete_pem("ENCRYPTED PRIVATE KEY"))
    cle = cle_privee_pem(si, chemin, secrets_hors_si(si)["PHRASE_CLE_CMR"].encode())
    exiger(description_cle(cle) == "ECDSA P-256", description_cle(cle))


@controle("V2-072")
def _cle_ac_oubliee(si):
    chemin = "sauvegardes/2021/exploitation.bak"
    cle = cle_privee_pem(si, chemin)
    exiger(isinstance(cle, ec.EllipticCurvePrivateKey), "clé EC attendue")
    exiger(meme_cle_publique(cle.public_key(), certificat(si, EXPLOITATION).public_key()), "≠ AC d'exploitation")
    non_chiffree(si, chemin)


# --- OpenPGP, scripts, .env : V2-073 à V2-080 ---


def cle_openpgp(si, chemin) -> dict:
    """Algorithme (numéro OpenPGP) et taille (bits du premier MPI) du paquet de clé publique."""
    texte = lire(si, chemin)
    exiger(texte.startswith("-----BEGIN PGP PUBLIC KEY BLOCK-----"), "armure OpenPGP attendue")
    corps = "".join(l for l in texte.strip().splitlines()[2:-1] if not l.startswith("="))
    donnees = base64.b64decode(corps)
    exiger(donnees[0] & 0x3F == 6, "paquet de clé publique attendu en tête")
    debut = 2 if donnees[1] < 192 else 3
    paquet = donnees[debut:]
    algorithme = paquet[5]
    if algorithme == 22:  # EdDSA : OID de courbe, puis MPI 0x40 || point
        longueur_oid = paquet[6]
        return {"algorithme": "EdDSA", "oid": paquet[7:7 + longueur_oid].hex(),
                "bits": struct.unpack(">H", paquet[7 + longueur_oid:9 + longueur_oid])[0]}
    return {"algorithme": lire_cle_publique(texte)["algorithme"], "bits": lire_cle_publique(texte)["taille"]}


controle("V2-073")(lambda si: exiger(cle_openpgp(si, "exploitation/gpg/sauvegarde_pub.asc")
                                     == {"algorithme": "RSA", "bits": 3072}, "RSA-3072 attendu"))
controle("V2-074")(lambda si: exiger(cle_openpgp(si, "exploitation/gpg/partenaires/douane.asc")
                                     == {"algorithme": "EdDSA", "oid": "2b06010401da470f01", "bits": 263},
                                     "EdDSA Ed25519 attendu"))
controle("V2-075")(lambda si: contient(si, "exploitation/scripts/sauvegarde.sh", "gpg --batch --symmetric --cipher-algo CAST5",
                                       "conservée 7 ans"))
controle("V2-076")(lambda si: contient(si, "exploitation/scripts/export_partenaires.sh",
                                       "openssl enc -aes-128-cbc -md md5"))
controle("V2-077")(lambda si: contient(si, "exploitation/scripts/renouveler_certs.sh",
                                       "openssl req -new -newkey rsa:2048"))
controle("V2-078")(lambda si: contient(si, "exploitation/scripts/rotation_cles_ssh.sh", "ssh-keygen -q -t ecdsa -b 256"))


@controle("V2-079")
def _secret_jwt(si):
    exiger(len(env(si, "suivi/.env")["JWT_SECRET"]) == 16, "secret JWT de 16 caractères")


@controle("V2-080")
def _digest_sha1(si):
    texte = contient(si, "exploitation/scripts/renouveler_certs.sh", '-"${DIGEST:-sha1}"')
    exiger(not re.search(r"^\s*(export\s+)?DIGEST=", texte, re.M), "DIGEST ne doit pas être affecté")


# --- Hors périmètre : V2-081 à V2-100 ---

JAVA = "flotte/passerelle-java/src/main/"


@controle("V2-081")
def _jks(si):
    donnees = (si / (JAVA + "resources/keystore.jks")).read_bytes()
    exiger(donnees[:8] == bytes.fromhex("feedfeed00000002"), "en-tête JKS version 2 attendu")
    directive(si, JAVA + "resources/application.properties", "server.ssl.key-store-type", "JKS")
    # La clé est protégée : on lit la taille sur le premier certificat de la chaîne.
    debut = donnees.index(bytes.fromhex("0005582e353039")) + 7  # « X.509 » au format UTF Java
    longueur = struct.unpack(">I", donnees[debut:debut + 4])[0]
    cert = x509.load_der_x509_certificate(donnees[debut + 4:debut + 4 + longueur])
    exiger(description_cle(cert.public_key()) == "RSA-2048", description_cle(cert.public_key()))


@controle("V2-082")
def _mot_de_passe_jks(si):
    directive(si, JAVA + "resources/application-prod.properties", "server.ssl.key-store-password",
              secrets_hors_si(si)["MOT_DE_PASSE_KEYSTORE"])
    exiger("password" not in lire(si, JAVA + "resources/application.properties"), "mot de passe hors du profil prod")


controle("V2-083")(lambda si: contient(si, JAVA + "java/lab/fret/passerelle/Chiffrement.java",
                                       'Cipher.getInstance("AES/ECB/PKCS5Padding")', "cle.length != 16"))


@controle("V2-084")
def _sha1_java(si):
    contient(si, JAVA + "java/lab/fret/passerelle/Empreinte.java", 'MessageDigest.getInstance("SHA-1")')
    for fichier in (si / JAVA).rglob("*.java"):
        if fichier.name != "Empreinte.java":
            exiger("Empreinte" not in fichier.read_text(encoding="utf-8"), f"Empreinte appelée dans {fichier.name}")


controle("V2-085")(lambda si: contient(si, "flotte/collecteur-go/signature.go", "rsa.GenerateKey(rand.Reader, 2048)",
                                       "rsa.SignPKCS1v15(rand.Reader, cleCollecteur, crypto.SHA256"))
controle("V2-086")(lambda si: exiger(lire(si, "flotte/collecteur-go/tls_ancien.go").startswith("//go:build legacy")
                                     and "tls.VersionTLS10" in lire(si, "flotte/collecteur-go/tls_ancien.go"),
                                     "//go:build legacy et TLS 1.0"))
controle("V2-087")(lambda si: contient(si, "portail-client/serveur/chiffrer.js", "createCipheriv('aes-128-cbc'",
                                       "Buffer.alloc(16, 0)"))
controle("V2-088")(lambda si: contient(si, "portail-client/serveur/jeton.js", "createHash('md5')"))


@controle("V2-089")
def _haproxy(si):
    lignes = lignes_actives(si, "lb/haproxy/haproxy.cfg")
    exiger("ssl-default-bind-ciphers ECDHE-RSA-AES256-GCM-SHA384:AES128-SHA" in lignes, "suites globales")
    exiger(lignes.index("global") < lignes.index("ssl-default-bind-ciphers ECDHE-RSA-AES256-GCM-SHA384:AES128-SHA")
           < lignes.index("defaults"), "dans la section global")
    exiger(not any(l.startswith("bind") and "ciphers" in l for l in lignes), "aucune suite sur bind")


@controle("V2-090")
def _openssl_cnf(si):
    directive(si, "portail/nginx/environnement", "OPENSSL_CONF", "/etc/nginx/openssl/openssl.cnf")
    directive(si, "portail/openssl/openssl.cnf", "Ciphersuites", "TLS_AES_128_GCM_SHA256")
    exiger("ssl_conf_command" not in lire(si, EDI_CONF), "le point EDI ne doit pas redéfinir les suites TLS 1.3")


controle("V2-091")(lambda si: directive(si, "vpn/ipsec.conf", "ike", "aes128-sha1-modp1024!"))
controle("V2-092")(lambda si: directive(si, "vpn/ipsec.conf", "esp", "3des-md5!"))
controle("V2-093")(lambda si: exiger(
    lignes_actives(si, "vpn/ipsec.secrets")[0].endswith(f'PSK "{secrets_hors_si(si)["PSK_IPSEC"]}"'), "PSK"))


@controle("V2-094")
def _wireguard(si):
    valeur = env(si, "vpn/wg0.conf")["PrivateKey"]
    exiger(len(base64.b64decode(valeur)) == 32, "clé X25519 de 32 octets")
    exiger("PresharedKey" not in lire(si, "vpn/wg0.conf"), "aucune PresharedKey")


controle("V2-095")(lambda si: exiger("cipher BF-CBC" in lignes_actives(si, "vpn/agences.ovpn"), "cipher BF-CBC"))


@controle("V2-096")
def _tls_auth(si):
    texte = lire(si, "vpn/agences.ovpn")
    bloc = texte.split("<tls-auth>")[1].split("</tls-auth>")[0]
    hexa = "".join(l for l in bloc.splitlines() if re.fullmatch(r"[0-9a-f]{32}", l))
    exiger("-----BEGIN OpenVPN Static key V1-----" in bloc and len(hexa) * 4 == 2048, "clé statique de 2048 bits")


@controle("V2-097")
def _terraform(si):
    contient(si, "deploiement/terraform/modules/vpn/main.tf", "algorithm = var.algorithme_cle")
    contient(si, "deploiement/terraform/modules/vpn/variables.tf", 'default     = "RSA"', "default     = 2048")
    exiger("algorithme_cle" not in lire(si, "deploiement/terraform/main.tf"), "aucune surcharge dans le module racine")


@controle("V2-098")
def _saml(si):
    texte = lire(si, "sso/metadata/idp-metadata.xml")
    corps = texte.split("<ds:X509Certificate>")[1].split("</ds:X509Certificate>")[0]
    cert = x509.load_der_x509_certificate(base64.b64decode("".join(corps.split())))
    exiger(description_cle(cert.public_key()) == "RSA-2048" and nom_signature(cert) == "sha256WithRSAEncryption",
           "SAML : RSA-2048, sha256WithRSAEncryption")


@controle("V2-099")
def _dnskey(si):
    (ligne,) = [l for l in lignes_actives(si, "dns/zones/db.fret.lab.local", ";") if "DNSKEY" in l]
    champs = ligne.split()
    exiger(champs[3:6] == ["257", "3", "8"], f"DNSKEY 257 3 8 attendu : {champs[3:6]}")
    brute = base64.b64decode(champs[6])
    longueur_exposant = brute[0]
    module = brute[1 + longueur_exposant:]
    exiger(int.from_bytes(module, "big").bit_length() == 2048, "RSA-2048 attendu")


controle("V2-100")(lambda si: directive(si, "messagerie/postfix/main.cf", "smtpd_tls_mandatory_protocols",
                                        "!SSLv2, !SSLv3"))


# --- Exécution ---

MARQUEURS_CRYPTO = ("-----BEGIN ", "ssh-ed25519 ", "ssh-rsa ", "ecdsa-sha2-", "ssh-dss ")
EXTENSIONS_CRYPTO = (".p12", ".pfx", ".key", ".jks", ".der", ".asc")


def verifier(si: Path, identifiants) -> dict[str, str | None]:
    """Applique le contrôle de chaque actif. Renvoie {ID: None si conforme, sinon le problème}."""
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


def fichiers_non_inventories(si: Path, references: list[str]) -> list[str]:
    """Fichiers contenant du matériel cryptographique cités ni par un actif (fichier ou notes)
    ni par un leurre : ils fausseraient la précision mesurée."""
    texte = "\n".join(references)
    oublies = []
    for fichier in sorted(Path(si).rglob("*")):
        if not fichier.is_file():
            continue
        relatif = fichier.relative_to(si).as_posix()
        contenu = fichier.read_bytes()
        cryptographique = relatif.endswith(EXTENSIONS_CRYPTO) or any(m.encode() in contenu for m in MARQUEURS_CRYPTO)
        if cryptographique and relatif.removesuffix(".pub") not in texte:
            oublies.append(relatif)
    return oublies


def charger_leurres(chemin: str | Path) -> list[dict[str, str]]:
    with open(chemin, encoding="utf-8", newline="") as fichier:
        return list(csv.DictReader(fichier))


def main(argv: list[str] | None = None) -> int:
    from quantum_ready.verite_terrain import charger_csv

    argv = sys.argv[1:] if argv is None else argv
    si = Path(argv[0] if argv else SI_PAR_DEFAUT)
    actifs = charger_csv(argv[1] if len(argv) > 1 else CSV_PAR_DEFAUT)
    leurres = charger_leurres(argv[2] if len(argv) > 2 else LEURRES_PAR_DEFAUT)
    resultats = verifier(si, [a.id for a in actifs])
    ecarts = {i: m for i, m in resultats.items() if m}
    for identifiant, message in ecarts.items():
        print(f"✗ {identifiant} : {message}")
    references = [f"{a.fichier}\n{a.notes}" for a in actifs] + [l["Fichier / emplacement"] for l in leurres]
    oublies = fichiers_non_inventories(si, references)
    for chemin in oublies:
        print(f"✗ fichier cryptographique absent de la vérité terrain et des leurres : {chemin}")
    print(f"{len(actifs) - len(ecarts)}/{len(actifs)} actifs conformes, {len(oublies)} fichier(s) en trop")
    return 1 if ecarts or oublies else 0


if __name__ == "__main__":
    raise SystemExit(main())
