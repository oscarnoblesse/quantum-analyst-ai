"""Outil lister_fichiers : la carte du SI, pour que l'agent planifie ses analyses.

La nature d'un fichier est reconnue d'après son CONTENU et non d'après son nom ou
son extension : dans un vrai SI, une clé privée peut s'appeler « backup.txt » et
une seconde variante du SI n'aura pas les mêmes noms de fichiers.
"""

from __future__ import annotations

import re
from pathlib import Path

from quantum_ready.outils.commun import FichierSI, Resultat, outil, relatif, resoudre

NOM = "lister_fichiers"
TAILLE_LUE = 8192
DOSSIERS_IGNORES = {".git", "__pycache__", ".venv", "node_modules"}

# nature reconnue -> outil à appeler ensuite
OUTILS = {
    "certificats_pem": "analyser_x509",
    "certificat_der": "analyser_x509",
    "cle_privee_pem": "analyser_cle",
    "cle_privee_openssh": "analyser_cle",
    "cles_publiques_ssh": "analyser_cle",
    "cle_openpgp": "analyser_cle",
    "parametres_dh": "analyser_cle",
    "pkcs12": "analyser_pkcs12",
    "config_nginx": "analyser_configuration",
    "config_sshd": "analyser_configuration",
    "config_postgresql": "analyser_configuration",
    "config_pg_hba": "analyser_configuration",
    "variables_env": "analyser_configuration",
    "dockerfile": "analyser_configuration",
    "script_shell": "analyser_configuration",
    "code_python": "scanner_code_crypto",
    "pyproject": "analyser_dependances",
    "verrou_uv": "analyser_dependances",
}

_SSH_PUBLIQUE = re.compile(r"^(\S+\s+)?(ssh-(rsa|dss|ed25519)|ecdsa-sha2-nistp\d+|sk-\S+)\s+AAAA", re.M)
_DIRECTIVE_SSHD = re.compile(r"^\s*(KexAlgorithms|HostKey|PermitRootLogin|PasswordAuthentication|Ciphers|MACs)\b", re.M)
_DIRECTIVE_PG = re.compile(r"^\s*(listen_addresses|password_encryption|ssl_cert_file|shared_buffers|ssl_min_protocol_version)\s*=", re.M)
_LIGNE_HBA = re.compile(r"^\s*(local|host|hostssl|hostnossl|hostgssenc)\s+\S+\s+\S+", re.M)
_LIGNE_ENV = re.compile(r"^[A-Z][A-Z0-9_]*=", re.M)


def reconnaitre(contenu: bytes) -> str:
    """Nature d'un fichier d'après ses premiers octets."""
    if contenu.startswith(b"\x30\x82") or contenu.startswith(b"\x30\x80"):
        # Une structure DER : PKCS#12 ou certificat. On essaie les deux.
        from asn1crypto import pkcs12, x509

        try:
            pkcs12.Pfx.load(contenu)["auth_safe"]["content_type"].native
            return "pkcs12"
        except Exception:
            pass
        try:
            x509.Certificate.load(contenu).subject
            return "certificat_der"
        except Exception:
            return "binaire_der"
    try:
        texte = contenu.decode("utf-8")
    except UnicodeDecodeError:
        return "binaire"
    if "-----BEGIN CERTIFICATE-----" in texte:
        return "certificats_pem"
    if "-----BEGIN OPENSSH PRIVATE KEY-----" in texte:
        return "cle_privee_openssh"
    if re.search(r"-----BEGIN [A-Z ]*PRIVATE KEY-----", texte):
        return "cle_privee_pem"
    if "-----BEGIN PGP " in texte:
        return "cle_openpgp"
    if "-----BEGIN DH PARAMETERS-----" in texte:
        return "parametres_dh"
    if _SSH_PUBLIQUE.search(texte):
        return "cles_publiques_ssh"
    premiere = texte.lstrip().splitlines()[0] if texte.strip() else ""
    if premiere.startswith("#!") and ("sh" in premiere.split("/")[-1]):
        return "script_shell"
    if premiere.startswith("#!") and "python" in premiere:
        return "code_python"
    if re.search(r"^\s*FROM\s+\S+", texte, re.M) and re.search(r"^\s*(RUN|CMD|COPY)\s", texte, re.M):
        return "dockerfile"
    if re.search(r"^\[\[package\]\]", texte, re.M) and "version = " in texte:
        return "verrou_uv"
    if re.search(r"^\[project\]", texte, re.M):
        return "pyproject"
    if re.search(r"\bserver\s*\{", texte) or re.search(r"^\s*ssl_certificate\s", texte, re.M):
        return "config_nginx"
    if _DIRECTIVE_SSHD.search(texte):
        return "config_sshd"
    if _DIRECTIVE_PG.search(texte):
        return "config_postgresql"
    if _LIGNE_HBA.search(texte):
        return "config_pg_hba"
    if re.search(r"^\s*(import|from)\s+\w+|^\s*def\s+\w+\(", texte, re.M) or texte.lstrip().startswith('"""'):
        return "code_python"
    lignes = [l for l in texte.splitlines() if l.strip() and not l.lstrip().startswith("#")]
    if lignes and sum(bool(_LIGNE_ENV.match(l)) for l in lignes) >= max(1, len(lignes) // 2):
        return "variables_env"
    if not texte.strip():
        return "vide"
    return "texte"


@outil(NOM)
def lister_fichiers(cible: str, racine: Path) -> Resultat:
    """Liste les fichiers d'un dossier du SI (récursivement), avec leur nature et l'outil conseillé."""
    dossier = resoudre(cible or ".", racine)
    if dossier.is_file():
        chemins = [dossier]
    else:
        chemins = sorted(
            p for p in dossier.rglob("*")
            if p.is_file() and not DOSSIERS_IGNORES.intersection(p.relative_to(racine).parts)
        )
    fichiers = []
    for chemin in chemins:
        if not chemin.resolve().is_relative_to(racine):  # lien symbolique vers l'extérieur
            continue
        with chemin.open("rb") as flux:
            nature = reconnaitre(flux.read(TAILLE_LUE))
        fichiers.append(
            FichierSI(
                chemin=relatif(chemin, racine),
                taille=chemin.stat().st_size,
                droits=oct(chemin.stat().st_mode & 0o777)[2:],
                nature=nature,
                outil_conseille=OUTILS.get(nature),
            )
        )
    return Resultat(outil=NOM, cible=cible, fichiers=fichiers)
