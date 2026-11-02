"""Outil lister_fichiers : la carte du SI, pour que l'agent planifie ses analyses.

La nature d'un fichier est reconnue d'après son CONTENU : dans un vrai SI, une
clé privée peut s'appeler « backup.txt ». L'extension n'est utilisée que pour le
code source, où elle est fiable et où le contenu est ambigu (« import x » est du
Python comme du Java).

Quand aucun analyseur dédié ne sait lire un format (Java, YAML inconnu, Postfix...),
l'outil le DIT et conseille rechercher_algorithmes, une détection textuelle de
repli : un angle mort signalé vaut mieux qu'un silence.
"""

from __future__ import annotations

import re
from pathlib import Path

from quantum_ready.outils.commun import FichierSI, Resultat, outil, relatif, resoudre

NOM = "lister_fichiers"
TAILLE_LUE = 8192
TAILLE_MAX_DER = 1_000_000  # une structure DER doit être lue en entier pour être reconnue
DOSSIERS_IGNORES = {".git", "__pycache__", ".venv", "node_modules"}
REPLI = "rechercher_algorithmes"

# nature reconnue -> outil dédié
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
    "config_apache": "analyser_configuration",
    "config_sshd": "analyser_configuration",
    "config_postgresql": "analyser_configuration",
    "config_pg_hba": "analyser_configuration",
    "variables_env": "analyser_configuration",
    "yaml": "analyser_configuration",
    "json": "analyser_configuration",
    "dockerfile": "analyser_configuration",
    "script_shell": "analyser_configuration",
    "code_python": "scanner_code_crypto",
    "pyproject": "analyser_dependances",
    "verrou_uv": "analyser_dependances",
    "verrou_poetry": "analyser_dependances",
    "requirements": "analyser_dependances",
}
# Code source : extension -> nature. Seul Python a un analyseur dédié.
LANGAGES = {
    ".py": "code_python", ".java": "code_java", ".kt": "code_kotlin", ".go": "code_go", ".js": "code_javascript",
    ".mjs": "code_javascript", ".ts": "code_typescript", ".php": "code_php", ".rb": "code_ruby", ".rs": "code_rust",
    ".c": "code_c", ".h": "code_c", ".cpp": "code_cpp", ".cs": "code_csharp", ".swift": "code_swift",
}
SANS_INTERET = {"vide", "binaire", "binaire_der"}

_SSH_PUBLIQUE = re.compile(r"^(\S+\s+)?(ssh-(rsa|dss|ed25519)|ecdsa-sha2-nistp\d+|sk-\S+)\s+AAAA", re.M)
_DIRECTIVE_SSHD = re.compile(
    r"^\s*(KexAlgorithms|HostKey|HostKeyAlgorithms|PermitRootLogin|PasswordAuthentication|Ciphers|MACs|"
    r"PubkeyAuthentication|PubkeyAcceptedAlgorithms|UsePAM|ListenAddress|AuthorizedKeysFile|Port|Protocol|X11Forwarding|"
    r"MaxAuthTries|ClientAliveInterval|ChallengeResponseAuthentication|KbdInteractiveAuthentication|Subsystem|AllowUsers)\s", re.M | re.I)
_DIRECTIVE_PG = re.compile(r"^\s*(listen_addresses|password_encryption|ssl_cert_file|shared_buffers|ssl_min_protocol_version|max_connections)\s*=", re.M)
_LIGNE_HBA = re.compile(r"^\s*(local|host|hostssl|hostnossl|hostgssenc)\s+\S+\s+\S+", re.M)
_LIGNE_ENV = re.compile(r"^(export\s+)?[A-Za-z_][A-Za-z0-9_]*=", re.M)
_DIRECTIVE_NGINX = re.compile(r"^\s*(ssl_\w+|server_name|listen|proxy_pass|include)\s+[^;{}]+;", re.M)
_DIRECTIVE_APACHE = re.compile(r"^\s*(<VirtualHost|SSLEngine|SSLProtocol|SSLCipherSuite|SSLCertificateFile)\b", re.M | re.I)
_EXIGENCE = re.compile(r"^\s*[A-Za-z0-9][A-Za-z0-9_.\-]*(\[[^\]]+\])?\s*(==|>=|<=|~=|!=|>|<)\s*[\w.*]+", re.M)


def _der(contenu: bytes) -> str:
    """Certificat ou PKCS#12 ? Le certificat est essayé d'abord, le PKCS#12 vérifié strictement."""
    from cryptography import x509 as x509_cryptography

    try:
        x509_cryptography.load_der_x509_certificate(contenu)
        return "certificat_der"
    except ValueError:
        pass
    from asn1crypto import pkcs12

    try:
        pfx = pkcs12.Pfx.load(contenu, strict=True)
        if pfx["version"].native == "v3" and pfx["auth_safe"]["content_type"].native in ("data", "signed_data"):
            list(pfx.authenticated_safe)  # force la lecture complète
            return "pkcs12"
    except Exception:
        pass
    return "binaire_der"


def _texte(texte: str) -> str:
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
    if premiere.startswith("#!"):
        if re.search(r"\b(ba|z|k|da)?sh\b", premiere):
            return "script_shell"
        if "python" in premiere:
            return "code_python"
    if re.search(r"^\s*FROM\s+\S+", texte, re.M | re.I) and re.search(r"^\s*(RUN|CMD|COPY|ENTRYPOINT)\s", texte, re.M | re.I):
        return "dockerfile"
    if re.search(r"^\[\[package\]\]", texte, re.M) and re.search(r"^version = ", texte, re.M):
        return "verrou_poetry" if "[metadata]" in texte and "content-hash" in texte else "verrou_uv"
    if re.search(r"^\[(project|tool\.poetry)\]", texte, re.M):
        return "pyproject"
    if _DIRECTIVE_APACHE.search(texte):
        return "config_apache"
    if re.search(r"\b(server|http|stream)\s*\{", texte) or len(_DIRECTIVE_NGINX.findall(texte)) >= 2 or re.search(r"^\s*ssl_\w+\s+[^;]+;", texte, re.M):
        return "config_nginx"
    if len(_DIRECTIVE_SSHD.findall(texte)) >= 2 or re.search(r"^\s*(KexAlgorithms|HostKey)\s", texte, re.M):
        return "config_sshd"
    if _DIRECTIVE_PG.search(texte):
        return "config_postgresql"
    if _LIGNE_HBA.search(texte):
        return "config_pg_hba"
    lignes = [l for l in texte.splitlines() if l.strip() and not l.lstrip().startswith("#")]
    if lignes and sum(bool(_EXIGENCE.match(l)) for l in lignes) >= max(1, len(lignes) * 2 // 3):
        return "requirements"
    if texte.lstrip().startswith(("{", "[")):
        try:
            import json

            json.loads(texte)
            return "json"
        except ValueError:
            pass
    if lignes and sum(bool(_LIGNE_ENV.match(l)) for l in lignes) >= max(1, len(lignes) * 2 // 3):
        return "variables_env"
    if lignes and sum(bool(re.match(r"^\s*(- )?[\w.\-\"']+\s*:(\s|$)", l)) or l.lstrip().startswith("- ") for l in lignes) >= max(1, len(lignes) * 2 // 3):
        return "yaml"
    if not texte.strip():
        return "vide"
    return "texte"


def reconnaitre(contenu: bytes, nom: str = "") -> str:
    """Nature d'un fichier d'après son contenu (et son extension pour le code source)."""
    if contenu[:1] == b"\x30" and contenu[1:2] in (b"\x80", b"\x81", b"\x82", b"\x83"):
        return _der(contenu)
    try:
        texte = contenu.decode("utf-8")
    except UnicodeDecodeError:
        return "binaire"
    nature = _texte(texte)
    extension = Path(nom).suffix.lower()
    if extension in LANGAGES and nature in ("texte", "variables_env", "yaml", "code_python", "config_nginx", "config_sshd"):
        return LANGAGES[extension]
    if nature == "texte" and re.search(r"^\s*(import|from)\s+[\w.]+(\s+import\s+\w+)?\s*$|^\s*def\s+\w+\(.*\)\s*:", texte, re.M) and ";" not in texte:
        return "code_python"
    return nature


def remarque(nature: str) -> str | None:
    if nature in OUTILS or nature in SANS_INTERET:
        return None
    if nature.startswith("code_"):
        return f"aucun analyseur dédié pour ce langage ({nature[5:]}) : détection textuelle seulement"
    return "format sans analyseur dédié : détection textuelle seulement"


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
        taille = chemin.stat().st_size
        with chemin.open("rb") as flux:
            debut = flux.read(TAILLE_LUE)
            if debut[:1] == b"\x30" and taille <= TAILLE_MAX_DER:
                debut += flux.read()
        nature = reconnaitre(debut, chemin.name)
        fichiers.append(FichierSI(
            chemin=relatif(chemin, racine), taille=taille, droits=oct(chemin.stat().st_mode & 0o777)[2:],
            nature=nature, outil_conseille=OUTILS.get(nature) or (None if nature in SANS_INTERET else REPLI),
            remarque=remarque(nature),
        ))
    return Resultat(outil=NOM, cible=cible, fichiers=fichiers)
