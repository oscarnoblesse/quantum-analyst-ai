"""Outils de contrôle du laboratoire TLS (démonstrateur) : démarrer, mesurer, arrêter.

Périmètre fermé : seuls les deux groupes ci-dessous sont acceptés, et le laboratoire
n'écoute que sur 127.0.0.1. Aucun argument ne peut changer l'image, le port ou l'hôte.
Le docker est appelé sans shell (liste d'arguments).
"""

from __future__ import annotations

import csv
import io
import statistics
import subprocess
import time
from pathlib import Path

from quantum_ready.outils.commun import ErreurOutil

RACINE = Path(__file__).resolve().parents[3]
DOSSIER_LABORATOIRE = RACINE / "demonstrateur"
IMAGE = "quantum-ready-lab:dev"
PORT_HOTE = 8443
ATTENTE_DEMARRAGE_SECONDES = 30
ECHAUFFEMENT = 100
MESURES_MAX = 1000
MESURES_MIN = 10
# Groupe demandé -> nom du conteneur (un seul serveur à la fois : le port hôte est partagé)
GROUPES = {"X25519MLKEM768": "qr-lab-hybride", "X25519": "qr-lab-classique"}


def _groupe(groupe: str) -> str:
    if groupe not in GROUPES:
        raise ErreurOutil(f"groupe refusé : {groupe}. Valeurs possibles : {', '.join(GROUPES)}")
    return groupe


def _docker(*args: str, verifier: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(["docker", *args], capture_output=True, text=True, encoding="utf-8", check=verifier, timeout=600)


def demarrer(groupe: str, cert: str = "ecdsa-p256") -> str:
    """Construit l'image si besoin et lance le serveur qui n'accepte que `groupe`, avec le certificat `cert`."""
    groupe = _groupe(groupe)
    nom = GROUPES[groupe]
    _docker("build", "-q", "-t", IMAGE, str(DOSSIER_LABORATOIRE))
    _docker("rm", "-f", nom, verifier=False)
    _docker("run", "-d", "--name", nom, "-p", f"127.0.0.1:{PORT_HOTE}:8443", "-e", f"GROUPES={groupe}", "-e", f"CERT={cert}", IMAGE)
    limite = time.monotonic() + ATTENTE_DEMARRAGE_SECONDES
    while time.monotonic() < limite:
        journal = _docker("logs", nom, verifier=False)
        if "Démarrage" in journal.stdout + journal.stderr:
            return f"laboratoire démarré : groupe {groupe} accepté seul, sur 127.0.0.1:{PORT_HOTE}"
        time.sleep(1)
    raise ErreurOutil(f"le laboratoire {groupe} ne s'est pas lancé en {ATTENTE_DEMARRAGE_SECONDES} s")


def groupe_demarre() -> str | None:
    """Le groupe accepté par le laboratoire en marche, ou None si aucun n'est démarré."""
    actifs = _docker("ps", "--filter", "name=qr-lab-", "--format", "{{.Names}}", verifier=False).stdout.split()
    return next((groupe for groupe, nom in GROUPES.items() if nom in actifs), None)


def arreter(groupe: str) -> str:
    groupe = _groupe(groupe)
    _docker("rm", "-f", GROUPES[groupe], verifier=False)
    return f"laboratoire arrêté : groupe {groupe}"


def mesurer(groupe: str, mesures: int = MESURES_MAX) -> dict:
    """Handshakes mesurés par bench_pqc, dans un conteneur qui partage le réseau du serveur."""
    groupe = _groupe(groupe)
    if not MESURES_MIN <= mesures <= MESURES_MAX:
        raise ErreurOutil(f"nombre de mesures hors limites ({MESURES_MIN} à {MESURES_MAX})")
    if _docker("inspect", "-f", "{{.State.Running}}", GROUPES[groupe], verifier=False).stdout.strip() != "true":
        raise ErreurOutil(f"le laboratoire {groupe} n'est pas démarré : appelez demarrer_laboratoire d'abord")
    sortie = _docker(
        "run", "--rm", "--network", f"container:{GROUPES[groupe]}", "--entrypoint", "/usr/local/bin/bench_pqc",
        IMAGE, "127.0.0.1", "8443", groupe, str(ECHAUFFEMENT), str(mesures),
    ).stdout
    lignes = list(csv.DictReader(io.StringIO(sortie)))
    if not lignes:
        raise ErreurOutil("bench_pqc n'a produit aucune mesure")
    temps = [float(l["microsecondes"]) for l in lignes]
    return {
        "groupe": lignes[0]["groupe"],
        "mesures": len(temps),
        "mediane_us": round(statistics.median(temps), 1),
        "p95_us": round(statistics.quantiles(temps, n=20, method="inclusive")[18], 1) if len(temps) >= 20 else None,
        "client_hello_octets": int(statistics.median(float(l["client_hello"]) for l in lignes)),
        "server_hello_octets": int(statistics.median(float(l["server_hello"]) for l in lignes)),
    }


# --- Vérifications de plan (décision de méthode n° 2) : chaque fonction démarre le laboratoire,
# --- vérifie ce qui est négocié, puis l'arrête. Elles renvoient (réussi, motif).

IMAGE_SSH = "quantum-ready-ssh:dev"
CONTENEUR_SSH = "qr-lab-ssh"
DOSSIER_SSH = RACINE / "demonstrateur" / "ssh"


MARQUEUR_CERTIFICAT = "---CERTIFICAT---"


def _client_tls(groupe: str, *, certificat: bool = False) -> str:
    """Handshake TLS 1.3 depuis le conteneur du serveur. Avec `certificat`, ajoute le texte du certificat
    présenté par le serveur (après MARQUEUR_CERTIFICAT)."""
    commande = f"echo | openssl s_client -connect 127.0.0.1:8443 -tls1_3 -groups {groupe} 2>&1"
    if certificat:
        commande += (f"; echo {MARQUEUR_CERTIFICAT}; echo | openssl s_client -connect 127.0.0.1:8443 -tls1_3 2>/dev/null"
                     " | sed -n '/-----BEGIN/,/-----END/p' | openssl x509 -noout -text 2>&1")
    return _docker("exec", GROUPES[groupe], "sh", "-c", commande, verifier=False).stdout


def verifier_tls_hybride() -> tuple[bool, str]:
    demarrer("X25519MLKEM768")
    try:
        sortie = _client_tls("X25519MLKEM768")
    finally:
        arreter("X25519MLKEM768")
    if "Negotiated TLS1.3 group: X25519MLKEM768" in sortie:
        return True, ""
    return False, "le groupe X25519MLKEM768 n'est pas négocié par le serveur du laboratoire"


def verifier_certificat_mldsa65() -> tuple[bool, str]:
    demarrer("X25519MLKEM768", cert="mldsa-65")
    try:
        sortie = _client_tls("X25519MLKEM768", certificat=True)
    finally:
        arreter("X25519MLKEM768")
    handshake, _, certificat = sortie.partition(MARQUEUR_CERTIFICAT)
    if "Negotiated TLS1.3 group: X25519MLKEM768" not in handshake:
        return False, "handshake hybride non réussi avec le certificat ML-DSA-65"
    if "Public Key Algorithm: ML-DSA-65" not in certificat:
        return False, "le certificat présenté n'est pas en ML-DSA-65"
    return True, ""


def verifier_ssh_hybride() -> tuple[bool, str]:
    """Serveur OpenSSH n'acceptant que mlkem768x25519-sha256 ; client qui propose la même liste."""
    _docker("build", "-q", "-t", IMAGE_SSH, str(DOSSIER_SSH))
    _docker("rm", "-f", CONTENEUR_SSH, verifier=False)
    try:
        _docker("run", "-d", "--name", CONTENEUR_SSH, "-e", "KEX=mlkem768x25519-sha256", IMAGE_SSH)
        limite = time.monotonic() + ATTENTE_DEMARRAGE_SECONDES
        while True:
            journal = _docker("logs", CONTENEUR_SSH, verifier=False)
            if "Démarrage" in journal.stdout + journal.stderr:
                break
            if time.monotonic() > limite:
                return False, "le serveur SSH du laboratoire ne s'est pas lancé"
            time.sleep(1)
        sortie = _docker("run", "--rm", "--network", f"container:{CONTENEUR_SSH}", "--entrypoint", "ssh", IMAGE_SSH,
                         "-v", "-p", "2222", "-l", "demo", "-o", "KexAlgorithms=mlkem768x25519-sha256",
                         "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-o", "BatchMode=yes",
                         "127.0.0.1", "true", verifier=False)
        sortie_texte = sortie.stdout + sortie.stderr
    finally:
        _docker("rm", "-f", CONTENEUR_SSH, verifier=False)
    if "kex: algorithm: mlkem768x25519-sha256" in sortie_texte:
        return True, ""
    return False, "l'échange mlkem768x25519-sha256 n'est pas négocié par OpenSSH"


VERIFICATEURS = {
    "tls-hybride": verifier_tls_hybride,
    "certificat-mldsa65": verifier_certificat_mldsa65,
    "ssh-hybride": verifier_ssh_hybride,
}


def verifier(cle: str) -> tuple[bool, str]:
    """Lance la démonstration correspondant à une clé de `verification_plan.DEMONSTRABLES`."""
    if cle not in VERIFICATEURS:
        return False, f"démonstration inconnue : {cle}"
    try:
        return VERIFICATEURS[cle]()
    except ErreurOutil as erreur:
        return False, str(erreur)
