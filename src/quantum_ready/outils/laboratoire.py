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


def demarrer(groupe: str) -> str:
    """Construit l'image si besoin et lance le serveur qui n'accepte que `groupe`."""
    groupe = _groupe(groupe)
    nom = GROUPES[groupe]
    _docker("build", "-q", "-t", IMAGE, str(DOSSIER_LABORATOIRE))
    _docker("rm", "-f", nom, verifier=False)
    _docker("run", "-d", "--name", nom, "-p", f"127.0.0.1:{PORT_HOTE}:8443", "-e", f"GROUPES={groupe}", IMAGE)
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
