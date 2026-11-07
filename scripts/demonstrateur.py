"""Lance le laboratoire TLS hybride, vérifie le handshake, puis l'arrête.

Usage (depuis la racine du dépôt, Docker en marche) :

    uv run python scripts/demonstrateur.py

Vérifications :
1. un client qui propose X25519MLKEM768 réussit et négocie ce groupe ;
2. un client qui ne propose que X25519 classique est refusé.

Les deux clients tournent DANS le conteneur, avec le même OpenSSL que le serveur :
le résultat ne dépend donc pas de la version d'OpenSSL installée sur la machine.
Le laboratoire n'écoute que sur 127.0.0.1 et ne contacte aucun autre système.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

RACINE = Path(__file__).resolve().parent.parent
DOSSIER = RACINE / "demonstrateur"
IMAGE = "quantum-ready-lab:dev"
CONTENEUR = "quantum-ready-lab"
PORT = int(os.environ.get("LAB_PORT", "8443"))
GROUPE_HYBRIDE = "X25519MLKEM768"
ATTENTE_SECONDES = 30


def docker(*args: str, verifier: bool = True, **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(["docker", *args], capture_output=True, text=True, encoding="utf-8",
                          check=verifier, **kwargs)


def construire() -> None:
    print("== Construction de l'image", flush=True)
    docker("build", "-t", IMAGE, str(DOSSIER))


def demarrer() -> None:
    print("== Démarrage du laboratoire (127.0.0.1 uniquement)", flush=True)
    docker("rm", "-f", CONTENEUR, verifier=False)
    docker("run", "-d", "--name", CONTENEUR, "-p", f"127.0.0.1:{PORT}:8443", IMAGE)
    limite = time.monotonic() + ATTENTE_SECONDES
    while time.monotonic() < limite:
        journal = docker("logs", CONTENEUR, verifier=False).stdout
        if "Démarrage" in journal or "ACCEPT" in journal:
            return
        time.sleep(1)
    raise RuntimeError("le serveur ne s'est pas lancé à temps : " + docker("logs", CONTENEUR, verifier=False).stdout)


def client(groupes: str) -> str:
    """Handshake depuis le conteneur vers le serveur ; renvoie la sortie d'openssl."""
    resultat = docker(
        "exec", CONTENEUR, "sh", "-c",
        f"echo | openssl s_client -connect 127.0.0.1:8443 -tls1_3 -groups {groupes} 2>&1",
        verifier=False,
    )
    return resultat.stdout


def verifier() -> bool:
    print("== Handshake avec le groupe hybride", flush=True)
    sortie = client(GROUPE_HYBRIDE)
    reussi = f"Negotiated TLS1.3 group: {GROUPE_HYBRIDE}" in sortie
    print(f"   {'OK' if reussi else 'ÉCHEC'} : groupe négocié = "
          f"{next((l.split(':', 1)[1].strip() for l in sortie.splitlines() if 'Negotiated TLS1.3 group' in l), '<aucun>')}")

    print("== Client classique seul (X25519) : doit être refusé", flush=True)
    classique = client("X25519")
    refus = "handshake failure" in classique or "Negotiated TLS1.3 group: <NULL>" in classique
    etat = "refusé" if refus else "accepté : le groupe hybride n'est pas imposé"
    print(f"   {'OK' if refus else 'ÉCHEC'} : {etat}")
    return reussi and refus


def arreter() -> None:
    docker("rm", "-f", CONTENEUR, verifier=False)


def main() -> int:
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
    if shutil.which("docker") is None:
        print("Docker est introuvable : installez Docker Desktop (macOS, Windows) ou le moteur Docker (Linux).", file=sys.stderr)
        return 2
    try:
        construire()
        demarrer()
        ok = verifier()
    except (subprocess.CalledProcessError, RuntimeError) as erreur:
        print(f"\nÉchec : {erreur}", file=sys.stderr)
        return 1
    finally:
        arreter()
    print("\nDémonstrateur vérifié." if ok else "\nDémonstrateur NON conforme.")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
