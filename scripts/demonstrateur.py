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
import json
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

RACINE = Path(__file__).resolve().parent.parent
DOSSIER = RACINE / "demonstrateur"
IMAGE = "quantum-ready-lab:dev"
IMAGE_SSH = "quantum-ready-ssh:dev"
CONTENEUR_SSH = "quantum-ready-ssh"
DOSSIER_SSH = RACINE / "demonstrateur" / "ssh"
KEX_HYBRIDE_SSH = "mlkem768x25519-sha256"
KEX_CLASSIQUE_SSH = "curve25519-sha256"
SORTIE = RACINE / "results" / "raw" / "demonstrateur_verification.json"
RESULTAT: dict = {}
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
    negocie = next((l.split(':', 1)[1].strip() for l in sortie.splitlines() if "Negotiated TLS1.3 group" in l), None)
    print(f"   {'OK' if reussi else 'ÉCHEC'} : groupe négocié = {negocie or '<aucun>'}")

    print("== Client classique seul (X25519) : doit être refusé", flush=True)
    classique = client("X25519")
    refus = "handshake failure" in classique or "Negotiated TLS1.3 group: <NULL>" in classique
    etat = "refusé" if refus else "accepté : le groupe hybride n'est pas imposé"
    print(f"   {'OK' if refus else 'ÉCHEC'} : {etat}")
    RESULTAT["tls"] = {"groupe_negocie": negocie, "groupe_attendu": GROUPE_HYBRIDE, "classique_refuse": refus,
                       "openssl_serveur": docker("run", "--rm", "--entrypoint", "openssl", IMAGE, "version", verifier=False).stdout.strip()}
    return reussi and refus


def kex_negociee(sortie_ssh_v: str) -> str | None:
    """Algorithme d'échange de clés lu dans la sortie de `ssh -v` (ligne « kex: algorithm »)."""
    for ligne in sortie_ssh_v.splitlines():
        if "kex: algorithm:" in ligne:
            return ligne.split("kex: algorithm:", 1)[1].strip()
    return None


def ssh_client(kex: str) -> str:
    """Connexion SSH depuis le conteneur du serveur ; renvoie la sortie de `ssh -v`.
    L'authentification est refusée volontairement : seul l'échange de clés nous intéresse."""
    resultat = docker(
        "run", "--rm", "--network", f"container:{CONTENEUR_SSH}", "--entrypoint", "ssh", IMAGE_SSH,
        "-v", "-p", "2222", "-l", "demo", "-o", f"KexAlgorithms={kex}", "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null", "-o", "BatchMode=yes", "127.0.0.1", "true",
        verifier=False,
    )
    return resultat.stdout + resultat.stderr


def verifier_ssh() -> bool:
    """SSH : l'échange hybride est négocié ; un client qui ne propose que X25519 classique est refusé."""
    print("== SSH : construction de l'image", flush=True)
    docker("build", "-q", "-t", IMAGE_SSH, str(DOSSIER_SSH))
    ok = False
    try:
        print("== SSH : serveur n'acceptant que l'échange hybride", flush=True)
        docker("rm", "-f", CONTENEUR_SSH, verifier=False)
        docker("run", "-d", "--name", CONTENEUR_SSH, "-e", f"KEX={KEX_HYBRIDE_SSH}", IMAGE_SSH)
        limite = time.monotonic() + ATTENTE_SECONDES
        while True:
            journal = docker("logs", CONTENEUR_SSH, verifier=False)
            if "Démarrage" in journal.stdout + journal.stderr:
                break
            if time.monotonic() > limite:
                raise RuntimeError("le serveur SSH ne s'est pas lancé à temps")
            time.sleep(1)
        negocie = kex_negociee(ssh_client(KEX_HYBRIDE_SSH))
        reussi = negocie == KEX_HYBRIDE_SSH
        print(f"   {'OK' if reussi else 'ÉCHEC'} : échange négocié = {negocie}", flush=True)
        classique = ssh_client(KEX_CLASSIQUE_SSH)
        refus = "no matching key exchange method" in classique
        print(f"   {'OK' if refus else 'ÉCHEC'} : client X25519 seul {'refusé' if refus else 'accepté'}", flush=True)
        ok = reussi and refus
        RESULTAT["ssh"] = {"kex_negociee": negocie, "kex_attendue": KEX_HYBRIDE_SSH, "classique_refuse": refus,
                           "openssh_serveur": docker("run", "--rm", "--entrypoint", "ssh", IMAGE_SSH, "-V", verifier=False).stderr.strip()}
    finally:
        docker("rm", "-f", CONTENEUR_SSH, verifier=False)
    return ok


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
        ok = verifier_ssh() and ok
    except (subprocess.CalledProcessError, RuntimeError) as erreur:
        print(f"\nÉchec : {erreur}", file=sys.stderr)
        return 1
    finally:
        arreter()
    RESULTAT["date_utc"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    RESULTAT["conforme"] = ok
    SORTIE.parent.mkdir(parents=True, exist_ok=True)
    SORTIE.write_text(json.dumps(RESULTAT, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print("\nDémonstrateur vérifié." if ok else "\nDémonstrateur NON conforme.")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
