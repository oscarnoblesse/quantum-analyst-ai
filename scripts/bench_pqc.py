"""Mesure le coût du handshake TLS 1.3 hybride (X25519MLKEM768) par rapport à X25519 classique.

Usage (depuis la racine du dépôt, Docker en marche) :

    uv run python scripts/bench_pqc.py

Méthode (choisie avec le titulaire du projet) :
- deux serveurs du laboratoire : un qui n'accepte que X25519MLKEM768, un qui n'accepte que X25519 ;
- 100 handshakes d'échauffement, puis 1000 handshakes mesurés, chacun sur une nouvelle connexion ;
- les mesures sont faites DANS un conteneur partageant le réseau du serveur (127.0.0.1) ;
- on publie la médiane, le 95e percentile et la moyenne du temps, ainsi que la taille
  en clair du ClientHello et du ServerHello (ce qui change avec ML-KEM).

Résultat : results/raw/bench_pqc.json. Les nombres dépendent de la machine : ils sont
publiés avec la version d'OpenSSL et le nombre de mesures, pas comme des constantes.
"""

from __future__ import annotations

import csv
import io
import json
import shutil
import statistics
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

RACINE = Path(__file__).resolve().parent.parent
DOSSIER = RACINE / "demonstrateur"
SORTIE = RACINE / "results" / "raw" / "bench_pqc.json"
IMAGE = "quantum-ready-lab:dev"
ECHAUFFEMENT = 100
MESURES = 1000
# Quatre configurations : échange de clés (hybride ou classique) x certificat serveur (ECDSA P-256 ou RSA-2048).
# Les clés « hybride » et « classique » sont celles du rapport de latence de référence (certificat ECDSA P-256).
CONFIGURATIONS = {
    "hybride": {"groupe": "X25519MLKEM768", "cert": "ecdsa-p256", "conteneur": "qr-lab-hybride"},
    "classique": {"groupe": "X25519", "cert": "ecdsa-p256", "conteneur": "qr-lab-classique"},
    "hybride_rsa2048": {"groupe": "X25519MLKEM768", "cert": "rsa-2048", "conteneur": "qr-lab-hybride-rsa"},
    "classique_rsa2048": {"groupe": "X25519", "cert": "rsa-2048", "conteneur": "qr-lab-classique-rsa"},
}


def docker(*args: str, verifier: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(["docker", *args], capture_output=True, text=True, encoding="utf-8", check=verifier)


def demarrer_serveur(nom: str, groupe: str, cert: str) -> None:
    docker("rm", "-f", nom, verifier=False)
    docker("run", "-d", "--name", nom, "-e", f"GROUPES={groupe}", "-e", f"CERT={cert}", IMAGE)
    limite = time.monotonic() + 30
    while time.monotonic() < limite:
        journal = docker("logs", nom, verifier=False)
        if "Démarrage" in journal.stdout + journal.stderr:
            return
        time.sleep(1)
    raise RuntimeError(f"le serveur {nom} ne répond pas")


def mesurer(nom_serveur: str, groupe: str) -> list[dict]:
    """Lance bench_pqc dans un conteneur qui partage le réseau du serveur."""
    resultat = docker(
        "run", "--rm", "--network", f"container:{nom_serveur}", "--entrypoint", "/usr/local/bin/bench_pqc",
        IMAGE, "127.0.0.1", "8443", groupe, str(ECHAUFFEMENT), str(MESURES),
    )
    return list(csv.DictReader(io.StringIO(resultat.stdout)))


def resumer(lignes: list[dict]) -> dict:
    temps = [float(l["microsecondes"]) for l in lignes]
    p95 = statistics.quantiles(temps, n=20, method="inclusive")[18]
    return {
        "groupe": lignes[0]["groupe"],
        "mesures": len(temps),
        "mediane_us": round(statistics.median(temps), 1),
        "p95_us": round(p95, 1),
        "moyenne_us": round(statistics.fmean(temps), 1),
        "client_hello_octets": int(statistics.median(float(l["client_hello"]) for l in lignes)),
        "server_hello_octets": int(statistics.median(float(l["server_hello"]) for l in lignes)),
        "certificat_octets": int(statistics.median(float(l["certificat"]) for l in lignes)),
    }


def version_openssl() -> str:
    return docker("run", "--rm", "--entrypoint", "openssl", IMAGE, "version").stdout.strip()


def verifier(resultats: dict[str, dict]) -> list[str]:
    """Propriétés qui doivent toujours être vraies, quelle que soit la machine. Liste des écarts."""
    problemes = []
    for nom, r in resultats.items():
        cfg = CONFIGURATIONS[nom]
        if r["mesures"] != MESURES:
            problemes.append(f"{nom} : {r['mesures']} mesures au lieu de {MESURES}")
        if r["groupe"].lower() != cfg["groupe"].lower():  # OpenSSL écrit « x25519 » en minuscules
            problemes.append(f"{nom} : groupe négocié {r['groupe']}, attendu {cfg['groupe']}")
        if r.get("certificat_octets") is not None and r["certificat_octets"] <= 0:
            problemes.append(f"{nom} : message Certificate absent")
    hybride, classique = resultats["hybride"], resultats["classique"]
    if hybride["client_hello_octets"] - classique["client_hello_octets"] < 1000:
        problemes.append("le ClientHello hybride devrait être plus gros d'au moins 1000 octets (clé ML-KEM-768)")
    # RSA-2048 : clé publique et signature plus grosses que ECDSA P-256 ; le certificat doit le refléter.
    if "classique_rsa2048" in resultats and "classique" in resultats:
        if resultats["classique_rsa2048"]["certificat_octets"] - resultats["classique"]["certificat_octets"] < 300:
            problemes.append("le Certificate RSA-2048 devrait être plus gros d'au moins 300 octets que ECDSA P-256")
    return problemes


def main() -> int:
    sys.stdout.reconfigure(encoding="utf-8")
    if shutil.which("docker") is None:
        print("Docker est introuvable.", file=sys.stderr)
        return 2

    print("== Construction de l'image", flush=True)
    docker("build", "-t", IMAGE, str(DOSSIER))
    resultats: dict[str, dict] = {}
    try:
        for nom, cfg in CONFIGURATIONS.items():
            print(f"== Serveur {nom} ({cfg['groupe']})", flush=True)
            demarrer_serveur(cfg["conteneur"], cfg["groupe"], cfg["cert"])
            print(f"== Mesure : {ECHAUFFEMENT} d'échauffement, {MESURES} handshakes", flush=True)
            resultats[nom] = resumer(mesurer(cfg["conteneur"], cfg["groupe"]))
            resultats[nom]["certificat_type"] = cfg["cert"]
            print(f"   médiane {resultats[nom]['mediane_us']} µs, p95 {resultats[nom]['p95_us']} µs, "
                  f"ClientHello {resultats[nom]['client_hello_octets']} o", flush=True)
    finally:
        for cfg in CONFIGURATIONS.values():
            docker("rm", "-f", cfg["conteneur"], verifier=False)

    hybride, classique = resultats["hybride"], resultats["classique"]
    document = {
        "date_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "openssl": version_openssl(),
        "echantillons": MESURES,
        "echauffement": ECHAUFFEMENT,
        "configurations": resultats,
        "rapport_mediane": round(hybride["mediane_us"] / classique["mediane_us"], 3),
        "octets_supplementaires_client_hello": hybride["client_hello_octets"] - classique["client_hello_octets"],
    }
    document["verifications"] = verifier(resultats)
    SORTIE.parent.mkdir(parents=True, exist_ok=True)
    SORTIE.write_text(json.dumps(document, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"\nRésultats écrits dans {SORTIE}")
    if document["verifications"]:
        print("Vérifications en échec :\n  - " + "\n  - ".join(document["verifications"]), file=sys.stderr)
        return 1
    print("Vérifications : toutes conformes.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
