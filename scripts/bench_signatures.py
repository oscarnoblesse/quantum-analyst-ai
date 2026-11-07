"""Compare ML-DSA-65 et SLH-DSA (deux jeux de paramètres) : génération, signature, vérification, tailles.

Usage (depuis la racine du dépôt, Docker en marche) :

    uv run python scripts/bench_signatures.py

Méthode :
- trois répétitions indépendantes par algorithme (exigence du sujet) ;
- 10 opérations d'échauffement puis 100 mesurées, par répétition ;
- médiane par répétition, puis moyenne et écart type sur les trois répétitions ;
- les tailles sont vérifiées contre les valeurs de la norme (FIPS 204 et FIPS 205).

Résultat : results/raw/bench_signatures.json.
"""

from __future__ import annotations

import csv
import io
import json
import shutil
import statistics
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

RACINE = Path(__file__).resolve().parent.parent
DOSSIER = RACINE / "demonstrateur"
SORTIE = RACINE / "results" / "raw" / "bench_signatures.json"
IMAGE = "quantum-ready-lab:dev"
ECHAUFFEMENT = 10
MESURES = 100
REPETITIONS = 3
ALGORITHMES = {
    # nom OpenSSL : (taille de clé publique, taille de signature) attendues par la norme
    "ML-DSA-65": (1952, 3309),
    "SLH-DSA-SHA2-128s": (32, 7856),
    "SLH-DSA-SHA2-128f": (32, 17088),
}


def docker(*args: str, verifier: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(["docker", *args], capture_output=True, text=True, encoding="utf-8", check=verifier)


def une_repetition(algo: str) -> dict:
    sortie = docker("run", "--rm", "--entrypoint", "/usr/local/bin/bench_signatures", IMAGE,
                    algo, str(ECHAUFFEMENT), str(MESURES)).stdout
    lignes = [l for l in sortie.splitlines() if l and not l.startswith("#")]
    tailles = next(l for l in sortie.splitlines() if l.startswith("#"))
    cle = int(tailles.split("cle_publique_octets=")[1].split()[0])
    sig = int(tailles.split("signature_octets=")[1].split()[0])
    lues = list(csv.DictReader(io.StringIO("\n".join(lignes))))
    return {
        "generation_us": statistics.median(float(l["generation_us"]) for l in lues),
        "signature_us": statistics.median(float(l["signature_us"]) for l in lues),
        "verification_us": statistics.median(float(l["verification_us"]) for l in lues),
        "cle_publique_octets": cle,
        "signature_octets": sig,
    }


def resume(valeurs: list[float]) -> dict:
    return {"moyenne_us": round(statistics.fmean(valeurs), 1),
            "ecart_type_us": round(statistics.stdev(valeurs), 1) if len(valeurs) >= 2 else None}


def main() -> int:
    sys.stdout.reconfigure(encoding="utf-8")
    if shutil.which("docker") is None:
        print("Docker est introuvable.", file=sys.stderr)
        return 2
    docker("build", "-q", "-t", IMAGE, str(DOSSIER))
    algorithmes = {}
    problemes = []
    for algo, (cle_attendue, sig_attendue) in ALGORITHMES.items():
        print(f"== {algo} : {REPETITIONS} répétitions de {MESURES} mesures", flush=True)
        repetitions = [une_repetition(algo) for _ in range(REPETITIONS)]
        tailles = {(r["cle_publique_octets"], r["signature_octets"]) for r in repetitions}
        if tailles != {(cle_attendue, sig_attendue)}:
            problemes.append(f"{algo} : tailles {tailles}, attendues {(cle_attendue, sig_attendue)}")
        algorithmes[algo] = {
            "repetitions": repetitions,
            "generation": resume([r["generation_us"] for r in repetitions]),
            "signature": resume([r["signature_us"] for r in repetitions]),
            "verification": resume([r["verification_us"] for r in repetitions]),
            "cle_publique_octets": repetitions[0]["cle_publique_octets"],
            "signature_octets": repetitions[0]["signature_octets"],
        }
        print(f"   signature médiane {algorithmes[algo]['signature']['moyenne_us']} µs, "
              f"vérification {algorithmes[algo]['verification']['moyenne_us']} µs", flush=True)
    version = docker("run", "--rm", "--entrypoint", "openssl", IMAGE, "version").stdout.strip()
    document = {
        "date_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "openssl": version,
        "echauffement": ECHAUFFEMENT, "mesures": MESURES, "repetitions": REPETITIONS,
        "algorithmes": algorithmes,
        "verifications": problemes,
    }
    SORTIE.parent.mkdir(parents=True, exist_ok=True)
    SORTIE.write_text(json.dumps(document, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"\nRésultats écrits dans {SORTIE}")
    if problemes:
        print("Vérifications en échec :\n  - " + "\n  - ".join(problemes), file=sys.stderr)
        return 1
    print("Vérifications : tailles conformes aux normes.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
