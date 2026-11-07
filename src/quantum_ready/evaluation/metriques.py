"""Génère results/metrics.json à partir des fichiers versionnés dans results/raw/.

Aucune valeur n'est saisie à la main : tout vient des fichiers produits par les scripts
(bench_pqc, scripts/demonstrateur.py, agent Démonstrateur). Ce qui n'est pas mesuré est
listé dans « non_mesure », jamais rempli par défaut.

Usage : uv run python -m quantum_ready.evaluation.metriques
"""

from __future__ import annotations

import json
import statistics
import sys
from datetime import datetime, timezone
from pathlib import Path

RACINE = Path(__file__).resolve().parents[3]
BRUT = RACINE / "results" / "raw"
SORTIE = RACINE / "results" / "metrics.json"

NON_MESURE = [
    "RSA-2048 et ECDSA P-256 : taille de la poignée de main et latence (sujet §4.4)",
    "certificat serveur et signatures ML-DSA-65 (sujet §4.4)",
    "chaîne ML-DSA racine, intermédiaire, feuille et taille du handshake (sujet §5.2)",
    "SLH-DSA vs ML-DSA : génération, signature, vérification, tailles, temps (sujet §5.1)",
    "débit des connexions (sujet, métriques)",
    "tailles des clés publiques et privées (sujet, métriques)",
    "rappel et précision de l'évaluation par catégorie, validité du CBOM sur 3 répétitions",
    "performance sur la variante non vue du SI (sujet §4)",
]


def lire(nom: str):
    chemin = BRUT / nom
    return json.loads(chemin.read_text(encoding="utf-8")) if chemin.is_file() else None


def resume(valeurs: list[float]) -> dict:
    """Moyenne et écart type (échantillon) ; l'écart type n'existe qu'à partir de deux valeurs."""
    if not valeurs:
        return {"n": 0, "moyenne": None, "ecart_type": None}
    return {
        "n": len(valeurs),
        "moyenne": round(statistics.fmean(valeurs), 1),
        "ecart_type": round(statistics.stdev(valeurs), 1) if len(valeurs) >= 2 else None,
    }


def section_latence(bench: dict | None) -> dict | None:
    if bench is None:
        return None
    return {
        "openssl": bench["openssl"],
        "echantillons": bench["echantillons"],
        "echauffement": bench["echauffement"],
        "configurations": bench["configurations"],
        "rapport_mediane_hybride_sur_classique": bench["rapport_mediane"],
        "octets_supplementaires_client_hello": bench["octets_supplementaires_client_hello"],
        "verifications": bench.get("verifications", []),
    }


def section_agent(runs: list[dict] | None) -> dict | None:
    if not runs:
        return None
    par_groupe: dict[str, dict[str, list[float]]] = {}
    for run in runs:
        for r in run.get("resultats") or []:
            cellule = par_groupe.setdefault(r["groupe"], {"mediane_us": [], "p95_us": [], "client_hello_octets": []})
            for cle in cellule:
                if r.get(cle) is not None:
                    cellule[cle].append(float(r[cle]))
    return {
        "executions": len(runs),
        "terminees": sum(1 for r in runs if r.get("arret") == "termine"),
        "appels_refuses_total": sum(r.get("appels_refuses") or 0 for r in runs),
        "appels_en_double_total": sum(r.get("appels_en_double") or 0 for r in runs),
        "erreurs_outils_total": sum(r.get("erreurs_outils") or 0 for r in runs),
        "groupes": {
            groupe: {cle: resume(valeurs) for cle, valeurs in cellules.items()}
            for groupe, cellules in par_groupe.items()
        },
        "modele": sorted({r.get("modele") for r in runs if r.get("modele")}),
    }


def construire() -> dict:
    bench = lire("bench_pqc.json")
    verification = lire("demonstrateur_verification.json")
    runs = lire("demonstrateur_agent.json")
    avertissements = []
    if bench and len(bench.get("configurations", {})) == 2:
        avertissements.append("latence : une seule série de mesures ; le sujet exige 3 répétitions (moyenne, écart type)")
    if runs and len(runs) < 3:
        avertissements.append(f"agent Démonstrateur : {len(runs)} exécution(s) ; le sujet exige 3 répétitions")
    if verification is not None and not verification.get("conforme"):
        avertissements.append("la vérification du laboratoire n'est pas conforme : voir demonstrateur_verification.json")
    return {
        "version": 1,
        "genere_le": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "sources": sorted(p.name for p in BRUT.glob("*.json")),
        "demonstrateur": {
            "verification": verification,
            "latence_bench_pqc": section_latence(bench),
            "agent": section_agent(runs),
        },
        "avertissements": avertissements,
        "non_mesure": NON_MESURE,
    }


def main() -> int:
    sys.stdout.reconfigure(encoding="utf-8")
    document = construire()
    SORTIE.parent.mkdir(parents=True, exist_ok=True)
    SORTIE.write_text(json.dumps(document, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"Métriques écrites dans {SORTIE} ({len(document['sources'])} sources, "
          f"{len(document['avertissements'])} avertissement(s), {len(NON_MESURE)} mesures non faites).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
