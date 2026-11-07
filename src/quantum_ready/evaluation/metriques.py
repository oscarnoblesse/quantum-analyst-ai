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
    "débit des connexions (sujet, métriques)",
    "discussion des hypothèses de sécurité ML-DSA (réseaux euclidiens) et SLH-DSA (hachage) : texte du rapport, pas une mesure (sujet §5.1)",
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


def section_signatures(sig: dict | None) -> dict | None:
    if sig is None:
        return None
    return {
        "openssl": sig["openssl"], "mesures": sig["mesures"], "repetitions": sig["repetitions"],
        "algorithmes": sig["algorithmes"], "verifications": sig.get("verifications", []),
    }


def section_agilite(cbom: dict | None) -> dict | None:
    """Indicateur de crypto-agilité sur le CBOM d'exemple versionné. Méthode à valider par l'auteur."""
    if cbom is None:
        return None
    from quantum_ready.outils.crypto_agilite import resumer

    return {"source": "results/cbom_exemple.json", "methode_a_valider": True, **resumer(cbom)}


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
    cbom_exemple = json.loads((RACINE / "results" / "cbom_exemple.json").read_text(encoding="utf-8")) \
        if (RACINE / "results" / "cbom_exemple.json").is_file() else None
    avertissements = []
    if bench:
        avertissements.append("latence : une seule série de mesures par configuration ; le sujet exige 3 répétitions (moyenne, écart type)")
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
            "signatures": section_signatures(lire("bench_signatures.json")),
            "agent": section_agent(runs),
        },
        "crypto_agilite": section_agilite(cbom_exemple),
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
