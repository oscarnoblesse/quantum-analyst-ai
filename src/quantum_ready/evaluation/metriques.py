"""Génère results/metrics.json à partir des fichiers versionnés dans results/raw/.

Aucune valeur n'est saisie à la main : tout vient des fichiers produits par les scripts
(bench_pqc, scripts/demonstrateur.py, agent Démonstrateur, évaluation du SI v2). Ce qui n'est pas mesuré est
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
    "inventaire sur le SI v1 : non repris ici ; valeurs exactes recalculables depuis les traces (AUDIT.md, section 3)",
    "ablation (c) : système avec un second modèle de taille différente (sujet §6.2)",
]

# Sessions de l'évaluation sur la variante non vue (SI v2). Rôle de chaque session, fixé ici et non déduit
# du nom : « a_posteriori » marque l'expérience décidée APRÈS avoir vu les résultats de la configuration principale.
SESSIONS_V2 = {
    "v2_reference_outils_seuls": {"configuration": "outils_seuls", "ablation": "a", "a_posteriori": False},
    "v2_regles": {"configuration": "agents_a_regles", "ablation": "a", "a_posteriori": False},
    "v2_ollama_run1": {"configuration": "modele_8go", "ablation": "b", "a_posteriori": False},
    "v2_ollama_run2": {"configuration": "modele_8go", "ablation": "b", "a_posteriori": False},
    "v2_ollama_run3": {"configuration": "modele_8go", "ablation": "b", "a_posteriori": False},
    "v2_posthoc_budget_run1": {"configuration": "modele_8go_budget_162", "ablation": "b", "a_posteriori": True},
}
MESURES_V2 = ("rappel", "rappel_caches", "precision_stricte", "precision_hors_doublons", "f1")


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


def _ligne_v2(evaluation: dict) -> dict:
    qualite, couts = evaluation["qualite"], evaluation["couts"]
    plan = evaluation.get("plan")
    return {
        **{m: qualite[m] for m in MESURES_V2},
        "rappel_par_perimetre": qualite.get("rappel_par_perimetre", {}),
        "shor_bien_classes": qualite["shor_bien_classes"],
        "leurres_touches": (qualite.get("leurres") or {}).get("leurres_touches"),
        "cbom_valide": evaluation.get("cbom_valide"),
        "plan_conforme": plan["conforme"] if plan else None,
        "plan_etapes": plan["etapes"] if plan else None,
        "arret_inventoriste": couts["arrets"].get("inventoriste"),
        "appels_outils": couts["appels_outils"],
        "erreurs_outils": couts["erreurs_outils"],
        "tours_de_modele": couts["tours_de_modele"],
        "duree_totale_s": couts["duree_totale_s"],
        "manques": qualite["manques"],
    }


def _repetitions(lignes: list[dict]) -> dict:
    """Moyenne et écart type de chaque mesure sur les répétitions (valeurs en %, sauf F1)."""
    sortie = {}
    for mesure in MESURES_V2:
        valeurs = [l[mesure] * (1 if mesure == "f1" else 100) for l in lignes]
        sortie[mesure] = {"n": len(valeurs), "moyenne": round(statistics.fmean(valeurs), 3),
                          "ecart_type": round(statistics.stdev(valeurs), 3) if len(valeurs) >= 2 else None}
    sortie["unite"] = "pourcentage (F1 : sans unité)"
    sortie["executions_identiques"] = all(l["manques"] == lignes[0]["manques"] and l["appels_outils"] == lignes[0]["appels_outils"]
                                          for l in lignes)
    return sortie


def section_inventaire_v2(brut: dict | None) -> dict | None:
    """Évaluation sur la variante non vue du SI (v2), depuis results/raw/evaluation_v2.json."""
    if not brut:
        return None
    par_configuration: dict[str, dict] = {}
    for evaluation in brut["sessions"]:
        nom = Path(evaluation["session"]).name
        role = SESSIONS_V2.get(nom)
        if role is None or "qualite" not in evaluation:
            continue
        cellule = par_configuration.setdefault(role["configuration"], {"ablation": role["ablation"],
                                                                        "a_posteriori": role["a_posteriori"], "sessions": {}})
        cellule["sessions"][nom] = _ligne_v2(evaluation)
    for cellule in par_configuration.values():
        cellule["repetitions"] = _repetitions(list(cellule["sessions"].values()))
    comparaison = {}
    outils = par_configuration.get("outils_seuls")
    if outils:
        manques_outils = set(next(iter(outils["sessions"].values()))["manques"])
        for nom, cellule in par_configuration.items():
            if nom == "outils_seuls":
                continue
            manques = set(next(iter(cellule["sessions"].values()))["manques"])
            comparaison[nom] = {"trouves_en_plus_des_outils": sorted(manques_outils - manques),
                                "perdus_par_rapport_aux_outils": sorted(manques - manques_outils)}
    return {"verite_terrain": brut["verite_terrain"], "leurres": brut.get("leurres"),
            "configurations": par_configuration, "comparaison_aux_outils_seuls": comparaison}


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
        "inventaire_v2": section_inventaire_v2(lire("evaluation_v2.json")),
        "avertissements": avertissements,
        "non_mesure": NON_MESURE,
    }


def main() -> int:
    sys.stdout.reconfigure(encoding="utf-8")
    document = construire()
    SORTIE.parent.mkdir(parents=True, exist_ok=True)
    SORTIE.write_text(json.dumps(document, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(f"Métriques écrites dans {SORTIE} ({len(document['sources'])} sources, "
          f"{len(document['avertissements'])} avertissement(s), {len(NON_MESURE)} mesures non faites).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
