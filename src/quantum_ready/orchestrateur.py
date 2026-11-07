"""Orchestrateur LangGraph : enchaîne les agents sur un état partagé typé.

    inventoriste -> cartographe <-> [le code revalide le CBOM]
                 -> analyste_risque
                 -> architecte <-> [le code vérifie le plan]
                 -> validation humaine -> fin

Deux boucles de vérification, qui ne font pas confiance au modèle :
- après le Cartographe, le CODE revalide le CBOM enregistré (schéma CycloneDX 1.6
  et cohérence) ; s'il est invalide, le Cartographe recommence avec les erreurs ;
- après l'Architecte, le CODE vérifie le plan (fiches du corpus existantes,
  actifs existants, actifs critiques tous couverts) ; sinon il recommence. Aucune modification du SI
n'est faite par le système ; la validation humaine porte sur les résultats avant
qu'ils servent à la migration.

    python -m quantum_ready.orchestrateur --racine si/generated/v1 --modele ollama
"""

from __future__ import annotations

import argparse
import asyncio
import dataclasses
import json
import shutil
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import TypedDict

import yaml
from langgraph.graph import END, START, StateGraph

from quantum_ready.agents import analyste_risque, architecte, cartographe, inventoriste
from quantum_ready.agents.communs import lancer
from quantum_ready.llm import Modele, ModeleSimule, depuis_configuration
from quantum_ready.outils.valider_schema import valider_schema
from quantum_ready.serveur_mcp.session import Session, ecrire_json, lire_json

CONFIGURATION = Path("config/experiment.yaml")


class EtatOrchestrateur(TypedDict, total=False):
    resultats: dict[str, dict]
    exclusions: list[dict]
    tentatives_cartographe: int
    erreurs_cbom: list[str]
    cbom_valide: bool
    tentatives_architecte: int
    erreurs_plan: list[str]
    plan_valide: bool
    validation: str
    arret: str


def construire_graphe(modeles: Callable[[str], Modele], session: Session, parametres: dict, transport: str = "stdio",
                      valider: Callable[[Session], bool] | None = None):
    """Graphe compilé. modeles(nom_agent) donne le modèle de chaque agent (le même, ou une politique d'ablation)."""
    agents = parametres.get("agents", {})
    horizon = parametres.get("mosca", {}).get("horizon_menace_annees", 10)
    tentatives_max = parametres.get("orchestrateur", {}).get("tentatives_cartographe", 3)
    tentatives_plan = parametres.get("orchestrateur", {}).get("tentatives_architecte", 2)
    # Vérification du plan par démonstration au laboratoire : désactivée par défaut (expérience v5 inchangée).
    demonstrer_plan = parametres.get("orchestrateur", {}).get("verification_demonstration", False)
    modele = parametres.get("modele", {})
    budget = modele.get("contexte", 4096) - modele.get("max_jetons_sortie", 1024) - 200

    def executer(config, etat: EtatOrchestrateur) -> dict:
        config.budget_jetons = budget
        resultat = asyncio.run(lancer(config, modeles(config.nom), session, horizon, transport))
        resultats = dict(etat.get("resultats", {}))
        cle = config.nom if config.nom not in resultats else f"{config.nom}_{sum(k.startswith(config.nom) for k in resultats) + 1}"
        resultats[cle] = resultat.model_dump()
        return {"resultats": resultats}

    def noeud_inventoriste(etat):
        mise_a_jour = executer(inventoriste.configuration(**agents.get("inventoriste", {})), etat)
        sortie = mise_a_jour["resultats"]["inventoriste"]["sortie"] or {}
        return mise_a_jour | {"exclusions": sortie.get("exclusions", [])}

    def apres_inventoriste(etat) -> str:
        # Un inventaire interrompu par une panne du modèle n'est pas transmis : il fausserait toute la suite.
        if etat["resultats"]["inventoriste"]["arret"] == "erreur_modele" or not session.trouvailles():
            return "fin"
        return "cartographe"

    def noeud_cartographe(etat):
        exclusions = list(etat.get("exclusions", []))
        config = cartographe.configuration(exclusions, **agents.get("cartographe", {}))
        if etat.get("erreurs_cbom"):
            config.consigne += "\nLa tentative précédente a produit un CBOM INVALIDE :\n" + "\n".join(f"- {e}" for e in etat["erreurs_cbom"][:5])
        mise_a_jour = executer(config, etat)
        # Vérification par le code, indépendamment de ce que dit le modèle
        validation = valider_schema(lire_json(session.fichier_cbom, {})) if session.fichier_cbom.is_file() else None
        return mise_a_jour | {
            "tentatives_cartographe": etat.get("tentatives_cartographe", 0) + 1,
            "cbom_valide": bool(validation and validation.valide),
            "erreurs_cbom": (validation.erreurs if validation else ["aucun CBOM enregistré"]),
        }

    def apres_cartographe(etat) -> str:
        if etat.get("cbom_valide"):
            return "analyste_risque"
        return "cartographe" if etat.get("tentatives_cartographe", 0) < tentatives_max else "fin"

    def noeud_analyste(etat):
        return executer(analyste_risque.configuration(horizon, **agents.get("analyste_risque", {})), etat)

    def noeud_architecte(etat):
        config = architecte.configuration(etat.get("erreurs_plan"), **agents.get("architecte", {}))
        mise_a_jour = executer(config, etat)
        cle = max((k for k in mise_a_jour["resultats"] if k.startswith("architecte")), key=lambda k: list(mise_a_jour["resultats"]).index(k))
        plan = mise_a_jour["resultats"][cle]["sortie"]
        erreurs = architecte.verifier_plan(plan, session)
        demonstration = None
        if not erreurs and demonstrer_plan:
            # Décision de méthode n° 2 : les étapes démontrables sont démontrées au laboratoire.
            from quantum_ready import verification_plan
            from quantum_ready.outils import laboratoire
            verdicts = verification_plan.classer(plan, laboratoire.verifier)
            demonstration = [dataclasses.asdict(v) for v in verdicts]
            erreurs = verification_plan.erreurs_pour_l_architecte(verdicts)
        if plan:
            ecrire_json(session.dossier / "plan.json", plan | {"verification": erreurs or "plan conforme",
                                                              "demonstration": demonstration})
        return mise_a_jour | {"tentatives_architecte": etat.get("tentatives_architecte", 0) + 1, "plan_valide": not erreurs, "erreurs_plan": erreurs}

    def apres_architecte(etat) -> str:
        if etat.get("plan_valide") or etat.get("tentatives_architecte", 0) >= tentatives_plan:
            return "validation_humaine"
        return "architecte"

    def noeud_validation(etat):
        decision = valider(session) if valider else True
        return {"validation": "acceptee" if decision else "refusee"}

    def noeud_fin(etat):
        if etat.get("resultats", {}).get("inventoriste", {}).get("arret") == "erreur_modele":
            arret = "erreur_modele"
        elif etat.get("validation") == "acceptee":
            arret = "termine"
        elif etat.get("validation") == "refusee":
            arret = "refuse_par_l_humain"
        elif not etat.get("cbom_valide") and etat.get("tentatives_cartographe"):
            arret = "cbom_invalide"
        else:
            arret = "inventaire_vide"
        return {"arret": arret}

    graphe = StateGraph(EtatOrchestrateur)
    graphe.add_node("inventoriste", noeud_inventoriste)
    graphe.add_node("cartographe", noeud_cartographe)
    graphe.add_node("analyste_risque", noeud_analyste)
    graphe.add_node("architecte", noeud_architecte)
    graphe.add_node("validation_humaine", noeud_validation)
    graphe.add_node("fin", noeud_fin)
    graphe.add_edge(START, "inventoriste")
    graphe.add_conditional_edges("inventoriste", apres_inventoriste, {"cartographe": "cartographe", "fin": "fin"})
    graphe.add_conditional_edges("cartographe", apres_cartographe, {"analyste_risque": "analyste_risque", "cartographe": "cartographe", "fin": "fin"})
    graphe.add_edge("analyste_risque", "architecte")
    graphe.add_conditional_edges("architecte", apres_architecte, {"architecte": "architecte", "validation_humaine": "validation_humaine"})
    graphe.add_edge("validation_humaine", "fin")
    graphe.add_edge("fin", END)
    return graphe.compile()


def resume_pour_humain(session: Session) -> str:
    scores = lire_json(session.fichier_scores, {})
    cbom = lire_json(session.fichier_cbom, {})
    noms = {c["bom-ref"]: c["name"] for c in cbom.get("components", [])}
    critiques = sorted((s for s in scores.items() if s[1]["priorite"] == "critique"), key=lambda s: -s[1]["score"])
    lignes = [f"CBOM : {len(noms)} composants ; {len(scores)} actifs évalués ; {len(critiques)} critiques."]
    lignes += [f"  {ref} {noms.get(ref, '?')[:50]} : score {s['score']} ({s['justification'][:80]})" for ref, s in critiques[:10]]
    plan = lire_json(session.dossier / "plan.json", {})
    if plan:
        lignes.append(f"Plan de migration : {len(plan.get('etapes', []))} étapes ; vérification : {plan.get('verification')}")
        lignes += [f"  {e['ordre']}. {e['action'][:90]} -> {e['cible']} ({e['echeance']}) [{', '.join(e['references'])}]" for e in plan.get("etapes", [])]
    return "\n".join(lignes)


def valider_dans_le_terminal(session: Session) -> bool:
    print(resume_pour_humain(session))
    return input("Valider ces résultats ? [o/N] ").strip().lower() in ("o", "oui", "y")


def executer(racine: str, dossier_session: str | None = None, modele: str = "ollama", validation: str | None = None,
             transport: str = "stdio", configuration: Path = CONFIGURATION) -> dict:
    parametres = yaml.safe_load(configuration.read_text(encoding="utf-8"))
    horodatage = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    dossier = Path(dossier_session or f"traces/{horodatage}_{modele}")
    session = Session(dossier, racine, f"SI fictif ({Path(racine).name})")
    shutil.copy(configuration, dossier / "configuration.yaml")
    if modele == "ollama":
        commun = depuis_configuration(parametres)
        choisir = lambda nom: commun  # noqa: E731 : un seul modèle pour tous les agents
    elif modele == "regles":
        from quantum_ready.agents.politiques import POLITIQUES

        choisir = lambda nom: ModeleSimule(POLITIQUES[nom], nom=f"regles-{nom}")  # noqa: E731
    else:
        raise ValueError(f"Modèle inconnu : {modele} (ollama ou regles)")
    mode = validation or parametres.get("orchestrateur", {}).get("validation_humaine", "demander")
    valider = valider_dans_le_terminal if mode == "demander" else (lambda s: True)
    etat = construire_graphe(choisir, session, parametres, transport, valider).invoke({})
    rapport = {"session": str(dossier), "racine": racine, "modele": modele, "arret": etat.get("arret"),
               "tentatives_cartographe": etat.get("tentatives_cartographe", 0), "cbom_valide": etat.get("cbom_valide", False),
               "tentatives_architecte": etat.get("tentatives_architecte", 0), "plan_valide": etat.get("plan_valide", False),
               "erreurs_plan": etat.get("erreurs_plan", []),
               "validation": etat.get("validation", "non_demandee"),
               "agents": {nom: {k: v for k, v in r.items() if k != "sortie"} | {"sortie": r.get("sortie")} for nom, r in etat.get("resultats", {}).items()}}
    ecrire_json(dossier / "rapport.json", rapport)
    return rapport


def main(argv: list[str] | None = None) -> None:
    analyseur = argparse.ArgumentParser(description="Exécute le système multi-agents Quantum-Ready sur un SI fictif.")
    analyseur.add_argument("--racine", default="si/generated/v1")
    analyseur.add_argument("--session", help="dossier de trace (par défaut traces/<horodatage>_<modèle>)")
    analyseur.add_argument("--modele", default="ollama", choices=["ollama", "regles"])
    analyseur.add_argument("--validation", choices=["demander", "accepter"])
    analyseur.add_argument("--configuration", type=Path, default=CONFIGURATION,
                           help="fichier de paramètres (par défaut config/experiment.yaml ; experiment_petit.yaml pour la CI)")
    options = analyseur.parse_args(argv)
    rapport = executer(options.racine, options.session, options.modele, options.validation, configuration=options.configuration)
    print(json.dumps({k: rapport[k] for k in ("session", "arret", "cbom_valide", "validation")}, ensure_ascii=False))


if __name__ == "__main__":
    main()
