"""Agent Architecte : plan de migration priorisé, appuyé sur le corpus de normes, vérifié par le code."""

from __future__ import annotations

from pydantic import BaseModel, Field

from quantum_ready.agents.boucle import ConfigurationAgent, EtatBoucle
from quantum_ready.agents.communs import lire_prompt
from quantum_ready.serveur_mcp.session import Session, lire_json

NOM = "architecte"


class Etape(BaseModel):
    ordre: int = Field(description="1 pour la plus urgente")
    actifs: list[str] = Field(description="références des actifs concernés (crypto-...)")
    action: str = Field(description="ce qu'il faut faire, concrètement")
    cible: str = Field(description="algorithme, protocole ou version visés")
    echeance: str = Field(description="immédiat, avant 2030, avant 2035...")
    references: list[str] = Field(description="identifiants des fiches du corpus qui justifient l'étape")


class SortieArchitecte(BaseModel):
    etapes: list[Etape] = Field(description="étapes du plan, de la plus urgente à la moins urgente")
    resume: str = Field(description="trois phrases au plus sur la stratégie")


def critiques(session: Session) -> list[str]:
    scores = lire_json(session.fichier_scores, {})
    return sorted(ref for ref, s in scores.items() if s.get("priorite") == "critique")


def verifier_plan(plan: dict | None, session: Session) -> list[str]:
    """Contrôles faits par le code, sans croire le modèle : références existantes, actifs existants, critiques couverts."""
    from quantum_ready.outils.rechercher_standard import fiches_connues

    if not plan:
        return ["aucun plan produit"]
    erreurs = []
    fiches = fiches_connues()
    actifs = {c["bom-ref"] for c in lire_json(session.fichier_cbom, {}).get("components", [])}
    couverts = set()
    for etape in plan.get("etapes", []):
        inconnues = [r for r in etape.get("references", []) if r not in fiches]
        if not etape.get("references"):
            erreurs.append(f"étape {etape.get('ordre')} : aucune référence au corpus")
        if inconnues:
            erreurs.append(f"étape {etape.get('ordre')} : références inconnues du corpus : {', '.join(inconnues)}")
        absents = [a for a in etape.get("actifs", []) if a not in actifs]
        if absents:
            erreurs.append(f"étape {etape.get('ordre')} : actifs absents du CBOM : {', '.join(absents[:5])}")
        couverts |= set(etape.get("actifs", []))
    oublies = [c for c in critiques(session) if c not in couverts]
    if oublies:
        erreurs.append(f"{len(oublies)} actif(s) critique(s) non couvert(s) : {', '.join(oublies[:10])}")
    if not plan.get("etapes"):
        erreurs.append("le plan ne contient aucune étape")
    return erreurs


def memoire(etat: EtatBoucle, session: Session) -> str:
    recherches = [a.arguments.get("requete", "") for a in etat.appels if a.nom == "rechercher_standard"]
    fiches = sorted({ligne.split("]")[0][1:] for a in etat.appels if a.nom == "rechercher_standard" for ligne in a.texte.splitlines() if ligne.startswith("[")})
    lignes = [f"Actifs critiques à couvrir ({len(critiques(session))}) : " + ", ".join(critiques(session)[:20])]
    lignes.append(f"Recherches faites ({len(recherches)}) : " + "; ".join(recherches[-6:]) if recherches else "Aucune recherche dans le corpus pour l'instant.")
    if fiches:
        lignes.append("Fiches trouvées (identifiants citables) : " + ", ".join(fiches))
    return "\n".join(lignes)


def configuration(erreurs_precedentes: list[str] | None = None, max_etapes: int = 20, fenetre: int = 6) -> ConfigurationAgent:
    consigne = "Rédige le plan de migration post-quantique priorisé du SI, étape par étape, en citant les fiches du corpus."
    if erreurs_precedentes:
        consigne += "\nTon plan précédent a été REFUSÉ par la vérification automatique :\n" + "\n".join(f"- {e}" for e in erreurs_precedentes[:8])
    return ConfigurationAgent(nom=NOM, prompt=lire_prompt(NOM), consigne=consigne, sortie=SortieArchitecte,
                              max_etapes=max_etapes, fenetre=fenetre, memoire=memoire)
