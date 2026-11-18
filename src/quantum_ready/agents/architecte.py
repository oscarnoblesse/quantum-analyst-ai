"""Agent Architecte : plan de migration priorisé, appuyé sur le corpus de normes, vérifié par le code."""

from __future__ import annotations

import re
from datetime import date

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


def aujourdhui() -> date:
    """Date du jour, lue par le code : le modèle ne la connaît pas et ne doit pas la deviner."""
    return date.today()


def echeance_passee(echeance: str, jour: date) -> date | None:
    """La date limite si elle est antérieure au jour, sinon None.

    Accepte une date ISO (2026-03-31) ou une année (« avant 2030 » : fin de l'année). « immédiat » n'est pas daté.
    """
    try:
        m = re.search(r"\b(\d{4})-(\d{2})-(\d{2})\b", echeance)
        limite = date(*map(int, m.groups())) if m else None
        if limite is None:
            m = re.search(r"\b(20\d{2})\b", echeance)
            limite = date(int(m.group(1)), 12, 31) if m else None
    except ValueError:  # date impossible, par exemple 2026-02-31 : ce n'est pas une échéance passée
        return None
    return limite if limite and limite < jour else None


def verifier_plan(plan: dict | None, session: Session, jour: date | None = None) -> list[str]:
    """Contrôles faits par le code, sans croire le modèle : références existantes, actifs existants, critiques couverts,
    échéances non passées."""
    from quantum_ready.outils.rechercher_standard import fiches_connues

    if not plan:
        return ["aucun plan produit"]
    jour = jour or aujourdhui()
    erreurs = []
    fiches = fiches_connues()
    actifs = {c["bom-ref"] for c in lire_json(session.fichier_cbom, {}).get("components", [])}
    couverts = set()
    for etape in plan.get("etapes", []):
        if echeance_passee(str(etape.get("echeance", "")), jour):
            erreurs.append(f"étape {etape.get('ordre')} : échéance {etape.get('echeance')} déjà passée "
                           f"(date du jour : {jour.isoformat()}) ; une échéance doit être postérieure à cette date")
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
    lignes = [f"Date du jour : {aujourdhui().isoformat()}. Une échéance antérieure à cette date est refusée par le code."]
    lignes.append(f"Actifs critiques à couvrir, TOUS dans le plan ({len(critiques(session))}) : " + ", ".join(critiques(session)))
    lignes.append(f"Recherches faites ({len(recherches)}) : " + "; ".join(recherches[-6:]) if recherches else "Aucune recherche dans le corpus pour l'instant.")
    if fiches:
        lignes.append("Fiches trouvées (identifiants citables) : " + ", ".join(fiches))
    return "\n".join(lignes)


def configuration(erreurs_precedentes: list[str] | None = None, max_etapes: int = 20, fenetre: int = 6) -> ConfigurationAgent:
    consigne = "Rédige le plan de migration post-quantique priorisé du SI, étape par étape, en citant les fiches du corpus."
    if erreurs_precedentes:
        consigne += "\nTon plan précédent a été REFUSÉ par la vérification automatique :\n" + "\n".join(f"- {e}" for e in erreurs_precedentes[:8])
    memoire_agent = memoire
    if erreurs_precedentes:
        # Le refus est rappelé à CHAQUE tour, en dernier, là où un petit modèle le lit (au second essai de la v4,
        # l'Architecte avait refait le même plan : le refus, placé en début de conversation, n'était pas suivi).
        rappel = "PLAN PRÉCÉDENT REFUSÉ, ton nouveau plan doit corriger : " + " ; ".join(erreurs_precedentes[:8])
        memoire_agent = lambda etat, session: memoire(etat, session) + "\n" + rappel  # noqa: E731
    return ConfigurationAgent(nom=NOM, prompt=lire_prompt(NOM), consigne=consigne, sortie=SortieArchitecte,
                              max_etapes=max_etapes, fenetre=fenetre, memoire=memoire_agent)
