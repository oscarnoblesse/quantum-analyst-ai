"""Agent Analyste risque : choisit x et y pour chaque actif ; score_mosca calcule."""

from __future__ import annotations

from pydantic import BaseModel, Field

from quantum_ready.agents.boucle import ConfigurationAgent, EtatBoucle
from quantum_ready.agents.communs import lire_prompt
from quantum_ready.serveur_mcp.session import Session, lire_json

NOM = "analyste_risque"


class SortieAnalyste(BaseModel):
    evalues: int = Field(description="nombre d'actifs évalués")
    critiques: list[str] = Field(default_factory=list, description="références des actifs de priorité critique")
    resume: str = Field(description="deux ou trois phrases sur les priorités")


def restants(session: Session) -> list[str]:
    references = [c["bom-ref"] for c in lire_json(session.fichier_cbom, {}).get("components", [])]
    evalues = lire_json(session.fichier_scores, {})
    return [r for r in references if r not in evalues]


def memoire(etat: EtatBoucle, session: Session) -> str:
    from quantum_ready.serveur_mcp.outils_exposes import ligne_actif

    composants = {c["bom-ref"]: c for c in lire_json(session.fichier_cbom, {}).get("components", [])}
    reste = restants(session)
    lignes = [f"{len(composants) - len(reste)} actifs évalués sur {len(composants)}."]
    if reste:
        lignes.append("Prochains actifs à évaluer, en un seul appel à score_mosca (réf | type | nom | exposition | lieu | indices) :")
        lignes += [ligne_actif(composants[r]) for r in reste[:5]]
    else:
        lignes.append("Tous les actifs sont évalués : réponds par le JSON final.")
    return "\n".join(lignes)


def configuration(horizon_menace: float = 10, max_etapes: int = 30, fenetre: int = 4) -> ConfigurationAgent:
    return ConfigurationAgent(
        nom=NOM, prompt=lire_prompt(NOM), sortie=SortieAnalyste, max_etapes=max_etapes, fenetre=fenetre, memoire=memoire,
        consigne=f"Évalue la priorité de migration de chaque actif du CBOM. Horizon de la menace retenu : z = {horizon_menace:g} ans.",
    )
