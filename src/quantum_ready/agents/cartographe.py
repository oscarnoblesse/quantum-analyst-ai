"""Agent Cartographe : choisit les exclusions, construit et valide le CBOM."""

from __future__ import annotations

from pydantic import BaseModel, Field

from quantum_ready.agents.boucle import ConfigurationAgent, EtatBoucle
from quantum_ready.agents.communs import lire_prompt
from quantum_ready.agents.inventoriste import Exclusion
from quantum_ready.serveur_mcp.session import Session

NOM = "cartographe"


class SortieCartographe(BaseModel):
    cbom_valide: bool = Field(description="true si valider_schema a répondu CBOM VALIDE")
    composants: int = Field(description="nombre de composants du CBOM")
    exclusions: list[Exclusion] = Field(default_factory=list, description="trouvailles exclues du CBOM")
    resume: str = Field(description="une ou deux phrases")


def memoire(etat: EtatBoucle, session: Session) -> str:
    validations = [a for a in etat.appels if a.nom == "valider_schema"]
    constructions = [a for a in etat.appels if a.nom == "construire_cbom" and not a.erreur]
    if not constructions:
        return f"{len(session.trouvailles())} trouvailles enregistrées. Aucun CBOM construit pour l'instant."
    etat_cbom = validations[-1].texte.splitlines()[0] if validations and etat.appels.index(validations[-1]) > etat.appels.index(constructions[-1]) else "pas encore validé"
    return f"Dernière construction : {constructions[-1].texte.splitlines()[0]}\nValidation : {etat_cbom}"


def configuration(exclusions_proposees: list[dict] | None = None, max_etapes: int = 12, fenetre: int = 4) -> ConfigurationAgent:
    proposees = exclusions_proposees or []
    consigne = "Construis le CBOM CycloneDX 1.6 du SI à partir des trouvailles de l'inventaire, puis valide-le."
    if proposees:
        consigne += "\nExclusions proposées par l'Inventoriste :\n" + "\n".join(f"- {e['id']} : {e['raison']}" for e in proposees)
    else:
        consigne += "\nL'Inventoriste n'a proposé aucune exclusion."
    return ConfigurationAgent(nom=NOM, prompt=lire_prompt(NOM), consigne=consigne, sortie=SortieCartographe,
                              max_etapes=max_etapes, fenetre=fenetre, memoire=memoire)
