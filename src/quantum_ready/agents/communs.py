"""Éléments partagés par les agents : lecture des prompts, exécution d'un agent avec son serveur MCP."""

from __future__ import annotations

from importlib import resources

from quantum_ready.agents.boucle import ConfigurationAgent, ResultatAgent, executer_agent
from quantum_ready.llm import Modele
from quantum_ready.serveur_mcp.client import ouvrir_outils
from quantum_ready.serveur_mcp.session import Session


def lire_prompt(nom: str) -> str:
    return resources.files("quantum_ready").joinpath("prompts", f"{nom}.md").read_text(encoding="utf-8").strip()


async def lancer(config: ConfigurationAgent, modele: Modele, session: Session, horizon_menace: float = 10, transport: str = "stdio") -> ResultatAgent:
    """Ouvre le serveur MCP de l'agent (sa liste fermée d'outils) et exécute sa boucle."""
    async with ouvrir_outils(config.nom, session, horizon_menace, transport) as outils:
        return await executer_agent(config, modele, outils, session)
