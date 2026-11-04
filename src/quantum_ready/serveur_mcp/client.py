"""Côté agent : un client MCP qui découvre les outils autorisés et les appelle."""

from __future__ import annotations

import sys
from contextlib import asynccontextmanager
from pathlib import Path

from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

from quantum_ready.serveur_mcp.session import Session


class ClientOutils:
    """Les outils d'un agent, vus à travers MCP."""

    def __init__(self, client: ClientSession, agent: str):
        self.client = client
        self.agent = agent
        self.schemas: list[dict] = []

    async def charger(self) -> None:
        """Liste les outils exposés par le serveur, au format attendu par le modèle (fonctions JSON Schema)."""
        outils = (await self.client.list_tools()).tools
        self.schemas = [{"type": "function", "function": {"name": o.name, "description": o.description or "", "parameters": o.inputSchema}} for o in outils]

    @property
    def noms(self) -> set[str]:
        return {s["function"]["name"] for s in self.schemas}

    async def appeler(self, nom: str, arguments: dict) -> tuple[str, bool]:
        """(texte du résultat, True si erreur). Les erreurs d'arguments reviennent comme texte lisible par le modèle."""
        resultat = await self.client.call_tool(nom, arguments)
        texte = "\n".join(c.text for c in resultat.content if getattr(c, "type", "") == "text")
        return texte, bool(resultat.isError) or texte.startswith("ERREUR")


@asynccontextmanager
async def ouvrir_outils(agent: str, session: Session, horizon_menace: float = 10, transport: str = "stdio"):
    """Ouvre la connexion MCP d'un agent. transport="stdio" : vrai processus serveur ; "memoire" : tests."""
    if transport == "memoire":
        from mcp.shared.memory import create_connected_server_and_client_session

        from quantum_ready.serveur_mcp.serveur import creer_serveur

        serveur = creer_serveur(agent, session, horizon_menace)
        async with create_connected_server_and_client_session(serveur._mcp_server) as client:
            outils = ClientOutils(client, agent)
            await outils.charger()
            yield outils
        return
    parametres = StdioServerParameters(
        command=sys.executable,
        args=["-m", "quantum_ready.serveur_mcp", "--agent", agent, "--session", str(Path(session.dossier).resolve()),
              "--racine", str(session.racine_si), "--horizon", str(horizon_menace), "--nom-systeme", session.nom_systeme],
    )
    async with stdio_client(parametres) as (lecture, ecriture), ClientSession(lecture, ecriture) as client:
        await client.initialize()
        outils = ClientOutils(client, agent)
        await outils.charger()
        yield outils
