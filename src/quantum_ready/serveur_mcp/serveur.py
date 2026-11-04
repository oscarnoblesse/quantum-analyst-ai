"""Construction du serveur MCP d'un agent : liste fermée d'outils et journal d'audit."""

from __future__ import annotations

import functools
import time
from collections.abc import Callable

from mcp.server.fastmcp import FastMCP

from quantum_ready.outils import outils_autorises
from quantum_ready.serveur_mcp.outils_exposes import creer_outils
from quantum_ready.serveur_mcp.session import Session

JOURNAL = "journal_outils.jsonl"


def _journalise(fonction: Callable[..., str], session: Session, agent: str) -> Callable[..., str]:
    @functools.wraps(fonction)
    def enveloppe(*args, **kwargs) -> str:
        debut = time.monotonic()
        arguments = {k: ([v.model_dump() if hasattr(v, "model_dump") else v for v in valeur] if isinstance(valeur, list) else valeur)
                     for k, valeur in kwargs.items()}
        try:
            sortie = fonction(*args, **kwargs)
        except Exception as erreur:
            session.journaliser(JOURNAL, {"agent": agent, "outil": fonction.__name__, "arguments": arguments, "statut": "exception",
                                          "duree_ms": int((time.monotonic() - debut) * 1000), "erreur": f"{type(erreur).__name__}: {erreur}"})
            raise
        statut = "erreur" if "ERREUR" in sortie else "ok"
        session.journaliser(JOURNAL, {"agent": agent, "outil": fonction.__name__, "arguments": arguments, "statut": statut,
                                      "duree_ms": int((time.monotonic() - debut) * 1000), "sortie": sortie})
        return sortie

    return enveloppe


def creer_serveur(agent: str, session: Session, horizon_menace: float = 10) -> FastMCP:
    """Serveur MCP qui n'expose QUE les outils de la liste fermée de l'agent."""
    autorises = outils_autorises(agent)
    if not autorises:
        raise ValueError(f"Agent inconnu ou sans outil : {agent}")
    serveur = FastMCP(f"quantum-ready-{agent}", instructions=f"Outils de l'agent {agent} de Quantum-Ready, sur un SI fictif uniquement.", log_level="WARNING")
    disponibles = creer_outils(session, agent, horizon_menace)
    for nom in autorises:
        if nom in disponibles:
            fonction = _journalise(disponibles[nom], session, agent)
            serveur.add_tool(fonction, name=nom, description=(disponibles[nom].__doc__ or "").strip())
    return serveur
