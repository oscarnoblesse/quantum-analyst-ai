"""Serveur MCP de Quantum-Ready : expose les outils déterministes aux agents.

Un serveur est lancé PAR AGENT, avec la seule liste fermée d'outils de cet agent :
un outil qui n'est pas dans la liste n'existe tout simplement pas pour lui.
Chaque appel est journalisé en JSONL dans le dossier de session.
"""
