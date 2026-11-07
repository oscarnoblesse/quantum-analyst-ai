"""Évaluation d'un système d'inventaire contre la vérité terrain, et comparaison de systèmes.

Contrat : un système évalué produit un DOSSIER DE SESSION contenant au minimum
`cbom.json` (CycloneDX 1.6). S'il contient aussi `journal_outils.jsonl` et
`journal_agents.jsonl` (format de quantum_ready.serveur_mcp.session), les coûts
(appels d'outils, tours, jetons, durée) sont mesurés. Deux implémentations
d'agents différentes sont ainsi comparées sur exactement le même examen.
"""
