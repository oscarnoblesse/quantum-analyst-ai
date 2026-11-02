"""Outils déterministes : toute la cryptographie et tous les calculs sont faits ici, jamais par le modèle.

LISTES_FERMEES donne, pour chaque agent, les SEULS outils qu'il a le droit
d'appeler. Le serveur MCP et l'orchestrateur s'appuieront sur ce dictionnaire :
un agent qui demande un outil hors de sa liste reçoit un refus, journalisé.
"""

from __future__ import annotations

LISTES_FERMEES: dict[str, tuple[str, ...]] = {
    "inventoriste": (
        "lister_fichiers",
        "analyser_x509",
        "analyser_cle",           # rôle de « ssh-keygen -l » dans le sujet
        "analyser_pkcs12",
        "analyser_configuration",
        "scanner_code_crypto",    # rôle de « semgrep_crypto » dans le sujet
        "analyser_dependances",
        # scan_tls_lab : avec le démonstrateur (il faut un serveur TLS du laboratoire en marche)
    ),
    "cartographe": ("construire_cbom", "valider_schema"),
    "analyste_risque": ("score_mosca",),
    "architecte": (),     # rechercher_standard (RAG FIPS/ANSSI/NIST) : étape suivante
    "demonstrateur": (),  # openssl >= 3.5 et bench_pqc : étape du démonstrateur
}


def outils_autorises(agent: str) -> tuple[str, ...]:
    """Liste fermée d'un agent ; un agent inconnu n'a droit à rien."""
    return LISTES_FERMEES.get(agent, ())
