"""Fichiers de configuration du SI fictif, écrits à partir des modèles de modeles/.

Chaque fonction couvre un service. Les valeurs cryptographiques sont dans les modèles,
telles qu'un administrateur les aurait écrites ; seuls les secrets sont injectés.
"""

from __future__ import annotations

from quantum_ready.si_fictif.generateur import Contexte


def generer_config_ssh(ctx: Contexte) -> None:
    """Serveur SSH : QR-027 à QR-031 (sshd_config) et QR-033 (version d'OpenSSH).

    QR-031 est un actif implicite : PubkeyAcceptedAlgorithms n'apparaît volontairement
    pas dans sshd_config, ce sont les valeurs par défaut d'OpenSSH qui s'appliquent.
    """
    ctx.ecrire_modele("ssh/server/sshd_config")
    ctx.ecrire_modele("ssh/Dockerfile")
