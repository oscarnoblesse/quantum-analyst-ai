"""Outil scan_tls_lab : interroge le serveur TLS du laboratoire (démonstrateur), en local uniquement.

Ce que l'outil observe, par des connexions réelles :
- les groupes d'échange de clés que le serveur accepte (X25519MLKEM768, X25519) ;
- la version de TLS négociée avec un client TLS 1.3.

Périmètre : seule une cible locale (127.0.0.1, localhost, ::1) est acceptée. Un balayage
d'un système qui n'est pas le laboratoire est refusé par le code, quelle que soit la demande.
Le client est l'OpenSSL de la machine ; sa version est notée dans la trouvaille, car
X25519MLKEM768 n'existe qu'à partir d'OpenSSL 3.5.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

from quantum_ready.outils.classification import exposition
from quantum_ready.outils.commun import ErreurOutil, Resultat, Trouvaille, outil

NOM = "scan_tls_lab"
HOTES_LOCAUX = ("127.0.0.1", "localhost", "::1")
GROUPES_TESTES = ("X25519MLKEM768", "X25519")
DELAI_SECONDES = 10
_GROUPE_NEGOCIE = re.compile(r"Negotiated TLS1\.3 group: (\S+)")
# OpenSSL n'écrit « Negotiated TLS1.3 group » que pour certains groupes ; pour X25519 il écrit « Peer Temp Key ».
_CLE_TEMPORAIRE = re.compile(r"Peer Temp Key: ([\w.]+)")
_VERSION_NEGOCIEE = re.compile(r"^\s*Protocol\s*:\s*(\S+)", re.M)


def separer_cible(cible: str) -> tuple[str, int]:
    """« hôte:port » -> (hôte, port). Refuse tout hôte qui n'est pas local."""
    hote, _, port = cible.rpartition(":")
    if not hote or not port.isdigit():
        raise ErreurOutil("Cible attendue sous la forme « 127.0.0.1:8443 »")
    if hote.strip("[]") not in HOTES_LOCAUX:
        raise ErreurOutil(f"Refusé : {hote} n'est pas local. Seul le serveur du laboratoire est scanné.")
    return hote.strip("[]"), int(port)


def groupe_negocie(sortie: str) -> str | None:
    """Groupe d'échange de clés de la sortie d'un `openssl s_client`, None si aucun n'a été négocié."""
    correspondance = _GROUPE_NEGOCIE.search(sortie)
    if correspondance is not None and correspondance.group(1) != "<NULL>":
        return correspondance.group(1)
    cle = _CLE_TEMPORAIRE.search(sortie)
    return cle.group(1) if cle else None


def version_negociee(sortie: str) -> str | None:
    correspondance = _VERSION_NEGOCIEE.search(sortie)
    return correspondance.group(1) if correspondance else None


def version_openssl() -> str | None:
    if shutil.which("openssl") is None:
        return None
    return subprocess.run(["openssl", "version"], capture_output=True, text=True, timeout=10).stdout.strip()


def _sonder(hote: str, port: int, groupes: str) -> str:
    """Une connexion TLS 1.3 proposant seulement `groupes`. Renvoie la sortie d'openssl."""
    commande = ["openssl", "s_client", "-connect", f"{hote}:{port}", "-tls1_3", "-groups", groupes]
    resultat = subprocess.run(commande, input="", capture_output=True, text=True, timeout=DELAI_SECONDES)
    return resultat.stdout + resultat.stderr


@outil(NOM)
def scan_tls_lab(cible: str, racine: Path) -> Resultat:
    """Sonde le serveur TLS du laboratoire : groupes acceptés et version de TLS négociée."""
    hote, port = separer_cible(cible)
    version = version_openssl()
    if version is None:
        raise ErreurOutil("openssl est introuvable sur cette machine")

    acceptes: list[str] = []
    protocole = None
    preuve = ""
    for groupe in GROUPES_TESTES:
        sortie = _sonder(hote, port, groupe)
        negocie = groupe_negocie(sortie)
        if negocie is not None:
            acceptes.append(negocie)
            protocole = protocole or version_negociee(sortie)
        if not preuve:
            preuve = next((ligne for ligne in sortie.splitlines() if "group" in ligne.lower()), "")

    trouvailles: list[Trouvaille] = []
    endroit = f"{hote}:{port}"
    if protocole:
        trouvailles.append(Trouvaille(
            outil=NOM, fichier="", type_actif="protocol", nom=protocole, exposition="inconnue",
            description=f"version de TLS négociée par le serveur du laboratoire ({endroit})",
            proprietes={"endroit": endroit, "client": version},
        ))
    for groupe in acceptes:
        trouvailles.append(Trouvaille(
            outil=NOM, fichier="", type_actif="algorithm", nom=groupe, exposition=exposition(groupe),
            description=f"groupe d'échange de clés accepté par le serveur du laboratoire ({endroit})",
            proprietes={"endroit": endroit, "client": version},
            preuve=preuve,
        ))
    if not acceptes:
        raise ErreurOutil(f"aucun groupe d'échange de clés négocié avec {endroit} : serveur arrêté ou injoignable ?")
    return Resultat(outil=NOM, cible=cible, trouvailles=trouvailles)


def main(argv: list[str] | None = None) -> int:
    """Commande : python -m quantum_ready.outils.scan_tls_lab 127.0.0.1:8443"""
    import sys
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 1:
        print("Utilisation : python -m quantum_ready.outils.scan_tls_lab <hôte:port>  (ex. 127.0.0.1:8443)", file=sys.stderr)
        return 2
    resultat = scan_tls_lab(argv[0], racine=Path("."))
    for erreur in resultat.erreurs:
        print(f"Erreur : {erreur}", file=sys.stderr)
    for t in resultat.trouvailles:
        print(f"{t.type_actif:<10} {t.nom:<18} exposition={t.exposition:<9} {t.description}")
    return 1 if resultat.erreurs else 0


if __name__ == "__main__":
    raise SystemExit(main())
