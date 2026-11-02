"""Outil analyser_configuration : fichiers de configuration, scripts et images.

Le format est reconnu d'après le contenu (comme lister_fichiers), puis confié
au module du dossier configurations/ qui sait le lire. Les chemins de fichiers
cités dans une configuration (certificat, clé...) sont renvoyés comme pistes,
relatifs à la racine du SI quand ils y existent.
"""

from __future__ import annotations

from pathlib import Path

from quantum_ready.outils.commun import ErreurOutil, Piste, Resultat, outil, relatif, resoudre
from quantum_ready.outils.configurations import nginx, sshd
from quantum_ready.outils.lister_fichiers import reconnaitre

NOM = "analyser_configuration"
ANALYSEURS = {
    "config_nginx": nginx.analyser,
    "config_sshd": sshd.analyser,
}


def _situer(piste: Piste, dossier: Path, racine: Path) -> Piste:
    """Une piste « ssl/server.key » devient « nginx/ssl/server.key » si ce fichier existe dans le SI.

    Un chemin absolu (« /etc/ssh/ssh_host_rsa_key ») désigne un fichier de la machine
    cible : on cherche alors un fichier de même nom à côté de la configuration.
    """
    if piste.vers.startswith("/"):
        voisin = dossier / Path(piste.vers).name
        if voisin.is_file():
            return Piste(vers=relatif(voisin, racine), raison=f"{piste.raison} ; {piste.vers} sur la machine, fichier de même nom trouvé ici")
        return piste
    for base in (dossier, *dossier.parents):
        candidat = (base / piste.vers).resolve()
        if candidat.is_relative_to(racine) and candidat.is_file():
            return Piste(vers=relatif(candidat, racine), raison=piste.raison)
        if base == racine:
            break
    return piste


@outil(NOM)
def analyser_configuration(cible: str, racine: Path) -> Resultat:
    """Analyse un fichier de configuration (nginx, sshd, PostgreSQL, .env, Dockerfile, script shell)."""
    chemin = resoudre(cible, racine)
    fichier = relatif(chemin, racine)
    texte = chemin.read_text(encoding="utf-8", errors="replace")
    nature = reconnaitre(texte.encode()[:8192])
    if nature not in ANALYSEURS:
        raise ErreurOutil(f"Format non pris en charge par cet outil (nature reconnue : {nature})")
    trouvailles, pistes = ANALYSEURS[nature](texte, fichier)
    pistes = [_situer(p, chemin.parent, racine) for p in pistes]
    return Resultat(outil=NOM, cible=fichier, trouvailles=trouvailles, pistes=pistes)
