"""Dockerfile : image de base, versions des logiciels cryptographiques, fichiers copiés."""

from __future__ import annotations

import re

from quantum_ready.outils.commun import Piste, Trouvaille
from quantum_ready.outils.configurations import defauts

NOM = "analyser_configuration"
PAQUETS_CRYPTO = {
    "openssh-server": "OpenSSH", "openssh-client": "OpenSSH", "openssl": "OpenSSL", "libssl3": "OpenSSL",
    "libssl1.1": "OpenSSL", "gnupg": "GnuPG", "gpg": "GnuPG", "nginx": "nginx", "libgcrypt20": "Libgcrypt",
}


def instructions(texte: str) -> list[tuple[int, str, str]]:
    """(ligne, INSTRUCTION, arguments), les lignes terminées par « \\ » étant recollées."""
    resultat, tampon, debut = [], "", 0
    for numero, ligne in enumerate(texte.splitlines(), start=1):
        if not tampon:
            if not ligne.strip() or ligne.lstrip().startswith("#"):
                continue
            debut = numero
        tampon += ligne.rstrip().removesuffix("\\") + " "
        if not ligne.rstrip().endswith("\\"):
            mots = tampon.split(None, 1)
            resultat.append((debut, mots[0].upper(), mots[1].strip() if len(mots) > 1 else ""))
            tampon = ""
    return resultat


def _version_upstream(version_paquet: str) -> str:
    """« 1:9.6p1-3ubuntu13.5 » -> « 9.6p1 » (on retire l'époque et la révision Debian)."""
    return version_paquet.split(":")[-1].split("-")[0]


def kex_post_quantique(version: str) -> str | None:
    nombres = re.match(r"(\d+)\.(\d+)", version)
    if not nombres:
        return None
    courante = (int(nombres.group(1)), int(nombres.group(2)))
    return next((kex for minimum, kex in defauts.KEX_POST_QUANTIQUE_OPENSSH if courante >= minimum), None)


def analyser(texte: str, fichier: str) -> tuple[list[Trouvaille], list[Piste]]:
    trouvailles, pistes, image = [], [], ""
    for ligne, instruction, arguments in instructions(texte):
        if instruction == "FROM":
            image = arguments.split()[0]
        elif instruction == "RUN" and re.search(r"\b(apt-get|apt|apk|dnf|yum)\b.*\binstall\b", arguments):
            for mot in arguments.replace(";", " ").replace("&&", " ").split():
                paquet, _, version = mot.partition("=")
                if paquet not in PAQUETS_CRYPTO:
                    continue
                logiciel = PAQUETS_CRYPTO[paquet]
                props: dict = {"paquet": paquet, "image_de_base": image}
                if version:
                    amont = _version_upstream(version)
                    props |= {"version_paquet": version, "version": amont}
                    nom = f"{logiciel} {amont}"
                    if logiciel == "OpenSSH" and (kex := kex_post_quantique(amont)):
                        props["kex_post_quantique_par_defaut"] = kex
                else:
                    props["version"] = f"non figée : celle du dépôt de {image}"
                    nom = f"{logiciel} (version de l'image {image})"
                trouvailles.append(Trouvaille(
                    outil=NOM, fichier=fichier, ligne=ligne, type_actif="library", nom=nom,
                    description=f"{logiciel} installé dans l'image ({paquet})", exposition="aucune",
                    proprietes=props, preuve=mot,
                ))
        elif instruction in ("COPY", "ADD"):
            mots = [m for m in arguments.split() if not m.startswith("--")]
            for source in mots[:-1]:
                pistes.append(Piste(vers=source, raison=f"copié dans l'image vers {mots[-1]} (ligne {ligne})"))
    return trouvailles, pistes
