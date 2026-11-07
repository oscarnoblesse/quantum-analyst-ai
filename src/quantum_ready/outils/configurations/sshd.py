"""Configuration du serveur OpenSSH (sshd_config).

Les listes d'algorithmes acceptent quatre écritures (sshd_config(5)) :
« a,b » remplace la liste par défaut, « +a » l'ajoute à la fin, « -a » la retire,
« ^a » la place en tête. Une directive absente laisse la valeur par défaut : un
actif implicite. Écrire une liste explicite peut aussi RETIRER un algorithme
post-quantique présent par défaut : c'est une régression que l'outil signale.
"""

from __future__ import annotations

import fnmatch
import re

from pathlib import Path

from quantum_ready.outils.classification import exposition, exposition_la_pire
from quantum_ready.outils.commun import Piste, Trouvaille
from quantum_ready.outils.configurations import defauts

NOM = "analyser_configuration"
ROLES = {
    "KexAlgorithms": "Échange de clés (KexAlgorithms)",
    "Ciphers": "Chiffrement de la session (Ciphers)",
    "MACs": "Intégrité des messages (MACs)",
    "HostKeyAlgorithms": "Algorithmes de signature des clés d'hôte (HostKeyAlgorithms)",
    "PubkeyAcceptedAlgorithms": "Algorithmes acceptés pour les clés des utilisateurs (PubkeyAcceptedAlgorithms)",
}
TYPES = {"KexAlgorithms": "algorithm", "Ciphers": "algorithm", "MACs": "algorithm", "HostKeyAlgorithms": "algorithm", "PubkeyAcceptedAlgorithms": "algorithm"}
_LIGNE = re.compile(r"^\s*(\w+)\s*(?:=\s*|\s+)(.+?)\s*$")


def directives(texte: str) -> dict[str, list[tuple[int, str]]]:
    """Directives (insensibles à la casse) -> occurrences (ligne, valeur). Arrêt au premier bloc Match."""
    trouvees: dict[str, list[tuple[int, str]]] = {}
    noms = {nom.lower(): nom for nom in [*ROLES, "HostKey", "PubkeyAcceptedKeyTypes"]}
    for numero, ligne in enumerate(texte.splitlines(), start=1):
        if ligne.strip().startswith("#") or not ligne.strip():
            continue
        correspondance = _LIGNE.match(ligne)
        if not correspondance:
            continue
        nom = correspondance.group(1)
        if nom.lower() == "match":
            break
        nom = noms.get(nom.lower(), nom)
        if nom == "PubkeyAcceptedKeyTypes":  # ancien nom de la même directive
            nom = "PubkeyAcceptedAlgorithms"
        trouvees.setdefault(nom, []).append((numero, correspondance.group(2)))
    return trouvees


def appliquer(valeur: str, defaut: list[str]) -> list[str]:
    """Liste effective selon l'écriture de la directive (remplacement, +, -, ^)."""
    if valeur.startswith("+"):
        return defaut + [a for a in valeur[1:].split(",") if a not in defaut]
    if valeur.startswith("-"):
        motifs = valeur[1:].split(",")
        return [a for a in defaut if not any(fnmatch.fnmatch(a, m) for m in motifs)]
    if valeur.startswith("^"):
        tete = valeur[1:].split(",")
        return tete + [a for a in defaut if a not in tete]
    return valeur.split(",")


def version_dans_le_si(racine: Path) -> tuple[tuple[int, int] | None, str]:
    """Version d'OpenSSH figée dans un Dockerfile du SI, si elle est unique."""
    from quantum_ready.outils.configurations import dockerfile

    versions = {}
    for chemin in sorted(racine.rglob("*")):
        if chemin.is_file() and chemin.name.lower().startswith(("dockerfile", "containerfile")):
            trouvailles, _ = dockerfile.analyser(chemin.read_text(encoding="utf-8", errors="replace"), chemin.relative_to(racine).as_posix())
            for t in trouvailles:
                if t.nom.startswith("OpenSSH ") and (m := re.match(r"(\d+)\.(\d+)", str(t.proprietes.get("version", "")))):
                    versions[(int(m.group(1)), int(m.group(2)))] = t.fichier
    if len(versions) == 1:
        version, source = next(iter(versions.items()))
        return version, source
    return None, "plusieurs versions dans le SI" if versions else "aucune version trouvée dans le SI"


def lire_version(texte: str) -> tuple[int, int] | None:
    m = re.match(r"\D*(\d+)\.(\d+)", texte or "")
    return (int(m.group(1)), int(m.group(2))) if m else None


def est_obsolete(algorithme: str) -> bool:
    """Algorithmes SSH retirés ou déconseillés : SHA-1, DSA, groupe DH 1024 bits, 3DES, modes CBC."""
    return algorithme.startswith(("ssh-rsa", "ssh-dss", "hmac-sha1", "diffie-hellman-group1-", "diffie-hellman-group-exchange-sha1", "3des")) or algorithme.endswith("-cbc")


def version_du_contexte(contexte) -> tuple[tuple[int, int] | None, str]:
    options = getattr(contexte, "options", {}) or {}
    version, origine = lire_version(str(options.get("version_openssh", ""))), "indiquée par l'agent"
    if version is None and contexte is not None:
        version, origine = version_dans_le_si(contexte.racine)
        origine = f"lue dans {origine}" if version else origine
    return version, origine


def analyser_client(texte: str, fichier: str, contexte=None) -> tuple[list[Trouvaille], list[Piste]]:
    """Configuration du CLIENT SSH (ssh_config, ~/.ssh/config) : réglages par bloc « Host ».

    Seules les directives écrites donnent une trouvaille : un bloc Host ne concerne
    que les serveurs qu'il désigne, et ce qui n'est pas écrit reprend la valeur par
    défaut du client, déjà inventoriée côté serveur.
    """
    version, origine = version_du_contexte(contexte)
    listes, source = defauts.openssh(version)
    noms = {nom.lower(): nom for nom in ROLES}
    trouvailles, pistes, hote = [], [], "*"
    for numero, ligne in enumerate(texte.splitlines(), start=1):
        if not ligne.strip() or ligne.strip().startswith("#") or not (correspondance := _LIGNE.match(ligne)):
            continue
        directive, valeur = correspondance.group(1), correspondance.group(2)
        if directive.lower() in ("host", "match"):
            hote = valeur
            continue
        if directive.lower() == "stricthostkeychecking" and valeur.lower() in ("no", "off", "accept-new"):
            trouvailles.append(Trouvaille(
                outil=NOM, fichier=fichier, ligne=numero, type_actif="protocol", nom=f"StrictHostKeyChecking {valeur}",
                description=f"Vérification de la clé d'hôte assouplie par le client SSH pour « {hote} »", exposition="shor",
                proprietes={"hotes": hote.split(), "faiblesse_classique": "homme du milieu possible à la première connexion (ou toujours avec « no »)"},
                preuve=ligne.strip(),
            ))
        if directive.lower() not in noms:
            continue
        directive = noms[directive.lower()]
        effective = appliquer(valeur, listes[directive])
        props: dict = {"algorithmes": effective, "hotes": hote.split(), "role": "client", "source_des_valeurs_par_defaut": source,
                       "version_openssh": f"{version[0]}.{version[1]} ({origine})" if version else f"inconnue ({origine})"}
        obsoletes = [a for a in effective if est_obsolete(a)]
        if obsoletes:
            props["faiblesse_classique"] = "algorithmes obsolètes réactivés pour ce client : " + ", ".join(obsoletes)
        trouvailles.append(Trouvaille(
            outil=NOM, fichier=fichier, ligne=numero, type_actif="algorithm", nom=",".join(effective),
            description=f"{ROLES[directive]} du client SSH pour « {hote} »", exposition=exposition_la_pire(effective),
            proprietes=props, preuve=ligne.strip(),
        ))
    return trouvailles, pistes


def analyser(texte: str, fichier: str, contexte=None) -> tuple[list[Trouvaille], list[Piste]]:
    d = directives(texte)
    trouvailles, pistes = [], []
    version, origine = version_du_contexte(contexte)
    listes, source = defauts.openssh(version)
    for directive, role in ROLES.items():
        defaut = listes[directive]
        if directive in d:
            ligne, valeur = d[directive][0]  # sshd retient la PREMIÈRE occurrence
            effective = appliquer(valeur, defaut)
            props: dict = {"algorithmes": effective, "ecriture": "liste explicite" if valeur[0] not in "+-^" else f"modification « {valeur[0]} » de la valeur par défaut"}
            retires = [a for a in defaut if exposition(a) == "resistant" and a not in effective]
            if retires:
                props["post_quantique_retire"] = retires
                props["regression"] = "la liste écrite retire l'échange post-quantique hybride proposé par défaut par OpenSSH"
            if any(est_obsolete(a) for a in effective):
                props["faiblesse_classique"] = "algorithmes obsolètes dans la liste"
            trouvailles.append(Trouvaille(
                outil=NOM, fichier=fichier, ligne=ligne, type_actif=TYPES[directive], nom=",".join(effective),
                description=f"{role} du serveur SSH", exposition=exposition_la_pire(effective),
                proprietes=props, preuve=f"{directive} {valeur}",
            ))
        elif directive == "PubkeyAcceptedAlgorithms":
            trouvailles.append(Trouvaille(
                outil=NOM, fichier="", type_actif="algorithm", nom=",".join(a for a in defaut if "cert-v01" not in a),
                description=f"{role} : directive absente, OpenSSH applique sa liste par défaut",
                exposition=exposition_la_pire(defaut), implicite=True,
                proprietes={"algorithmes": defaut, "source": source},
                preuve=f"{directive} absente de {fichier}",
            ))
        else:
            trouvailles.append(Trouvaille(
                outil=NOM, fichier="", type_actif=TYPES[directive], nom=",".join(defaut),
                description=f"{role} : directive absente, OpenSSH applique sa liste par défaut",
                exposition=exposition_la_pire(defaut), implicite=True,
                proprietes={"algorithmes": defaut, "source": source},
                preuve=f"{directive} absente de {fichier}",
            ))
    for ligne, chemin in d.get("HostKey", []):
        pistes.append(Piste(vers=chemin, raison=f"clé d'hôte du serveur (HostKey, ligne {ligne})"))
    for trouvaille in trouvailles:
        trouvaille.proprietes["version_openssh"] = f"{version[0]}.{version[1]} ({origine})" if version else f"inconnue ({origine})"
    if version is None:
        pistes.append(Piste(vers="version d'OpenSSH", raison="version inconnue : les valeurs par défaut sont une HYPOTHÈSE (OpenSSH 9.6) ; "
                            "trouver la version installée, puis rappeler l'outil avec version_openssh"))
    return trouvailles, pistes
