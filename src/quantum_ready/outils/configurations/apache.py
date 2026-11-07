"""Configuration Apache httpd (mod_ssl).

Grammaire : une directive par ligne (« Nom arguments »), des sections
« <VirtualHost ...> ... </VirtualHost> », des lignes prolongées par « \\ », et
Include / IncludeOptional. Les directives SSL* du niveau global s'appliquent aux
VirtualHost qui ne les redéfinissent pas ; chaque VirtualHost avec
« SSLEngine on » est évalué à part.
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass

from quantum_ready.outils.classification import exposition, exposition_la_pire
from quantum_ready.outils.commun import Piste, Trouvaille
from quantum_ready.outils.configurations import defauts
from quantum_ready.outils.configurations.nginx import Lecteur
from quantum_ready.outils.configurations.tls import resume_suites

NOM = "analyser_configuration"
TOUTES_VERSIONS = ["TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"]
DEFAUT_PROTOCOLES = "all -SSLv3"
SOURCE_APACHE = "valeur par défaut d'Apache 2.4 (mod_ssl)"
FICHIERS = {"SSLCertificateFile": "certificat du serveur", "SSLCertificateKeyFile": "clé privée du serveur",
            "SSLCertificateChainFile": "chaîne de certificats", "SSLCACertificateFile": "AC de confiance (certificats clients)",
            "SSLOpenSSLConfCmd": None}


@dataclass
class Ligne:
    nom: str
    arguments: list[str]
    fichier: str
    ligne: int


def lignes(texte: str, fichier: str, lecteur: Lecteur, dossier, profondeur: int = 0):
    """Directives et bornes de sections (« <VirtualHost », « </VirtualHost »), include dépliés."""
    tampon, debut = "", 0
    for numero, brute in enumerate(texte.splitlines(), start=1):
        if not tampon:
            debut = numero
        if brute.rstrip().endswith("\\"):
            tampon += brute.rstrip()[:-1] + " "
            continue
        contenu = (tampon + brute).strip()
        tampon = ""
        if not contenu or contenu.startswith("#"):
            continue
        try:
            mots = shlex.split(contenu, comments=True)
        except ValueError:
            mots = contenu.split()
        if not mots:
            continue
        nom = mots[0]
        if nom.lower() in ("include", "includeoptional") and len(mots) > 1 and profondeur < 10:
            fichiers = lecteur.candidats(mots[1], dossier)
            if not fichiers and nom.lower() == "include":
                lecteur.introuvables.append(f"{mots[1]} ({fichier}, ligne {debut})")
            for chemin in fichiers:
                if chemin.resolve() in lecteur.lus:
                    continue
                lecteur.lus.add(chemin.resolve())
                yield from lignes(chemin.read_text(encoding="utf-8", errors="replace"), chemin.relative_to(lecteur.racine).as_posix(),
                                  lecteur, chemin.parent, profondeur + 1)
            continue
        yield Ligne(nom.rstrip(">"), [m.rstrip(">") for m in mots[1:]], fichier, debut)


def protocoles(expression: str) -> list[str]:
    """« all -SSLv3 -TLSv1 » -> versions effectives."""
    versions: list[str] = []
    for mot in expression.split():
        signe, nom = (mot[0], mot[1:]) if mot[0] in "+-" else ("+", mot)
        liste = TOUTES_VERSIONS if nom.lower() == "all" else [nom]
        for v in liste:
            if signe == "+" and v not in versions:
                versions.append(v)
            elif signe == "-" and v in versions:
                versions.remove(v)
    return versions


def analyser(texte: str, fichier: str, contexte=None) -> tuple[list[Trouvaille], list[Piste]]:
    lecteur = Lecteur(getattr(contexte, "racine", None))
    chemin = getattr(contexte, "chemin", None)
    if chemin is not None:
        lecteur.lus.add(chemin.resolve())
    dossier = chemin.parent if chemin is not None else None
    globales: dict[str, Ligne] = {}
    hotes: list[tuple[str, dict[str, Ligne]]] = []
    courant: dict[str, Ligne] | None = None
    nom_hote = ""
    for l in lignes(texte, fichier, lecteur, dossier):
        bas = l.nom.lower()
        if bas == "<virtualhost":
            courant, nom_hote = {}, " ".join(l.arguments)
        elif bas == "</virtualhost" and courant is not None:
            hotes.append((nom_hote, courant))
            courant = None
        elif l.nom.startswith("<") or l.nom.startswith("</"):
            continue
        else:
            cible = courant if courant is not None else globales
            if l.nom == "ServerName" and courant is not None:
                nom_hote = f"{l.arguments[0]} ({nom_hote})" if l.arguments else nom_hote
            cle = l.nom if l.nom != "SSLOpenSSLConfCmd" else f"SSLOpenSSLConfCmd {l.arguments[0] if l.arguments else ''}"
            cible[cle] = l
    if not hotes and any(k.startswith("SSL") for k in globales):
        hotes.append((f"configuration globale de {fichier}", {}))

    trouvailles: dict[tuple, Trouvaille] = {}
    pistes: list[Piste] = []
    for nom, propres in hotes:
        d = {**globales, **propres}
        if "SSLEngine" in d and d["SSLEngine"].arguments[:1] != ["on"] and propres:
            continue
        if "SSLEngine" not in d and propres:
            continue
        for t in _trouvailles(nom, d):
            cle = (t.type_actif, t.nom, t.fichier, t.ligne)
            if cle in trouvailles:
                trouvailles[cle].proprietes["serveurs"].append(nom)
            else:
                trouvailles[cle] = t
        for directive, role in FICHIERS.items():
            if role and directive in d:
                pistes.append(Piste(vers=d[directive].arguments[0], raison=f"{role} ({directive}, {d[directive].fichier} ligne {d[directive].ligne}, {nom})"))
    for introuvable in lecteur.introuvables:
        pistes.append(Piste(vers=introuvable.split(" (")[0], raison=f"fichier inclus introuvable dans le SI : {introuvable}"))
    return list(trouvailles.values()), pistes


def _trouvailles(nom: str, d: dict[str, Ligne]) -> list[Trouvaille]:
    resultat = []

    def ajouter(cle, type_actif, nom_actif, description, expo, props, source=SOURCE_APACHE):
        ecrite = cle in d
        props = dict(props) | {"serveurs": [nom]} | ({} if ecrite else {"source": source})
        resultat.append(Trouvaille(
            outil=NOM, fichier=d[cle].fichier if ecrite else "", ligne=d[cle].ligne if ecrite else None, type_actif=type_actif,
            nom=nom_actif, description=description, exposition=expo, implicite=not ecrite, proprietes=props,
            preuve=f"{cle.split()[0]} {' '.join(d[cle].arguments)}" if ecrite else f"{cle} absente ({nom})",
        ))

    expression = " ".join(d["SSLProtocol"].arguments) if "SSLProtocol" in d else DEFAUT_PROTOCOLES
    versions = protocoles(expression)
    faibles = [v for v in versions if v in ("SSLv2", "SSLv3", "TLSv1", "TLSv1.1")]
    ajouter("SSLProtocol", "protocol", " ".join(versions), "Versions de TLS acceptées par Apache", "shor",
            {"versions": versions, "expression": expression} | ({"faiblesse_classique": "versions obsolètes : " + ", ".join(faibles)} if faibles else {}))

    if "SSLCipherSuite" in d:
        arguments = d["SSLCipherSuite"].arguments
        if len(arguments) == 2 and arguments[0].upper() in ("SSL", "TLSV1.3"):
            suites = arguments[1].split(":")
            ajouter("SSLCipherSuite", "protocol", arguments[1], "Suites de chiffrement TLS 1.3 fixées pour Apache", exposition_la_pire(suites), {"suites": suites})
        else:
            chaine = arguments[-1]
            props, echange_rsa = resume_suites(chaine)
            expo = exposition_la_pire(props["echanges_de_cles"]) if props.get("echanges_de_cles") else "inconnue"
            ajouter("SSLCipherSuite", "protocol", chaine, "Suites de chiffrement TLS 1.2 acceptées par Apache", expo, props)
            if echange_rsa:
                ajouter("SSLCipherSuite", "protocol", f"Échange de clés RSA (Kx=RSA) : {len(echange_rsa)} suites",
                        "Suites TLS 1.2 sans confidentialité persistante activées par SSLCipherSuite", "shor",
                        {"suites": echange_rsa, "faiblesse_classique": "pas de confidentialité persistante"})
    if "TLSv1.3" in versions and not any(len(l.arguments) == 2 and l.arguments[0].upper() == "TLSV1.3" for k, l in d.items() if k == "SSLCipherSuite"):
        ajouter("SSLCipherSuite TLSv1.3", "protocol", ":".join(defauts.SUITES_TLS13_OPENSSL),
                "Suites TLS 1.3 : aucune directive ne les fixe, Apache applique celles d'OpenSSL", "grover",
                {"suites": defauts.SUITES_TLS13_OPENSSL}, defauts.SOURCE_TLS13)

    groupes = next((l for k, l in d.items() if k.split()[-1] in ("Curves", "Groups")), None)
    if groupes is not None and len(groupes.arguments) > 1:
        liste = groupes.arguments[1].split(":")
        cle = f"SSLOpenSSLConfCmd {groupes.arguments[0]}"
        ajouter(cle, "algorithm", groupes.arguments[1], "Groupes d'échange de clés proposés par Apache", exposition_la_pire(liste),
                {"groupes": liste, "hybride_post_quantique": any(exposition(g) == "resistant" for g in liste)})
    else:
        ajouter("SSLOpenSSLConfCmd Groups", "algorithm", "auto", "Groupes d'échange de clés : liste par défaut d'OpenSSL (dépend de sa version)",
                "shor", {"groupes": defauts.GROUPES_OPENSSL_3}, defauts.SOURCE_GROUPES_OPENSSL)
    if "SSLSessionTickets" not in d or d["SSLSessionTickets"].arguments[:1] == ["on"]:
        ajouter("SSLSessionTickets", "related-crypto-material", "Clé des tickets de session TLS",
                "Clé symétrique générée par Apache pour chiffrer les tickets de reprise de session", "grover", {})
    return resultat
