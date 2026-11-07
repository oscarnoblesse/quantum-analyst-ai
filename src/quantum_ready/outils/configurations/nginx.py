"""Configuration nginx, lue selon sa grammaire.

Une configuration nginx est un arbre de directives : « nom arguments ; » ou
« nom arguments { ... } ». Les directives ssl_* écrites dans le bloc http
s'appliquent à tous les blocs server qui ne les redéfinissent pas, et « include »
insère un autre fichier (chemin relatif, absolu, ou motif comme conf.d/*.conf).
Chaque bloc server en TLS est donc évalué séparément, avec ce dont il hérite ;
deux serveurs qui ont le même réglage donnent une seule trouvaille.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from quantum_ready.outils.classification import exposition, exposition_la_pire
from quantum_ready.outils.commun import Piste, Trouvaille
from quantum_ready.outils.configurations import defauts
from quantum_ready.outils.configurations.tls import resume_suites

NOM = "analyser_configuration"
PROFONDEUR_INCLUDE = 10
FICHIERS = {
    "ssl_certificate": "certificat présenté aux clients",
    "ssl_certificate_key": "clé privée du serveur",
    "ssl_dhparam": "paramètres Diffie-Hellman",
    "ssl_client_certificate": "AC de confiance pour les certificats clients (mTLS)",
    "ssl_trusted_certificate": "AC de confiance (OCSP)",
    "ssl_session_ticket_key": "clé fixe des tickets de session",
}


@dataclass
class Directive:
    nom: str
    arguments: list[str]
    fichier: str
    ligne: int
    enfants: list["Directive"] | None = None


def lexemes(texte: str):
    """(lexème, ligne, entre_guillemets) : mots, chaînes entre guillemets, « ; », « { », « } »."""
    i, ligne, n = 0, 1, len(texte)
    while i < n:
        c = texte[i]
        if c == "\n":
            ligne += 1
            i += 1
        elif c.isspace():
            i += 1
        elif c == "#":
            while i < n and texte[i] != "\n":
                i += 1
        elif c in ";{}":
            yield c, ligne, False
            i += 1
        elif c in "\"'":
            debut_ligne, j, morceaux = ligne, i + 1, []
            while j < n and texte[j] != c:
                if texte[j] == "\\" and j + 1 < n:
                    j += 1
                if texte[j] == "\n":
                    ligne += 1
                morceaux.append(texte[j])
                j += 1
            yield "".join(morceaux), debut_ligne, True
            i = j + 1
        else:
            j = i
            while j < n and not texte[j].isspace() and texte[j] not in ";{}" and not (texte[j] == "#" and j == i):
                j += 1
            yield texte[i:j], ligne, False
            i = j


def analyser_arbre(texte: str, fichier: str) -> list[Directive]:
    """Arbre des directives d'un texte (une accolade manquante ferme simplement le bloc)."""
    racine: list[Directive] = []
    pile = [racine]
    courants: list[tuple[str, bool]] = []
    debut = 0
    for lexeme, ligne, cite in lexemes(texte):
        if not cite and lexeme in (";", "{"):
            if courants:
                directive = Directive(courants[0][0], [m for m, _ in courants[1:]], fichier, debut)
                pile[-1].append(directive)
                if lexeme == "{":
                    directive.enfants = []
                    pile.append(directive.enfants)
            courants = []
        elif not cite and lexeme == "}":
            courants = []
            if len(pile) > 1:
                pile.pop()
        else:
            if not courants:
                debut = ligne
            courants.append((lexeme, cite))
    return racine


@dataclass
class Lecteur:
    """Lit un fichier nginx et ses include, sans sortir du SI ni tourner en rond."""

    racine: Path | None
    lus: set = field(default_factory=set)
    introuvables: list[str] = field(default_factory=list)

    def candidats(self, motif: str, dossier: Path) -> list[Path]:
        if self.racine is None:
            return []
        if motif.startswith("/"):  # chemin de la machine cible : on cherche la même fin de chemin dans le SI
            morceaux = Path(motif).parts[1:]
            for debut in range(len(morceaux)):
                trouves = sorted(p for p in self.racine.glob("**/" + "/".join(morceaux[debut:])) if p.is_file())
                if trouves:
                    return trouves
            return []
        for base in (dossier, *dossier.parents):
            trouves = sorted(p for p in base.glob(motif) if p.is_file())
            if trouves:
                return [p for p in trouves if p.resolve().is_relative_to(self.racine)]
            if base == self.racine:
                break
        return []

    def deplier(self, directives: list[Directive], dossier: Path, profondeur: int = 0) -> list[Directive]:
        resultat = []
        for directive in directives:
            if directive.nom == "include" and directive.arguments and profondeur < PROFONDEUR_INCLUDE:
                fichiers = self.candidats(directive.arguments[0], dossier)
                if not fichiers:
                    self.introuvables.append(f"{directive.arguments[0]} ({directive.fichier}, ligne {directive.ligne})")
                for chemin in fichiers:
                    cle = chemin.resolve()
                    if cle in self.lus:
                        continue
                    self.lus.add(cle)
                    nom = chemin.relative_to(self.racine).as_posix()
                    inclus = analyser_arbre(chemin.read_text(encoding="utf-8", errors="replace"), nom)
                    resultat += self.deplier(inclus, chemin.parent, profondeur + 1)
                    self.lus.discard(cle)
                continue
            if directive.enfants is not None:
                directive.enfants = self.deplier(directive.enfants, dossier, profondeur)
            resultat.append(directive)
        return resultat


def contextes_tls(arbre: list[Directive], fichier: str) -> list[tuple[str, dict[str, Directive]]]:
    """(nom du serveur, directives effectives) pour chaque bloc server en TLS, héritage compris."""
    def reglages(directives, herites):
        effectifs = dict(herites)
        for d in directives:
            if d.enfants is None and (d.nom.startswith("ssl_") or d.nom in ("listen", "server_name", "ssl")):
                if d.nom == "listen":
                    effectifs.setdefault("_listen", [])
                    effectifs["_listen"] = effectifs["_listen"] + [d]
                else:
                    effectifs[d.nom] = d
        return effectifs

    resultats = []

    def parcourir(directives, herites):
        effectifs = reglages(directives, herites)
        serveurs = [d for d in directives if d.nom == "server" and d.enfants is not None]
        for d in directives:
            if d.enfants is not None and d.nom in ("http", "stream", "mail"):
                parcourir(d.enfants, {k: v for k, v in effectifs.items() if k != "_listen"})
        for serveur in serveurs:
            propres = reglages(serveur.enfants, {k: v for k, v in effectifs.items() if k not in ("_listen", "server_name")})
            ecoutes = propres.get("_listen", [])
            en_tls = any("ssl" in d.arguments or "quic" in d.arguments for d in ecoutes) or "ssl_certificate" in propres or (
                "ssl" in propres and propres["ssl"].arguments[:1] == ["on"])
            if en_tls:
                nom = " ".join(propres["server_name"].arguments) if "server_name" in propres else f"server ligne {serveur.ligne} de {serveur.fichier}"
                resultats.append((nom, propres))
        return effectifs

    effectifs = parcourir(arbre, {})
    if not resultats and any(k.startswith("ssl_") for k in effectifs):
        resultats.append((f"fragment {fichier}", effectifs))  # fichier inclus ailleurs : pas de bloc server
    return resultats


def trouvailles_d_un_serveur(nom: str, d: dict[str, Directive]) -> tuple[list[Trouvaille], list[Piste]]:
    trouvailles, pistes = [], []

    def valeur(nom_directive):
        return " ".join(d[nom_directive].arguments) if nom_directive in d else None

    def ajouter(directive, type_actif, nom_actif, description, expo, props=None, source=None):
        props = dict(props or {})
        ecrite = directive in d
        if not ecrite:
            props["source"] = source or defauts.SOURCE_NGINX
        trouvailles.append(Trouvaille(
            outil=NOM, fichier=d[directive].fichier if ecrite else "", ligne=d[directive].ligne if ecrite else None,
            type_actif=type_actif, nom=nom_actif, description=description, exposition=expo, implicite=not ecrite,
            proprietes=props | {"serveurs": [nom]},
            preuve=f"{directive} {valeur(directive)};" if ecrite else f"{directive} absente (serveur {nom})",
        ))

    versions = valeur("ssl_protocols").split() if "ssl_protocols" in d else defauts.NGINX_SSL_PROTOCOLS
    faibles = [v for v in versions if v in ("SSLv2", "SSLv3", "TLSv1", "TLSv1.1")]
    ajouter("ssl_protocols", "protocol", " ".join(versions), "Versions de TLS acceptées par nginx", "shor",
            {"versions": versions} | ({"faiblesse_classique": "versions obsolètes : " + ", ".join(faibles)} if faibles else {}),
            defauts.SOURCE_NGINX_SSL_PROTOCOLS)

    if any(v != "TLSv1.3" for v in versions):
        chaine = valeur("ssl_ciphers") or defauts.NGINX_SSL_CIPHERS
        props, echange_rsa = resume_suites(chaine)
        expo = exposition_la_pire(props["echanges_de_cles"]) if props.get("echanges_de_cles") else ("inconnue" if "developpement" in props else exposition(chaine))
        ajouter("ssl_ciphers", "protocol", chaine, "Suites de chiffrement TLS 1.2 acceptées par nginx", expo, props)
        if echange_rsa:
            ajouter("ssl_ciphers", "protocol", f"Échange de clés RSA (Kx=RSA) : {len(echange_rsa)} suites",
                    "Suites TLS 1.2 sans confidentialité persistante activées par la chaîne ssl_ciphers : "
                    "la clé RSA du certificat chiffre directement le secret de session", "shor",
                    {"suites": echange_rsa, "faiblesse_classique": "pas de confidentialité persistante"})
            pistes.append(Piste(vers=valeur("ssl_certificate") or "certificat du serveur",
                                raison="les suites Kx=RSA ne servent que si la clé du certificat est RSA : vérifier son type"))

    if "TLSv1.3" in versions:
        commandes = [x for x in d.values() if isinstance(x, Directive) and x.nom == "ssl_conf_command" and x.arguments[:1] == ["Ciphersuites"]]
        if not commandes:
            ajouter("ssl_conf_command", "protocol", ":".join(defauts.SUITES_TLS13_OPENSSL),
                    "Suites de chiffrement TLS 1.3 : aucune directive ne les fixe, nginx applique celles d'OpenSSL",
                    "grover", {"suites": defauts.SUITES_TLS13_OPENSSL}, defauts.SOURCE_TLS13)

    groupes = valeur("ssl_ecdh_curve")
    if groupes and groupes != "auto":
        liste = groupes.split(":")
        ajouter("ssl_ecdh_curve", "algorithm", groupes, "Groupes d'échange de clés (ECDHE) proposés par nginx",
                exposition_la_pire(liste), {"groupes": liste, "hybride_post_quantique": any(exposition(g) == "resistant" for g in liste)})
    else:
        ajouter("ssl_ecdh_curve", "algorithm", "auto", "Groupes d'échange de clés : liste par défaut d'OpenSSL (dépend de sa version)",
                "shor", {"groupes": defauts.GROUPES_OPENSSL_3}, defauts.SOURCE_GROUPES_OPENSSL)

    if (valeur("ssl_session_tickets") or "on") == "on":
        ajouter("ssl_session_tickets", "related-crypto-material", "Clé des tickets de session TLS",
                "Clé symétrique générée par nginx pour chiffrer les tickets de reprise de session", "grover",
                {"rotation": "au redémarrage de nginx" if "ssl_session_ticket_key" not in d else "fichier de clé fixe"})

    for directive, role in FICHIERS.items():
        if directive in d:
            pistes.append(Piste(vers=valeur(directive), raison=f"{role} ({directive}, {d[directive].fichier} ligne {d[directive].ligne}, serveur {nom})"))
    if "ssl_verify_client" in d:
        pistes.append(Piste(vers=d["ssl_verify_client"].fichier, raison=f"authentification des clients par certificat ({nom}) : ssl_verify_client {valeur('ssl_verify_client')}"))
    return trouvailles, pistes


def analyser(texte: str, fichier: str, contexte=None) -> tuple[list[Trouvaille], list[Piste]]:
    racine = getattr(contexte, "racine", None)
    chemin = getattr(contexte, "chemin", None)
    lecteur = Lecteur(racine)
    arbre = analyser_arbre(texte, fichier)
    if chemin is not None:
        lecteur.lus.add(chemin.resolve())
        arbre = lecteur.deplier(arbre, chemin.parent)
    trouvailles: dict[tuple, Trouvaille] = {}
    pistes: list[Piste] = []
    for nom, directives in contextes_tls(arbre, fichier):
        nouvelles, nouvelles_pistes = trouvailles_d_un_serveur(nom, directives)
        pistes += nouvelles_pistes
        for t in nouvelles:  # même réglage dans plusieurs serveurs : une seule trouvaille
            cle = (t.type_actif, t.nom, t.fichier, t.ligne, t.description)
            if cle in trouvailles:
                trouvailles[cle].proprietes["serveurs"] += t.proprietes["serveurs"]
            else:
                trouvailles[cle] = t
    for introuvable in lecteur.introuvables:
        pistes.append(Piste(vers=introuvable.split(" (")[0], raison=f"fichier inclus introuvable dans le SI : {introuvable} ; ses directives n'ont pas pu être lues"))
    return list(trouvailles.values()), pistes
