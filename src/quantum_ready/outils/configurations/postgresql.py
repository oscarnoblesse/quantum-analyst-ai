"""Configuration PostgreSQL : postgresql.conf (TLS du serveur) et pg_hba.conf (authentification)."""

from __future__ import annotations

import re

from quantum_ready.outils.classification import exposition
from quantum_ready.outils.commun import Piste, Trouvaille
from quantum_ready.outils.configurations import defauts
from quantum_ready.outils.configurations.tls import resume_suites

NOM = "analyser_configuration"
_PARAMETRE = re.compile(r"^\s*(\w+)\s*=?\s*('(?:[^']|'')*'|[^\s#]+)")


def parametres(texte: str) -> dict[str, tuple[int, str]]:
    """Paramètres « nom = valeur » ; la dernière occurrence l'emporte, comme dans PostgreSQL."""
    trouves = {}
    for numero, ligne in enumerate(texte.splitlines(), start=1):
        correspondance = _PARAMETRE.match(ligne)
        if correspondance and not ligne.lstrip().startswith("#"):
            trouves[correspondance.group(1).lower()] = (numero, correspondance.group(2).strip("'"))
    return trouves


def analyser_conf(texte: str, fichier: str) -> tuple[list[Trouvaille], list[Piste]]:
    p = parametres(texte)
    trouvailles, pistes = [], []
    if p.get("ssl", (0, "off"))[1].lower() not in ("on", "true", "yes", "1"):
        pistes.append(Piste(vers=fichier, raison="ssl n'est pas activé : les connexions à la base ne sont pas chiffrées"))
        return trouvailles, pistes

    def ajouter(parametre, type_actif, description, expo, props=None):
        implicite = parametre not in p
        ligne, valeur = p.get(parametre, (None, defauts.POSTGRESQL.get(parametre, "")))
        props = dict(props or {})
        if implicite:
            props["source"] = defauts.SOURCE_POSTGRESQL
        trouvailles.append(Trouvaille(
            outil=NOM, fichier="" if implicite else fichier, ligne=ligne, type_actif=type_actif, nom=valeur,
            description=description + (" : paramètre absent, valeur par défaut" if implicite else ""),
            exposition=expo, implicite=implicite, proprietes=props,
            preuve=f"{parametre} = '{valeur}'" if not implicite else f"{parametre} absent de {fichier}",
        ))

    version = p.get("ssl_min_protocol_version", (0, defauts.POSTGRESQL["ssl_min_protocol_version"]))[1]
    ajouter("ssl_min_protocol_version", "protocol", "Version TLS minimale du serveur PostgreSQL", "shor",
            {"faiblesse_classique": "TLS 1.0/1.1 autorisés"} if version in ("TLSv1", "TLSv1.1") else {})
    chaine = p.get("ssl_ciphers", (0, defauts.POSTGRESQL["ssl_ciphers"]))[1]
    props, echange_rsa = resume_suites(chaine)
    if "+3DES" in chaine or "MEDIUM" in chaine:
        props["faiblesse_classique"] = "MEDIUM et 3DES autorisés"
    ajouter("ssl_ciphers", "protocol", "Suites de chiffrement TLS 1.2 du serveur PostgreSQL", "shor" if echange_rsa else "grover", props)
    courbe = p.get("ssl_ecdh_curve", (0, defauts.POSTGRESQL["ssl_ecdh_curve"]))[1]
    ajouter("ssl_ecdh_curve", "algorithm", "Groupe d'échange de clés (ECDHE) du serveur PostgreSQL", exposition(courbe))

    if "password_encryption" in p:
        ligne, valeur = p["password_encryption"]
        pistes.append(Piste(vers="pg_hba.conf", raison=f"password_encryption = {valeur} (ligne {ligne}) : les empreintes de mots de passe stockées sont au format {valeur}, à rapprocher des méthodes d'authentification de pg_hba.conf"))
    for parametre, role in (("ssl_cert_file", "certificat du serveur"), ("ssl_key_file", "clé privée du serveur"), ("ssl_ca_file", "AC de confiance")):
        if parametre in p:
            pistes.append(Piste(vers=p[parametre][1], raison=f"{role} ({parametre}, ligne {p[parametre][0]})"))
    return trouvailles, pistes


METHODES = {
    "md5": ("défi-réponse MD5 sur une empreinte MD5 du mot de passe", "grover", "MD5 est cassé ; une empreinte volée suffit pour se connecter"),
    "password": ("mot de passe envoyé en clair", "aucune", "mot de passe en clair sur le réseau si la connexion n'est pas chiffrée"),
    "scram-sha-256": ("SCRAM-SHA-256 (RFC 7677)", "grover", None),
    "cert": ("certificat client X.509", "shor", None),
    "trust": ("aucune authentification", "aucune", "connexion sans aucune authentification"),
}


def analyser_hba(texte: str, fichier: str) -> tuple[list[Trouvaille], list[Piste]]:
    """Une trouvaille par méthode d'authentification cryptographique utilisée."""
    par_methode: dict[str, list[tuple[int, str]]] = {}
    pistes = []
    for numero, ligne in enumerate(texte.splitlines(), start=1):
        champs = ligne.split("#")[0].split()
        if len(champs) < 4 or champs[0] not in ("local", "host", "hostssl", "hostnossl"):
            continue
        methode = champs[3] if champs[0] == "local" else (champs[4] if len(champs) > 4 else "")
        if methode in METHODES:
            par_methode.setdefault(methode, []).append((numero, " ".join(champs)))
            if champs[0] in ("host", "hostnossl"):
                pistes.append(Piste(vers=fichier, raison=f"ligne {numero} : « {champs[0]} » accepte aussi des connexions sans TLS"))
    trouvailles = []
    for methode, lignes in par_methode.items():
        description, expo, faiblesse = METHODES[methode]
        props: dict = {"lignes": [l for _, l in lignes]}
        if faiblesse:
            props["faiblesse_classique"] = faiblesse
        trouvailles.append(Trouvaille(
            outil=NOM, fichier=fichier, ligne=lignes[0][0], type_actif="protocol", nom=methode,
            description=f"Authentification des connexions à la base : {description}", exposition=expo,
            proprietes=props, preuve=lignes[0][1],
        ))
    if "md5" in par_methode:
        pistes.append(Piste(vers="postgresql.conf", raison="méthode md5 : vérifier password_encryption ; avec scram-sha-256, PostgreSQL utiliserait SCRAM malgré « md5 »"))
    return trouvailles, pistes
