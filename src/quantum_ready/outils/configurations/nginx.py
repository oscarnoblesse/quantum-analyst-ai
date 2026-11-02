"""Configuration nginx : directives TLS (ssl_*)."""

from __future__ import annotations

import re

from quantum_ready.outils.classification import exposition, exposition_la_pire
from quantum_ready.outils.commun import Piste, Trouvaille
from quantum_ready.outils.configurations import defauts
from quantum_ready.outils.configurations.tls import resume_suites

NOM = "analyser_configuration"
_DIRECTIVE = re.compile(r"^\s*(ssl_\w+)\s+([^;#]+);", re.M)
FICHIERS = {
    "ssl_certificate": "certificat présenté aux clients",
    "ssl_certificate_key": "clé privée du serveur",
    "ssl_dhparam": "paramètres Diffie-Hellman",
    "ssl_client_certificate": "AC de confiance pour les certificats clients (mTLS)",
    "ssl_trusted_certificate": "AC de confiance (OCSP)",
}


def directives(texte: str) -> dict[str, tuple[int, str]]:
    """Directives ssl_* : nom -> (ligne, valeur). La dernière occurrence l'emporte."""
    trouvees = {}
    for correspondance in _DIRECTIVE.finditer(texte):
        ligne = texte.count("\n", 0, correspondance.start()) + 1
        trouvees[correspondance.group(1)] = (ligne, " ".join(correspondance.group(2).split()))
    return trouvees


def analyser(texte: str, fichier: str) -> tuple[list[Trouvaille], list[Piste]]:
    d = directives(texte)
    trouvailles, pistes = [], []

    def ajouter(directive, type_actif, nom, description, expo, props=None, implicite=False):
        ligne, valeur = d.get(directive, (None, ""))
        trouvailles.append(Trouvaille(
            outil=NOM, fichier="" if implicite else fichier, ligne=ligne, type_actif=type_actif, nom=nom,
            description=description, exposition=expo, implicite=implicite, proprietes=props or {},
            preuve=f"{directive} {valeur};" if not implicite else f"{directive} absente de {fichier}",
        ))

    versions = d.get("ssl_protocols", (None, ""))[1].split()
    if versions:
        faibles = [v for v in versions if v in ("SSLv2", "SSLv3", "TLSv1", "TLSv1.1")]
        props = {"versions": versions} | ({"faiblesse_classique": "versions obsolètes : " + ", ".join(faibles)} if faibles else {})
        ajouter("ssl_protocols", "protocol", " ".join(versions), "Versions de TLS acceptées par nginx", "shor", props)

    if "ssl_ciphers" in d:
        chaine = d["ssl_ciphers"][1]
        props, echange_rsa = resume_suites(chaine)
        ajouter("ssl_ciphers", "protocol", chaine, "Suites de chiffrement TLS 1.2 acceptées par nginx",
                exposition_la_pire(props.get("echanges_de_cles", [])) if "echanges_de_cles" in props else "inconnue", props)
        if echange_rsa:
            ajouter("ssl_ciphers", "protocol", f"Échange de clés RSA (Kx=RSA) : {len(echange_rsa)} suites",
                    "Suites TLS 1.2 sans confidentialité persistante activées par la chaîne ssl_ciphers : "
                    "la clé RSA du certificat chiffre directement le secret de session", "shor",
                    {"suites": echange_rsa, "faiblesse_classique": "pas de confidentialité persistante"})
            pistes.append(Piste(vers=d.get("ssl_certificate", (0, "certificat du serveur"))[1],
                                raison="les suites Kx=RSA ne servent que si la clé du certificat est RSA : vérifier son type"))

    if "TLSv1.3" in versions and "ssl_conf_command" not in d:
        ajouter("ssl_conf_command", "protocol", ":".join(defauts.SUITES_TLS13_OPENSSL),
                "Suites de chiffrement TLS 1.3 : aucune directive ne les fixe, nginx applique celles d'OpenSSL",
                "grover", {"suites": defauts.SUITES_TLS13_OPENSSL, "source": defauts.SOURCE_TLS13}, implicite=True)

    if "ssl_ecdh_curve" in d:
        groupes = d["ssl_ecdh_curve"][1].split(":")
        ajouter("ssl_ecdh_curve", "algorithm", d["ssl_ecdh_curve"][1], "Groupes d'échange de clés (ECDHE) proposés par nginx",
                exposition_la_pire(groupes), {"groupes": groupes, "hybride_post_quantique": any(exposition(g) == "resistant" for g in groupes)})
    elif versions:
        ajouter("ssl_ecdh_curve", "algorithm", "auto", "Groupes d'échange de clés : valeur par défaut d'OpenSSL", "shor",
                {"groupes": defauts.GROUPES_OPENSSL_3, "source": "valeur par défaut d'OpenSSL 3.0 à 3.4"}, implicite=True)

    if d.get("ssl_session_tickets", (0, "on"))[1] == "on" and versions:
        ajouter("ssl_session_tickets", "related-crypto-material", "Clé des tickets de session TLS",
                "Clé symétrique générée par nginx pour chiffrer les tickets de reprise de session", "grover",
                {"rotation": "au redémarrage de nginx" if "ssl_session_ticket_key" not in d else "fichier de clé fixe"},
                implicite="ssl_session_tickets" not in d)

    for directive, role in FICHIERS.items():
        if directive in d:
            pistes.append(Piste(vers=d[directive][1], raison=f"{role} ({directive}, ligne {d[directive][0]})"))
    if "ssl_verify_client" in d:
        pistes.append(Piste(vers=fichier, raison=f"authentification des clients par certificat : ssl_verify_client {d['ssl_verify_client'][1]}"))
    return trouvailles, pistes
