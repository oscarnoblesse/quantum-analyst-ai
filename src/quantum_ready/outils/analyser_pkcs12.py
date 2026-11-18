"""Outil analyser_pkcs12 : conteneurs PKCS#12 (.p12, .pfx).

Un PKCS#12 protège une clé privée et des certificats par un mot de passe. Sa
structure ASN.1 laisse pourtant voir, SANS le mot de passe :
- l'algorithme qui chiffre la clé (sac « pkcs8ShroudedKeyBag ») ;
- l'algorithme qui chiffre les certificats (« encryptedData ») ;
- l'algorithme du MAC d'intégrité et son nombre d'itérations.
C'est un actif caché typique : rien ne l'indique dans le nom du fichier.

Pour voir le contenu (type de clé, certificats), il faut le mot de passe. L'agent
ne le fournit jamais lui-même : il indique le fichier .env et le nom de la
variable, et l'outil lit la valeur sans la recopier dans son résultat.
"""

from __future__ import annotations

from pathlib import Path

from quantum_ready.outils._cles import decrire_cle
from quantum_ready.outils.analyser_x509 import analyser_certificat
from quantum_ready.outils.commun import ErreurOutil, Piste, Resultat, Trouvaille, outil, relatif, resoudre, secret_depuis_env

NOM = "analyser_pkcs12"

NOMS_ALGORITHMES = {
    "pkcs12_sha1_tripledes_3key": "pbeWithSHA1And3-KeyTripleDES-CBC",
    "pkcs12_sha1_tripledes_2key": "pbeWithSHA1And2-KeyTripleDES-CBC",
    "pkcs12_sha1_rc2_40": "pbeWithSHA1And40BitRC2-CBC",
    "pkcs12_sha1_rc2_128": "pbeWithSHA1And128BitRC2-CBC",
    "pkcs12_sha1_rc4_40": "pbeWithSHA1And40BitRC4",
    "pkcs12_sha1_rc4_128": "pbeWithSHA1And128BitRC4",
}
FAIBLES = ("sha1", "tripledes", "rc2", "rc4", "des")


def _nom_algorithme(algorithme) -> str:
    """Nom lisible d'un AlgorithmIdentifier de chiffrement par mot de passe."""
    nom = algorithme["algorithm"].native
    if nom == "pbes2":
        try:
            return f"PBES2 ({algorithme.kdf.upper()}-{algorithme.kdf_hmac}, {algorithme.encryption_cipher.upper()}-{algorithme.key_length * 8}-CBC)"
        except (ValueError, KeyError, AttributeError):
            return "PBES2"
    return NOMS_ALGORITHMES.get(nom, nom)


def structure(donnees: bytes) -> dict:
    """Ce qui se lit sans mot de passe : chiffrement de la clé, des certificats, et MAC."""
    from asn1crypto import cms, pkcs12

    pfx = pkcs12.Pfx.load(donnees)
    chiffrements_cles, chiffrements_certificats, en_clair = [], [], []
    for info in pfx.authenticated_safe:
        if info["content_type"].native == "encrypted_data":
            algorithme = info["content"]["encrypted_content_info"]["content_encryption_algorithm"]
            chiffrements_certificats.append(_nom_algorithme(algorithme))
        elif info["content_type"].native == "data":
            contenu = pkcs12.SafeContents.load(info["content"].native)
            for sac in contenu:
                type_sac = sac["bag_id"].native
                if type_sac == "pkcs8_shrouded_key_bag":
                    chiffrements_cles.append(_nom_algorithme(sac["bag_value"]["encryption_algorithm"]))
                else:
                    en_clair.append(type_sac)
        elif isinstance(info, cms.ContentInfo):
            en_clair.append(info["content_type"].native)
    mac = pfx["mac_data"]
    return {
        "chiffrement_cle": chiffrements_cles,
        "chiffrement_certificats": chiffrements_certificats,
        "sacs_en_clair": en_clair,
        "mac": mac["mac"]["digest_algorithm"]["algorithm"].native.upper().replace("SHA", "SHA-") if mac.native else "aucun",
        "iterations_mac": mac["iterations"].native if mac.native else 0,
    }


@outil(NOM)
def analyser_pkcs12(cible: str, racine: Path, fichier_env: str | None = None, variable: str | None = None) -> Resultat:
    """Analyse un conteneur PKCS#12 ; avec fichier_env et variable, l'ouvre pour lister son contenu."""
    chemin = resoudre(cible, racine)
    fichier = relatif(chemin, racine)
    donnees = chemin.read_bytes()
    try:
        infos = structure(donnees)
    except Exception as erreur:
        raise ErreurOutil("Ce fichier n'est pas un conteneur PKCS#12 lisible") from erreur

    algorithmes = sorted(set(infos["chiffrement_cle"] + infos["chiffrement_certificats"]))
    proprietes: dict = {k: v for k, v in infos.items() if v not in ([], "")}
    faiblesses = [a for a in algorithmes + [infos["mac"]] if any(f in a.lower().replace("-", "") for f in FAIBLES)]
    if faiblesses:
        proprietes["faiblesse_classique"] = "algorithmes anciens : " + ", ".join(faiblesses)
    resultat = Resultat(outil=NOM, cible=fichier, trouvailles=[Trouvaille(
        outil=NOM, fichier=fichier, type_actif="algorithm",
        nom=", ".join(algorithmes) + f" ; MAC {infos['mac']}",
        description="Chiffrement par mot de passe du conteneur PKCS#12 (clé et certificats) et son MAC d'intégrité",
        exposition="grover", proprietes=proprietes,
        preuve=f"PFX : clé {infos['chiffrement_cle']}, certificats {infos['chiffrement_certificats']}, MAC {infos['mac']}",
    )])

    if not (fichier_env and variable):
        resultat.pistes.append(Piste(
            vers="mot de passe du conteneur",
            raison="le contenu (clé privée, certificats) n'est lisible qu'avec le mot de passe : chercher la "
            "variable d'environnement que le code lit pour ouvrir ce fichier, puis rappeler cet outil avec fichier_env et variable",
        ))
        return resultat

    from cryptography.hazmat.primitives.serialization import pkcs12

    mot_de_passe = secret_depuis_env(fichier_env, variable, racine)
    try:
        cle, certificat, autres = pkcs12.load_key_and_certificates(donnees, mot_de_passe.encode())
    except ValueError as erreur:
        raise ErreurOutil(f"Mot de passe refusé : {variable} (dans {fichier_env}) n'ouvre pas ce conteneur") from erreur
    if cle is not None:
        nom, props = decrire_cle(cle)
        props["mot_de_passe_lu_dans"] = f"{fichier_env} ({variable})"
        resultat.trouvailles.append(Trouvaille(
            outil=NOM, fichier=fichier, type_actif="related-crypto-material", nom=nom,
            description=f"Clé privée {nom} contenue dans le PKCS#12", exposition="shor", proprietes=props,
            preuve="pkcs8ShroudedKeyBag",
        ))
    certificats = ([certificat] if certificat else []) + list(autres)
    for rang, cert in enumerate(certificats, start=1):
        resultat.trouvailles += analyser_certificat(cert, fichier, rang, len(certificats))
    return resultat
