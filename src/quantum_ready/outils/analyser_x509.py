"""Outil analyser_x509 : certificats X.509 (PEM, éventuellement plusieurs par fichier, ou DER).

Un certificat donne TROIS actifs du CBOM, comme dans la vérité terrain :
1. le certificat lui-même (certificate) : sujet, émetteur, validité, usages ;
2. sa clé publique (related-crypto-material) : RSA-2048, ECDSA P-256... ;
3. l'algorithme de la signature posée par l'émetteur (algorithm).
Les deux derniers sont exposés à Shor ; c'est précisément ce que le CBOM doit montrer.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import ExtensionOID, NameOID

from quantum_ready.outils._cles import decrire_cle, empreinte_spki
from quantum_ready.outils.classification import exposition
from quantum_ready.outils.commun import ErreurOutil, Piste, Resultat, Trouvaille, outil, relatif, resoudre

NOM = "analyser_x509"
_BLOC_PEM = re.compile(rb"-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----", re.S)
SIGNATURES_FAIBLES = ("md5", "sha1")


def charger_certificats(donnees: bytes) -> list[x509.Certificate]:
    """Tous les certificats d'un fichier PEM (dans l'ordre) ou le certificat d'un fichier DER."""
    blocs = _BLOC_PEM.findall(donnees)
    if blocs:
        return [x509.load_pem_x509_certificate(bloc) for bloc in blocs]
    try:
        return [x509.load_der_x509_certificate(donnees)]
    except ValueError as erreur:
        raise ErreurOutil("Aucun certificat X.509 lisible dans ce fichier") from erreur


def nom_commun(nom: x509.Name) -> str:
    valeurs = nom.get_attributes_for_oid(NameOID.COMMON_NAME)
    return str(valeurs[0].value) if valeurs else nom.rfc4514_string()


def _extension(cert: x509.Certificate, oid):
    try:
        return cert.extensions.get_extension_for_oid(oid).value
    except x509.ExtensionNotFound:
        return None


def _usages(cert: x509.Certificate) -> list[str]:
    usages = []
    cle = _extension(cert, ExtensionOID.KEY_USAGE)
    if cle is not None:
        for attribut in ("digital_signature", "key_encipherment", "key_cert_sign", "crl_sign", "key_agreement"):
            if getattr(cle, attribut):
                usages.append(attribut)
    etendus = _extension(cert, ExtensionOID.EXTENDED_KEY_USAGE)
    if etendus is not None:
        usages += [usage._name for usage in etendus]
    return usages


def analyser_certificat(cert: x509.Certificate, fichier: str, rang: int, total: int) -> list[Trouvaille]:
    sujet, emetteur = nom_commun(cert.subject), nom_commun(cert.issuer)
    auto_signe = cert.subject == cert.issuer
    contraintes = _extension(cert, ExtensionOID.BASIC_CONSTRAINTS)
    est_ac = bool(contraintes and contraintes.ca)
    maintenant = datetime.now(timezone.utc)
    nom_cle, props_cle = decrire_cle(cert.public_key())
    props_cle["empreinte_spki_sha256"] = empreinte_spki(cert.public_key())
    algo_signature = cert.signature_algorithm_oid._name
    position = f" (certificat {rang}/{total} du fichier)" if total > 1 else ""
    sans = _extension(cert, ExtensionOID.SUBJECT_ALTERNATIVE_NAME)

    props_cert: dict = {
        "sujet": cert.subject.rfc4514_string(),
        "emetteur": cert.issuer.rfc4514_string(),
        "version": cert.version.name,
        "numero_serie": format(cert.serial_number, "x"),
        "debut_validite": cert.not_valid_before_utc.date().isoformat(),
        "fin_validite": cert.not_valid_after_utc.date().isoformat(),
        "expire": cert.not_valid_after_utc < maintenant,
        "auto_signe": auto_signe,
        "autorite": est_ac,
        "usages": _usages(cert),
        "empreinte_sha256": cert.fingerprint(hashes.SHA256()).hex(),
        "certificat_sha256": cert.fingerprint(hashes.SHA256()).hex(),
        "rang_dans_fichier": rang,
        "cle_publique": nom_cle,
        "algorithme_signature": algo_signature,
    }
    if sans is not None:
        props_cert["noms_alternatifs"] = [str(n.value) for n in sans]
    empreinte = cert.fingerprint(hashes.SHA256()).hex()
    props_cle["certificat_sha256"] = empreinte
    props_signature: dict = {"signe_par": emetteur, "auto_signature": auto_signe, "certificat_sha256": empreinte}
    if any(faible in algo_signature.lower() for faible in SIGNATURES_FAIBLES):
        props_signature["faiblesse_classique"] = "fonction de hachage cassée (collisions)"

    role = "d'autorité" if est_ac else "d'entité finale"
    return [
        Trouvaille(
            outil=NOM, fichier=fichier, type_actif="certificate",
            nom=f"Certificat « {sujet} »",
            description=f"Certificat {role} « {sujet} », émis par « {emetteur} »{position}",
            exposition=exposition(nom_cle), proprietes=props_cert,
            preuve=f"Subject: {cert.subject.rfc4514_string()}",
        ),
        Trouvaille(
            outil=NOM, fichier=fichier, type_actif="related-crypto-material",
            nom=nom_cle, description=f"Clé publique du certificat « {sujet} »{position}",
            exposition=exposition(nom_cle), proprietes=props_cle,
            preuve=f"Public Key Algorithm: {nom_cle}",
        ),
        Trouvaille(
            outil=NOM, fichier=fichier, type_actif="algorithm",
            nom=algo_signature,
            description=f"Signature du certificat « {sujet} » par « {emetteur} »{position}",
            exposition=exposition(algo_signature), proprietes=props_signature,
            preuve=f"Signature Algorithm: {algo_signature}",
        ),
    ]


@outil(NOM)
def analyser_x509(cible: str, racine: Path) -> Resultat:
    """Analyse les certificats X.509 d'un fichier : certificat, clé publique et signature de chacun."""
    chemin = resoudre(cible, racine)
    fichier = relatif(chemin, racine)
    certificats = charger_certificats(chemin.read_bytes())
    resultat = Resultat(outil=NOM, cible=fichier)
    sujets = {cert.subject for cert in certificats}
    for rang, cert in enumerate(certificats, start=1):
        resultat.trouvailles += analyser_certificat(cert, fichier, rang, len(certificats))
        if cert.subject != cert.issuer and cert.issuer not in sujets:
            resultat.pistes.append(Piste(
                vers=f"émetteur « {nom_commun(cert.issuer)} »",
                raison="certificat de l'émetteur absent de ce fichier : le chercher ailleurs dans le SI",
            ))
    if len(certificats) > 1:
        resultat.pistes.append(Piste(
            vers=fichier,
            raison=f"{len(certificats)} certificats dans ce fichier : vérifier que chacun est attendu",
        ))
    return resultat
