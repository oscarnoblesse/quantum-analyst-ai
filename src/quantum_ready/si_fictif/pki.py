"""PKI du SI fictif : AC racine, AC intermédiaire, certificats feuilles et leurs clés.

Actifs couverts :
- QR-001, QR-002, QR-065 : AC racine RSA-4096 auto-signée (sha256WithRSAEncryption) ;
- QR-003, QR-004, QR-066 : AC intermédiaire ECDSA P-384, signée par la racine ;
- QR-005 à QR-012, QR-067 à QR-070 : certificats nginx, base, factures et admin,
  signés par l'intermédiaire (ecdsa-with-SHA384) ;
- QR-015 (caché) : le certificat nginx RSA autorise keyEncipherment, donc l'échange
  de clés RSA de TLS 1.2 ;
- QR-020, QR-021 : conteneur PKCS#12 des factures, à l'ancien format 3DES + MAC SHA-1 ;
- QR-045 (caché) : ancienne AC RSA-1024 / SHA-1 oubliée dans ca_bundle.pem ;
- QR-046 (caché) : copie oubliée de la clé privée de l'intermédiaire ;
- QR-047 à QR-049 : clés privées des feuilles (en clair pour les serveurs, chiffrée pour l'admin).

Les clés privées des AC (racine, intermédiaire, ancienne AC) sont écrites hors du SI.
"""

from __future__ import annotations

import datetime as dt

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from quantum_ready.si_fictif.generateur import Contexte

ORGANISATION = "Lab"
PAYS = "FR"
UN_AN = 365


# --- Étape 1 : petites fonctions utilitaires ---


def nom(nom_commun: str) -> x509.Name:
    """Nom distinctif « C=FR, O=Lab, CN=<nom_commun> »."""
    return x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, PAYS),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, ORGANISATION),
        x509.NameAttribute(NameOID.COMMON_NAME, nom_commun),
    ])


def validite(jours: int, debut: dt.datetime | None = None) -> tuple[dt.datetime, dt.datetime]:
    """Période de validité (début, fin). Par défaut, le certificat commence hier (marge d'horloge)."""
    debut = debut or dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=1)
    return debut, debut + dt.timedelta(days=jours)


def pem_certificats(*certs: x509.Certificate) -> bytes:
    """Un ou plusieurs certificats PEM à la suite (une chaîne si plusieurs)."""
    return b"".join(c.public_bytes(serialization.Encoding.PEM) for c in certs)


def pem_cle(cle, phrase_de_passe: str | None = None) -> bytes:
    """Clé privée PEM au format PKCS#8, chiffrée si une phrase de passe est donnée."""
    chiffrement = (
        serialization.BestAvailableEncryption(phrase_de_passe.encode())
        if phrase_de_passe
        else serialization.NoEncryption()
    )
    return cle.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, chiffrement)


def usages(**actifs: bool) -> x509.KeyUsage:
    """KeyUsage où seuls les usages nommés sont à True (ex. usages(digital_signature=True))."""
    champs = dict.fromkeys(
        ("digital_signature", "content_commitment", "key_encipherment", "data_encipherment",
         "key_agreement", "key_cert_sign", "crl_sign", "encipher_only", "decipher_only"),
        False,
    )
    champs.update(actifs)
    return x509.KeyUsage(**champs)


def emettre(
    sujet: x509.Name,
    cle_publique,
    emetteur: x509.Name,
    cle_emetteur,
    hachage: hashes.HashAlgorithm,
    periode: tuple[dt.datetime, dt.datetime],
    extensions: list[tuple[x509.ExtensionType, bool]],
    cle_publique_emetteur=None,
) -> x509.Certificate:
    """Construit et signe un certificat X.509 v3.

    L'algorithme de signature dépend de la clé de l'ÉMETTEUR (RSA ou ECDSA), pas de
    celle du sujet. Ajoute toujours SubjectKeyIdentifier, et AuthorityKeyIdentifier
    quand l'émetteur est différent du sujet.
    """
    debut, fin = periode
    constructeur = (
        x509.CertificateBuilder()
        .subject_name(sujet)
        .issuer_name(emetteur)
        .public_key(cle_publique)
        .serial_number(x509.random_serial_number())
        .not_valid_before(debut)
        .not_valid_after(fin)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(cle_publique), critical=False)
    )
    if cle_publique_emetteur is not None:
        constructeur = constructeur.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(cle_publique_emetteur), critical=False
        )
    for extension, critique in extensions:
        constructeur = constructeur.add_extension(extension, critical=critique)
    return constructeur.sign(cle_emetteur, hachage)


def extensions_feuille(cle_usages: x509.KeyUsage, eku=None, noms_dns=()) -> list:
    """Extensions communes d'un certificat final : pas une AC, KeyUsage, et éventuellement EKU / SAN."""
    extensions = [(x509.BasicConstraints(ca=False, path_length=None), True), (cle_usages, True)]
    if eku:
        extensions.append((x509.ExtendedKeyUsage(eku), False))
    if noms_dns:
        extensions.append((x509.SubjectAlternativeName([x509.DNSName(n) for n in noms_dns]), False))
    return extensions


# --- Étapes 2 et 3 : les autorités ---


def generer_racine(ctx: Contexte):
    """QR-001, QR-002, QR-065 : AC racine RSA-4096, auto-signée en SHA-256, valide 20 ans."""
    cle = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    sujet = nom("Lab Root CA")
    cert = emettre(
        sujet, cle.public_key(), sujet, cle, hashes.SHA256(), validite(20 * UN_AN),
        [(x509.BasicConstraints(ca=True, path_length=1), True),
         (usages(key_cert_sign=True, crl_sign=True), True)],
    )
    ctx.ecrire_hors_si("ca/racine.key", pem_cle(cle))
    ctx.ecrire("certs/ca/racine.crt", pem_certificats(cert))
    return cle, cert


def generer_intermediaire(ctx: Contexte, cle_racine, racine: x509.Certificate):
    """QR-003, QR-004, QR-066 : AC intermédiaire ECDSA P-384, signée par la racine (donc en RSA)."""
    cle = ec.generate_private_key(ec.SECP384R1())
    cert = emettre(
        nom("Lab Intermediate CA"), cle.public_key(), racine.subject, cle_racine,
        hashes.SHA256(), validite(10 * UN_AN),
        [(x509.BasicConstraints(ca=True, path_length=0), True),
         (usages(key_cert_sign=True, crl_sign=True), True)],
        cle_publique_emetteur=racine.public_key(),
    )
    ctx.ecrire_hors_si("ca/intermediaire.key", pem_cle(cle))
    ctx.ecrire("certs/ca/intermediaire.crt", pem_certificats(cert))
    return cle, cert


# --- Étape 4 : les certificats feuilles ---


def emettre_feuille(cle_inter, inter: x509.Certificate, nom_commun: str, cle, jours: int, extensions):
    """Certificat final signé par l'intermédiaire ECDSA P-384, donc en ecdsa-with-SHA384."""
    return emettre(
        nom(nom_commun), cle.public_key(), inter.subject, cle_inter, hashes.SHA384(),
        validite(jours), extensions, cle_publique_emetteur=inter.public_key(),
    )


def generer_feuilles(ctx: Contexte, cle_inter, inter: x509.Certificate) -> dict:
    """QR-005 à QR-012, QR-067 à QR-070. Renvoie {nom: (clé privée, certificat)}."""
    serveur = [ExtendedKeyUsageOID.SERVER_AUTH]
    feuilles = {
        # keyEncipherment : indispensable à l'échange de clés RSA de TLS 1.2, où le client
        # chiffre le pre-master secret avec la clé publique du serveur (actif caché QR-015).
        "nginx": (rsa.generate_private_key(65537, 2048), "app.lab.local", UN_AN, lambda: extensions_feuille(
            usages(digital_signature=True, key_encipherment=True), serveur, ("app.lab.local", "api.lab.local"))),
        "base": (rsa.generate_private_key(65537, 3072), "db.lab.local", 2 * UN_AN, lambda: extensions_feuille(
            usages(digital_signature=True, key_encipherment=True), serveur, ("db.lab.local",))),
        "factures": (ec.generate_private_key(ec.SECP256R1()), "Lab Factures", 3 * UN_AN, lambda: extensions_feuille(
            usages(digital_signature=True, content_commitment=True))),
        "admin": (ec.generate_private_key(ec.SECP256R1()), "admin", UN_AN, lambda: extensions_feuille(
            usages(digital_signature=True), [ExtendedKeyUsageOID.CLIENT_AUTH])),
    }
    resultat = {}
    for cle_nom, (cle, nom_commun, jours, extensions) in feuilles.items():
        resultat[cle_nom] = (cle, emettre_feuille(cle_inter, inter, nom_commun, cle, jours, extensions()))
    ctx.ecrire("nginx/ssl/server.crt", pem_certificats(resultat["nginx"][1]))
    ctx.ecrire("db/tls/server.crt", pem_certificats(resultat["base"][1]))
    ctx.ecrire("factures/keys/factures.crt", pem_certificats(resultat["factures"][1]))
    ctx.ecrire("clients/admin/admin.crt", pem_certificats(resultat["admin"][1]))
    return resultat


# --- Étape 8 (QR-045) : l'ancienne AC oubliée ---

# OID DER (balise, longueur, valeur) : sha256WithRSAEncryption et sha1WithRSAEncryption.
_OID_SHA256_RSA = bytes.fromhex("06092a864886f70d01010b")
_OID_SHA1_RSA = bytes.fromhex("06092a864886f70d010105")


def resigner_en_sha1(cert: x509.Certificate, cle: rsa.RSAPrivateKey) -> x509.Certificate:
    """Transforme un certificat signé en sha256WithRSAEncryption en sha1WithRSAEncryption.

    Depuis la version 47, `cryptography` refuse de signer un certificat en SHA-1. On
    signe donc d'abord en SHA-256, puis on remplace l'OID de l'algorithme (présent dans
    le TBS et dans l'enveloppe) et on recalcule la signature RSA du TBS avec SHA-1. Les
    deux OID ont la même longueur et la signature RSA garde la taille de la clé : aucune
    longueur DER ne change.
    """
    der = cert.public_bytes(serialization.Encoding.DER)
    assert der.count(_OID_SHA256_RSA) == 2, "OID de signature attendu dans le TBS et dans l'enveloppe"
    tbs = cert.tbs_certificate_bytes.replace(_OID_SHA256_RSA, _OID_SHA1_RSA)
    signature = cle.sign(tbs, padding.PKCS1v15(), hashes.SHA1())
    assert der.endswith(cert.signature) and len(signature) == len(cert.signature)
    nouveau = der[: -len(signature)].replace(_OID_SHA256_RSA, _OID_SHA1_RSA) + signature
    return x509.load_der_x509_certificate(nouveau)



def generer_ancienne_ac(ctx: Contexte) -> x509.Certificate:
    """QR-045 : ancienne AC RSA-1024 signée en SHA-1, valide de 2015 à 2035 (dates fixées)."""
    cle = rsa.generate_private_key(65537, 1024)
    sujet = nom("Lab CA 2015")
    debut = dt.datetime(2015, 3, 1, tzinfo=dt.timezone.utc)
    fin = dt.datetime(2035, 3, 1, tzinfo=dt.timezone.utc)
    cert = emettre(
        sujet, cle.public_key(), sujet, cle, hashes.SHA256(), (debut, fin),
        [(x509.BasicConstraints(ca=True, path_length=None), True),
         (usages(key_cert_sign=True, crl_sign=True), True)],
    )
    cert = resigner_en_sha1(cert, cle)
    ctx.ecrire_hors_si("ca/ancienne_ac.key", pem_cle(cle))
    return cert


# --- Étape 7 : le conteneur PKCS#12 des factures ---


def conteneur_factures(cle, cert: x509.Certificate, mot_de_passe: str) -> bytes:
    """QR-020, QR-021 : PKCS#12 à l'ancien format (PBES1 3DES pour la clé et le certificat, MAC SHA-1).

    `cryptography` ne sait pas produire RC2-40 : le certificat est donc lui aussi
    chiffré en 3DES, contrairement à l'option -legacy d'OpenSSL.
    """
    chiffrement = (
        serialization.PrivateFormat.PKCS12.encryption_builder()
        .kdf_rounds(2048)
        .key_cert_algorithm(pkcs12.PBES.PBESv1SHA1And3KeyTripleDESCBC)
        .hmac_hash(hashes.SHA1())
        .build(mot_de_passe.encode())
    )
    return pkcs12.serialize_key_and_certificates(b"factures", cle, cert, None, chiffrement)


# --- Enchaînement : étapes 5, 6, 7 et 8 ---


def generer_pki(ctx: Contexte) -> None:
    """Étape PKI du générateur."""
    cle_racine, racine = generer_racine(ctx)
    cle_inter, inter = generer_intermediaire(ctx, cle_racine, racine)
    feuilles = generer_feuilles(ctx, cle_inter, inter)
    ancienne_ac = generer_ancienne_ac(ctx)

    # Étape 5 : copies de la racine et chaînes.
    ctx.ecrire("nginx/ssl/ca_clients.crt", pem_certificats(racine))  # vérifie les clients mTLS
    ctx.ecrire("db/tls/root.crt", pem_certificats(racine))
    # QR-045 : l'ancienne AC est restée dans le magasin de confiance de l'API, après la racine.
    ctx.ecrire("api/config/ca_bundle.pem", pem_certificats(racine, ancienne_ac))
    ctx.ecrire("nginx/ssl/fullchain.pem", pem_certificats(feuilles["nginx"][1], inter))

    # Étape 6 : clés privées des feuilles (QR-047 à QR-049).
    ctx.ecrire("nginx/ssl/server.key", pem_cle(feuilles["nginx"][0]), prive=True)  # nginx redémarre seul
    ctx.ecrire("db/tls/server.key", pem_cle(feuilles["base"][0]), prive=True)
    ctx.ecrire(
        "clients/admin/admin.key",
        pem_cle(feuilles["admin"][0], ctx.valeurs["PHRASE_DE_PASSE_ADMIN_MTLS"]),
        prive=True,
    )

    # Étape 7 : conteneur PKCS#12 des factures (mot de passe = KEYSTORE_PASS du .env).
    cle_factures, cert_factures = feuilles["factures"]
    ctx.ecrire(
        "factures/keys/factures.p12",
        conteneur_factures(cle_factures, cert_factures, ctx.valeurs["MOT_DE_PASSE_CONTENEUR_FACTURES"]),
        prive=True,
    )

    # Étape 8 (QR-046) : copie oubliée de la clé de l'intermédiaire, en clair, dans un vieux dossier.
    ctx.ecrire("deploy/old/backup_2024/inter.key", pem_cle(cle_inter), prive=True)
