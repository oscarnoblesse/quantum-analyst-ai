"""PKI de Fret Lab (V2-001 à V2-018) et clés associées (V2-067 à V2-072, V2-081, V2-098).

Hiérarchie :
    AC racine Fret Lab (RSA-3072, 20 ans)
      └─ AC d'exploitation Fret Lab (ECDSA P-256, 8 ans)
           ├─ suivi.fret.lab.local (RSA-2048)          portail de suivi des colis
           ├─ edi.fret.lab.local (ECDSA P-384, DER)    échange EDI avec la douane
           ├─ camion-0427 (Ed25519, client mTLS)        télématique de la flotte
           └─ passerelle-flotte (RSA-2048, keystore JKS de la passerelle Java)
    AC Douane 2012 (RSA-1024, SHA-1), recopiée dans une procédure en .txt
"""

from __future__ import annotations

import base64
import datetime as dt

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from quantum_ready.si_fictif.generateur import Contexte
from quantum_ready.si_fictif.pki import resigner_en_sha1  # import seul : pki.py (v1) n'est pas modifié
from quantum_ready.si_fictif.v2 import formats
from quantum_ready.si_fictif.v2.valeurs import DOMAINE, MAINTENANT, ORGANISATION, alea

JOUR = dt.timedelta(days=1)
AN = dt.timedelta(days=365)


def publiques(ctx: Contexte) -> dict[str, str]:
    """Valeurs publiques partagées entre étapes (PEM de certificats, clés publiques)."""
    return ctx.__dict__.setdefault("publiques", {})


def nom(nom_commun: str, organisation: str = ORGANISATION) -> x509.Name:
    return x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "FR"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, organisation),
        x509.NameAttribute(NameOID.COMMON_NAME, nom_commun),
    ])


def pem(*certs: x509.Certificate) -> str:
    return "".join(c.public_bytes(serialization.Encoding.PEM).decode() for c in certs)


def cle_pem(cle, format_=serialization.PrivateFormat.PKCS8, phrase: str | None = None) -> str:
    chiffrement = (serialization.BestAvailableEncryption(phrase.encode()) if phrase
                   else serialization.NoEncryption())
    return cle.private_bytes(serialization.Encoding.PEM, format_, chiffrement).decode()


class Emetteur:
    """Construit des certificats avec des numéros de série tirés d'une graine fixe."""

    def __init__(self) -> None:
        self._alea = alea()

    def certificat(self, sujet: x509.Name, cle_publique, emetteur: x509.Name, cle_emetteur, hachage,
                   debut: dt.datetime, duree: dt.timedelta, ac: bool, extensions=()) -> x509.Certificate:
        constructeur = (
            x509.CertificateBuilder()
            .subject_name(sujet)
            .issuer_name(emetteur)
            .public_key(cle_publique)
            .serial_number(self._alea.getrandbits(63) + 1)
            .not_valid_before(debut)
            .not_valid_after(debut + duree)
            .add_extension(x509.BasicConstraints(ca=ac, path_length=None), critical=True)
        )
        for extension, critique in extensions:
            constructeur = constructeur.add_extension(extension, critical=critique)
        return constructeur.sign(cle_emetteur, hachage)


def _usage_ac() -> tuple:
    return (x509.KeyUsage(digital_signature=False, content_commitment=False, key_encipherment=False,
                          data_encipherment=False, key_agreement=False, key_cert_sign=True, crl_sign=True,
                          encipher_only=False, decipher_only=False), True)


def _feuille(eku, noms_dns=()) -> list:
    extensions = [
        (x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False,
                       data_encipherment=False, key_agreement=False, key_cert_sign=False, crl_sign=False,
                       encipher_only=False, decipher_only=False), True),
        (x509.ExtendedKeyUsage([eku]), False),
    ]
    if noms_dns:
        extensions.append((x509.SubjectAlternativeName([x509.DNSName(n) for n in noms_dns]), False))
    return extensions


PROCEDURE_DOUANE = """Procédure : raccordement au portail EDI de la douane (version 2012)
=====================================================================

1. Demander le compte EDI auprès du bureau de dédouanement de rattachement.
2. Importer l'autorité ci-dessous dans le magasin de confiance du poste de saisie.
3. Tester l'envoi d'un message de déclaration sur l'environnement de recette.

Autorité de la douane (fournie par le prestataire en 2012, à conserver) :

{certificat}
En cas de rejet du certificat, contacter l'assistance du prestataire.
"""


def generer_pki(ctx: Contexte) -> None:
    emetteur = Emetteur()
    p = publiques(ctx)

    # V2-001 à V2-003 : AC racine, RSA-3072, sha384WithRSAEncryption, 20 ans.
    cle_racine = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    nom_racine = nom("AC Racine Fret Lab")
    racine = emetteur.certificat(nom_racine, cle_racine.public_key(), nom_racine, cle_racine, hashes.SHA384(),
                                 MAINTENANT - 3 * AN, 20 * AN, True, [_usage_ac()])

    # V2-004 à V2-006 : AC d'exploitation, ECDSA P-256, signée par la racine en SHA-384, 8 ans.
    cle_exploitation = ec.generate_private_key(ec.SECP256R1())
    nom_exploitation = nom("AC Exploitation Fret Lab")
    exploitation = emetteur.certificat(nom_exploitation, cle_exploitation.public_key(), nom_racine, cle_racine,
                                       hashes.SHA384(), MAINTENANT - 2 * AN, 8 * AN, True, [_usage_ac()])

    def feuille(nom_commun, cle, eku, noms_dns=(), duree=398 * JOUR):
        return emetteur.certificat(nom(nom_commun), cle.public_key(), nom_exploitation, cle_exploitation,
                                   hashes.SHA256(), MAINTENANT - 30 * JOUR, duree, False, _feuille(eku, noms_dns))

    # V2-007 à V2-009 et V2-067 : portail de suivi, RSA-2048.
    cle_suivi = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    suivi = feuille(f"suivi.{DOMAINE}", cle_suivi, ExtendedKeyUsageOID.SERVER_AUTH, [f"suivi.{DOMAINE}"])

    # V2-010 à V2-012 et V2-068 : serveur EDI, ECDSA P-384, certificat au format DER.
    cle_edi = ec.generate_private_key(ec.SECP384R1())
    edi = feuille(f"edi.{DOMAINE}", cle_edi, ExtendedKeyUsageOID.SERVER_AUTH, [f"edi.{DOMAINE}"])

    # V2-013 à V2-015 et V2-070 : certificat client du camion 0427, Ed25519, 2 ans.
    cle_camion = ed25519.Ed25519PrivateKey.generate()
    camion = feuille("camion-0427", cle_camion, ExtendedKeyUsageOID.CLIENT_AUTH, duree=2 * AN)

    # V2-016 à V2-018 : ancienne AC de la douane, RSA-1024, SHA-1, émise il y a 14 ans pour 20 ans.
    cle_douane = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    nom_douane = nom("AC Douane EDI 2012", "Prestataire EDI")
    # cryptography refuse de signer en SHA-1 : on signe en SHA-256, puis on re-signe en SHA-1.
    douane = resigner_en_sha1(
        emetteur.certificat(nom_douane, cle_douane.public_key(), nom_douane, cle_douane, hashes.SHA256(),
                            MAINTENANT - 14 * AN, 20 * AN, True, [_usage_ac()]),
        cle_douane,
    )

    ctx.ecrire("pki/racine/ac-racine.pem", pem(racine))
    ctx.ecrire("pki/exploitation/ac-exploitation.pem", pem(exploitation))
    ctx.ecrire("portail/tls/suivi.crt", pem(suivi))
    ctx.ecrire("portail/tls/suivi.key", cle_pem(cle_suivi, serialization.PrivateFormat.TraditionalOpenSSL),
               prive=True)
    ctx.ecrire("portail/tls/chaine.pem", pem(exploitation, racine))
    ctx.ecrire("edi/certs/edi-douane.der", edi.public_bytes(serialization.Encoding.DER))
    ctx.ecrire("edi/certs/ca.pem", pem(racine))
    ctx.ecrire("edi/certs/procedure_douane.txt", PROCEDURE_DOUANE.format(certificat=pem(douane)))
    ctx.ecrire("flotte/certs/camion-0427.crt", pem(camion))
    ctx.ecrire("flotte/certs/camion-0427.key", cle_pem(cle_camion), prive=True)

    # V2-068 : PKCS#12 moderne (PBES2 AES-256-CBC, PBKDF2, MAC HMAC-SHA256).
    chiffrement_p12 = (
        serialization.PrivateFormat.PKCS12.encryption_builder()
        .kdf_rounds(100_000)
        .key_cert_algorithm(pkcs12.PBES.PBESv2SHA256AndAES256CBC)
        .hmac_hash(hashes.SHA256())
        .build(ctx.valeurs["EDI_CONTENEUR_SECRET"].encode())
    )
    ctx.ecrire("edi/certs/edi-douane.p12",
               pkcs12.serialize_key_and_certificates(b"edi-douane", cle_edi, edi, [exploitation, racine],
                                                     chiffrement_p12), prive=True)

    # V2-071 : clé de signature des e-CMR, ECDSA P-256, PKCS#8 chiffré par phrase de passe.
    cle_cmr = ec.generate_private_key(ec.SECP256R1())
    ctx.ecrire("lettres/cles/signature-cmr.pem", cle_pem(cle_cmr, phrase=ctx.valeurs["PHRASE_CLE_CMR"]),
               prive=True)

    # V2-072 : copie oubliée de la clé de l'AC d'exploitation, en clair.
    ctx.ecrire("sauvegardes/2021/exploitation.bak",
               cle_pem(cle_exploitation, serialization.PrivateFormat.TraditionalOpenSSL))

    # V2-081 : keystore JKS de la passerelle Java (clé RSA-2048, chaîne jusqu'à la racine).
    cle_passerelle = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    passerelle = feuille(f"passerelle-flotte.{DOMAINE}", cle_passerelle, ExtendedKeyUsageOID.SERVER_AUTH,
                         [f"passerelle-flotte.{DOMAINE}"])
    chaine = [c.public_bytes(serialization.Encoding.DER) for c in (passerelle, exploitation, racine)]
    horodatage = int((MAINTENANT - 30 * JOUR).timestamp()) * 1000
    ctx.ecrire("flotte/passerelle-java/src/main/resources/keystore.jks",
               formats.keystore_jks("passerelle", cle_passerelle, chaine, ctx.valeurs["MOT_DE_PASSE_KEYSTORE"],
                                    horodatage), prive=True)

    # V2-098 : certificat de signature du fournisseur d'identité SAML (RSA-2048, auto-signé).
    cle_idp = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    nom_idp = nom(f"sso.{DOMAINE}")
    idp = emetteur.certificat(nom_idp, cle_idp.public_key(), nom_idp, cle_idp, hashes.SHA256(),
                              MAINTENANT - 60 * JOUR, 3 * AN, False, _feuille(ExtendedKeyUsageOID.SERVER_AUTH))
    der_idp = idp.public_bytes(serialization.Encoding.DER)
    corps = base64.b64encode(der_idp).decode()
    p["CERTIFICAT_SAML"] = "\n".join(corps[i:i + 64] for i in range(0, len(corps), 64))

    # V2-046 : clé publique RSA-2048 du partenaire, recopiée en PEM dans le code Python.
    cle_partenaire = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    p["CLE_PUBLIQUE_PARTENAIRE"] = cle_partenaire.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode().strip()

    # V2-099 : clé de signature de clés DNSSEC (KSK), RSA-2048, algorithme 8.
    p["DNSKEY_KSK"] = formats.dnskey_rsa(rsa.generate_private_key(public_exponent=65537, key_size=2048))

    # Leurre L2-04 : certificat de test auto-signé, sous tests/ (non compté comme actif).
    cle_test = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    nom_test = nom("test.example", "Tests")
    test = emetteur.certificat(nom_test, cle_test.public_key(), nom_test, cle_test, hashes.SHA256(),
                               MAINTENANT - JOUR, 30 * JOUR, False)
    ctx.ecrire("suivi/tests/donnees/certificat_test.pem", pem(test))
