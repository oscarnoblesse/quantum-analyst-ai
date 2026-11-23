"""Formats écrits à la main pour la variante 2, faute de bibliothèque d'écriture courante.

Chaque format suit sa documentation publique ; sa lecture est vérifiée dans les tests par
un outil tiers quand il en existe un (pyjks pour JKS, gpg pour OpenPGP, openssl pour PEM).
"""

from __future__ import annotations

import base64
import hashlib
import secrets
import struct

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa, x25519

from quantum_ready.si_fictif.openpgp import _mpi, _paquet, _sous_paquet, armure

# --- Magasin de clés Java (JKS) ---
# Format « JKS » de Sun : en-tête 0xFEEDFEED version 2, entrées, puis empreinte SHA-1 de
# l'ensemble. La clé privée est protégée par l'algorithme propriétaire de Sun
# (OID 1.3.6.1.4.1.42.2.17.1.1) : flux de SHA-1 enchaînés sur le mot de passe et un sel.

MAGIQUE_JKS = 0xFEEDFEED
OID_PROTECTION_SUN = bytes([0x2B, 0x06, 0x01, 0x04, 0x01, 0x2A, 0x02, 0x11, 0x01, 0x01])


def _der(etiquette: int, contenu: bytes) -> bytes:
    longueur = len(contenu)
    if longueur < 0x80:
        taille = bytes([longueur])
    else:
        octets = longueur.to_bytes((longueur.bit_length() + 7) // 8, "big")
        taille = bytes([0x80 | len(octets)]) + octets
    return bytes([etiquette]) + taille + contenu


def _utf_java(texte: str) -> bytes:
    donnees = texte.encode("utf-8")
    return struct.pack(">H", len(donnees)) + donnees


def _proteger_cle_sun(pkcs8: bytes, mot_de_passe: str) -> bytes:
    mdp = mot_de_passe.encode("utf-16-be")
    sel = secrets.token_bytes(20)
    flux, bloc = b"", sel
    while len(flux) < len(pkcs8):
        bloc = hashlib.sha1(mdp + bloc).digest()
        flux += bloc
    chiffre = bytes(a ^ b for a, b in zip(pkcs8, flux))
    controle = hashlib.sha1(mdp + pkcs8).digest()
    algorithme = _der(0x30, _der(0x06, OID_PROTECTION_SUN) + b"\x05\x00")
    return _der(0x30, algorithme + _der(0x04, sel + chiffre + controle))


def keystore_jks(alias: str, cle: rsa.RSAPrivateKey, chaine_der: list[bytes], mot_de_passe: str,
                 horodatage_ms: int) -> bytes:
    """Keystore JKS contenant une entrée de clé privée et sa chaîne de certificats."""
    pkcs8 = cle.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
                              serialization.NoEncryption())
    protegee = _proteger_cle_sun(pkcs8, mot_de_passe)
    entree = (
        struct.pack(">I", 1) + _utf_java(alias) + struct.pack(">Q", horodatage_ms)
        + struct.pack(">I", len(protegee)) + protegee
        + struct.pack(">I", len(chaine_der))
        + b"".join(_utf_java("X.509") + struct.pack(">I", len(c)) + c for c in chaine_der)
    )
    corps = struct.pack(">III", MAGIQUE_JKS, 2, 1) + entree
    empreinte = hashlib.sha1(mot_de_passe.encode("utf-16-be") + b"Mighty Aphrodite" + corps).digest()
    return corps + empreinte


# --- Clé publique OpenPGP EdDSA (Ed25519, algorithme 22) ---

ALGO_EDDSA = 22
OID_ED25519 = bytes([0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01])
HACHAGE_SHA256 = 8


def cle_publique_eddsa(cle: ed25519.Ed25519PrivateKey, identite: str, creation: int) -> str:
    """Clé publique OpenPGP v4 EdDSA auto-signée (format « legacy » lu par GnuPG 2.2+)."""
    brute = cle.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    point = int.from_bytes(b"\x40" + brute, "big")
    corps_cle = (bytes([4]) + struct.pack(">I", creation) + bytes([ALGO_EDDSA])
                 + bytes([len(OID_ED25519)]) + OID_ED25519 + _mpi(point))
    empreinte = hashlib.sha1(b"\x99" + struct.pack(">H", len(corps_cle)) + corps_cle).digest()
    uid = identite.encode("utf-8")
    hachees = (
        _sous_paquet(2, struct.pack(">I", creation))
        + _sous_paquet(27, bytes([0x03]))  # certifier, signer
        + _sous_paquet(33, bytes([4]) + empreinte)
    )
    entete = bytes([4, 0x13, ALGO_EDDSA, HACHAGE_SHA256]) + struct.pack(">H", len(hachees)) + hachees
    a_signer = (
        b"\x99" + struct.pack(">H", len(corps_cle)) + corps_cle
        + b"\xb4" + struct.pack(">I", len(uid)) + uid
        + entete + b"\x04\xff" + struct.pack(">I", len(entete))
    )
    condense = hashlib.sha256(a_signer).digest()
    signature = cle.sign(condense)  # EdDSA OpenPGP : signature du condensé
    non_hachees = _sous_paquet(16, empreinte[-8:])
    corps_signature = (
        entete + struct.pack(">H", len(non_hachees)) + non_hachees + condense[:2]
        + _mpi(int.from_bytes(signature[:32], "big")) + _mpi(int.from_bytes(signature[32:], "big"))
    )
    return armure(_paquet(6, corps_cle) + _paquet(13, uid) + _paquet(2, corps_signature))


# --- DNSSEC : enregistrement DNSKEY RSA/SHA-256 (RFC 3110, RFC 5702) ---


def dnskey_rsa(cle: rsa.RSAPrivateKey) -> str:
    """Champ « clé publique » d'un DNSKEY d'algorithme 8 (RSASHA256), en base64."""
    publiques = cle.public_key().public_numbers()
    exposant = publiques.e.to_bytes((publiques.e.bit_length() + 7) // 8, "big")
    module = publiques.n.to_bytes((publiques.n.bit_length() + 7) // 8, "big")
    return base64.b64encode(bytes([len(exposant)]) + exposant + module).decode()


# --- WireGuard et OpenVPN ---


def cle_wireguard() -> tuple[str, str]:
    """(clé privée, clé publique) X25519 en base64, comme `wg genkey | wg pubkey`."""
    cle = x25519.X25519PrivateKey.generate()
    privee = cle.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                               serialization.NoEncryption())
    publique = cle.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return base64.b64encode(privee).decode(), base64.b64encode(publique).decode()


def cle_statique_openvpn() -> str:
    """Clé statique OpenVPN (2048 bits), comme `openvpn --genkey secret`."""
    hexa = secrets.token_bytes(256).hex()
    lignes = [hexa[i:i + 32] for i in range(0, len(hexa), 32)]
    return ("#\n# 2048 bit OpenVPN static key\n#\n-----BEGIN OpenVPN Static key V1-----\n"
            + "\n".join(lignes) + "\n-----END OpenVPN Static key V1-----")
