"""Clé publique OpenPGP (RFC 4880) des sauvegardes, construite sans dépendre de gpg.

Une clé publique OpenPGP « armurée » est une suite de paquets binaires :
  1. le paquet de clé publique (algorithme, date, n et e pour RSA) ;
  2. le paquet d'identité (« Nom <adresse> ») ;
  3. la signature de cette identité par la clé elle-même (auto-signature), sans
     laquelle gpg refuse d'importer la clé.
"""

from __future__ import annotations

import base64
import hashlib
import struct
import time

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

ALGO_RSA = 1
HACHAGE_SHA256 = 8
# Préférences annoncées par la clé : AES-256, AES-192, AES-128 / SHA-256.
PREFERENCES_SYMETRIQUES = bytes([9, 8, 7])


def _mpi(nombre: int) -> bytes:
    """Entier multiprécision OpenPGP : nombre de bits sur 2 octets, puis l'entier."""
    return struct.pack(">H", nombre.bit_length()) + nombre.to_bytes((nombre.bit_length() + 7) // 8, "big")


def _paquet(etiquette: int, corps: bytes) -> bytes:
    """En-tête de paquet au « nouveau format » (RFC 4880, section 4.2.2)."""
    longueur = len(corps)
    if longueur < 192:
        taille = bytes([longueur])
    elif longueur < 8384:
        longueur -= 192
        taille = bytes([(longueur >> 8) + 192, longueur & 0xFF])
    else:
        taille = b"\xff" + struct.pack(">I", longueur)
    return bytes([0xC0 | etiquette]) + taille + corps


def _sous_paquet(type_: int, donnees: bytes) -> bytes:
    return bytes([len(donnees) + 1, type_]) + donnees


def _crc24(donnees: bytes) -> int:
    crc = 0xB704CE
    for octet in donnees:
        crc ^= octet << 16
        for _ in range(8):
            crc <<= 1
            if crc & 0x1000000:
                crc ^= 0x1864CFB
    return crc & 0xFFFFFF


def armure(donnees: bytes) -> str:
    """Armure ASCII : base64 en lignes de 64 caractères, puis somme de contrôle CRC-24."""
    corps = base64.b64encode(donnees).decode()
    lignes = [corps[i : i + 64] for i in range(0, len(corps), 64)]
    somme = base64.b64encode(_crc24(donnees).to_bytes(3, "big")).decode()
    return (
        "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n"
        + "\n".join(lignes)
        + f"\n={somme}\n-----END PGP PUBLIC KEY BLOCK-----\n"
    )


def cle_publique_rsa(cle: rsa.RSAPrivateKey, identite: str, creation: int | None = None) -> str:
    """Construit la clé publique OpenPGP v4 auto-signée correspondant à une clé RSA."""
    creation = int(time.time()) if creation is None else creation
    publiques = cle.public_key().public_numbers()
    corps_cle = bytes([4]) + struct.pack(">I", creation) + bytes([ALGO_RSA]) + _mpi(publiques.n) + _mpi(publiques.e)
    empreinte = hashlib.sha1(b"\x99" + struct.pack(">H", len(corps_cle)) + corps_cle).digest()
    uid = identite.encode("utf-8")

    hachees = (
        _sous_paquet(2, struct.pack(">I", creation))   # date de la signature
        + _sous_paquet(27, bytes([0x0F]))               # usages : certifier, signer, chiffrer
        + _sous_paquet(11, PREFERENCES_SYMETRIQUES)     # algorithmes symétriques préférés
        + _sous_paquet(21, bytes([HACHAGE_SHA256]))     # hachage préféré
        + _sous_paquet(33, bytes([4]) + empreinte)      # empreinte de l'émetteur
    )
    entete = bytes([4, 0x13, ALGO_RSA, HACHAGE_SHA256]) + struct.pack(">H", len(hachees)) + hachees
    a_signer = (
        b"\x99" + struct.pack(">H", len(corps_cle)) + corps_cle
        + b"\xb4" + struct.pack(">I", len(uid)) + uid
        + entete
        + b"\x04\xff" + struct.pack(">I", len(entete))
    )
    signature = cle.sign(a_signer, padding.PKCS1v15(), hashes.SHA256())
    non_hachees = _sous_paquet(16, empreinte[-8:])  # identifiant de clé de l'émetteur
    corps_signature = (
        entete
        + struct.pack(">H", len(non_hachees)) + non_hachees
        + hashlib.sha256(a_signer).digest()[:2]
        + _mpi(int.from_bytes(signature, "big"))
    )
    return armure(_paquet(6, corps_cle) + _paquet(13, uid) + _paquet(2, corps_signature))


def lire_cle_publique(texte: str) -> dict:
    """Relit l'algorithme, la taille et l'identité d'une clé armurée (pour les contrôles)."""
    lignes = texte.strip().splitlines()
    corps = "".join(l for l in lignes[2:-1] if not l.startswith("="))
    donnees = base64.b64decode(corps)
    resultat, position = {}, 0
    while position < len(donnees):
        etiquette = donnees[position] & 0x3F
        premier = donnees[position + 1]
        if premier < 192:
            longueur, debut = premier, position + 2
        elif premier < 255:
            longueur, debut = ((premier - 192) << 8) + donnees[position + 2] + 192, position + 3
        else:
            longueur, debut = struct.unpack(">I", donnees[position + 2 : position + 6])[0], position + 6
        corps_paquet = donnees[debut : debut + longueur]
        if etiquette == 6:
            resultat["algorithme"] = {ALGO_RSA: "RSA"}.get(corps_paquet[5], corps_paquet[5])
            resultat["taille"] = struct.unpack(">H", corps_paquet[6:8])[0]
        elif etiquette == 13:
            resultat["identite"] = corps_paquet.decode("utf-8")
        position = debut + longueur
    return resultat
