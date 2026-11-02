"""Outil analyser_cle : clés privées et publiques, quel que soit leur format.

Formats reconnus, d'après le contenu :
- clés privées PEM : PKCS#8, format « traditionnel » (RSA/EC/DSA), PKCS#8 chiffré ;
- clés privées OpenSSH (« openssh-key-v1 »), chiffrées ou non ;
- clés publiques SSH, une par ligne (.pub, authorized_keys, known_hosts) ;
- clés publiques OpenPGP armurées (GPG) ;
- paramètres Diffie-Hellman (dhparam).

Pour les clés SSH, l'empreinte est calculée comme le fait `ssh-keygen -l` :
SHA-256 du blob de la clé, en base64 sans « = » final.

Une clé chiffrée cache parfois son type : l'outil le dit franchement plutôt que de
deviner, et laisse une piste à l'agent (chercher le certificat associé).
"""

from __future__ import annotations

import base64
import hashlib
import re
import struct
import warnings
from pathlib import Path

from cryptography.hazmat.primitives import serialization

from quantum_ready.outils._cles import COURBES, decrire_cle, empreinte_spki
from quantum_ready.outils.classification import exposition
from quantum_ready.outils.commun import ErreurOutil, Piste, Resultat, Trouvaille, outil, relatif, resoudre

NOM = "analyser_cle"
_BLOC_PEM = re.compile(r"-----BEGIN ([A-Z0-9 ]+)-----\n(.*?)-----END \1-----", re.S)
_TYPE_SSH = re.compile(r"^(ssh-(rsa|dss|ed25519|ed448)|ecdsa-sha2-nistp\d+|sk-\S+)$")
ALGOS_OPENPGP = {1: "RSA", 2: "RSA", 3: "RSA", 16: "ElGamal", 17: "DSA", 18: "ECDH", 19: "ECDSA", 22: "EdDSA", 25: "X25519", 27: "Ed25519"}


# --- Format SSH : des « string » préfixées par leur longueur sur 4 octets ---

def _chaine(donnees: bytes, position: int) -> tuple[bytes, int]:
    (longueur,) = struct.unpack(">I", donnees[position : position + 4])
    fin = position + 4 + longueur
    if fin > len(donnees):
        raise ErreurOutil("Structure SSH tronquée")
    return donnees[position + 4 : fin], fin


def empreinte_ssh(blob: bytes) -> str:
    """Empreinte affichée par `ssh-keygen -l` (format SHA256 par défaut)."""
    return "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")


def decrire_blob_ssh(blob: bytes) -> tuple[str, dict]:
    """Type et taille d'une clé publique SSH, lus directement dans son blob."""
    type_cle, position = _chaine(blob, 0)
    type_cle = type_cle.decode()
    props: dict = {"type_ssh": type_cle, "empreinte": empreinte_ssh(blob)}
    if type_cle == "ssh-rsa":
        _exposant, position = _chaine(blob, position)
        module, _ = _chaine(blob, position)
        taille = int.from_bytes(module, "big").bit_length()
        props |= {"algorithme": "RSA", "taille": taille}
        if taille < 2048:
            props["faiblesse_classique"] = f"taille insuffisante aujourd'hui ({taille} bits)"
        return f"RSA-{taille}", props
    if type_cle == "ssh-dss":
        premier, _ = _chaine(blob, position)
        taille = int.from_bytes(premier, "big").bit_length()
        props |= {"algorithme": "DSA", "taille": taille, "faiblesse_classique": "DSA est obsolète (retiré d'OpenSSH)"}
        return f"DSA-{taille}", props
    if type_cle.startswith("ecdsa-sha2-"):
        courbe = {"nistp256": "P-256", "nistp384": "P-384", "nistp521": "P-521"}.get(type_cle[11:], type_cle[11:])
        props |= {"algorithme": "ECDSA", "courbe": courbe}
        return f"ECDSA {courbe}", props
    if type_cle in ("ssh-ed25519", "ssh-ed448"):
        nom = "Ed25519" if type_cle == "ssh-ed25519" else "Ed448"
        props["algorithme"] = nom
        return nom, props
    props["algorithme"] = type_cle
    return type_cle, props


def lignes_ssh(texte: str, fichier: str) -> list[Trouvaille]:
    """Clés publiques SSH d'un fichier, une par ligne, avec leur préfixe (hôte ou options)."""
    trouvailles = []
    for numero, ligne in enumerate(texte.splitlines(), start=1):
        mots = ligne.split()
        if not mots or mots[0].startswith("#"):
            continue
        rang = next((i for i, mot in enumerate(mots[:-1]) if _TYPE_SSH.match(mot) and mots[i + 1].startswith("AAAA")), None)
        if rang is None:
            continue
        blob = base64.b64decode(mots[rang + 1])
        nom, props = decrire_blob_ssh(blob)
        prefixe, commentaire = " ".join(mots[:rang]), " ".join(mots[rang + 2 :])
        if commentaire:
            props["commentaire"] = commentaire
        if prefixe and "=" not in prefixe and '"' not in prefixe:
            props["hotes"] = prefixe.split(",")
            description = f"Clé publique SSH {nom} mémorisée pour l'hôte « {prefixe} »"
        else:
            if prefixe:
                props["options"] = prefixe
            description = f"Clé publique SSH {nom}" + (f" (« {commentaire} »)" if commentaire else "")
        trouvailles.append(Trouvaille(
            outil=NOM, fichier=fichier, ligne=numero, type_actif="related-crypto-material",
            nom=nom, description=description, exposition=exposition(nom), proprietes=props,
            preuve=f"{mots[rang]} {mots[rang + 1][:20]}... {commentaire}".strip(),
        ))
    return trouvailles


# --- Clés privées ---

def cle_openssh(corps: bytes, fichier: str) -> Trouvaille:
    """Clé privée « openssh-key-v1 » : la clé publique et le chiffrement se lisent sans mot de passe."""
    donnees = base64.b64decode(corps)
    entete = b"openssh-key-v1\x00"
    if not donnees.startswith(entete):
        raise ErreurOutil("Clé OpenSSH illisible (en-tête inattendu)")
    chiffrement, position = _chaine(donnees, len(entete))
    derivation, position = _chaine(donnees, position)
    _options, position = _chaine(donnees, position)
    position += 4  # nombre de clés
    publique, _ = _chaine(donnees, position)
    nom, props = decrire_blob_ssh(publique)
    chiffree = chiffrement != b"none"
    props |= {"format": "OpenSSH", "chiffree": chiffree}
    if chiffree:
        props["chiffrement"] = f"{chiffrement.decode()} (dérivation {derivation.decode()})"
    etat = "chiffrée par phrase de passe" if chiffree else "NON chiffrée"
    return Trouvaille(
        outil=NOM, fichier=fichier, type_actif="related-crypto-material", nom=nom,
        description=f"Clé privée SSH {nom}, {etat}", exposition=exposition(nom), proprietes=props,
        preuve=f"-----BEGIN OPENSSH PRIVATE KEY----- (chiffrement : {chiffrement.decode()})",
    )


def cle_pem_chiffree_pkcs8(der: bytes, fichier: str) -> tuple[Trouvaille, Piste]:
    """PKCS#8 chiffré : l'algorithme de la clé est DANS la partie chiffrée, seul le chiffrement est visible."""
    from asn1crypto import keys

    algorithme = keys.EncryptedPrivateKeyInfo.load(der)["encryption_algorithm"]
    props: dict = {"format": "PKCS#8 chiffré", "chiffree": True}
    try:
        props["chiffrement"] = (
            f"{algorithme.kdf.upper()} ({algorithme.kdf_iterations} itérations), "
            f"{algorithme.encryption_cipher.upper()}-{algorithme.key_length * 8}"
        )
    except (ValueError, KeyError, AttributeError):
        props["chiffrement"] = algorithme["algorithm"].native
    trouvaille = Trouvaille(
        outil=NOM, fichier=fichier, type_actif="related-crypto-material", nom="Clé privée (type masqué)",
        description="Clé privée chiffrée par phrase de passe : son algorithme n'est pas lisible sans elle",
        exposition="inconnue", proprietes=props, preuve="-----BEGIN ENCRYPTED PRIVATE KEY-----",
    )
    piste = Piste(vers=str(Path(fichier).parent) + "/", raison="chercher le certificat associé à cette clé chiffrée pour connaître son algorithme")
    return trouvaille, piste


def cle_pem(etiquette: str, bloc: str, fichier: str) -> Trouvaille:
    """Clé privée PEM non chiffrée (PKCS#8 ou traditionnelle), ou traditionnelle chiffrée."""
    if "Proc-Type: 4,ENCRYPTED" in bloc:
        info = re.search(r"DEK-Info: ([^,\n]+)", bloc)
        algorithme = etiquette.replace(" PRIVATE KEY", "").replace("EC", "ECDSA")
        return Trouvaille(
            outil=NOM, fichier=fichier, type_actif="related-crypto-material", nom=f"{algorithme} (taille masquée)",
            description=f"Clé privée {algorithme} au format traditionnel, chiffrée par phrase de passe",
            exposition=exposition(algorithme),
            proprietes={"format": "PEM traditionnel chiffré", "chiffree": True, "chiffrement": info.group(1) if info else "?"},
            preuve=f"-----BEGIN {etiquette}----- / Proc-Type: 4,ENCRYPTED",
        )
    with warnings.catch_warnings():  # DSA est déprécié dans cryptography : on veut quand même le lire
        warnings.simplefilter("ignore")
        cle = serialization.load_pem_private_key(f"-----BEGIN {etiquette}-----\n{bloc}-----END {etiquette}-----\n".encode(), None)
    nom, props = decrire_cle(cle)
    props |= {
        "format": "PKCS#8" if etiquette == "PRIVATE KEY" else "PEM traditionnel",
        "chiffree": False,
        "empreinte_spki_sha256": empreinte_spki(cle),
    }
    return Trouvaille(
        outil=NOM, fichier=fichier, type_actif="related-crypto-material", nom=nom,
        description=f"Clé privée {nom}, NON chiffrée ({props['format']})", exposition=exposition(nom),
        proprietes=props, preuve=f"-----BEGIN {etiquette}-----",
    )


# --- OpenPGP (RFC 4880) ---

def paquets_openpgp(donnees: bytes):
    """Itère sur les paquets OpenPGP : (étiquette, corps). Gère l'ancien et le nouveau format d'en-tête."""
    position = 0
    while position < len(donnees):
        octet = donnees[position]
        if octet & 0x40:  # nouveau format
            etiquette, premier = octet & 0x3F, donnees[position + 1]
            if premier < 192:
                longueur, debut = premier, position + 2
            elif premier < 224:
                longueur, debut = ((premier - 192) << 8) + donnees[position + 2] + 192, position + 3
            else:
                longueur, debut = struct.unpack(">I", donnees[position + 2 : position + 6])[0], position + 6
        else:  # ancien format
            etiquette, type_longueur = (octet >> 2) & 0x0F, octet & 0x03
            taille = {0: 1, 1: 2, 2: 4}[type_longueur]
            longueur = int.from_bytes(donnees[position + 1 : position + 1 + taille], "big")
            debut = position + 1 + taille
        yield etiquette, donnees[debut : debut + longueur]
        position = debut + longueur


def cles_openpgp(texte: str, fichier: str) -> list[Trouvaille]:
    corps = texte.split("\n\n", 1)[1] if "\n\n" in texte else texte
    base = "".join(l.strip() for l in corps.splitlines() if l.strip() and not l.startswith(("=", "-----")))
    identites, cles = [], []
    for etiquette, contenu in paquets_openpgp(base64.b64decode(base)):
        if etiquette == 13:
            identites.append(contenu.decode("utf-8", "replace"))
        elif etiquette in (6, 14) and contenu and contenu[0] == 4:
            algorithme = ALGOS_OPENPGP.get(contenu[5], f"algorithme {contenu[5]}")
            taille = struct.unpack(">H", contenu[6:8])[0] if algorithme in ("RSA", "DSA", "ElGamal") else None
            cles.append((etiquette == 14, algorithme, taille))
    trouvailles = []
    for sous_cle, algorithme, taille in cles:
        nom = f"{algorithme}-{taille}" if taille else algorithme
        props: dict = {"format": "OpenPGP v4", "algorithme": algorithme, "sous_cle": sous_cle}
        if taille:
            props["taille"] = taille
        if identites:
            props["identites"] = identites
        role = "Sous-clé" if sous_cle else "Clé"
        trouvailles.append(Trouvaille(
            outil=NOM, fichier=fichier, type_actif="related-crypto-material", nom=nom,
            description=f"{role} publique OpenPGP {nom}" + (f" de « {identites[0]} »" if identites else ""),
            exposition=exposition(algorithme), proprietes=props, preuve="-----BEGIN PGP PUBLIC KEY BLOCK-----",
        ))
    return trouvailles


# --- Paramètres Diffie-Hellman ---

def parametres_dh(bloc: str, fichier: str) -> Trouvaille:
    from asn1crypto import algos

    parametres = algos.DHParameters.load(base64.b64decode(bloc))
    premier, generateur = parametres["p"].native, parametres["g"].native
    taille = premier.bit_length()
    masque = (1 << 64) - 1
    standard = (premier >> (taille - 64)) == masque and (premier & masque) == masque
    props: dict = {"algorithme": "DH", "taille": taille, "generateur": generateur, "groupe_standard": standard}
    if taille < 2048:
        props["faiblesse_classique"] = f"taille insuffisante aujourd'hui ({taille} bits)"
    return Trouvaille(
        outil=NOM, fichier=fichier, type_actif="algorithm", nom=f"DH-{taille}",
        description=f"Paramètres Diffie-Hellman sur corps fini, {taille} bits"
        + (" (groupe standard de type RFC 3526 / 7919)" if standard else " (groupe non standard)"),
        exposition="shor", proprietes=props, preuve="-----BEGIN DH PARAMETERS-----",
    )


@outil(NOM)
def analyser_cle(cible: str, racine: Path) -> Resultat:
    """Analyse les clés d'un fichier : type, taille, chiffrement, empreinte (comme ssh-keygen -l)."""
    chemin = resoudre(cible, racine)
    fichier = relatif(chemin, racine)
    texte = chemin.read_text(encoding="utf-8", errors="replace")
    droits = oct(chemin.stat().st_mode & 0o777)[2:]
    resultat = Resultat(outil=NOM, cible=fichier)
    for etiquette, bloc in _BLOC_PEM.findall(texte):
        if etiquette == "OPENSSH PRIVATE KEY":
            resultat.trouvailles.append(cle_openssh(bloc.encode(), fichier))
        elif etiquette == "ENCRYPTED PRIVATE KEY":
            trouvaille, piste = cle_pem_chiffree_pkcs8(base64.b64decode(bloc), fichier)
            resultat.trouvailles.append(trouvaille)
            resultat.pistes.append(piste)
        elif etiquette.endswith("PRIVATE KEY"):
            resultat.trouvailles.append(cle_pem(etiquette, bloc, fichier))
        elif etiquette == "DH PARAMETERS":
            resultat.trouvailles.append(parametres_dh(bloc, fichier))
        elif etiquette == "CERTIFICATE":
            resultat.pistes.append(Piste(vers=fichier, raison="ce fichier contient aussi un certificat : appeler analyser_x509"))
    if "-----BEGIN PGP PUBLIC KEY BLOCK-----" in texte:
        resultat.trouvailles += cles_openpgp(texte, fichier)
    if not resultat.trouvailles:
        resultat.trouvailles = lignes_ssh(texte, fichier)
    for trouvaille in resultat.trouvailles:
        if trouvaille.proprietes.get("chiffree") is False:
            trouvaille.proprietes["droits"] = droits
    if not resultat.trouvailles and not resultat.pistes:
        raise ErreurOutil("Aucune clé reconnue dans ce fichier")
    return resultat
