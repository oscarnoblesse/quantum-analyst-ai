"""Outil construire_cbom : des trouvailles vers un CBOM CycloneDX 1.6.

Deux étapes, toutes deux déterministes :
1. Fusion des doublons. Un même actif est souvent vu plusieurs fois : la racine
   dans trois magasins de certificats, une clé d'hôte SSH dans sa clé privée et son
   .pub. On fusionne seulement quand c'est sûr (même empreinte), et chaque fichier
   devient une « occurrence » de l'actif dans le CBOM. Deux fichiers de dossiers
   différents (known_hosts, authorized_keys) restent deux actifs : ce sont deux
   copies à remplacer séparément lors de la migration.
2. Traduction en CycloneDX 1.6 : composant « cryptographic-asset » avec
   cryptoProperties (algorithm, certificate, protocol, related-crypto-material),
   ou composant « library » pour les dépendances.

Le CBOM est reproductible : même entrée, même sortie, octet pour octet (numéro de
série dérivé du contenu, date prise dans SOURCE_DATE_EPOCH si elle est définie).
"""

from __future__ import annotations

import hashlib
import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import PurePosixPath

from pydantic import BaseModel, ConfigDict, Field

from quantum_ready.outils.commun import Trouvaille

NOM = "construire_cbom"
ESPACE = "quantum-ready"


class Actif(BaseModel):
    """Un actif après fusion : une trouvaille de référence et toutes ses occurrences."""

    model_config = ConfigDict(extra="forbid")

    reference: str
    trouvaille: Trouvaille
    occurrences: list[tuple[str, int | None]] = Field(default_factory=list)


class ResultatCbom(BaseModel):
    model_config = ConfigDict(extra="forbid")

    outil: str = NOM
    cbom: dict = Field(default_factory=dict)
    nombre_de_composants: int = 0
    fusions: list[str] = Field(default_factory=list, description="Actifs fusionnés, pour que l'agent puisse les vérifier")
    erreurs: list[str] = Field(default_factory=list)


def cle_de_fusion(t: Trouvaille) -> tuple:
    """Deux trouvailles de même clé désignent le même actif."""
    p = t.proprietes
    if "certificat_sha256" in p:
        return (t.type_actif, t.nom, p["certificat_sha256"])
    if "empreinte" in p and t.fichier:  # clé SSH : la clé privée et son .pub, dans le même dossier
        chemin = PurePosixPath(t.fichier)
        return (t.type_actif, p["empreinte"], str(chemin.parent), chemin.name.removesuffix(".pub"))
    if t.type_actif == "library":
        return (t.type_actif, t.nom.split()[0])
    if t.implicite:
        return (t.type_actif, t.nom, t.description)
    return (t.type_actif, t.nom, t.fichier, t.ligne, t.description)


def fusionner(trouvailles: list[Trouvaille]) -> tuple[list[Actif], list[str]]:
    actifs: dict[tuple, Actif] = {}
    for trouvaille in trouvailles:
        cle = cle_de_fusion(trouvaille)
        occurrence = (trouvaille.fichier or f"implicite : {trouvaille.proprietes.get('source', 'valeur par défaut')}", trouvaille.ligne)
        if cle not in actifs:
            reference = "crypto-" + hashlib.sha256(repr(cle).encode()).hexdigest()[:12]
            actifs[cle] = Actif(reference=reference, trouvaille=trouvaille)
        if occurrence not in actifs[cle].occurrences:
            actifs[cle].occurrences.append(occurrence)
    fusions = [f"{a.trouvaille.nom} : {', '.join(o[0] for o in a.occurrences)}" for a in actifs.values() if len(a.occurrences) > 1]
    return list(actifs.values()), fusions


# --- traduction CycloneDX ---

def primitive(t: Trouvaille) -> str:
    """Famille de l'algorithme, parmi les valeurs autorisées par CycloneDX 1.6."""
    texte = f"{t.nom} {t.description}".lower()
    regles = [
        (("mersenne", "random", "urandom", "secrets ("), "drbg"),
        (("argon2", "pbkdf2", "bcrypt", "scrypt"), "kdf"),
        (("hmac", "jwt hs", "macs)"), "mac"),
        (("signature", "with", "ecdsa", "ed25519", "jwt"), "signature"),
        (("fernet", "poly1305", "gcm", "chiffrement de la session"), "ae"),
        (("échange de clés", "diffie", "dh-", "groupe", "ecdhe", "kexalgorithms"), "key-agree"),
        (("openpgp à clé publique", "oaep", "pke"), "pke"),
        (("pbewith", "pbes2", "3des", "aes"), "block-cipher"),
        (("md5", "sha-", "sha3", "blake", "empreinte"), "hash"),
    ]
    for motifs, famille in regles:
        if any(m in texte for m in motifs):
            return famille
    return "other"


def _type_materiel(t: Trouvaille) -> str:
    texte = f"{t.nom} {t.description}".lower()
    if "privée" in texte:
        return "private-key"
    if "publique" in texte:
        return "public-key"
    if "mot de passe" in texte or "pass" in str(t.proprietes.get("variable", "")).lower():
        return "password"
    if "clé" in texte or "secret" in texte:
        return "secret-key"
    return "other"


def _date(texte: str) -> str:
    return f"{texte}T00:00:00Z"


def _proprietes(t: Trouvaille) -> list[dict]:
    paires = [("exposition-quantique", t.exposition), ("outil", t.outil), ("implicite", str(t.implicite).lower())]
    for nom in ("faiblesse_classique", "regression", "duree_conservation_jours", "source", "variable", "fonction", "contexte"):
        if nom in t.proprietes:
            paires.append((nom.replace("_", "-"), str(t.proprietes[nom])))
    return [{"name": f"{ESPACE}:{nom}", "value": valeur} for nom, valeur in paires]


def composant(actif: Actif, references: dict) -> dict:
    t, p = actif.trouvaille, actif.trouvaille.proprietes
    occurrences = [{"location": lieu} | ({"line": ligne} if ligne else {}) for lieu, ligne in actif.occurrences]
    if t.type_actif == "library":
        nom_paquet, version = t.nom.split()[0], p.get("version_verrouillee") or p.get("version", "")
        resultat = {"type": "library", "bom-ref": actif.reference, "name": nom_paquet, "description": t.description}
        if version and version[0].isdigit():
            resultat["version"] = version
            if t.outil == "analyser_dependances":
                resultat["purl"] = f"pkg:pypi/{nom_paquet}@{version}"
        return resultat | {"evidence": {"occurrences": occurrences}, "properties": _proprietes(t)}

    crypto: dict = {"assetType": t.type_actif}
    if t.type_actif == "algorithm":
        proprietes: dict = {"primitive": primitive(t)}
        if "taille" in p:
            proprietes["parameterSetIdentifier"] = str(p["taille"])
        if isinstance(p.get("courbe"), str) and len(p["courbe"]) < 16:
            proprietes["curve"] = p["courbe"]
        if t.exposition == "shor":
            proprietes["nistQuantumSecurityLevel"] = 0
        crypto["algorithmProperties"] = proprietes
    elif t.type_actif == "certificate":
        certificat = {"subjectName": p.get("sujet", ""), "issuerName": p.get("emetteur", ""), "certificateFormat": "X.509"}
        if "debut_validite" in p:
            certificat |= {"notValidBefore": _date(p["debut_validite"]), "notValidAfter": _date(p["fin_validite"])}
        empreinte = p.get("certificat_sha256")
        if (ref := references.get(("algorithm", empreinte))):
            certificat["signatureAlgorithmRef"] = ref
        if (ref := references.get(("related-crypto-material", empreinte))):
            certificat["subjectPublicKeyRef"] = ref
        extension = PurePosixPath(actif.occurrences[0][0]).suffix.lstrip(".")
        if extension:
            certificat["certificateExtension"] = extension
        crypto["certificateProperties"] = certificat
    elif t.type_actif == "related-crypto-material":
        materiel: dict = {"type": _type_materiel(t)}
        if isinstance(p.get("taille"), int):
            materiel["size"] = p["taille"]
        if "format" in p:
            materiel["format"] = str(p["format"])
        crypto["relatedCryptoMaterialProperties"] = materiel
    elif t.type_actif == "protocol":
        texte = f"{t.nom} {t.description}".lower()
        protocole: dict = {"type": "ssh" if "ssh" in texte else "tls" if ("tls" in texte or "ssl" in texte) else "other"}
        versions = p.get("versions") or ([t.nom] if t.nom.startswith("TLSv") else [])
        if versions:
            protocole["version"] = " ".join(v.removeprefix("TLSv") for v in versions)
        suites = p.get("suites") or p.get("suites_echange_rsa")
        if isinstance(suites, list):
            protocole["cipherSuites"] = [{"name": s} for s in suites]
        crypto["protocolProperties"] = protocole
    return {
        "type": "cryptographic-asset", "bom-ref": actif.reference, "name": t.nom, "description": t.description,
        "cryptoProperties": crypto, "evidence": {"occurrences": occurrences}, "properties": _proprietes(t),
    }


def construire_cbom(trouvailles: list[Trouvaille | dict], nom_systeme: str = "SI fictif") -> ResultatCbom:
    """Fusionne les doublons et produit un CBOM CycloneDX 1.6 (dictionnaire JSON)."""
    try:
        objets = [t if isinstance(t, Trouvaille) else Trouvaille.model_validate(t) for t in trouvailles]
    except Exception as erreur:
        return ResultatCbom(erreurs=[f"Trouvailles invalides : {erreur}"])
    if not objets:
        return ResultatCbom(erreurs=["Aucune trouvaille : rien à mettre dans le CBOM"])
    actifs, fusions = fusionner(objets)
    references = {
        (a.trouvaille.type_actif, a.trouvaille.proprietes["certificat_sha256"]): a.reference
        for a in actifs if "certificat_sha256" in a.trouvaille.proprietes and a.trouvaille.type_actif != "certificate"
    }
    composants = [composant(a, references) for a in actifs]
    contenu = json.dumps(composants, sort_keys=True, ensure_ascii=False)
    epoch = os.environ.get("SOURCE_DATE_EPOCH")
    horodatage = datetime.fromtimestamp(int(epoch), timezone.utc) if epoch else datetime.now(timezone.utc).replace(microsecond=0)
    cbom = {
        "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, ESPACE + contenu)}",
        "version": 1,
        "metadata": {
            "timestamp": horodatage.isoformat().replace("+00:00", "Z"),
            "tools": {"components": [{"type": "application", "name": ESPACE, "version": "0.1.0"}]},
            "component": {"type": "application", "bom-ref": "systeme-analyse", "name": nom_systeme},
        },
        "components": composants,
    }
    return ResultatCbom(cbom=cbom, nombre_de_composants=len(composants), fusions=fusions)
