"""CBOM CycloneDX 1.6 attendu d'un SI fictif, construit depuis sa vérité terrain (CSV).

C'est le CBOM qu'un inventaire parfait produirait : un composant par actif, dont le
bom-ref est l'identifiant de la vérité terrain. Il est construit ici, indépendamment du
système évalué (construire_cbom n'est pas utilisé), puis validé contre le schéma
CycloneDX 1.6 par l'outil valider_schema du dépôt, appelé en lecture seule.

Le document est déterministe : ni horodatage, ni numéro de série aléatoire.

    uv run python scripts/cbom_attendu.py data/ground_truth/verite_terrain_v2.csv data/ground_truth/cbom_attendu_v2.json
"""

from __future__ import annotations

import json
import re
import sys
import uuid
from pathlib import Path

from quantum_ready.outils.valider_schema import valider_schema
from quantum_ready.verite_terrain import Actif, charger_csv, verifier_ensemble

ESPACE_UUID = uuid.UUID("6f1c2a4e-0b7d-4c55-9a51-3c1f2b8e7d20")  # fixe : numéro de série reproductible


def type_materiel(actif: Actif) -> str:
    """Type CycloneDX d'un « related-crypto-material », d'après la nature de l'actif."""
    texte = actif.actif.lower()
    if texte.startswith("mot de passe"):
        return "password"
    if "clé publique" in texte or "known_hosts" in actif.fichier or "mémorisée" in texte:
        return "public-key"
    if any(m in texte for m in ("secret", "clé fernet", "tickets", "pré-partagée", "statique")):
        return "secret-key"
    if actif.id in {"V2-099"}:  # DNSKEY publié dans la zone : seule la clé publique est présente
        return "public-key"
    return "private-key"


def type_protocole(actif: Actif) -> str:
    if actif.composant == "SSH":
        return "ssh"
    if actif.composant == "strongSwan":
        return "ike" if "IKE" in actif.actif else "ipsec"
    return "tls"


def nom_bibliotheque(actif: Actif) -> tuple[str, str]:
    nom = re.sub(r"^Bibliothèque\s+", "", actif.actif).split(" (")[0].strip()
    version = actif.algorithme.split()[0].rstrip(",")
    return nom, version


def composant(actif: Actif) -> dict:
    proprietes = [
        {"name": "quantum-ready:identifiant_verite_terrain", "value": actif.id},
        {"name": "quantum-ready:composant_si", "value": actif.composant},
        {"name": "quantum-ready:algorithme", "value": actif.algorithme},
        {"name": "quantum-ready:vulnerabilite_quantique", "value": actif.vulnerabilite},
        {"name": "quantum-ready:visibilite", "value": actif.visibilite},
    ]
    if actif.perimetre:
        proprietes.append({"name": "quantum-ready:perimetre", "value": actif.perimetre})
    evidence = {"occurrences": [{"location": actif.fichier}]}

    if actif.type_cyclonedx == "library":
        nom, version = nom_bibliotheque(actif)
        return {"type": "library", "bom-ref": actif.id, "name": nom, "version": version,
                "evidence": evidence, "properties": proprietes}

    proprietes_crypto: dict = {"assetType": actif.type_cyclonedx}
    if actif.type_cyclonedx == "certificate":
        details = {"subjectName": actif.actif}
        if actif.parents:
            cle, signature = actif.parents
            details |= {"subjectPublicKeyRef": cle, "signatureAlgorithmRef": signature}
        proprietes_crypto["certificateProperties"] = details
    elif actif.type_cyclonedx == "related-crypto-material":
        proprietes_crypto["relatedCryptoMaterialProperties"] = {"type": type_materiel(actif)}
    elif actif.type_cyclonedx == "protocol":
        proprietes_crypto["protocolProperties"] = {"type": type_protocole(actif)}
    return {"type": "cryptographic-asset", "bom-ref": actif.id, "name": actif.actif,
            "cryptoProperties": proprietes_crypto, "evidence": evidence, "properties": proprietes}


def construire(actifs: list[Actif], nom_systeme: str) -> dict:
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid5(ESPACE_UUID, nom_systeme)}",
        "version": 1,
        "metadata": {"component": {"type": "application", "bom-ref": "si", "name": nom_systeme}},
        "components": [composant(a) for a in actifs],
    }


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 2:
        print(__doc__.strip().splitlines()[-1])
        return 2
    actifs = charger_csv(argv[0])
    verifier_ensemble(actifs)
    variante = re.search(r"v\d+", Path(argv[0]).stem)
    cbom = construire(actifs, f"SI fictif {variante.group(0) if variante else ''} : CBOM attendu".replace("  ", " "))
    validation = valider_schema(cbom)
    if not validation.valide:
        print("\n".join(validation.erreurs), file=sys.stderr)
        return 1
    Path(argv[1]).write_text(json.dumps(cbom, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(f"{argv[1]} : {len(cbom['components'])} composants, valide CycloneDX 1.6")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
