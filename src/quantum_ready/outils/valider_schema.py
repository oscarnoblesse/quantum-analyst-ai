"""Outil valider_schema : un CBOM est-il un document CycloneDX 1.6 valide ?

Deux niveaux :
1. le schéma JSON officiel de CycloneDX 1.6 (fourni par cyclonedx-python-lib,
   donc utilisable hors ligne) ;
2. la cohérence interne, que le schéma ne vérifie pas : références (bom-ref)
   uniques, et chaque renvoi (signatureAlgorithmRef...) pointe vers un composant.
"""

from __future__ import annotations

import json

from pydantic import BaseModel, ConfigDict, Field

NOM = "valider_schema"
CHAMPS_DE_RENVOI = ("signatureAlgorithmRef", "subjectPublicKeyRef", "algorithmRef")


class ResultatValidation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    outil: str = NOM
    valide: bool
    erreurs: list[str] = Field(default_factory=list)


def _renvois(objet, chemin=""):
    if isinstance(objet, dict):
        for cle, valeur in objet.items():
            if cle in CHAMPS_DE_RENVOI and isinstance(valeur, str):
                yield f"{chemin}.{cle}", valeur
            yield from _renvois(valeur, f"{chemin}.{cle}")
    elif isinstance(objet, list):
        for i, valeur in enumerate(objet):
            yield from _renvois(valeur, f"{chemin}[{i}]")


def valider_schema(cbom: dict | str) -> ResultatValidation:
    """Valide un CBOM contre le schéma CycloneDX 1.6, puis sa cohérence interne."""
    from cyclonedx.schema import SchemaVersion
    from cyclonedx.validation.json import JsonStrictValidator

    try:
        texte = cbom if isinstance(cbom, str) else json.dumps(cbom)
        document = json.loads(texte)
    except (TypeError, ValueError) as erreur:
        return ResultatValidation(valide=False, erreurs=[f"JSON invalide : {erreur}"])
    erreurs = []
    erreur_schema = JsonStrictValidator(SchemaVersion.V1_6).validate_str(texte)
    if erreur_schema is not None:
        detail = getattr(erreur_schema, "data", erreur_schema)
        chemin = "/".join(str(p) for p in getattr(detail, "absolute_path", []))
        erreurs.append(f"Schéma CycloneDX 1.6 : {getattr(detail, 'message', detail)}" + (f" (à {chemin})" if chemin else ""))
    references = [c.get("bom-ref") for c in document.get("components", []) if isinstance(c, dict)]
    doublons = sorted({r for r in references if r and references.count(r) > 1})
    if doublons:
        erreurs.append(f"bom-ref en double : {', '.join(doublons)}")
    for chemin, cible in _renvois(document.get("components", [])):
        if cible not in references:
            erreurs.append(f"Renvoi vers un composant absent : {chemin} = {cible}")
    return ResultatValidation(valide=not erreurs, erreurs=erreurs)
