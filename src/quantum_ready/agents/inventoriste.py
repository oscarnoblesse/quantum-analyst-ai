"""Agent Inventoriste : parcourt le SI avec les outils et suit les pistes."""

from __future__ import annotations

import re

from pydantic import BaseModel, Field

from quantum_ready.agents.boucle import ConfigurationAgent, EtatBoucle
from quantum_ready.agents.communs import lire_prompt
from quantum_ready.serveur_mcp.session import Session

NOM = "inventoriste"
# outils qui, appelés sur un dossier, couvrent les fichiers de ces natures qu'il contient
OUTILS_DE_DOSSIER = {"scanner_code_crypto": {"code_python"}, "analyser_dependances": {"pyproject", "verrou_uv", "verrou_poetry", "requirements"},
                     "rechercher_algorithmes": None, "lister_fichiers": set()}


class Exclusion(BaseModel):
    id: str = Field(description="identifiant de la trouvaille (T0001...)")
    raison: str = Field(description="pourquoi elle ne doit pas entrer dans le CBOM")


class Lien(BaseModel):
    de: str = Field(description="fichier ou identifiant de départ")
    vers: str = Field(description="fichier ou identifiant d'arrivée")
    explication: str = Field(description="ce que le lien révèle")


class SortieInventoriste(BaseModel):
    resume: str = Field(description="deux ou trois phrases sur ce qui a été trouvé")
    exclusions: list[Exclusion] = Field(default_factory=list, description="trouvailles à ne pas mettre dans le CBOM")
    liens: list[Lien] = Field(default_factory=list, description="liens découverts entre fichiers (actifs cachés)")
    fichiers_non_analyses: list[str] = Field(default_factory=list, description="fichiers volontairement laissés de côté")


def carte(etat: EtatBoucle) -> dict[str, tuple[str, str]]:
    """Fichiers du SI d'après le premier appel réussi à lister_fichiers : chemin -> (nature, outil conseillé)."""
    for appel in etat.appels:
        if appel.nom == "lister_fichiers" and not appel.erreur:
            fichiers = {}
            for ligne in appel.texte.splitlines()[1:]:
                morceaux = [m.strip() for m in ligne.split("|")]
                if len(morceaux) >= 3 and morceaux[2] != "-":
                    fichiers[morceaux[0]] = (morceaux[1], morceaux[2])
            return fichiers
    return {}


def fichiers_couverts(etat: EtatBoucle, fichiers: dict[str, tuple[str, str]]) -> set[str]:
    couverts = set()
    for appel in etat.appels:
        if appel.refuse or appel.erreur and "trouvaille" not in appel.texte:
            continue
        cible = str(appel.arguments.get("cible", ".")).strip("/") or "."
        for chemin, (nature, outil) in fichiers.items():
            if chemin == cible and appel.nom == outil:  # analysé par l'outil qui sait le lire
                couverts.add(chemin)
            elif appel.nom in OUTILS_DE_DOSSIER and (cible == "." or chemin.startswith(cible + "/")):
                natures = OUTILS_DE_DOSSIER[appel.nom]
                if natures is None or nature in natures:
                    couverts.add(chemin)
    return couverts


_PISTE_ACTION = re.compile(r"appeler|rappeler|version", re.I)


def memoire(etat: EtatBoucle, session: Session) -> str:
    fichiers = carte(etat)
    if not fichiers:
        return "Aucune carte du SI pour l'instant : commence par lister_fichiers avec cible \".\"."
    restants = [c for c in fichiers if c not in fichiers_couverts(etat, fichiers)]
    lignes = [f"{len(fichiers) - len(restants)} fichiers analysés sur {len(fichiers)} ; {len(session.trouvailles())} trouvailles enregistrées."]
    if restants:
        lignes.append(f"Fichiers restant à analyser ({len(restants)}) :")
        lignes += [f"- {c} -> {fichiers[c][1]}" for c in restants[:12]]
        if len(restants) > 12:
            lignes.append(f"- (+{len(restants) - 12} autres)")
    else:
        lignes.append("Tous les fichiers ont été analysés. Suis les pistes utiles restantes, puis réponds par le JSON final.")
    pistes = []
    for appel in etat.appels:
        for ligne in appel.texte.splitlines():
            if ligne.startswith("- ") and _PISTE_ACTION.search(ligne) and ligne not in pistes:
                pistes.append(ligne)
    if pistes:
        lignes.append("Pistes à suivre relevées :")
        lignes += pistes[-5:]
    return "\n".join(lignes)


def verifier_fin(etat: EtatBoucle, session: Session, sortie: BaseModel) -> str | None:
    """Pas de fin avec des fichiers non analysés (sauf s'ils sont déclarés laissés de côté) ; exclusions limitées aux indices."""
    motifs = []
    fichiers = carte(etat)
    laisses = set(getattr(sortie, "fichiers_non_analyses", []))
    restants = [c for c in fichiers if c not in fichiers_couverts(etat, fichiers) and c not in laisses]
    if not fichiers:
        motifs.append("aucune carte du SI : appelle d'abord lister_fichiers avec cible \".\"")
    elif restants:
        motifs.append(f"{len(restants)} fichier(s) pas encore analysé(s) avec l'outil conseillé, par exemple "
                      + ", ".join(f"{c} -> {fichiers[c][1]}" for c in restants[:3]))
    indices = {e["id"] for e in session.trouvailles() if "confiance" in e["trouvaille"]["proprietes"]}
    abusives = [e.id for e in getattr(sortie, "exclusions", []) if e.id not in indices]
    if abusives:
        motifs.append(f"les exclusions {', '.join(abusives)} portent sur des actifs trouvés par un analyseur dédié. Un actif vulnérable "
                      "ou faible DOIT rester dans l'inventaire : n'exclus que des « indices à confirmer » qui se révèlent faux. "
                      "Retire ces identifiants des exclusions")
    return " ; ".join(motifs) or None


def configuration(max_etapes: int = 90, fenetre: int = 6) -> ConfigurationAgent:
    return ConfigurationAgent(
        nom=NOM, prompt=lire_prompt(NOM), sortie=SortieInventoriste, max_etapes=max_etapes, fenetre=fenetre, memoire=memoire,
        verifier_fin=verifier_fin,
        consigne="Dresse l'inventaire cryptographique complet du SI fictif, fichier par fichier, et suis les pistes vers les actifs cachés.",
    )
