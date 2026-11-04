"""La boucle agentique, commune à tous les agents.

À chaque tour :
1. on envoie au modèle sa consigne, une mémoire de travail écrite par le code et
   les derniers échanges (fenêtre glissante : le contexte d'un petit modèle est court) ;
2. le modèle répond soit par des appels d'outils, soit par sa réponse finale ;
3. les appels sont exécutés via MCP, et leurs résultats ajoutés à l'historique ;
4. la réponse finale doit être un JSON conforme au schéma de sortie de l'agent
   (Pydantic) ; sinon le modèle est invité à la corriger, deux fois au plus.

Garde-fous : nombre maximal de tours et d'appels par tour ; un outil absent de la
liste fermée est refusé et journalisé ; un appel identique à un appel déjà fait
n'est pas réexécuté (son résultat est resservi).
"""

from __future__ import annotations

import asyncio
import json
import time
import typing
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Literal

from pydantic import BaseModel, ValidationError

from quantum_ready.llm import ErreurModele, Modele
from quantum_ready.serveur_mcp.client import ClientOutils
from quantum_ready.serveur_mcp.session import Session

JOURNAL_AGENTS = "journal_agents.jsonl"
JOURNAL_OUTILS = "journal_outils.jsonl"
MAX_APPELS_PAR_TOUR = 5
MAX_CORRECTIONS = 2
MAX_REFUS_DE_FIN = 4  # au-delà, la réponse finale est acceptée telle quelle, avec le motif du refus dans le message


@dataclass
class Appel:
    nom: str
    arguments: dict
    texte: str
    erreur: bool
    double: bool = False
    refuse: bool = False


@dataclass
class EtatBoucle:
    """Ce que la boucle sait de son propre déroulement (utilisé par la mémoire de travail)."""

    appels: list[Appel] = field(default_factory=list)
    echanges: list[list[dict]] = field(default_factory=list)
    corrections: list[dict] = field(default_factory=list)
    debut: int = 0  # premier échange encore envoyé au modèle (avance par blocs : début de conversation stable)


CARACTERES_PAR_JETON = 3.2  # estimation prudente pour du français mêlé de chemins et d'identifiants
TAILLE_RESULTAT_ANCIEN = 240


def estimer_jetons(messages: list[dict], outils: list[dict]) -> int:
    """Estimation (prudente) du nombre de jetons d'une requête : messages et description des outils."""
    taille = sum(len(m.get("content", "")) + len(json.dumps(m.get("tool_calls", ""), ensure_ascii=False)) + 16 for m in messages)
    return int((taille + len(json.dumps(outils, ensure_ascii=False))) / CARACTERES_PAR_JETON)


def raccourcir(echange: list[dict]) -> list[dict]:
    """Un échange déjà lu : les résultats d'outils sont raccourcis, l'essentiel est dans la mémoire de travail."""
    resultat = []
    for message in echange:
        if message["role"] == "tool" and len(message["content"]) > TAILLE_RESULTAT_ANCIEN:
            message = message | {"content": message["content"][:TAILLE_RESULTAT_ANCIEN] + " … (résultat déjà lu ; voir la mémoire de travail)"}
        resultat.append(message)
    return resultat


def composer(config: "ConfigurationAgent", consigne: str, etat: EtatBoucle, session: Session, outils: list[dict]) -> list[dict]:
    """Messages d'un tour, sous le budget de contexte.

    Ordre : consigne fixe, échanges, corrections, puis mémoire de travail EN DERNIER. Le
    début reste identique d'un tour à l'autre, ce qui permet à Ollama de réutiliser son
    cache. Si le budget est dépassé : d'abord raccourcir les résultats déjà lus, puis
    oublier les échanges les plus anciens PAR BLOCS (pour garder un début stable).
    """
    raccourcis = False

    def assembler():
        gardes = etat.echanges[etat.debut :]
        messages = [{"role": "system", "content": config.prompt}, {"role": "user", "content": consigne}]
        for i, echange in enumerate(gardes):
            messages += raccourcir(echange) if raccourcis and i < len(gardes) - 1 else echange
        messages += etat.corrections
        if config.memoire:
            messages.append({"role": "user", "content": "Mémoire de travail (écrite par le système) :\n" + config.memoire(etat, session)})
        return messages

    if len(etat.echanges) - etat.debut > config.fenetre:
        etat.debut = len(etat.echanges) - max(1, config.fenetre // 2)
    messages = assembler()
    if estimer_jetons(messages, outils) > config.budget_jetons:
        raccourcis = True
        messages = assembler()
    while estimer_jetons(messages, outils) > config.budget_jetons and etat.debut < len(etat.echanges) - 1:
        etat.debut = min(len(etat.echanges) - 1, etat.debut + max(1, (len(etat.echanges) - etat.debut) // 2))
        messages = assembler()
    if estimer_jetons(messages, outils) > config.budget_jetons:  # un seul résultat trop long : on le tronque
        exces = int((estimer_jetons(messages, outils) - config.budget_jetons) * CARACTERES_PAR_JETON) + 200
        for message in reversed(messages):
            if message["role"] == "tool" and len(message["content"]) > exces:
                message["content"] = message["content"][: len(message["content"]) - exces] + " … (tronqué : contexte limité)"
                break
    return messages


@dataclass
class ConfigurationAgent:
    nom: str
    prompt: str
    consigne: str
    sortie: type[BaseModel]
    max_etapes: int = 30
    fenetre: int = 6
    memoire: Callable[[EtatBoucle, Session], str] | None = None
    budget_jetons: int = 3000          # taille maximale estimée de ce qui est envoyé au modèle (outils compris)
    # Contrôle de la réponse finale par le code : renvoie un message si le travail n'est pas fini ou incohérent.
    verifier_fin: Callable[[EtatBoucle, Session, BaseModel], str | None] | None = None


class ResultatAgent(BaseModel):
    agent: str
    arret: Literal["termine", "limite_etapes", "sortie_invalide", "erreur_modele"]
    sortie: dict | None = None
    etapes: int = 0
    appels_outils: int = 0
    appels_refuses: int = 0
    appels_en_double: int = 0
    erreurs_outils: int = 0
    fins_refusees: int = 0
    jetons_entree: int = 0
    jetons_sortie: int = 0
    duree_ms: int = 0
    message: str = ""


def decrire_schema(modele: type[BaseModel]) -> str:
    """Description courte des champs attendus, lisible par un petit modèle."""
    lignes = []
    for nom, champ in modele.model_fields.items():
        annotation = champ.annotation
        type_texte = getattr(annotation, "__name__", str(annotation)).replace("typing.", "")
        if typing.get_origin(annotation) is list:
            (element,) = typing.get_args(annotation)
            if isinstance(element, type) and issubclass(element, BaseModel):
                type_texte = "liste d'objets {" + ", ".join(element.model_fields) + "}"
            else:
                type_texte = f"liste de {getattr(element, '__name__', element)}"
        lignes.append(f'- "{nom}" ({type_texte}) : {champ.description or ""}')
    return "\n".join(lignes)


def extraire_json(texte: str) -> dict:
    """Le premier objet JSON du texte (le modèle l'entoure parfois de ```json ... ```)."""
    debut, fin = texte.find("{"), texte.rfind("}")
    if debut < 0 or fin <= debut:
        raise ValueError("aucun objet JSON dans la réponse")
    return json.loads(texte[debut : fin + 1])


async def executer_agent(config: ConfigurationAgent, modele: Modele, outils: ClientOutils, session: Session) -> ResultatAgent:
    debut = time.monotonic()
    etat = EtatBoucle()
    deja_faits: dict[str, Appel] = {}
    resultat = ResultatAgent(agent=config.nom, arret="limite_etapes")
    consigne = f"{config.consigne}\n\nQuand tu as terminé, réponds UNIQUEMENT par un objet JSON avec ces champs :\n{decrire_schema(config.sortie)}"
    import hashlib

    session.journaliser(JOURNAL_AGENTS, {"agent": config.nom, "evenement": "debut", "modele": modele.nom,
                                         "empreinte_prompt": hashlib.sha256(config.prompt.encode()).hexdigest()[:12],
                                         "budget_jetons": config.budget_jetons, "prompt": config.prompt,
                                         "consigne": consigne, "outils": sorted(outils.noms)})

    for etape in range(1, config.max_etapes + 1):
        resultat.etapes = etape
        messages = composer(config, consigne, etat, session, outils.schemas)

        try:
            reponse = await asyncio.to_thread(modele.discuter, messages, outils.schemas)
        except ErreurModele as erreur:
            resultat.arret, resultat.message = "erreur_modele", str(erreur)
            break
        resultat.jetons_entree += reponse.jetons_entree or 0
        resultat.jetons_sortie += reponse.jetons_sortie or 0
        session.journaliser(JOURNAL_AGENTS, {"agent": config.nom, "evenement": "tour", "etape": etape, "messages": len(messages),
                                             "jetons_estimes": estimer_jetons(messages, outils.schemas),
                                             "texte": reponse.texte[:2000], "appels": [a.model_dump() for a in reponse.appels],
                                             "jetons_entree": reponse.jetons_entree, "jetons_sortie": reponse.jetons_sortie, "duree_ms": reponse.duree_ms})

        if reponse.appels:
            etat.corrections = []
            echange: list[dict] = [{"role": "assistant", "content": reponse.texte,
                                    "tool_calls": [{"function": {"name": a.nom, "arguments": a.arguments}} for a in reponse.appels[:MAX_APPELS_PAR_TOUR]]}]
            for demande in reponse.appels[:MAX_APPELS_PAR_TOUR]:
                appel = await _executer_appel(demande.nom, demande.arguments, outils, session, config.nom, deja_faits)
                etat.appels.append(appel)
                resultat.appels_outils += not (appel.refuse or appel.double)
                resultat.appels_refuses += appel.refuse
                resultat.appels_en_double += appel.double
                resultat.erreurs_outils += appel.erreur and not appel.refuse
                echange.append({"role": "tool", "content": appel.texte, "tool_name": demande.nom})
            if len(reponse.appels) > MAX_APPELS_PAR_TOUR:
                echange.append({"role": "user", "content": f"Seuls les {MAX_APPELS_PAR_TOUR} premiers appels ont été exécutés."})
            etat.echanges.append(echange)
            continue

        try:
            sortie = config.sortie.model_validate(extraire_json(reponse.texte))
        except (ValueError, ValidationError) as erreur:
            if len(etat.corrections) // 2 >= MAX_CORRECTIONS:
                resultat.arret, resultat.message = "sortie_invalide", f"réponse finale invalide après {MAX_CORRECTIONS} corrections : {str(erreur)[:300]}"
                break
            etat.corrections += [
                {"role": "assistant", "content": reponse.texte[:1500]},
                {"role": "user", "content": "Si tu n'as pas terminé, appelle un outil. Si tu as terminé, ta réponse doit être UNIQUEMENT "
                 f"un objet JSON avec ces champs :\n{decrire_schema(config.sortie)}\nProblème : {str(erreur)[:400]}"},
            ]
            continue
        refus = config.verifier_fin(etat, session, sortie) if config.verifier_fin else None
        if refus and resultat.fins_refusees < MAX_REFUS_DE_FIN:
            resultat.fins_refusees += 1
            etat.corrections = [{"role": "assistant", "content": reponse.texte[:1500]},
                                {"role": "user", "content": f"Réponse finale REFUSÉE par la vérification automatique : {refus}"}]
            session.journaliser(JOURNAL_AGENTS, {"agent": config.nom, "evenement": "fin_refusee", "etape": etape, "motif": refus})
            continue
        if refus:
            resultat.message = f"réponse finale acceptée après {MAX_REFUS_DE_FIN} refus : {refus}"
        resultat.arret, resultat.sortie = "termine", sortie.model_dump(mode="json")
        break

    resultat.duree_ms = int((time.monotonic() - debut) * 1000)
    session.journaliser(JOURNAL_AGENTS, {"agent": config.nom, "evenement": "fin", **resultat.model_dump(exclude={"sortie"}), "sortie": resultat.sortie})
    return resultat


async def _executer_appel(nom: str, arguments: dict, outils: ClientOutils, session: Session, agent: str, deja_faits: dict[str, Appel]) -> Appel:
    if nom not in outils.noms:
        texte = f"REFUS : l'outil « {nom} » n'est pas dans ta liste. Outils autorisés : {', '.join(sorted(outils.noms))}."
        session.journaliser(JOURNAL_OUTILS, {"agent": agent, "outil": nom, "arguments": arguments, "statut": "refus", "duree_ms": 0})
        return Appel(nom, arguments, texte, erreur=True, refuse=True)
    cle = nom + json.dumps(arguments, sort_keys=True, ensure_ascii=False)
    if cle in deja_faits:
        precedent = deja_faits[cle]
        return Appel(nom, arguments, "(Appel déjà fait avec ces arguments : résultat rappelé, inutile de recommencer.)\n" + precedent.texte,
                     precedent.erreur, double=True)
    try:
        texte, erreur = await outils.appeler(nom, arguments)
    except Exception as exception:  # robustesse : une panne d'outil ne tue pas l'agent
        texte, erreur = f"ERREUR : l'appel a échoué ({type(exception).__name__}) : {exception}", True
    appel = Appel(nom, arguments, texte, erreur)
    deja_faits[cle] = appel
    return appel
