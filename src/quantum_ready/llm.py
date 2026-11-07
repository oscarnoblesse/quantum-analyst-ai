"""Client du modèle de langage : une interface, deux implémentations.

- ModeleOllama parle à un modèle local servi par Ollama (API /api/chat), avec la
  description des outils : le modèle répond soit par du texte, soit par des
  appels d'outils structurés.
- ModeleSimule rejoue des réponses écrites à l'avance. Il sert aux tests et à la
  CI (pas de modèle de 3 Go dans GitHub Actions), et rend la mécanique des agents
  vérifiable indépendamment de la qualité du modèle.

Le modèle ne fait jamais de cryptographie : il ne voit que les résultats compacts
des outils et décide quoi appeler ensuite.
"""

from __future__ import annotations

import json
import re
import time
from collections.abc import Callable
from typing import Any, Protocol

import httpx
from pydantic import BaseModel, Field


class ErreurModele(RuntimeError):
    """Le modèle est injoignable ou sa réponse est inexploitable."""


class AppelOutil(BaseModel):
    nom: str
    arguments: dict[str, Any] = Field(default_factory=dict)


class Reponse(BaseModel):
    texte: str = ""
    appels: list[AppelOutil] = Field(default_factory=list)
    jetons_entree: int | None = None
    jetons_sortie: int | None = None
    duree_ms: int = 0


class Modele(Protocol):
    nom: str

    def discuter(self, messages: list[dict], outils: list[dict]) -> Reponse: ...


def _arguments(brut) -> dict:
    if isinstance(brut, dict):
        return brut
    if isinstance(brut, str) and brut.strip():
        try:
            valeur = json.loads(brut)
            return valeur if isinstance(valeur, dict) else {}
        except ValueError:
            return {}
    return {}


_APPEL_DANS_LE_TEXTE = re.compile(r"\{\s*\"(?:name|nom)\"\s*:\s*\"([\w.-]+)\"\s*,\s*\"(?:arguments|parameters)\"\s*:\s*(\{.*?\})\s*\}", re.S)


def appels_dans_le_texte(texte: str, noms_connus: set[str]) -> list[AppelOutil]:
    """Certains petits modèles écrivent l'appel d'outil en JSON dans le texte au lieu
    d'utiliser le champ prévu. On le récupère, seulement pour un outil connu."""
    appels = []
    for nom, arguments in _APPEL_DANS_LE_TEXTE.findall(texte):
        if nom in noms_connus:
            appels.append(AppelOutil(nom=nom, arguments=_arguments(arguments)))
    return appels


def retirer_reflexion(texte: str) -> str:
    """Retire le raisonnement qu'un modèle « thinking » écrit malgré think=False.

    Les variantes « thinking » de qwen3 raisonnent toujours ; selon le gabarit, le
    raisonnement arrive dans un bloc <think>…</think> ou SANS balise d'ouverture,
    terminé par </think>. Dans les deux cas, seule la partie après la dernière
    balise </think> est la réponse.
    """
    texte = re.sub(r"<think>.*?</think>", "", texte, flags=re.S)
    if "</think>" in texte:
        texte = texte.rsplit("</think>", 1)[1]
    return texte.strip()


class ModeleOllama:
    """Modèle local servi par Ollama, réglé pour être aussi reproductible que possible."""

    def __init__(self, nom: str, hote: str = "http://localhost:11434", contexte: int = 4096,
                 temperature: float = 0, graine: int = 42, delai_secondes: float = 300, client: httpx.Client | None = None,
                 max_jetons_sortie: int = 1024):
        self.nom = nom
        self.hote = hote.rstrip("/")
        # num_predict borne la réponse : une génération qui s'emballe ne peut plus bloquer l'agent
        self.options = {"num_ctx": contexte, "temperature": temperature, "seed": graine, "num_predict": max_jetons_sortie}
        self.client = client or httpx.Client(timeout=delai_secondes)

    def discuter(self, messages: list[dict], outils: list[dict]) -> Reponse:
        corps = {"model": self.nom, "messages": messages, "tools": outils, "stream": False, "think": False, "options": self.options}
        debut = time.monotonic()
        try:
            reponse = self.client.post(f"{self.hote}/api/chat", json=corps)
            reponse.raise_for_status()
            donnees = reponse.json()
        except httpx.HTTPStatusError as erreur:
            raise ErreurModele(f"Ollama a répondu {erreur.response.status_code} : {erreur.response.text[:300]}") from erreur
        except (httpx.HTTPError, ValueError) as erreur:
            raise ErreurModele(f"Ollama injoignable sur {self.hote} ({type(erreur).__name__}) : est-il lancé, le modèle {self.nom} est-il téléchargé ?") from erreur
        message = donnees.get("message", {})
        texte = message.get("content", "") or ""
        texte = retirer_reflexion(texte)
        appels = [AppelOutil(nom=a["function"]["name"], arguments=_arguments(a["function"].get("arguments")))
                  for a in message.get("tool_calls") or [] if a.get("function", {}).get("name")]
        if not appels:
            appels = appels_dans_le_texte(texte, {o["function"]["name"] for o in outils})
        return Reponse(texte=texte, appels=appels, jetons_entree=donnees.get("prompt_eval_count"),
                       jetons_sortie=donnees.get("eval_count"), duree_ms=int((time.monotonic() - debut) * 1000))


class ModeleSimule:
    """Modèle factice : rejoue une liste de réponses, ou appelle une fonction (messages, outils) -> Reponse."""

    def __init__(self, reponses: list[Reponse] | Callable[[list[dict], list[dict]], Reponse], nom: str = "simule"):
        self.nom = nom
        self._reponses = reponses
        self.recus: list[list[dict]] = []

    def discuter(self, messages: list[dict], outils: list[dict]) -> Reponse:
        self.recus.append(messages)
        if callable(self._reponses):
            return self._reponses(messages, outils)
        if not self._reponses:
            raise ErreurModele("Le modèle simulé n'a plus de réponse prévue")
        return self._reponses.pop(0)


def appel(nom: str, **arguments) -> Reponse:
    """Raccourci pour écrire des scénarios de test : une réponse qui appelle un outil."""
    return Reponse(appels=[AppelOutil(nom=nom, arguments=arguments)])


def texte(contenu: str | dict) -> Reponse:
    """Raccourci : une réponse finale (texte ou JSON)."""
    return Reponse(texte=contenu if isinstance(contenu, str) else json.dumps(contenu, ensure_ascii=False))


def depuis_configuration(config: dict) -> ModeleOllama:
    modele = config["modele"]
    return ModeleOllama(modele["nom"], modele.get("hote", "http://localhost:11434"), modele.get("contexte", 4096),
                        modele.get("temperature", 0), modele.get("graine", 42), modele.get("delai_secondes", 300),
                        max_jetons_sortie=modele.get("max_jetons_sortie", 1024))
