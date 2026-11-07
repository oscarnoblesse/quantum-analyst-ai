"""Injection de pannes (sujet §6.3) : outil en échec, hors délai, JSON invalide, réponse vide, modèle injoignable.

Pour chaque cas, l'agent doit soit réessayer, soit se replier, soit s'arrêter proprement, et le
journal doit le dire. Le modèle et les outils sont simulés : aucune panne réelle n'est nécessaire.
"""

import asyncio
import json

import pytest
from pydantic import BaseModel, Field

from quantum_ready.agents import boucle
from quantum_ready.agents.boucle import ConfigurationAgent, executer_agent
from quantum_ready.llm import ErreurModele, ModeleSimule, Reponse, appel, texte
from quantum_ready.serveur_mcp.session import Session


class Sortie(BaseModel):
    resume: str = Field(description="Une phrase")


class OutilsFactices:
    """Client d'outils simulé : chaque appel suit le comportement passé en paramètre."""

    def __init__(self, comportement):
        self.schemas = []
        self.noms = {"outil"}
        self._comportement = comportement

    async def appeler(self, nom, arguments):
        return await self._comportement(nom, arguments)


def _executer(tmp_path, reponses, outils):
    session = Session(tmp_path / "s", tmp_path)
    modele = ModeleSimule(reponses)
    config = ConfigurationAgent(nom="inventoriste", prompt="Tu es un agent.", consigne="Inventorie.", sortie=Sortie)
    resultat = asyncio.run(executer_agent(config, modele, outils, session))
    return resultat, session, modele


def _evenements(session, fichier):
    return [json.loads(l) for l in (session.dossier / fichier).read_text(encoding="utf-8").splitlines()]


async def _reussit(nom, arguments):
    return "résultat utile", False


# --- outil en échec ou hors délai : l'agent continue ---

def test_outil_en_echec_l_agent_se_replie(tmp_path):
    async def echoue(nom, arguments):
        raise OSError("disque illisible")
    resultat, session, modele = _executer(tmp_path, [appel("outil"), texte({"resume": "sans l'outil"})], OutilsFactices(echoue))
    assert resultat.arret == "termine" and resultat.erreurs_outils == 1
    assert "disque illisible" in [m["content"] for m in modele.recus[1] if m["role"] == "tool"][-1]


def test_outil_hors_delai_devient_une_erreur_lisible(tmp_path, monkeypatch):
    monkeypatch.setattr(boucle, "DELAI_OUTIL_SECONDES", 0.05)

    async def trop_lent(nom, arguments):
        await asyncio.sleep(5)
        return "trop tard", False
    resultat, session, modele = _executer(tmp_path, [appel("outil"), texte({"resume": "sans l'outil"})], OutilsFactices(trop_lent))
    assert resultat.arret == "termine" and resultat.erreurs_outils == 1
    contenu = [m["content"] for m in modele.recus[1] if m["role"] == "tool"][-1]
    assert "n'a pas répondu" in contenu


# --- réponse finale : JSON invalide, réponse vide ---

def test_json_invalide_est_corrige_au_second_essai(tmp_path):
    resultat, _, modele = _executer(tmp_path, [texte("{resume: pas du JSON"), texte({"resume": "corrigé"})], OutilsFactices(_reussit))
    assert resultat.arret == "termine" and resultat.sortie["resume"] == "corrigé"
    assert "UNIQUEMENT" in modele.recus[1][-1]["content"]  # le modèle a été prévenu de l'erreur


def test_reponse_vide_repetee_s_arrete_proprement(tmp_path):
    resultat, session, _ = _executer(tmp_path, [texte("")] * 3, OutilsFactices(_reussit))
    assert resultat.arret == "sortie_invalide" and resultat.sortie is None
    fin = [e for e in _evenements(session, "journal_agents.jsonl") if e.get("evenement") == "fin"][-1]
    assert fin["arret"] == "sortie_invalide"


def test_reponse_vide_puis_reponse_valable(tmp_path):
    resultat, _, _ = _executer(tmp_path, [texte(""), texte({"resume": "après une réponse vide"})], OutilsFactices(_reussit))
    assert resultat.arret == "termine"


# --- modèle injoignable : arrêt propre et journalisé ---

def test_modele_injoignable_arrete_proprement_et_journalise(tmp_path):
    def panne(messages, outils):
        raise ErreurModele("Ollama injoignable")
    resultat, session, _ = _executer(tmp_path, panne, OutilsFactices(_reussit))
    assert resultat.arret == "erreur_modele" and "injoignable" in resultat.message
    fin = [e for e in _evenements(session, "journal_agents.jsonl") if e.get("evenement") == "fin"][-1]
    assert fin["arret"] == "erreur_modele"


# --- sortie d'un outil vide : pas de plantage ---

def test_outil_qui_ne_renvoie_rien_ne_plante_pas(tmp_path):
    async def vide(nom, arguments):
        return "", False
    resultat, _, _ = _executer(tmp_path, [appel("outil"), texte({"resume": "rien trouvé"})], OutilsFactices(vide))
    assert resultat.arret == "termine"
