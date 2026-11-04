"""Boucle agentique, avec un modèle simulé et le vrai serveur MCP (en mémoire)."""

import asyncio

from pydantic import BaseModel, Field

from quantum_ready.agents.boucle import ConfigurationAgent, decrire_schema, executer_agent, extraire_json
from quantum_ready.llm import ErreurModele, ModeleSimule, Reponse, appel, texte
from quantum_ready.serveur_mcp.client import ouvrir_outils
from quantum_ready.serveur_mcp.session import Session


class Sortie(BaseModel):
    resume: str = Field(description="Une phrase")
    fichiers: list[str] = Field(default_factory=list, description="Fichiers vus")


def _executer(racine, tmp_path, reponses, **options):
    session = Session(tmp_path / "s", racine)
    modele = ModeleSimule(reponses)
    config = ConfigurationAgent(nom="inventoriste", prompt="Tu es un agent.", consigne="Inventorie.", sortie=Sortie, **options)

    async def lancer():
        async with ouvrir_outils("inventoriste", session, transport="memoire") as outils:
            return await executer_agent(config, modele, outils, session)
    return asyncio.run(lancer()), session, modele


def test_parcours_nominal(racine_si, tmp_path):
    resultat, session, modele = _executer(racine_si, tmp_path, [
        appel("lister_fichiers", cible="nginx"),
        appel("analyser_x509", cible="nginx/ssl/server.crt"),
        texte('Voici :\n```json\n{"resume": "fini", "fichiers": ["nginx/ssl/server.crt"]}\n```'),
    ])
    assert resultat.arret == "termine" and resultat.sortie == {"resume": "fini", "fichiers": ["nginx/ssl/server.crt"]}
    assert (resultat.etapes, resultat.appels_outils) == (3, 2)
    assert len(session.trouvailles()) == 3
    dernier = modele.recus[-1]
    assert dernier[-1]["role"] == "tool" and "T0001" in dernier[-1]["content"]
    assert [e["evenement"] for e in session.evenements("journal_agents.jsonl")] == ["debut", "tour", "tour", "tour", "fin"]


def test_refus_double_et_erreur_d_outil(racine_si, tmp_path):
    resultat, session, modele = _executer(racine_si, tmp_path, [
        Reponse(appels=[appel("score_mosca").appels[0], appel("analyser_cle", cible="nginx/ssl/server.key").appels[0]]),
        appel("analyser_cle", cible="nginx/ssl/server.key"),
        appel("analyser_x509", cible="../../etc/passwd"),
        texte({"resume": "ok"}),
    ])
    assert (resultat.appels_refuses, resultat.appels_en_double, resultat.erreurs_outils, resultat.appels_outils) == (1, 1, 1, 2)
    refus = [e for e in session.evenements("journal_outils.jsonl") if e["statut"] == "refus"]
    assert refus[0]["outil"] == "score_mosca"
    contenus = [m["content"] for m in modele.recus[1] if m["role"] == "tool"]
    assert contenus[0].startswith("REFUS") and "analyser_x509" in contenus[0]
    assert "Appel déjà fait" in [m["content"] for m in modele.recus[2] if m["role"] == "tool"][-1]


def test_correction_de_la_reponse_finale(racine_si, tmp_path):
    resultat, _, modele = _executer(racine_si, tmp_path, [texte("J'ai terminé l'analyse."), texte({"fichiers": "pas une liste"}), texte({"resume": "corrigé"})])
    assert resultat.arret == "termine" and resultat.sortie["resume"] == "corrigé"
    assert "UNIQUEMENT" in modele.recus[1][-1]["content"]


def test_sortie_invalide_apres_deux_corrections(racine_si, tmp_path):
    resultat, _, _ = _executer(racine_si, tmp_path, [texte("non")] * 3)
    assert resultat.arret == "sortie_invalide" and resultat.sortie is None


def test_limite_d_etapes_et_fenetre(racine_si, tmp_path):
    reponses = [appel("lister_fichiers", cible=d) for d in ("api", "db", "ssh", "nginx", "certs")]
    resultat, _, modele = _executer(racine_si, tmp_path, reponses, max_etapes=5, fenetre=2,
                                    memoire=lambda etat, session: f"{len(etat.appels)} appels faits")
    assert resultat.arret == "limite_etapes" and resultat.appels_outils == 5
    dernier = modele.recus[-1]
    assert sum(m["role"] == "tool" for m in dernier) == 2
    assert "4 appels faits" in dernier[-1]["content"]  # mémoire de travail en dernier


def test_erreur_du_modele(racine_si, tmp_path):
    def panne(messages, outils):
        raise ErreurModele("Ollama injoignable")
    resultat, _, _ = _executer(racine_si, tmp_path, panne)
    assert resultat.arret == "erreur_modele" and "injoignable" in resultat.message


def test_utilitaires():
    assert extraire_json('bla {"a": {"b": 1}} bla') == {"a": {"b": 1}}
    description = decrire_schema(Sortie)
    assert '"resume" (str) : Une phrase' in description and '"fichiers" (liste de str)' in description


def test_budget_de_contexte(racine_si, tmp_path):
    """Sous un budget serré, les résultats déjà lus sont raccourcis (puis, si besoin, les échanges anciens oubliés)."""
    reponses = [appel("lister_fichiers", cible=".")] + [appel("lister_fichiers", cible=d) for d in ("api", "db", "ssh", "nginx")]
    resultat, _, modele = _executer(racine_si, tmp_path, reponses, max_etapes=5, fenetre=10, budget_jetons=2500,
                                    memoire=lambda etat, session: "mémoire")
    assert resultat.etapes == 5
    assert not any("résultat déjà lu" in m["content"] for m in modele.recus[1])  # sous le budget : rien n'est raccourci
    assert any("résultat déjà lu" in m["content"] for m in modele.recus[-1] if m["role"] == "tool")
    assert modele.recus[-1][-1]["content"].startswith("Mémoire de travail")
