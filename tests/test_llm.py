"""Client du modèle : requête envoyée à Ollama, lecture des appels d'outils, erreurs, modèle simulé."""

import json

import httpx
import pytest

from quantum_ready.llm import ErreurModele, ModeleOllama, ModeleSimule, appel, depuis_configuration, texte

OUTILS = [{"type": "function", "function": {"name": "lister_fichiers", "description": "d", "parameters": {"type": "object", "properties": {}}}}]


def _ollama(reponse: dict | None = None, statut: int = 200, erreur: Exception | None = None):
    envoyes = []

    def gerer(requete: httpx.Request) -> httpx.Response:
        envoyes.append(json.loads(requete.content))
        if erreur:
            raise erreur
        return httpx.Response(statut, json=reponse or {})

    return ModeleOllama("qwen3:test", client=httpx.Client(transport=httpx.MockTransport(gerer))), envoyes


def test_requete_reproductible_et_appel_d_outil():
    modele, envoyes = _ollama({"message": {"content": "", "tool_calls": [{"function": {"name": "lister_fichiers", "arguments": {"cible": "."}}}]},
                               "prompt_eval_count": 120, "eval_count": 15})
    reponse = modele.discuter([{"role": "user", "content": "go"}], OUTILS)
    assert reponse.appels[0].nom == "lister_fichiers" and reponse.appels[0].arguments == {"cible": "."}
    assert reponse.jetons_entree == 120
    corps = envoyes[0]
    assert corps["options"] == {"num_ctx": 4096, "temperature": 0, "seed": 42}
    assert corps["think"] is False and corps["stream"] is False and corps["tools"] == OUTILS


def test_arguments_en_chaine_json_et_raisonnement_retire():
    modele, _ = _ollama({"message": {"content": "<think>hmm</think>Fini.", "tool_calls": [{"function": {"name": "lister_fichiers", "arguments": "{\"cible\": \"api\"}"}}]}})
    reponse = modele.discuter([], OUTILS)
    assert reponse.appels[0].arguments == {"cible": "api"} and reponse.texte == "Fini."


def test_appel_ecrit_dans_le_texte_recupere_si_l_outil_est_connu():
    modele, _ = _ollama({"message": {"content": 'Je vais appeler {"name": "lister_fichiers", "arguments": {"cible": "."}} puis {"name": "pirate", "arguments": {}}'}})
    reponse = modele.discuter([], OUTILS)
    assert [a.nom for a in reponse.appels] == ["lister_fichiers"]


def test_erreurs_lisibles():
    modele, _ = _ollama(erreur=httpx.ConnectError("refusé"))
    with pytest.raises(ErreurModele, match="injoignable"):
        modele.discuter([], OUTILS)
    modele, _ = _ollama({"error": "model not found"}, statut=404)
    with pytest.raises(ErreurModele, match="404"):
        modele.discuter([], OUTILS)


def test_modele_simule():
    modele = ModeleSimule([appel("lister_fichiers", cible="."), texte({"resume": "ok"})])
    assert modele.discuter([{"role": "user", "content": "a"}], OUTILS).appels[0].nom == "lister_fichiers"
    assert json.loads(modele.discuter([], OUTILS).texte) == {"resume": "ok"}
    assert len(modele.recus) == 2
    with pytest.raises(ErreurModele):
        modele.discuter([], OUTILS)
    fonction = ModeleSimule(lambda messages, outils: texte(str(len(messages))))
    assert fonction.discuter([{}, {}], OUTILS).texte == "2"


def test_depuis_configuration():
    modele = depuis_configuration({"modele": {"nom": "m", "contexte": 2048, "graine": 7}})
    assert modele.nom == "m" and modele.options == {"num_ctx": 2048, "temperature": 0, "seed": 7}
