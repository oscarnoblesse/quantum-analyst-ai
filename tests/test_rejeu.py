"""Rejeu d'une session : appels purs identiques, écart détecté, dossier absent refusé."""

import asyncio
import json
import shutil

from quantum_ready import rejeu
from quantum_ready.agents import inventoriste
from quantum_ready.agents import politiques as politiques_simulees
from quantum_ready.agents.communs import lancer
from quantum_ready.llm import ModeleSimule
from quantum_ready.serveur_mcp.session import Session


def _session(racine_si, tmp_path):
    session = Session(tmp_path / "session", racine_si, "SI v1")
    asyncio.run(lancer(inventoriste.configuration(), ModeleSimule(politiques_simulees.inventoriste), session, transport="memoire"))
    return session.dossier


def test_appels_purs_rejoues_a_l_identique(racine_si, tmp_path):
    dossier = _session(racine_si, tmp_path)
    rapport = rejeu.rejouer(dossier, racine_si)
    assert rapport["differents"] == []
    assert rapport["identiques"] > 0


def test_ecart_enregistre_est_detecte(racine_si, tmp_path):
    dossier = _session(racine_si, tmp_path)
    journal = dossier / "journal_outils.jsonl"
    lignes = [json.loads(l) for l in journal.read_text(encoding="utf-8").splitlines()]
    modifie = next(e for e in lignes if e["outil"] == "lister_fichiers" and e["statut"] == "ok")
    modifie["sortie"] = modifie["sortie"] + "\nLIGNE AJOUTEE A LA MAIN"
    journal.write_text("\n".join(json.dumps(e, ensure_ascii=False) for e in lignes) + "\n", encoding="utf-8")
    rapport = rejeu.rejouer(dossier, racine_si)
    assert any(r["outil"] == "lister_fichiers" for r in rapport["differents"])


def test_identifiants_de_trouvailles_ne_comptent_pas(racine_si, tmp_path):
    assert rejeu._contenu("trouvaille T0023 | RSA") == rejeu._contenu("trouvaille T0101 | RSA")
    assert rejeu._contenu("trouvaille T0023 | RSA") != rejeu._contenu("trouvaille T0023 | ECDSA")


def test_dossier_sans_journal_est_refuse(tmp_path, capsys):
    (tmp_path / "vide").mkdir()
    assert rejeu.main([str(tmp_path / "vide")]) == 2
    assert "Pas de journal" in capsys.readouterr().err


def test_commande_retourne_zero_sur_une_session_saine(racine_si, tmp_path, capsys):
    dossier = _session(racine_si, tmp_path)
    assert rejeu.main([str(dossier), "--racine", str(racine_si)]) == 0
    assert "identique(s)" in capsys.readouterr().out
