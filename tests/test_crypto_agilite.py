"""Indicateur de crypto-agilité : classement des emplacements et règle du niveau le plus rigide."""

import json
from pathlib import Path

from quantum_ready.outils.crypto_agilite import categorie_d_un_emplacement, evaluer_actif, resumer


def test_emplacements_classes_par_nature():
    assert categorie_d_un_emplacement("api/.env") == "configuration"
    assert categorie_d_un_emplacement("nginx/nginx.conf") == "configuration"
    assert categorie_d_un_emplacement("app/requirements.txt") == "dépendance"
    assert categorie_d_un_emplacement("app/main.py") == "code"
    assert categorie_d_un_emplacement("nginx/ssl/server.key") == "matériel"
    assert categorie_d_un_emplacement("clients/admin/.ssh/id_ed25519") == "matériel"


def test_actif_dans_plusieurs_fichiers_prend_le_niveau_le_plus_rigide():
    composant = {"evidence": {"occurrences": [{"location": "api/.env"}, {"location": "app/main.py"}]}}
    assert evaluer_actif(composant)["categorie"] == "code"


def test_actif_sans_emplacement_depend_du_logiciel():
    assert evaluer_actif({"evidence": {"occurrences": []}})["categorie"] == "logiciel"


def test_resume_du_cbom_exemple_compte_tous_les_actifs():
    cbom = json.loads((Path(__file__).resolve().parents[1] / "results" / "cbom_exemple.json").read_text(encoding="utf-8"))
    resume = resumer(cbom)
    assert resume["actifs"] == len(cbom["components"]) == sum(resume["niveaux"].values())
