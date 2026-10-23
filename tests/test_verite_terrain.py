"""Tests de la vérité terrain : règles du document docs/regles_verite_terrain.md."""

import csv
import json
from pathlib import Path

import pytest

from quantum_ready.verite_terrain import (
    COLONNES,
    Actif,
    ErreurVeriteTerrain,
    charger_csv,
    convertir,
    main,
    verifier_ensemble,
)

RACINE = Path(__file__).resolve().parents[1]
CSV_V1 = RACINE / "data" / "ground_truth" / "verite_terrain_v1.csv"


@pytest.fixture(scope="module")
def actifs():
    return charger_csv(CSV_V1)


def ligne_valide(**changements) -> dict:
    """Une ligne correcte, à modifier pour tester les cas d'erreur."""
    donnees = {
        "id": "QR-999",
        "composant": "API",
        "fichier": "api/exemple.py",
        "actif": "Exemple",
        "algorithme": "AES-256-GCM",
        "visibilite": "Visible",
        "vulnerabilite": "Non",
        "type_risque": "Aucun",
        "notes": "",
        "type_cyclonedx": "algorithm",
    }
    donnees.update(changements)
    return donnees


def ecrire_csv(chemin: Path, lignes: list[dict]) -> Path:
    with chemin.open("w", encoding="utf-8", newline="") as fichier:
        ecrivain = csv.writer(fichier)
        ecrivain.writerow(list(COLONNES))
        for ligne in lignes:
            ecrivain.writerow([ligne[champ] for champ in COLONNES.values()])
    return chemin


# --- Seuils du sujet et règles d'ensemble sur la vraie vérité terrain ---


def test_seuils_du_sujet(actifs):
    assert len(actifs) >= 40
    assert sum(a.est_cache for a in actifs) >= 10


def test_compte_actuel(actifs):
    assert len(actifs) == 70
    assert sum(a.est_cache for a in actifs) == 16


def test_identifiants_uniques_et_continus(actifs):
    assert [a.id for a in actifs] == [f"QR-{i:03d}" for i in range(1, len(actifs) + 1)]


def test_chaque_cache_a_une_categorie(actifs):
    for actif in actifs:
        if actif.est_cache:
            assert actif.categorie_cachee is not None, actif.id


def test_les_visibles_n_ont_pas_de_categorie(actifs):
    for actif in actifs:
        if not actif.est_cache:
            assert actif.categorie_cachee is None, actif.id


def test_certificats_relies_a_cle_et_signature(actifs):
    index = {a.id: a for a in actifs}
    certificats = [a for a in actifs if a.type_cyclonedx == "certificate" and a.parents]
    assert len(certificats) == 6
    for certificat in certificats:
        cle, signature = certificat.parents
        assert index[cle].type_cyclonedx == "related-crypto-material"
        assert index[signature].type_cyclonedx == "algorithm"


def test_pieges_de_precision_classes_surs(actifs):
    index = {a.id: a for a in actifs}
    assert index["QR-055"].vulnerabilite == "Non"
    assert index["QR-029"].vulnerabilite == "Non"


def test_verifier_ensemble_accepte_la_v1(actifs):
    verifier_ensemble(actifs)


# --- Validation ligne par ligne ---


def test_valeur_hors_liste_refusee():
    with pytest.raises(ValueError):
        Actif(**ligne_valide(type_cyclonedx="Library"))


def test_identifiant_mal_forme_refuse():
    with pytest.raises(ValueError):
        Actif(**ligne_valide(id="QR-1"))


def test_cache_sans_categorie_refuse():
    with pytest.raises(ValueError, match="Caché"):
        Actif(**ligne_valide(visibilite="Caché", notes="Pas de catégorie"))


def test_cache_categorie_inconnue_refuse():
    with pytest.raises(ValueError):
        Actif(**ligne_valide(visibilite="Caché", notes="Caché, très bien caché : …"))


def test_categorie_avec_precision_entre_parentheses():
    actif = Actif(**ligne_valide(visibilite="Caché", notes="Caché, code mort (côté config) : x"))
    assert actif.categorie_cachee == "code mort"


# --- Règles d'ensemble sur des cas fabriqués ---


def test_doublon_detecte():
    a = Actif(**ligne_valide())
    with pytest.raises(ErreurVeriteTerrain, match="double"):
        verifier_ensemble([a, a])


def test_vide_refuse():
    with pytest.raises(ErreurVeriteTerrain):
        verifier_ensemble([])


def test_parent_inexistant_detecte():
    certificat = Actif(**ligne_valide(
        type_cyclonedx="certificate", notes="Composant parent de QR-001 et QR-002"))
    with pytest.raises(ErreurVeriteTerrain, match="n'existe pas"):
        verifier_ensemble([certificat])


def test_parent_de_mauvais_type_detecte():
    cle = Actif(**ligne_valide(id="QR-001", type_cyclonedx="algorithm"))
    signature = Actif(**ligne_valide(id="QR-002", type_cyclonedx="algorithm"))
    certificat = Actif(**ligne_valide(
        id="QR-003", type_cyclonedx="certificate", notes="Composant parent de QR-001 et QR-002"))
    with pytest.raises(ErreurVeriteTerrain, match="devrait être de type"):
        verifier_ensemble([cle, signature, certificat])


# --- Lecture du CSV et conversion en JSON ---


def test_colonne_manquante(tmp_path):
    chemin = tmp_path / "incomplet.csv"
    chemin.write_text("ID,Composant\nQR-001,API\n", encoding="utf-8")
    with pytest.raises(ErreurVeriteTerrain, match="Colonnes manquantes"):
        charger_csv(chemin)


def test_ligne_invalide_signale_son_numero(tmp_path):
    chemin = ecrire_csv(tmp_path / "faux.csv", [ligne_valide(), ligne_valide(id="QR-998", vulnerabilite="Peut-être")])
    with pytest.raises(ErreurVeriteTerrain, match="Ligne 3"):
        charger_csv(chemin)


def test_conversion_json(tmp_path):
    sortie = tmp_path / "si_v1.json"
    convertir(CSV_V1, sortie)
    document = json.loads(sortie.read_text(encoding="utf-8"))
    assert document["version"] == "si_v1"
    assert document["resume"]["total"] == 70
    assert document["resume"]["caches"] == 16
    assert document["actifs"][0]["id"] == "QR-001"
    assert document["actifs"][14]["categorie_cachee"] == "croisement de fichiers"


def test_main_succes(tmp_path, capsys):
    assert main([str(CSV_V1), str(tmp_path / "si_v1.json")]) == 0
    assert "70 actifs" in capsys.readouterr().out


def test_main_mauvais_arguments(capsys):
    assert main([]) == 2


def test_main_erreur(tmp_path, capsys):
    chemin = tmp_path / "incomplet.csv"
    chemin.write_text("ID\nQR-001\n", encoding="utf-8")
    assert main([str(chemin), str(tmp_path / "x.json")]) == 1
    assert "Erreur" in capsys.readouterr().err
