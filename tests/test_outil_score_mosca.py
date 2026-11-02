"""Tests de score_mosca, écrits AVANT l'implémentation (développement piloté par les tests)."""

import pytest

from quantum_ready.outils.score_mosca import score_mosca

def test_factures_conservees_dix_ans():
    """Signature ECDSA des factures : x = 10, migration y = 3, menace z = 10."""
    resultat = score_mosca(10, 3, 10, "shor")
    assert (resultat.marge, resultat.en_danger, resultat.score, resultat.priorite) == (3, True, 100, "critique")


def test_juste_a_la_limite_n_est_pas_en_danger():
    resultat = score_mosca(7, 3, 10, "shor")
    assert resultat.marge == 0 and resultat.en_danger is False and resultat.score == 100


def test_donnees_de_courte_duree():
    resultat = score_mosca(1, 2, 10, "shor")
    assert (resultat.en_danger, resultat.score, resultat.priorite) == (False, 30, "moyenne")


def test_grover_pese_moins():
    assert score_mosca(10, 3, 10, "grover").score == 30


def test_inconnue_par_prudence_comme_shor():
    assert score_mosca(10, 3, 10, "inconnue").score == 100


@pytest.mark.parametrize("exposition", ["resistant", "aucune"])
def test_rien_a_migrer(exposition):
    resultat = score_mosca(30, 5, 10, exposition)
    assert (resultat.score, resultat.priorite) == (0, "faible")


@pytest.mark.parametrize(("x", "y", "z", "seuil"), [(4, 1, 10, "haute"), (2, 0, 10, "moyenne"), (1, 0.5, 10, "faible")])
def test_seuils_de_priorite(x, y, z, seuil):
    assert score_mosca(x, y, z, "shor").priorite == seuil


def test_explication_cite_les_valeurs():
    explication = score_mosca(10, 3, 10, "shor").explication
    assert all(valeur in explication for valeur in ("10", "3"))


@pytest.mark.parametrize(("x", "y", "z", "exposition"), [(-1, 3, 10, "shor"), (1, -3, 10, "shor"), (1, 3, 0, "shor"), (1, 3, 10, "rsa")])
def test_entrees_invalides_sans_exception(x, y, z, exposition):
    resultat = score_mosca(x, y, z, exposition)
    assert resultat.valide is False and resultat.erreurs
