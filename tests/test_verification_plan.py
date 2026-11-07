"""Classement des étapes du plan : démontrée, échec, non vérifiée. Aucun Docker : vérificateur simulé."""

from quantum_ready import verification_plan as vp


def _plan(*cibles):
    return {"etapes": [{"ordre": i + 1, "cible": c} for i, c in enumerate(cibles)]}


def test_cible_demontrable_et_reussie_est_demontree():
    verdicts = vp.classer(_plan("X25519MLKEM768"), lambda cle: (True, ""))
    assert [v.statut for v in verdicts] == ["démontrée"]


def test_cible_demontrable_en_echec_renvoie_un_motif_a_l_architecte():
    verdicts = vp.classer(_plan("ML-DSA-65"), lambda cle: (False, "certificat ECDSA négocié"))
    assert verdicts[0].statut == "échec"
    erreurs = vp.erreurs_pour_l_architecte(verdicts)
    assert len(erreurs) == 1 and "certificat ECDSA négocié" in erreurs[0]


def test_cible_non_demontrable_n_est_jamais_validee():
    verdicts = vp.classer(_plan("GnuPG 2.4 avec ECC"), lambda cle: (True, ""))
    assert verdicts[0].statut == "non vérifiée"
    assert vp.erreurs_pour_l_architecte(verdicts) == []  # pas une erreur : juste non vérifiée


def test_le_verificateur_n_est_appele_qu_une_fois_par_cible():
    appels = []
    def verifier(cle):
        appels.append(cle)
        return True, ""
    vp.classer(_plan("X25519MLKEM768", "x25519mlkem768", "X25519MLKEM768"), verifier)
    assert appels == ["tls-hybride"]


def test_plan_vide_ou_absent():
    assert vp.classer(None, lambda cle: (True, "")) == []
    assert vp.classer({"etapes": []}, lambda cle: (True, "")) == []


def test_demonstration_inconnue_echoue_sans_rien_lancer():
    from quantum_ready.outils import laboratoire
    reussi, motif = laboratoire.verifier("cle-inventee")
    assert reussi is False and "inconnue" in motif


def test_chaque_demonstration_du_plan_a_un_verificateur_reel():
    from quantum_ready.outils import laboratoire
    assert set(vp.DEMONSTRABLES.values()) == set(laboratoire.VERIFICATEURS)
