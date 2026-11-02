"""Socle des outils : périmètre, gestion des erreurs, secrets, classification."""

import pytest

from quantum_ready.outils.classification import exposition, exposition_la_pire
from quantum_ready.outils.commun import ErreurOutil, Resultat, decrire_secret, outil, racine_si, resoudre


def test_resoudre_accepte_un_fichier_du_si(tmp_path):
    (tmp_path / "a.txt").write_text("x")
    assert resoudre("a.txt", tmp_path.resolve()) == (tmp_path / "a.txt").resolve()


@pytest.mark.parametrize("chemin", ["../secret", "/etc/passwd", "a/../../b", ""])
def test_resoudre_refuse_ce_qui_sort_du_si(tmp_path, chemin):
    with pytest.raises(ErreurOutil):
        resoudre(chemin, tmp_path.resolve())


def test_resoudre_refuse_un_lien_symbolique_vers_l_exterieur(tmp_path):
    dehors = tmp_path / "dehors.txt"
    dehors.write_text("secret")
    si = tmp_path / "si"
    si.mkdir()
    (si / "lien").symlink_to(dehors)
    with pytest.raises(ErreurOutil, match="hors du périmètre"):
        resoudre("lien", si.resolve())


def test_resoudre_signale_un_fichier_absent(tmp_path):
    with pytest.raises(ErreurOutil, match="introuvable"):
        resoudre("absent.txt", tmp_path.resolve())


def test_racine_lue_dans_l_environnement(tmp_path, monkeypatch):
    monkeypatch.setenv("QR_RACINE_SI", str(tmp_path))
    assert racine_si() == tmp_path.resolve()


def test_racine_absente(monkeypatch):
    monkeypatch.delenv("QR_RACINE_SI", raising=False)
    with pytest.raises(ErreurOutil, match="QR_RACINE_SI"):
        racine_si()


def test_racine_qui_n_est_pas_un_dossier(tmp_path):
    fichier = tmp_path / "f"
    fichier.write_text("")
    with pytest.raises(ErreurOutil, match="pas un dossier"):
        racine_si(fichier)


@outil("outil_de_test")
def _outil_qui_plante(cible, racine):
    if cible == "prevu":
        raise ErreurOutil("message pour l'agent")
    raise ValueError("bogue")


def test_le_decorateur_transforme_les_erreurs_en_resultat(tmp_path):
    prevu = _outil_qui_plante("prevu", racine=tmp_path)
    imprevu = _outil_qui_plante("autre", racine=tmp_path)
    assert isinstance(prevu, Resultat) and prevu.erreurs == ["message pour l'agent"]
    assert "ValueError" in imprevu.erreurs[0]
    assert _outil_qui_plante.nom_outil == "outil_de_test"


def test_decrire_secret_ne_revele_pas_la_valeur():
    description = decrire_secret("dev-secret-2024")
    assert "dev-secret" not in description
    assert description.startswith("15 caractères")


@pytest.mark.parametrize(
    ("nom", "attendu"),
    [
        ("RSA-2048", "shor"),
        ("sha256WithRSAEncryption", "shor"),
        ("ecdsa-with-SHA384", "shor"),
        ("diffie-hellman-group14-sha256", "shor"),
        ("X25519MLKEM768", "resistant"),
        ("ML-DSA-65", "resistant"),
        ("AES-256-GCM", "grover"),
        ("hmac-sha2-256-etm@openssh.com", "grover"),
        ("Argon2id", "grover"),
        ("PermitRootLogin", "inconnue"),
    ],
)
def test_exposition(nom, attendu):
    assert exposition(nom) == attendu


def test_le_maillon_le_plus_faible_l_emporte():
    assert exposition_la_pire(["aes256-gcm", "curve25519-sha256"]) == "shor"
    assert exposition_la_pire(["chacha20-poly1305", "aes128-ctr"]) == "grover"
    assert exposition_la_pire([]) == "inconnue"
