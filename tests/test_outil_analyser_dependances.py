"""analyser_dependances : déclarées, verrouillées, transitives, importées, vulnérables."""

import pytest

from quantum_ready.outils.analyser_dependances import analyser_dependances, normaliser, version_tuple


@pytest.fixture(scope="module")
def bibliotheques(racine_si):
    resultat = analyser_dependances("api", racine=racine_si)
    assert resultat.erreurs == []
    return {t.nom.split()[0]: t for t in resultat.trouvailles}


def test_bibliotheques_du_si(bibliotheques):
    assert set(bibliotheques) == {"argon2-cffi", "argon2-cffi-bindings", "bcrypt", "cryptography", "paramiko", "pycryptodome", "pyjwt", "pynacl"}
    assert all(t.type_actif == "library" for t in bibliotheques.values())


def test_dependance_morte_et_vulnerable(bibliotheques):
    pycryptodome = bibliotheques["pycryptodome"]
    assert pycryptodome.proprietes["importee_dans"] == []
    assert "dépendance morte" in pycryptodome.proprietes["faiblesse_classique"]
    assert "CVE-2023-52323" in pycryptodome.proprietes["faiblesse_classique"]


def test_transitives_tirees_par_paramiko(bibliotheques):
    for nom in ("pynacl", "bcrypt"):
        assert bibliotheques[nom].proprietes["declaree"] is False
        assert bibliotheques[nom].proprietes["tiree_par"] == ["paramiko"]
        assert bibliotheques[nom].fichier == "api/uv.lock"


def test_imports_dans_tout_le_si(bibliotheques):
    assert bibliotheques["paramiko"].proprietes["importee_dans"] == ["scripts/deploy.py"]
    assert "factures/signer.py" in bibliotheques["cryptography"].proprietes["importee_dans"]
    assert "version_verrouillee" in bibliotheques["pyjwt"].proprietes


def test_sans_verrou_et_version_ancienne(tmp_path):
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "x"\ndependencies = ["PyJWT==2.3.0", "requests"]\n')
    (tmp_path / "app.py").write_text("import jwt\n")
    resultat = analyser_dependances("pyproject.toml", racine=tmp_path)
    (pyjwt,) = resultat.trouvailles
    assert "CVE-2022-29217" in pyjwt.proprietes["faiblesse_classique"]
    assert "uv.lock" in resultat.pistes[0].raison


def test_sans_aucun_fichier(tmp_path):
    assert "Aucun fichier de dépendances" in analyser_dependances(".", racine=tmp_path).erreurs[0]


def test_requirements_txt(tmp_path):
    (tmp_path / "requirements.txt").write_text("# dépendances\npycryptodome==3.4.7\nrequests>=2.31 ; python_version >= '3.8'\n-r autres.txt\nparamiko\n")
    (tmp_path / "a.py").write_text("from Crypto.Cipher import AES\n")
    resultat = analyser_dependances(".", racine=tmp_path)
    noms = {t.nom: t for t in resultat.trouvailles}
    assert noms["pycryptodome 3.4.7"].proprietes["importee_dans"] == ["a.py"]
    assert "CVE-2023-52323" in noms["pycryptodome 3.4.7"].proprietes["faiblesse_classique"]
    assert "dépendance morte" in noms["paramiko toute version"].proprietes["faiblesse_classique"]
    assert noms["pycryptodome 3.4.7"].fichier == "requirements.txt"


def test_poetry(tmp_path):
    (tmp_path / "pyproject.toml").write_text('[tool.poetry]\nname = "x"\n[tool.poetry.dependencies]\npython = "^3.11"\nparamiko = "^3.0"\n')
    (tmp_path / "poetry.lock").write_text(
        '[[package]]\nname = "paramiko"\nversion = "3.3.1"\n[package.dependencies]\npynacl = ">=1.5"\n\n'
        '[[package]]\nname = "pynacl"\nversion = "1.5.0"\n\n[metadata]\ncontent-hash = "abc"\n')
    noms = {t.nom: t for t in analyser_dependances(".", racine=tmp_path).trouvailles}
    assert "CVE-2023-48795" in noms["paramiko 3.3.1"].proprietes["faiblesse_classique"]
    assert noms["pynacl 1.5.0"].proprietes["tiree_par"] == ["paramiko"]


def test_utilitaires():
    assert normaliser("Argon2_CFFI") == "argon2-cffi"
    assert version_tuple("3.9.9") < (3, 19, 1)
