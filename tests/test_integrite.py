"""Tests du fichier SHA256SUMS des artefacts publiés."""

import hashlib

import pytest

from quantum_ready import integrite


@pytest.fixture
def depot(tmp_path):
    (tmp_path / "results" / "raw").mkdir(parents=True)
    (tmp_path / "results" / "metrics.json").write_bytes(b'{"f1": 0.961}\n')
    (tmp_path / "results" / "raw" / ".gitkeep").write_bytes(b"")
    (tmp_path / "traces" / "run1").mkdir(parents=True)
    (tmp_path / "traces" / "run1" / "journal.jsonl").write_bytes(b'{"a": 1}\n')
    (tmp_path / "data" / "ground_truth").mkdir(parents=True)
    (tmp_path / "data" / "ground_truth" / "si_v1.json").write_bytes(b"{}\n")
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "code.py").write_bytes(b"print(1)\n")
    return tmp_path


def test_artefacts_publies_tries_sans_code_ni_gitkeep(depot):
    assert integrite.artefacts(depot) == [
        "data/ground_truth/si_v1.json",
        "results/metrics.json",
        "traces/run1/journal.jsonl",
    ]


def test_format_sha256sum(depot):
    texte = integrite.generer(depot).read_bytes()
    attendu = hashlib.sha256(b'{"f1": 0.961}\n').hexdigest()
    assert f"{attendu}  results/metrics.json\n".encode() in texte
    assert b"\r" not in texte and b"\\" not in texte


def test_generation_deterministe(depot):
    premier = integrite.generer(depot).read_bytes()
    assert integrite.generer(depot).read_bytes() == premier


def test_verification_conforme(depot):
    integrite.generer(depot)
    bilan = integrite.verifier(depot)
    assert bilan.conforme and bilan.verifies == 3


def test_modification_detectee(depot):
    integrite.generer(depot)
    (depot / "results" / "metrics.json").write_bytes(b'{"f1": 0.999}\n')
    bilan = integrite.verifier(depot)
    assert not bilan.conforme and bilan.differents == ["results/metrics.json"]


def test_suppression_detectee(depot):
    integrite.generer(depot)
    (depot / "traces" / "run1" / "journal.jsonl").unlink()
    assert integrite.verifier(depot).manquants == ["traces/run1/journal.jsonl"]


def test_fichier_non_liste_est_un_avertissement(depot):
    integrite.generer(depot)
    (depot / "traces" / "run1" / "evaluation.json").write_bytes(b"{}\n")
    bilan = integrite.verifier(depot)
    assert bilan.conforme and bilan.non_listes == ["traces/run1/evaluation.json"]


def test_lecture_format_invalide(tmp_path):
    (tmp_path / "SHA256SUMS").write_text("pas une empreinte\n", encoding="utf-8")
    with pytest.raises(ValueError):
        integrite.lire(tmp_path / "SHA256SUMS")


def test_lecture_mode_binaire_et_lignes_vides(tmp_path):
    valeur = "a" * 64
    (tmp_path / "SHA256SUMS").write_text(f"{valeur} *results/x.json\n\n", encoding="utf-8")
    assert integrite.lire(tmp_path / "SHA256SUMS") == {"results/x.json": valeur}


def test_cli(depot, capsys):
    assert integrite.main(["verifier", "--racine", str(depot)]) == 2
    assert integrite.main(["generer", "--racine", str(depot)]) == 0
    assert integrite.main(["verifier", "--racine", str(depot)]) == 0
    (depot / "results" / "metrics.json").write_bytes(b"modifie\n")
    assert integrite.main(["verifier", "--racine", str(depot)]) == 1
    assert "DIFFÉRENT  results/metrics.json" in capsys.readouterr().out
