"""scan_tls_lab : périmètre local, lecture de la sortie d'openssl, trouvailles (sans serveur réel)."""

from pathlib import Path

import pytest

from quantum_ready.outils import scan_tls_lab as tls
from quantum_ready.outils.commun import ErreurOutil


@pytest.mark.parametrize("cible", ["127.0.0.1:8443", "localhost:9", "[::1]:443"])
def test_cible_locale_acceptee(cible):
    hote, port = tls.separer_cible(cible)
    assert hote in tls.HOTES_LOCAUX and port > 0


@pytest.mark.parametrize("cible", ["8.8.8.8:443", "example.com:443", "192.168.1.10:8443", "127.0.0.1", "127.0.0.1:port"])
def test_cible_non_locale_ou_mal_formee_refusee(cible):
    with pytest.raises(ErreurOutil):
        tls.separer_cible(cible)


def test_groupe_negocie_lu_dans_la_sortie():
    sortie = "New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384\nNegotiated TLS1.3 group: X25519MLKEM768\nProtocol: TLSv1.3\n"
    assert tls.groupe_negocie(sortie) == "X25519MLKEM768"
    assert tls.version_negociee(sortie) == "TLSv1.3"


def test_groupe_absent_quand_le_serveur_refuse():
    sortie = "40ECE0F101000000:error:...:ssl/tls alert handshake failure\nNegotiated TLS1.3 group: <NULL>\n"
    assert tls.groupe_negocie(sortie) is None


def _faux_sonde(reponses):
    """Remplace la connexion réelle : renvoie la sortie préparée pour chaque groupe proposé."""
    def sonder(hote, port, groupes):
        return reponses[groupes]
    return sonder


HYBRIDE = "New, TLSv1.3\nNegotiated TLS1.3 group: X25519MLKEM768\nProtocol  : TLSv1.3\n"
REFUS = "alert handshake failure\nNegotiated TLS1.3 group: <NULL>\n"


def test_trouvailles_pour_serveur_hybride_seul(monkeypatch):
    monkeypatch.setattr(tls, "version_openssl", lambda: "OpenSSL 3.5.9")
    monkeypatch.setattr(tls, "_sonder", _faux_sonde({"X25519MLKEM768": HYBRIDE, "X25519": REFUS}))
    resultat = tls.scan_tls_lab("127.0.0.1:8443", racine=Path("."))
    assert resultat.erreurs == []
    noms = {(t.type_actif, t.nom): t for t in resultat.trouvailles}
    assert set(noms) == {("protocol", "TLSv1.3"), ("algorithm", "X25519MLKEM768")}
    assert noms[("algorithm", "X25519MLKEM768")].exposition == "resistant"
    assert noms[("algorithm", "X25519MLKEM768")].proprietes["endroit"] == "127.0.0.1:8443"


def test_serveur_qui_accepte_aussi_le_classique(monkeypatch):
    classique = "Negotiated TLS1.3 group: X25519\nProtocol  : TLSv1.3\n"
    monkeypatch.setattr(tls, "version_openssl", lambda: "OpenSSL 3.5.9")
    monkeypatch.setattr(tls, "_sonder", _faux_sonde({"X25519MLKEM768": HYBRIDE, "X25519": classique}))
    noms = {t.nom: t.exposition for t in tls.scan_tls_lab("localhost:8443", racine=Path(".")).trouvailles}
    assert noms["X25519"] == "shor"


def test_aucun_groupe_negocie_est_une_erreur(monkeypatch):
    monkeypatch.setattr(tls, "version_openssl", lambda: "OpenSSL 3.5.9")
    monkeypatch.setattr(tls, "_sonder", _faux_sonde({"X25519MLKEM768": REFUS, "X25519": REFUS}))
    resultat = tls.scan_tls_lab("127.0.0.1:8443", racine=Path("."))
    assert resultat.erreurs and "aucun groupe" in resultat.erreurs[0]


def test_openssl_absent_est_signale(monkeypatch):
    monkeypatch.setattr(tls, "version_openssl", lambda: None)
    resultat = tls.scan_tls_lab("127.0.0.1:8443", racine=Path("."))
    assert resultat.erreurs and "openssl" in resultat.erreurs[0]


def test_cible_externe_refusee_avant_toute_connexion(monkeypatch):
    def interdit(*args, **kwargs):
        raise AssertionError("aucune connexion ne doit être tentée vers une cible externe")
    monkeypatch.setattr(tls, "_sonder", interdit)
    resultat = tls.scan_tls_lab("8.8.8.8:443", racine=Path("."))
    assert resultat.erreurs and "n'est pas local" in resultat.erreurs[0]


def test_commande_terminal_affiche_les_trouvailles(monkeypatch, capsys):
    monkeypatch.setattr(tls, "version_openssl", lambda: "OpenSSL 3.5.9")
    monkeypatch.setattr(tls, "_sonder", _faux_sonde({"X25519MLKEM768": HYBRIDE, "X25519": REFUS}))
    assert tls.main(["127.0.0.1:8443"]) == 0
    sortie = capsys.readouterr().out
    assert "X25519MLKEM768" in sortie and "resistant" in sortie


def test_commande_terminal_refuse_une_cible_externe(monkeypatch, capsys):
    assert tls.main(["8.8.8.8:443"]) == 1
    assert "n'est pas local" in capsys.readouterr().err


def test_commande_terminal_sans_argument_donne_l_aide(capsys):
    assert tls.main([]) == 2
    assert "Utilisation" in capsys.readouterr().err
