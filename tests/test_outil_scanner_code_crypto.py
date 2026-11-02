"""scanner_code_crypto : imports résolus, contexte, pièges de précision, liens vers le .env."""

import pytest

from quantum_ready.outils.scanner_code_crypto import scanner_code_crypto


@pytest.fixture(scope="module")
def si(racine_si):
    resultat = scanner_code_crypto(".", racine=racine_si)
    assert resultat.erreurs == []
    return resultat


def _du_fichier(resultat, fichier):
    return [t for t in resultat.trouvailles if t.fichier == fichier]


def _pistes(resultat):
    return {p.vers: p.raison for p in resultat.pistes}


def test_tous_les_usages_du_si(si):
    assert sorted((t.fichier, t.nom) for t in si.trouvailles) == sorted([
        ("api/auth.py", "Argon2id"),
        ("api/cache.py", "MD5"),
        ("api/crypto_fields.py", "Fernet (AES-128-CBC + HMAC-SHA256)"),
        ("api/files.py", "SHA-256"),
        ("api/legacy_auth.py", "SHA-256"),
        ("api/reset.py", "Mersenne Twister (module random)"),
        ("api/tokens.py", "JWT (algorithme à déterminer)"),
        ("api/utils/codes.py", "random.SystemRandom (os.urandom)"),
        ("api/webhooks.py", "HMAC-SHA-256"),
        ("factures/signer.py", "ECDSA avec SHA-256"),
    ])


def test_pieges_de_precision(si):
    """SystemRandom est sûr ; MD5 d'une clé de cache n'est pas un hachage de mot de passe."""
    (codes,) = _du_fichier(si, "api/utils/codes.py")
    assert "faiblesse_classique" not in codes.proprietes
    (cache,) = _du_fichier(si, "api/cache.py")
    assert cache.proprietes["fonction"] == "cle_de_cache" and "usage_probable" not in cache.proprietes
    (reset,) = _du_fichier(si, "api/reset.py")
    assert "NON cryptographique" in reset.proprietes["faiblesse_classique"]


def test_mot_de_passe_hache_sans_sel_et_code_mort(si):
    (legacy,) = _du_fichier(si, "api/legacy_auth.py")
    assert legacy.proprietes["usage_probable"] == "mot de passe"
    assert legacy.proprietes["module_importe_ailleurs"] is False
    assert "code mort" in _pistes(si)["api/legacy_auth.py"]
    (argon,) = _du_fichier(si, "api/auth.py")
    assert (argon.proprietes["t"], argon.proprietes["m_kio"], argon.proprietes["p"]) == (2, 19456, 1)
    assert "module_importe_ailleurs" not in argon.proprietes


def test_liens_vers_le_env(si):
    (jwt,) = _du_fichier(si, "api/tokens.py")
    assert jwt.exposition == "inconnue" and "JWT_ALGORITHM" in jwt.proprietes["algorithme"]
    assert jwt.proprietes["fonctions"] == ["creer_jeton", "verifier_jeton"]
    pistes = _pistes(si)
    assert "analyser_pkcs12" in pistes["KEYSTORE_PASS"]
    assert pistes["factures/keys/factures.p12"].startswith("fichier de clé ouvert")
    assert {"JWT_SECRET", "WEBHOOK_SECRET", "FIELD_ENCRYPTION_KEY", "DATABASE_URL", "paramiko"} <= set(pistes)


def test_hmac_compare_avec_egal(si):
    (hmac,) = _du_fichier(si, "api/webhooks.py")
    assert "attaque temporelle" in hmac.proprietes["faiblesse_classique"]


def test_imports_avec_alias_et_cas_divers(tmp_path):
    (tmp_path / "m.py").write_text(
        '"""Module de test."""\n'
        "import hashlib as h, hmac, jwt, os\n"
        "from random import choice as c\n"
        "from cryptography.hazmat.primitives.asymmetric import rsa, ec\n"
        "def jeton():\n    return c('ab')\n"
        "def empreinte(x):\n    return h.new('sha1', x).hexdigest()\n"
        "def deriver(pwd):\n    return h.pbkdf2_hmac('sha256', pwd, b's', 1000)\n"
        "def verifier(cle, msg, tag):\n"
        "    calcule = hmac.new(cle, msg, 'sha512').digest()\n    return hmac.compare_digest(calcule, tag)\n"
        "def signer():\n    return jwt.encode({}, os.getenv('K'), algorithm='RS256')\n"
        "def cles():\n    rsa.generate_private_key(65537, key_size=1024)\n    ec.generate_private_key(ec.SECP384R1())\n"
    )
    resultat = scanner_code_crypto("m.py", racine=tmp_path)
    noms = {t.nom: t for t in resultat.trouvailles}
    assert noms["Mersenne Twister (module random)"].proprietes["fonction"] == "jeton"
    assert "faiblesse_classique" in noms["SHA-1"].proprietes
    assert noms["PBKDF2-HMAC-SHA256"].proprietes["faiblesse_classique"] == "trop peu d'itérations"
    assert noms["HMAC-SHA-512"].proprietes["comparaison"].startswith("hmac.compare_digest")
    assert noms["JWT RS256"].exposition == "shor"
    assert {"RSA-1024", "ECDSA P-384"} <= set(noms)
    assert "K" in _pistes(resultat)
    assert all("module_importe_ailleurs" not in t.proprietes for t in resultat.trouvailles)  # un seul fichier


def test_erreurs(tmp_path):
    (tmp_path / "casse.py").write_text("def f(:\n")
    (tmp_path / "ok.py").write_text("import secrets\nsecrets.token_hex(16)\n")
    resultat = scanner_code_crypto(".", racine=tmp_path)
    assert "syntaxe Python invalide" in resultat.erreurs[0]
    assert [t.nom for t in resultat.trouvailles] == ["secrets (os.urandom)"]
    vide = tmp_path / "vide"
    vide.mkdir()
    assert "Aucun fichier Python" in scanner_code_crypto("vide", racine=tmp_path).erreurs[0]
