#!/bin/sh
# Serveur TLS 1.3 du laboratoire. Par défaut, n'accepte que le groupe hybride X25519MLKEM768 ;
# GROUPES=X25519 permet la référence classique pour les mesures.
# CERT choisit le type du certificat éphémère (ecdsa-p256 par défaut, rsa-2048, mldsa-65 ou mldsa-65-chaine) ; créé dans /run, jamais persisté ni commité.
set -eu

PORT="${PORT:-8443}"
GROUPES="${GROUPES:-X25519MLKEM768}"
CERT="${CERT:-ecdsa-p256}"
DOSSIER=/run/lab
mkdir -p "$DOSSIER"
case "$CERT" in
    ecdsa-p256) openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
        -keyout "$DOSSIER/cle.pem" -out "$DOSSIER/cert.pem" -days 1 -subj "/CN=lab.localhost" 2>/dev/null ;;
    rsa-2048) openssl req -x509 -newkey rsa:2048 -nodes \
        -keyout "$DOSSIER/cle.pem" -out "$DOSSIER/cert.pem" -days 1 -subj "/CN=lab.localhost" 2>/dev/null ;;
    mldsa-65) openssl req -x509 -newkey ML-DSA-65 -nodes \
        -keyout "$DOSSIER/cle.pem" -out "$DOSSIER/cert.pem" -days 1 -subj "/CN=lab.localhost" 2>/dev/null ;;
    mldsa-65-chaine)
        # Racine -> intermédiaire -> feuille, tout en ML-DSA-65. Le serveur envoie feuille + intermédiaire ;
        # la racine n'est pas envoyée (le client la connaît, comme dans une PKI réelle).
        printf 'basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n' > "$DOSSIER/ca.ext"
        printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nsubjectAltName=DNS:lab.localhost\n' > "$DOSSIER/feuille.ext"
        openssl req -x509 -newkey ML-DSA-65 -nodes -keyout "$DOSSIER/racine.key" -out "$DOSSIER/racine.pem" -days 1 -subj "/CN=Racine lab" -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
        openssl req -new -newkey ML-DSA-65 -nodes -keyout "$DOSSIER/intermediaire.key" -out "$DOSSIER/intermediaire.csr" -subj "/CN=Intermediaire lab" 2>/dev/null
        openssl x509 -req -in "$DOSSIER/intermediaire.csr" -CA "$DOSSIER/racine.pem" -CAkey "$DOSSIER/racine.key" -CAcreateserial -out "$DOSSIER/intermediaire.pem" -days 1 -extfile "$DOSSIER/ca.ext" 2>/dev/null
        openssl req -new -newkey ML-DSA-65 -nodes -keyout "$DOSSIER/cle.pem" -out "$DOSSIER/feuille.csr" -subj "/CN=lab.localhost" 2>/dev/null
        openssl x509 -req -in "$DOSSIER/feuille.csr" -CA "$DOSSIER/intermediaire.pem" -CAkey "$DOSSIER/intermediaire.key" -CAcreateserial -out "$DOSSIER/cert.pem" -days 1 -extfile "$DOSSIER/feuille.ext" 2>/dev/null ;;
    *) echo "CERT inconnu : $CERT (ecdsa-p256, rsa-2048, mldsa-65 ou mldsa-65-chaine)" >&2; exit 2 ;;
esac

echo "Démarrage sur le port $PORT (OpenSSL $(openssl version | cut -d' ' -f2))" >&2
if [ "$CERT" = mldsa-65-chaine ]; then
    exec openssl s_server -accept "$PORT" -tls1_3 -groups "$GROUPES" \
        -cert "$DOSSIER/cert.pem" -key "$DOSSIER/cle.pem" -cert_chain "$DOSSIER/intermediaire.pem" -www
fi
exec openssl s_server -accept "$PORT" -tls1_3 -groups "$GROUPES" \
    -cert "$DOSSIER/cert.pem" -key "$DOSSIER/cle.pem" -www
