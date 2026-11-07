#!/bin/sh
# Serveur TLS 1.3 du laboratoire. Par défaut, n'accepte que le groupe hybride X25519MLKEM768 ;
# GROUPES=X25519 permet la référence classique pour les mesures.
# CERT choisit le type du certificat éphémère (ecdsa-p256 par défaut, rsa-2048 ou mldsa-65) ; créé dans /run, jamais persisté ni commité.
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
    *) echo "CERT inconnu : $CERT (ecdsa-p256, rsa-2048 ou mldsa-65)" >&2; exit 2 ;;
esac

echo "Démarrage sur le port $PORT (OpenSSL $(openssl version | cut -d' ' -f2))" >&2
exec openssl s_server -accept "$PORT" -tls1_3 -groups "$GROUPES" \
    -cert "$DOSSIER/cert.pem" -key "$DOSSIER/cle.pem" -www
