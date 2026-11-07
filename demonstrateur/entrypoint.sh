#!/bin/sh
# Serveur TLS 1.3 du laboratoire. Par défaut, n'accepte que le groupe hybride X25519MLKEM768 ;
# GROUPES=X25519 permet la référence classique pour les mesures.
# Certificat éphémère (EC P-256, auto-signé) créé dans /run : jamais persisté, jamais commité.
set -eu

PORT="${PORT:-8443}"
GROUPES="${GROUPES:-X25519MLKEM768}"
DOSSIER=/run/lab
mkdir -p "$DOSSIER"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -keyout "$DOSSIER/cle.pem" -out "$DOSSIER/cert.pem" -days 1 \
    -subj "/CN=lab.localhost" 2>/dev/null

echo "Démarrage sur le port $PORT (OpenSSL $(openssl version | cut -d' ' -f2))" >&2
exec openssl s_server -accept "$PORT" -tls1_3 -groups "$GROUPES" \
    -cert "$DOSSIER/cert.pem" -key "$DOSSIER/cle.pem" -www
