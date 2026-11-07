#!/bin/sh
# Serveur SSH du laboratoire. KEX fixe la liste d'échanges de clés acceptés
# (par défaut le groupe hybride seul). Clé d'hôte éphémère, jamais persistée.
set -eu

PORT="${PORT:-2222}"
KEX="${KEX:-mlkem768x25519-sha256}"
mkdir -p /run/sshd /run/ssh
ssh-keygen -q -t ed25519 -N '' -f /run/ssh/ssh_host_ed25519_key

echo "Démarrage sshd sur le port $PORT, échanges acceptés : $KEX" >&2
exec /usr/sbin/sshd -D -e -p "$PORT" -h /run/ssh/ssh_host_ed25519_key \
    -o KexAlgorithms="$KEX" -o PasswordAuthentication=no -o PubkeyAuthentication=yes
