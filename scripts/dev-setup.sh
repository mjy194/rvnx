#!/bin/sh
# Run from the repository root. Creates local-only development credentials.
set -eu
umask 077

for path in certs/server.pem certs/server-key.pem srv.local.toml clnt.local.toml; do
    if [ -e "$path" ]; then
        echo "Refusing to overwrite $path" >&2
        exit 1
    fi
done
mkdir -p certs
openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 30 \
    -keyout certs/server-key.pem -out certs/server.pem \
    -subj '/CN=localhost' \
    -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1' \
    -addext 'basicConstraints=critical,CA:FALSE' \
    -addext 'keyUsage=critical,digitalSignature,keyEncipherment' \
    -addext 'extendedKeyUsage=serverAuth'

rvnx_token=$(openssl rand -hex 32)
sed "s/REPLACE_WITH_A_RANDOM_SECRET_AT_LEAST_32_BYTES/$rvnx_token/;s/0.0.0.0/127.0.0.1/g" \
    examples/srv.toml > srv.local.toml
sed "s/REPLACE_WITH_A_RANDOM_SECRET_AT_LEAST_32_BYTES/$rvnx_token/" \
    examples/clnt.toml > clnt.local.toml
echo 'Created certs/, srv.local.toml and clnt.local.toml (loopback only).'
