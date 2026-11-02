#!/bin/sh
set -eu

umask 077
key_source="${RESOURCE_SIGNING_PRIVATE_KEY_PATH:?RESOURCE_SIGNING_PRIVATE_KEY_PATH is required}"
key_copy="/tmp/resource-signing-key.pem"

rm -f "$key_copy"
cp "$key_source" "$key_copy"
chmod 0600 "$key_copy"

export RESOURCE_SIGNING_PRIVATE_KEY_PATH="$key_copy"
exec "$@"
