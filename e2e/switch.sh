#!/usr/bin/env bash
# Replaces the "samename" Synapse with Continuwuity on the same server name.
set -euo pipefail
E2E=$(cd "$(dirname "$0")" && pwd)
docker rm -f samename >/dev/null
TRUSTED='["synapse", "host.docker.internal:38020"]' "$E2E/continuwuity.sh" samename samename 38010
