#!/usr/bin/env bash
# Restarts the "samename" Continuwuity with OIDC enabled, keeping its data.
set -euo pipefail
OIDC=1 exec "$(dirname "$0")/switch.sh"
