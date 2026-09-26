#!/usr/bin/env bash
# wait.sh <host port> [path]: waits for a server to answer.
set -euo pipefail
url="http://127.0.0.1:$1${2:-/_matrix/client/versions}"
for _ in $(seq 90); do
	curl -sf "$url" >/dev/null && exit 0
	sleep 1
done
echo "$url did not come up" >&2
exit 1
