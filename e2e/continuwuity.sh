#!/usr/bin/env bash
# continuwuity.sh <container> <server name> <host port>
# Starts Continuwuity with an admin account "cadmin" (password cadmin-password).
set -euo pipefail

CONTINUWUITY_IMAGE=${CONTINUWUITY_IMAGE:-ghcr.io/continuwuity/continuwuity:latest}
E2E=$(cd "$(dirname "$0")" && pwd)
WORK=$(cat "$E2E/.workdir")
name=$1 server=$2 port=$3 dir="$WORK/cw-$1"

trusted=${TRUSTED:-'["synapse"]'}
mkdir -p "$dir/data"
chmod 777 "$dir/data"
cat >"$dir/continuwuity.toml" <<EOF
[global]
server_name = "$server"
database_path = "/data/db"
address = ["0.0.0.0"]
port = [8008, 8448]
allow_registration = true
registration_token = "e2e-registration-token"
force_disable_first_run_mode = true
trusted_servers = $trusted
ip_range_denylist = []
allow_invalid_tls_certificates_yes_i_know_what_the_fuck_i_am_doing_with_this_and_i_know_this_is_insecure = true
admin_execute = ["users create-user cadmin cadmin-password", "users make-user-admin @cadmin:$server"]
admin_execute_errors_ignore = true

$( [ "${OIDC:-}" = 1 ] && printf '[global.oauth.oidc]\ndiscovery_url = "http://oidc"\nclient_id = "c10y"\nclient_secret = "secret"\n' )

[global.tls]
certs = "/certs/tls.crt"
key = "/certs/tls.key"
dual_protocol = true
EOF

docker run -d --name "$name" --network exodus-e2e --network-alias "${NETWORK_ALIAS:-$server}" -p "127.0.0.1:$port:8008" \
	--add-host host.docker.internal:host-gateway \
	-e CONTINUWUITY_CONFIG=/etc/continuwuity.toml \
	-v "$dir/continuwuity.toml:/etc/continuwuity.toml:ro" \
	-v "$dir/data:/data" -v "$WORK/certs:/certs:ro" "$CONTINUWUITY_IMAGE" >/dev/null
"$E2E/wait.sh" "$port"
# OIDC disables password login; this mode restarts an existing fixture.
if [ "${OIDC:-}" = 1 ]; then
	exit 0
fi
# The listener starts before admin_execute has created the test account.
for _ in {1..100}; do
	if curl -fsS -o /dev/null -H 'Content-Type: application/json' \
		-d '{"type":"m.login.password","identifier":{"type":"m.id.user","user":"cadmin"},"password":"cadmin-password","device_id":"e2e-readiness"}' \
		"http://127.0.0.1:$port/_matrix/client/v3/login" 2>/dev/null; then
		exit 0
	fi
	sleep 0.2
done
echo "Continuwuity admin account did not become ready" >&2
exit 1
