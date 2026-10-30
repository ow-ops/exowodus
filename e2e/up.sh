#!/usr/bin/env bash
# Starts the end-to-end test servers on a Docker network:
#   synapse       Synapse, server name "synapse"            127.0.0.1:38008
#   continuwuity  Continuwuity, server name "continuwuity"  127.0.0.1:38009
#   samename      Synapse, server name "samename"           127.0.0.1:38010
#   massyn        Synapse using MAS, server name "massyn"   127.0.0.1:38014
#   mas           Matrix Authentication Service for massyn  127.0.0.1:38015
#   maspg         Postgres for MAS                          127.0.0.1:38016
#   oidc          static OIDC discovery document (network only)
# switch.sh replaces "samename" with Continuwuity on the same server name.
set -euo pipefail

SYNAPSE_IMAGE=${SYNAPSE_IMAGE:-ghcr.io/element-hq/synapse:latest}
MAS_IMAGE=${MAS_IMAGE:-ghcr.io/element-hq/matrix-authentication-service:latest}
NET=exowodus-e2e
WORK=$(mktemp -d /tmp/exowodus-e2e.XXXXXX)
chmod 755 "$WORK"
E2E=$(cd "$(dirname "$0")" && pwd)

"$E2E/down.sh"
docker network create "$NET" >/dev/null

mkdir -p "$WORK/certs"
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj /CN=e2e \
	-addext "subjectAltName=DNS:synapse,DNS:continuwuity,DNS:samename,DNS:massyn" \
	-keyout "$WORK/certs/tls.key" -out "$WORK/certs/tls.crt" 2>/dev/null
chmod 644 "$WORK/certs/"*
echo "$WORK" >"$E2E/.workdir"

synapse() {
	local name=$1 port=$2 extra=${3:-} dir="$WORK/$1"
	mkdir -p "$dir"
	docker run --rm -v "$dir:/data" -e SYNAPSE_SERVER_NAME="$name" -e SYNAPSE_REPORT_STATS=no \
		-e UID="$(id -u)" -e GID="$(id -g)" "$SYNAPSE_IMAGE" generate >/dev/null
	local limit='{per_second: 1000, burst_count: 1000}'
	cat >"$dir/homeserver.yaml" <<EOF
server_name: $name
pid_file: /data/homeserver.pid
listeners:
  - {port: 8008, type: http, tls: false, resources: [{names: [client, federation]}]}
  - {port: 8448, type: http, tls: true, resources: [{names: [client, federation]}]}
tls_certificate_path: /certs/tls.crt
tls_private_key_path: /certs/tls.key
database: {name: sqlite3, args: {database: /data/homeserver.db}}
log_config: /data/$name.log.config
media_store_path: /data/media_store
signing_key_path: /data/$name.signing.key
report_stats: false
registration_shared_secret: e2e-shared-secret
federation_verify_certificates: false
trusted_key_servers: []
suppress_key_server_warning: true
ip_range_whitelist: [172.16.0.0/12, 10.0.0.0/8, 192.168.0.0/16]
rc_message: $limit
rc_registration: $limit
rc_joins: {local: $limit, remote: $limit}
rc_invites: {per_room: $limit, per_user: $limit, per_issuer: $limit}
rc_login: {address: $limit, account: $limit, failed_attempts: $limit}
room_list_publication_rules: [{action: allow}]
EOF
	printf '%s\n' "$extra" >>"$dir/homeserver.yaml"
	if [ "$name" = samename ]; then
		cp "$E2E/bridge.yaml" "$dir/bridge.yaml"
		cat >>"$dir/homeserver.yaml" <<'EOF'
app_service_config_files: [/data/bridge.yaml]
experimental_features: {msc3814_enabled: true}
allow_guest_access: true
EOF
	fi
	docker run -d --name "$name" --network "$NET" -p "127.0.0.1:$port:8008" \
		-e UID="$(id -u)" -e GID="$(id -g)" \
		-v "$dir:/data" -v "$WORK/certs:/certs:ro" "$SYNAPSE_IMAGE" >/dev/null
}

# A static OpenID Connect discovery document, for Continuwuity's SSO linking.
mkdir -p "$WORK/oidc/.well-known"
cat >"$WORK/oidc/.well-known/openid-configuration" <<'EOF'
{"issuer": "http://oidc", "authorization_endpoint": "http://oidc/auth", "token_endpoint": "http://oidc/token",
 "jwks_uri": "http://oidc/jwks.json", "response_types_supported": ["code"], "subject_types_supported": ["public"],
 "id_token_signing_alg_values_supported": ["RS256"]}
EOF
echo '{"keys": []}' >"$WORK/oidc/jwks.json"
docker run -d --name oidc --network "$NET" -v "$WORK/oidc:/srv:ro" --entrypoint python "$SYNAPSE_IMAGE" -c \
	"import functools, http.server as h; h.SimpleHTTPRequestHandler.extensions_map[''] = 'application/json'; h.test(HandlerClass=functools.partial(h.SimpleHTTPRequestHandler, directory='/srv'), port=80, bind='0.0.0.0')" >/dev/null

synapse synapse 38008
synapse samename 38010
"$E2E/continuwuity.sh" continuwuity continuwuity 38009

docker run -d --name maspg --network "$NET" -p 127.0.0.1:38016:5432 \
	-e POSTGRES_PASSWORD=mas -e POSTGRES_DB=mas postgres:17-alpine >/dev/null
mkdir -p "$WORK/mas"
docker run --rm "$MAS_IMAGE" config generate >"$WORK/mas/generated.yaml" 2>/dev/null
python3 "$E2E/mas_config.py" "$WORK/mas/generated.yaml" >"$WORK/mas/config.yaml"
chmod 644 "$WORK/mas/config.yaml"
until docker exec maspg pg_isready -U postgres >/dev/null 2>&1; do sleep 1; done
docker run -d --name mas --network "$NET" -p 127.0.0.1:38015:8080 \
	-v "$WORK/mas/config.yaml:/config.yaml:ro" "$MAS_IMAGE" server -c /config.yaml >/dev/null
synapse massyn 38014 "public_baseurl: http://massyn:8008/
matrix_authentication_service: {enabled: true, endpoint: 'http://mas:8080/', secret: e2e-mas-secret}"

for port in 38008 38010 38014; do
	"$E2E/wait.sh" "$port"
done
"$E2E/wait.sh" 38015 /.well-known/openid-configuration
for u in madmin mira; do
	admin=$([ "$u" = madmin ] && echo --admin || echo --no-admin)
	docker exec mas mas-cli manage register-user -c /config.yaml -y --ignore-password-complexity \
		-p "$u-password" "$admin" "$u" >/dev/null 2>&1
done
for u in admin alice bob; do
	admin=$([ "$u" = admin ] && echo -a || echo --no-admin)
	docker exec synapse register_new_matrix_user -u "$u" -p "$u-password" "$admin" \
		-c /data/homeserver.yaml http://localhost:8008 >/dev/null
done
for u in sadmin dave erin; do
	admin=$([ "$u" = sadmin ] && echo -a || echo --no-admin)
	docker exec samename register_new_matrix_user -u "$u" -p "$u-password" "$admin" \
		-c /data/homeserver.yaml http://localhost:8008 >/dev/null
done
echo "$WORK"
