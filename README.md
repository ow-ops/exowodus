# exowodus

Migrate a Matrix homeserver from Synapse or Tuwunel to [Continuwuity](https://continuwuity.org),
or move a single account from any homeserver (including matrix.org). Continuwuity
itself is not modified.

## Build

Prebuilt binaries for Linux, macOS and Windows, with a `SHA256SUMS` file, are
attached to each release.

To build from source, you need Go 1.27:

```sh
go build -o exowodus .
```

`EXOWODUS_*` environment variables take precedence over the older `EXODUS_*`
names, which remain supported. The default archive is `exowodus-archive`; an
existing `exodus-archive` is reused when the new directory is absent. Use
`--archive` to select another directory.

All commands show an inline terminal display with the current step, elapsed
time, batch counts and transfer progress. HTTP waits show the request path and
attempt number. Redirected output uses plain logs; `--progress plain` disables
the display explicitly, and `--progress tty` forces it. `--verbose` keeps
request details and logs in scrollback. `NO_COLOR` disables colors.

Verification export shows batch and user counts. Each key-query batch allows
three attempts within two minutes, with 45-second HTTP and 10-second remote-key
timeouts. Retries use jittered backoff and respect rate-limit delays. Partial
federation failures retry only affected users. Unreachable peers leave recorded
verification warnings; cached keys are kept and other batches continue. Required
account keys and `--require-lossless` exports still fail on unresolved lookups.

## Before you start

1. On a fresh Continuwuity, create **your own admin account first**: the first
   account created becomes the server admin.
2. Issue a registration token with `!admin token issue`.
3. Pass the admin's access token as `--to-admin-token`. It is needed for admin
   rights, account statuses, emails, recreated rooms, devices, bridges and
   server state. exowodus temporarily registers an `exodus` appservice through
   the admin room and removes it when the import ends.

Good to know:

- **Retry failed steps with the same archive and destination.** Commands exit
  nonzero on failure. Check
  `exowodus-archive/import-report.json` and the per-user reports under
  `exowodus-archive/users/*/import-report.json` before cutover.
- **Incomplete exports cannot be imported.** Check
  `exowodus-archive/export-report.json` and rerun `export`. Media download
  failures also fail the export. Pass `--skip-missing-media` to migrate
  accounts while omitting source media that returns HTTP 404.
  Remote media is always skipped; local uploads are exported.
- **`export --jobs N`** exports N accounts or rooms at once. More jobs use
  more memory.
- **The archive is sensitive.** It holds account data, encrypted key backups,
  password hashes, access tokens and generated passwords. Keep it safe, and
  retain it while you run the proxy or need archive-only room history.
- **Secrets can be passed as environment variables** instead of flags:

  | Variable                           | Flag                        |
  | ---------------------------------- | --------------------------- |
  | `EXOWODUS_FROM_TOKEN`              | `--from-token`              |
  | `EXOWODUS_FROM_PASSWORD`           | `--from-password`           |
  | `EXOWODUS_FROM_ADMIN_TOKEN`        | `--from-admin-token`        |
  | `EXOWODUS_FROM_MAS_TOKEN`          | `--from-mas-token`          |
  | `EXOWODUS_FROM_MAS_CLIENT_ID`      | `--from-mas-client-id`      |
  | `EXOWODUS_FROM_MAS_CLIENT_SECRET`  | `--from-mas-client-secret`  |
  | `EXOWODUS_SYNAPSE_DB`              | `--synapse-db`              |
  | `EXOWODUS_MAS_DB`                  | `--mas-db`                  |
  | `EXOWODUS_TO_TOKEN`                | `--to-token`                |
  | `EXOWODUS_TO_PASSWORD`             | `--to-password`             |
  | `EXOWODUS_TO_ADMIN_TOKEN`          | `--to-admin-token`          |
  | `EXOWODUS_REGISTRATION_TOKEN`      | `--registration-token`      |
  | `EXOWODUS_SYNAPSE_PASSWORD_PEPPER` | `--synapse-password-pepper` |
  | `EXOWODUS_SYNAPSE_MACAROON_SECRET` | `--synapse-macaroon-secret` |

## Usage

### Migrating from Tuwunel

Keep the same `server_name` to preserve message IDs, encrypted history and logins.

1. Pause client, bridge and federation writes, keeping Tuwunel's APIs available.
2. Back up the database and media, then [prepare the database export](docs/tuwunel.md).
3. Export, stop Tuwunel, and start Continuwuity with the same `server_name`.
4. [Configure the relay](#relay---relay-name) and import.
5. Stop Continuwuity, run `exowodus finish` to restore the signing key, media and
   logins, then start it again. Use [the proxy](#the-proxy) for sessions
   `finish` reports it could not restore and for pending deliveries.

```sh
exowodus export --from https://example.org --from-type tuwunel \
  --from-admin-token "$ADMIN" --all-users --tuwunel-dump ./tuwunel-dump

# Stop Tuwunel and start Continuwuity with the same server_name.
exowodus import --to http://continuwuity:8008 --to-admin-token "$CADMIN" \
  --registration-token "$REG" --relay-name relay.example.net

# Stop Continuwuity.
exowodus finish --database /path/to/continuwuity-database --ldb /absolute/path/to/ldb
# Start Continuwuity.
```

Some Tuwunel data, including certain read receipts, cannot be restored in stock
Continuwuity and blocks import. Check the
[limitations](docs/tuwunel.md#original-events-and-strict-cutover-checks) before
cutover. Retry failed steps with the same archive; see `import-report.json`.

To resume an interrupted whole-server Tuwunel export, rerun the same export
command with the same archive and unchanged dump. Keep source writes paused.
Completed accounts, rooms and media are verified and reused.

Import verifies original messages and checks each exported token against the
destination user and device. Keep the archive and proxy running for existing
logins. Whole-server migration cannot disable these checks.

For one account, use `--from-type tuwunel` with the [single-account flow](#moving-a-single-account).

### Replacing Synapse on the same server name

This restores sessions, devices and encryption on the same server name.
Keep a source database and media backup. Before the final export, stop client,
bridge and federation writes to Synapse while leaving its APIs available to
exowodus. Export reads APIs and database tables separately; it is not a consistent
snapshot while the source is changing. Route clients to the destination only
after import completes without failures.

```sh
exowodus export --from https://example.org --from-admin-token "$ADMIN" --all-users \
  --synapse-db postgres://synapse@db/synapse

# stop Synapse, start Continuwuity with the same server_name

exowodus import --to http://continuwuity:8008 --registration-token "$REG" --to-admin-token "$CADMIN" \
  --appservice-registration /etc/synapse/bridges/telegram.yaml

exowodus proxy --upstream http://continuwuity:8008
```

Keep each bridge's database and crypto store. Its registration file does not
restore device keys; queued messages wait until their original devices exist
on the destination.

To leave an unavailable room in the archive, add `--skip-room '!room:server'`
to the import command. The exclusion also applies to later imports.

Then route all client and federation traffic through `exowodus proxy`, for
example by pointing your reverse proxy at it instead of Continuwuity. See
[The proxy](#the-proxy).

Rooms shared with other servers are rejoined through them. Continuwuity has a
new signing key, so it needs `trusted_servers` (default `matrix.org`) to fetch
your old key and verify your server's past events.

### Moving to a new server name

With the source server still online:

```sh
exowodus migrate --from https://synapse.example.org --from-admin-token "$ADMIN" --all-users \
  --synapse-db postgres://synapse@db/synapse \
  --to https://continuwuity.example.net --registration-token "$REG" --to-admin-token "$CADMIN"

exowodus proxy --upstream https://continuwuity.example.net   # password migration
exowodus proxy --listen :8080   # behind the old domain's TLS reverse proxy, for old media links
```

Each old account invites its new account into every room with the same power
level, so all rooms, including invite-only and local-only ones, keep working
after the old server shuts down. The new account sees earlier history when the
room's history visibility allows it (`shared`, the default).

- `--users @a:example.org,@b:example.org` selects a subset of users.
- Accounts without a known password get a random one, written to
  `exowodus-archive/credentials.csv`. The proxy replaces it with the old
  password on first login.

### Moving a single account

No admin access is needed, for example to leave matrix.org. Copy your access
token from Element (Settings → Help & About):

```sh
exowodus migrate --from https://matrix-client.matrix.org --from-token "$TOKEN" \
  --to https://matrix.example.org --registration-token "$REG" --to-password "$NEW_PASSWORD"
```

### Synapse with MAS

Add `--from-mas-url` and `--from-mas-token`:

- `--from-mas-token` needs the `urn:mas:admin` scope.
- `--from-admin-token` must be a MAS personal token with `urn:synapse:admin:*`.

For automatic token renewal, replace `--from-mas-token` with
`--from-mas-client-id` and `--from-mas-client-secret`. The MAS client must use
`client_secret_basic` and appear in `policy.data.admin_clients`; see the
[MAS admin API setup](https://element-hq.github.io/matrix-authentication-service/topics/admin-api.html#automated-tools).
Use `EXOWODUS_FROM_MAS_CLIENT_ID` and `EXOWODUS_FROM_MAS_CLIENT_SECRET` to keep the
secret out of command arguments.

exowodus impersonates users through MAS personal sessions and reads emails, SSO
links and registration tokens from MAS. Add `--mas-db` to also export
passwords and sessions:

- **Passwords:** pass the MAS configuration to the proxy (`--mas-config`) when
  a password scheme uses a `secret` or Unicode normalization.
- **Legacy sessions:** mapped like Synapse sessions.
- **OAuth 2.0 sessions:** clients refresh their tokens at MAS's token
  endpoint, so route `/oauth2/token` on the MAS domain to the proxy. It answers
  these refreshes with the migrated device's session. It also handles mapped
  OAuth refresh tokens at `/_continuwuity/oauth2/grant/token`, forwarding
  unknown tokens to Continuwuity.

### SSO users

Enabling OIDC on Continuwuity disables the password logins the import relies
on, but linking identities requires OIDC. So, in order:

1. Run the import.
2. Configure `[global.oauth.oidc]` on Continuwuity.
3. Run `exowodus link-sso --to ... --to-admin-token ...`.

## The proxy

`exowodus proxy` sits in front of Continuwuity and keeps old credentials and
links working:

| What                | How                                                                                                                                                                                                                    |
| ------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Sessions            | Old Synapse access and refresh tokens are swapped for sessions on the same devices, so users stay logged in with encryption intact.                                                                                    |
| Passwords           | A user's first password login is checked against the old hash, then the password is set on Continuwuity. Supports Synapse bcrypt, and MAS argon2, PBKDF2 and bcrypt, with or without a secret.                         |
| Media               | Old media IDs are served from the archive, over the client and federation media APIs.                                                                                                                                  |
| Guests              | Synapse guest tokens are macaroons Synapse never stored. Pass `--synapse-macaroon-secret` (Synapse's `macaroon_secret_key`, or `registration_shared_secret` if unset), or `--synapse-signing-key` when neither is set. |
| Registration tokens | Old tokens are swapped for the ones issued on import.                                                                                                                                                                  |
| Shadow bans         | Continuwuity has none, so the proxy answers shadow-banned users' messages, state changes and invites as if they succeeded, without sending them.                                                                       |

Archived to-device messages from remote senders are delivered to their original
devices and retained until the client acknowledges receipt.

Proxy request logs include method, host, path, status and duration, with 4xx
responses as warnings and 5xx as errors. `--verbose` also logs request starts.
Query strings, headers and bodies are omitted. `--progress plain` writes plain
logs to stderr.

## Rooms only your server was in

These rooms are recreated under their **original room ID**, so links, key
backups and encrypted messages keep working. There are two modes.

### Replay (default)

Events are replayed one by one, as their original senders and with their
original timestamps:

- Messages, replies, edits, reactions, redactions, membership and state changes
  are all replayed.
- From room version 12 the ID is the hash of the create event, which is
  reproduced with the original creator, content and timestamp.
- Media is re-uploaded and re-pointed.
- Deactivated users are recreated to send their messages, then deactivated
  again.
- Bridge puppets post through their bridge's own token.

### Relay (`--relay-name`)

exowodus hands the rooms over with their **original events**: event IDs,
signatures, senders and timestamps are unchanged. Requires exported original
PDUs, the source signing key and `import --to-admin-token`.

During the import, exowodus runs a temporary federation server under that name
(`--relay-listen`, default `:8448`) that serves the exported events:

1. The relay joins through an authorized invitation, or joins a public room
   directly when its join rules allow it.
2. The relay sends the events it signed to the room's other servers, then a
   migrated member joins through it and Continuwuity backfills the whole
   history from it. Continuwuity does not serve events it received while
   joining, so other servers can only get these from the relay.
3. The relay sends its own signed leave after restoration succeeds.

Use a server name such as `--relay-name relay.example.net`, without `https://`.
The listener uses HTTPS, including behind a reverse proxy. Point the proxy at
`https://<reachable-host>:8448` and configure backend certificate trust. With a
proxy on a Docker bridge network and Exowodus on the host, use the host's LAN
address and `--relay-listen 0.0.0.0:8448`. `127.0.0.1` points inside the container.
For public port 443, use `--relay-name relay.example.net:443` or provide federation
delegation separately. Exowodus does not serve `/.well-known/matrix/server`.
See the [Traefik example](docs/tuwunel.md#relay-behind-traefik).

While import is running, test the local listener and public route:

```sh
curl -kfsS https://127.0.0.1:8448/_matrix/key/v2/server
curl -fsS https://relay.example.net/_matrix/key/v2/server
```

`-k` is only for diagnosing the local self-signed listener. Both responses should
identify the configured relay server name.

Exowodus checks that Continuwuity can reach the relay before importing accounts or
rooms. A failed check stops import and appears in `import-report.json`. Room
permissions can still block individual rooms.

Requirements:

- Continuwuity must reach the relay over federation.
- Add the relay to Continuwuity's `trusted_servers`, since it also serves your
  old server's key. With unchanged user IDs, this also permits backfill without
  changing room power levels. Private rooms still need an authorized inviter.
- In federated rooms, other servers must reach the relay at its name with a
  trusted certificate to verify its events. Otherwise they reject later events
  from your server in those rooms.
- Continuwuity must trust the public relay certificate. Use a reverse proxy with
  a trusted certificate, or provide one with `--relay-tls-cert` and
  `--relay-tls-key`. The relay's default certificate is self-signed.

The relay stays in the room until all exported events are backfilled and room
restoration succeeds. Incomplete backfill fails the import; retry with the same
archive and relay configuration. Retries check the relay's membership and rejoin
it if room admission rules allow. Rooms created by earlier attempts are reused.

In federated rooms Continuwuity may ask another server for history first; an
empty answer is retried up to 20 times before backfill fails. Members missing
from the destination's room state are invited by the room's most powerful
migrated member, then joined. History is checked as each migrated member, since
history visibility can hide events from one of them. An archived event that was
redacted later on another server matches its redacted form. An event the source
stored with emptied content matches its original content when that content
reproduces the archived content hash.

Continuwuity only backfills events older than the earliest one it has. If an
earlier attempt reached a room's create event but missed events, import offers
them to Continuwuity directly; they then appear before the create event in the
room's timeline.

Rooms with a version before 3, or whose event IDs cannot be recomputed from the
exported events, fall back to replay.

### Rooms without local members

`--all-users` also exports retained history from rooms that all local users
have left. These rooms are marked `archive_only` in `rooms/*/room.json` and
stay in the archive. Import does not rejoin them or publish their aliases.
Subset and single-account exports omit this inventory.

### Retrying an incomplete migration

Fix the reported cause and rerun with the same archive. Failed event sends,
device-key uploads, pushers and room restoration are not marked complete.
Power transfers that need the old account require rerunning `migrate` while the
source is still online. Account locks, suspensions and deactivations are deferred
until the preceding migration steps succeed.

Older archives may have marked failed steps complete. Upgrading does not repair
those flags or recover skipped data. Compare against the source backup.

## What is migrated

| Area                   | Details                                                                                                                                                                                                                                                                                                                       |
| ---------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Accounts               | Account (including guests) and admin rights; lock, suspension, deactivation (user IDs stay reserved) and shadow bans (enforced by the proxy); email; SSO identities; display name, avatar, other profile fields and status message                                                                                            |
| Passwords and sessions | Passwords, set by the proxy on first login; existing client sessions, including guest and MAS legacy and OAuth 2.0 sessions (same server name)                                                                                                                                                                                |
| Encryption             | Key backup and secret storage (the recovery key keeps working); cross-signing keys, verifications, devices and their keys, unclaimed one-time and fallback keys, dehydrated devices (same server name); undelivered to-device messages from local users, such as room keys in flight (same server name, needs `--synapse-db`) |
| Data                   | Account data (DM lists, ignore lists, tags, room settings), push rules, pushers, read markers and receipts (private stay private), pending invites and knocks; media, re-uploaded, with old links served by the proxy                                                                                                         |
| Rooms                  | Memberships, power levels, per-room nicknames and avatars, local aliases, room directory listings; [rooms only your server was in](#rooms-only-your-server-was-in), with full history including encrypted messages; bridges (appservices) with their portal rooms and puppets                                                 |
| Server                 | Registration tokens (old strings work through the proxy); blocked rooms; reports of events, rooms and users, refiled by their reporters with their original date so they reach the Continuwuity admin room (needs `--synapse-db`)                                                                                             |

## What cannot be migrated

- **Messages from other servers' users in replayed rooms.** Events are signed
  by their origin server, and exowodus cannot sign as another server. `@exodus`
  posts them as notices naming the sender. Relayed rooms keep them.
- **Some timestamps in replayed rooms** (relayed rooms keep them all). These
  carry the import time:
  - events generated by room creation: the creator's join, power levels, join
    rules, history visibility and guest access
  - redactions in rooms before version 11, since only Continuwuity's `/redact`
    route, which takes no timestamp, sets their target
- **Identities, on a new server name.** Devices, cross-signing and
  verifications embed the old user ID, so users sign in again and set up a new
  identity. The recovery key still restores the key backup. Old messages stay
  in the shared rooms and are visible when history visibility allows.
- **Per-thread read receipts.** Continuwuity keeps one receipt per room, so
  only the main one is restored.
- **Private read receipts on backfilled events**, i.e. history fetched from
  other servers or from the relay.
- **To-device messages from other servers.** Only their server can send them.
  Clients request missing room keys again.
- **Features Continuwuity lacks:** phone numbers, multiple email addresses,
  media quarantine (quarantined media is not exported), per-user rate limits,
  server notices, consent tracking and retention policies.
- **Synapse's configuration.** Configure Continuwuity yourself.

If a recreated room once had users from other servers, it keeps its ID and the
report warns about it: if one of those servers rejoins, it may reject the
recreated room.

For test commands and compatibility workarounds, see the [development notes](docs/development.md).

## License

[Apache-2.0](LICENSE)
