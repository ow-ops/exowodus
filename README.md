# exodus

Migrate a Matrix homeserver from Synapse to [Continuwuity](https://continuwuity.org),
or move a single account from any homeserver (including matrix.org). Continuwuity
itself is not modified.

Continuwuity cannot read a Synapse database, so exodus works through the Matrix,
Synapse admin and Matrix Authentication Service (MAS) APIs, plus read-only
database access for what no API exposes. Client and federation requests use
[mautrix-go](https://github.com/mautrix/go).

## Build

Prebuilt binaries for Linux, macOS and Windows, with a `SHA256SUMS` file, are
attached to each release.

To build from source, you need Go 1.27:

```sh
go build -o exodus .
```

## Before you start

1. On a fresh Continuwuity, create **your own admin account first**: the first
   account created becomes the server admin.
2. Issue a registration token with `!admin token issue`.
3. Pass the admin's access token as `--to-admin-token`. It is needed for admin
   rights, account statuses, emails, recreated rooms, devices, bridges and
   server state. exodus temporarily registers an `exodus` appservice through
   the admin room and removes it when the import ends.

Good to know:

- **Retry failed steps with the same archive and destination.** Commands exit
  nonzero on failure. Check
  `exodus-archive/import-report.json` and the per-user reports under
  `exodus-archive/users/*/import-report.json` before cutover.
- **Incomplete exports cannot be imported.** Check
  `exodus-archive/export-report.json` and rerun `export`. Media download
  failures also fail the export. Pass `--skip-missing-media` to migrate
  accounts while omitting source media that returns HTTP 404.
- **The archive is sensitive.** It holds account data, encrypted key backups,
  password hashes, access tokens and generated passwords. Keep it safe, and
  retain it while you run the proxy or need archive-only room history.
- **Secrets can be passed as environment variables** instead of flags:

  | Variable                         | Flag                        |
  | -------------------------------- | --------------------------- |
  | `EXODUS_FROM_TOKEN`              | `--from-token`              |
  | `EXODUS_FROM_PASSWORD`           | `--from-password`           |
  | `EXODUS_FROM_ADMIN_TOKEN`        | `--from-admin-token`        |
  | `EXODUS_FROM_MAS_TOKEN`          | `--from-mas-token`          |
  | `EXODUS_SYNAPSE_DB`              | `--synapse-db`              |
  | `EXODUS_MAS_DB`                  | `--mas-db`                  |
  | `EXODUS_TO_TOKEN`                | `--to-token`                |
  | `EXODUS_TO_PASSWORD`             | `--to-password`             |
  | `EXODUS_TO_ADMIN_TOKEN`          | `--to-admin-token`          |
  | `EXODUS_REGISTRATION_TOKEN`      | `--registration-token`      |
  | `EXODUS_SYNAPSE_PASSWORD_PEPPER` | `--synapse-password-pepper` |
  | `EXODUS_SYNAPSE_MACAROON_SECRET` | `--synapse-macaroon-secret` |

## Usage

### Replacing Synapse on the same server name

This restores sessions, devices and encryption on the same server name.
Keep a source database and media backup. Before the final export, stop client,
bridge and federation writes to Synapse while leaving its APIs available to
exodus. Export reads APIs and database tables separately; it is not a consistent
snapshot while the source is changing. Route clients to the destination only
after import completes without failures.

```sh
exodus export --from https://example.org --from-admin-token "$ADMIN" --all-users \
  --synapse-db postgres://synapse@db/synapse

# stop Synapse, start Continuwuity with the same server_name

exodus import --to http://continuwuity:8008 --registration-token "$REG" --to-admin-token "$CADMIN" \
  --appservice-registration /etc/synapse/bridges/telegram.yaml

exodus proxy --upstream http://continuwuity:8008
```

Then route all client and federation traffic through `exodus proxy`, for
example by pointing your reverse proxy at it instead of Continuwuity. See
[The proxy](#the-proxy).

Rooms shared with other servers are rejoined through them. Continuwuity has a
new signing key, so it needs `trusted_servers` (default `matrix.org`) to fetch
your old key and verify your server's past events.

### Moving to a new server name

With the source server still online:

```sh
exodus migrate --from https://synapse.example.org --from-admin-token "$ADMIN" --all-users \
  --synapse-db postgres://synapse@db/synapse \
  --to https://continuwuity.example.net --registration-token "$REG" --to-admin-token "$CADMIN"

exodus proxy --upstream https://continuwuity.example.net   # password migration
exodus proxy --listen :8080   # behind the old domain's TLS reverse proxy, for old media links
```

Each old account invites its new account into every room with the same power
level, so all rooms, including invite-only and local-only ones, keep working
after the old server shuts down. The new account sees earlier history when the
room's history visibility allows it (`shared`, the default).

- `--users @a:example.org,@b:example.org` selects a subset of users.
- Accounts without a known password get a random one, written to
  `exodus-archive/credentials.csv`. The proxy replaces it with the old
  password on first login.

### Moving a single account

No admin access is needed, for example to leave matrix.org. Copy your access
token from Element (Settings → Help & About):

```sh
exodus migrate --from https://matrix-client.matrix.org --from-token "$TOKEN" \
  --to https://matrix.example.org --registration-token "$REG" --to-password "$NEW_PASSWORD"
```

### Synapse with MAS

Add `--from-mas-url` and `--from-mas-token`:

- `--from-mas-token` needs the `urn:mas:admin` scope.
- `--from-admin-token` must be a MAS personal token with `urn:synapse:admin:*`.

exodus impersonates users through MAS personal sessions and reads emails, SSO
links and registration tokens from MAS. Add `--mas-db` to also export
passwords and sessions:

- **Passwords:** pass the MAS configuration to the proxy (`--mas-config`) when
  a password scheme uses a `secret` or Unicode normalization.
- **Legacy sessions:** mapped like Synapse sessions.
- **OAuth 2.0 sessions:** clients refresh their tokens at MAS's token
  endpoint, so route `/oauth2/token` on the MAS domain to the proxy. It answers
  these refreshes with the migrated device's session.

### SSO users

Enabling OIDC on Continuwuity disables the password logins the import relies
on, but linking identities requires OIDC. So, in order:

1. Run the import.
2. Configure `[global.oauth.oidc]` on Continuwuity.
3. Run `exodus link-sso --to ... --to-admin-token ...`.

## The proxy

`exodus proxy` sits in front of Continuwuity and keeps old credentials and
links working:

| What                | How                                                                                                                                                                                                                    |
| ------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Sessions            | Old Synapse access and refresh tokens are swapped for sessions on the same devices, so users stay logged in with encryption intact.                                                                                    |
| Passwords           | A user's first password login is checked against the old hash, then the password is set on Continuwuity. Supports Synapse bcrypt, and MAS argon2, PBKDF2 and bcrypt, with or without a secret.                         |
| Media               | Old media IDs are served from the archive, over the client and federation media APIs.                                                                                                                                  |
| Guests              | Synapse guest tokens are macaroons Synapse never stored. Pass `--synapse-macaroon-secret` (Synapse's `macaroon_secret_key`, or `registration_shared_secret` if unset), or `--synapse-signing-key` when neither is set. |
| Registration tokens | Old tokens are swapped for the ones issued on import.                                                                                                                                                                  |
| Shadow bans         | Continuwuity has none, so the proxy answers shadow-banned users' messages, state changes and invites as if they succeeded, without sending them.                                                                       |

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

exodus hands the rooms over with their **original events**: event IDs,
signatures, senders and timestamps are unchanged. Requires
`export --synapse-db --synapse-signing-key` and `import --to-admin-token`.

During the import, exodus runs a temporary federation server under that name
(`--relay-listen`, default `:8448`) that serves the exported events:

1. An original member invites the relay's member, signed with your old server
   key, and the relay joins.
2. A migrated member joins through the relay, and Continuwuity backfills the
   whole history from it.
3. The migrated member removes the relay's member, leaving the room only on
   Continuwuity.

Requirements:

- Continuwuity must reach the relay over federation.
- Add the relay to Continuwuity's `trusted_servers`, since it also serves your
  old server's key.
- The relay uses a self-signed certificate unless you pass `--relay-tls-cert`
  and `--relay-tls-key`. Continuwuity only accepts a self-signed one with
  `allow_invalid_tls_certificates_yes_i_know_what_the_fuck_i_am_doing_with_this_and_i_know_this_is_insecure`.

The relay stays in the room until all exported events are backfilled and room
restoration succeeds. Incomplete backfill fails the import; retry with the same
archive and relay configuration.

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
  by their origin server, and exodus cannot sign as another server. `@exodus`
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

## Quirks handled

- **Federated invites.** Continuwuity currently rejects federated invites from
  Synapse, which still sends stripped `invite_room_state`. New accounts are
  invited locally by an already migrated member instead. If there is none, the
  old account briefly makes the room public, the new account joins, and the
  join rules are restored.
- **Federated knocks.** Continuwuity currently fails while processing the knock
  state Synapse returns, after the knock has reached the room. The import
  reports the error and exits nonzero; the knock stays pending on the room's
  side.
- **Master keys without signatures.** Continuwuity only records other users'
  signatures on master keys that have a `signatures` field, so exodus adds one
  before uploading.

## Tests

```sh
go test ./...                                              # unit tests
./e2e/up.sh && go test -tags e2e ./e2e/; ./e2e/down.sh     # Synapse, MAS and Continuwuity in Docker
```

The end-to-end suite covers same-server replacement, a new server name (with
and without the relay), single users, MAS-backed Synapse, bridges and the
proxy. Encryption tests use the original recovery key to restore the backup
and decrypt a Megolm message after relay, replay and new-server migration.
Unit tests inject failures and verify retries for events, keys, room data and
pushers.

## License

[Apache-2.0](LICENSE)
