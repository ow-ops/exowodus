# Tuwunel database export

Use separate `export` and `import` commands with the same `server_name` and a
[relay](../README.md#relay---relay-name). Omit `--to-password` and `--to-token`;
the proxy needs generated credentials to restore source passwords.

Pause client, bridge and federation writes before taking a database backup or
checkpoint. Leave Tuwunel's APIs available for export and keep writes paused
until cutover. Run a compatible RocksDB
[ldb tool](https://github.com/facebook/rocksdb/wiki/Administration-and-Data-Access-Tool)
against the backup, never the live database.

Set `DB` to your database backup and `LDB` to your RocksDB tool
(`rocksdb_ldb` on Homebrew). Run from your migration directory.
`OUT` must not already exist.

```sh
(
set -eu
umask 077
DB=/backup/tuwunel
LDB=ldb
OUT=./tuwunel-dump

families=$("$LDB" --db="$DB" list_column_families)
available=$(printf '%s\n' "$families" | sed -n 's/^{\(.*\)}$/\1/p' | tr ',' '\n' | sed 's/^ *//;s/ *$//')
[ -n "$available" ] || { echo "Could not list database tables" >&2; exit 1; }
mkdir -m 700 "$OUT"

for table in \
  userid_password token_userdeviceid userdeviceid_metadata \
  userdeviceidalgorithm_fallback senderkey_pusher pushkey_deviceid \
  todeviceid_events bannedroomids alias_roomid \
  mediaid_file mediaid_lazy mediaid_lazycontent \
  readreceiptid_readreceipt roomuserid_privateread \
  servercurrentevent_data servernameevent_data \
  global server_signingkeys pduid_pdu eventid_outlierpdu \
  shorteventid_eventid shortstatekey_statekey shorteventid_shortstatehash \
  roomid_shortstatehash shortstatehash_statediff roomid_pduleaves \
  userdeviceid_refresh onetimekeyid4225_otk onetimekeyid_onetimekeys \
  id_appserviceregistrations
do
  case "$table" in
    userdeviceid_refresh|onetimekeyid4225_otk|onetimekeyid_onetimekeys|id_appserviceregistrations)
      if ! printf '%s\n' "$available" | grep -Fxq "$table"; then
        continue
      fi
      ;;
  esac
  echo "Extracting $table" >&2
  "$LDB" --db="$DB" --column_family="$table" scan --hex > "$OUT/$table.txt.part"
  mv "$OUT/$table.txt.part" "$OUT/$table.txt"
done

if [ ! -f "$OUT/onetimekeyid4225_otk.txt" ] && [ ! -f "$OUT/onetimekeyid_onetimekeys.txt" ]; then
  echo "Missing one-time-key table; extraction incomplete" >&2
  exit 1
fi
echo "Extraction complete: $OUT" >&2
)
```

If a scan fails, the command stops and leaves a `.part` file. Fix the error
and retry with a new `OUT` directory. Missing refresh-token, legacy one-time-key
and appservice tables are skipped; empty tables are kept.

Whole-server export skips bridge ghosts identified by exclusive namespaces in
`id_appserviceregistrations.txt`. Accounts with saved passwords, tokens or device
data, bridge bots and admins are kept. Import restores the registrations on the
same server name. Back up each bridge's database and configuration separately.
Registrations loaded only from Tuwunel's configuration are absent from this scan.
Queued device messages from local bridge users are sent through their owning
appservice; remote senders' messages are delivered by the proxy.

For an existing dump, extract this table from the same database backup:

```sh
(
set -eu
umask 077
DB=/backup/tuwunel
LDB=ldb
OUT=./tuwunel-dump

"$LDB" --db="$DB" --column_family=id_appserviceregistrations scan --hex > "$OUT/id_appserviceregistrations.txt.part"
mv "$OUT/id_appserviceregistrations.txt.part" "$OUT/id_appserviceregistrations.txt"
)
```

Adding a scan changes the dump; use a new `--archive` directory.

Export reads Tuwunel schema version 17, used from v1.5 through v1.9.4, from
`global.txt` and refuses other versions.

Keep the dump private: it contains password hashes, login tokens and the server
signing key. Pending federation deliveries can be retained for proxy retry as
described below. Exodus excludes
expired tokens, superseded refresh tokens and used fallback keys.

Tuwunel must provide the [Synapse-compatible admin endpoints](https://github.com/matrix-construct/tuwunel/blob/main/docs/development/compliance/synapse-admin.md)
used by export. If you renamed the `conduit` server bot, pass its localpart with
`--tuwunel-server-user`. Native dumps cannot be combined with MAS authentication.

## Original events and strict cutover checks

```sh
exodus export --from https://example.org --from-type tuwunel \
  --from-admin-token "$ADMIN" --all-users --tuwunel-dump ./tuwunel-dump

# Stop Tuwunel and prepare Continuwuity on the same server_name.
exodus import --to http://continuwuity:8008 --to-admin-token "$CADMIN" \
  --registration-token "$REG" --relay-name relay.example.net

exodus proxy --upstream http://continuwuity:8008
```

Import checks destination login methods and username compatibility before creating
accounts. With `--to-admin-token`, ordinary registration requests authenticate
through the temporary migration appservice, so public registration can stay
disabled on current Continuwuity.
The configured registration-token flow still applies. Legacy login APIs must be
available; delegated `[global.oauth.oidc]` forces OAuth-exclusive mode and blocks
the appservice logins needed to restore devices.

If an earlier attempt created a passwordless account but failed before recording
ownership, confirm that the destination account belongs to that attempt, then
add `--adopt-existing-user` to the same import command:

```sh
exodus import --to http://continuwuity:8008 --to-admin-token "$CADMIN" \
  --registration-token "$REG" --relay-name relay.example.net \
  --adopt-existing-user '@bridgebot:example.org'
```

This restores the account's data from the archive and may overwrite changes made
on the destination. It requires the original server name and applies only to
passwordless, guest or ID-only accounts. Existing accounts are refused by default.

For an existing account with a password, verify its destination login before
retrying import:

```sh
exodus recover-login --archive ./exodus-archive \
  --to https://matrix.example.org --user '@alice:example.org'
```

Stop import first. The command prompts without echoing the password and saves
the verified login in the private archive. It does not recreate the account or
change its password, profile or rooms. The proxy can restore the source
password on first login. Rerun import with the same archive afterward.

If recovery says the user cannot log in with a password, the destination account
is a passwordless shadow account. In the Continuwuity admin room, run:

```text
!admin users reset-password --convert-to-local-account @alice:example.org
```

Use the generated password returned by the bot in `recover-login`. Omit
`--logout` to preserve existing devices and sessions.

Keep dump files unchanged during export. Original event bodies stream from
these files. Room state and event indexes still use RAM.

Export downloads local uploads through the authenticated media API. Remote
media, including cached files and remote avatars, is skipped. Those files
depend on their original servers remaining available after migration.
Remote avatar URLs are retained in profiles without downloading their files.
`allow_legacy_media` is not needed. Missing local media still fails the export.
The archive records this policy as `skipped_remote_media` in `server.json`, and
import reports it as a note.

Backfilled events without historical state are retained. State queries for
those events return an error. Archive format 3 stores state deletions as deltas.
Update Exodus for export, import and proxy; formats 1 and 2 remain readable.

Room exports include accepted events, referenced state and their auth chains.
Unused outliers remain in the retained database scans. Missing auth dependencies
and invalid IDs of required events still block export.

To resume a whole-server Tuwunel export, rerun the same command with the same
archive and unchanged dump. Keep source writes paused between attempts. Exodus
verifies completed accounts, rooms and media against `export-progress/` before
reuse. A changed source, dump or account selection requires a new `--archive`
directory.

Failed rooms reuse completed API history and retry the remaining steps,
including preservation checks. Interrupted history downloads restart that
room's history. Older partial archives can reuse histories after their retained
dump and events are verified; other steps run once to create checkpoints.

Errors before export starts leave `export-report.json` unchanged. Use the
terminal error for that attempt; the report may describe an earlier run.

If the source changes, pause writes, back up the database and extract all tables
into a new dump directory. Export to a new `--archive` directory. Keep the old
archive and its retained dump unchanged.

To export room history and state from the backup, use `--history-at-checkpoint`
with a new archive:

```sh
exodus export --from https://example.org --from-type tuwunel \
  --from-admin-token "$ADMIN" --all-users --tuwunel-dump ./tuwunel-dump \
  --history-at-checkpoint --archive ./exodus-checkpoint
```

This omits later messages, redactions, membership changes and rooms absent from
the checkpoint. Read markers pointing outside its timeline are also omitted.
Account data and directory visibility still come from the API. Account, device,
event-ID and auth checks remain enabled; missing required auth events block export.

Invalid `org.matrix.dummy_event` events are omitted only when they have no state
key and are unused by room state, auth checks or room heads. Their IDs and failure reasons
are recorded in `room.json` and the import report. Other events keep their
original IDs and contents; backfill can traverse the omitted events' predecessors.

Some servers have sent dummy events whose `content` is a string or `null`.
Exodus computes their IDs as Tuwunel and Continuwuity do, so these events are
kept. Archives exported by earlier versions omit them; export again to a new
`--archive` directory to keep them.

Pause writes for cutover and keep the original backup. `server.json` records
`history_at_checkpoint`, and import reports it as a note. Resume with the same
flag, archive and unchanged dump.

When an auth event is missing from the dump, export tries other servers in the
room using the source signing key. It verifies the event's ID, room, signatures
and content hash. Content with a failed hash is redacted under the room version's
rules. Verified events and signing keys are cached in the archive and reused on
retry. Recovery adds auth dependencies; it does not add newer timeline messages
or change the dump. Each server attempt has a 15-second timeout.

If no server supplies the event, export fails. To omit an affected room entirely,
repeat the export command with `--skip-room`:

```sh
exodus export --from https://example.org --from-type tuwunel \
  --from-admin-token "$ADMIN" --all-users --tuwunel-dump ./tuwunel-dump \
  --history-at-checkpoint --archive ./exodus-checkpoint \
  --skip-room '!broken:example.org'
```

Repeat `--skip-room` for each excluded room. Keep the same dump, archive and
other flags to reuse completed exports. Skipped room IDs are recorded in
`manifest.json`, `export-report.json` and the import report. Import omits their
history, membership, receipts, room account data and aliases. Removing a
`--skip-room` option on a later export includes that room again. Use the updated
binary for import as well; new archives use format version 8.

Whole-server migration requires these scans, even for empty tables. Export
checks the database timeline against the API unless `--history-at-checkpoint` is
set. Import checks original event IDs, content, senders and timestamps, and
verifies destination sessions. It does not fall back to replaying messages.

Import blocks these cases unless the corresponding import option is supplied:

- `--skip-private-receipts` omits private read positions.
- `--skip-threaded-receipts` omits per-thread read positions. For older Tuwunel
  archives, room-wide receipts are read from the retained dump so a thread's
  position is not applied to the whole room.
- `--archive-departed-rooms` keeps rooms with no joined local users in the archive
  only, including their history and media.
- `--deactivated-id-only` recreates deactivated IDs without their old account data.
  Accounts with saved logins, devices or encryption keys still block import.

Registered bridge ghosts without login or device data are handled through their
appservice registration. Existing archives are checked against the retained dump;
user-name prefixes are not used to identify bridge accounts.

Tuwunel's admin API reports every account with an empty password as
deactivated. Export reads the dump instead: accounts with an empty password
and live devices are exported as passwordless accounts, because deactivation
removes all devices first.

Archives exported by older Exodus versions may still list these accounts as
deactivated. If import refuses ID-only restoration for such an account, export
again to a new `--archive` directory, or recover its missing account data from
the **original database backup used for the dump**:

```sh
exodus repair-tuwunel-accounts --archive ./exodus-archive \
  --database /backup/tuwunel --ldb /path/to/ldb
```

For a registered bridge bot with no devices, add `--include-appservice-senders`
only if it should be active. Tuwunel uses empty passwords for both bridge bots
and deactivated accounts.

Stop export and import commands first. Recovery reads the backup without
changing it and checks passwords, tokens, devices and signing data against
the retained dump. It uses the archived appservice registrations.
It checks all required table names before scanning account data and reports
missing tables together.

Passwordless accounts with live devices are restored with their device keys,
tokens, cross-signing keys, account data and latest encrypted key backup. The
existing room histories and media are reused. Accounts whose import has already
started are refused. Recovery inputs are retained in a private
`.tuwunel-account-repair-*-saved` directory in the archive. Account recovery is
limited to 32 MiB of source records per account.

Prekeys left behind for deleted devices do not create new devices or block
ID-only restoration. Their original rows remain in the retained dump.

These cases remain unsupported:

- Pending appservice and push deliveries.
- Accounts with multiple email addresses.

Moderation reports, older fallback-key formats and disabled-room settings are
not restored. Unknown source features may also require separate handling.
All supplied scans are kept under `source/tuwunel/` in the archive.

Failed backfill, knock and read-marker steps appear in `import-report.json`.
Rerun import with the same archive and relay settings to retry. Keep the archive
and proxy running to serve existing logins and original media URLs.

Import logs each final step: server data, pending invites, session verification
and report writing. Canceling at this stage skips remaining checks and saves an
incomplete report. Unchecked sessions are not reported as invalid. Session cleanup
has a 30-second limit. The relay stops when import exits, so test it while import
is running.

Continuwuity keeps its existing `#admins` alias. The report records the source
admin room ID; its history follows the normal room import path. Other alias
conflicts remain failures.

Import loads one relay room at a time and releases it after each attempt.
Event bodies stay in the archive and are read when served; the relay keeps
about 300 bytes per event plus the room's state. Verification streams the
archived messages, and key backups upload one session at a time. Continuwuity
uses memory separately: backfilling a large room can use more than Exodus does.

Key backups are restored after rooms. Import reuses the current destination
backup when its algorithm and encryption key match the archive. It retains the
destination's signatures and uses per-session uploads so Continuwuity keeps
better existing keys. A new version is created only when the account has no
backup. Matching version changes are retried without creating another version.

Normal client activity does not require pausing for this backup step. If the
recovery keys differ, backup restoration fails without blocking room import.
The report retains the failure and migration remains incomplete. Existing
backups and the archived keys are retained. Configure that account's key backup
with the source recovery key before retrying. Repeated version rejections also
appear in the report; check the destination backup or pause automatic key backup
for the affected account. Rerun import with the same archive to retry the backup
without repeating completed room writes.

On Linux with systemd, this example caps Exodus at 1 GiB. Adjust the limit to
leave room for Continuwuity and the rest of the system:

```sh
GOMEMLIMIT=512MiB systemd-run --user --scope --expand-environment=no \
  -p MemoryHigh=768M -p MemoryMax=1G -p MemorySwapMax=256M \
  exodus import --archive ./exodus-archive \
  --to http://continuwuity:8008 --to-admin-token "$CADMIN" \
  --registration-token "$REG" --relay-name relay.example.net \
  --skip-private-receipts --skip-threaded-receipts \
  --archive-departed-rooms --deactivated-id-only
```

[`MemoryMax`](https://www.freedesktop.org/software/systemd/man/latest/systemd.resource-control.html#MemoryMax=bytes)
limits the importer process group. The kernel may terminate Exodus at this
limit; rerun with the same archive to retry. `GOMEMLIMIT` is a soft limit.
Limit Continuwuity separately.

Queued to-device messages from remote senders stay in the archive. The proxy
delivers them to the original recipient and device through sync, up to 100 per
response. It saves acknowledgements under `proxy-inbox/` and retries unacknowledged
messages after a restart. Run one proxy process per archive and keep that directory
with the archive. Both classic sync and sliding sync are supported. Use the updated
binary for import and proxy; existing archives do not need a new export.

## Relay behind Traefik

When Traefik runs on a Docker bridge network and Exodus runs on the host,
`127.0.0.1` points inside the Traefik container. Use the Pi's LAN address for
the upstream. Merge this into Traefik's dynamic file configuration, replacing
`PI_LAN_IP` and the example domain:

```yaml
http:
  routers:
    relay:
      entryPoints:
        - websecure
      rule: Host(`relay.example.net`)
      service: relay
  services:
    relay:
      loadBalancer:
        serversTransport: relay
        servers:
          - url: "https://PI_LAN_IP:8448"
  serversTransports:
    relay:
      insecureSkipVerify: true
```

The relay transport skips verification of Exodus's default self-signed backend
certificate. Public HTTPS still uses Traefik's trusted certificate. This setting
applies only to the relay service; see [Traefik's transport documentation](https://doc.traefik.io/traefik/reference/routing-configuration/http/load-balancing/serverstransport).

For public port 443, use `--relay-name relay.example.net:443` and
`--relay-listen 0.0.0.0:8448`. The explicit port avoids requiring
`/.well-known/matrix/server`, which Exodus does not serve. Add the relay name and
port to Continuwuity's existing `trusted_servers` list in `[global]`:

```toml
trusted_servers = ["matrix.org", "relay.example.net:443"]
```

Keep existing trusted servers. Apply the configuration, then start import. While
import runs, this must return keys with `server_name` set to `relay.example.net:443`:

```sh
curl -fsS https://relay.example.net/_matrix/key/v2/server
```

Unchanged user IDs use this trusted relay for backfill without a power-level
change. Room admission rules still apply: the relay must have a valid invitation
or be allowed to join directly. Rooms with federation disabled cannot use the
relay. The relay leaves through its own signed federation event after history
verification and membership restoration.

## Pending federation deliveries

The proxy can retry the outgoing federation queue from the retained dump. It
preserves original PDU IDs and EDU payloads, including device-list updates and
receipts. Expired typing notifications are omitted. Import verifies queued PDU
IDs before making the queue available to the proxy.

Continuwuity must use the original server signing key. Stop Continuwuity, then
run this as the database owner with a compatible `ldb`:

```sh
exodus restore-signing-key --archive ./exodus-archive \
  --database /path/to/continuwuity-database --ldb /absolute/path/to/ldb
```

The command backs up the current key to
`exodus-archive/continuwuity-signing-key-backup.txt` before replacing it. Private
key material is passed to `ldb` through stdin. It also writes
`exodus-archive/continuwuity-old-verify-key.toml`; merge that entry into the
Continuwuity configuration so events already signed by its previous key remain
verifiable. Then restart Continuwuity.

Run the command as the database owner. A read-only `get` can succeed even when
that user cannot write the database directory. If the database is owned by root,
use `sudo` with absolute paths for the executable, archive, database and `--ldb`.

Old messages keep their original `mxc://` links, which Continuwuity does not
know after import. To serve them without the proxy, stop Continuwuity and run:

```sh
exodus restore-media --archive ./exodus-archive \
  --database /path/to/continuwuity-database --ldb /absolute/path/to/ldb
```

It stores each archived local upload under its original ID and leaves IDs
Continuwuity already has unchanged; rerunning it is safe. Remote media is not
restored. `ldb` must come from the RocksDB version Continuwuity uses (11.x for
Continuwuity 26.9); older tools can read the database but cannot write to it.

Old access tokens and passwords also work only through the proxy. To keep
clients logged in without it, stop Continuwuity and the proxy and run:

```sh
exodus restore-sessions --archive ./exodus-archive \
  --database /path/to/continuwuity-database --ldb /absolute/path/to/ldb
```

Each device gets its Tuwunel access token back and the token import created for
it stops working. Users log in with their Tuwunel password again. Devices whose
token changed since the import, guests and refresh tokens are left to the
proxy; the command reports how many. Rerunning it is safe.

To accept these metadata limitations, import with:

```sh
exodus import --archive ./exodus-archive \
  --to http://continuwuity:8008 --to-admin-token "$CADMIN" \
  --registration-token "$REG" --relay-name relay.example.net \
  --skip-private-receipts --skip-threaded-receipts \
  --archive-departed-rooms --deactivated-id-only

exodus proxy --archive ./exodus-archive --upstream http://continuwuity:8008
```

Import prepares `federation-outbox.sqlite` once by scanning the retained PDU
tables. It stores payloads on disk and reuses the prepared queue on retry; no new
dump or export is needed. Keep the SQLite file with the archive. The proxy sends
one transaction at a time, with up to 50 entries and a 512 KiB batch target. A
larger individual event is sent alone. Failed destinations back off independently.
Network retries keep the same transaction ID, and PDU processing errors retain
the batch for retry. Logs report the remaining delivery count.
