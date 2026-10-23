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
  userdeviceid_refresh onetimekeyid4225_otk onetimekeyid_onetimekeys
do
  case "$table" in
    userdeviceid_refresh|onetimekeyid4225_otk|onetimekeyid_onetimekeys)
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
and retry with a new `OUT` directory. Missing refresh-token and legacy
one-time-key tables are skipped; empty tables are kept.

Keep the dump private: it contains password hashes, login tokens and the server
signing key. Drain pending outbound deliveries before cutover. Exodus excludes
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

Keep dump files unchanged during export. Original event bodies stream from
these files. Room state and event indexes still use RAM.

Export downloads local uploads through the authenticated media API. Remote
media, including cached files and remote avatars, is skipped. Those files
depend on their original servers remaining available after migration.
`allow_legacy_media` is not needed. Missing local media still fails the export.
The archive records this policy as `skipped_remote_media` in `server.json`, and
import reports it as a note.

Backfilled events without historical state are retained. State queries for
those events return an error. New exports use archive format 2 and require
an updated Exodus for import. Format 1 archives remain readable.

To resume a whole-server Tuwunel export, rerun the same command with the same
archive and unchanged dump. Keep source writes paused between attempts. Exodus
verifies completed accounts, rooms and media against `export-progress/` before
reuse. A changed source, dump or account selection requires a new `--archive`
directory.

Failed rooms reuse completed API history and retry the remaining steps,
including preservation checks. Interrupted history downloads restart that
room's history. Older partial archives can reuse histories after their retained
dump and events are verified; other steps run once to create checkpoints.

If the source changes, pause writes, back up the database and extract all tables
into a new dump directory. Export to a new `--archive` directory. Keep the old
archive and its retained dump unchanged.

Whole-server migration requires these scans, even for empty tables. Export
checks the database timeline against the API. Import checks original event IDs,
content, senders and timestamps, and verifies destination sessions. It does not
fall back to replaying messages.

Import blocks these known unsupported cases:

- Private receipts on backfilled events and per-thread receipts.
- Undelivered messages from remote senders and pending outbound deliveries.
- Rooms without joined local users.
- Deactivated accounts and accounts with multiple email addresses.

Moderation reports, older fallback-key formats and disabled-room settings are
not restored. Unknown source features may also require separate handling.
All supplied scans are kept under `source/tuwunel/` in the archive.

Failed backfill, knock and read-marker steps appear in `import-report.json`.
Rerun import with the same archive and relay settings to retry. Keep the archive
and proxy running to serve existing logins and original media URLs.
