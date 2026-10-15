# Tuwunel database export

Use separate `export` and `import` commands with the same `server_name` and a
[relay](../README.md#relay---relay-name). Omit `--to-password` and `--to-token`;
the proxy needs generated credentials to restore source passwords.

Pause client, bridge and federation writes before taking a database backup or
checkpoint. Leave Tuwunel's APIs available for export and keep writes paused
until cutover. Run a compatible RocksDB
[ldb tool](https://github.com/facebook/rocksdb/wiki/Administration-and-Data-Access-Tool)
against the backup, never the live database.

Create one hex scan per table, starting with the password and token tables:

```sh
mkdir -m 700 tuwunel-dump
umask 077
ldb --db=/backup/tuwunel --column_family=userid_password scan --hex \
  > tuwunel-dump/userid_password.txt
ldb --db=/backup/tuwunel --column_family=token_userdeviceid scan --hex \
  > tuwunel-dump/token_userdeviceid.txt
ldb --db=/backup/tuwunel --column_family=userdeviceid_refresh scan --hex \
  > tuwunel-dump/userdeviceid_refresh.txt
```

Check that each scan succeeds. Older databases without refresh tokens do not
need `userdeviceid_refresh.txt`. Expired tokens and superseded refresh tokens
are excluded. Protect the dump: it contains password hashes and bearer tokens.

Export the remaining tables with the same command, replacing `NAME`:

```sh
ldb --db=/backup/tuwunel --column_family=NAME scan --hex \
  > tuwunel-dump/NAME.txt
```

| Table | Data |
| --- | --- |
| `userdeviceid_metadata` | Device IDs, including devices without active tokens |
| `onetimekeyid4225_otk` | One-time keys on current Tuwunel |
| `onetimekeyid_onetimekeys` | One-time keys on older Conduit-lineage schemas |
| `userdeviceidalgorithm_fallback` | Unused fallback keys on current Tuwunel |
| `senderkey_pusher` and `pushkey_deviceid` | Push notifications and their device bindings (both files required) |
| `todeviceid_events` | Queued device messages |
| `bannedroomids` | Banned rooms |
| `alias_roomid` | Local aliases, including aliases outside joined rooms |
| `mediaid_file`, `mediaid_lazy`, `mediaid_lazycontent` | Stored media, including files without uploader metadata |
| `readreceiptid_readreceipt`, `roomuserid_privateread` | Unsupported receipt checks |
| `servercurrentevent_data`, `servernameevent_data` | Pending deliveries; drain before cutover |

Include empty scans for current-schema tables. The older one-time-key table
applies only to legacy databases. Used fallback keys are excluded.

Tuwunel must provide the [Synapse-compatible admin endpoints](https://github.com/matrix-construct/tuwunel/blob/main/docs/development/compliance/synapse-admin.md)
used by export. If you renamed the `conduit` server bot, pass its localpart with
`--tuwunel-server-user`. Native dumps cannot be combined with MAS authentication.

## Original events and strict cutover checks

Original-event transfer also reads these hex scans from the same checkpoint:
`global`, `server_signingkeys`, `pduid_pdu`, `eventid_outlierpdu`,
`shorteventid_eventid`, `shortstatekey_statekey`,
`shorteventid_shortstatehash`, `roomid_shortstatehash`,
`shortstatehash_statediff`, and `roomid_pduleaves`.
The `global` scan contains the server's private signing key. Protect it along
with the password and token scans.

```sh
exodus export --from https://example.org --from-type tuwunel \
  --from-admin-token "$ADMIN" --all-users --tuwunel-dump ./tuwunel-dump

# Stop Tuwunel and prepare Continuwuity on the same server_name.
exodus import --to http://continuwuity:8008 --to-admin-token "$CADMIN" \
  --registration-token "$REG" --relay-name relay.example.net

exodus proxy --upstream http://continuwuity:8008
```

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
