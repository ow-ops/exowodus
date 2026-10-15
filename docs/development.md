# Development

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
