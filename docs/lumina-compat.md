# Lumina reference parity

Decisions taken while aligning dazhbog with the behaviour of the Hex-Rays
Lumina server as observed on the wire. Byte-level fixtures captured from that
server live in `tests/lumina_fixtures.rs`.

| Topic | Behaviour |
|---|---|
| Varints | `pack_dd` uses the reference widths (2 bytes to `0x3FFF`, 4 bytes to `0x1FFFFFFF`, `0xFF` escape above); decode treats any lead byte `0xE0..=0xFF` as the 5-byte form. `index_t` is `dd(x + 1)`. |
| Hello | Versions above 6 get `rpc_fail(-1, "This server doesn't support version N")`. Empty or `guest` usernames are accepted (`lumina.accept_any_username` accepts all). Malformed hellos are answered in Lumina framing. |
| Pull codes | One code per pattern: `-3` for a non-MD5 or non-16-byte pattern (no lookup), `-2` not found, `0` found. Over-cap requests are refused with `rpc_fail`, never truncated. |
| `size` field | The pushed `func_info_t.size` is stored in `Record.len_bytes` with flag `0x02` and returned on pull and `get_pop`. Records written before this change carry the metadata length there (flag clear); the value cannot be recovered. |
| Frequency | A per-key pull counter (`context_db/pull_freq`) mirrors `func_freqs.counter`: returned before the increment, bumped once per occurrence in the request unless `PULL_MD_SEEN_FILE` (`0x2`) is set. Pushes never bump it. |
| Push | Whole-request failures use the reference strings (`Bad IDB`, `Bad input file path`, `Bad hostname`, `Bad addresses count`, `Invalid metadata` for BADADDR, non-ASCII names or metadata keys outside `1..12`). Per entry: `-3` bad pattern, `1` new, `0` updated or unchanged. `PMF_PUSH_DO_NOT_OVERRIDE` records only the binary observation; other modes append a version and let selection decide. |
| Histories | `pattern_idx_to_entries_idx[i]` is the index into the histories vector or `-1`. Metadata is only included with `BOPF_DETAILS`. Authors and IDB paths are not disclosed (`-1`, empty pools), matching lumina.hex-rays.com. Enabled by default (`lumina.get_history_limit = 128`). |
| Delete | `del_history` parses `filters_t`; only `calcrel_hashes` selectors are supported. With `BOPF_LAST_FUNC_RECORD` (what IDA sends) the last change of each function is undone: the previous version is re-appended as the head and the undone version leaves the chain, so repeated undos walk back through history and finally tombstone the key. Without the flag the key is tombstoned. `ndeleted` counts keys that had a live head. Requires `lumina.allow_deletes`; otherwise `rpc_fail(-1, "Unknown command")`. |
| `get_pop` | Capped at 100. Sends the 16-byte pattern (type 0, as the reference does), the pull frequency, the first observed binary's basename, hostname and MD5, and `BADADDR` for the address. |
| Names | Reference rejects no names. dazhbog defaults to `lumina.name_rejection = "prefixes"`; see `AGENTS.md` for the rules. |
| Not implemented | Admin packets, telemetry, cloud decompilation, license validation, per-user accounts. Unknown packets get `rpc_fail(-1, "Unhandled packet type: N")`. |
