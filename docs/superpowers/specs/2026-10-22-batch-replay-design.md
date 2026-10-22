# Versions that match the monitored tree after every batch (0.43)

## Intent

Each version is meant to hold exactly what the monitored tree held when it was taken. A batch is turned into a version in three steps:

1. `change_events_to_backup_entries` collapses the batch's watcher events, keyed by path, to at most one entry per path.
2. `do_reverb_backup` makes the new version as a referenced copy of the latest one: folders are real, and unchanged files are links back to it.
3. It then replays the entries onto that copy.

The round 7 investigation, a builder's check and a read-only audit of the live vaults showed that this misses in many ordinary sequences. One entry per path cannot record every interleaving of moves, re-creations and deletes, and the watcher queues a folder's move-out delete late. Each wrong version stays wrong; only a full comparison at a later restart repairs the latest version.

The fix in this round does not try to make the collapse exact. **The batch's events say where to look; a comparison says what changed.** After the replay, every place the batch touched is compared with the monitored tree, and what differs is fixed in the same, still uncommitted version.

### Sequences that give a wrong version today

All of these were reproduced with the real watcher, collapse and backup, except where marked "reasoned".

| Case | Operations in one batch | Wrong result |
|---|---|---|
| a, d4, d6, d7 | `mv D out; mkdir D` (or a move-in, a subfolder, `mkdir -p D/sub`) | D's old children stay, in the version and the manifest |
| c | `mv D out; mv E D` | D's old children stay, in the version folder only, after an ERROR and a delete-and-copy fallback |
| f1 | `mv D D2; rm D2/old.txt` | D2/old.txt stays |
| e1 | `mv f f~; write f` (an editor's rename-save) | f is missing, and f~ holds the new bytes |
| e2 | `mv f f~; write f; rm f~` (vim's save) | f is missing, and the change list says it was deleted |
| e3 | `mv D D2; mkdir D; D/new.txt; rm -rf D2` | D is missing |
| e4 | `mv D D.old; mv D.new D; rm -rf D.old` (an atomic swap) | D is missing, and D.new stays |
| d5 | `mv D D2; mkdir D; D/new.txt` | D is missing, and D2 holds new.txt |
| f3 | `echo x > D/new.txt; mv D D2` | D2/new.txt is missing |
| f5 | `echo changed > D/old.txt; mv D D2` | D2/old.txt holds the old bytes |
| git | `X.lock` renamed over an existing X, then X deleted (`git branch -D`) | X stays. **Live now:** two refs in the work job's vault |
| swap | `mv a a.tmp; mv b a; mv a.tmp b` | a is missing, and b holds the old b |
| loop | `mv D D2; mv D2 D` | the backup raises FileNotFoundError, and the batch goes back to the queue |
| chain | `mv a b; echo more >> b; mv b c` | a stays |
| late delete | `mv D/old.txt <outside>; mv D D2` | D2/old.txt stays (reasoned, from the watcher's late queueing) |

The reproductions are in the session scratchpad, `r7/`: `investigation.md`, `repro_*.py`, `check/` and `audit/`.

## Goals

1. **Verify what the batch touched.** After the replay, `do_reverb_backup` compares every touched scope of the monitored tree with the new version, and fixes the new version where they differ.
   - **The scopes** are every path named by the batch's raw events, before the collapse: each event's path, and the source of each move.
     - A folder create, delete or move covers its whole subtree.
     - An attribute change or modify on a folder covers only that folder: a `chmod`, `touch` or `setfattr` on D must not walk D.
     - A file covers just that path.
     - A scope nested inside another is covered once.
     - `scan`, `full_scan` and `self_destruct` events are left out. Scans were already compared before the replay, and the other two name the root.
   - **The comparison** reuses the core of the existing scoped comparison, the one a full comparison and an inner-mount scan use (`delta_generate_backup_entries` with a scope), with three changes. As written, that function begins, may rebuild, commits and reads the committed version: it would commit the replay's rows early, and rebuild could wipe the job's rows.
     - It runs inside the open transaction, against the manifest rows as the replay left them, with no begin, rebuild, commit or rollback of its own.
     - Where it reads the vault, it reads `backup_folder`, the new version.
     - It handles all scopes in one pass: one manifest prefetch and one pool per batch, not one per scope.
   - **It gives create, delete and modify entries for what differs,** for presence, kind and content only. Attribute-only differences (mode, owner) are left to the job's existing attribute handling. That handling syncs them onto the latest copy, which can live in an older version, and the verification must not add more of that.
   - **Those entries are replayed into the new version** with the same code as the batch, inside the same try/finally, before the copies are stopped. It first waits for every copy the batch started.
   - **This backup's own copies are not read back.** Rows this replay copied, which are dirty and not yet recorded, are checked for presence and kind only, so their crash check (`unchecked`) stays for the next comparison. Rows a move carried have no record, as now, and are read once through their link chains into older, committed versions. That moves forward to this batch the one read the next full comparison would make.
   - **The version folder must agree with the manifest** for the touched scopes. An entry in the new version's folder that the manifest does not list is removed; this is case c's leftovers. A manifest row whose entry is missing from the folder is copied from the monitored tree.
   - **Paused inner mounts, the skip list and unreadable folders** are handled as the scoped comparison already handles them: they keep their old entries.
2. **The change list records the fixes.** Every entry the verification creates, deletes or modifies is written to the version's change list, after the batch's own rows. History and folder history then show each change at the right version, and the restore picker offers the right versions.
3. **A move onto itself is a no-op.** A collapsed `move X from X` (case loop) is dropped in the collapse, so the replay no longer raises. The verification then compares X.
3b. **A batch without its raw events is followed by one full comparison.**
   - A batch resumed from the pending file, or put back in front of the queue after a backup that did not commit, has only its collapsed entries left (`backup_entries_to_change_events`).
   - Those can miss a path the collapse dropped; the git case's X is one.
   - So the job runs a full comparison as the next batch after such a batch. That is what a restart with nothing to resume already does.
4. **Pending events keep sane times across a reboot.** Pending transactions store monotonic times, and the monotonic clock restarts at boot. That is why the versions replayed after the 2026-10-21 reboot have change-list times about four days in the future.
   - On load, the times are shifted so the newest equals the moment the pending file was written, read from its mtime and mapped to the monotonic clock. Their spacing and order are kept.
   - A normal restart keeps working as now.
5. **Version 0.43.** Set it in `reverberator.py` and `pyproject.toml`. README: one sentence in the design notes saying that after each batch, the places it touched are compared with the monitored tree, so renames, saves through a backup file and folder swaps come out as they are in the tree.

## Non-goals

- **Making the collapse exact,** reordering the replay, or changing the watcher. The verification makes the version right whatever they produce. They keep doing what they do, so cheap renames and link chains survive.
- **Repairing versions written before 0.43.**
  - A full comparison repairs the latest version going forward, as now.
  - The audit found the two stale git refs in the work job's latest version. A full comparison at the next restart without pending transactions removes them.
  - Forcing one is the user's call.
- **The corrupt 2026-10-17 log file** found by the audit. That is in Tee_Logger's in-place xz writing, and is a separate investigation.
- **Changing the change-list or pending-transactions format.**

## Anti-goals

- **Touching anything outside the new, uncommitted version.** The verification reads the monitored tree and writes only `backup_folder` and the manifest rows inside the open transaction. Links point only back into older versions, so nothing in an older version can be affected. Removal must not follow links, and must never act on the version folder itself.
- **Losing data on a crash.** Everything stays in the transaction `do_backup` commits with the version. A crash before the commit rolls back, and the incomplete version is removed at startup, as now.
- **Making ordinary batches noticeably slower.**
  - A batch of file edits verifies only those files: one stat and one manifest lookup each.
  - A folder move or create walks that folder twice, once in the monitored tree and once in the version, without reading file contents unless the comparison already would.
- **Reading files the comparison does not already read.** The verification uses the comparison's own rules for when to look at bytes.

## Decisions (builder's calls, made here)

- **Raw events, not collapsed entries, define the scopes.** The collapse is where information is lost: the git case's collapsed entries do not name X at all.
- **The verification runs inside `do_reverb_backup`,** after the replay and before `do_backup` writes the change list and commits. The replay is split into a function the batch and the verification share, if it is not one already.
- **Changes made after the batch was taken.** Monitored files can change after the batch was taken; they show up as differences and are copied into this version. The replay already copies whatever is there at replay time, and the new events stay queued for the next batch, which copies them again. This is accepted.
- **Re-copies (round 4).** They run before the replay, as now. A stale child the verification deletes takes its re-copy with it, and the `recopy` row is suppressed as for any rewritten path.
- **Changes during the backup window.** A move made while the backup runs, from a touched scope to an untouched path, shows up only as deletes. The next batch's move then finds no source and falls back to delete-and-copy, with its ERROR line. The result is right, so this is accepted.
- **Cost of renames.** A folder rename now reads each moved file's tail once in this batch, through its link chain. It is the read the next full comparison would have made, moved forward. Swaps and folder swaps (e4) can end as copies rather than renames.
- **The size estimate** before the backup does not count verification copies. The next measurement after the version counts them. This is accepted: the copies are what a correct version needed.

## Tests the change must add

All in the existing styles: replay tests with `run_backup`, and sequence tests through the real watcher, marked `inotify`.

- **Every sequence in the table above,** run as one batch:
  - each version's folder and manifest equal the monitored tree: names, kinds and file bytes;
  - the change list has a row for each verification fix.
- **The live git pattern,** with an X that existed before the batch: X is gone from the version.
- **Ordinary batches don't verify more than they touched:** a batch of one file modify compares one path.
- **Paused inner mounts:** a paused inner mount under a touched folder keeps its entries.
- **Nothing outside the new version changes:** every older version's listing and link targets are byte-identical before and after the batch.
- **Pending times:** a pending file written with monotonic times from a "previous boot", much larger than `time.monotonic()`, loads with times that end at the file's mtime. Its change-list times are not in the future.
- **The self-move:** `move X from X` is dropped, and the backup succeeds.
- **No read-back of fresh copies:** after a batch, rows this replay copied keep `unchecked` set.
- **No early commit:** a crash injected between the verification and the commit leaves the manifest and the vault as before the batch.
- **Folder attribute change:** a `chmod D` batch compares D itself, not its children.
- **Round trip:** a batch resumed from the pending file is followed by a full comparison, and the git pattern, round-tripped, ends with X gone.
- **Attribute-only differences:** found by the verification, they are not replayed, and no older version's mode, owner or mtime changes.

## Left to the builder

- How the replay is factored for reuse.
- How touched scopes are gathered and de-duplicated.
- Helper names.
- Test file layout.
