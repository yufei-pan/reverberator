# Non-UTF-8 names, long chains, empty job names, and round 3's leftovers

Date: 2026-10-21  
Status: approved 2026-10-21  
Scope: `reverberator.py`, README, tests. Version 0.40.

## Intent

Round 3 (0.39) surfaced three older bugs and left about forty small review items for later. This round fixes them,
most urgently the first: a monitored file whose name is not valid UTF-8 makes a job's backups fail every time, so a
single such file (an old archive, a zip extracted with the wrong encoding) stops a whole job for good, and anyone who
can create files in a monitored tree can do that on purpose.

## Goals

1. **Non-UTF-8 file names are backed up like any other**, at every stage: the first full backup, watcher events,
   delta generation, moves, retention, the change lists, the pending transactions file, the journal, and the
   `status` / `history` / `restore` commands (including paths typed on the command line with such bytes). A name is
   stored so that its exact bytes come back: `restore` recreates the file under its original name.
2. **Names in log lines are escaped**, as the commands already print them (`shown()`): control characters, line
   separators and undecodable bytes become visible escapes. A file name can then neither break a log write nor forge
   a line: today a name containing a line break could write a fake `reverberator job … FAILED:` line into the
   journal, which firewatcher would alert on.
3. **No vault link longer than the kernel can follow.** When a file's link in a new version would be too long a
   chain, the new version gets a real copy instead (details below).
4. **A rule whose job name cleans up to nothing stops that job** with a clear STOPPED reason, as two rows sharing one
   job name already do. It never puts a vault at the vault root.
5. **Round 3's deferred review items** are fixed, except the few listed with a reason to leave them (appendix).

## Non-goals

- Running an older reverberator on a vault after 0.40 has used it (the user's decision: rollback is not supported).
- Non-UTF-8 bytes in the rule file itself (job names, monitored or vault paths, skip-list paths) or in skip-list
  patterns: those stay as today (a skip list that is not UTF-8 is a skip-list error that stops the job).
- Changing versions that already exist in a vault (no rewriting of old links or old change lists).

## Anti-goals (would make this a failure even if it technically works)

- Upgrading a vault to 0.40 costing a full comparison, a vault re-read of every entry, or any re-copy on a job that
  keeps 32 versions or fewer.
- A name stored or logged in a form that cannot be turned back into its exact bytes where it matters (the vault
  database, change lists, pending transactions, restore).
- A healthy vault's existing UTF-8 names reading back differently after the upgrade.
- The long-chain re-copy copying the live monitored file instead of the backed-up copy (that would silently record
  a newer state in an older version).
- Losing the skip-list fingerprint or remembered inner mounts in the upgrade (either would force a full comparison).

## Decisions

Made by the user:

- **Scope:** all four groups above.
- **Long chains:** copy again rather than cap kept versions or use hard links. The hop count at which a file is
  copied again is spread between **32 and 38** (inclusive), chosen per file from its name, so files unchanged since
  the same version do not all re-copy in one version. 38 keeps two links of headroom under the kernel's 40 (which
  counts every symlink on the path, including a user's backed-up symlink at the end of a chain).
- **Rollback:** not supported once 0.40 has run.

Made by Claude while designing (flagged so they can be checked):

- **What an older daemon does with an upgraded vault database:** the existing code discards a database whose schema
  it does not know and rebuilds it by reading the vault (slow, not wrong). That is acceptable under "rollback not
  supported"; the README says so.
- **Database upgrade in place:** the vault database (`.reverberator_manifest.sqlite`, schema '1') is upgraded to a
  new schema on first open by SQL alone: existing rows, the skip-list fingerprint and the remembered inner mounts are
  kept; nothing is read from the vault. How paths are stored (a BLOB of the name's bytes, or a reversible text
  escape) is left to the builder, with these constraints: existing UTF-8 rows keep their identity and ordering, the
  folder-range queries (`path >= ? AND path < ?`, `folder_range_end`) keep working for every name, and the upgrade
  is one transaction that either completes or leaves schema '1' as it was.
- **Change lists, pending transactions and journal:** written so that each name's bytes round-trip (e.g. writing
  with surrogateescape so the file holds the original bytes); `iter_change_list` and the pending-transactions reader
  read them back the same way. Existing files written by 0.39 read exactly as before. Verified by the builder check:
  TSVZ 3.39 encodes with `errors='replace'`, so a name with undecodable bytes would silently become `?` — names must
  be made safe before TSVZ sees them, or these files written without TSVZ. Also verified: sqlite orders every TEXT
  value before every BLOB, so a path column cannot mix the two.
- **Where the re-copy comes from:** the backed-up copy in the vault (the end of the chain), with its metadata, never
  the monitored file. A chain ending at a user's backed-up symlink re-copies that symlink.
- **How the re-copy knows a chain's length without walking it:** the vault database records, for each file entry,
  the number of the version that holds its real copy. A new version links an entry whose chain would exceed its
  threshold (`version − copy_version > threshold(name)`) by copying it instead and recording the new copy version.
  Retention, when it moves a pruned version's copies into the next version, updates the recorded copy versions
  accordingly. A job keeping 32 versions or fewer never reaches a threshold (no chain can be longer than the number
  of kept versions), so it never re-copies, never needs to know an upgraded row's copy version, and never pays for
  the check beyond reading a column. The live vaults keep 3 to 5 versions (round 3's audit); their version numbers
  (e.g. V212) are not counts.
- **Upgraded rows on a vault keeping more than 32 versions:** their copy version is unknown after the upgrade, and
  assuming the oldest kept version would re-copy nearly the whole tree in the first 0.40 version. Instead, the first
  backup that needs a row's copy version learns it once by walking that row's chain (lstat/readlink, bounded by the
  number of kept versions, not by the 39-link read limit, since such a vault's chains may already be longer), and
  records it. That vault read is allowed: the anti-goal's "nothing read from the vault" applies to jobs keeping 32
  versions or fewer.
- **Re-copies and the size limit:** the backup's size estimate counts the re-copies it will make, so retention prunes
  before the version is written instead of overshooting the limit.
- **Re-copies are not changes:** each re-copy is recorded in the version's change list as its own event (`recopy`),
  and `history` (file rows and folder counts) and the `restore` version picker skip it, so a re-copy never shows as a
  change and never offers an identical version. Re-copied rows are recorded from the vault copy they came from, so the
  next comparison does not hash them again.
- **threshold(name):** a stable function of the entry's path (e.g. a hash of its UTF-8/bytes form mod 7, plus 32), so
  the same file keeps the same threshold across runs and versions.
- **Escaping in logs:** the same escaping as `shown()`, applied where paths enter log lines (backuper/watcher log
  helpers and the marker lines `UNREADABLE`, `FAILED: waiting … for <path>`), so the firewatcher regex keeps
  matching real markers and a name can never start a line.
- **Empty job names:** detected where colliding names are (rule parsing / `run_daemon`), as a permanent failure:
  `reverberator job <row number or raw name, escaped> STOPPED: its name has no letters, digits, '-' or '_' left after cleanup`.
  The exact wording is the builder's; it must say what to change.
- **Version:** 0.40.

## Appendix: round 3's deferred items

From the round 3 ledger (saved at /tmp/claude-0/-mnt-optane-work-reverberator/8ad4e979-212b-4a0b-9477-1847dfee5560/scratchpad/history-restore-ledger.md);
items already fixed in round 3's final fix wave are left out.

| # | Item | Plan |
|---|---|---|
| 1 | A re-targeting failure after a successful move logs "Failed to move" and re-copies the entry | Log the re-targeting failure as what it is; keep the moved links (they resolve by the rule); no re-copy |
| 2 | An unreadable subfolder of a moved vault folder leaves its links un-retargeted while the move reports success | Log an error naming that folder; the rows stay unverified so the next comparison checks them |
| 3 | `chain_link_target` docstring overstates; `is_real_folder_under` assumes normalised paths | Correct both docstrings |
| 4 | Positive real-folder cache entries outlive a pruned version | Drop the pruned version's entries when it is removed |
| 5 | Chain-form parsing duplicated between `chain_form_missing_version` and `chain_link_target` | One shared parser |
| 6 | Referenced-link comparison uses an unnormalised join for a missing monitored path | Normalise |
| 7 | `find_job` uses abspath only: a path typed through a symlinked parent of a monitored path is "not under any job" | Also try the path with its longest existing parent resolved |
| 8 | `unescape_change_list_field` has no fast path | Return early when no `<` is present |
| 9 | `max_hops` for an unnumbered version name is 1 | Fix |
| 10 | A MonitorGate wait keeps its first reason when the path appears but the signature stays unknown | Update the published wait detail |
| 11 | Status files are written under the job lock; the board's "logged once" flag is unlocked | Write outside the job lock from a snapshot taken under it; lock the flag |
| 12 | `status` shows "4.00 inodes", "limit no limit", "0.00B" | Integer counts below 1000, "no limit", "0 B" |
| 13 | `status` lists each vault twice | Once |
| 14 | "Postponing removal of the oldest version" can be logged three times per backup | Once per backup |
| 15 | `RestoreLock`'s stream default binds `sys.stderr` at import | Resolve at entry |
| 16 | The lock file is opened without O_NOFOLLOW | Add it |
| 17 | A restore lock file the daemon can never open postpones pruning on every backup with only a plain error line | After a grace (as for disk waits), log a `reverberator job <name> FAILED: cannot check the restore lock …; pruning postponed` marker, repeated hourly while it lasts |
| 18 | `history --files` on a job root holds every row in memory | Print rows as they are produced |
| 19 | `history` reads change lists of versions where neither N nor N−1 holds the path, and resolves whole chains per version | Skip those lists; resolve each version's entry once |
| 20 | A move row without a source drops the source the chain shows | Fall back to the chain's source |
| 21 | "never backed up" decides folder vs file from the live tree | Also use a trailing `/` and the versions |
| 22 | `restore` failure and warning lists are unbounded (600K dangling entries ≈ 1 GB) | Print FAILED lines as they happen; the summary gives counts and the first lines |
| 23 | Signals after the last stop check are ignored; a stop check can take (threads+1)×0.1 s | Check during the metadata pass; bound the wait per check |
| 24 | A failed progress write (broken pipe, EIO after hang-up) gives a traceback | Stop writing progress, carry on |
| 25 | Folder metadata warnings drop the reason; the picker writes to stdout | Include the error; picker and prompt go to stderr |
| 26 | An in-place file restore moves the live file aside even when the version's entry is a certain failure | Check first |
| 27 | Resume keeps a file without comparing xattrs; an interrupted run's metadata warnings are lost | Compare xattrs too (re-copy on difference); a resumed run reports entries it kept whose metadata the earlier run could not set, if recorded in the marker |
| 28 | The claim does not re-check the marker after taking the target lock | Re-check under the lock |
| 29 | A marker vanishing between the `--accept` read and the check can move a just-completed restore aside | `--accept` with no marker found is "nothing to accept", checked once |
| 30 | Another user's flock on the target reads as "another run of this restore" | Say "another run, or another program, holds a lock on it" |
| 31 | Messages: "another user can change <folder>" for a folder that cannot be stat'd; resolved destination shown | Say why; show the path as typed alongside the resolved one |
| 32 | `restore_folder_meta` returns a bare False | Return the error for the warning |
| 33 | Status file test unclosed file; return annotations that omit None | Fix |
| 34 | Test gaps listed by the reviews (2-hop read with a broken middle link; pruning after a retargeted move; retarget failure fallback; referenced link after a move; '\r' in a name; MonitorGate publishing; logged-once and no temp file; postponing line asserted; size/inode loops under the lock; prune holding the lock; killed-process readline timeout; move-to-another-depth-and-back and delete-then-recreate history; DST `--at`; vault snapshot with ctime/uid/gid; daemon-side test of the nanosecond `copy_file_meta`; `restore_entry` using `restore_folder_meta`; the "replaced as it was made" branch; non-root subcases of the untrusted-marker test; `disk_line` statvfs flake; resume skipping the free-space refusal) | Add them |
| 35 | README omissions (exit 2 cases; root must belong to the restoring user; free-space check skipped on resume; in place refused when the target would contain a vault; `--accept` refused without a marker) | Add them |

Left as they are, with the reason:

- A crafted user symlink naming the previous version's exact folder name still counts as a vault link. It needs read
  access to the vault's folder names; the real-folder check already keeps everything inside the vault.
- `read_vault_record` follows at most 39 links: with re-copies at 38 hops at most, no daemon chain reaches it.
- Commands redirect stdout/stderr process-wide while loading rules: the commands are single-threaded.
- `get_path_fs_info` logs through the backuper's logger in commands: the commands' logger writes nothing.
- Folders that cannot be flocked (NFS) are not kept apart, and the microsecond window between an in-place mkdir and
  its lock can leave an extra empty moved-aside folder: no data is at risk.
- A `cp` that outlives the stop timeout may still write a partial file after the lock is released: it needs an
  unkillable `cp`.
- The version picker and the whole-job prompt wait while holding the restore lock: deliberate, so the version list
  cannot change under the person choosing; pruning resumes when they answer or quit.

## Future (noted at the user's request, not part of this round)

- **Hard links as well as symlinks.** A later round may let a version refer to an unchanged file with a hard link to
  its real copy instead of (or as well as) a symlink chain. That would remove chain length entirely, cost no extra
  space where this round re-copies, and let the kernel open every version's files directly. It needs its own design:
  the vault layout and its readers (retention's materialising, `read_vault_record`, history and restore's chain rule),
  size accounting (`measure_version_usage` would count a shared inode once per version unless taught otherwise),
  attribute syncs (a hard link shares one inode's metadata across versions, as a chain's real copy does today),
  vaults on filesystems without hard links, and how existing symlink vaults move over.

## Constraints

- Single module, tabs, the file's naming mix and comment density, doctests on small pure helpers; Python ≥3.8; no new
  dependencies; must run on the service venv's libraries (TSVZ 3.39, multiCMD 1.51, Tee_Logger 6.40, xxhash 3.8.1,
  pathspec 1.1.1) and on a fresh resolve.
- Work happens in a worktree; the live service runs from the main checkout. Tests never touch /run, /etc or the live
  vaults.
- The daemon's command line and the status files' format are unchanged.

## Testing expectations

- Non-UTF-8: a tree holding `bad\xff.txt` (and a folder with such a name, and a name with a newline and an ESC)
  backs up on the first full backup and through watcher events, moves (including to another depth), modification,
  deletion and retention; the change list and pending transactions round-trip the bytes; `history` lists it and
  `restore` recreates it under its exact bytes; `status`/`history` output and log lines show it escaped; a log line
  never contains a raw line break from a name.
- Database upgrade: a schema '1' database with entries, a skip fingerprint and inner mounts upgrades in place; the
  next comparison reads nothing from the vault and finds no differences; a failed upgrade leaves schema '1' intact.
- Long chains: with a hand-built or fast-forwarded vault of 40+ versions, every file's chain stays within 38 hops; a
  file is re-copied at its own threshold in 32..38 (deterministic per name); the re-copy has the vault copy's content
  and metadata even when the live file has since changed; retention moving copies updates the recorded copy version;
  a job keeping ≤32 versions makes no re-copies; an upgraded vault keeping 40+ versions learns copy versions by
  walking chains and re-copies only files past their threshold; the size estimate includes re-copies; `history` and
  the restore picker show no re-copy as a change.
- Empty job name: the job is STOPPED with the reason; the others run; nothing is created at the vault root.
- Each appendix item has a test where it changes behaviour.
- The existing suite still passes on both venvs.

## Left to the builder

- The path storage form in the database, and the change-list/pending/journal encoding mechanism, within the
  constraints above.
- The schema version string and migration code layout.
- The exact threshold function.
- Message wording.
