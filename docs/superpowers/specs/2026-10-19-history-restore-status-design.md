# Status, history and restore commands

Date: 2026-10-19  
Status: approved 2026-10-19  
Scope: `reverberator.py` (new subcommands; in the daemon a status file, a restore lock, and a fix for links broken by
moves to another folder depth), README, tests

## Intent

Reverberator keeps versions, but getting anything back today means walking `V…` folders and their symlink chains by
hand, and the only view of the daemon's health is the journal. The user has not needed a restore yet; this round is so
that when something goes wrong, getting a file, a folder or a whole job back is quick and trustworthy, and so that a
glance tells whether every job is healthy. The user is the only operator and runs it as root on the host that runs
the daemon.

## Goals

- `reverberator.py status`: one block per job with its health and its vault numbers.
- `reverberator.py history <path>`: when a file or folder changed, across the versions the vault still keeps,
  including paths that have since been deleted.
- `reverberator.py restore <path> [dest]`: copy a file, a folder or a whole job out of a chosen version, into a
  folder the user names or back in place.
- Whole-job restores (tens of GiB, hundreds of thousands of files) are a real use and must cope.
- The daemon's own command line (`reverberator.py -t 6 /etc/reverb_rule.tsv`) keeps working unchanged.
- Moving a file or folder to another folder depth no longer leaves the vault with links that point nowhere, and
  retention no longer deletes the only copy behind such a link (see "The move-depth bug").

## Non-goals

- Mounting or browsing the vault as a filesystem.
- Restoring from versions retention has already pruned.
- Restoring to or from another host.
- Live progress of the daemon (queue sizes, a backup in progress, compare progress) in `status`.
- Machine-readable (`--json`) output.

## Anti-goals (would make this a failure even if it technically works)

- A restore that leaves files out and still reports success.
- Any of the new commands writing to a vault, its manifest, or the rule file (the daemon fix below is the daemon's own
  write path, not the commands').
- The commands slowing down or blocking backups.
- `status` showing a job as healthy when the daemon is not running (including after it was killed).
- A restore that hands back the *current* live file while claiming it is an older version.

## Background: what a vault holds

(For the builder; verified on the live vault `/mnt/jank/klein/work`.)

- A job's vault is `<Vault Path>/<slugified job name>/`, holding `V<n>--<timestamp>` folders
  (`VAULT_TIMESTAMP_FORMAT`, e.g. `V212--2026-10-18_06-21-54_-0700`), a `current_version` symlink to the newest one,
  and `.reverberator_manifest.sqlite` (latest version only).
- Each version folder is a full tree. A file unchanged since the previous version is a relative symlink into the
  previous version's folder (`../V211--…/longctx_test.py`), and that may itself be such a link, so a file resolves
  through a chain (at most `MAX_CHAINED_LINKS`). The oldest kept version holds real files for everything, because
  `decrement_stepper` moves the pruned version's files into it.
- A user's own symlink is copied into the version as a symlink with its original target. The rule that tells the two
  apart is the one retention uses: a link whose resolved target lies inside another version folder of the same job
  vault is a chain link.
- Each committed version has a change list next to it,
  `V<n>--<timestamp>--<size>B-<inodes>_ino.modified_contents.nsv`: NUL-separated rows with header
  `path, iso_time, event, source_path`, where `path` and `source_path` are absolute monitored paths and `event` is one
  of `create`, `modify`, `delete`, `attrib`, `move`. The size and inode count in the name are the daemon's own
  measurement of that version (see the reliability round on version usage). A version folder without a change list
  is incomplete and is not a version.
- With `Keep 1 Complete Backup` false, the first version is a referenced backup: its files are links into the
  monitored path, not copies. All live jobs use true.
- With `Only Sync Attributes` true (all live jobs), an attribute change is applied through the new version's chain
  link to the shared real copy in an older version, so every version sharing that copy shows the newest mode, owner
  and times. The folders therefore never show an attribute-only change; only the change list's `attrib` row does.

## The move-depth bug

Found by the builder check and confirmed in the code (`do_reverb_backup`'s `move` branch, `VaultManifest.move_tree`,
`tests/test_manifest.py::test_folder_moved_to_another_depth_is_copied_again`). A move renames the vault entry (a file's
link, or a folder with all its links) and keeps each link's relative text. When the new place is at another folder
depth, the text no longer reaches the version holding the copy: `../../V211--…/a/x` moved from `a/x` to `deep/er/x`
resolves to nothing. Only a full comparison (at daemon start, or after a queue overflow) copies such a file again, and
until then every later version chains onto the broken link. `decrement_stepper` only materialises links whose
resolved target lies in the version being pruned, so it skips these links and deletes the real copy with that version:
the vault then holds no copy of a live file. The user chose to fix this in this round.

- **One rule for chain links, used everywhere:** the daemon writes chain links as relative links
  (`do_referenced_copy(..., relative=True)`). A link is a chain link when its target text is relative and contains a
  path component in the form of a version folder name (`V<n>--<timestamp>`, as `get_vault_info` recognises them); it
  then refers to `<job vault>/<that component>/<rest of the text after it>`, whatever folder depth the link now sits
  at, and is dangling if that version no longer exists. For a link at its original depth this is exactly where the
  text resolves today. Daemon re-targeting, retention, `history` and `restore` all use this rule. A user's own symlink
  does not name a version folder, so it is left alone; the absolute links of a referenced backup are not chain links.
- **Moves:** when a move changes folder depth, each chain link it carries (the file's own link, or every chain link
  under a moved folder) is rewritten to the relative text that reaches the same copy from its new place. User
  symlinks keep their text, as in the monitored tree. Same-depth moves need no rewrite.
- **Retention:** when pruning version P, a link in the next version that refers (by the rule above) into P is
  materialised from P like any other, including links an older daemon already broke.
- **Links broken before this fix:** the next start's full comparison already re-copies the newest version's broken
  entries; older versions' broken links are read through the rule by `history` and `restore`, and materialised by
  retention when their version is pruned. No separate repair pass.

## Decisions

Made by the user:

- **Commands:** subcommands of `reverberator.py`, reading the same rule file to find the jobs and vaults. One file to
  deploy.
- **Status content:** each job's health (running, retrying, waiting for a disk, stopped, with the reason, and when its
  last backup was) plus its vault numbers (version count, oldest version kept, vault size against its limit).
- **History of a folder:** one line per version with counts of what was created, modified and deleted under it;
  `--files` lists the paths.
- **Choosing the version to restore:** `--version N` or `--at TIME` pick it; with neither, `restore` lists the
  versions that differ and lets the user pick one.
- **Restore destination:** by default into a folder the user names; `--in-place` restores at the original path.
- **In place, when something is already there:** it is moved aside to `<name>.before-restore-<timestamp>` next to it
  first. Nothing is overwritten.
- **Whole-job restores must cope:** progress output, parallel copies, and a final report naming everything it could
  not restore.

Made by Claude while designing (flagged so they can be checked):

- **How `status` learns the daemon's state:** the daemon writes a small status file per job (and one for itself)
  under a state folder, `/run/reverberator/` by default, written atomically (temp file and rename) whenever the job's
  state changes and after each committed backup. The daemon's file records its pid, process start time, version, start
  time and rule file path. `status` treats the daemon as running only if that pid is alive *and* has the recorded start
  time (so a killed daemon or a reused pid reads as not running); then the job files are current, otherwise they are
  shown as the last known state, marked as such. Failing to write a status file never fails a job (logged once).
  The state folder is created by the daemon; the unit file does not change.
- **Vault numbers without a walk:** `status` reads the job vault's folder listing and the sizes in the change-list
  names; it never walks a version. It must answer in about a second for all jobs. The limits shown are the rule's
  `Keep N versions` and `Backup Size Limit`, resolved against the vault filesystem the way retention resolves them
  (`5%` of the disk, `i5%` of its inodes). A vault that is not mounted is shown as such.
- **Which rule file the commands read:** `--rule PATH`; by default the rule file the daemon recorded in its status
  file, whether or not it is still running. With no record (nothing has run since boot), `--rule` is required; the
  commands never fall back to `reverb_rule.tsv` in the current folder, which in the checkout is the sample file with
  other jobs. The commands parse it read-only: no header upgrade, no auto-filled rows written back, and no
  filesystem-signature lookups beyond what `status` needs to say a disk is missing.
- **Paths:** the user types live paths (`/mnt/optane/work/cas/x.py`), absolute or relative to the current folder,
  which need not exist any more. The job is the one whose monitored path is the longest prefix of it; `--job NAME`
  overrides that (and then a relative path is relative to the job's monitored path). A path under no job is an error
  naming the jobs' monitored paths.
- **When a file "changed" in a version:** the version folders are the truth. A file changed in version N when its
  entry in N is not a chain link into version N−1 (a real file, a user symlink, or a link to another path, which is a
  move); it was deleted in N when N−1 has it and N does not. The oldest kept version is shown as the oldest copy kept,
  not as a change. The change lists supply the event label (`create`, `modify`, `attrib`, `move` with its source) and
  the counts for folder history, and a version whose change list has a row for the path is listed even when its folder
  shows no change (an `attrib` change, see Background).
- **A path never backed up:** `history` says so, and if the job's skip list matches it, names the matching pattern.
- **Picking interactively:** a numbered list, newest first, of the versions that differ (for a file, the versions
  where it changed; for a folder, the versions where anything under it changed, plus the oldest kept), each with its
  time, event or counts, and size; the user enters a number. With only one candidate, it is used and named. Without a
  terminal on stdin, `restore` with neither `--version` nor `--at` is an error rather than a guess. `--at TIME` means
  the newest version whose timestamp is at or before TIME, in local time.
- **Destination layout:** `restore /a/b/proj /tmp/out` creates `/tmp/out/proj`. If that name already exists in the
  destination and is not this restore's own unfinished output (below), the restore stops before writing anything.
- **Picking up an interrupted restore** (the user's choice): a folder restore marks its output as its own with a
  marker file at the top of it, naming the job, the source path and the version. Running the same restore again
  (same job, path and version, same destination or in place) finds the marker and continues: entries already there
  under their real names with the vault copy's type, size and mtime are kept, the rest are copied, and folder metadata
  is applied at the end. It never moves aside, replaces or deletes anything in output it did not mark. A marker for a
  different job, path or version is refused, naming it. The marker is removed when the restore finishes with nothing
  failed; while anything failed it stays, so a re-run retries just those, and the final report says that removing it
  accepts the result as it is. An in-place re-run does not move the partial output aside again.
- **What a restore copies:** chain links are followed to the real file; user symlinks are restored as symlinks;
  folders, files and symlinks keep their mode, owner, times and extended attributes, as the daemon's own copies do.
  With `Only Sync Attributes` true those are the newest ones the shared copy carries, not necessarily that version's
  (see Background); the README says so.
  A file is written under a temporary name and renamed into place only once complete, so an interrupted restore never
  leaves a half-written file under a real name. A link that leaves the job vault into the monitored path (a referenced
  backup) is not followed: that entry is reported as not held in the vault, never filled with the current live file.
  A dangling chain, an unreadable file or a failed copy is reported per path, the rest of the restore continues, and
  the command exits non-zero.
- **Old versions removed during a restore:** retention could delete the version a restore is reading from. A
  restore holds a lock for its job (an `flock` on a file in the state folder, so a crashed restore releases it), and
  the daemon postpones pruning that job's oldest version while the lock is held, logging that it did. Backups go on
  as usual; only pruning waits. The vault may exceed its size limit until the restore finishes.
- **Restoring a job's whole monitored path in place:** the root cannot be moved aside (it is often a mount point), so
  an in-place restore of the root requires it to be empty (an empty `lost+found` is allowed) or to hold this restore's
  own unfinished output, which covers a replaced disk; otherwise it says to restore into a folder instead. If the daemon is running that job, `restore --in-place` warns that the job will back the
  restore up as one large change and asks for confirmation (`--yes` skips the question).
- **Exit codes:** 0 when everything asked for was restored (or shown), 1 when anything failed, 2 for usage errors
  (unknown path, no version chosen without a terminal).
- **Version:** 0.39.

## Output shapes

Illustrative, not binding; the builder may adjust layout.

```
$ reverberator.py status
reverberator 0.39, running since 2026-10-19 09:12 (pid 8776), rules /etc/reverb_rule.tsv

work            running         last backup 2026-10-18 06:21 (V212)
                5 versions (limit 5), oldest V208 2026-10-17 02:54
                vault 52.6 GiB / limit 5% = 186 GiB, 126.75K inodes / limit i5% = 3.1M
kes_files       waiting for disk since 08:40: /mnt/impulse not mounted
                3 versions (limit 3), oldest V40 2026-10-12 11:02
                vault not mounted: /mnt/jank/impulse
mein            stopped: skip list lost its patterns; set the cell to none to back up everything
...
```

```
$ reverberator.py history /mnt/optane/work/cas/multiSSH3/multiSSH3.py
job work, vault /mnt/jank/klein/work
V212  2026-10-18 06:21  modify   41.2 KiB
V209  2026-10-17 05:28  create   40.8 KiB   (moved from …/multiSSH3.py.tmp.9988)
V208  2026-10-17 02:54  oldest kept copy
```

```
$ reverberator.py history /mnt/optane/work/cas
V212  2026-10-18 06:21  12 created, 4 modified, 1 deleted
V210  2026-10-17 11:43  3 modified
V208  2026-10-17 02:54  oldest kept copy
```

## Constraints

- Single module, as today: tabs, the file's naming mix and comment density, doctests on small pure helpers.
  Python floor `>=3.8`; the dependency floors stay as raised in 0.38, and code must also run on the service venv's
  libraries (Tee_Logger 6.40, multiCMD 1.51, TSVZ 3.39, xxhash 3.8.1, pathspec 1.1.1).
- The daemon's argument parsing and behaviour are unchanged apart from writing status files, honouring the restore
  lock, and the move-depth fix. `reverberator.py [options] RULE_PATH` still starts the daemon.
- The commands open nothing in a vault for writing, and do not open the manifest (sqlite can create files beside it).
- Restore copies run in parallel with a bounded number of workers; a restore must not starve the daemon of its
  `BACKUP_SEMAPHORE` (it runs in its own process, so this is about not saturating the vault disk by default; a
  `--threads` option sets it).
- History reads change lists that can be tens of MiB (V209 here: 73 MiB, 478K rows); stream them, do not load them.
- The status and lock folder must be overridable (option or environment variable) so tests do not touch `/run`.
- The live service runs from the main checkout; work happens in a worktree, and the suite must pass on both the
  service venv and a fresh one.

## Testing expectations

- Unit: chain resolution (multi-hop, dangling, a user symlink, a link that leaves the vault, `MAX_CHAINED_LINKS`),
  path-to-job mapping (longest prefix, `--job`, relative paths, a path under no job), `--at` selection, read-only rule
  parsing (the file is byte-for-byte unchanged afterwards, including an 11-column file).
- History: a file created, modified, moved and deleted across versions, built with the test harness's vault helpers;
  a folder summary and `--files`; a path never backed up, and one matching a skip pattern.
- Restore: a file and a folder into a destination, metadata kept, user symlinks kept; in place with something there
  (moved aside, nothing lost); in place into an empty root; refusal when the destination name exists; a dangling link
  reported with a non-zero exit and the rest restored; no terminal and no version is an error; nothing in the vault
  changes (compare a listing with lstat data before and after).
- Move-depth fix: a file and a folder (with nested folders and a user symlink inside) moved deeper and shallower keep
  every chain link resolving to the same copy, with no full comparison; user symlinks keep their text; same-depth moves
  are unchanged; pruning a version materialises a link an older daemon broke (built by hand in the test); the existing
  `test_folder_moved_to_another_depth_is_copied_again` is updated to the new behaviour.
- Restore re-run: an interrupted folder restore (stopped part way) completes on a re-run with correct contents, keeps
  what it had finished, refuses a marker for another version, and never touches unmarked output.
- Restore against retention: pruning is postponed while a restore holds the lock and resumes after it is released,
  including when the restoring process is killed.
- Status: daemon running, daemon gone with stale files, a reused pid, a job retrying, waiting for a disk, stopped;
  a vault not mounted; the numbers match the vault.
- A larger restore (thousands of files) completes with correct contents and a progress line.
- The existing suite still passes.

## Left to the builder

- Status file format and fields beyond those named above, and how the daemon's supervisor, `wait_for_path` and
  backuper report state changes into it.
- How subcommands are told apart from the daemon's `RULE_PATH` positional in argument parsing.
- The copy mechanism for restores (reusing `cp`-based copies and the checked-copy handling from 0.38, or another
  way) and the default worker count.
- Progress line format and how often it updates.
- How the daemon checks the restore lock around `decrement_stepper`, and how often it retries.
- README section for the commands.
