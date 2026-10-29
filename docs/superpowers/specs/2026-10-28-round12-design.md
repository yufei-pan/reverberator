# Round 12: no writes under a vault that is not there, no vault reads for a vouched chmod, checked deletes

Version 0.48. The three items the user deferred to round 12 on 2026-10-28 (docs/limitations.md), with the mechanisms the
user chose.

## The user's words

- Writes under a vault that is not mounted: "Defer to round 12 (Recommended)", on "Never create or write into a vault
  path whose pool or signature is not ready; keep queued changes as a full-comparison request instead." The auto
  signature: "Defer to round 12 (Recommended)", on "With the missing-vault item: fill an auto signature only when the
  vault path is on a mounted pool or disk, never from a folder it just created."
- How to tell the disk is there: "fstab mount must be mounted (Recommended)": "If /etc/fstab names a mount point above
  the path (here /mnt/jank) and it is not mounted, the job waits with the FAILED: waiting marker instead. A vault on a
  disk not in fstab (e.g. /var/reverbs on /var) is still created as today."
- The chmod read: "Defer to round 12 (Recommended)", on "Keep the record's hash when it vouches for the copy, so an
  attribute-only change reads nothing from the vault."
- The failed rm: "Defer to round 12 (Recommended)", on "Check each rm's result and fail the batch (handed back and
  retried) when one fails."
- Round 12: "yes start now".
- After the spec check (2026-10-28): a stop that drops queued changes while an older pending file stays in the vault:
  "Known limitation (Recommended)".
- During the build (2026-10-28), on the monitored side: gating monitored waits by the same fstab check: "Add to round 12
  (Recommended)"; filling an auto Monitoring File System Signature only from a folder whose disk is there: "Add to round
  12 (Recommended)".
- Standing: nothing is merged, pushed or restarted without the user; known limitations and deferrals need the user's OK.

## Goal 1: never create or write into a vault that is not there

**The check (`vault_disk_problem(path) -> str or None`, None when the disk is there).** A vault path's disk is not there
when:
- /etc/fstab (`FSTAB_PATH`, a module constant tests patch, like `MOUNTINFO_PATH`) names a mount point that is the path
  or a folder above it, and the longest such one is not mounted now; or
- the path is on a mergerfs pool with a missing or failed branch (round 9's `pool_problem()`, which works on a path that
  does not exist yet and also covers a dead mergerfs).

A path under no fstab mount point counts as there, as today (a vault on a disk mounted some other way). fstab parsing:
skip blank and `#` lines, take field 2, decode `\040` `\011` `\012` `\134`, skip mount points that are not absolute
(`none`, swap), normpath the rest; every entry counts alike (mergerfs, bind, `noauto`, `nofail`, automount), only the
mount point matters. "Mounted" means a mount point of the live mount table (`parse_mount_table()`, as decoded there)
equals the normalised fstab mount point; the vault path goes through non-strict realpath and is matched by path
component (`p == mp or p.startswith(mp + '/')`, never a plain prefix: /mnt/jank must not match /mnt/jank_data/...). A
missing or unreadable fstab names nothing; a mount table that cannot be read means not there (wait), as `pool_state()`
does. An fstab mount point that the mount table does not list is resolved (non-strict realpath) before matching, so a symlinked mount point is judged too; a listed one is never stat'ed, so a hung mounted filesystem cannot block the check (the main session's call after the task 1 review). The fstab is read at each check
(about 10 KB).

The signature (the user's "pool or signature") is checked as today, by the vault wait once the path exists; before the
path exists, the check above decides.

**Where it applies:**
- **Every vault wait** (the backuper's start and its per-batch wait, both `wait_for_path()` on the vault) also requires
  the disk check: while it fails, the job waits with the FAILED: waiting marker naming the unmounted mount point or the
  pool's missing disk, re-checking every poll. So a bare folder already left under an unmounted mount point (0.47 made
  such folders) is never backed up into, at the start or mid-run, whatever the signature cell holds. The start creates a
  missing Vault Path inside that wait, once the disk is there; the signature monitor learns of the new folder at once
  (register after creating, or invalidate it), not after `FS_RECHECK_SECONDS`.
- **parse_rules** no longer creates a missing Vault Path (a row whose path cannot be created is then a job that fails and
  retries, not a rule ignored at parse: the main session's call). It fills an auto Vault File System Signature only when
  the vault path exists and its disk is there; otherwise the cell stays auto, and the job runs without signature gating
  until the next start fills it from the path the backuper created (the main session's call: the disk check above gates
  fstab disks meanwhile). It still writes the row back for the cells it does fill.
- **A stop** (the backuper's hand-back, and a failed job's queue, both through `persist_pending_transactions()`) writes
  no pending file when the job's vault path is not a folder, or its disk is not there (a live check, not the vault flag,
  which the backuper unregisters before it persists): the queued changes are dropped with one log line, as a start with
  no pending file compares the whole tree ("keep queued changes as a full-comparison request instead"). Round 11's
  narrower guard (a full_scan-only queue with the vault path absent) becomes part of this rule.
- **Known limitation (the user's, 2026-10-28):** an older pending file already in the vault (saved by a stop while the
  vault was there, and not yet loaded because the next start never got past the vault wait) stays; a later start may
  replay it, and the dropped changes are missed until the next full comparison, as changes made while the daemon is down
  would be when the quick resume check passes.

**The monitored side (added during the build).** The monitored-path waits (the watcher's and the backuper's) make the
same disk check on the monitored path: while an fstab mount at or above it is not mounted, or its pool has a missing
disk, the job waits with the FAILED: waiting marker, so an unmounted disk's empty bare folder is never backed up as
every file deleted. parse_rules fills an auto Monitoring File System Signature only from a folder whose disk is there;
otherwise the cell stays auto with one warning, as for the vault.

## Goal 2: a vouched attribute change reads nothing from the vault

Under Only Sync Attributes, when the replay syncs an attribute-only change onto a chain end whose record vouches for it
(`record_vouches()` with the chain end: the live file has the recorded size, mtime and tail, and the chain end has the
recorded size and mtime), the row is recorded at commit from that record's hash and the chain end's new metadata,
without hashing the copy again: the commit reads no file data for it (it still walks the chain with lstat). Today the
commit (`record_dirty_entries()` → `read_copied_record()` → `read_vault_record()`) hashes every dirty row's chain end.
The row keeps the record's unchecked flag. Rows not synced this way are recorded as today.

How (the spec check's answer, the builder may refine): a manifest method that sets dirty and keeps the row's record
(`VaultManifest.add()` is INSERT OR REPLACE and wipes it), so "dirty with a record" means vouched and any later `add()`
for that rel (a fix, a move, a copy) wipes it by itself; `record_dirty_entries()` reuses the record's hash only when the
chain end's (size, mtime_ns) still equal the record's, else hashes as today. No schema change.

## Goal 3: a delete whose removal fails fails the batch

The replay's delete (`delete_path()`) checks that each removal worked. Today the `rm` tasks' results are dropped
(`mcae.run_command()`'s return value is ignored). The removal stays `rm` through the AsyncExecutor (its parallelism on
the HDD pool is kept); each task and its path is kept, and checked when the replay's async commands are waited for: a
task that reports failure (a non-zero exit, multiCMD's own -1, or a stopped task) and whose entry is still there fails
the batch, as a vault-side copy failure does today (a JobFailure: rollback, no version committed, the batch handed back
and retried), with rm's own message in the log. A removal of an entry that is already gone is not a failure. An entry of
another kind in a file row's place (a folder where a file row was, which `rm -f` refuses) is another row's entry: the
row is dropped, as the folder branch's `replaced_folder()` does, not a failure.

What the operator sees on a lasting failure: the job's FAILED: ...; retrying lines with the growing delay, each retry
rebuilding the batch.

## Goal 4: version 0.48, docs

- `__version__ = 0.48`, pyproject `version = "0.48"`.
- docs/limitations.md: remove the three deferred entries this round closes ("Writes under a vault that is not mounted",
  "A chmod reads each file's vault copy once at commit", "A delete whose rm fails leaves the entry in the version"), and
  their README Known-limits lines; add the known limitation above ("An older pending file replayed after a stop dropped
  changes", approved 2026-10-28, "Known limitation (Recommended)") with a README line; README design lines for the disk
  check, the stop rule, the commit-time record and the checked delete. Examples use a test fstab, never /var (on this
  host /var is an fstab mount).

## Non-goals

- Mounts not named in /etc/fstab (systemd mount units, autofs, manual mounts): treated as there, as today.
- Any change-list, pending-batch, manifest or rule-file format change.

## Constraints

- Work in `.worktrees/round12`, branch `round12`; never in the live checkout; never write under /mnt/jank, /mnt/impulse,
  /mnt/klein or /etc; never read /etc/firewatcher/firewatcher.conf; never `sudo sysctl`; tests at 2 processes at most;
  both full suites pass (worktree venv and the live venv's older libraries).
- The user's rules: /mnt/optane/work/agent-rules/RULES.md.

## Left to the builder

The exact log and marker wording, and refinements of the "how" notes above that keep their behaviour. Tests use a fake
fstab and mount table (`FSTAB_PATH`, `MOUNTINFO_PATH`): /tmp and /root are fstab bind mounts on this host.
