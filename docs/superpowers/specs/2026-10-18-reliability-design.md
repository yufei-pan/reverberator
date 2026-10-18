# Reliability round: per-job failures, inner mounts, version sizes, follow-ups

Date: 2026-10-18  
Status: draft, pending approval  
Scope: `reverberator.py`, tests, README / sample text, a firewatcher pattern file (repo sample + installed on this machine)

## Intent

reverberator should keep backing up every healthy job no matter what one job runs into, heal on its own when the
cause goes away, and say so in log lines a log watcher can match. Today any job's watcher or backuper failure clears
`GREEN_LIGHT`, every job stops, and `main()` returns normally, so the process exits 0 and systemd's
`Restart=on-failure` never restarts it: backups quietly stop. On this machine the user's own tool, firewatcher, reads
the journal and alerts on patterns in `/etc/firewatcher/patterns.d`, so stable failure lines are how the user will
notice. A status view belongs to the later CLI round.

The same round fixes the watcher crash on an inner mount being unmounted (and decides what an unmount means for the
vault), removes the two `du` walks over every new version, and clears the follow-ups left from the skip-list round.

## Goals

- One job failing never stops the others; a failed job retries itself with a growing delay and recovers on its own.
- Fixed, greppable log lines for a job failing, being stopped for good, recovering, and the daemon exiting on error;
  a firewatcher pattern file that matches them, shipped in the repo and installed here.
- The daemon exits non-zero when it stops because nothing can run, so systemd restarts it.
- A filesystem mounted inside a monitored folder is backed up while mounted; its unmount never shows up as deletions.
- New versions are sized without walking them, reporting the same numbers `du` would.
- The small fixes and the four skip-list follow-ups listed below.

## Non-goals

- A status command or status file (CLI round).
- Changing how `decrement_stepper` measures the version it removes (it still uses `du`), or the pre-backup estimate
  in `get_backup_size_inode`.
- Detecting that a *different* disk was mounted at an inner mount point: whatever is mounted there is what gets
  backed up.
- Live reload of the rule file.

## Anti-goals

- A job silently stuck: every way a job stops working must end in a logged FAILED (retrying) or STOPPED line.
- Losing queued change events across a job restart.
- History loss from a transient condition: an unmounted inner disk, an I/O error, a vault that briefly vanished.
- Retry loops that hammer a broken disk or flood the log (the delay grows; one FAILED line per attempt).
- Version sizes that drift from what the disk really uses (retention decisions depend on them).

## Decisions

Made by the user:

- **Job failure:** isolate and retry. The other jobs keep running; the failed job restarts itself after a growing
  delay — 1 min, 2, 4, … capped at 1 hour — and logs a recovered line when an attempt succeeds.
- **Noticing:** through logs; firewatcher on this machine. Add the pattern file here as part of this round
  (the user confirms before anything under `/etc` is written).
- **Inner mounts:** pause that subtree. Back the inner disk up while mounted; when it is unmounted, new versions keep
  its last backed-up contents and nothing under it is recorded as deleted; when it comes back, compare it again.
- **Version size:** stop walking the new version, provided the result still reflects actual disk usage with
  filesystem compression and dedup in mind (`du` was there for that reason).
- **Follow-ups in scope:** folder moved away and back, interrupted startup comparison, watch-removal noise,
  crash-safety edges (all four, detailed below).
- **I/O errors: keep the last copy, fail when it is wide.** A failed read never turns into deletions. A folder or
  file of the monitored tree that cannot be read keeps its last backed-up copy in new versions, the rest of the job
  backs up as normal, and a line names what could not be read. If the monitored root itself cannot be read (for
  example a dead mergerfs mount answering ENOTCONN), or a copy into the vault fails, the job fails and retries.
- **Disk waits alert after a grace period.** A job waiting for its disk (late mount at boot, a vault or monitored
  path that vanished, a filesystem signature that does not match) waits quietly at first; if it is still waiting after
  15 minutes it logs one FAILED line, repeated hourly while the wait lasts. It resumes as soon as the disk or path is
  back, not on the backoff timer.
- **All jobs stopped: exit with a distinct code that systemd does not restart.** The daemon exits with code 3 when
  every job is STOPPED, and `RestartPreventExitStatus=3` goes into the repo's `reverberator.service` and, with the
  user's OK at that step, into the installed `/etc/systemd/system/reverberator.service` (then `systemctl
  daemon-reload`). systemd then shows the unit as failed instead of looping every 5 s and re-sending alerts.

Made by Claude while designing (flagged so they can be checked):

- **What is retried and what is not.** Problems only a config change can fix stop the job for good with one STOPPED
  line: the skip list lost its patterns without `none`, a pattern that will not parse, an invalid rule, a job name
  that collides with another row's. Failures are retried with the backoff: an unreadable monitored root, a failed
  copy into the vault, a missing skip-list file (the disk may still be on its way), an uncommitted backup, a watcher
  or backuper exception. Waiting for a disk or path is neither: it is a wait, with the grace-period alert above.
- **A monitored path missing when the rules are read** no longer drops the rule ("Ignoring rule" today): the job is
  kept and waits for the path like a vanished one, so a monitored disk that mounts late at boot works.
- **Waits notice a path coming back** through the mount-table wake-up and also a periodic re-check (a deleted and
  re-created monitored root changes no mount).
- **Reading errors, by side.** Walks of the monitored tree report the folders they could not read instead of
  treating them as empty; delta generation keeps every tracked entry under such a folder (marked seen, linked
  forward). A copy whose *source* cannot be read (EIO, EACCES on the monitored file) keeps the previous copy; a copy
  whose *destination* fails (ENOSPC, EIO, EROFS in the vault), or whose failure cannot be attributed, fails the job
  and the version is not committed. Copy results are checked: today `cp` exit codes from the async executor are not.
- **Duplicate job names.** `parse_rules` writes auto-filled values back by rewriting that row in place instead of
  appending an updated copy (appending makes every auto-filled job appear twice and, for names that only match after
  `slugify`, starts a second job on the same vault on the next start). Two distinct rows whose names clean up to the
  same job name are both STOPPED with a line naming both rows.
- **A retry restarts the whole job** (its watcher and backuper), reusing the job's in-memory event queue, so nothing
  queued is lost; the restart runs the normal startup path (skip list, resume decision or full comparison). The
  backoff resets after a job has run cleanly for an hour.
- **Exit status.** Exit 3 when every job is STOPPED (see the user's decision above); exit 1 when the main thread
  itself fails (systemd restarts it); a signal (Ctrl-C, SIGTERM) still exits 0. While any job is retrying or waiting,
  the daemon keeps running.
- **Log markers** (exact text, so a pattern can rely on it), printed at error level:
  - `reverberator job <name> FAILED: <reason>; retrying in <N>s`
  - `reverberator job <name> FAILED: waiting <N> min for <path>: <reason>` (the grace-period wait alert)
  - `reverberator job <name> UNREADABLE: <path>: <error>; keeping its last backed-up copy`
  - `reverberator job <name> STOPPED: <reason>`
  - `reverberator job <name> RECOVERED after <N> failed attempts`
  - `reverberator EXITING with error: <reason>`
  The firewatcher file (`reverberator.txt`, fnmatch style, which firewatcher wraps in `*`) matches
  `reverberator job * FAILED`, `reverberator job * UNREADABLE`, `reverberator job * STOPPED` and
  `reverberator EXITING with error`. RECOVERED is not matched, to keep a flapping disk from sending two alerts per
  cycle. An UNREADABLE path is reported once per backup that meets it, not once per entry under it.
- **Inner mount rules.** An inner mount is a mount point strictly under a job's monitored path (from
  `/proc/self/mountinfo`, which `fs_signature_monitor` already reads and wakes on). The job remembers the inner mount
  points it has backed up, recorded with the committed state so it survives restarts. A remembered mount point that is
  not mounted is *paused* while its folder exists and is empty: walks do not descend into it, its tracked entries are
  kept and linked forward, and events under it are dropped. If the folder is gone, or holds entries of its own, the
  pause ends and the folder is treated as what it now is (that is how a user retires an inner disk for good: remove
  or repopulate the mount point folder). When the mount comes back, the job re-adds watches for that subtree and
  compares just that subtree against the vault — not a full-tree comparison, and not a recursive copy.
- **The watcher crash.** On `IN_UNMOUNT` the watcher removes the watches under the unmounted point instead of
  re-adding one per vanished folder (the `add_watch` that raises today), keeps the mount point folder watched, and
  leaves the remount to the mount-table wake-up above.
- **Version size.** Size and inode totals are counted from what the backup writes — every copied file, link and
  folder — reading each entry's allocated blocks (`st_blocks * 512`) after it is written, folders after they are
  populated, and subtracting entries the replay removes. That is exactly what `du -csP` / `du --inodes -csP` add up,
  so compression shows as the filesystem reports it and shared (reflinked or deduplicated) blocks are counted per
  file as `du` counts them; space a filesystem allocates late (ZFS transaction groups, ext4 delayed allocation) reads
  the same as `du` run at that moment. A test checks the counted totals against real `du` output for a mixed version.
  `get_vault_info(recalculate=True)` keeps `du` as the reference.
- **Small fixes.** `current_version` is replaced atomically (new symlink under a temporary name, then `os.replace`).
  Duplicate job names are handled as described above. `get_args`'s fallback parses the arguments it was given rather
  than `sys.argv`.
- **Follow-ups.**
  - *Folder moved away and back:* when a create (or an unpaired move in) arrives for a path that still has a pending
    move-from, the pending delete is queued first, then the create, so the vault never ends with the restored folder
    deleted.
  - *Interrupted comparison:* a full comparison that does not finish is re-queued as a full scan rather than
    replaced by whatever events arrived meanwhile.
  - *Watch-removal noise:* the nameless `IN_IGNORED` events that removed watches produce are dropped without an
    info line; the "watch descriptor not found" line no longer prints the whole watch table; removing many watches at
    once must not overflow the inotify queue into a full scan (raise the queue limit first, or remove in batches —
    builder's choice).
  - *Crash-safety edges:* a recorded skip-list fingerprint is trusted only when the manifest describes the latest
    committed version — otherwise an `unchanged` verdict becomes `changed` (the refuse-without-`none` rule still uses
    the recorded value); and a stop that lands while startup is reading pending transactions keeps them for the next
    start.

## Constraints

- Keep the existing crash-safety rules (commit protocol, content file last, pending transactions, manifest commits).
- A job's retry must not race its own previous threads: the old watcher and backuper have fully exited (watches
  closed, manifest closed, pending events handed back) before the new attempt starts.
- Shared resources stay correct across restarts: the inotify instance and watch counts (`inotify_resource_manager`),
  the `FS_SIGNATURE_MONITOR` registrations, the semaphore.
- Every wait stays interruptible by `GREEN_LIGHT` (Ctrl-C still stops everything promptly).
- Writing under `/etc/firewatcher/patterns.d` (and restarting firewatcher if it only reads patterns at start), and
  editing `/etc/systemd/system/reverberator.service` (then `systemctl daemon-reload`), happen only after the user
  confirms at that step. Restarting `reverberator.service` itself is the user's call, not part of the build.
- Vaults and most monitored paths on this machine are mergerfs (FUSE) mounts: a dead mergerfs answers ENOTCONN on
  every access while the mount table still lists it, so mount-table checks alone cannot tell it is gone.
- Code style follows `reverberator.py`; tests follow the existing layers (unit, inotify, process, privileged).
  Inner-mount behaviour needs real mounts: privileged tests (tmpfs), skipped without root, like the existing ones.

## Testing expectations

- A job whose backuper raises keeps the other jobs backing up; it logs FAILED with the delay, retries, logs
  RECOVERED, and its queued events survive (unit + process).
- A config-only failure logs STOPPED once and is not retried; when every job is STOPPED the process exits 3
  (process test). SIGTERM still exits 0; a main-thread failure exits 1.
- I/O: an unreadable folder in a full comparison keeps its entries in the new version and logs UNREADABLE once; an
  unreadable monitored root fails the job with no new version and no deletions; a failed copy into the vault (e.g. a
  read-only or full destination, simulated) fails the job without committing; a source file that cannot be read keeps
  its previous copy.
- Disk waits: no FAILED line inside the grace period, one at 15 minutes, hourly after (clock injected); the job
  resumes when the path returns, including a deleted and re-created monitored root; a rule whose monitored path is
  missing at start is kept and waits.
- Duplicate names: an auto-fill write-back rewrites the row in place (the file does not grow across starts); two rows
  colliding after `slugify` are both STOPPED.
- Backoff sequence and cap, and the reset after a clean hour (unit, with the clock injected).
- Inner mount (privileged): back up a tmpfs mounted inside the monitored path; unmount → new versions still hold its
  files, nothing recorded deleted, no watcher crash; remount with a change → only that subtree is compared and the
  change lands; remove the empty mount point folder → its entries are dropped. Restart while unmounted → still
  paused.
- Version size: counted totals equal `du -csP` and `du --inodes -csP` of the finished version for V0 complete,
  referenced, and replay versions with copies, deletes, moves, long and short link targets.
- Each small fix and follow-up gets a test pinning it.

## Left to the builder

- How a job's lifecycle is structured (a supervisor thread per job, or `main` supervising), as long as the
  constraints above hold.
- Where the remembered inner mount points are stored (the manifest `meta` table is the natural home).
- How sizes are collected during the backup (per-entry as written, or from manifest rows at the end without a
  directory walk).
- The exact wording after the fixed marker prefixes, and how firewatcher picks up a new pattern file (check its
  behaviour before restarting it).
- Version bump (next is 0.38) and README / sample text.
