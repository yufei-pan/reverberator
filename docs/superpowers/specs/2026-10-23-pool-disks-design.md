# Round 9: pool disks, changes inside moved folders, pruning's temporaries (0.45)

## Intent

Round 9 does the items the user deferred on 2026-10-23 (`docs/limitations.md`), and what the user added while this
design was discussed.

Three mergerfs pools are live:

| Pool | Disks | Used by |
|---|---|---|
| `/mnt/jank` | 6 XFS, `/mnt/jank_data/*`, SnapRAID parity | every job's vault |
| `/mnt/impulse` | 22 f2fs, `/mnt/impulse_data/*` | the monitored folder of the five Nextcloud jobs |
| `/mnt/klein` | 6 f2fs | the monitored folder of `mein` |

`work` and `docker_volumes` watch `/mnt/optane`, which is a plain filesystem.

Each pool is built from a glob. When a disk is missing, its mount point is an empty folder on the root filesystem: it
still matches the glob and stays a branch. mergerfs then silently leaves that disk's files out of every listing, and
with the `pfrd` create policy it can put new files in that folder on the root disk. reverberator cannot tell a hidden
file from a deleted one, so:
- on the vault side, a scan can refuse a version, and a prune can remove copies whose next-version links sit on the
  missing disk;
- on the monitored side, a backup records the hidden files as deleted. Older versions keep them, but they age out as
  versions are pruned.

## The user's decisions (their words)

- Disk check: "Defer to round 9 (Recommended)", "Round 9 adds the check before scans and prunes."
- When a disk is missing: "Pause those jobs until it's back (Recommended)", "Each job on the pool waits, with a FAILED
  waiting marker as it does now for a missing disk: no backup, scan or prune until every disk is mounted again. Changes
  queue up and are caught up afterwards."
- The monitored pool too: "Yes, pause on either pool (Recommended)", "A job waits whenever a disk of its vault pool or its
  monitored pool is missing, so neither side's gap is ever recorded as deletions or acted on."
- Power loss: "Defer with the disk check (Recommended)", "Round 9's check that every disk is present closes the second
  half, plus an fsync of the vault folder after the link swap."
- Attributes after a move: "Defer to round 9 (Recommended)", "Round 9 replays attribute changes after moves, or verifies
  attributes for the paths a batch touched."
- Changes inside a moved folder: "Yes, include it (Recommended)", "Creates, modifies and attribute changes at or under a
  move's destination are replayed after the move, so the folder is moved, not copied again."
- Pruning's temporaries: "Next prune drops them, restore skips (Recommended)", "No extra walk. A temp lives until the
  next prune, usually the next backup, and is never written out by a restore." This replaces the deferral's "the job's
  scan".
- SnapRAID fix: "Known limitation, README says stop it (Recommended)", "Record it, and have the README say to stop
  reverberator (systemctl stop reverberator) until snapraid fix ends."
- Restore and history while a vault disk is missing: "Warn and name the disk (Recommended)", "Do the restore, print a
  warning naming the missing disk, and exit non-zero so a script notices."
- The playback: "Yes, write it up (Recommended)".

## Goals

### 1. A job pauses while a disk of its vault pool or its monitored pool is missing

- **Pools and disks.**
  - A pool is a `fuse.mergerfs` mount in `/proc/self/mountinfo` that holds a job's vault path or its monitored path.
  - Its disks are its branches: the `user.mergerfs.srcmounts` xattr of `<mount point>/.mergerfs`, split on `:`. It holds
    expanded absolute paths, with no globs and no `=RW` modes. That was checked live on all three pools, mergerfs 2.42.0.
  - Resolve each branch path (`realpath`) before testing it.
- **Missing.** A branch is missing when it is not a mount point, or when `os.statvfs` of it fails, as for a disk that
  failed but is still mounted. If the branch list itself cannot be read (EIO, ENOTSUP, or a mergerfs without
  `srcmounts`), the whole pool counts as not ready, and the reason names the pool.
- **A disk that comes back counts too.** Each check also compares every branch's mount id (field 1 of
  `/proc/self/mountinfo`, new on every mount) with the ids taken when the step it guards began. A disk that dropped and
  came back during a walk or a comparison therefore counts as missing for that step.
- **The pause.** While its vault pool or monitored pool has a missing disk, a job does not back up, prune or commit. It
  does not scan its vault while its vault pool has one.
  - It waits through the existing readiness flags and `wait_for_path`, logging the existing marker
    `reverberator job <name> FAILED: waiting <N> min for <path>: <reason>`. The reason names the pool and the missing
    disk(s), for example `disk /mnt/jank_data/a58 of pool /mnt/jank is not mounted`.
  - The pool state lives in the job's `vault_fs_flag` and `monitor_fs_flag`, so the watcher's own start waits too.
  - The watcher keeps queuing changes, and the job catches up once every disk is back.
  - When an alerted wait ends, one info line says the job goes on. RECOVERED stays for failed attempts only.
- **The checks.** These are live reads (the xattr, the mount test and the mount ids), not the monitor's cached flag,
  which can lag behind a slow `df`.
  - **At the start of every attempt,** and **before every batch.** The batch loop waits on the monitored flag beside its
    vault wait (about reverberator.py:3726).
  - **Right before a vault scan's deletions,** against the vault pool only. Round 8's order stays: the scan runs after
    the vault wait and before the monitored wait, so a monitored-pool gap does not stop a vault scan, which is safe with
    every vault disk present.
  - **In a prune, right before its `rm -rf` of the oldest version** (about :8912), after the walk, against the ids taken
    when the walk began. A missing disk ends the prune through `keep_oldest`, keeping the oldest version whole.
  - **Right before each backup's manifest commit.**
- **A disk lost mid-batch.**
  - When the vault pool loses a disk, the batch stops its copies (`stop_copies`) at once, so no new vault file lands on
    the root disk. Then it fails its attempt before deleting or committing anything.
  - A monitored-pool disk lost mid-batch fails the attempt at the next check.
  - The attempt's failure logs `FAILED: ...; retrying`. The next attempt waits with the waiting marker and, once every
    disk is back, makes a full comparison, as after any failed attempt.
- **Noticed on mount changes.** The filesystem-signature monitor's fingerprint of a path includes the mount ids of the
  path's pool branches, so a branch's unmount or mount makes it re-check, not only a change of the pool's own mount.
- **No change elsewhere.** Paths on filesystems that are not mergerfs behave exactly as now.

### 2. Vault folders are flushed on the disks themselves

mergerfs 2.42.0 does not implement fsyncdir. It returns ENOSYS, after which the kernel treats every later folder fsync
on that mount as done. So today's folder fsyncs on `/mnt/jank` reach no disk. That covers the change list's placement,
the salt file, and the new one after the link swap.

- Every place that fsyncs a vault folder calls one helper.
- For a path on a mergerfs pool, the helper fsyncs that folder on each branch where it exists. Otherwise it fsyncs the
  folder itself.
- `do_backup`'s commit gains an fsync of the job vault, through that helper, right after the `current_version` swap.

### 3. Changes after a move into a folder are replayed after the move

- **What goes wrong today.**
  - The collapse drops an attrib on a move's own target.
  - The replay runs creates, modifies and attribs before moves.
  - So `mv x d/x; chmod 600 d/x` loses the chmod until a full comparison.
  - `mv d e; echo > e/new` or `mv d e; chown e/y` makes `e/` before the move. The move then fails with
    IsADirectoryError, and reverberator copies the whole folder again from the live tree.
- **The fix.**
  - Every non-delete change (create, modify, attrib) at or under a path that a move in the same batch lands on, coming
    after that move, is replayed after the moves.
  - For the move's own target, the move step syncs metadata onto the moved entry when the live entry's metadata differs
    from what its chain end holds. That is the moved file, or a moved user link (lchown and lutimes only). No change-list,
    pending-transactions or history format changes.
- **The metadata rule is unchanged.** An attribute-only change carries the newest metadata onto the shared copy at the
  end of the chain, as the README documents for any attribute change. Older versions sharing that copy show it too.

### 4. Pruning's leftover temporaries are skipped by restore

A prune killed between its hard link and its rename leaves `.<hash>.reverberator-partial` beside a link in the next
version. The next prune's walk reuses it and consumes it. That prune runs at the job's next backup, because the oldest
version is still there.

Restore, meanwhile, never writes one out:
- An entry of that name form is pruning's temporary when it is the same inode (`same_inode`) as the copy a sibling chain
  link of the same folder resolves to. This is exact, needs no salt, and works for non-root restores and for prunes that
  ran without a salt.
- Anything else of that form is a user's file, and is restored as now.

### 5. Restore and history warn when a vault disk is missing

When the job vault's pool has a missing disk (the same test as Goal 1), `restore` and `history` still run, and:
- print one warning on stderr naming the missing disk(s), saying that what lives on it is not shown;
- exit non-zero, with a code the README documents.

`status` shows the pause through the job's state, as for any wait.

### 6. Version 0.45, the README and docs/limitations.md

- Set 0.45 in `reverberator.py` and `pyproject.toml`.
- In `docs/limitations.md`, remove the four round 9 entries, which this round does:
  - "A pool disk missing during a scan or a prune"
  - "current_version left behind by a power loss"
  - "Attribute changes after a move in the same batch"
  - "A prune's temporary file left in the next version"
- Add the user-approved known limitation **"A SnapRAID fix while reverberator runs"**:
  - what the operator sees: a replaced disk is mounted, so jobs resume while `snapraid fix` restores its files;
  - why: nothing tells a disk being rebuilt from one that is whole;
  - revisit when: it bites;
  - approved: 2026-10-23, "Known limitation, README says stop it (Recommended)".
- In the README:
  - update the "Known limits" lines;
  - add a line for the pause;
  - add a line for restore's warning and exit code;
  - add a line saying to stop reverberator (`systemctl stop reverberator`) before `snapraid fix`, and to start it after.

## Non-goals

- SnapRAID itself, and rebuilding a disk.
- Pools other than mergerfs.
- Inner mounts under a monitored path: they keep their own pause.
- The other known limitations the user approved on 2026-10-23.

## Anti-goals

- **Never treat a hidden file as deleted, or act on a vault while a disk is out.** A version recording a vanished disk's
  files as deletions, or a prune removing copies while a disk is out, is a failure even if every test passes.
- **Never write vault files onto the root disk** because a vault disk dropped.
- **Never block a job for a pool it doesn't use.**
- **Don't slow the normal backup.** The checks read one xattr, the mount table and a handful of `statvfs` calls, at the
  points above, never per file.
- **Don't keep a copy of the pool layout.** Branches come from mergerfs at check time, never from the rule file.

## Calls (the builder's, made here; to confirm with the user)

- "Missing" means not a mount point or `statvfs` fails, after resolving symlinks. There is no per-job switch.
- The pause also covers the commit step, so a disk lost mid-backup never commits a version made from a partial view.
- Mount ids are compared across each guarded step, to catch a disk that drops and comes back within it.
- The checks are live reads, not the cached flag.
- A monitored-pool gap does not stop the vault scan, which keeps round 8's order.
- An alerted wait that ends logs one info line, not RECOVERED.
- The fix for the move's own target is a metadata sync in the move step, with no format change. Metadata follows the
  existing shared-copy rule.
- Restore tells a temporary by inode, not by its salted name.

## Tests the change must add

- **A fake pool.** A control file with a `user.mergerfs.srcmounts` xattr (or a patched reader), branches as real
  folders, and patched mount tests and mount ids. With it:
  - A missing branch pauses the job with the waiting marker, on the vault side and on the monitored side.
  - While paused, the job does no backup, prune or commit, and no vault scan for a vault-side gap. Its watcher keeps
    queuing.
  - The branch coming back resumes the job and catches up the changes.
  - An unreadable branch list waits, with the pool named.
  - A branch that drops and comes back with a new mount id during a prune's walk keeps the oldest version.
- **A disk lost mid-batch:** copies stop, and the attempt ends before the scan's deletions, the prune's `rm -rf` and the
  commit. Test each point. No file is written into the branch's empty folder.
- **The flush helper:** a folder on a fake pool is fsynced on each branch holding it. The commit runs in the order
  prepare, manifest, swap, flush, place.
- **Changes after a move, each in one batch:**
  - `mv x d/x; chmod 600 d/x`
  - `mv x d/x; chown d/x`
  - an xattr change after a move
  - a user's link moved, then lchown'ed
  - `mv F p/q/F; chmod p/q/F/y`
  - `mv d e; chown e/y`
  - `mv d e; echo new > e/new`
  - `mv d e; echo changed > e/old`

  For each, the new version reads right. No IsADirectoryError appears, and no folder is copied again. Older versions
  follow the shared-copy rule.
- **Restore skips pruning's temporary:**
  - a prune killed after its link and before its rename, then a folder restore, writes no temp;
  - a user's file of the same name form, sharing no inode with a sibling chain link's copy, is restored;
  - the same without a salt file.
- **Restore and history with a missing vault disk:** a warning naming the disk, and the non-zero exit.
- **The ground-truth plugin and both full suites pass.** The live read-only scan of the 8 jobs still passes.
