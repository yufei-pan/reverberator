# Round 9: pool disks, attributes after moves, pruning's temporaries (0.45)

## Intent

Round 9 does the three items the user deferred on 2026-10-23 (`docs/limitations.md`), plus one the user added while
this design was being discussed.

The live vaults sit on `/mnt/jank`, a mergerfs pool of six XFS disks (`/mnt/jank_data/{4f0,850,89d,a02,a58,e82}`, with
SnapRAID parity). The Nextcloud data that several jobs back up sits on `/mnt/impulse`, a mergerfs pool of
`/mnt/impulse_data/*`.

When one disk of a pool is missing, its mount point is an empty folder on the root filesystem. mergerfs then silently
leaves that disk's files out of every listing, and with the `pfrd` create policy it could even create new files on the
root disk. reverberator cannot tell a hidden file from a deleted one, so:
- on the vault side, a scan can refuse a version, and a prune can remove copies whose next-version links sit on the
  missing disk;
- on the monitored side, a backup records the hidden files as deleted. Older versions keep them, but they age out as
  versions are pruned.

## The user's decisions (their words)

- Disk check: "Defer to round 9 (Recommended)". The option read: "Round 9 adds the check before scans and prunes."
- When a disk is missing: "Pause those jobs until it's back (Recommended)". The option read: "Each job on the pool waits,
  with a FAILED waiting marker as it does now for a missing disk: no backup, scan or prune until every disk is mounted
  again. Changes queue up and are caught up afterwards."
- The monitored pool too: "Yes, pause on either pool (Recommended)". The option read: "A job waits whenever a disk of its
  vault pool or its monitored pool is missing, so neither side's gap is ever recorded as deletions or acted on."
- Power loss: "Defer with the disk check (Recommended)". The option read: "Round 9's check that every disk is present
  closes the second half, plus an fsync of the vault folder after the link swap."
- Attributes after a move: "Defer to round 9 (Recommended)". The option read: "Round 9 replays attribute changes after
  moves, or verifies attributes for the paths a batch touched."
- Pruning's temporaries: "Defer to round 9 (Recommended)". The option read: "Round 9 makes restore and the job's scan
  recognise and drop pruning's own temporaries."
- The playback of this design: "Yes, write it up (Recommended)".

## Goals

### 1. A job pauses while a disk of its vault pool or its monitored pool is missing

- **Which pools.** A pool is a mergerfs mount, `fuse.mergerfs` in `/proc/self/mountinfo`, that holds a job's vault path
  or its monitored path. Its disks are its branches: the `user.mergerfs.srcmounts` xattr of the pool's control file
  `<mount point>/.mergerfs`, split on `:`.
- **Missing.** A branch is missing when its path is not a mount point. The empty-folder state is exactly that. A branch
  that cannot be looked at counts as missing too.
- **Pause.** While any branch of a job's vault pool or monitored pool is missing, the job does not back up, scan its
  vault, prune or commit.
  - It waits as it waits today for a filesystem that is not ready, through the same readiness flags and `wait_for_path`,
    logging the existing marker `reverberator job <name> FAILED: waiting <N> min for <path>: <reason>`. The reason names
    the pool and the missing disk(s), for example `disk /mnt/jank_data/a58 of pool /mnt/jank is not mounted`.
  - The watcher keeps queuing changes, as it does while a filesystem is not ready, and the job catches up when every disk
    is back.
- **When it is checked.**
  - At every point where the job checks today that its filesystems are ready.
  - Right before each vault scan's deletions.
  - Right before each prune.
  - Right before each backup's commit, the manifest commit step.

  A disk lost in the middle of a backup ends that attempt before it deletes or commits anything. The next attempt waits.
- **Noticed when the mount table changes.** The filesystem-signature monitor already re-checks on every change of the
  mount table. A branch's unmount or mount must make it re-check the pool's readiness, not only changes of the pool's own
  mount.
- **Pools that are not mergerfs** behave exactly as now. So do jobs whose paths sit on no pool.
- **Recovery is automatic.** When every branch is mounted again, the flag is set, the job resumes and its backlog is
  caught up. The existing RECOVERED marker follows the next commit.

### 2. The vault folder is flushed after the current_version swap

In `do_backup`'s commit, after `current_version` is swapped (step 3), fsync the job vault folder before the change list
is placed (step 4). On mergerfs, fsyncdir reaches the branches; the final round 8 review confirmed it works on
`/mnt/jank`.

Together with Goal 1, this closes the deferred "current_version left behind by a power loss" entry.

### 3. Attribute changes after a move in the same batch are kept

Today, the collapse drops a later attrib event when the batch has a move, and the replay applies every attrib before
every move. A moved chain link's metadata step is skipped, and the verification compares without attributes. So
`mv x d/x; chmod 600 d/x` in one batch leaves the new version with x's old mode. The same goes for chown, setxattr, a
user's symlink moved then chowned, and a folder moved with a chown inside it.

The fix: attribute events (chmod, chown, utime, xattr) at or under a path that a move in the same batch lands on, and
coming after that move, are kept by the collapse and replayed after the moves. Their metadata is synced onto the moved
entry in the version being written: the moved file, the moved user link (lchown and lutimes only), or the entries under
a moved folder.

The same reordering removes a related robustness issue, with the same cause. When an attrib creates a move's destination
folder before the move runs (`mv d e` plus `chown e/y` in one batch), the move fails with IsADirectoryError, logs a
traceback and falls back to a copy.

### 4. Pruning's leftover temporaries are recognised and dropped

A prune killed between its hard link and its rename leaves `.<hash>.reverberator-partial` beside a link in the next
version. The name is `prune_link_path(link, copy_st, salt)`: a keyed hash of the link's name and the copy's inode under
the job's `.reverberator_prune_salt`.

- **Restore recognises them and never writes them out.** For an entry of that form in a version folder being restored,
  restore recomputes the name for each sibling chain link of that folder from the copy it names and the job's salt. A
  match is pruning's temporary, and is skipped. Anything else of that form is a user's file and is restored as now.
- **They are dropped by the next prune's walk, which already reuses them.** It runs at the job's next backup, because the
  oldest version is still there. The job's vault scan does not walk versions, so it does not look for them; see Calls.

### 5. Version 0.45, and docs/limitations.md

- Set 0.45 in `reverberator.py` and `pyproject.toml`.
- In `docs/limitations.md`, update the four round 9 entries ("A pool disk missing during a scan or a prune",
  "current_version left behind by a power loss", "Attribute changes after a move in the same batch", "A prune's
  temporary file left in the next version") to say they are done, or remove them. Update the README's "Known limits"
  lines the same way. Add a README line for the pause.

## Non-goals

- SnapRAID itself, and rebuilding a disk.
- Checking pools other than mergerfs (for example LVM or btrfs RAID).
- Inner mounts under a monitored path: they keep their own pause, as today.
- The known limitations the user approved on 2026-10-23 stay as they are.

## Anti-goals

- **Never treat a hidden file as deleted, or act on a vault while a disk is out.** A version recording a vanished pool
  disk's files as deletions would be a failure, even if every test passed.
- **Never block a job forever for a pool the job doesn't use,** or for a branch that mergerfs no longer lists.
- **Don't slow the normal backup.** The branch check reads one xattr and stats a handful of mount points. It runs at the
  points above and on mount table changes, never per file.
- **Don't add a moving part that has to be kept in step with mergerfs's config.** The branches come from mergerfs at
  check time, never from a copy in the rule file.

## Calls (the builder's, made here; to confirm with the user)

- **"Missing" means "not a mount point".** A branch configured as a plain folder on purpose, not a mount, would count as
  missing forever. None of the live pools has one, since all eight branches are XFS mounts. The rule file gets no
  per-job switch: "Fewer moving parts".
- **The pause also covers the commit step,** not only scans and prunes, so a disk lost mid-backup never commits a
  version made from a partial view.
- **The job's vault scan does not look for pruning's temporaries.** Finding them means walking whole versions, about
  140K entries for `work`, at every scan. The next prune's walk already finds and consumes them, and restore skips them
  in the meantime. The user's deferral named "the job's scan"; this changes where the dropping happens, not the result.
- **Attributes after a move are replayed** rather than added to the verification: one change fixes both the lost
  metadata and the IsADirectoryError fallback.

## Tests the change must add

- **A fake pool.** A mergerfs-like layout in tests: a control file with a `user.mergerfs.srcmounts` xattr, or a patched
  reader, and branches as real folders with patched mount-point answers.
  - A missing branch pauses the job with the waiting marker.
  - The job does no scan, prune or commit while the branch is missing.
  - Its watcher keeps queuing.
  - Restoring the branch resumes the job and catches up the changes.
  - Cover both the vault side and the monitored side.
- **A disk lost mid-backup:** the attempt ends before the scan's deletions, the prune, and the commit, each tested.
- **The fsync after the swap:** assert the commit order prepare, manifest, swap, fsync of the job vault, place.
- **Attributes after a move:**
  - `mv x d/x; chmod 600 d/x`;
  - `mv x d/x; chown d/x`;
  - an xattr change after a move;
  - a user's link moved, then lchown'ed;
  - `mv F p/q/F; chmod p/q/F/y`;
  - `mv d e; chown e/y`, with no IsADirectoryError.

  Each in one batch: the new version holds the new metadata, and every older version is unchanged.
- **Restore skips pruning's temporary:** a prune killed after its link and before its rename, then a folder restore of that
  folder writes no `.reverberator-partial`. A user's file of the same form, matching no sibling link, is restored.
- **The ground-truth plugin and both full suites pass.** The live read-only scan of the 8 jobs still passes.
