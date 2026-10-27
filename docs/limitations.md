# Known limitations and deferred work

Each entry here has the user's OK. Reviewers read this file first and don't raise these entries again.

### A user's link written as its own path's chain link

- **Kind:** known limitation.
- **What the operator sees:** a symlink in the monitored tree whose text is exactly its own path's link to the previous
  version (for example `a/U -> ../../V<n-1>--<timestamp>/a/U`) is taken for the vault's own link. Pruning and restore then
  give a/U's own older copy in place of the link. Nothing beyond that one path is affected.
- **Why:** the vault holds nothing that tells such a link from the daemon's own. Telling it would need a new per-version
  record of user links, a new vault artifact.
- **Revisit when:** someone needs to back up symlinks of that exact form, which requires typing the newest version's
  folder name between two backups.
- **Approved:** 2026-10-22, the user's choice "Leave it (Recommended)" on the round 8 design's blind spot.

### World-readable vault database and change lists

- **Kind:** known limitation.
- **What the operator sees:** any local user can read `.reverberator_manifest.sqlite` and the `V<n>--…modified_contents.nsv`
  change lists in a job vault. Together they list every backed-up file name and its size, the passwords job's included.
- **Why:** making them root-only (0600) would leave only root able to run status, history and restore. The user chose to
  keep them readable.
- **Revisit when:** a vault is shared with users who must not see other jobs' file names.
- **Approved:** 2026-10-23, the user's choice "Known limitation".

### No flush before a prune's removal

- **Kind:** known limitation.
- **What the operator sees:** after a power loss in the middle of a prune on mergerfs, a link that was being replaced may
  come back in either form, old or new. No copy is lost, but a restore can show a dangling link for that file until the
  next full comparison.
- **Why:** flushing the whole pool before every prune would cost time on each backup, for a rare event that loses no copy.
- **Revisit when:** power losses during prunes are seen in practice.
- **Approved:** 2026-10-23, the user's choice "Known limitation (Recommended)".

### Size records rounded to 2 decimals

- **Kind:** known limitation, already in 0.43.
- **What the operator sees:** each version's size is stored rounded to 2 decimals in its change list's name (for example
  `11.54_MiB`). After a restart, the vault's total can be off by up to 0.5% per version, so a prune can remove the oldest
  version slightly early.
- **Why:** it is small, it errs toward removing early and never toward growing past the limit, and exact sizes would
  change the change-list name format.
- **Revisit when:** a vault's size limit needs to be met exactly.
- **Approved:** 2026-10-23, the user's choice "Known limitation (Recommended)".

### User symlinks past 40 hops when keep-N is 41 or more

- **Kind:** known limitation, already in 0.43.
- **What the operator sees:** with keep-N at 41 or more, an unchanged user symlink is chained through more than 40 links,
  so browsing the vault by hand through the kernel gives "too many levels of symbolic links" for it. Restore gives it back
  correctly. The live jobs keep 3 to 5 versions.
- **Why:** the re-copies every 32-38 hops that keep files under the kernel's limit apply to files only.
- **Revisit when:** a job keeps 41 or more versions and its vault is browsed by hand.
- **Approved:** 2026-10-23, the user's choice "Known limitation (Recommended)".

### A SnapRAID fix while reverberator runs

- **Kind:** known limitation.
- **What the operator sees:** a replaced disk is mounted, so jobs resume while `snapraid fix` restores its files.
- **Why:** nothing tells a disk being rebuilt from one that is whole.
- **Revisit when:** it bites.
- **Approved:** 2026-10-23, the user's choice "Known limitation, README says stop it (Recommended)".

### Kernels before 6.8 and the pool check

- **Kind:** known limitation.
- **What the operator sees:** on a kernel before 6.8, a disk of a pool swapped very quickly for another may not pause its
  jobs. This host runs 7.0.
- **Why:** statx gives no unique mount id before 6.8, so the check falls back to mountinfo ids, which the kernel reuses.
- **Revisit when:** reverberator runs on an older kernel.
- **Approved:** 2026-10-26, the user's choice "Known limitation (Recommended)".

### A disk that is dying but not yet failed

- **Kind:** known limitation.
- **What the operator sees:** jobs keep writing to a dying disk until its filesystem shuts down (XFS) or flags a
  checkpoint error (f2fs); only then do they pause, as for a missing disk.
- **Why:** catching it earlier needs SMART or I/O-error watching, which is a separate tool.
- **Revisit when:** a disk fails without its filesystem noticing.
- **Approved:** 2026-10-26, the user's choice "Known limitation (Recommended)".

### Two pools out at once are reported one after the other

- **Kind:** known limitation.
- **What the operator sees:** when a vault disk and a monitored disk are both missing, an idle or batching job's waiting
  marker names one pool; once that pool is back, a second marker names the other. Nothing is lost.
- **Why:** each wait is for one path, and a combined wait would add a part for a rare case.
- **Revisit when:** the two-step report confuses.
- **Approved:** 2026-10-26, the user's choice "Known limitation (Recommended)".

### Files written through mmap

- **Kind:** deferred (round 10).
- **What the operator sees:** a file written through mmap raises no inotify event. If its mode, owner or xattrs then
  change in the same batch, the version keeps its old bytes under the new metadata, and a full comparison does not see
  it either (same size, mtime as synced, same tail), until the file is written normally again. 0.44 did the same.
- **Why:** the only sure fix is reading whole files.
- **Revisit when:** round 10: look for a way to catch mmap writes, or to tell that a file is mmapped.
- **Approved:** 2026-10-26. The user: "let's defer. let's see if we can catch something, or if we can know if a file is
  mmaped".

### A file moved and then touched in one batch is copied again

- **Kind:** known limitation.
- **What the operator sees:** a file moved and then given a new mtime (`touch -m`, `rsync -t`) in the same batch is
  copied again whole by the check after the batch, and the size estimate does not count that copy.
- **Why:** letting a moved row vouch for its copy would weaken the guard that keeps a swap from putting one file's
  metadata on another's copy.
- **Revisit when:** it costs noticeable space.
- **Approved:** 2026-10-26, the user's choice "Known limitation (Recommended)".

### Swaps in one batch are repaired by copies

- **Kind:** known limitation.
- **What the operator sees:** a swap collapsed in one batch (`mv a t; mv b a; mv t b`) copies both files again instead of
  renaming them, and logs `Failed to move … delete & copy instead` at ERROR level (firewatcher does not alert on it). The
  result is right.
- **Why:** renaming them in one step would need a change-list format change.
- **Revisit when:** the change list's format changes for another reason.
- **Approved:** 2026-10-26, the user's choice "Known limitation (Recommended)".

### A move into a folder made after an earlier move in one batch

- **Kind:** known limitation.
- **What the operator sees:** `mv d e; mkdir e/sub; mv x e/sub/x` in one batch falls back to delete & copy for x, logging
  `Failed to move … delete & copy instead` at ERROR level (firewatcher does not alert on it), and x is copied once more.
  The result is right.
- **Why:** replaying such moves in batch order is a larger change to the replay for one extra copy in a rare order.
- **Revisit when:** it is seen often.
- **Approved:** 2026-10-26, the user's choice "Known limitation (Recommended)".

### One folder renamed back and forth thousands of times in one batch

- **Kind:** known limitation.
- **What the operator sees:** the batch's collapse slows: 12,500 round trips of one folder take 49 s, as every event
  inside it is carried through each rename. The watcher slows too, as each of those moves also walks the folder again:
  for a folder of 5,000 subfolders (37 ms a walk) they add about 460 s of watcher time. Normal use, even 50k moves of
  different paths, stays under a second.
- **Why:** a memo that fixes it does not fit in a small, clean change.
- **Revisit when:** a real workload does this.
- **Approved:** 2026-10-26, the user's choice "Known limitation (Recommended)".

### Size estimates leave out a version's own small blocks

- **Kind:** known limitation.
- **What the operator sees:** with a size limit, the estimate made before a backup leaves out the new version's own
  folders, links and xattr blocks (a few KB, at most ~77 KB in testing) and a change kept under a folder moved into a new
  folder (up to that file's size), so a vault can go over its limit by that much until the next prune. The sizes recorded
  after each backup are measured, so later prunes are right.
- **Why:** counting them would add estimates for a small, one-batch overshoot.
- **Revisit when:** a vault's limit is tight enough for it to matter.
- **Approved:** 2026-10-26, the user's choice "Known limitation (Recommended)".

### Changes made outside the watched folder

- **Kind:** known limitation.
- **What the operator sees:** an xattr-only change made outside the watched folder (straight onto a disk of a mergerfs
  pool, such as /mnt/impulse_data/<disk>/..., or a remote write on a network filesystem) raises no event, and once a
  later batch moves the vault's matched time past it, no full comparison reads it: that xattr is missing from the
  versions until the file changes again. Content changes are still caught, by size and mtime.
- **Why:** round 10's matched time bounds a full comparison's xattr reads to what changed since the vault last matched
  the whole tree, and that bound assumes every change goes through the watched folder.
- **Revisit when:** a job monitors a network filesystem, or files are changed on a pool's disks directly.
- **Approved:** 2026-10-27, the user's choice "Known limitation (Recommended)".
