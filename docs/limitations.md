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

### A pool disk missing during a scan or a prune

- **Kind:** deferred (round 9).
- **What the operator sees:** with one mergerfs disk of the vault pool out, its change lists, `current_version` or folders
  can be hidden. A job then stops with `reverberator job <name> FAILED: ...` until the disk is back, or until it is fixed by
  hand. A prune that runs while a disk is out could still remove copies of the oldest version whose next-version links sit
  on the missing disk.
- **Why:** the scan refuses anything it cannot be sure of, but nothing checks that every disk of the pool is present
  before a scan or a prune.
- **Revisit when:** round 9, by checking that every branch of the pool is present (mergerfs `srcmounts`) before each scan
  and each prune, and waiting while one is missing.
- **Approved:** 2026-10-23, the user's choice "Defer to round 9 (Recommended)".

### Attribute changes after a move in the same batch

- **Kind:** deferred (round 9). This was already in 0.43.
- **What the operator sees:** a file moved and then chmod'ed, chown'ed or given new xattrs in the same batch (for example
  `mv x d/x; chmod 600 d/x`) keeps its old mode, owner and xattrs in new versions until the next full comparison. That
  comparison runs at a restart, a failed attempt or an inotify overflow, so it can be weeks away.
- **Why:** the replay applies every attribute change before every move, and the check after a batch compares content,
  not attributes.
- **Revisit when:** round 9, by replaying attribute changes at or under a move's destination after the moves, or by
  comparing attributes for the paths a batch's attribute events touched.
- **Approved:** 2026-10-23, the user's choice "Defer to round 9 (Recommended)".

### World-readable vault database and change lists

- **Kind:** known limitation.
- **What the operator sees:** any local user can read `.reverberator_manifest.sqlite` and the `V<n>--…modified_contents.nsv`
  change lists in a job vault. Together they list every backed-up file name and its size, the passwords job's included.
- **Why:** making them root-only (0600) would leave only root able to run status, history and restore. The user chose to
  keep them readable.
- **Revisit when:** a vault is shared with users who must not see other jobs' file names.
- **Approved:** 2026-10-23, the user's choice "Known limitation".

### current_version left behind by a power loss

- **Kind:** deferred (round 9, with the pool disk check).
- **What the operator sees:** after a power loss, `current_version` can name the version before the newest one, because
  the link and the change list may sit on different mergerfs disks. If a disk then also hides the newest change list, the
  scan could take that newest version for a crashed attempt and remove it.
- **Why:** nothing flushes the vault folder between the link swap and the list's placement. The second half needs a
  disk to be missing, which round 9's disk check closes.
- **Revisit when:** round 9: the disk check, plus an fsync of the job vault after the link swap.
- **Approved:** 2026-10-23, the user's choice "Defer with the disk check (Recommended)".

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

### Two kills in a new job's first two backups

- **Kind:** known limitation.
- **What the operator sees:** a brand-new job whose first backup is killed between its change list and its first
  `current_version`, and whose second backup is then killed between its manifest's commit and its change list, stops with
  `reverberator job <name> FAILED: ...` until V1's folder is removed by hand. Nothing is lost.
- **Why:** that state cannot be told from a mergerfs disk hiding a committed version's list, so the scan refuses rather
  than guess. Each window is a few milliseconds wide.
- **Revisit when:** it is seen in practice.
- **Approved:** 2026-10-23, the user's choice "Known limitation (Recommended)".

### User symlinks past 40 hops when keep-N is 41 or more

- **Kind:** known limitation, already in 0.43.
- **What the operator sees:** with keep-N at 41 or more, an unchanged user symlink is chained through more than 40 links,
  so browsing the vault by hand through the kernel gives "too many levels of symbolic links" for it. Restore gives it back
  correctly. The live jobs keep 3 to 5 versions.
- **Why:** the re-copies every 32-38 hops that keep files under the kernel's limit apply to files only.
- **Revisit when:** a job keeps 41 or more versions and its vault is browsed by hand.
- **Approved:** 2026-10-23, the user's choice "Known limitation (Recommended)".

### A kill between the link swap and the change list's placement

- **Kind:** known limitation.
- **What the operator sees:** if the daemon is killed in the few calls between moving `current_version` to a new version
  and placing its change list, that job stops with `reverberator job <name> FAILED: ...`. The message says to remove that
  version's folder by hand once every disk of the vault is there. Nothing is lost.
- **Why:** the stop is what keeps a committed version whose list a missing disk hides from being taken for a crash.
- **Revisit when:** round 9's disk check is in place, which may let this state be cleaned up automatically.
- **Approved:** 2026-10-23, the user's choice "Known limitation (Recommended)".

### A prune's temporary file left in the next version

- **Kind:** deferred (round 9).
- **What the operator sees:** a prune killed between its hard link and its rename leaves a hidden
  `.<hash>.reverberator-partial` in the next version. The next prune of that version uses and removes it. Until then, a
  restore of that folder also writes out the hidden extra file.
- **Why:** neither restore nor the job's scan recognises pruning's own temporaries yet.
- **Revisit when:** round 9: make restore and the job's scan recognise and drop them.
- **Approved:** 2026-10-23, the user's choice "Defer to round 9 (Recommended)".

### A SnapRAID fix while reverberator runs

- **Kind:** known limitation.
- **What the operator sees:** a replaced disk is mounted, so jobs resume while `snapraid fix` restores its files.
- **Why:** nothing tells a disk being rebuilt from one that is whole.
- **Revisit when:** it bites.
- **Approved:** 2026-10-23, the user's choice "Known limitation, README says stop it (Recommended)".
