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
