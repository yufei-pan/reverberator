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
