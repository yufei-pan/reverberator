# Round 11: mmap, a remembered sync failure, a chain length per job, rewrites made while down, no empty versions

Version 0.47. The five items the user deferred to round 11 on 2026-10-27 (docs/limitations.md), with the mechanisms the
user chose.

## The user's words

- mmap: "should we trust mtime change as indication of file is changed to just do the copy? this way we only do one read
  and one write not three reads and one write in most cases"; then, on keeping that rule though it does not see
  mmap-only writes: "Keep it, round 11 (Recommended)"; on a scheduled full comparison: "Configurable per job and default
  off"; its format: "A duration like 1d, 12h, 30m (Recommended)".
- The write error: "Defer to round 11 (Recommended)", on "a failed sync is remembered per disk until the next reboot (a
  marker under /run); while it is there, every comparison keeps that pool's copies unchecked, so the restart after the
  reboot reads them from disk".
- The chain length: "make this max chain length configurable? let's default to our current one and keep some notes about
  your case so user knows to change it on systems that may only want 20 linkx. and for users that do not intend to
  manually copy them, then maybe no link limit is acceptable." Then: "Per job, in the rule file (Recommended)".
- Rewrites made while down: "Defer to round 11 (Recommended)", on "A full comparison reads the whole file when its ctime
  is after the matched time but size and mtime are unchanged."
- The empty version: "Defer to round 11 (Recommended)", on "Drop delete entries of paths the vault no longer tracks
  before deciding a batch has work, so such a batch ends in 'No differences'."
- Round 11: "Yes, all five (Recommended)". The rule file: "Accept it as is (Recommended)" (missing columns mean the
  defaults; the daemon never rewrites the file).
- Standing: nothing is merged, pushed or restarted without the user; known limitations and deferrals need the user's OK.

## Goal 1: mmap writes

**1a. An attribute-only change whose mtime moved is copied.** Under Only Sync Attributes, an attribute-only change
(chmod, chown, xattr, touch) is synced onto the vault copy only when that copy holds the same contents as the live file
by the comparison's own test (same size, the same mtime, the same tail hash: `same_contents()`). When the live file's
mtime differs from the copy's, the file is copied. This replaces round 9's `record_vouches()` exception, which synced a
`touch -m` when the record's size and tail matched whatever the mtime: that exception is what puts an mmap write's new
mtime on the old copy and hides it from every later comparison. The size estimate and `batch_rewrites()` count these
copies (`attribs_to_copy()`).

- Cost (the user's trade): a touch or `rsync -t` of a big unchanged file copies it once, in that version; a copy is one
  read and one write, where comparing first would be three reads and a write whenever the content did change.
- A moved file's move-step sync keeps round 9's rule (it already requires `same_contents()`).

**1b. A scheduled full comparison per job, off by default.** A new optional rule-file column, `Full Comparison
Interval`, holds a duration: `1d`, `12h`, `30m`, `45s`, case and spaces ignored, a plain number read as hours; blank,
`0` or a missing column means off. Each job whose interval is set runs a full comparison of its whole tree that often,
counted from the end of its last full comparison (a restart's, a failed attempt's, an overflow's or a scheduled one), so
files that raise no event (an mmap-only writer) are compared by size and mtime. It goes through the existing full-scan
path (a `full_scan` event the backuper takes), with round 10's matched time bounding its xattr reads. A value the parser
cannot read fails the job as other bad rule cells do, naming the cell.

## Goal 2: a vault disk's failed sync is remembered until reboot

When the sync of a comparison fails on a branch (round 10's `sync_vault_filesystems()`), a marker is written under the
daemon's state folder (`/run/reverberator`, a tmpfs, so a reboot clears it), one per failed branch, naming the branch.
Before a comparison syncs, it checks for markers on any branch holding the job vault: with one there, that comparison
treats its sync as failed (its file records stay unchecked, one warning names the branch and says a reboot or removing
the marker clears it). After the reboot, the restart's full comparison reads the unchecked copies back from disk. The
README says how to clear a marker by hand once the disk is replaced without a reboot.

- Which branch failed must be known: the per-branch sync reports each branch's failure, not only the first error.
- A marker that cannot be written is logged; the comparison still keeps its records unchecked.

## Goal 3: the chain length, per job

A new optional rule-file column, `Chain Length`: the most links a new version may chain to a file's copy before it
copies it again. Blank or a missing column keeps today's rule (each file re-copied after 32-38 links, spread by its name
so not every file is copied in the same version); a number N sets the same spread just below N (the builder picks the
spread; today's is 32-38 for 40); `0` means no limit (chains as long as the versions kept). reverberator's own chain
followers (`chain_end()`, `read_vault_record()`, the restore resolver; today bounded by `MAX_CHAINED_LINKS` = 40) follow
whatever the job allows. The README notes why a host whose vault is read through the kernel (hand browsing, cp, other
tools) may want about 20: while mounts change on the host the kernel can count a chain's links twice.

- A job whose versions already hold chains longer than a newly lowered N re-copies those files at its next versions, as
  today's rule does when a chain passes the threshold.

## Goal 4: rewrites made while down that keep size and mtime

A full comparison (not a batch's check) that finds a regular file unchanged by size, mtime and tail hash, whose live
ctime is at or after the comparison's matched-time bound (round 10, the same bound as its xattr reads), compares the
whole live file with its vault copy (stopping at the first difference) and treats a difference as a modify. utime cannot
set ctime back, so a rewrite whose writer restores size and mtime is caught.

- Cost: one read of the file and its vault copy for each file whose ctime moved since the vault last matched the tree
  without a recorded change: chmods and chowns to the same values, link count changes, and such rewrites. A chown -R
  over a big tree made while nothing watched makes the next full comparison read all of it once (the matched time then
  moves past it). Stated in the README.

## Goal 5: no empty version after a carried move-out

Before a batch decides it has work, its delete entries of paths the vault does not track (no manifest row at or under
them) are dropped, so a batch whose only entries were such deletes ends in "No differences" through the collapsed-batch
comparison of its touched places, as an empty batch does today. Deletes of tracked paths are unchanged.

## Goal 6: version 0.47, docs

- `__version__ = 0.47`, pyproject `version = "0.47"`.
- docs/limitations.md: remove the deferred entries this round closes (the data-write error, the chain length, the rewrite
  made while down, the empty version); the mmap entry is rewritten by what is left (asked at the handoff, not written
  until the user agrees: a store into an already-dirty page that does not move mtime, mergerfs without passthrough or
  writeback cache, mmap-only writers when no scheduled comparison is set).
- README: the two new columns in the rule header's description, with their formats and defaults; the chain-length note;
  the touch-copies cost; the sync-failure marker; Goal 4's cost.
- LESSONS.md (agent-rules): an entry for the behaviour change in 1a (a touch now copies), which reverses round 9's call.

## Non-goals

- Rewriting the rule file (the user: accept it as is).
- Detecting mmap writes directly (no kernel interface does it cleanly; round 10's research).
- Any change-list, pending-batch or history format change.

## Constraints

- Work in a worktree (`.worktrees/round11`, branch `round11`); never in the live checkout; never under /mnt/jank,
  /mnt/impulse or /mnt/klein; never `sudo sysctl`; tests at 2 processes at most; both full suites pass.
- The rule file is parsed as today; the new columns are optional and read tolerantly (RULES.md: "What is accepted stays
  accepted").
- The user's rules: /mnt/optane/work/agent-rules/RULES.md.

## Left to the builder

The column names' exact spelling in the README's header line (the cells are read by position after Skip List File), the
marker file's name and content, the spread below N, and how the scheduled comparison's timer is kept (the watcher loop
or the backuper).
