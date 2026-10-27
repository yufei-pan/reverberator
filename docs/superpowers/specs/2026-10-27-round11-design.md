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
- After the spec check (2026-10-27): a plain number in the interval column: "Seconds, like its neighbours (Recommended)";
  a bad new cell: "Log an error, use the default (Recommended)"; a mid-file write error after the reboot: "Known
  limitation (Recommended)"; an alert for a failed vault sync: "Yes, with a new firewatcher pattern"; the whole-file check
  for rewrites made while down (Goal 4): "why do we bother?", then "Drop it, known limitation (Recommended)".
- Standing: nothing is merged, pushed or restarted without the user; known limitations and deferrals need the user's OK.

## Goal 1: mmap writes

**1a. An attribute-only change whose mtime moved is copied.** Under Only Sync Attributes, an attribute-only change
(chmod, chown, xattr, touch) is synced onto the vault copy only when the live file's mtime equals the recorded one, by
either path the code has: `record_vouches()` (the cheap path, which reads only the live file) gains that requirement, and
`same_contents()` already has it. When the live mtime differs, the file is copied. Before, `record_vouches()` vouched
for a `touch -m` whatever the mtime: that is what puts an mmap write's new mtime on the old copy and hides it from every
later comparison. The size estimate and `batch_rewrites()` count these copies (`attribs_to_copy()`).

- Cost (the user's trade): a touch or `rsync -t` of a big unchanged file copies it once, in that version; a copy is one
  read and one write, where comparing first would be three reads and a write whenever the content did change.
- A moved file's move-step sync keeps round 9's rule (it already requires `same_contents()`).

**1b. A scheduled full comparison per job, off by default.** A new optional rule-file column (column 13), `Full
Comparison Interval`, holds a duration: `1d`, `12h`, `30m`, `45s`, case and spaces ignored, a plain number read as
seconds like the snapshot-interval columns beside it; blank, `0` or a missing column means off. Each job whose interval
is set runs a full comparison of its whole tree that often, counted (monotonic, in memory) from the end of its last full
comparison of any kind; a restart always makes one. The timer lives in the backuper's idle wait: once the interval has
passed it appends a `full_scan` and goes at once, without waiting for the tree to be quiet (in the watcher it would wait
for the quiet delay, 8-12 h on the Nextcloud jobs). A running batch delays it; a job waiting for its vault postpones it.
It goes through the existing full-scan path, with round 10's matched time bounding its xattr reads. A cell that cannot
be read logs an error naming the cell and the accepted format, and the job runs with the default (off).

## Goal 2: a vault disk's failed sync is remembered until reboot

When the sync of a comparison fails on a branch (round 10's `sync_vault_filesystems()`), a marker is written under the
daemon's state folder, one per failed branch, naming the branch and holding the boot id
(`/proc/sys/kernel/random/boot_id`): a marker from another boot is ignored (and may be removed), so "until reboot" holds
even when `$REVERB_STATE_DIR` is not a tmpfs. Before a comparison stores a checked record, it still syncs every branch (a
second disk's error then gets its own marker) and treats its sync as failed when any branch holding the job vault has a
marker of this boot: its file records stay unchecked. After the reboot, the restart's full comparison reads the
unchecked copies back from disk. The README says how to clear a marker by hand once the disk is replaced without a
reboot, and that while a marker stands every comparison reads the unchecked copies' tails again.

- The per-branch sync returns each branch's result, not only the first error (`on_vault_branches()` raises the first).
- **The alert (the user's choice):** when a marker is first written, the daemon logs one line of a new form,
  `reverberator job <name> VAULT WRITE ERROR: disk <branch> failed a sync (<error>); its copies stay unchecked until a
  reboot`, and the repo's firewatcher pattern file (firewatcher/reverberator.regex) gains a pattern for it. Installing
  that pattern in /etc/firewatcher/patterns.d and restarting firewatcher is a deploy step, done with the user's OK at the
  merge.
- A marker that cannot be written is logged; the comparison still keeps its records unchecked.

## Goal 3: the chain length, per job

A new optional rule-file column (column 14), `Chain Length`, read like the kernel's link budget, as today's default is:
N means a path into the vault may meet at most N links, two kept for the `current_version` link and a user's own link,
so each file is re-copied after a number of links from max(1, N-8) to N-2, spread by its name so not every file is
copied in the same version. Blank or a missing column is 40 (today's 32-38); N below 3 is read as 3 with the error a bad
cell gets; `0` means no limit (chains as long as the versions kept). reverberator's own chain followers then need no
limit: `chain_end()` and the restore resolver are already bounded by the version count, `read_vault_record()` is bounded
the same way ("each hop names an older version"), and `MAX_CHAINED_LINKS` goes. The two comparison steps that follow
vault links through the kernel, `kernel_cannot_follow()` (os.path.exists) and `xattrs_differ()` (listxattr through the
links), resolve the chain end themselves, and only a really broken link (ENOENT) counts as "cannot follow"; this also
stops today's spurious re-copies when mount churn makes the kernel count a chain over ~20 links twice. `recopy_rels()`'
early exit uses the job's minimum. The README notes why a host whose vault is read through the kernel (hand browsing,
cp, other tools) may want about 20, and that lowering N makes the files whose chains are now too long due at the next
versions at once.

## Goal 4 (dropped by the user)

The whole-file check for rewrites made while down was dropped ("why do we bother?", then "Drop it, known limitation
(Recommended)"): the case is rare and making it affordable needed three more parts. It is written down as a known
limitation (Goal 6).

## Goal 5: no empty version after a carried move-out

Before a batch decides it has work (do_backup's else-branch, before `if not backup_entries:`), its delete entries of
paths the vault does not track (no manifest row at the path, at the path with `/`, or under it) are dropped, so a batch
whose only entries were such deletes ends in "No differences" through the collapsed-batch comparison of its touched
places, as an empty batch does today. Only when the manifest describes the latest version (`manifest.describes()`); with
a stale manifest the deletes stay, as today. Deletes of tracked paths are unchanged.

## Goal 6: version 0.47, docs

- `__version__ = 0.47`, pyproject `version = "0.47"`.
- docs/limitations.md: remove the deferred entries this round closes (the data-write error, the chain length, the empty
  version); turn "A rewrite made while down that keeps size and mtime" into a known limitation (approved 2026-10-27,
  "Drop it, known limitation (Recommended)"); add "A write error in the middle of a copy after the reboot" (the restart's
  read-back checks size, mtime and the last 64 KiB, so a mid-file page lost to a write error passes; approved 2026-10-27,
  "Known limitation (Recommended)"); the mmap entry, the "moved and then touched" entry (a touch now always copies) and
  the chain-length entry's "reverberator follows chains itself" sentence are rewritten at the handoff, with the user's
  OK.
- README: the two new columns (13 and 14) with their formats and defaults; the chain-length note; the touch-copies cost;
  the sync-failure marker, its alert line and how to clear it.
- The rule file: a file with a 12-column header (or any known prefix of 12 or more) is read as is, every row padded to 14
  cells (`correctColumnNum=14`, the file's own header passed as the known prefix), and new cells under a 12-cell header
  are read; rows the parser rewrites for filled-in auto cells keep the cell count they were written with; the round 1
  11-to-12 header upgrade keeps its old form; the sample rule file (`--drop-sample-rule`) gets the 14-column header and
  description rows; `ReverbRule` has defaults for the two new fields.
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

The marker file's name and format, and the exact README wording.
