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
- Standing: nothing is merged, pushed or restarted without the user; known limitations and deferrals need the user's OK.

## Goal 1: never create or write into a vault that is not there

**The check.** A vault path's disk counts as there unless /etc/fstab names a mount point that is the path or a folder
above it (the longest such one) and that mount point is not mounted now (the live mount table, as the daemon already
reads it). A path under no fstab mount point counts as there, as today (a vault on the root disk, or on a disk mounted
some other way). The fstab is read when needed (it is small); a missing or unreadable fstab names nothing. Mount points
are compared as fstab writes them (fstab escapes such as `\040` decoded), after realpath of the vault path's existing
part.

**Where it applies:**
- **The backuper's start** creates a missing Vault Path only when its disk is there. Otherwise it waits, as it waits for
  a vault filesystem that is not ready, with the FAILED: waiting marker naming the unmounted mount point, and creates the
  path once the mount is there (then the existing signature wait follows).
- **parse_rules** no longer creates a missing Vault Path. It fills an auto Vault File System Signature only when the
  vault path exists and its disk is there; otherwise the cell stays auto (the backuper creates the path when the disk is
  there, and the next start fills the signature from it). It still writes the row back for the cells it does fill.
- **A stop** (the backuper's hand-back, and a failed job's queue) writes no pending file when the job's vault path, or
  its disk, is not there: the queued changes are dropped with one log line, as the next start compares the whole tree
  anyway ("keep queued changes as a full-comparison request instead"). Round 11's narrower guard (a full_scan-only queue
  with the vault path absent) becomes part of this rule.

## Goal 2: a vouched attribute change reads nothing from the vault

Under Only Sync Attributes, when the replay syncs an attribute-only change onto a chain end whose record vouches for it
(`record_vouches()` with the chain end: the live file has the recorded size, mtime and tail, and the chain end has the
recorded size and mtime), the row is recorded at commit from that record's hash and the chain end's new metadata,
without hashing the copy again. Today the commit (`record_dirty_entries()` → `read_copied_record()` →
`read_vault_record()`) hashes every dirty row's chain end. The row keeps the record's unchecked flag. Rows not synced
this way are recorded as today.

## Goal 3: a delete whose removal fails fails the batch

The replay's delete (`delete_path()`) checks that each removal worked. A removal that fails (the entry is still there
afterwards, or the remover reports an error) fails the batch, as a failed copy does today: no version is committed, the
batch is handed back and retried. A removal of an entry that is already gone is not a failure.

## Goal 4: version 0.48, docs

- `__version__ = 0.48`, pyproject `version = "0.48"`.
- docs/limitations.md: remove the three deferred entries this round closes ("Writes under a vault that is not mounted",
  "A chmod reads each file's vault copy once at commit", "A delete whose rm fails leaves the entry in the version"), and
  their README Known-limits lines; README design lines for the fstab check, the stop rule, the commit-time record and
  the checked delete.

## Non-goals

- Mounts not named in /etc/fstab (systemd mount units, autofs, manual mounts): treated as there, as today.
- Any change-list, pending-batch, manifest or rule-file format change.

## Constraints

- Work in `.worktrees/round12`, branch `round12`; never in the live checkout; never write under /mnt/jank, /mnt/impulse,
  /mnt/klein or /etc; never read /etc/firewatcher/firewatcher.conf; never `sudo sysctl`; tests at 2 processes at most;
  both full suites pass (worktree venv and the live venv's older libraries).
- The user's rules: /mnt/optane/work/agent-rules/RULES.md.

## Left to the builder

How the fstab is parsed and cached, the exact log and marker wording, how a stop learns the vault is not there, how the
vouched record reaches the commit, and how a removal's result is checked (the remover may change, within the standard
library).
