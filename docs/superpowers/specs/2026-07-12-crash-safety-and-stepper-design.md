# Crash safety, incomplete versions, and stepper hardening

Date: 2026-07-12  
Status: approved for planning  
Scope: `reverberator.py` behavior + sample/docs text

## Goals

- Never treat an incomplete backup as a committed version.
- Prefer fast shutdown; clean up incomplete trees on the next startup.
- Make `decrement_stepper` abort-safe without cascading size/dict corruption.
- Avoid useless empty versions on restart; fail closed on watcher/backuper hard errors.
- Fix docs that disagree with limit-selection code.

## Non-goals / unchanged

- `only_sync_attributes` following vault symlinks into older versions remains intentional.
- `keep_one_complete_backup=False` (V0 may reference live source) remains intentional.
- Pending-resume **mtime gate** stays as today: resume pending only when the monitor tree looks unchanged; otherwise discard pending and rely on delta. Pending is a best-effort optimization (especially moves), not the correctness net.

---

## 1. Commit protocol and incomplete versions

### Commit rule

A vault version is **committed** only when its content file exists
(suffix `CONTENT_FILE_EXTENSION_NAME`, currently `.modified_contents.nsv`).
Successful `do_backup` then updates `current_version` to that directory.

Absence of a content file means the directory is **not** a version and must
not be indexed as one.

### During backup / SIGTERM

- Prefer **fast exit**. Do not block shutdown on deleting partial trees.
- If work stops early (`GREEN_LIGHT` cleared, or copy wait aborted before completion):
  - Do **not** write the content file.
  - Do **not** update `current_version` to the incomplete folder.
  - Leave the partial `V*` directory on disk (may be briefly useful to inspect).
  - Persist resume state: remaining `to_process`, and re-queue the in-flight `backupEntries` into pending-event form when aborting mid-backup (so the drained batch is not silently lost when the mtime gate still allows resume).

### On startup

- Scan the job vault. Any `V*` directory **without** a matching content file is incomplete → **delete it** and log.
- Do **not** invent empty content files for orphans (remove the current “promote orphan” path).
- Document that users who want to keep anything from a partial tree must copy it out before the next start.

### After cleanup / resume

- Apply existing pending mtime gate (unchanged).
- Next backup always bases off the last **committed** version.

---

## 2. `decrement_stepper` hardening

### Materialize

- Replace remove-then-rename with a single `os.rename(link_target, symlink_path)` so a failed rename leaves both sides intact (symlink still points at the old version file).

### On any materialize failure

- Do **not** `rm -rf` the oldest (reference) version.
- Put the reference entry back into `vault_info_dict` (it is popped at the start today; abort must restore it).
- Return `(0, 0)` so callers do not subtract phantom freed space.
- Do **not** rename/update the applying version’s content filename from a partial `new_size`.

### Immediate size refresh (chosen)

- Before continuing the backup after abort: recalculate applying and reference sizes from disk and refresh their content-file size metadata accordingly.

### Retry semantics

- Later steppers are idempotent: already-real files in the newer version are skipped; remaining symlinks finish draining; then delete the oldest.
- Partial drain is acceptable: paths already moved “live” in the newer version; the oldest is missing those paths until a successful purge.

---

## 3. Empty versions, exit paths, documentation

### Empty skip

After coalescing events or running delta, if `backup_entries` is empty:

- Do not create a new `V*`.
- Do not write a content file.
- Do not bump `current_version`.
- Return existing vault info unchanged.

### Watcher monitor-root init failure

If initializing watches for the monitor root fails, clear `GREEN_LIGHT` (or otherwise terminate the job) instead of busy-looping `watchFolder`.

### Backuper uncaught exception

Wrap `do_backup` (backuper main loop body) so an uncaught exception is logged and `GREEN_LIGHT` is cleared, allowing watcher/main to exit gracefully so systemd can restart.

### Documentation fixes

- Sample rule / comments: when multiple size/inode limits are given, the **stricter (smaller)** limit wins — match `get_backup_limits_from_str`.
- Document startup removal of incomplete `V*` dirs (no content file); advise copying out anything to keep before restart.

---

## Testing notes (for implementation plan)

- Abort mid-backup: no content file, `current_version` unchanged; pending contains in-flight work when applicable.
- Startup: incomplete `V*` deleted; committed versions untouched.
- Stepper: forced materialize failure → oldest retained on disk and in dict; sizes recalculated; no `rm -rf`.
- Empty delta/events → no new version directory.
- Backuper exception / watch init failure → process exits via `GREEN_LIGHT`.

## Out of scope for this change set

- Full mid-`cp` byte-level pause/resume.
- Reusing incomplete trees as scratch for the next version (discarded for complexity; delete on startup instead).
- Changing pending mtime-gate policy.
- Changing attrib-through-symlink or incomplete-initial-backup reference semantics.
