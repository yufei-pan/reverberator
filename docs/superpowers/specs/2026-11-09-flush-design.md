# The daemon's vault syncs go through handles opened before its writes

For the release after 0.55.2. Branch flush, from r0552 at ab6e3fa (0.55.2 is not merged yet). It closes the deferred entry in docs/limitations.md, "Another program's sync can take a vault disk's write error from the daemon". Section 4 is a question for the user; the build's first two tasks don't wait for the answer.

## The user's words

Their goals, verbatim:
- "I want this to be as light and as fast as possible... cause it is an backup solution, so it is designed to always in run the background. so every little bit will sum up to a lot over days month years."
- "simpler and smarter is better"
- "one of the core for reverberator is reuse existing linux features and easy browse / restore."

Their pick, 2026-11-09, "Next release after 0.55.2 (Recommended)". The question was: "The daemon's VAULT WRITE ERROR alarm has a blind spot, in 0.55.1 today: before each commit the daemon syncs the vault's disk through a handle it opens right then. If another program synced that disk first and took the write error, the daemon hears nothing, gives no alert, and commits a version whose files may not be on disk. … The fix: each batch opens its vault disks' handles before its first copy and syncs through them, as the 0.55.2 restore now does. It touches the commit flush, so the power-loss and pool-cut VM gates apply. When should it ship?" The option said: "Its own small round in its own worktree, started now alongside the watcher round, with its own reviews and VM gates. It ships as the next release after 0.55.2, before or after the watcher round, whichever is ready first. 0.55.2 ships without waiting for it."

Still standing, for 0.55.2's restore: "Recopy after a kill (Recommended)": "… never wrong data."

Their picks on this spec's two questions, 2026-11-09:
- On the leftovers of a cut batch (section 4): "Copy again, marker goes (Recommended)". The option said: "A batch never commits past a failed sync of its own; a comparison's failed sync now fails the attempt too, then it retries. After a cut, the next attempt copies the cut batch's files again instead of reading 64 KiB of each back. Every copy a version commits is then written while its own handles were open. The cross-job markers, their locks and the restore's report to the daemon all go: less code. It closes the deferred entry and four limitations. Cost only after a cut or a write error." So the round builds option 1 (tasks 3 and 4), and the approved limitation "A comparison's failed sync does not fail the attempt" goes with the user's pick.
- On a copy made where the vault refused a hard link (section 10, question 2): "Known limitation (Recommended)". The entry: what the operator sees (an older version's file can hold lost bytes with no alert, only where the vault refused a hard link and another program synced the disk at the wrong moment), why (no other copy of those bytes exists), and revisit if the vault ever shows refused hard links. The question told the user the main session had not checked whether their mergerfs pool ever refuses a hard link; the build checks it (section 9).

## Why

- **The kernel's rule.** Linux keeps a filesystem's writeback errors in `sb->s_wb_err`.
  - `do_dentry_open()` samples it into each file it opens. `errseq_sample()` gives 0 while no one has seen the newest error, so that file's first check reports it.
  - `syncfs()` reports what changed since its file's sample, and marks the error seen.
  - So a syncfs reports an error once to each file that was open when it happened. A file opened later hears of it only while no syncfs has seen it.
  - Source: fs/open.c, fs/sync.c and lib/errseq.c, read but not run. The probe in section 6 checks it on the VM's kernel.
- **What the daemon does today.** Every daemon vault sync goes through `syncfs_folder()`, which opens the folder at the moment of the sync. Its callers are `sync_vault_filesystems()`, `check_vault_sync()` and `flush_vault_disks()`.
- **What goes wrong.** When another sync meets the error first, the daemon gets 0. That other sync can be `sync -f`, any tool that calls syncfs, or a reverberator restore's sync. The daemon then:
  - raises no VAULT WRITE ERROR and writes no marker;
  - commits a version over copies that may not be on disk;
  - may later read those copies back from the page cache and record them as checked.
- **The restore already does it right.** 0.55.2's `open_restore_disks()` opens its handles before the first copy, and `sync_restore()` syncs through them.

## 1. Every vault sync, what it vouches for, and its unit

| Sync | Code | What it vouches for | Unit (section 2) |
|---|---|---|---|
| Commit flush | `do_backup()` → `flush_copies()` → `flush_or_fail()` → `flush_vault_disks()` | The batch's copies, and a roll-forward's tree. They must be on disk before the change list's fsync (a checkpoint) and the manifest's commit. It is skipped when a comparison's clean sync came after the last copy (`copies_unsynced`). | `do_backup()`'s |
| A comparison's sync | `compare_scopes()` → `check_vault_sync()`, at the first copy it would record as checked | The copies it read back, before they are recorded as checked. A clean sync also clears `copies_unsynced`. | `do_backup()`'s (delta, roll-forward, verification), or `compare_scanned_folders()`'s |
| Hand-over | `hand_over()`: `TreeWriter.flush()` ×3 on two renames; `pre_record()`, `flush_if_needed()` | On a pool or a filesystem with no exchange: the skeleton, the tree's rename and the records are on every disk before the next rename or change. | `do_backup()`'s |
| Prune, design R | `prune_version()` → `flush_or_fail()`, on a pool | The rename into staging is on every disk before `rm -rf` | `do_backup()`'s (`remove_oldest()`) |
| Prune, 0.54 | `decrement_stepper()` → `flush_disks()` ×2, on a pool | The walk's links before the removal; the removal before the lists go | `convert_at_start()`'s (`finish_cut_prune()`) |
| Conversion | `materialize_version()` → `flush_or_fail()` ×4 (pool or no exchange); `migrate_job_vault()`, once per version | The built tree is on every disk before the version moves. Each version's swap and times are on disk before the manifest says it is done. | `convert_at_start()`'s |
| Scan | `repair_pool_vault()` → `flush_or_fail()` ×2; `remove_stale_change_lists()` → `flush_vault_disks()` (pool) | The repairs' renames before the read. A folder's removal before its list goes. | `get_vault_info()`'s, or the enclosing unit's |
| Restore | `sync_restore()` | Already through `open_restore_disks()` | unchanged |

**These need nothing:**
- The per-file fsyncs: `fsync_path()`, `fsync_vault_folder()`, the manifest's sqlite and the change list.
  - A file's own error is kept on its inode, in `mapping->wb_err`. Source: read, not run; the probe checks it.
  - A syncfs does not mark that error seen. It advances only the superblock's error, and `sync_inodes_sb()` waits with `filemap_fdatawait_keep_errors()`.
  - Only an fsync of that same file would mark it seen, and nothing else fsyncs the vault's files.
- The CLI. The restore is the only command that syncs anything.

## 2. The handles

- **A unit of vault work.**
  - Each of `do_backup()`, `compare_scanned_folders()`, `get_vault_info()` and `convert_at_start()` opens the job vault's handles at its start, before its first vault write. It closes them when it returns or raises.
  - `do_backup()` opens its unit right after it makes the job vault, when it has to make it.
  - A call made while a unit for that job vault is already open uses that unit and closes nothing. An example is `get_vault_info()` inside `do_backup()`.
  - Units are kept by job vault, normalised as `PoolGuard` normalises paths. Every sync below them finds its unit with no change of signature: `sync_vault_filesystems(job_vault, job_name)` keeps its arguments.
  - These four functions are the only ways into the sync sites of section 1. The grep of every caller says so.
- **One handle per disk,** named as `vault_disks()` names disks. The markers and `VAULT_SYNC_LOCKS` use the same names.
  - Off a mergerfs pool: one fd of the job vault.
  - On a pool: for each disk the pool lists, an fd of the first of its branches that opens. That is the branch root, as `open_restore_disks()` opens it, so a copy that lands on a disk the job vault was not on yet is still covered. Share that function's core if the code comes out simpler.
  - The mount table is read once, when the unit opens.
  - A handle that cannot be opened keeps its OSError, and every sync of that disk in the unit raises it.
  - If the pool's disks cannot be listed, every sync of the unit raises that error, as today's sync does.
- **A sync** (`sync_vault_filesystems()`) goes through the unit's handles and never opens a path. `syncfs_folder()` goes.
  - **Off a pool,** it lists nothing and uses the unit's one handle. The batch's answer to "is it on a pool?" already holds for the whole batch (`on_pool` in `do_backup()`).
  - **On a pool,** each handle whose branch holds the job vault now is synced. An lstat of the job vault's folder on the branch replaces today's open. The syncs run side by side as today (`sync_each_disk()`), each under its disk's lock, with errors recorded as today (`record_failed_sync()`).
  - **A disk that joined the pool during the unit:** after the syncs, the pool is listed again, as today. A disk it lists that has no handle and holds the job vault makes the sync raise OSError, naming the disk: "joined the pool … during this step: what was written onto it is not known to be on disk". It writes no marker and raises no alert, because it is not a write error. This is what `sync_restore()` does. A disk joins by a branch being added, or by a disk being mounted on a branch's empty mount point. `PoolGuard` would also fail the step, but not every flush has a `require()` between it and what it guards.
  - **A disk that left the pool** keeps its handle, and is synced while its branch holds the job vault.
- **A sync with no unit open raises** an error that names the job vault. That is a programming error, and the tests in section 6 would find it. No sync falls back to opening a path.
- **A disk missing when the unit opens** needs no special case.
  - The waits before each batch already pause a job whose vault's disk is missing.
  - If a disk is missing anyway, its branch is the bare mount point. Its handle belongs to the filesystem underneath, which never holds the job vault, so that handle is never synced. The batch's `PoolGuard` fails the batch at its first `require()`.
- **Shared within a batch.** Every sync in the unit, whatever its step, goes through the same fds. One handle reports each error once: the unit's first sync that meets the error gets it, and a later sync through the same handle does not (section 3).
- **How long a handle is held:** from the unit's open to its end.
  - That is a batch (seconds, or as long as a full comparison's walk), a scan, or a conversion.
  - Between batches and while idle, nothing is held.
  - **Off a pool this pins nothing new.** The job's manifest, an sqlite connection held for the job's whole run, already keeps that disk busy for umount.
  - **On a pool it pins the pool's other disks during the unit.** An `umount` of one of them returns EBUSY until the unit ends. That unit would fail on its `PoolGuard` anyway, and `umount -l` detaches the disk at once.
  - Acceptable, because no one unmounts a vault pool's disk under a running batch on purpose.

## 3. What the handles hear, and what the marker and VAULT_SYNC_LOCKS still cover

- **Heard now, missed by 0.55.2:** any write error the filesystem met after the unit opened, whoever wrote and whoever's sync saw it first. That covers another program's syncfs, a restore's sync, and another job's sync. As before, an error from before the open is also heard if no sync had seen it. So every write of the unit itself is vouched for by the unit's syncs, whatever else syncs the disk.
- **The restore's window,** found in the review of 0.55.2's last round.
  - A restore records the daemon's marker only after its syncfs returns. A comparison whose handle was opened in between got 0 and found no marker.
  - A unit whose handles were open before the restore's syncfs saw the error hears the error itself, with no marker needed. The window is closed for the unit's own writes.
- **Not heard:** an error that a sync saw before the unit opened.
  - It cannot concern the unit's own writes, which all come later.
  - It can concern something written earlier that the unit commits or reads back:
    1. **A cut batch's leftovers.** The batch stopped, was killed, or failed after its hand-over and before a clean flush. The next attempt's roll-forward reads the leftovers back from the page cache and commits them.
    2. **Copies committed after a failed comparison sync.** The comparison's sync heard the error, and the commit flush through the same handle gets 0. Today's behaviour is the same.
    3. **Copies committed unchecked while a marker stood.**
- **What the marker still carries.** For those three cases, it passes an error that one of our syncs heard (a unit of any job, or a restore) to every unit opened later. Until a reboot, those copies read from the page cache prove nothing. Nothing about the marker changes.
- **VAULT_SYNC_LOCKS keeps its job.**
  - A unit opened after another job's sync saw the error gets 0 from its own sync, so the marker must be written before that unit reads the markers. The disk's lock puts the two in that order.
  - Nothing about it changes.
  - A restore runs in another process and takes no part in the lock. Its window stays open, but only for those three cases.
- **What stays open.** If another program's sync saw such an error before the unit opened, no marker exists. Those copies can be committed and recorded as checked, with no alert. Section 4 asks about it.

## 4. Question 1: what a cut batch leaves

The core (sections 2 and 3) makes the alarm hear every error on a unit's own writes. What it leaves: section 3's cases 1 to 3. Case 1 is a gap when another program's sync took the error; the other cases are covered by the marker, apart from the restore's short window.

**Option 1, "Copy again, and the marker goes" (Recommended).** It is built as tasks 3 and 4, after the core:

1. **No unit commits past a sync of its own that failed.**
   - The comparison's sync and the stale lists' flush fail the attempt (JobFailure), as `flush_or_fail()` already does.
   - Line: one VAULT WRITE ERROR per unit that heard the error, then the job's FAILED line, as for any failed attempt.
   - The retry waits `JOB_RETRY_FIRST_SECONDS` (60 s) first.
2. **The roll-forward copies again each file the cut batch recorded.** It replays them as modifies instead of trusting a read-back.
   - "Recorded" means `prepare_roll_forward()`'s recorded files, folders left out, whose monitored path is a regular file now.
   - `roll_forward_entries()` already turns a stop's saved entries into modifies the same way.
   - Files the cut batch created have no row, so they are already copied again.
   - Every copy a version commits is then written inside its own unit, after that unit's handles opened.
3. **Nothing then needs another party's report, so these parts go:**
   - the markers: `mark_failed_sync()`, `failed_sync_disks()`, `read_vault_sync_marker()`, `vault_sync_marker_path()`, `VAULT_SYNC_MARKER_PREFIX`, `current_boot_id()` and `BOOT_ID_PATH` (only the markers use the boot id);
   - `VAULT_SYNC_LOCKS`, `VAULT_SYNC_MARKERS_LOCK` and `UNRECORDED_FAILED_DISKS`;
   - `check_vault_sync()`'s reading of the markers, and `compare_scopes()`'s `sync_failed` branch;
   - the restore's report to the daemon: `record_restore_write_error()`, `RestoreReport.tell_daemon()`, its WARNING, and `RestoreReport`'s `vault_folders` and `state_dir`, which only that report uses.
4. **It closes:**
   - this round's deferred entry;
   - "A write error in the middle of a copy after the reboot": a batch that met an error copies its files again, whole;
   - "A failed sync that cannot be recorded, after a restart";
   - "Bind mounts and btrfs subvolumes get separate failed-sync markers": every unit hears the error through its own handle;
   - "A comparison's failed sync does not fail the attempt": now it does.
5. **Cost.**
   - After a cut, the cut batch's changed files are copied a second time, where today 64 KiB of each is read back.
   - An attempt that meets a write error fails and retries.
   - Each comparison sync no longer reads the boot id or lists the state folder.
6. **Rollout.** The new version no longer reads markers that stand at the upgrade. The copies those markers hold unchecked would then be read back from the page cache and recorded as checked. Before the upgrade, the main session lists the state folder for `vault-sync-failed-*` files of this boot. If one stands, the upgrade waits for a reboot or comes with one.

**Why it is recommended:**
- It gives "never wrong data", as the restore's pick did.
- It closes four known limitations and one deferred entry.
- It needs less code.
- Its cost is paid only after a cut or a write error.

**Option 2, "Keep the marker, accept the gap".** The round is the core only. Case 1 with another program's sync becomes a known limitation:
- **What the operator sees:** a batch is cut after its copies. Before its next attempt, another program's sync of the vault's disk takes a write error on those copies. The next attempt then commits them and records them as checked, with no alert. A version can hold a file whose bytes never reached the disk until that file changes.
- **Revisit when:** another program syncs a vault's disk, or a vault disk shows write errors.

**Option 3, "Copy again in the next round".** The round is the core only. Option 1 becomes the next round's, and the deferred entry is narrowed to case 1.

## 5. Cost against 0.55.1

The daemon's syncs in 0.55.2 are those of 0.55.1. The live vaults are single f2fs disks; the limitations' "Revisit when a vault goes back on a pool" entries say none is on a pool now. A mount table read costs 0.44 ms of CPU at 162 mounts, from docs/limitations.md, "Eight mount table reads in a one-file batch" (3.5 ms for eight).

| Off a pool | 0.55.1 | Core |
|---|---|---|
| **Batch with no sync.** No copy: a delete, a rename, an attribute change, or a comparison that finds nothing to read back. | none | 1 mount table read, 1 open, 1 close |
| **Batch with one sync,** the usual case. The commit flush, or a comparison's clean sync after the last copy. The verification reads none of the batch's own copies back, because they are trusted. | 1 mount table read, then open, syncfs, close | the same: 1 mount table read and 1 open when the unit opens, the syncfs, 1 close at its end |
| **Each further sync in a batch,** such as a comparison's sync before copies that need the commit flush | 1 mount table read, open, syncfs, close | syncfs only |
| **A comparison's sync** also reads the markers | the boot id (open, read, close) and the state folder (open, getdents, close) | the same; with option 1, none |
| **fds held** | 1, during each sync | 1, for the unit |
| **f2fs checkpoints** (a syncfs of a dirty f2fs runs one) | one per syncfs | the same syncfs calls, so the same number. Opening or closing a folder writes nothing. |
| **Per idle hour** | none | none: no unit opens while idle |

- **On a pool of D disks:**
  - Each unit costs 1 mount table read, the branch list (one getxattr), D opens and D closes.
  - Each sync, as today, reads the mount table and the branch list (to spot a disk that joined). It then does an lstat and a syncfs per disk holding the job vault, where today it does an open, a syncfs and a close.
  - A pool batch with a hand-over makes at least four syncs (three flushes and the commit), so it comes out ahead.
- **A batch with scan events** opens `compare_scanned_folders()`'s unit and then `do_backup()`'s, one after the other: one more mount table read, open and close.
- **The open's mount table read** could reuse the one the batch's `PoolGuard` makes. That belongs with the deferred "Eight mount table reads in a one-file batch".

## 6. Tests

Tests run in Docker as uid 65534, with the code read-only, as 0.55.2's spec section 6 says: `pytest -n auto <files>`. Root, loop, dm and mergerfs tests run in the test VM, which the main session runs.

**The stand-in** sits at the binding (`LIBC_SYNCFS`), as the suite's other stand-ins do, so everything above it is real. It models one disk's `s_wb_err` and restates the kernel rule from "Why":
- `fail()`: a write error happens. Every fd open now on the test's filesystem will report it. Open fds are listed from /proc/self/fd and kept as (fd, st_dev, st_ino), so a reused fd number is not mistaken for the old one.
- `seen_elsewhere()`: another program's syncfs, a restore's or another job's sync sees the error. Every fd open now still reports it; an fd opened after this does not.
- `LIBC_SYNCFS(fd)`: returns EIO, once, for an fd that will report the error. That marks the error seen, and the fds open at that moment keep reporting. Otherwise it returns 0.

**Tests 1 to 6, for the core.** Each must fail on 0.55.2. To prove it, run the test file on a worktree of ab6e3fa with the file copied in.
1. **Commit flush.** The error is made and seen elsewhere between a batch's copies and its commit flush. Expect:
   - the flush raises;
   - VAULT WRITE ERROR names the disk;
   - the marker stands;
   - nothing commits: the manifest names the version before, and no change list is placed;
   - no fd of the unit is still open afterwards.
2. **A comparison's sync.** The same, before a comparison's sync that reads back an unchecked copy. Expect the copies to stay unchecked, the alert, and the marker.
3. **Who saw it first.** Test 1 again, with the error seen by:
   - a restore's sync, before its marker is written (the window);
   - another job's batch in the same process.
   In both, the unit hears it itself. With another job, there is one marker and one VAULT WRITE ERROR line (that job's), and this job's FAILED line.
4. **Each sync site that runs off a pool.** Make the error and see it elsewhere right after the step's first write. That step's sync must fail. Sites:
   - the hand-over on a vault with no exchange (three flushes);
   - the scan's repair of a cut between two renames;
   - the conversion's `materialize_version()` with no exchange, and `migrate_job_vault()`'s per-version flush.
   The pool-only sites are the prune's flush, the stale lists' flush and `decrement_stepper()`'s. Test them with the suite's pool fakes where those reach the real flush, else in the VM.
5. **Pool membership (VM, or fakes).**
   - A disk that joins during a batch and holds the job vault makes the sync raise, with no marker.
   - A disk that joins without the job vault is passed over.
   - A disk that left the pool is synced through its handle.
6. **One-file batch off a pool.** Expect:
   - one handle opened before the first copy;
   - one syncfs through it;
   - no folder opened at a sync;
   - the handle closed when the batch ends, and also when it raises.

**Tests 7 to 9, for option 1.** Each must fail on the core's commit.
7. **Copy again.** A batch is killed after placing a copy. The leftover's middle is overwritten, keeping its size, mtime and last 64 KiB, so a read-back passes. The roll-forward must copy it again, and the version must hold the right bytes. 0.55.2 commits the leftover.
8. **A failed comparison sync fails the attempt.** Nothing commits, and the next attempt does commit.
9. **No markers.** Neither the daemon nor a restore writes a `vault-sync-failed-*` file. The alert is one line.

**Stand-ins that must move** to the binding, or the gates never run through the handles. This is lesson 2026-11-06: a stand-in goes as low in the stack as it can. They are:
- test_crash_power_loss.py's `flushing_for_real`;
- test_migration.py's stand-in at line 1007;
- test_pool_cut.py's `real_flushes`, which replaces `syncfs_folder()` (that function goes);
- test_prune_power_loss.py at line 381;
- test_manifest.py, test_vault_flush.py, and test_restore_sync.py's guards on `syncfs_folder()`.

A stand-in that flushes a scratch image by path finds the path from the fd (/proc/self/fd/N). conftest's stub of `sync_vault_filesystems` can stay: the units still open under it.

**VM gates** (main session):
- **The whole suite,** as root with `REVERB_SCRATCH`. The power-loss tests on scratch f2fs images must run, not skip, and pass: test_crash_power_loss.py, test_prune_power_loss.py and test_restore_power_loss.py.
- **tests/test_pool_cut.py,** run alone.
- **A real write error.** This is worth it. The round rests on the kernel's rule, which the stand-in only restates. If that reading of the kernel were wrong, every test above would pass and the alarm would still be deaf.
  - It is a new test, skipped without root, dm and a scratch image, as the scratch-image tests are. It therefore runs at every VM gate and does not rot.
  - Setup: ext4 on dm-linear over a loop device. Preallocate a file with fallocate and find its extent with FIEMAP. Open handle A on the filesystem. Reload the dm table with that extent on the error target. Write the file, and run `sync -f` in another process, which should exit 1.
  - Expect:
    - a syncfs through A returns EIO;
    - a syncfs through a handle opened now returns 0, which is 0.55.2's blind spot;
    - an fsync of the file through a new fd returns EIO, which checks section 1's per-file fsyncs;
    - one batch with its vault there, with the error made between its copy and its commit flush, gives VAULT WRITE ERROR and commits nothing.
  - **Why ext4 and not f2fs.** f2fs writes out of place, so no fixed range is the file's next write. The rule belongs to the VFS, and f2fs records data write errors the same way (`f2fs_write_end_io()` calls `mapping_set_error()`; read, not run). ext4's default `data_err=ignore` keeps a data write error from aborting its journal.
  - If the VM has no dm-mod, the gate report says so.
- **Docker:** in the same container, nothing fails that does not also fail on ab6e3fa.

## 7. Docs and version

- **The builder, in the commit that changes the code:**
  - README line 4 gains one sentence: every sync of the vault goes through handles the step opened before its first write (on a mergerfs pool, one per disk), so a write error that another program's sync met first is still heard.
  - The core changes no API: internal helpers only, and no change to any line, format or flag. So it adds no lessons entry, and the alert lines stay.
  - With option 1:
    - README line 5 (the marker paragraph), lines 37 to 39, and line 102's sentence about recording the error for the daemon go;
    - lines 82 and 83 become one VAULT WRITE ERROR line, keeping the "VAULT WRITE ERROR:" prefix that firewatcher/reverberator.regex matches;
    - a lessons entry is needed, because the state folder's files, the alert line and the restore's warning all change.
- **The main session, in docs/limitations.md:**
  - removes the deferred entry;
  - with option 1, removes the four entries in section 4, item 4;
  - with option 2, writes the known limitation once the user approves it;
  - with option 3, narrows the deferred entry.
- **Version:** the main session sets `__version__` at merge, to the next free version. That is 0.55.3 if this ships before the watcher round, which also claims 0.55.3. The builder leaves "0.55.2".

## 8. Build tasks, in order

1. **Write the stand-in and tests 1 to 6.**
   - Prove: on a worktree of ab6e3fa with the test file copied in, `pytest -n auto <the new file>` fails every test. List them in the handback.
2. **Build the units and handles (section 2).** `syncfs_folder()` goes, and the stand-ins move.
   - Prove: tests 1 to 6 pass.
   - Prove: `git grep -n syncfs_folder` finds nothing.
   - Prove: the whole suite in Docker fails nothing that does not also fail on ab6e3fa in the same container.
3. **Option 1 only: write tests 7 to 9.**
   - Prove: they fail on task 2's commit.
4. **Option 1 only: build section 4's option 1.**
   - Prove: tests 7 to 9 pass.
   - Prove: `git grep -n -E 'mark_failed_sync|VAULT_SYNC_LOCKS|UNRECORDED_FAILED_DISKS|tell_daemon|vault-sync-failed'` finds nothing outside docs/lessons*.
   - Prove: the whole suite passes.
5. **Write the real-error test of section 6.**
   - Prove: in Docker it skips, printing its reason.
6. **Write the docs of section 7.**
   - Prove: every alert line in the README matches the code's text (grep each one).

## 9. Left to the builder

- Check whether a hard link on a mergerfs pool vault can be refused (EXDEV across branches under the pool's link and create policies, as the live pool sets them), and say what the record does then; the known limitation's text names the case.

- Names, and the unit's form: a context manager, a registry, or both.
- Whether to share `open_restore_disks()`'s core.
- The exact point of each open, before its function's first write.
- How a stand-in finds its image from an fd.
- With option 1:
  - how the roll-forward gets the recorded files: VaultInfo carries them, or it walks the previous version's real part a second time;
  - whether their read-back goes, since it costs 64 KiB each before the copy;
  - the alert line's words.

## 10. Questions for the user (answered 2026-11-09: option 1, and a known limitation; see The user's words)

1. **The leftovers of a cut batch** (section 4). The options, recommended first:
   1. "Copy again, and the marker goes (Recommended)"
   2. "Keep the marker, accept the gap"
   3. "Copy again in the next round"
2. **Known limitation? A copy made where the vault refused a hard link.**
   - Such a copy holds the only copy of an older file. It is either a cut batch's record of an older version's file, or a 0.54 conversion's tree.
   - Suppose its write failed and the error was seen before the next unit opened: by another program, or by the unit that made it, whose retry then gets 0. Then nothing hears it, nothing can copy it again, and that older version's file reads wrong.
   - The marker never helped here, because older versions have no rows to read back.
   - On f2fs, ext4 and XFS a record is a hard link: the link count stays at 2 or lower (read, not run). So this happens only on a vault filesystem without hard links.
   - Options:
     1. "Known limitation (Recommended)": revisit when such a vault is used.
     2. "Find a fix first": no design is known. Hearing it would mean keeping a handle across a cut, and nothing survives a kill.

## 11. Calls to confirm (the spec's own calls)

- A sync with no unit open raises instead of opening a path, and `syncfs_folder()` goes.
- Off a pool, a sync lists nothing.
- On a pool, a disk that joined during a unit and holds the job vault makes the sync raise, with no marker and no alert, as a restore does.
- A unit's handles pin a pool's other disks against umount until the unit ends.
- Costs:
  - a batch that syncs nothing pays one mount table read, an open and a close (0.44 ms of CPU);
  - a batch with one sync costs what it does today;
  - reusing the `PoolGuard`'s mount table read is left to the lightness round.
- Units belong to the four functions, so a batch with scan events opens two units in turn.
- The core adds no lessons entry, because it changes no API.
- The real-error probe runs on ext4, not f2fs.
- With option 1:
  - the comparison's failed sync fails the attempt, which reverses an approved limitation;
  - the alert line and the restore's output change, and these are API changes;
  - markers that stand at the upgrade are dropped, so the main session checks the state folder before the rollout.
