# The daemon's vault syncs go through handles opened before its writes

For the release after 0.55.2. Branch flush, on r0552 (0.55.2, not merged yet). The builder rebases onto 0.55.2's final commit before building; every "fails on 0.55.2" below means on that commit. The round closes the deferred entry in docs/limitations.md, "Another program's sync can take a vault disk's write error from the daemon", and builds section 4 as the user picked.

## The user's words

Their goals, verbatim:
- "I want this to be as light and as fast as possible... cause it is an backup solution, so it is designed to always in run the background. so every little bit will sum up to a lot over days month years."
- "simpler and smarter is better"
- "one of the core for reverberator is reuse existing linux features and easy browse / restore."

Their pick, 2026-11-09, "Next release after 0.55.2 (Recommended)". The question was: "The daemon's VAULT WRITE ERROR alarm has a blind spot, in 0.55.1 today: before each commit the daemon syncs the vault's disk through a handle it opens right then. If another program synced that disk first and took the write error, the daemon hears nothing, gives no alert, and commits a version whose files may not be on disk. … The fix: each batch opens its vault disks' handles before its first copy and syncs through them, as the 0.55.2 restore now does. It touches the commit flush, so the power-loss and pool-cut VM gates apply. When should it ship?" The option said: "Its own small round in its own worktree, started now alongside the watcher round, with its own reviews and VM gates. It ships as the next release after 0.55.2, before or after the watcher round, whichever is ready first. 0.55.2 ships without waiting for it."

Still standing, for 0.55.2's restore: "Recopy after a kill (Recommended)": "… never wrong data."

Their picks on this spec's two questions, 2026-11-09:
- On the leftovers of a cut batch (section 4): "Copy again, marker goes (Recommended)". The option said: "A batch never commits past a failed sync of its own; a comparison's failed sync now fails the attempt too, then it retries. After a cut, the next attempt copies the cut batch's files again instead of reading 64 KiB of each back. Every copy a version commits is then written while its own handles were open. The cross-job markers, their locks and the restore's report to the daemon all go: less code. It closes the deferred entry and four limitations. Cost only after a cut or a write error." So the round builds option 1 (section 4, task 3), and the approved limitation "A comparison's failed sync does not fail the attempt" goes with the user's pick.
- On a copy made where the vault refused a hard link (section 10, question 2): "Known limitation (Recommended)". The entry: what the operator sees (an older version's file can hold lost bytes with no alert, only where the vault refused a hard link and another program synced the disk at the wrong moment), why (no other copy of those bytes exists), and revisit if the vault ever shows refused hard links. The question told the user the main session had not checked whether their mergerfs pool ever refuses a hard link; the build checks it (section 9).

Fact (the main session checked it): every live vault is on its own f2fs disk, none on a mergerfs pool, so a refused hard link does not arise for them.

## Why

- **The kernel's rule.** Linux keeps a filesystem's writeback errors in `sb->s_wb_err`.
  - `do_dentry_open()` samples it into each file it opens. `errseq_sample()` gives 0 while no one has seen the newest error, so that file's first check reports it.
  - `syncfs()` reports what changed since its file's sample, and marks the error seen.
  - So a syncfs reports an error once to each file that was open when it happened, and to one opened later only while no syncfs has seen it.
  - Source: fs/open.c, fs/sync.c and lib/errseq.c, read but not run. The VM test in section 6 checks it on the kernel.
- **What the daemon does today.** `sync_vault_filesystems()` is the one caller of `syncfs_folder()`, which opens the folder at the moment of the sync. `check_vault_sync()` and `flush_vault_disks()` go through it.
- **What goes wrong.** When another sync meets the error first, the daemon gets 0. That other sync can be `sync -f`, any tool that calls syncfs, or a reverberator restore's sync. The daemon then:
  - raises no VAULT WRITE ERROR;
  - commits a version over copies that may not be on disk;
  - may later read those copies back from the page cache and record them as checked.
- **The restore already does it right.** 0.55.2's `open_restore_disks()` opens its handles before the first copy, and `sync_restore()` syncs through them.

## 1. Every vault sync, what it vouches for, and its unit

| Sync | Code | What it vouches for | Unit (section 2) |
|---|---|---|---|
| Commit flush | `do_backup()` → `flush_copies()` → `flush_or_fail()` → `flush_vault_disks()` | The batch's copies, and a roll-forward's tree, before the change list's fsync (a checkpoint) and the manifest's commit. Now it runs whenever the batch placed a copy (section 4). | `do_backup()`'s |
| A comparison's sync | `compare_scopes()` → `check_vault_sync()` | Goes (section 3) | none |
| Hand-over | `hand_over()`: `TreeWriter.flush()` ×3 on two renames; `pre_record()`, `flush_if_needed()` | On a pool or a filesystem with no exchange: the skeleton, the tree's rename and the records are on every disk before the next rename or change | `do_backup()`'s |
| Prune, design R | `prune_version()` → `flush_or_fail()`, on a pool | The rename into staging is on every disk before `rm -rf` | `do_backup()`'s (`remove_oldest()`) |
| Prune, 0.54 | `decrement_stepper()` → `flush_disks()` ×2, on a pool | The walk's links before the removal; the removal before the lists go | `convert_at_start()`'s (`finish_cut_prune()`) |
| Conversion | `materialize_version()` → `flush_or_fail()` ×4 (pool or no exchange); `migrate_job_vault()`, once per version | The built tree is on every disk before the version moves; each version's swap and times before the manifest says it is done | `convert_at_start()`'s |
| Scan | `repair_pool_vault()` → `flush_or_fail()` ×2; `remove_stale_change_lists()` → `flush_vault_disks()` (pool) | The repairs' renames before the read; a folder's removal before its list goes | `get_vault_info()`'s, or the enclosing unit's |
| Restore | `sync_restore()` | Already through `open_restore_disks()` | unchanged |

**These need nothing:**
- The per-file fsyncs: `fsync_path()`, `fsync_vault_folder()`, the manifest's sqlite and the change list.
  - A file's own error is kept on its inode, in `mapping->wb_err`. A syncfs does not mark it seen: it advances only the superblock's error, and `sync_inodes_sb()` waits with `filemap_fdatawait_keep_errors()`.
  - Only an fsync of that same file would mark it seen, and nothing else fsyncs the vault's files.
  - Source: read, not run; the VM test checks it.
- The CLI. The restore is the only command that syncs.

## 2. The handles

- **A unit of vault work.**
  - Each of `do_backup()`, `get_vault_info()` and `convert_at_start()` opens the job vault's handles before its first vault write, and closes them when it returns or raises.
  - `do_backup()` opens right after it makes the job vault, when it has to make it.
  - `convert_at_start()` opens after its early `layout() == 'r'` return, so the start of a design-R vault opens nothing.
  - A call made while a unit for that job vault is open uses it and closes nothing. An example is `get_vault_info()` inside `do_backup()`.
  - These three are the only ways into the sync sites of section 1. The grep of every caller says so. `compare_scanned_folders()` needs none of its own: its scan's unit is `get_vault_info()`'s, and comparisons no longer sync.
- **Where "on a pool?" comes from.** The unit takes the answer from its step's `PoolGuard`: `do_backup()`'s `pool_guard`, `get_vault_info()`'s guard, and a `PoolGuard([job_vault])` that `convert_at_start()` builds. It reads no mount table.
  - **Off a pool:** one fd of the job vault.
  - **On a pool:** one fd per branch the guard's `PoolState` lists, at the branch root, as `open_restore_disks()` opens it. Duplicates are closed, so one fd remains per filesystem (by `fstat().st_dev`), and branches that are folders of one filesystem share it. The pool's mount point also comes from the guard's state.
  - A handle that cannot be opened keeps its OSError, and every sync that needs it raises that error.
- **Naming the disk.** A disk is named only when its sync fails, for the alert: the mount point holding the handle's path, as `vault_disks()` names disks, or that path when the mount table has none. The locks that needed a name at every sync go (section 4).
- **A sync** (`sync_vault_filesystems()`) goes through the unit's handles and never opens a path. `syncfs_folder()` goes. One rule covers both layouts.
  - Each branch that holds the job vault counts. Off a pool that is the job vault itself; on a pool, the branch list is read again (one getxattr) and the job vault's folder is checked with an lstat on each branch.
  - The lstat's `st_dev` picks the handle.
  - Each handle picked is synced once, side by side as today (`sync_each_disk()`).
  - A branch holding the job vault whose `st_dev` no handle of the unit has makes the sync raise OSError naming it: "is not on a filesystem this step opened: what was written there is not known to be on disk". It writes no alert, because it is not a write error. That covers:
    - a disk that joined the pool (a branch added, or a disk mounted on a branch's empty mount point);
    - a disk swapped at a mount point (`umount -l` and a new mount there), on or off a pool.
  - It replaces `sync_restore()`'s joined-disk check, which the daemon's sync never had, and is no more code than that check.
  - A branch whose lstat fails other than "not there" can't be checked, so the sync raises.
  - A disk the pool no longer lists while it is still mounted (a branch removed at run time) is not synced. Today's sync does not sync it either, and `PoolGuard` does not see it.
- **A sync with no unit open** raises `RuntimeError` naming the job vault. That is a bug. `backuper()`'s `except Exception` logs the traceback and fails the job (`job.fail()`), as for any internal error, and every retry fails the same way until the bug is fixed. No sync falls back to opening a path.
- **Finding the unit.** `sync_vault_filesystems()` looks the unit up on the calling thread, keyed by `os.path.normpath(os.path.abspath(job_vault))`. That is also how `PoolGuard` normalises paths, and every remaining caller derives its job vault from the rule's vault path. The thread then passes the handles to `sync_each_disk()`'s workers, as `sync_restore()` does. No thread-local is used.
- **A disk missing when the unit opens.** The waits before each batch already pause a job whose vault's disk is missing. If a disk is missing anyway, its branch is a bare mount point on the filesystem below, which never holds the job vault, so its handle is never synced. The step's `PoolGuard` fails the batch at its first `require()`.
- **Shared within a batch.** Every sync of the unit goes through the same fds, and each handle reports an error once. That needs no memory of past errors, because a failed sync ends the attempt (section 4).
- **How long a handle is held:** from the unit's open to its end.
  - That is a batch (seconds, or a full comparison's walk), a scan, or a conversion.
  - Between batches and while idle, nothing is held.
  - **Off a pool this pins nothing new.** The job's manifest, an sqlite connection held for the job's whole run, already keeps that disk busy for umount.
  - **On a pool it pins the other disks during the unit.** An `umount` returns EBUSY until the unit ends. That unit would fail on its `PoolGuard` anyway, and `umount -l` works.
  - Acceptable, because no one unmounts a vault pool's disk under a running batch on purpose.

## 3. What the handles hear, and why the comparison's sync and the markers go

- **Heard now, missed by 0.55.2:** any write error the filesystem met after the unit opened, whoever wrote and whoever's sync saw it first: another program's syncfs, a restore's sync, another job's sync. As before, an error from before the open is heard if no sync had seen it.
- **The restore's window,** found in the review of 0.55.2's last round. A restore records the daemon's marker only after its syncfs returns, and a comparison whose handle was opened in between got 0 and found no marker.
  - A unit whose handles were open before that syncfs saw the error hears it itself, with no marker needed.
  - With section 4, no unit relies on a marker at all, so the window has nothing left to break.
- **Not heard:** an error a sync saw before the unit opened. It cannot be on the unit's own writes, which come later. It matters only where the unit commits or reads back something written earlier.
- **Every path that records a read-back copy as checked.** `compare_entry()` reads a copy back with `read_vault_record()` (which leaves it checked) in two cases: for a row with no record, and for an unchecked row. `compare_scopes()` then records it, after the sync this round removes. What those rows can be:
  1. **An unchecked row of the latest version.** These are copies committed earlier, recorded unchecked by `read_copied_record()`. With section 4, a batch that placed a copy always runs its commit flush through its unit's handles, and no commit goes past a failed sync. So every copy this version commits was synced clean before its commit. A read-back from the page cache equals the disk. Copies 0.55.2 committed after a missed error were never protected by the comparison's sync either: its handle, opened at the sync, missed the same error.
  2. **A cut batch's recorded files,** which `prepare_roll_forward()` marks unchecked in the tree. Section 4 keeps them out of the read-back and copies them again.
  3. **`read_rows_from_tree()`'s rows with no record** (an entry gone, or now of another kind). The read-back finds nothing (a create) or no file; no file is recorded as checked from them.
  4. **`manifest.rebuild()`'s rows with no record.**
     - Without a tree (`do_backup()`: "Manifest does not describe …", and the scans), those are the latest version's committed copies, which is case 1.
     - With `tree_path`, when a roll-forward's manifest was lost, the tree's files are read back. Among them are the cut batch's creates, written before the unit opened.
     - Their records stand only if the roll-forward commits, and it always runs its commit flush first, through the same handle. That flush hears exactly what the comparison's sync would have heard.
     - What neither hears is an error seen before the unit opened. 0.55.2's marker covered that when one of our syncs saw it. Section 10, question 3 asks about it.
  5. **The verification after the replay** (`compare_scopes(fixes, …)`). The batch's own rows are trusted and never read back; the rest are cases 1 to 4.
  6. **`compare_scanned_folders()`** compares the latest version only. It hands a cut tree to the roll-forward (its `vaultInfo.tree is not None` return).
- **Verdict:** no path needs the comparison's sync. `check_vault_sync()` goes, along with:
  - the comparison's half of `copies_unsynced`: the `manifest.copies_unsynced = False` after a clean comparison sync;
  - the marker reading inside the comparison;
  - the warning lines that came with them.
- **What the drop saves:** one syncfs for each comparison that reads a copy back. That covers the start's full comparison, and a moved file (`A moved file is read back and syncs the vault`), whose read-back stays. Each such syncfs was an f2fs checkpoint when the disk was dirty, plus its mount table read, open, close and marker reads. A batch that placed a copy now always runs its commit flush, but its comparison no longer syncs, so no batch syncs more often than in 0.55.2.
- **The markers and `VAULT_SYNC_LOCKS`.** They existed to carry an error that one sync saw to the syncs that would then get 0. With section 4, no committed copy and no read-back depends on another sync's report, apart from case 4 with a lost manifest. So they go.

## 4. The rest of the build (the user's pick, "Copy again, marker goes")

1. **No unit commits past a sync of its own that failed.**
   - Every failed vault sync fails the attempt, as `flush_or_fail()` does.
   - `remove_stale_change_lists()` keeps its lists and fails the attempt, where 0.55.2 went on.
   - The comparison no longer syncs (section 3).
   - The retry waits `JOB_RETRY_FIRST_SECONDS` (60 s), doubling to `JOB_RETRY_MAX_SECONDS` (3,600 s).
2. **The roll-forward copies again what the cut batch recorded.**
   - `prepare_roll_forward()` returns its recorded files: `give_back_folder_times()`'s list, with folders and links left out. `VaultInfo` carries them from the scan to the roll-forward.
   - `roll_forward_entries()` passes them to `compare_scopes()` as trusted. They are then compared for presence and kind only, never read back.
   - Each one whose monitored path is a regular file now is replayed as a modify, the way `roll_forward_entries()` already turns a stop's saved entries into modifies.
   - What the cut batch created has no row, so it is already copied again.
   - **Why this list is complete.** Design R records every entry of the tree before changing it: `TreeWriter.copy()` calls `record(rel, True)` first, and `replay_ops()` records a file's attribute change as an entry when Only Sync Attributes is off. So the list holds every file the cut batch wrote over, including a copy made for an attribute change.
   - The 64 KiB read-back of each of those files goes.
3. **The commit flush runs whenever the batch placed a copy** (`copies_unsynced`, set by `finish_copies()` and `TreeWriter.keep_entry()`), or the batch is a roll-forward, or on two renames, as today minus the comparison's half.
4. **Parts that go,** as of 0.55.2's final commit:
   - the markers: `mark_failed_sync()` (with its `restore=`), `failed_sync_markers()`, `failed_sync_disks()`, `read_vault_sync_marker()`, `vault_sync_marker_path()`, `VAULT_SYNC_MARKER_PREFIX`, `current_boot_id()` and `BOOT_ID_PATH` (only the markers use the boot id);
   - `VAULT_SYNC_LOCKS`, `VAULT_SYNC_MARKERS_LOCK` and `UNRECORDED_FAILED_DISKS`;
   - `check_vault_sync()`, `compare_scopes()`'s sync and `sync_failed` branch, and `record_failed_sync()`'s marker part (the alert stays);
   - the restore's report to the daemon: `record_restore_write_error()`, its call in `sync_restore()`'s per-disk sync, the warning "could not record the write error of disk … for the daemon", and `RestoreReport`'s `vault_folders` and `state_dir`, which only that report uses;
   - in the tests: tests/test_tree_writes.py's `NOT_FOLLOWED` entry for `failed_sync_markers`, conftest's `UNRECORDED_FAILED_DISKS.clear()`, and the marker tests in test_manifest.py, test_restore_sync.py and crash_child.py.
5. **What the operator sees when a disk fails.**
   - VAULT WRITE ERROR is logged once per unit that hears the error, then the job's FAILED line. With no marker, a disk that keeps failing alerts again at every retry of every job on it: after 60 s, then doubling up to every hour.
   - 0.55.2 alerted once per disk per boot.
   - The line keeps the "VAULT WRITE ERROR:" prefix that firewatcher/reverberator.regex matches. It says the disk failed a sync, that nothing is committed past it, and that the next attempt copies again what this one changed.
6. **It closes:**
   - this round's deferred entry;
   - "A comparison's failed sync does not fail the attempt" (the comparison no longer syncs, and no attempt goes on past a failed sync);
   - "A write error in the middle of a copy after the reboot" (a batch that met an error copies its files again, whole, and nothing waits for a reboot);
   - "A failed sync that cannot be recorded, after a restart";
   - "Bind mounts and btrfs subvolumes get separate failed-sync markers" (each unit hears the error through its own handle);
   - "A copy whose start was lost after a power loss". An attribute change with Only Sync Attributes off is recorded before its copy (item 2), so the roll-forward after the power cut copies it again instead of comparing its tail.
   It narrows "A moved file is read back and syncs the vault" to the read-back.
7. **Rollout.** A failed-sync marker of this boot that stands at the upgrade is no longer read, so the copies it holds unchecked would be read back from the page cache and recorded as checked. If one stands, the upgrade waits for a reboot or comes with one. That is the user's decision at rollout, asked then; this spec decides nothing about it.

## 5. Cost against 0.55.1

0.55.2's daemon syncs as 0.55.1's does. Every live vault is on its own f2fs disk. A mount table read is 0.44 ms of CPU at 162 mounts, from docs/limitations.md, "Eight mount table reads in a one-file batch" (3.5 ms for eight).

| Off a pool, per batch | 0.55.1 | This round |
|---|---|---|
| **A unit** (every `do_backup()` call, and every scan) | none | 1 open and 1 close; no mount table read |
| **Each sync** | 1 mount table read, then open, syncfs, close | lstat of the job vault and syncfs; the unit's first sync also an fstat of its handle |
| **Batch that placed a copy** (the commit flush) | 1 mount table read, open, syncfs, close | open, fstat, lstat, syncfs, close: one mount table read fewer, two syscalls more |
| **Batch with no copy** (a delete, a rename, an attribute change under Only Sync Attributes) | none | open and close |
| **A comparison that reads a copy back** (the start's full comparison, a moved file) | 1 syncfs, which is an f2fs checkpoint on a dirty disk, plus a mount table read, open, close, the boot id (open, read, close) and the state folder (open, getdents, close) | none |
| **After a cut** | 64 KiB read back of each file the cut batch changed | each of those files copied again |
| **After a write error** | the attempt goes on past a comparison's failed sync | the attempt fails and retries after 60 s |
| **fds held** | 1, during each sync | 1 per filesystem, for the unit |
| **f2fs checkpoints** | one per syncfs of a dirty disk | the commit flushes as before; each comparison's syncfs is gone |
| **Per idle hour** | none | none: no unit opens while idle |

- **On a pool of B branches:**
  - Each unit costs B opens and B fstats, closing duplicates, with no mount table read.
  - Each sync costs the branch list (one getxattr), B lstats, and one syncfs per filesystem holding the job vault. 0.55.1 spends a mount table read, the getxattr, and an open, a syncfs and a close per branch holding the job vault.
  - 0.55.1 never looked for a joined disk; that check comes from `sync_restore()`.
- **"Eight mount table reads in a one-file batch"** loses one: the commit flush reads none.

## 6. Tests

Tests run in Docker as uid 65534, with the code read-only, as 0.55.2's spec section 6 says: `pytest -n auto <files>`. Root, loop, dm and mergerfs tests run in the test VM, which the main session runs.

**The stand-in:** errseq per superblock, as the kernel keeps it, at the binding (`LIBC_SYNCFS`), as the suite's other stand-ins are.
- **State per filesystem,** keyed by `st_dev`: a counter of errors, and whether the newest has been seen. It starts at 0, seen.
- **Opens and closes.** `os.open` and `os.close` are wrapped for the test on the os module, which the product shares.
  - An open samples the fd's cursor: the counter when the newest error is seen, else 0, as `errseq_sample()` does.
  - A close forgets the cursor, so a reopened fd number gets a new sample.
- **`fail(path)`:** an error on that filesystem. The counter moves on only when the newest was seen, as `errseq_set()` does, and the error is unseen.
- **`seen_elsewhere(path)`:** another program's syncfs marks the error seen.
- **`LIBC_SYNCFS(fd)`:** when the fd's filesystem's counter differs from its cursor, it returns EIO, marks the error seen and moves the cursor to the counter. Otherwise it returns 0. An fd the wrapper never saw opened samples at its first sync.
- **One model per superblock,** so a pool test with branches on several filesystems gets one model each.

**The tests.** Task 1 writes them for the final behaviour, so none is rewritten later. Each fails on 0.55.2's final commit.
1. **Commit flush.** Between a batch's copies and its commit flush, `fail()` and then `seen_elsewhere()`. Expect:
   - the flush raises;
   - VAULT WRITE ERROR names the disk;
   - no `vault-sync-failed-*` file;
   - nothing commits: the manifest names the version before, and no change list is placed;
   - no fd of the unit is still open afterwards.
2. **The comparison no longer syncs** (it replaces the first draft's comparison test).
   - A comparison that reads back an unchecked copy makes no syncfs.
   - A batch that placed a copy runs its commit flush even when a read-back came after its last copy.
   - 0.55.2 syncs in the comparison and skips the flush.
3. **Who saw it first.** Test 1 again, with the error seen by:
   - a real `sync_restore()` through its own handles;
   - another job's batch in the same process.
   In both, this unit hears it itself and nothing commits. Each unit that heard it logs one VAULT WRITE ERROR. No marker is written.
4. **Each sync site.** `fail()` and `seen_elsewhere()` right after the step's first write; the step's sync must fail the attempt.
   - Off a pool:
     - the hand-over on a vault with no exchange (its three flushes);
     - the scan's repair of a cut between two renames;
     - `materialize_version()` with no exchange, and `migrate_job_vault()`'s per-version flush.
   - On `harness.FakePool`, with the real helper (`REAL_SYNC_VAULT_FILESYSTEMS`):
     - `prune_version()`'s flush, with test_pool_writer.py's `job` and `fake_pool` fixtures;
     - `remove_stale_change_lists()`'s flush, which now fails the attempt where 0.55.2 went on;
     - `decrement_stepper()`'s flushes, on a 0.54 vault built by tests/legacy054.py.
5. **Pool membership.** FakePool, with one branch on another filesystem the container has (/dev/shm, a tmpfs).
   - A branch that joins holding the job vault on that filesystem makes the sync raise, naming it, with no alert. This fails on 0.55.2, which syncs it.
   - In the same run, a branch that joins without the job vault is passed over, and a joined branch that is a folder of a filesystem a handle has is synced through that handle. These two pins hold on 0.55.2 by nature; they ride in this test.
   - The swap (`umount -l` and a new tmpfs at a branch's mount point, and the same off a pool) runs in the VM.
6. **One-file batch off a pool.** Expect:
   - one handle opened before the first copy;
   - no mount table read and no folder opened for the unit or its sync;
   - one syncfs;
   - the handle closed at the batch's end, and also when it raises.
7. **Copy again.** A batch is killed after placing a copy, and the leftover's middle is overwritten, keeping its size, mtime and last 64 KiB. Expect:
   - the roll-forward reads none of the cut batch's recorded files back (a recorder on `read_vault_record()` for those rels);
   - it copies each again;
   - the newest version holds the right bytes.
   0.55.2 reads the leftover back and commits it.
8. **Copy again after an attribute change.** Test 7 for a chmod with Only Sync Attributes off, of a file ending in 128 KiB of zeros, with the leftover all NUL at its size and mtime. The newest version holds the file's bytes. 0.55.2 keeps it all NUL: the limitation "A copy whose start was lost after a power loss".
9. **No markers.**
   - Neither the daemon nor a restore writes a `vault-sync-failed-*` file.
   - A restore whose sync fails warns nothing about the daemon.
   - The alert is one line.

**Stand-ins that must move** to the binding, or the gates never run through the handles. This is lesson 2026-11-06: a stand-in goes as low in the stack as it can.
- test_crash_power_loss.py's `flushing_for_real`;
- test_migration.py's stand-in near line 1007;
- test_pool_cut.py's `real_flushes`, which replaces `syncfs_folder()`;
- test_prune_power_loss.py near line 381;
- test_manifest.py, test_vault_flush.py, and test_restore_sync.py's guards on `syncfs_folder()`.

A stand-in that flushes a scratch image by path finds the path from the fd (/proc/self/fd/N). conftest's stub of `sync_vault_filesystems` can stay: the units still open under it.

**VM gates** (main session):
- **The whole suite,** as root with `REVERB_SCRATCH`. The power-loss tests on scratch f2fs images must run and pass: test_crash_power_loss.py, test_prune_power_loss.py (its mergerfs tests run `decrement_stepper()` on a real pool) and test_restore_power_loss.py.
  - They include a new power-loss test in the shape of tests 7 and 8, so the power-loss gate covers the closed limitation:
    - a chmod with Only Sync Attributes off of a file ending in 128 KiB of zeros;
    - the power cut after a checkpoint that keeps the copy's size and before the commit flush (the sweep's `power-loss-checkpoint` way of making one);
    - the retry's newest version holds the file's bytes.
  - This test fails on 0.55.2.
- **tests/test_pool_cut.py,** run alone. Its batches include a prune, with real flushes on a real pool.
- **Test 5's swap cases.**
- **A real write error.**
  - **Worth it.** The round rests on the kernel's rule, which the stand-in only restates. If that reading of the kernel were wrong, every test above would pass and the alarm would still be deaf.
  - **It must run.** At the VM gate a skip counts as a failure. Elsewhere it may skip without root, dm-mod or a scratch image.
  - **Setup.** ext4 on dm-linear over a loop device, mounted `nodelalloc`, so blocks are allocated at write(2) and FIEMAP finds them before writeback.
  - **The kernel's rule.** Write a file and find its extent. Open handle A on the filesystem. Load the table with that extent on the error target. Run `sync -f` in another process, which should exit 1. Expect:
    - a syncfs through A returns EIO;
    - a syncfs through a handle opened now returns 0, which is 0.55.2's blind spot;
    - an fsync of the file through a new fd returns EIO, which checks section 1's per-file fsyncs.
  - **The batch.** Put a job's vault there. A hook before the commit flush finds the placed copy's extent by FIEMAP, loads the error table, runs `sync -f` and loads the plain table back. Then the commit flush raises: VAULT WRITE ERROR, and nothing commits.
  - **Why ext4 and not f2fs.** f2fs writes out of place, so no fixed range is a file's next write. The rule belongs to the VFS, and f2fs records data write errors the same way (`f2fs_write_end_io()` calls `mapping_set_error()`; read, not run). ext4's default `data_err=ignore` keeps a data write error from aborting its journal.
- **Docker:** in the same container, nothing fails that does not also fail on 0.55.2's final commit.

## 7. Docs and version

- **The builder, in the commits that change the code.** README line numbers are as of r0552 at the time of writing.
  - **Line 4.** Its comparison-sync sentences go, including "a failed sync keeps that comparison's copies unchecked, for a later comparison to read back again". In their place, say:
    - a copy read back is recorded checked with no sync of its own, because every committed copy was flushed before its commit;
    - a commit flushes the batch's copies through handles the batch opened before its first write (on a mergerfs pool, one per filesystem), so a write error that another program's sync met first is still heard;
    - a sync that fails commits nothing and fails the attempt, whose next attempt copies again what it changed.
  - **Removed:** line 5 (the marker paragraph); lines 37 to 39; line 55 (the attribute change after a power cut); line 102's sentence about recording the error for the daemon.
  - **Lines 82 and 83** become one VAULT WRITE ERROR line (section 4, item 5).
  - **A lessons entry is needed,** because APIs change: the state folder's files, the alert line, and the restore's output.
- **The main session, in docs/limitations.md:**
  - removes the deferred entry and the five entries in section 4, item 6;
  - narrows "A moved file is read back and syncs the vault";
  - takes one read off "Eight mount table reads";
  - writes the known limitations once they are approved (section 10).
- **Version:** the main session sets `__version__` at merge, to the next free version. That is 0.55.3 if this ships before the watcher round, which also claims 0.55.3. The builder leaves "0.55.2".

## 8. Build tasks, in order

The builder first rebases onto 0.55.2's final commit.
1. **Write the stand-in and tests 1 to 9.**
   - Prove: on a worktree of 0.55.2's final commit with the test files copied in, `pytest -n auto <the new files>` fails every test. List them in the handback.
2. **Build the units and handles (section 2).** `syncfs_folder()` goes, and the stand-ins move.
   - Prove: tests 5 and 6 pass.
   - Prove: `git grep -n syncfs_folder` finds nothing.
3. **Build section 4 and section 3's drop of the comparison's sync.**
   - Prove: tests 1 to 9 pass.
   - Prove: `git grep -n -E 'check_vault_sync|mark_failed_sync|failed_sync_markers|VAULT_SYNC_LOCKS|UNRECORDED_FAILED_DISKS|record_restore_write_error|vault-sync-failed'` finds nothing outside docs/lessons*.
   - Prove: the whole suite in Docker fails nothing that does not also fail on 0.55.2's final commit in the same container.
4. **Write the VM tests:** the real-error test, the power-loss shape of section 6, and test 5's swap cases.
   - Prove: in Docker each skips, printing its reason.
5. **Write the docs of section 7.**
   - Prove: every VAULT WRITE ERROR line in the README matches the code's text (grep each one).

The reviews and the VM gates are the main session's.

## 9. Left to the builder

- Check whether a hard link on a mergerfs pool vault can be refused (EXDEV across branches under the pool's link and create policies, as the live pool sets them), and say what the record does then; the known limitation's text names the case.

- Names, and the unit's form: a context manager, a registry, or both.
- Whether to share `open_restore_disks()`'s core.
- The exact point of each open, before its function's first write.
- How a stand-in finds its image from an fd.
- Whether `prepare_roll_forward()` still marks the recorded files unchecked. Once they are trusted, nothing reads the mark.
- The alert line's words, within section 4, item 5.

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
3. **New, open: known limitation? A roll-forward whose manifest was lost** (section 3, case 4).
   - **What happens.** A batch is cut, and its manifest is lost too (the sqlite file deleted or corrupt). Its creates then get rows from the rebuild of the tree, are read back, and are committed.
   - **Where it goes wrong.** If a write error on one of them was seen before the retry's handles opened, nothing hears it, and the newest version holds that file wrong, with no alert, until the file changes. The error may have been seen by the cut batch's own failed flush, or by another program.
   - **What 0.55.2 did.** Its marker kept those copies unchecked when one of our syncs had seen the error.
   - **How likely.** It needs three faults at once: a cut, a lost manifest and a write error. The approved "A manifest lost in the same cut as a split on a pool" needs two.
   - Options:
     1. **"Known limitation (Recommended)":** revisit if a manifest is ever lost on a live vault.
     2. **"Copy those again too":** a roll-forward over a rebuilt manifest also copies again each tree file under a real folder of the previous version that the folder does not list (the cut batch's creates, and its moves' targets). It is a walk of the cut batch's real folders, on a path only a lost manifest takes.

## 11. Calls to confirm (the spec's own calls)

- A sync with no unit open raises `RuntimeError`, and the attempt fails as on any internal error. `syncfs_folder()` goes.
- **The `st_dev` rule.** Each sync finds the handle for each branch holding the job vault by its `lstat().st_dev`, and raises when none has it. That catches a joined disk and a swapped one, on or off a pool, for one lstat per branch per sync.
  - A branch removed from a pool's list at run time while still mounted is not synced, as today, and `PoolGuard` doesn't see it either.
- A unit's handles pin a pool's other disks against umount until it ends.
- Units belong to `do_backup()`, `get_vault_info()` and `convert_at_start()`. `compare_scanned_folders()` has none.
- **The comparison's sync goes** (section 3, the ruling's trace). So do the comparison's half of `copies_unsynced`, and the first draft's comparison test, which a test pinning the drop replaces.
- **The commit flush runs whenever a batch placed a copy.**
- **`remove_stale_change_lists()`'s failed flush now fails the attempt.**
- **Alerts.** VAULT WRITE ERROR is logged once per unit that hears the error. A failing disk alerts at every retry of every job on it (60 s, doubling up to 1 h), where 0.55.2 alerted once per disk per boot.
- **Five limitations close** (section 4, item 6), one more than the user's option named: "A copy whose start was lost after a power loss" closes through the same recopy.
- **API changes, with a lessons entry:**
  - the state folder's `vault-sync-failed-*` files go;
  - the alert line changes;
  - the restore's warning about the daemon goes.
- **Rollout:** a marker of this boot at the upgrade is the user's decision then (section 4, item 7).
- **The real-error test** runs on ext4 mounted `nodelalloc`, and a skip at the VM gate fails it.
