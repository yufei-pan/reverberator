# Pool Disks, Changes Inside Moved Folders, Pruning's Temporaries Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A job pauses while a disk of its vault pool or monitored mergerfs pool is missing, and never scans, prunes, copies or commits across a disk that drops. Vault folders are flushed on the disks themselves. Changes made inside or onto a moved path in one batch are replayed after the move. Restore never writes out pruning's leftover temporaries, and restore and history warn when a vault disk is missing. Version 0.45.

**Architecture:**
- One live check reads the mount table, the pool's `user.mergerfs.srcmounts` and one `statvfs` per branch, and says what is wrong in one reason text.
  - `wait_for_path` runs it on every poll, so every wait already in the code pauses on a pool problem.
  - The filesystem-signature monitor folds it into each flag, and its fingerprint holds the branches' mount ids.
- A `PoolGuard` takes the branches' mount ids when a step begins. Its `require()` raises `PoolNotReady`, a `JobFailure`, which fails the attempt through the paths already there:
  - the scan checks before its deletions;
  - the prune checks before its `rm -rf`;
  - a backup checks before its commit, and polls it (throttled) while it writes into the version.
- `fsync_vault_folder` fsyncs a folder on each branch holding it. The replay order and the move step change locally. Restore tells a temporary by its inode.

**Tech Stack:** Python ≥ 3.8, single module `reverberator.py` (tab-indented), pytest.

**Spec:** `docs/superpowers/specs/2026-10-23-pool-disks-design.md`

## Global Constraints

- **Style.** Code is tab-indented and matches the surrounding naming, comment density and docstring-with-doctest style.
- **Library versions.** It must work on both venvs: the worktree's `.venv`, and the service venv `/mnt/optane/work/reverberator/.venv` (Tee_Logger 6.40, multiCMD 1.51, TSVZ 3.39).
- **Where to work.** Only in `/mnt/optane/work/reverberator/.worktrees/pool-disks`, on branch `pool-disks`.
  - Never write under `/mnt/jank`, `/mnt/impulse` or `/mnt/klein`.
  - Never write in the main checkout: the live service runs from it.
  - Never touch `/etc`, systemctl or real vaults.
  - Never commit `uv.lock`.
- **Tests.** Run from the worktree root, on both venvs:
  - worktree: `.venv/bin/python -m pytest -q`
  - service venv: `PYTHONDONTWRITEBYTECODE=1 /mnt/optane/work/reverberator/.venv/bin/python -m pytest -q -p no:cacheprovider`
  - The ground-truth plugin `tests/chain_ground_truth.py` stays on and passing. It wraps `do_backup` and `decrement_stepper` with `*args, **kwargs`, so new keyword arguments pass through.
- **Commit messages.** One or two plain sentences in the repository's style, ending with:
  ```
  Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01JihhsZfJ71AqrEdg8CbPKJ
  ```
- **Facts checked live** (use as given): mergerfs 2.42.0. `user.mergerfs.srcmounts` holds expanded absolute paths joined by `:`, with no globs and no modes. Each branch has its own line in `/proc/self/mountinfo`. mergerfs's fsyncdir returns ENOSYS, so the kernel treats later folder fsyncs on the mount as done. The pools are `/mnt/jank` (6 branches, all vaults), `/mnt/impulse` (22) and `/mnt/klein` (6).
- **Anti-goals (the spec's), binding on every task:**
  - never treat a hidden file as deleted, or act on a vault while a disk is out;
  - never write vault files onto the root disk because a vault disk dropped;
  - never block a job for a pool it doesn't use;
  - don't slow the normal backup: the checks run at the points below, never per file (a poll per entry is a clock compare);
  - don't keep a copy of the pool layout: branches come from mergerfs at check time.
- **Paths not on mergerfs behave exactly as now.** Every task keeps the existing suite passing unchanged, apart from the one doctest named in Task 1.

## Review Focus

1. **A disk dropping while a big batch is still queuing copies.** The replay of 500k creates queues every copy before its first wait. The copies stop within `POOL_CHECK_SECONDS`, not when queuing ends. Pinned in Task 3 by `test_copies_stop_while_the_replay_is_still_queuing`.
2. **The referenced copy of a big job** (`do_referenced_copy`, 500k links and folders written into the new version) when a vault disk drops: it stops too. Pinned in Task 3 by `test_the_referenced_copy_stops_when_a_vault_disk_drops`.
3. **A lost monitored root with a batch pending.** The watcher's lost-root wait and the batch loop's new monitored wait both wait for the same path; one `FAILED: waiting` line per period, not two. Pinned in Task 2 by `test_a_lost_root_alerts_once_with_a_batch_pending`.
4. **A job off any pool, beside jobs on pools** (`work` and `docker_volumes` on `/mnt/optane`): it never waits for a pool disk, and reads no branch list, even while another job's pool is out. Pinned in Task 1 by `test_a_path_off_any_pool_reads_no_branch_list`, and in Task 2 by `test_a_job_off_the_pool_runs_while_the_pool_is_out`.
5. **Branch paths and job paths given through symlinks**, or with a trailing `/`: they are resolved before the mount test, so a present disk is never taken for missing. Pinned in Task 1 by `test_branches_and_paths_are_resolved`.

---

## The fake pool (shared by Tasks 1-4 and 6)

Add to `tests/harness.py` (class) and `tests/conftest.py` (fixture `fake_pool(tmp_path, monkeypatch)`):

- `class FakePool`. It keeps a mount table file at `tmp_path/'fake_mountinfo'`, starting with `22 1 8:1 / / rw - ext4 /dev/sda1 rw`. Each line it adds is `f'{id} 22 0:{id} / {path} rw - {fstype} {source} rw\n'`, with mount ids counted up from 100.
  - `add(mount_point:str, branches:list) -> list`: a `fuse.mergerfs` line (source `pool`) for `mount_point`, and an `xfs` line per branch. It makes `tmp_path/'disks'/<name>` folders when given bare names. Returns the branches' real paths.
  - `drop(branch)`: the branch's line goes; its folder stays, empty, as a disk's mount point does.
  - `mount(branch)`: the line comes back with a new mount id.
  - `fail_statvfs(branch, err=errno.EIO)`: `os.statvfs` of that path raises `OSError(err)`, through monkeypatch; other paths delegate to the real one.
  - `unreadable(mount_point, err=errno.ENOTSUP)`: the patched reader raises `OSError(err)` for that pool.
  - `reads: int`: how many times the reader ran.
  - Every change rewrites the file and calls `monitor.wake()`.
- The fixture monkeypatches:
  - `rv.MOUNTINFO_PATH` to the file;
  - `rv.FS_SIGNATURE_MONITOR` to a fresh `rv.fs_signature_monitor(mountinfo_path=<file>)`, as `tests/test_inner_mounts.py`'s `fake_mount_table` does;
  - `rv.read_pool_branches` to serve each pool's branches.
- It also sets `rv.POOL_CHECK_SECONDS = 0`, so every poll checks.
- Folders are real (tmp paths), so the vault is not really a union. A test proves "no write onto the root disk" by showing that nothing is copied, linked or committed after the drop, not by looking in the branch folder.

---

### Task 1: Pool detection, the live check and the monitor's flags

**Files:**
- Modify: `reverberator.py`:
  - `parse_mount_table` (about :3053): the fingerprint gains the fstype as a 5th field, `(mount id, device, fs root, source, fstype)`; update its doctest;
  - add the pool helpers after `current_mount_table` (about :3141);
  - `fs_signature_monitor.check_changed` (about :3473-3507);
  - add `PoolNotReady` after `VaultScanError` (about :596).
- Test: `tests/test_pool_detection.py` (new); `tests/harness.py`, `tests/conftest.py` (the fake pool).

**Interfaces:**
- Produces these constants: `MERGERFS_FSTYPE = b'fuse.mergerfs'`, `MERGERFS_CONTROL_FILE = '.mergerfs'`, `MERGERFS_BRANCHES_XATTR = 'user.mergerfs.srcmounts'` and `POOL_CHECK_SECONDS = 1.0`.
- `read_pool_branches(mount_point:str) -> list`: the xattr of `<mount_point>/.mergerfs`, decoded with `os.fsdecode`, split on `:`, empty parts dropped. It raises `OSError` (ENODATA, ENOTSUP, EIO) as `os.getxattr` does.
- `mergerfs_mount(mount_table:list, path:str) -> 'str | None'`: the mount point of the mount holding `os.path.realpath(path)`, when that mount's fingerprint has `[4:5] == (MERGERFS_FSTYPE,)`; else None. Tests' short fake fingerprints such as `('1',)` are never mergerfs.
- `PoolState = namedtuple('PoolState', ['pool', 'ids', 'problem'])`:
  - `ids` is a tuple of `(branch realpath, mount id bytes or None)` in branch order;
  - `problem` is `str | None`.
- `pool_state(path:str, mount_table:list = None) -> 'PoolState | None'`:
  - None when the path is on no mergerfs mount, without reading any xattr.
  - It reads `current_mount_table()` when `mount_table` is None.
  - A branch's id is the topmost mount whose mount point equals the branch's realpath. It is missing when there is none, or when `os.statvfs(branch)` raises.
- `pool_problem(path:str, since:'PoolState' = None, mount_table:list = None) -> 'str | None'`: the state's problem, plus every branch whose id differs from `since`'s (None to an id counts too). The reasons are exact; several are joined with `'; '`:
  - `disk {b} of pool {p} is not mounted`, or for several, `disks {b1}, {b2} of pool {p} are not mounted`;
  - `disk {b} of pool {p} cannot be read: {error}` (statvfs);
  - `disk {b} of pool {p} was mounted again during this step` (mount id changed);
  - `the disks of pool {p} cannot be listed: {error}` (the branch list).
- `class PoolNotReady(JobFailure)`: its reason is the problem text, and it is never permanent.
- `class PoolGuard`:
  - `__init__(self, paths, clock = time.monotonic)` reads one mount table and takes `pool_state` of each path;
  - `problem() -> 'str | None'` is a live `pool_problem` of each path against its state at init, the first problem found;
  - `require() -> None` raises `PoolNotReady(problem)` when there is one;
  - `poll() -> None` calls `require()` at most once every `POOL_CHECK_SECONDS` by `clock`, and does nothing between.
- `check_changed`:
  - The stored fingerprint of a key becomes `(mount_fingerprint(...), pool_state(real, mount_table))`, so a branch line's change re-checks the pair.
  - `fs_ok` is `state is None or state.problem is None`, then `check_fs_signature(path, signature)`; df and lsblk run only when the pool is whole.
  - When the state changes to a pool problem, the log line is `f'{path}: {problem}, pausing.'`.

- [ ] **Step 1: Write the fake pool and the failing tests** in `tests/test_pool_detection.py`:
  - `test_read_pool_branches_reads_the_control_file_xattr`: set `user.mergerfs.srcmounts = b'/a:/b'` on a real file at `tmp/.mergerfs`. The result is `['/a', '/b']`. Skip on ENOTSUP or EPERM.
  - `test_a_path_off_any_pool_reads_no_branch_list`: `pool_state(tmp_path)` is None, and `fake_pool.reads == 0`.
  - `test_a_whole_pool_has_no_problem`: two branches mounted; `pool_problem(vault)` is None, and `pool_state(vault).ids` holds both ids.
  - `test_a_missing_disk_is_named`: drop `a`. The result is `f'disk {a} of pool {vault} is not mounted'`. Dropping `b` too gives `f'disks {a}, {b} of pool {vault} are not mounted'`.
  - `test_a_failed_disk_still_mounted_is_named`: `fail_statvfs(a)`. The result starts with `f'disk {a} of pool {vault} cannot be read: '`.
  - `test_an_unreadable_branch_list_names_the_pool`: `unreadable(vault)`. The result starts with `f'the disks of pool {vault} cannot be listed: '`.
  - `test_a_disk_mounted_again_counts_against_the_ids_taken_before`:
    - `guard = PoolGuard([vault])`, then `drop(a)` and `mount(a)`;
    - `guard.problem() == f'disk {a} of pool {vault} was mounted again during this step'`;
    - `pytest.raises(rv.PoolNotReady)` on `guard.require()`, and `isinstance` it of `rv.JobFailure`.
  - `test_branches_and_paths_are_resolved`: the branch list names a symlink to a mounted branch folder, and the job path is given through a symlink to the pool, with a trailing `/`. `pool_problem` is None.
  - `test_poll_checks_at_most_once_a_period`: with `POOL_CHECK_SECONDS = 10` and a fake clock, `poll()` at t=0, 5, 9 reads the branch list once (after init). At t=10 it reads again and raises after a `drop`.
  - `test_the_monitor_clears_and_sets_a_flag_on_a_branch_change`: `flag = monitor.register(vault, 'N/A')`, then `check_changed()` → set; `drop(a)`, `check_changed()` → cleared; `mount(a)`, `check_changed()` → set. With `counted_signatures` (as in `tests/test_fs_monitor.py`), a pair with a signature runs no df while the pool is missing.
  - `test_mount_table_fingerprints_carry_the_fstype`: the `parse_mount_table` doctest's `table[1][1]` becomes `(b'40', b'8:17', b'/data', b'/dev/sdb1', b'xfs')`.

- [ ] **Step 2: Run them and watch them fail.** Run `.venv/bin/python -m pytest -q tests/test_pool_detection.py`. Expected: FAIL with `AttributeError` for `read_pool_branches`, `pool_state`, `PoolGuard`.

- [ ] **Step 3: Implement** the helpers, `PoolNotReady`, `PoolGuard`, the fstype field and the monitor's fingerprint and flag. Branch realpaths come from `os.path.realpath`; the job path is resolved the same way before `mergerfs_mount`.

- [ ] **Step 4: Run the new file and both full suites.** Expected: all pass on both venvs.

- [ ] **Step 5: Commit.**

### Task 2: The pause: every wait checks the pools live

**Files:**
- Modify: `reverberator.py`:
  - `wait_for_path` (about :1154-1180);
  - `JobControl.begin_wait` and `_publish` (about :660-700): each wait record gains its `alert` flag;
  - `backuper`'s batch loop (about :3726): a monitored wait beside the vault wait;
  - `README.md` and `docs/limitations.md` (the SnapRAID entry).
- Test: `tests/test_pool_pause.py` (new).

**Interfaces:**
- Consumes `pool_problem` (Task 1).
- `wait_for_path(job, flag, path, what, clock = time.monotonic, alert:bool = True) -> bool` keeps its signature.
  - Each poll computes `problem = pool_problem(path)` first.
    - With a problem, it waits, and the wait's reason is the problem.
    - Without one, it returns True when `flag.is_set() and os.path.isdir(path)` as now; otherwise the reason is `what`.
  - The reason goes to `job.update_wait` whenever it changes, so `status` shows `waiting` with `<path>: <problem>`. The marker is the existing `FAILED: waiting {N} min for {path}: {reason}`.
  - A wait that logged its marker logs one info line when it ends with True, through `tl.teeok(cut_line(shown(...)))`, never at error level. The text is exact: `reverberator job {job.job_name} goes on: {path} is ready again after {N} min`.
- `JobControl.begin_wait(path:str, what:str, alert:bool = True) -> object` stores the flag in the record, as `[token, path, what, started, alert]`.
- `JobControl.alerts(token) -> bool`: True when the token's wait has `alert` set, and no older wait of this job for the same path has `alert` set. `wait_for_path` alerts only when `alert and job.alerts(token)`.
- The batch loop: right after `wait_for_path(job, vault_fs_flag, vault_path, 'vault filesystem not ready')` and its `running()` check, add `wait_for_path(job, monitor_fs_flag, monitor_path, 'monitored filesystem not ready')` and the same check. Round 8's order at the start stays: vault wait, vault scan, monitored wait.

- [ ] **Step 1: Write the failing tests** in `tests/test_pool_pause.py`. Drive `rv.backuper` in a thread with a `JobControl`, as `tests/test_job_startup.py`'s `_run_backuper` does. Use `DISK_WAIT_GRACE_SECONDS = 0.1` and `poll_fast`.
  - `test_a_missing_vault_disk_pauses_the_job_with_the_waiting_marker`:
    - Set up a committed V0, an orphan `V1` (`write_incomplete_version`), the vault on a fake pool and its branch `a` dropped.
    - While paused: the log holds `f'reverberator job job FAILED: waiting 0 min for {job.vault}: disk {a} of pool {job.vault} is not mounted'`; the orphan is still there (no scan); no version is committed; `job` state is `waiting`.
    - After `mount(a)`: the orphan goes, a version is committed, and `f'reverberator job job goes on: {job.vault} is ready again after 0 min'` is logged once.
  - `test_a_missing_monitored_disk_pauses_the_backup_but_not_the_vault_scan`:
    - The monitored path is on a fake pool with a branch dropped.
    - The orphan is removed (the scan ran), no version is committed, and the marker names the monitored path and the disk.
    - After `mount`, the backup commits.
  - `test_the_watcher_keeps_queuing_while_the_vault_pool_is_out`:
    - Start `rv.watcher` and `rv.backuper` with a shared queue (as `tests/test_jobs.py`'s `_run_backuper` does), and drop a vault branch.
    - Write `monitor/new.txt`. Its event is in the queue while the backuper waits.
    - After `mount`, the next version holds `new.txt`.
  - `test_a_disk_dropped_between_batches_pauses_the_next_one`: one batch commits, then `drop`, then queue an event. No second version appears, and the marker appears. After `mount`, the second version is committed.
  - `test_a_lost_root_alerts_once_with_a_batch_pending`:
    - Two waits for the same path in one `JobControl`: the first with `alert=True`, the second with `alert=True` begun later.
    - Exactly one marker line per period.
    - A first wait with `alert=False` leaves the second one alerting (the start-up case `test_watcher_leaves_the_startup_wait_alert_to_the_backuper` keeps passing).
  - `test_a_job_off_the_pool_runs_while_the_pool_is_out`: another job's pool has a branch dropped. This job, on plain tmp folders, commits its backup and logs no `FAILED: waiting`.
  - `test_a_wait_that_never_alerted_ends_silently`: a pool problem shorter than the grace logs no marker and no `goes on` line.

- [ ] **Step 2: Run them and watch them fail.** Expected: FAIL. The job backs up through the dropped branch, and the `goes on` line is missing.

- [ ] **Step 3: Implement** the live check in `wait_for_path`, the alert flag, and the batch loop's monitored wait.

- [ ] **Step 4: Docs.**
  - `docs/limitations.md`: add the known limitation `### A SnapRAID fix while reverberator runs`, with:
    - kind: known limitation;
    - what the operator sees: a replaced disk is mounted, so jobs resume while `snapraid fix` restores its files;
    - why: nothing tells a disk being rebuilt from one that is whole;
    - revisit when: it bites;
    - approved: 2026-10-23, the user's choice "Known limitation, README says stop it (Recommended)".
  - `README.md`, under "Failure handling and log markers", after the sentence on a missing disk, add the line:
    > mergerfs pools: when a job's vault or monitored path is on a mergerfs pool, every disk of the pool must be there. While one is not mounted or cannot be read, the job waits with the FAILED: waiting marker, whose reason names the disk (disk /mnt/jank_data/a58 of pool /mnt/jank is not mounted): it makes no backup, prune or commit, and no vault scan while a vault disk is out. Its watcher keeps queuing changes, which are backed up once the disk is back. A disk that drops during a backup stops its copies and fails the attempt before anything is deleted or committed. Once a wait that alerted ends, one line says the job goes on.
  - Under "Known limits", add:
    > Before snapraid fix rebuilds a disk of a pool, stop reverberator (systemctl stop reverberator), and start it again once the fix ends: a replaced disk counts as there as soon as it is mounted, so jobs would resume while its files are still being restored.

- [ ] **Step 5: Run the new file and both full suites.** Expected: all pass.

- [ ] **Step 6: Commit.**

### Task 3: The guards in the scan, the prune and the commit, and copies that stop

**Files:**
- Modify: `reverberator.py`:
  - `get_vault_info` (about :5006-5050);
  - `decrement_stepper`: the walk's start (about :8832) and before `rm -rf` (about :8912);
  - `backuper`'s `do_backup` call (about :3746);
  - `do_backup`:
    - its signature;
    - the V0 walk and copy wait (about :4317-4335);
    - the referenced V0 (about :4345);
    - the "No differences" commit (about :4378);
    - the commit (about :4505-4515);
  - `do_referenced_copy` (about :5581): its two loops;
  - `do_reverb_backup` (about :8926):
    - its signature;
    - `wait_for_async_commands` (about :9128);
    - `replay`'s entry loop (about :9165);
    - the recopy loop (about :9348).
  - `README.md`, `docs/limitations.md`.
- Test: `tests/test_pool_guards.py` (new).

**Interfaces:**
- Consumes `PoolGuard`, `PoolNotReady` (Task 1).
- `get_vault_info`:
  - takes `guard = PoolGuard([job_vault_path])` before `read_job_vault`;
  - right after the read, before anything else (the "shows no committed version" checks, the stale lists, the unfinished, the orphans, the move forward), calls `guard.require()`;
  - on `PoolNotReady`, logs `f'Cannot scan the vault, nothing in it is removed: {reason}'` at error level, and raises.
  - The attempt then fails (`FAILED: ...; retrying`), and the next one waits with the marker (Task 2).
- `decrement_stepper(...)`:
  - its signature is unchanged;
  - it takes `guard = PoolGuard([job_vault, monitor_path])` right before the walk;
  - right before `multiCMD.run_command(['rm','-rf',own_folder], ...)`, it computes `problem = guard.problem()`. When there is one, it calls `keep_oldest(problem)` and raises `PoolNotReady(problem)`.
  - The attempt's own retry rescans the vault, so the caller's sums need not be updated.
- `do_backup(..., pool_guard:'PoolGuard' = None)`:
  - None means `PoolGuard([vault_path, monitor_path])`, taken at its start, so direct calls (tests, `run_backup`) are guarded too.
  - The backuper takes `PoolGuard([vault_path, monitor_path])` after the batch's two waits, and passes it.
  - `pool_guard.require()`:
    - right before `manifest.commit(backup_folder)`, inside the block that already undoes on a `readlink` failure: `discard_change_list(prepared_list)`, `manifest.rollback()`, then raise;
    - before the "No differences after delta" `manifest.begin()`.
  - `pool_guard.poll()`:
    - in the V0 walk loop and in its copy wait loop (`while GREEN_LIGHT.is_set() and mcae.runningThreads`);
    - passed to `do_referenced_copy` and `do_reverb_backup`.
  - A raise inside the copy blocks goes through their `finally` (`stop_copies`), so no copy keeps writing.
- `do_referenced_copy(source_path, backup_folder, manifest, relative = False, pool_guard:'PoolGuard' = None) -> bool`: `pool_guard.poll()` once per folder and per file, beside each `GREEN_LIGHT` check.
- `do_reverb_backup(..., pool_guard:'PoolGuard' = None)`: `pool_guard.poll()`:
  - in each pass of `wait_for_async_commands`'s loop;
  - once per entry in `replay`;
  - once per rel in the recopy loop.

  None means no polling (only `do_backup` calls it).

- [ ] **Step 1: Write the failing tests** in `tests/test_pool_guards.py`. Each puts the vault on a fake pool and drops (or drops and mounts again) a branch at one point, through a wrapper of the named function.
  - `test_the_scan_removes_nothing_when_a_disk_drops_during_it`:
    - Set up a committed V0, an orphan V1, and a stale change list.
    - Wrap `rv.read_job_vault` to `drop(a)` after reading.
    - `get_vault_info` raises `rv.PoolNotReady`, and the orphan and the stale list are both still there.
  - `test_a_disk_mounted_again_during_a_prune_walk_keeps_the_oldest_version`:
    - V0 and V1 are committed, with V1 linking to V0.
    - Wrap `rv.vault_chain_hop` to `drop(a); mount(a)` on its first call.
    - `decrement_stepper(info, 'job', job.monitor)` raises `rv.PoolNotReady`. V0's folder and change list are still there, and a `FAILED: cannot remove ... as disk ... was mounted again during this step` marker is logged.
  - `test_the_commit_is_refused_when_a_disk_drops_after_the_list_is_written`:
    - Wrap `rv.prepare_change_list` to `drop(a)` after it returns.
    - `do_backup` raises `rv.PoolNotReady`, and the committed versions are unchanged.
    - `current_version` names V0, no `.reverberator-change-list-*` folder is left, and `VaultManifest(job_vault)` still describes V0.
  - `test_copies_stop_while_the_replay_is_still_queuing`:
    - A batch creates 50 files. Wrap `rv.cp_af_copy_path` to count calls and `drop(a)` on the 3rd.
    - `do_backup` raises `rv.PoolNotReady`. At most one call starts after the drop, nothing is committed, and no `*.reverberator-partial` is left in the version folder.
  - `test_the_referenced_copy_stops_when_a_vault_disk_drops`:
    - A V0 of 50 files, then a batch of one change. Monkeypatch `os.symlink` with a wrapper of the current one (the ground-truth plugin's recorder, so both see the calls) that does `drop(a)` on its 3rd call inside `do_referenced_copy`.
    - `do_backup` raises, at most one more link is made after the drop, and nothing is committed.
  - `test_a_first_backup_stops_its_copies_when_a_vault_disk_drops`: the same as the queuing test, for the V0 complete backup.
  - `test_a_monitored_disk_lost_mid_batch_commits_nothing`: the monitored path is on a fake pool, and a branch drops in the replay. `do_backup` raises, and nothing is committed.
  - `test_a_failed_attempt_waits_then_compares_the_whole_tree`:
    - Run the backuper thread, and drop the branch during the replay.
    - The log shows `FAILED: disk ... ; retrying` (via `run_job`, or `job.failure.reason`), and then the waiting marker.
    - After `mount`, a full comparison commits the batch's change.

- [ ] **Step 2: Run them and watch them fail.** Expected: FAIL. The scan removes the orphan, the prune removes V0, and the commit and the copies go on.

- [ ] **Step 3: Implement** the guards and the polls.

- [ ] **Step 4: Docs.**
  - `docs/limitations.md`: remove `### A pool disk missing during a scan or a prune`.
  - `README.md` "Known limits": remove the line beginning "A mergerfs disk of the vault pool that is out can stop a job".

- [ ] **Step 5: Run the new file and both full suites.** Expected: all pass. The ground-truth plugin reports no violation.

- [ ] **Step 6: Commit.**

### Task 4: Vault folders flushed on the disks, and the flush after the link swap

**Files:**
- Modify: `reverberator.py`:
  - add `fsync_vault_folder` after `fsync_path` (about :1749);
  - `place_change_list` (about :1804);
  - `vault_prune_salt`'s `make_secret` (about :8386);
  - `do_backup`'s commit, right after `swap_current_version(...)` (about :4514);
  - `README.md`, `docs/limitations.md`.
- Test: `tests/test_vault_flush.py` (new).

**Interfaces:**
- Consumes `mergerfs_mount`, `read_pool_branches` (Task 1).
- `fsync_vault_folder(path:str) -> None`:
  - On a mergerfs pool: `rel = os.path.relpath(os.path.realpath(path), pool)`, then `fsync_path(os.path.join(branch, rel), folder=True)` for each branch where that folder exists. A branch without it (FileNotFoundError, NotADirectoryError) is passed over.
  - The first other error is raised after every branch was tried. A branch list that cannot be read raises its `OSError`.
  - Off a pool: `fsync_path(path, folder=True)`.
- Every folder fsync of a vault calls it: `place_change_list` and `make_secret` switch from `fsync_path(job_vault, folder=True)`.
- `do_backup`'s commit runs in the order prepare, manifest commit, swap, `fsync_vault_folder(job_vault)`, place. A flush that raises `OSError` is logged as a warning, `f'Could not sync {job_vault} to disk after moving current_version: {e}'`, and the commit goes on, as `place_change_list` does for its own flush.

- [ ] **Step 1: Write the failing tests** in `tests/test_vault_flush.py`:
  - `test_a_folder_on_a_pool_is_flushed_on_each_branch_holding_it`:
    - Branches `a`, `b`, `c`; `job/` exists on `a` and `c` only. Patch `rv.fsync_path` to record calls.
    - `fsync_vault_folder(<pool>/job)` records exactly `[(a/job, True), (c/job, True)]`.
  - `test_a_folder_off_any_pool_is_flushed_itself`: the record is `[(path, True)]`.
  - `test_an_error_on_one_branch_still_flushes_the_others`: `a/job` raises EIO. `c/job` is still recorded, and the EIO is raised.
  - `test_the_commit_flushes_the_job_vault_after_the_swap`:
    - Record `prepare_change_list`, `VaultManifest.commit`, `swap_current_version`, `fsync_vault_folder` and `place_change_list` in a second backup.
    - From the first `prepare`, the sequence starts `['prepare', 'manifest', 'swap', 'flush', 'place']`, and the flush's argument is the job vault.
  - `test_the_change_list_and_the_salt_are_flushed_through_the_helper`: `place_change_list` and a first `vault_prune_salt` each call `fsync_vault_folder(job_vault)`.
  - `test_a_failed_flush_after_the_swap_still_commits`: `fsync_vault_folder` raises EIO once. The version commits, and the warning is logged.

- [ ] **Step 2: Run them and watch them fail.** Expected: FAIL with `AttributeError: fsync_vault_folder`.

- [ ] **Step 3: Implement.**

- [ ] **Step 4: Docs.**
  - `docs/limitations.md`: remove `### current_version left behind by a power loss`.
  - `README.md` design notes: add
    > On a mergerfs pool, whose folder fsync reaches no disk, the job vault is flushed on each disk that holds it, after current_version moves and after the change list is placed.

- [ ] **Step 5: Run the new file and both full suites.** Expected: all pass.

- [ ] **Step 6: Commit.**

### Task 5: Changes after a move are replayed after it

**Files:**
- Modify: `reverberator.py`:
  - `order_backup_entries_for_replay` (about :5135-5158) and its docstring;
  - `do_reverb_backup`'s `sync_attributes` (about :9067), split;
  - the move branch's metadata sync (about :9268-9271);
  - add `entry_metadata` near `copy_file_meta` (about :5652);
  - `README.md`, `docs/limitations.md`.
- Test: `tests/test_moves_then_changes.py` (new); a unit test appended to `tests/test_backup_replay_ordering.py`.

**Interfaces:**
- `order_backup_entries_for_replay(backup_entries:dict) -> OrderedDict`. The order is deletes, then rest-before, then moves, then rest-after.
  - A create, modify or attrib entry is rest-after when a move entry earlier in `backup_entries` landed at its path or on a folder above it.
  - The test walks the entry's path and each folder above it (with `/`) against the set of move destinations seen so far: O(depth), never O(moves).
  - Both rests are sorted shallowest first, as now. Deletes and moves are unchanged.
- `entry_metadata(path:str) -> tuple`, by `lstat`, never followed:
  - for a symlink: `('link', uid, gid, mtime_ns)`;
  - otherwise: `(st_mode, uid, gid, mtime_ns, sorted (name, value) xattrs)` (`os.listxattr` and `os.getxattr`, `follow_symlinks=False`).
  - It raises `OSError`.
- Inside `do_reverb_backup`: `attribute_end(source_real_path, relative_path) -> 'str | bool'`:
  - It is today's `sync_attributes` up to `copy_file_meta`.
  - It returns the path the metadata goes onto: the entry itself, or its chain end.
  - It returns True for nothing to sync (the referenced-backup link), or False after a `refuse(...)`.
  - `sync_attributes` becomes `attribute_end` plus `copy_file_meta(source, end)` when it is a str, with the same results as now.
- The move step, after the rename, for a file whose target is a chain link (`os.path.islink(target)` and `own_chain_hop(target)` is not None):
  - `end = attribute_end(source, rel)`.
  - When `end` is a str and `entry_metadata(source) != entry_metadata(end)` (an `OSError` counts as differing):
    - with `only_sync_attributes`: `copy_file_meta(source, end)`;
    - otherwise: `cp_af_copy_path(source, target, mcae, pending)` and `manifest.add(rel, dirty=True)`, as the attrib branch replays an attribute change.
  - Other targets keep today's `copy_file_meta(source, target)`, which covers a moved real copy and a moved user link (lchown and lutimes only).
- No change to the collapse, the change-list, the pending-transactions or the history format.

- [ ] **Step 1: Write the failing tests.**
  - In `tests/test_backup_replay_ordering.py`:
    - `test_changes_at_or_under_a_move_destination_after_the_move_come_after_the_moves`:
      - entries `[move /m/e/ from /m/d/, attrib /m/e/y, create /m/e/new, modify /m/x]`;
      - the order is `['/m/x', '/m/e/', '/m/e/y', '/m/e/new']`, with the rest-after sorted shallowest first.
    - `test_changes_before_a_move_stay_before_it`: `[attrib /m/d/y, move /m/e/ from /m/d/]` keeps the attrib first.
  - In `tests/test_moves_then_changes.py`:
    - Each test commits V0 with `run_backup`, then changes the live tree.
    - It builds the batch with `rv.change_events_to_backup_entries(deque([...ChangeEvent...]), job.monitor)`, as the watcher would queue it, and runs `run_backup(job, entries)` without `touched`, so the verification cannot hide a wrong replay.
    - For each, it reads the new version through `resolve_version_entry` (content, mode, owner, xattrs, link text). The captured log has no `IsADirectoryError`, `Failed to move` or `Doing delete & copy instead`. A file left alone in a moved folder is still a symlink in V1 (not copied again).
    - The tests:
      - `test_mv_then_chmod_of_the_moved_file`: `mv x d/x; chmod 600 d/x`. The chain end has mode 600, and V0's x (the shared copy) shows 600 too, the shared-copy rule. With `only_sync_attributes=False`, V1's `d/x` is a real copy with mode 600, and V0's x keeps its mode.
      - `test_mv_then_chown_of_the_moved_file` (root only, skip otherwise): `chown 1234:1234`.
      - `test_mv_then_an_xattr_of_the_moved_file`: `user.k = b'v'`. Skip when user xattrs are unsupported.
      - `test_a_moved_user_link_then_lchown` (root only): the stored link's owner is 1234, and its text is unchanged.
      - `test_mv_folder_deep_then_chmod_inside`: `mv F p/q/F; chmod 600 p/q/F/y`.
      - `test_mv_folder_then_chown_inside` (root only): `mv d e; chown e/y`.
      - `test_mv_folder_then_create_inside`: `mv d e; echo new > e/new`.
      - `test_mv_folder_then_modify_inside`: `mv d e; echo changed > e/old`.
    - `test_a_plain_move_leaves_the_shared_copy_alone`: `mv x d/x` with no attribute change. `entry_metadata` of V0's x is equal before and after, and a spy on `rv.copy_file_meta` records no call with V0's x.

- [ ] **Step 2: Run them and watch them fail.** Expected: FAIL:
  - the chmod, chown and xattr are lost;
  - the folder cases log `IsADirectoryError` and `Doing delete & copy instead`, and copy `e/old2` again.

- [ ] **Step 3: Implement.**

- [ ] **Step 4: Docs.**
  - `docs/limitations.md`: remove `### Attribute changes after a move in the same batch`.
  - `README.md` "Known limits": remove the line beginning "A file moved and then chmod'ed".
  - `README.md` design notes, after the batch-verification line, add:
    > Changes made in one batch after a move, at the moved path or inside a moved folder (mv x d/x; chmod 600 d/x, or mv d e; echo new > e/new), are replayed after the move, so a folder is moved, not copied again, and a moved file's new mode, owner and extended attributes reach the new version.

- [ ] **Step 5: Run the new files and both full suites.** Expected: all pass, with no ground-truth violation.

- [ ] **Step 6: Commit.**

### Task 6: Restore skips pruning's temporaries; restore and history warn on a missing vault disk; 0.45

**Files:**
- Modify: `reverberator.py`:
  - add `is_prune_temp` after `remove_stale_partials` (about :10885);
  - `restore_entry`'s walk (about :11043-11090), the non-folder branch;
  - add `vault_pool_warning` near `require_job_vault` (about :10309);
  - `history_command` (about :10320) and `restore_command` (about :11440);
  - `__version__` (:58);
  - `pyproject.toml`, `README.md`, `docs/limitations.md`.
- Test: `tests/test_restore_pool.py` (new).

**Interfaces:**
- Consumes `pool_problem` (Task 1), and `resolve_version_entry`, `same_inode` and `PARTIAL_COPY_NAME` (existing).
- `is_prune_temp(job_vault:str, version_path:str, rel:str, monitor_path:str, moves:'VaultMoves') -> bool`. It is True when `basename(rel)` fully matches `PARTIAL_COPY_NAME`, and its `lstat` is the same inode as the `lstat` of the `path` of `resolve_version_entry(...)`, with kind `file` or `symlink`, for some symlink sibling in the same folder of the version.
  - It stops at the first match.
  - Any `OSError` gives False, so the entry is restored as now.
  - No salt is read.
- `restore_entry`'s walk: a non-folder entry for which `is_prune_temp(...)` is True is passed over silently: not restored, not counted, no warning. Folder restores only; a restore that names such a path itself restores it as now.
- `vault_pool_warning(job_vault:str, stream = sys.stderr) -> bool`:
  - With `problem = pool_problem(job_vault)`, it prints exactly `f'Warning: {problem}: what it holds of {job_vault} is not shown'` (through `shown()`), and returns True.
  - With no problem, it prints nothing and returns False.
- `history_command` and `restore_command` call it once, inside the restore lock, before `require_job_vault`. A command that would return 0 returns `EXIT_COMMAND_FAILED` (1) when it warned. 1 and 2 (and a `CommandError`'s code) are unchanged.
- `__version__ = 0.45`; `pyproject.toml` `version = "0.45"`.

- [ ] **Step 1: Write the failing tests** in `tests/test_restore_pool.py`:
  - `test_a_folder_restore_skips_a_prune_temp`:
    - Set up committed V0 `d/a` (a copy) and V1 `d/a` (a chain link to V0's), as a backup makes them.
    - Add `os.link(V0/d/a, os.path.join(V1/d, os.path.basename(rv.prune_link_path(V1/d/a, os.lstat(V0/d/a), salt))))`, with the vault's salt from `rv.vault_prune_salt`.
    - `restore --version 1 d DEST` exits 0, `DEST/d` holds only `a`, and nothing of the `.reverberator-partial` form appears.
  - `test_a_prune_temp_without_a_salt_is_skipped_too`: the same, with `prune_link_path(..., None)` and no `.reverberator_prune_salt`.
  - `test_a_users_file_of_the_temp_form_is_restored`: V1 `d/.<32 hex>.reverberator-partial` is a real file of its own, sharing no inode with a sibling's copy. It is restored with its bytes.
  - `test_a_killed_prune_then_the_next_prune_consumes_its_temp`:
    - Make `os.rename` raise `KeyboardInterrupt` on the temp's rename once in `decrement_stepper`, and catch it in the test. That is a kill: `link_copy`'s `except Exception` does not clean it up, so the temp is left.
    - A folder restore of V1 writes no temp.
    - The next `decrement_stepper` removes V0, and the temp is gone.
  - `test_history_warns_and_exits_1_when_a_vault_disk_is_missing`:
    - The vault is on a fake pool with `a` dropped.
    - `rv.run_command(['history', ...])` prints the history on stdout, and exactly `f'Warning: disk {a} of pool {job.vault} is not mounted: what it holds of {job.job_vault} is not shown'` on stderr. It returns 1.
  - `test_restore_runs_warns_and_exits_1_when_a_vault_disk_is_missing`: the file is restored, the same warning is printed once, and it returns 1.
  - `test_commands_off_any_pool_print_no_warning`: an existing history run returns 0, with an empty stderr.

- [ ] **Step 2: Run them and watch them fail.** Expected: FAIL. The restore writes out the temp, and the commands print no warning and return 0.

- [ ] **Step 3: Implement**, and set the version.

- [ ] **Step 4: Docs.**
  - `docs/limitations.md`: remove `### A prune's temporary file left in the next version`.
  - `README.md` "Known limits": remove the line beginning "A prune killed between its hard link and its rename".
  - `README.md` design notes, after the salt line, add:
    > A prune cut off between its hard link and its rename leaves a hidden .<hash>.reverberator-partial beside a link of the next version; the next prune uses and removes it, and a restore never writes it out (it is told by being the same file as a link beside it leads to).
  - `README.md` "Exit codes of the commands", at the end, add:
    > history and restore still run while a disk of the vault's mergerfs pool is missing: they print a warning on stderr naming the disk, as what it holds is not shown, and exit 1.

- [ ] **Step 5: Run the new file and both full suites.** Expected: all pass on both venvs.

- [ ] **Step 6: The live read-only scan.**
  - Copy `/tmp/claude-0/-mnt-optane-work-reverberator/8ad4e979-212b-4a0b-9477-1847dfee5560/scratchpad/ff/live/live_scan_refused.py` to `/tmp/claude-0/-mnt-optane-work-reverberator/8ad4e979-212b-4a0b-9477-1847dfee5560/scratchpad/r9/live_scan_refused.py`, with its `sys.path.insert` pointed at this worktree.
  - Run it with the service venv's python.
  - Expected: all 8 jobs scan, with zero refused writes. The pool checks only read: mountinfo, getxattr and statvfs.

- [ ] **Step 7: Commit.**

---

## Self-review notes

- **Spec coverage:**
  - Goal 1: Tasks 1 (pools, missing, ids, monitor) through 3 (scan, prune, commit, copies). Task 2 covers the pause, the waiting marker, the flags, queuing, the goes-on line, before every batch, and plain paths unchanged.
  - Goal 2 → Task 4.
  - Goal 3 → Task 5.
  - Goal 4 → Task 6.
  - Goal 5 → Task 6. `status` shows the pause through `begin_wait`/`update_wait` (Task 2).
  - Goal 6 → docs in each task, and the version in Task 6.
  - Every test the spec lists has a named test in its task. "No file is written into the branch's empty folder" is shown by no copy, link or commit after the drop, as the fake vault is no union (see The fake pool).
- **Types:** `PoolGuard`, `PoolNotReady`, `pool_problem`, `pool_state`, `read_pool_branches`, `mergerfs_mount`, `fsync_vault_folder`, `attribute_end`, `entry_metadata` and `is_prune_temp` are used under the same names and signatures in every task.

## Calls to confirm

Decisions this plan makes that the design leaves open and that change behaviour:

1. **One guard covers both pools inside a backup.** A monitored-pool disk lost mid-batch stops the copies and the prune at once, not only at the commit check, as for a vault disk. The vault scan checks the vault pool only, keeping round 8's order.
2. **A prune stopped by a missing disk logs two markers.** `keep_oldest`'s own `FAILED: cannot remove …, as disk … ; it is kept` (at most hourly), then the attempt's `FAILED: …; retrying`.
3. **How fast copies stop.** During a batch the pools are checked live at most once a second (`POOL_CHECK_SECONDS = 1.0`): per queued copy, per referenced link or folder, per replayed entry and in copy waits. Copies stop within about a second of the drop being visible.
4. **The scan, prune and commit fail the attempt** (`PoolNotReady` is a `JobFailure`, so `FAILED: <reason>; retrying in Ns`). The next attempt waits with the waiting marker.
5. **The exact reason texts:**
   - `disk X of pool P is not mounted`
   - `disks X, Y of pool P are not mounted`
   - `disk X of pool P cannot be read: …`
   - `disk X of pool P was mounted again during this step`
   - `the disks of pool P cannot be listed: …`

   Several are joined with `; `.
6. **The end-of-wait line** is `reverberator job <name> goes on: <path> is ready again after <N> min`, at info (ok) level. It is logged only by a wait that alerted.
7. **One alert per path.** A job's wait alerts only when no older alerting wait of the same job waits for the same path. This keeps the new batch-loop wait for the monitored path and the watcher's lost-root wait from doubling the hourly marker.
8. **A moved file whose live metadata differs from its chain end:**
   - with Only Sync Attributes, the metadata goes onto the shared copy at the chain end, so older versions show it too;
   - without it, the file is copied into the new version, as any attribute change is replayed today.

   Compared are the mode, owner, group, mtime (ns) and xattrs; for a symlink, the owner, group and mtime.
9. **A failed flush after the link swap** is a warning, and the commit goes on, like the change list's flush today. A pool whose branch list cannot be read makes the flush fail the same way.
10. **Restore passes over pruning's temporary silently** (no warning, not counted), in folder restores only. A restore naming the temp's own path restores it.
11. **Restore and history with a missing vault disk exit 1** (the existing "anything failed" code), not a new code. A usage error (2) still wins. The warning text is `Warning: <reason>: what it holds of <job vault> is not shown`, and only the vault's pool is checked, not the monitored one. This extends what exit 1 means for these commands. Should it get a LESSONS.md entry, or does it count as a new behaviour the user asked for?
12. **When the ids are taken:** a batch takes them right after its two waits, a prune at its walk's start, a scan at its start, and a direct `do_backup` call at its start.
13. **The "No differences" commit** (skip fingerprint and inner mounts, no new version) is guarded too.
