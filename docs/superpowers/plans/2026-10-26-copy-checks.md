# Copies Trusted Once On Disk, A Matching Time For Full Comparisons, No Phantom After A Move-Out Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A copy read back from the vault is recorded checked only once it is 10 min old. A full comparison reads xattrs only of entries changed since the vault last matched the whole tree. A move-out whose pair cannot come any more goes into the batch it belongs to. A restart whose pending batch holds only scans still compares the whole tree. Version 0.46.

**Architecture:**
- Goal 1 is one rule in `read_vault_record()`: a regular file's record is unchecked while the chain end's `st_ctime_ns` is within `CHECKED_COPY_AGE_SECONDS` of now.
- Goal 2 has two halves:
  - The watcher stamps the queue with `read_wall_ns`: the wall clock time at which its latest read began whose events are all queued. `take()` carries it into the batch.
  - The backuper passes `do_backup(matched_since=...)`, and do_backup's final commit writes the meta key `matched` = `[version folder name, ns]`. The key advances, is carried forward or is left alone, and `full_comparison_since()` reads it.
- Goal 3 changes one branch of the watcher. A read that returns nothing once the tree is quiet queues every pending move-out as its delete.
- Goal 5 counts a resumed pending batch as round-tripped, and runs the follow-up full comparison from either way a batch completes.

**Tech Stack:** Python ≥ 3.8, the single module `reverberator.py` (tab-indented), pytest.

**Spec:** `docs/superpowers/specs/2026-10-26-copy-checks-design.md`. Its "The user's words" section is the source of truth. The user's rules are in `/mnt/optane/work/agent-rules/RULES.md`.

## Global Constraints

- **Where to work.** Work only in the worktree `/mnt/optane/work/reverberator/.worktrees/copy-checks`, on branch `copy-checks`.
  - Never write under `/mnt/jank`, `/mnt/impulse` or `/mnt/klein`.
  - Never write in the main checkout `/mnt/optane/work/reverberator`: the live service runs from it.
  - Never commit `uv.lock`.
- **Never run `sudo sysctl` or `sysctl -w`.**
- **Tests.** Run from the worktree root, at 2 processes at most (one pytest at a time is fine). Both full suites must pass:
  - `.venv/bin/python -m pytest -q -p no:cacheprovider`
  - `PYTHONDONTWRITEBYTECODE=1 /mnt/optane/work/reverberator/.venv/bin/python -m pytest -q -p no:cacheprovider`
  - Both stand at 1476 passed, 1 skipped at 821ab79; a full run takes about 3 min.
  - `tests/test_jobs.py::test_fs_monitor_invalidate_sets_the_flag_again_when_the_check_passes` can fail under load and passes alone. Rerun it alone before treating it as a failure.
  - The ground-truth plugin `tests/chain_ground_truth.py` stays on. It wraps `do_backup` with `*args, **kwargs`, so the new keyword passes through.
- **Library versions.** Code must run on the live venv's older libraries (Tee_Logger 6.40, multiCMD 1.51, TSVZ 3.39) and on the worktree's.
- **Formats.** No change-list, pending-batch or history format change. The new meta key `matched` is an addition that the older daemon ignores.
- **No flush.** No fsync is added on the write path or the read path (spec Non-goals).
- **Style.** Tab indentation. Match the surrounding naming, comment density, and docstring-with-doctest style.
- **Commits.** One or two plain sentences in the repository's style, ending with:
  ```
  Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01JihhsZfJ71AqrEdg8CbPKJ
  ```
- **Handoffs.** Every task's report ends with **Calls to confirm**: each proposed limitation or deferral, each changed API or behaviour, and each call of the builder's own that changed what got built. The calls listed under each task below are the known ones; add any others.

## Review Focus

1. **A batch taken at the max-delay hand-over.** That hand-over fires before the current read's events are handled, so the batch's read time must be the previous read's, never the current one's. Pinned in Task 2 by `test_a_max_delay_hand_over_carries_the_previous_reads_time`.
2. **An attempt that met an unreadable folder or file** (EIO on a failing disk) did not see the whole tree. It carries the old time forward, so a later full comparison still reads that folder's xattrs. Pinned in Task 3 by `test_an_attempt_that_met_an_unreadable_folder_carries_the_time_forward`.
3. **A restart's own full comparison on a vault with no key yet** (every vault, at the 0.46 restart) writes a key. Without one, every later restart pays the 252 s comparison until a fresh batch commits. Pinned in Task 3 by `test_a_restarts_full_comparison_records_a_key`.
4. **A move-out made while a batch is signalled but not yet taken**, as when the backuper is busy with a long batch. It still reaches that batch once the tree is quiet. Pinned in Task 4 by `test_a_move_out_reaches_a_batch_signalled_before_it`.
5. **A resumed scans-only batch whose scanned folder differs** reaches `do_backup()`. The follow-up still runs, and the resumed batch carries the time forward. Pinned in Task 5 by `test_a_resumed_scan_with_differences_is_followed_by_a_full_comparison`.

---

### Task 1: A copy is recorded as checked only once it can be on disk (Goal 1)

**Files:**
- Modify: `reverberator.py:1245` (add the constant after `VERIFY_CTIME_MARGIN_SECONDS`).
- Modify: `reverberator.py:8076-8128` (`read_vault_record`).
- Modify: `reverberator.py:6534` (one sentence in `VaultManifest`'s docstring).
- Test: `tests/test_manifest.py`.
- Modify tests that assume an immediate check: `tests/test_manifest.py`, `tests/test_long_chains.py`, `tests/test_compare_scopes.py`, `tests/test_names.py`.

**Interfaces:**
- Produces: `CHECKED_COPY_AGE_SECONDS = 600`, a module constant that tests patch.
- Produces: `read_vault_record()` keeps its signature. Its regular-file record has `unchecked=1` when the chain end's `st.st_ctime_ns > time.time_ns() - CHECKED_COPY_AGE_SECONDS * 10 ** 9`, else 0. Records of other kinds keep `unchecked=0`.
- `read_copied_record()` and `read_version_record(fresh=True)` already force `unchecked=1` and are unchanged.

- [ ] **Step 1: Write the failing tests** in `tests/test_manifest.py`, next to `test_unchecked_copy_missing_its_bytes_is_copied_again`:

```python
def test_a_young_copy_reads_back_unchecked_and_an_old_one_checked(job, monkeypatch):
	seed_monitor(job, {'a.txt': 'hello', 'sub/': None})
	v0 = run_backup(job)[0]
	monkeypatch.setattr(rv, 'CHECKED_COPY_AGE_SECONDS', 600)
	assert rv.read_vault_record(v0, 'a.txt', job.monitor).unchecked == 1
	assert rv.read_vault_record(v0, 'sub/', job.monitor).unchecked == 0
	monkeypatch.setattr(rv, 'CHECKED_COPY_AGE_SECONDS', 0)
	assert rv.read_vault_record(v0, 'a.txt', job.monitor).unchecked == 0


def test_a_full_comparison_checks_copies_only_once_they_are_old(job, monkeypatch):
	seed_monitor(job, {'a.txt': 'hello'})
	run_backup(job)
	run_backup(job)                                   # the restart's full comparison right after the backup
	manifest = rv.VaultManifest(job.job_vault)
	assert manifest.lookup('a.txt').unchecked == 1
	manifest.close()
	monkeypatch.setattr(rv, 'CHECKED_COPY_AGE_SECONDS', 0)
	run_backup(job)                                   # one after the window
	manifest = rv.VaultManifest(job.job_vault)
	assert manifest.lookup('a.txt').unchecked == 0
	manifest.close()


@pytest.mark.parametrize('loss', ['truncated', 'zeroed'])
def test_a_copy_lost_after_a_batch_read_it_back_is_copied_again(job, monkeypatch, loss):
	# the power-loss test: a later batch's check reads the young copy back (0.45 recorded it checked), then a failed
	# writeback leaves the copy short or zeroed, and the restart's full comparison must still catch it
	seed_monitor(job, {'a.txt': 'hello world'})
	copy = os.path.join(run_backup(job)[0], 'a.txt')
	run_backup(job, OrderedDict(), touched=rv.TouchedScopes(['a.txt/'], ['a.txt'], None, None))
	st = os.lstat(copy)
	if loss == 'truncated':
		os.truncate(copy, 3)
	else:
		with open(copy, 'r+b') as f:
			f.write(b'\0' * st.st_size)
		os.utime(copy, ns=(st.st_atime_ns, st.st_mtime_ns))
	lines = []
	real = rv.backuperTeeLogToTl
	monkeypatch.setattr(rv, 'backuperTeeLogToTl', lambda path, message, **kw: lines.append(message) or real(path, message, **kw))
	versions = run_backup(job)
	assert any('does not match its record, copying again' in line for line in lines)
	assert open(os.path.join(versions[-1], 'a.txt')).read() == 'hello world'
```

- [ ] **Step 2: Run them and see them fail.**
  - Run: `.venv/bin/python -m pytest -q -p no:cacheprovider tests/test_manifest.py -k "young_copy or only_once_they_are_old or lost_after_a_batch"`
  - Expected: they fail with `AttributeError: ... CHECKED_COPY_AGE_SECONDS` or an assertion on `unchecked`. The power-loss cases fail because no line says the copy does not match.

- [ ] **Step 3: Implement.**
  - Add `CHECKED_COPY_AGE_SECONDS = 600` after `VERIFY_CTIME_MARGIN_SECONDS`, with a comment. Copies older than this are trusted to be on disk: this host writes dirty pages back after 30 s, at 15 s intervals, and ten times that covers a congested writeback.
  - In `read_vault_record()`'s final return, set `unchecked` by the rule in Interfaces, using the chain end's `st` it already holds. Add one line to its docstring.
  - In the `VaultManifest` docstring, change "stays unchecked until delta generation reads the copy back" to "...reads the copy back once it is `CHECKED_COPY_AGE_SECONDS` old".

- [ ] **Step 4: Run the new tests and see them pass.** Use the Step 2 command. Expected: PASS.

- [ ] **Step 5: Fix the existing tests that assume an immediate check.** A trial run with the rule in place failed exactly these five. Each one tests that a second backup reads the copies back and records them checked, so add `monkeypatch.setattr(rv, 'CHECKED_COPY_AGE_SECONDS', 0)` (taking the `monkeypatch` fixture where it is missing) before its backups, with a comment that its copies count as old. Change nothing else.
  - `tests/test_manifest.py::test_cold_start_reads_each_copy_back_once_then_only_the_monitored_side`
  - `tests/test_manifest.py::test_content_rewritten_keeping_size_and_mtime_is_modify_without_reading_the_vault`
  - `tests/test_long_chains.py::test_recopy_comes_from_the_vault`
  - `tests/test_compare_scopes.py::test_it_leaves_the_transaction_open`
  - `tests/test_names.py::test_upgraded_database_reads_nothing_from_the_vault`

- [ ] **Step 6: Run both full suites** (Global Constraints). Expected: all pass, 4 more than 1476 (the parametrized test counts twice).

- [ ] **Step 7: Commit** `reverberator.py` and the four test files: "Record a copy read back from the vault as checked only once it is 10 min old, so a power loss cannot leave a short copy that nothing reads back again; version 0.46 work."

**Calls to confirm:**
- The rule sits in `read_vault_record()`, so it covers every read-back that stores a record.
- 600 s is a constant, not a config key.
- The five tests above are patched to an age of 0, keeping what they test.
- The design's own call stands: nothing is flushed, and the rule relies on the kernel writing dirty data back within 600 s.

---

### Task 2: The queue carries the time of the latest read whose events are all queued (Goal 2, first half)

**Files:**
- Modify: `reverberator.py:215-370` (`ChangeEventQueue`: docstring, `__init__`, `take`).
- Modify: `reverberator.py:2468-2690` (the `watchFolder` loop).
- Modify: `tests/harness.py` (add `scripted_watch`).
- Test: `tests/test_matched_time.py` (new).
- Test: `tests/test_inotify.py`.

**Interfaces:**
- Produces: `ChangeEventQueue.read_wall_ns: int | None`. It is None until the watcher sets it.
  - Set in `__init__` only: `clear()`, and `append()` of a full scan, leave it as it is.
  - `take()` copies it into the batch and keeps it on the queue.
  - Callers hold `to_process_lock`, as for every other use of the queue.
- Produces: the watcher takes `read_began = time.time_ns()` just before each `inotify_obj.read()`. It sets `to_process.read_wall_ns = read_began`, under `to_process_lock`, once every event of that read is queued:
  - For an empty read, just before the quiet-hand-over check. (Task 4 queues the move-outs before this point.)
  - For a non-empty read, after the `for event in events` loop.
  - So the max-delay hand-over, which fires before the read's events are handled, hands over the previous read's time.
- Produces, in `tests/harness.py`: `scripted_watch(monkeypatch, monitor:str, reads:list, flag=None, queue=None, **watch_kwargs) -> tuple`. It runs `rv.watchFolder` synchronously on `monitor`, with an inotify that returns each item of `reads` in turn and then stops.
  - Each item is a list of `(mask, name, cookie)` on the root watch (wd 1), or a callable taking the queue and returning such a list.
  - After the last item, the fake clears `rv.GREEN_LIGHT` and returns `[]`. `conftest` sets it again.
  - It patches `rv.inotify_simple.INotify` (a context manager with `read`, `add_watch` returning 1, and `rm_watch`) and `rv.initializeFolderWatchers` (it sets `wdDic[1] = monitor` and returns 1), as `tests/test_jobs.py::_fake_inotify_with` does.
  - It returns `(queue, flag, returned)`. `returned` is a list of the wall clock ns at which each read returned. The queue is `rv.ChangeEventQueue(monitor)` and `flag` is a `threading.Event`, unless they are passed in.
- Consumed by: Task 3 (`take()`'s `read_wall_ns`) and Task 4 (`scripted_watch`).

- [ ] **Step 1: Write the failing tests.**

In `tests/test_matched_time.py` (new; `pytestmark = pytest.mark.unit`):

```python
def test_take_carries_the_read_time_and_keeps_it():
	queue = rv.ChangeEventQueue('/m')
	assert queue.read_wall_ns is None
	queue.read_wall_ns = 5
	queue.append(rv.ChangeEvent(1.0, False, 'modify', '/m/a', None))
	taken = queue.take()
	assert taken.read_wall_ns == 5 and queue.read_wall_ns == 5
	queue.append(rv.ChangeEvent(2.0, False, 'full_scan', '/m', None))
	assert queue.read_wall_ns == 5


class RecordingFlag(threading.Event):
	'''A flag that records the queue's read time at the moment the watcher signals.'''
	def __init__(self):
		super().__init__()
		self.queue, self.seen = None, []
	def set(self):
		self.seen.append(self.queue.read_wall_ns)
		super().set()


def test_a_max_delay_hand_over_carries_the_previous_reads_time(job, monkeypatch):
	flags = rv.inotify_simple.flags
	flag = RecordingFlag()
	monitor = job.monitor
	# reads[0]'s events are queued; reads[1] arrives while the tree is busy and the max delay has passed
	reads = [[(flags.CREATE, 'a', 0)], [(flags.CREATE, 'b', 0)]]
	flag.queue = rv.ChangeEventQueue(monitor)
	queue, _, returned = scripted_watch(monkeypatch, monitor, reads, flag=flag, queue=flag.queue,
		min_snapshot_delay_seconds=3600, max_shapshot_delay_seconds=0)
	# read 0 began before it returned; read 1's events were not all queued when it was handed over
	assert flag.seen and flag.seen[0] is not None and flag.seen[0] <= returned[0]
	assert queue.read_wall_ns >= returned[0]
```

In `tests/test_inotify.py`:

```python
def test_a_read_time_past_a_change_means_its_event_is_queued(job, poll_fast):
	to_process = rv.ChangeEventQueue(job.monitor)
	flag = threading.Event()
	thread, lock = _start_watch(job, to_process, flag)
	try:
		_wait_watch_ready(job, to_process, lock)
		path = os.path.join(job.monitor, 'f.txt')
		open(path, 'w').write('a')
		done = time.time_ns()
		def published():
			with lock:
				return (to_process.read_wall_ns or 0) > done, [e for e in to_process if e.path == path and e.event == 'create']
		wait_until(lambda: published()[0], message='no read time past the change')
		assert published()[1]
	finally:
		rv.GREEN_LIGHT.clear()
		thread.join(timeout=2)
		rv.GREEN_LIGHT.set()
```

- [ ] **Step 2: Run them and see them fail.**
  - Run: `.venv/bin/python -m pytest -q -p no:cacheprovider tests/test_matched_time.py tests/test_inotify.py -k "read_time or max_delay_hand_over"`
  - Expected: FAIL with `AttributeError: 'ChangeEventQueue' object has no attribute 'read_wall_ns'` (or an ImportError for `scripted_watch`).

- [ ] **Step 3: Implement.**
  - `ChangeEventQueue`: add `read_wall_ns` per Interfaces. Describe it in the docstring after `first_wall_ns`, and extend the doctest by one line: a `take()` keeps it on both queues.
  - Watcher: set `read_began` and publish it per Interfaces.
  - `tests/harness.py`: add `scripted_watch`.
  - `tests/test_crash_safety.py` passes a `deque` to `watchFolder`, but its run returns on the first read, before any publish; leave it alone.

- [ ] **Step 4: Run the new tests and see them pass.** Use the Step 2 command. Expected: PASS.

- [ ] **Step 5: Run both full suites.** Expected: all pass.

- [ ] **Step 6: Commit** `reverberator.py`, `tests/harness.py`, `tests/test_matched_time.py` and `tests/test_inotify.py`: "The watcher stamps its queue with the time its latest read began once all that read's events are queued, and a batch takes the stamp along."

**Calls to confirm:**
- The stamp survives `take()` and `clear()`. An older stamp is always a safe claim, never a wrong one.
- An empty read publishes its time before the quiet hand-over signals.

---

### Task 3: The `matched` key, its use as the full comparison's xattr bound (Goal 2, second half)

**Files:**
- Modify: `reverberator.py:6667-6713` (`VaultManifest`: add `matched` and `record_matched` beside `skip_fingerprint`).
- Modify: `reverberator.py:8651-8673` (`full_comparison_since`, and its doctest).
- Modify: `reverberator.py:4652-4960` (`do_backup`: a new keyword; its "No differences" commit at :4804-4815; its final commit at :4920-4935; the full comparison's bound at :4787).
- Modify: `reverberator.py:3888-4140` (`backuper`: compute `matched_since` at its two take sites and before `do_backup`).
- Leave alone: `compare_scanned_folders` (:3888) keeps `full_comparison_since(vaultInfo.vault_info_dict)`, today's rule. `delta_generate_backup_entries` writes no key.
- Test: `tests/test_matched_time.py`.
- Test: `tests/test_vault_scan.py` (the cut-off commit).

**Interfaces:**
- Consumes: `ChangeEventQueue.read_wall_ns` (Task 2).
- Produces: `VaultManifest.matched -> tuple | None`. It is the `matched` meta key's `(version folder name:str, wall ns:int)`, or None when the key is absent or does not parse.
- Produces: `VaultManifest.record_matched(version_path:str, since:int = None, base_path:str = None) -> None`. The caller holds the transaction.
  - With `since`, it writes `["<basename of version_path>", since]`.
  - Else, when `matched` names `basename(base_path)`, it writes that old time with the new name.
  - Else it writes nothing.
- Produces: `full_comparison_since(vault_info_dict:OrderedDict, matched:tuple = None) -> int`. It returns `matched[1]` when `matched` names the newest committed version's folder (`basename` of its path). Otherwise it uses today's rule. The margin is still taken off downstream, in `ctime_bound()`.
- Produces: `do_backup(..., matched_since:int = None)`. This is the wall clock ns from which the attempt saw the whole tree, or None when it did not. Both commits call `manifest.record_matched()`, in their transaction, just before `manifest.commit(...)`:
  - At the final commit (V0 and later): `version_path=backup_folder`, `base_path=latest_version_info.path`, or None for V0.
  - At the "No differences" commit: `version_path=base_path=latest_version_info.path`.
  - `since` is `matched_since` only when `paused` is empty at the commit (its final value, after `drop_unmounted_entries()`) and `reported` is empty (nothing was logged unreadable in this attempt). Otherwise `since` is None.
  - The full comparison's call becomes `full_comparison_since(vault_info_dict, manifest.matched)`.
- Produces: the backuper passes `matched_since=`:
  - For a full comparison, `time.time_ns()` taken just before `do_backup()`. Its walk sees every change made before it begins.
  - For a batch that is not `round_tripped`, `batch_read_ns`.
  - Else None.
  - `batch_read_ns = to_process_temp.read_wall_ns` is set at both take sites, and reset to None where `round_tripped` is reset.

The design says a full comparison uses "the queue's read time as of when it began". At a restart the watcher has not finished a read when the comparison begins, so that time is None, and the restart's comparison would write no key (Review Focus 3). This plan uses the comparison's own start instead. If the main session rules for the design's words, the change is one line: `matched_since = to_process.read_wall_ns` under the lock, and `test_a_restarts_full_comparison_records_a_key` is dropped.

- [ ] **Step 1: Write the failing tests** in `tests/test_matched_time.py`. Helpers to add there:
  - `matched(job)` opens `rv.VaultManifest(job.job_vault)`, returns `.matched` and closes it.
  - `name(path)` is `os.path.basename(path)`.
  - `modify(job, rel, text)` writes the file and returns `OrderedDict([event_entry(job, rel, 'modify')])`.
  - `_fake_mounts` as in `tests/test_inner_mounts.py`.
  - `start_backuper` and `stop_backuper` copied from `tests/test_verify_replay.py`.
  - `record_matched_since(monkeypatch)` wraps `rv.do_backup` as `record_backups` there does, appending `kwargs.get('matched_since')` for each call.
  - `user_xattrs_or_skip` imported from `tests/test_moves_then_changes.py`.

```python
def test_full_comparison_since_uses_a_key_naming_the_newest_version():
	infos = OrderedDict([(4, rv.VaultEntry(4, '/v/V4--a', 100.0, 0, 0)), (5, rv.VaultEntry(5, '/v/V5--b', 200.0, 0, 0))])
	assert rv.full_comparison_since(infos, ('V5--b', 150 * 10 ** 9)) == 150 * 10 ** 9
	assert rv.full_comparison_since(infos, ('V4--a', 150 * 10 ** 9)) == 100 * 10 ** 9
	assert rv.full_comparison_since(infos, None) == 100 * 10 ** 9


def test_each_final_commit_advances_or_carries_the_key(job):
	seed_monitor(job, {'a.txt': 'a'})
	v0 = run_backup(job, matched_since=100)[-1]
	assert matched(job) == (name(v0), 100)
	v1 = run_backup(job, modify(job, 'a.txt', 'b'), matched_since=200)[-1]
	assert matched(job) == (name(v1), 200)
	run_backup(job, matched_since=300)                      # "No differences"
	assert matched(job) == (name(v1), 300)
	v2 = run_backup(job, modify(job, 'a.txt', 'c'))[-1]     # round-tripped: carried forward
	assert matched(job) == (name(v2), 300)


def test_no_key_is_carried_from_a_vault_without_one(job):
	seed_monitor(job, {'a.txt': 'a'})
	run_backup(job)
	run_backup(job, modify(job, 'a.txt', 'b'))
	assert matched(job) is None


def test_a_paused_inner_mount_carries_the_time_forward(job, monkeypatch):
	seed_monitor(job, {'a.txt': 'a', 'disk/f.txt': 'f'})
	_fake_mounts(monkeypatch, job, ['disk/'])
	run_backup(job, matched_since=100)
	os.remove(os.path.join(job.monitor, 'disk', 'f.txt'))
	_fake_mounts(monkeypatch, job, [])
	v1 = run_backup(job, modify(job, 'a.txt', 'b'), matched_since=200)[-1]
	assert matched(job) == (name(v1), 100)


def test_an_attempt_that_met_an_unreadable_folder_carries_the_time_forward(job, monkeypatch):
	seed_monitor(job, {'a.txt': 'a', 'bad/x': 'x'})
	run_backup(job, matched_since=100)
	bad = os.path.join(job.monitor, 'bad')
	original = os.scandir
	def scandir(path='.'):
		if os.path.abspath(path).rstrip('/') == bad:
			raise OSError(errno.EIO, os.strerror(errno.EIO), path)
		return original(path)
	monkeypatch.setattr(os, 'scandir', scandir)
	v0 = rv.list_versions(job.job_vault)[-1].path
	run_backup(job, matched_since=200)                      # a full comparison that could not read bad/
	assert matched(job) == (name(v0), 100)


def test_delta_generation_writes_no_key(job):
	seed_monitor(job, {'a.txt': 'a'})
	run_backup(job)
	rv.delta_generate_backup_entries(OrderedDict(), latest_version(job), job.monitor).close()
	assert matched(job) is None


def test_a_full_comparison_reads_xattrs_only_of_entries_changed_since_the_matched_time(job, monkeypatch):
	monkeypatch.setattr(rv, 'VERIFY_CTIME_MARGIN_SECONDS', 0)
	files = [os.path.join(job.monitor, f'f{i}.txt') for i in range(5)]
	seed_monitor(job, {os.path.basename(path): 'x' for path in files})
	run_backup(job)
	for path in files:                                      # a version that changed every entry
		os.chmod(path, 0o600)
	time.sleep(0.02)
	since = time.time_ns()
	time.sleep(0.02)
	run_backup(job, OrderedDict(event_entry(job, os.path.basename(path), 'attrib') for path in files), matched_since=since)
	os.chmod(files[2], 0o600)                               # a new ctime, nothing else
	calls = []
	real = os.listxattr
	monkeypatch.setattr(os, 'listxattr', lambda path, *a, **kw: calls.append(path) or real(path, *a, **kw))
	run_backup(job)
	assert [path for path in calls if path.startswith(job.monitor)] == [files[2]]


def test_the_backuper_passes_each_batch_its_matched_time(job, monkeypatch):
	seed_monitor(job, {'a.txt': 'a', 'b.txt': 'b'})
	run_backup(job)
	calls = record_matched_since(monkeypatch)
	queue = rv.ChangeEventQueue(job.monitor)
	queue.read_wall_ns = 111
	open(os.path.join(job.monitor, 'a.txt'), 'w').write('changed')
	queue.append(rv.ChangeEvent(1.0, False, 'modify', os.path.join(job.monitor, 'a.txt'), None))
	thread, lock, flag = start_backuper(job, queue)
	try:
		wait_for_committed_count(job, 2)
		open(os.path.join(job.monitor, 'b.txt'), 'w').write('changed')
		before = time.time_ns()
		with lock:
			queue.prepend(rv.backup_entries_to_change_events(OrderedDict([event_entry(job, 'b.txt', 'modify')])))
			queue.read_wall_ns = 222
		flag.set()
		wait_until(lambda: len(calls) == 3, message='no follow-up full comparison')
	finally:
		stop_backuper(thread)
	assert calls[:2] == [111, None] and before <= calls[2] <= time.time_ns()


def test_a_restarts_full_comparison_records_a_key(job, poll_fast):
	seed_monitor(job, {'a.txt': 'a'})
	v0 = run_backup(job)[-1]
	assert matched(job) is None
	before = time.time_ns()
	startup = rv.JobStartup(job.job_name, job.monitor)
	startup.watching.set()
	thread = threading.Thread(target=rv.backuper, args=(job.job_name, rv.ChangeEventQueue(job.monitor), threading.Lock(),
		job.monitor, job.vault, 'N/A', threading.Event()), kwargs=dict(startup=startup), daemon=True)
	thread.start()
	try:
		wait_until(lambda: matched(job) is not None, message='the restart wrote no key')
	finally:
		stop_backuper(thread)
	assert matched(job)[0] == name(v0) and before <= matched(job)[1] <= time.time_ns()


def test_an_xattr_set_while_down_reaches_the_follow_up_version(job, monkeypatch):
	user_xattrs_or_skip(job.monitor)
	seed_monitor(job, {'a.txt': 'a', 'b.txt': 'b'})
	for path in (job.monitor, os.path.join(job.monitor, 'a.txt'), os.path.join(job.monitor, 'b.txt')):
		os.utime(path, (1000, 1000))
	run_backup(job, matched_since=time.time_ns())
	# while the daemon is down: an xattr of b, and a write to a its pending batch holds
	os.setxattr(os.path.join(job.monitor, 'b.txt'), 'user.down', b'1')
	a = os.path.join(job.monitor, 'a.txt')
	open(a, 'w').write('changed')
	os.utime(a, (1000, 1000))
	pending = write_pending(job, [rv.ChangeEvent(time.monotonic(), False, 'modify', a, None)])
	os.utime(pending, (2000, 2000))
	queue = rv.ChangeEventQueue(job.monitor)
	assert rv.load_pending_transactions_for_resume(job.job_name, job.monitor, job.vault, queue)
	queue.read_wall_ns = time.time_ns() + 3600 * 10 ** 9   # a resumed batch's stamp is never used
	thread, lock, flag = start_backuper(job, queue)
	try:
		v2 = wait_for_committed_count(job, 3)[2]
	finally:
		stop_backuper(thread)
	assert os.getxattr(os.path.join(v2, 'b.txt'), 'user.down') == b'1'
```

In `tests/test_vault_scan.py`, give `cut_off_at_the_swap` a `**backup_options` that it passes to `run_backup`, then add:

```python
def test_a_cut_off_commits_key_is_not_used_once_the_scan_rolls_it_back(tmp_path):
	job = three_versions(tmp_path)
	attempt = cut_off_at_the_swap(job, matched_since=time.time_ns())
	restart_and_scan(job)
	infos = rv.get_vault_info(job.job_vault).vault_info_dict
	manifest = rv.VaultManifest(job.job_vault)
	assert manifest.matched[0] == os.path.basename(attempt)
	assert rv.full_comparison_since(infos, manifest.matched) == rv.full_comparison_since(infos)
	manifest.close()
```

- [ ] **Step 2: Run them and see them fail.**
  - Run: `.venv/bin/python -m pytest -q -p no:cacheprovider tests/test_matched_time.py tests/test_vault_scan.py -k "key or matched or xattr or carries or full_comparison_since"`
  - Expected: FAIL. `do_backup()` raises `TypeError: unexpected keyword argument 'matched_since'`, and `VaultManifest` has no attribute `matched`.
  - The xattr count fails with all five files counted, as on 0.45.

- [ ] **Step 3: Implement** per Interfaces.
  - Extend `full_comparison_since()`'s docstring and its doctest by a key naming the newest version and one naming another.
  - Comment the new meta key where `skip_fingerprint` and `inner_mounts` are: written only by `do_backup()`'s commits, in their transaction.

- [ ] **Step 4: Run the new tests and see them pass.** Use the Step 2 command. Expected: PASS, or SKIP for the xattr test where user xattrs are unsupported.

- [ ] **Step 5: Run both full suites.** Expected: all pass.

- [ ] **Step 6: Commit** `reverberator.py`, `tests/test_matched_time.py` and `tests/test_vault_scan.py`: "A backup attempt that saw the whole tree records in the vault database from when the vault matches it, and a full comparison reads the xattrs of entries changed since then only; attempts that did not carry the time forward."

**Calls to confirm:**
- **A full comparison's time is its own start, not the queue's read time** (the design's words). See the note above Step 1. The main session rules.
- **An attempt that logged anything unreadable carries the time forward.** This is the builder's reading of "saw the whole tree". It is an addition to the design.
- A new meta key `matched`, and a new `do_backup()` keyword `matched_since`.
- `full_comparison_since()` takes an optional second argument.

---

### Task 4: A move-out whose pair cannot come any more goes into the batch it belongs to (Goal 3)

**Files:**
- Modify: `reverberator.py:2468-2520` (`watchFolder`: the expiry loop and the empty-read branch).
- Test: `tests/test_inotify.py`.
- Test: `tests/test_matched_time.py` (the injected max-delay case, using `scripted_watch`).

**Interfaces:**
- Consumes: `scripted_watch` (Task 2). The read-time publish point from Task 2 stays after the move-outs are queued.
- Produces: a local `expire_move_out(cookie)` in `watchFolder`, holding the expiry loop's body unchanged:
  - pop the cookie;
  - `remove_moved_away_watches()` for a folder's watches;
  - `append_change_event()` of `pop_pending_move_from(cookie)`.
  The expiry loop calls it.
- Produces: the empty-read branch becomes, in this order:
  1. `quiet = time.monotonic() - lastReadTime > min_snapshot_delay_seconds`.
  2. When quiet, `expire_move_out()` every cookie of `list(pendingMoveFromEvents)`. A rename queues its move-in right after its move-out, so after a quiet read no pair is still coming.
  3. Publish the read time (Task 2).
  4. When quiet, `to_process` is non-empty and the flag is not set, signal as today. Because step 2 ran first, a move-out that is the only event now makes `to_process` non-empty.
  - Step 2 runs whether or not a batch is already signalled. A move-out made while the batch waits to be taken thus still joins it (Review Focus 4).
- The max-delay hand-over and the timeout are unchanged.

- [ ] **Step 1: Write the failing tests.**
  - The real-watcher tests in `tests/test_inotify.py` use a context manager `_quiet_watch(job)`. It starts the watcher with `min_snapshot_delay_seconds=1`, runs `_wait_watch_ready` and `_consume_batch`, yields `(to_process, lock, flag)`, and stops the watcher on exit as the other tests do.
  - The pair timeout stays at its default, 30 s, so a delete seen within 5 s comes from the quiet hand-over.
  - `taken(to_process, lock, flag)` waits (5 s) for the flag, then takes the queue under the lock, clears the flag and returns the batch.
  - `rels(job, events)` is `[(e.event, os.path.relpath(e.path, job.monitor)) for e in events]`.

```python
def test_a_file_moved_into_a_new_folder_leaves_only_its_new_place(job, poll_fast):
	seed_monitor(job, {'a.txt': 'a'})
	run_backup(job)
	with _quiet_watch(job) as (to_process, lock, flag):
		os.mkdir(os.path.join(job.monitor, 'd'))
		os.rename(os.path.join(job.monitor, 'a.txt'), os.path.join(job.monitor, 'd', 'a.txt'))
		batch = taken(to_process, lock, flag)
	assert ('delete', 'a.txt') in rels(job, batch)
	version = run_backup(job, rv.change_events_to_backup_entries(batch, job.monitor), touched=rv.touched_scopes(batch, job.monitor))[-1]
	assert not os.path.lexists(os.path.join(version, 'a.txt'))
	assert open(os.path.join(version, 'd', 'a.txt')).read() == 'a'


def test_a_move_out_that_is_the_last_event_lands_in_its_batch(job, tmp_path, poll_fast):
	seed_monitor(job, {'a.txt': 'a'})
	with _quiet_watch(job) as (to_process, lock, flag):
		open(os.path.join(job.monitor, 'b.txt'), 'w').write('b')
		os.rename(os.path.join(job.monitor, 'a.txt'), str(tmp_path / 'a.txt'))
		got = rels(job, taken(to_process, lock, flag))
	assert [r for r in got if r[0] in ('create', 'delete')] == [('create', 'b.txt'), ('delete', 'a.txt')]


def test_a_move_out_alone_is_handed_over(job, tmp_path, poll_fast):
	seed_monitor(job, {'a.txt': 'a'})
	with _quiet_watch(job) as (to_process, lock, flag):
		os.rename(os.path.join(job.monitor, 'a.txt'), str(tmp_path / 'a.txt'))
		assert rels(job, taken(to_process, lock, flag)) == [('delete', 'a.txt')]


def test_a_create_at_a_move_outs_source_keeps_the_order(job, tmp_path, poll_fast):
	seed_monitor(job, {'a.txt': 'a'})
	with _quiet_watch(job) as (to_process, lock, flag):
		os.rename(os.path.join(job.monitor, 'a.txt'), str(tmp_path / 'a.txt'))
		open(os.path.join(job.monitor, 'a.txt'), 'w').write('new')
		got = rels(job, taken(to_process, lock, flag))
	assert [r for r in got if r[0] in ('create', 'delete')] == [('delete', 'a.txt'), ('create', 'a.txt')]


def test_a_folder_moved_out_before_a_quiet_hand_over_is_gone_and_unwatched(job, tmp_path, poll_fast):
	seed_monitor(job, {'d/sub/x': 'x', 'keep.txt': 'k'})
	run_backup(job)
	with _quiet_watch(job) as (to_process, lock, flag):
		os.rename(os.path.join(job.monitor, 'd'), str(tmp_path / 'd'))
		batch = taken(to_process, lock, flag)
		assert rels(job, batch) == [('delete', 'd')]
		open(str(tmp_path / 'd' / 'sub' / 'y'), 'w').write('y')
		_wait_watch_ready(job, to_process, lock)
		assert not [e for e in _events(to_process, lock) if e.path.startswith(os.path.join(job.monitor, 'd') + '/')]
	version = run_backup(job, rv.change_events_to_backup_entries(batch, job.monitor), touched=rv.touched_scopes(batch, job.monitor))[-1]
	assert not os.path.lexists(os.path.join(version, 'd'))


def test_a_move_out_reaches_a_batch_signalled_before_it(job, tmp_path, poll_fast):
	seed_monitor(job, {'a.txt': 'a'})
	with _quiet_watch(job) as (to_process, lock, flag):
		open(os.path.join(job.monitor, 'b.txt'), 'w').write('b')
		wait_until(flag.is_set, timeout=5)                 # signalled, not taken: the backuper is busy
		os.rename(os.path.join(job.monitor, 'a.txt'), str(tmp_path / 'a.txt'))
		wait_until(lambda: ('delete', 'a.txt') in rels(job, _events(to_process, lock)), timeout=5)
```

In `tests/test_matched_time.py`:

```python
def test_a_move_out_pending_at_a_max_delay_hand_over_still_pairs(job, monkeypatch):
	flags = rv.inotify_simple.flags
	reads = [[(flags.CREATE, 'f', 0)], [(flags.MOVED_FROM, 'a', 7)], [(flags.MOVED_TO, 'b', 7)]]
	queue, flag, _ = scripted_watch(monkeypatch, job.monitor, reads, min_snapshot_delay_seconds=3600, max_shapshot_delay_seconds=0)
	assert flag.is_set()
	m = job.monitor
	assert [(e.event, e.path, e.moved_from) for e in queue] == [('create', f'{m}/f', None), ('move', f'{m}/b', f'{m}/a')]
```

- [ ] **Step 2: Run them and see them fail.**
  - Run: `.venv/bin/python -m pytest -q -p no:cacheprovider tests/test_inotify.py tests/test_matched_time.py -k "move_out or moved_into_a_new_folder or moved_out_before"`
  - Expected: the real-watcher tests time out waiting for the delete. The pending move-out waits 30 s on 0.45.
  - The max-delay pairing test already passes. It pins today's behaviour; keep it.

- [ ] **Step 3: Implement** per Interfaces. The comment at step 2 of the empty-read branch carries the reason (no grace needed).

- [ ] **Step 4: Run the new tests and see them pass.** Use the Step 2 command. Expected: PASS.

- [ ] **Step 5: Run both full suites.** Expected: all pass. Many watcher tests run at `min_snapshot_delay_seconds=0`, where every empty read is quiet; a failure there is a test that waited on the 30 s timeout. Read the test's intent before changing it, and report each one changed.

- [ ] **Step 6: Commit** `reverberator.py`, `tests/test_inotify.py` and `tests/test_matched_time.py`: "Once the tree is quiet, the watcher queues every move-out still waiting for its pair as its delete, so mkdir d; mv f d/f no longer leaves f at its old place in the batch's version."

**Calls to confirm:**
- **Move-outs are queued whenever a read finds the tree quiet**, also while a batch is signalled and not taken. This is wider than "when it hands a batch over", for Review Focus 4.
- **Would-be known limitation, for the user** (not written down until they agree): a move-out pending at a max-delay hand-over still shows its phantom in that version.
  - What the operator sees: on a busy tree, a file moved into a new folder shows at both places in one version, until the next batch.
  - Why it is not fixed: breaking a split pair would turn a rename into a delete and a copy.
  - What would bring it back: a report of it on the live jobs.
- The design's own call stands: the expired move-out is handed over as its delete, with no new event kind.

---

### Task 5: A restart whose pending batch holds only scans still compares the whole tree (Goal 5, verify first)

**Files:**
- Test: `tests/test_job_startup.py`.
- Modify, only if Step 2 fails:
  - `reverberator.py:3038-3040` (`load_pending_transactions_for_resume`'s `round_tripped` condition);
  - `reverberator.py:3993-3995` (the startup's prepend);
  - `reverberator.py:4040-4072` (`backuper`: where the follow-up is decided);
  - `tests/test_pending_times.py:69-75`.

**Interfaces:**
- Consumes: Task 3's `matched_since`, which is None for a round-tripped batch.
- Produces, only if needed: any resumed pending batch that is not a full scan counts as round-tripped, and its follow-up full comparison runs. Three edits:
  - The loader sets `to_process.round_tripped = True` for any rows loaded, scans too.
  - The startup carries `restored.round_tripped` onto `to_process` after `to_process.prepend(list(restored))`. Today's `prepend()` sets it only for non-scan events.
  - The backuper moves its `if round_tripped and not full_comparison: ... follow_up = True` (with its log line) from inside the `do_backup()` block to just after it. It then also runs after the scans-only branch that logs "Compared folders match the vault; no new version for this batch". That branch never reached the check before.
- A batch of scans handed back within one run stays not round-tripped (`test_scans_handed_back_alone_are_not_round_tripped` is unchanged).

- [ ] **Step 1: Write the test** in `tests/test_job_startup.py`. A plain write while the daemon is down already moves an mtime, which the resume check (`get_monitor_path_most_recent_change_time()`) sees: no resume, and the whole tree is compared. So the test changes the tree in the two ways that check cannot see: a chmod, and a write with its mtime set back.

```python
def test_a_restart_with_only_scans_pending_compares_the_whole_tree(job, poll_fast):
	seed_monitor(job, {'a.txt': 'a', 'b.txt': 'b', 'disk/x': 'x'})
	_age(job)                                               # every monitored entry at mtime 1000, before V0
	_v0(job)
	# while the daemon is down, outside the scanned folder
	os.chmod(os.path.join(job.monitor, 'a.txt'), 0o600)
	b = os.path.join(job.monitor, 'b.txt')
	open(b, 'w').write('changed while down')
	os.utime(b, (1000, 1000))
	pending = write_pending(job, [rv.ChangeEvent(1.0, True, 'scan', os.path.join(job.monitor, 'disk'), None)])
	os.utime(pending, (2000, 2000))
	startup = rv.JobStartup(job.job_name, job.monitor)
	startup.watching.set()
	thread = _run_backuper(job, startup)
	try:
		v1 = wait_for_committed_count(job, 2)[1]
	finally:
		_stop(thread)
	assert not os.path.exists(pending)
	assert open(os.path.join(v1, 'b.txt')).read() == 'changed while down'
	assert os.stat(os.path.join(v1, 'a.txt')).st_mode & 0o777 == 0o600


def test_a_resumed_scan_with_differences_is_followed_by_a_full_comparison(job, poll_fast):
	seed_monitor(job, {'a.txt': 'a', 'b.txt': 'b', 'disk/x': 'x'})
	_age(job)
	_v0(job)
	b, x = os.path.join(job.monitor, 'b.txt'), os.path.join(job.monitor, 'disk', 'x')
	for path, text in ((b, 'changed while down'), (x, 'x changed while down')):
		open(path, 'w').write(text)
		os.utime(path, (1000, 1000))
	pending = write_pending(job, [rv.ChangeEvent(1.0, True, 'scan', os.path.join(job.monitor, 'disk'), None)])
	os.utime(pending, (2000, 2000))
	startup = rv.JobStartup(job.job_name, job.monitor)
	startup.watching.set()
	thread = _run_backuper(job, startup)
	try:
		v1, v2 = wait_for_committed_count(job, 3)[1:3]     # the resumed scan's version, then the follow-up's
	finally:
		_stop(thread)
	assert open(os.path.join(v1, 'disk', 'x')).read() == 'x changed while down'
	assert open(os.path.join(v2, 'b.txt')).read() == 'changed while down'
	manifest = rv.VaultManifest(job.job_vault)
	assert manifest.matched[0] == os.path.basename(v2)      # the follow-up advanced it; the resumed batch carried nothing
	manifest.close()
```

(`_age(job)` sets `os.utime(path, (1000, 1000))` on every entry of the tree, as `_resumable_pending` does, but before V0, so V0 records those times.)

- [ ] **Step 2: Run the first test.**
  - Run: `.venv/bin/python -m pytest -q -p no:cacheprovider tests/test_job_startup.py -k only_scans_pending`
  - Expected on the current code: FAIL. The wait for a second version times out: the resume compares only `disk/`, and the scans-only branch never reaches the follow-up.
  - If it PASSES instead: delete both tests and stop. The task ends with a report saying Goal 5 is not an issue, and why (the log lines that show the whole tree was compared).

- [ ] **Step 3: Implement** the three edits in Interfaces.

- [ ] **Step 4: Reverse the test that pins the old behaviour.** `tests/test_pending_times.py::test_scan_rows_alone_are_not_round_tripped` becomes `test_scan_rows_alone_are_round_tripped`, asserting `queue.round_tripped`. Its comment says a restart cannot tell what changed while the daemon was down.

- [ ] **Step 5: Run the Goal 5 tests and the pending tests.**
  - Run: `.venv/bin/python -m pytest -q -p no:cacheprovider tests/test_job_startup.py tests/test_pending_times.py tests/test_verify_replay.py -k "scan or round_tripped or follow"`
  - Expected: PASS.

- [ ] **Step 6: Run both full suites.** Expected: all pass.

- [ ] **Step 7: Commit** `reverberator.py`, `tests/test_job_startup.py` and `tests/test_pending_times.py`: "A restart that resumes a pending batch of scans only also compares the whole tree after it, so a chmod or an mtime-keeping write made while the daemon was down is backed up."

**Calls to confirm:**
- The verify result: what the test showed on the current code.
- **Behaviour change:** a resumed scans-only batch is round-tripped. `test_scan_rows_alone_are_not_round_tripped` is reversed, against an earlier round's pin.
- The follow-up now also runs after a round-tripped batch whose scans matched.

---

### Task 6: Version 0.46 and the docs (Goal 4)

**Files:**
- Modify: `reverberator.py:59` (`__version__ = 0.46`).
- Modify: `pyproject.toml:3` (`version = "0.46"`).
- Modify: `README.md` (lines 4-23).
- Modify: `docs/limitations.md` (remove three entries).

**Interfaces:** none. These are docs only, apart from the two version strings.

- [ ] **Step 1: Bump the version** in both places.
- [ ] **Step 2: Edit `docs/limitations.md`.**
  - Remove the three entries this round closes:
    - `### Copies marked checked before they reach the disk`;
    - `### Full comparisons read every changed entry's xattrs since the previous version`;
    - `### A file moved into a folder made in the same batch shows at its old place too`.
  - Keep `### Files written through mmap`.
  - Add nothing. The max-delay phantom (Task 4) waits for the user.
- [ ] **Step 3: Edit `README.md`.**
  - Line 23: remove the phantom's known-limits line ("After mkdir d; mv f d/f in one batch, ...").
  - Line 12: replace "the entries changed since the version before the latest was made" with "the entries changed since the vault last matched the whole tree (the last backup or comparison that saw all of it)". Keep the rest.
  - Line 7: "are checked like any other copy at the next comparison" becomes "are checked like any other copy at the next comparison once 10 min old".
  - After line 4, add one design-decision line: "A copy is trusted to be on disk once 10 min old: until then every comparison that meets it reads it back from the vault. This assumes the kernel writes dirty data back within that time, as it does with the default 30 s writeback; nothing is flushed."
  - If the Task 3 or Task 4 rulings changed what the code does, word these lines to match it.
- [ ] **Step 4: Run both full suites.** Expected: all pass. A doctest or test that reads the version would show here.
- [ ] **Step 5: Commit** `reverberator.py`, `pyproject.toml`, `README.md` and `docs/limitations.md`: "Version 0.46: drop the three limitations round 10 closes and describe the 10 min check age and the matched time in the README."

**Calls to confirm:** the README wording; the mmap entry left as it is.

---

### Task 7: A batch taken without the watcher's signal does not leave new folders' events discarded (Goal 7)

Added by the main session after Task 2's review (pre-existing; the spec's Goal 7). Run after Task 4, which edits the
same watcher loop; execution order is 1, 2, 3, 4, 5, 7, 8, 6.

**Files:**
- Modify: `reverberator.py` (`ChangeEventQueue`: `__init__`, `take`, docstring; `watchFolder`: the `processPending`
  check right after `inotify_obj.read()`, and the two places that set `processPending`).
- Test: `tests/test_matched_time.py` (scripted reads), `tests/test_inotify.py` (a real watcher).

**Interfaces:**
- Produces: `ChangeEventQueue.takes: int`, 0 at `__init__`, incremented by `take()` (on the queue taken from; the batch
  returned keeps whatever, it is never read). Callers hold `to_process_lock`.
- Produces: in `watchFolder`, `seen_takes`, read from the queue under the lock when the watcher starts; right after each
  read returns, under the lock: when `to_process.takes != seen_takes`, clear `newDirWDs`, reset `lastProcessTime`, and
  take the new count. `processPending` and its two setters go; the signal conditions are otherwise unchanged.

- [ ] **Step 1: Write the failing tests.**
  - Scripted (`scripted_watch`, whose reads may be callables taking the queue): read 0 creates folder `d` (CREATE|ISDIR;
    the harness gives it a fresh wd in `newDirWds`), read 1 is a callable that takes the queue (`queue.take()`, no flag)
    and returns an event in `d` (CREATE `x` on d's wd); assert the event in d is queued. A variant whose read 1 does not
    take: the event in d is discarded (today's behaviour, kept).
  - Real watcher (`_start_watch`): `mkdir d` and wait for its create to be queued, take the queue directly under the
    lock (no flag cleared, no signal), write `d/f`, and assert its event is queued within the timeout. On 0.45 it is
    discarded until a signalled take.
  - A watcher started while the flag is already set (`flag.set()` before `_start_watch`): a new folder's events are
    discarded until the next take, then kept.
- [ ] **Step 2: Run them and see them fail** (the unsignalled-take tests).
- [ ] **Step 3: Implement** per Interfaces, with a comment at the check saying why it sits right after the read.
- [ ] **Step 4: Run them and see them pass; run both full suites.**
- [ ] **Step 5: Commit:** "The watcher learns of every take from a count on the queue, not only of those it signalled,
  so after the backuper's startup take a new folder's later events are recorded again."

**Calls to confirm:** added to round 10 by the main session (a pre-existing silent loss); `processPending` goes.

---

### Task 8: A folder made while the watcher walks its parent is watched (Goal 6)

Added by the main session after Task 2's review (pre-existing; the spec's Goal 6).

**Files:**
- Modify: `reverberator.py` (`initializeFolderWatchers`; `get_all_folders` only if nothing else uses it).
- Test: `tests/test_inotify.py` or `tests/test_jobs.py`, beside the existing `initializeFolderWatchers` tests.

**Interfaces:**
- `initializeFolderWatchers()` keeps its signature and return value. It adds the root's watch first (as today), then
  walks with `iter_tree_entries()` and adds each folder's watch as the walk yields it, before the walk reads that folder.
  A folder the walk then reports unreadable (its `errors`) has its watch removed (`rm_watch`, `wdDic`, `newDirWds`, and
  the `irm` count given back) and is logged as today ("Not watching unreadable folder ..."). Skipped folders are not
  descended into and get no watch, as today. `irm.increaseUserWatches()` is called per watch added (or once per batch of
  them), and every watch removed or failed is given back.

- [ ] **Step 1: Write the failing test,** from the review's probe
  (/tmp/claude-0/-mnt-optane-work-reverberator/8ad4e979-212b-4a0b-9477-1847dfee5560/scratchpad/r10/review-t2/copy/tests/test_probe_walk_race.py):
  make the walk itself create `d/a/b` right after `d/a` is listed and before `d/a`'s watch would be added on 0.45
  (wrap `rv.iter_tree_entries` or `os.scandir` to create it at the right moment), then assert `d/a/b` is watched (a
  change in it is queued by a real watcher, or its path is in `wdDic`). Plus: the watch count given to the `irm` equals
  the watches held, with an unreadable folder in the tree.
- [ ] **Step 2: Run it and see it fail.**
- [ ] **Step 3: Implement** per Interfaces.
- [ ] **Step 4: Run it and see it pass; run both full suites** (the existing unreadable-folder, skip-list and
  inner-mount watcher tests must pass unchanged).
- [ ] **Step 5: Commit:** "The watcher adds each folder's watch as its walk reaches it, before reading the folder, so a
  folder made while the walk runs is watched."

**Calls to confirm:** added to round 10 by the main session (a pre-existing silent loss).

---

## Self-review

- **Spec coverage:**
  - Goal 1: rule, 600 s, tests (power loss (a) and (b), young/old, restart before and after the window) → Task 1.
  - Goal 2:
    - key format, where it is written, advance/carry/nothing, fallback, margin kept, `compare_scanned_folders` unchanged, scans-only batch writes nothing (no `do_backup()` call), version name, failed attempt writes nothing → Task 3.
    - the read time → Task 2.
    - tests (fresh batch, No differences, xattr count, resumed, handed back, paused, other/no key, cut-off, delta's commit) → Tasks 2-3.
  - Goal 3: rule, max-delay kept, timeout kept, create-at-source order, folder moved out → Task 4.
  - Goal 5 → Task 5.
  - Goal 4 → Task 6.
- **Departures from the design, in Calls to confirm:**
  - a full comparison's own start time (Task 3);
  - an unreadable path carries forward (Task 3);
  - move-outs flushed whenever quiet (Task 4).
- **Names across tasks:**
  - `read_wall_ns` (Tasks 2, 3);
  - `scripted_watch` (Tasks 2, 4);
  - `matched` / `record_matched` / `matched_since` / `full_comparison_since(vault_info_dict, matched)` (Tasks 3, 5).
