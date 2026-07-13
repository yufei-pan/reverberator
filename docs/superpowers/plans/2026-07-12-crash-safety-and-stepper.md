# Crash Safety and Stepper Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make version commits crash/stop-safe, delete incomplete vault dirs on startup, harden `decrement_stepper` abort paths, skip empty versions, and fail closed on watcher/backuper hard errors — per `docs/superpowers/specs/2026-07-12-crash-safety-and-stepper-design.md`.

**Architecture:** Keep the single-module layout (`reverberator.py`). Add small pure helpers (incomplete-dir cleanup, backup-entry→ChangeEvent conversion, content-file size rename) that are unit-tested under `tests/` with stdlib `unittest` + temp dirs. Wire those helpers into `get_vault_info`, `do_backup`/`backuper`, `decrement_stepper`, `watcher`, and sample docs. Content-file presence remains the sole commit marker.

**Tech Stack:** Python 3.7+, stdlib `unittest`, existing `doctest` via `./docTest.sh`, inotify/multiCMD/TSVZ unchanged.

## Global Constraints

- Spec: incomplete `V*` is never indexed; delete on startup only (not on SIGTERM).
- Spec: pending mtime gate unchanged.
- Spec: attrib-through-symlink and `keep_one_complete_backup=False` unchanged.
- Spec: on stepper materialize failure — restore dict entry, no `rm -rf`, return `(0,0)`, recalculate sizes from disk before continuing.
- Prefer stdlib tests (no new test-framework dependency).
- Bump `__version__` / `pyproject.toml` version to `0.23` in the final task.

## File map

| File | Responsibility |
|------|----------------|
| `reverberator.py` | All daemon logic + helpers |
| `tests/test_crash_safety.py` | Unit tests for helpers + stepper/commit behavior with temp dirs |
| `docs/superpowers/specs/2026-07-12-crash-safety-and-stepper-design.md` | Spec (read-only reference) |
| `README.md` | Short note on incomplete-version startup cleanup (if present and relevant) |

---

### Task 1: Incomplete-version cleanup helper

**Files:**
- Modify: `reverberator.py` (add helper near `get_vault_info`)
- Create: `tests/test_crash_safety.py`

**Interfaces:**
- Produces: `remove_incomplete_vault_versions(job_vault_path: str) -> list` — returns list of deleted directory paths
- Consumes: `CONTENT_FILE_EXTENSION_NAME`, `backuperTeeLogToTl`, `os`, `glob`/`scandir`

- [ ] **Step 1: Write the failing test**

Create `tests/test_crash_safety.py`:

```python
import os
import tempfile
import unittest
import reverberator as rv


class TestRemoveIncompleteVaultVersions(unittest.TestCase):
	def test_deletes_vdir_without_content_file_keeps_committed(self):
		with tempfile.TemporaryDirectory() as job_vault:
			committed = os.path.join(job_vault, 'V1--2021-01-01_00-00-00_-0800')
			orphan = os.path.join(job_vault, 'V2--2021-01-02_00-00-00_-0800')
			os.makedirs(committed)
			os.makedirs(orphan)
			open(os.path.join(committed, 'f.txt'), 'w').write('x')
			content = (
				f'{committed}--1_B-1_ino{rv.CONTENT_FILE_EXTENSION_NAME}'
			)
			open(content, 'w').write('path\tiso_time\tevent\tsource_path\n')
			deleted = rv.remove_incomplete_vault_versions(job_vault)
			self.assertTrue(os.path.isdir(committed))
			self.assertTrue(os.path.isfile(content))
			self.assertFalse(os.path.isdir(orphan))
			self.assertEqual(deleted, [orphan])


if __name__ == '__main__':
	unittest.main()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m unittest tests.test_crash_safety.TestRemoveIncompleteVaultVersions -v`

Expected: FAIL with `AttributeError: module 'reverberator' has no attribute 'remove_incomplete_vault_versions'`

- [ ] **Step 3: Implement helper**

In `reverberator.py`, near `get_vault_info`:

```python
def remove_incomplete_vault_versions(job_vault_path: str) -> list:
	'''
	Delete V* version directories that have no matching content file.

	A version is committed only when its content file exists. Incomplete
	directories left after a crash/stop are removed on startup.

	Returns:
		list: Absolute paths of deleted version directories.
	'''
	deleted = []
	if not os.path.isdir(job_vault_path):
		return deleted
	# Map version dir path -> whether a content file was seen
	version_dirs = {}
	content_for = set()
	try:
		for entry in os.scandir(job_vault_path):
			name = entry.name
			if not (name.startswith('V') and '--' in name):
				continue
			version_number_str = strip_prefix(name, 'V').partition('--')[0]
			if not version_number_str.isdigit():
				continue
			if CONTENT_FILE_EXTENSION_NAME in name:
				if entry.is_file():
					vault_path = entry.path.rpartition('--')[0]
					content_for.add(vault_path)
			elif entry.is_dir():
				version_dirs[entry.path] = True
	except Exception as e:
		backuperTeeLogToTl(job_vault_path, f'Error scanning for incomplete versions: {e}', error=True)
		return deleted
	for vault_dir in list(version_dirs):
		if vault_dir in content_for:
			continue
		backuperTeeLogToTl(
			job_vault_path,
			f'Removing incomplete version (no content file): {vault_dir}',
			error=True,
		)
		try:
			multiCMD.run_command(['rm', '-rf', vault_dir], quiet=not DEBUG, return_code_only=True)
			deleted.append(vault_dir)
		except Exception as e:
			backuperTeeLogToTl(job_vault_path, f'Failed to remove incomplete version {vault_dir}: {e}', error=True)
	return deleted
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m unittest tests.test_crash_safety.TestRemoveIncompleteVaultVersions -v`

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add reverberator.py tests/test_crash_safety.py
git commit -m "Add helper to delete incomplete vault versions on scan."
```

---

### Task 2: Wire startup cleanup; stop promoting orphans in `get_vault_info`

**Files:**
- Modify: `reverberator.py` (`main` job loop ~253, `get_vault_info` orphan loop ~1730–1751)
- Modify: `tests/test_crash_safety.py`

**Interfaces:**
- Consumes: `remove_incomplete_vault_versions`
- Produces: startup calls cleanup before `load_pending_transactions_for_resume`; `get_vault_info` deletes orphans instead of inventing empty content files

- [ ] **Step 1: Write failing tests for orphan policy**

Append to `tests/test_crash_safety.py`:

```python
class TestGetVaultInfoOrphans(unittest.TestCase):
	def test_orphan_dir_is_removed_not_indexed(self):
		with tempfile.TemporaryDirectory() as job_vault:
			orphan = os.path.join(job_vault, 'V3--2021-01-03_00-00-00_-0800')
			os.makedirs(orphan)
			open(os.path.join(orphan, 'x'), 'w').write('y')
			info = rv.get_vault_info(job_vault)
			self.assertFalse(os.path.isdir(orphan))
			self.assertNotIn(3, info.vault_info_dict)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m unittest tests.test_crash_safety.TestGetVaultInfoOrphans -v`

Expected: FAIL — orphan still exists and/or is indexed (current promote behavior).

- [ ] **Step 3: Change `get_vault_info` orphan handling**

Replace the `for entry in orphan_entries:` block that creates empty content files with deletion via `remove_incomplete_vault_versions` logic, or simply:

```python
		for entry in orphan_entries:
			backuperTeeLogToTl(
				job_vault_path,
				f'Removing incomplete orphan version (no content file): {entry}',
				error=True,
			)
			try:
				multiCMD.run_command(['rm', '-rf', entry], quiet=not DEBUG, return_code_only=True)
			except Exception as e:
				backuperTeeLogToTl(job_vault_path, f'Error removing orphan {entry}: {e}', error=True)
```

Do **not** add the orphan to `vault_info_dict`. Do **not** create an empty content file.

Also call cleanup at job start in `main`, **before** pending resume (~line 253):

```python
		job_vault = os.path.join(vault_path, job_name)
		remove_incomplete_vault_versions(job_vault)
		to_process = deque()
		to_process_lock = threading.Lock()
		load_pending_transactions_for_resume(...)
```

- [ ] **Step 4: Run tests**

Run: `python -m unittest tests.test_crash_safety -v`

Expected: all PASS

- [ ] **Step 5: Commit**

```bash
git add reverberator.py tests/test_crash_safety.py
git commit -m "Delete incomplete vault dirs on startup instead of promoting orphans."
```

---

### Task 3: Commit only when backup finishes; re-queue in-flight entries on abort

**Files:**
- Modify: `reverberator.py` (`do_backup`, `do_reverb_backup`, `backuper`, new `backup_entries_to_change_events`)
- Modify: `tests/test_crash_safety.py`

**Interfaces:**
- Produces: `backup_entries_to_change_events(backup_entries: dict) -> list` of `ChangeEvent`
- Produces: `do_backup(...) -> tuple` of `(VaultInfo, TrackingFilesFolders, committed: bool)`
- Consumes: `GREEN_LIGHT`, `persist_pending_transactions`, `ChangeEvent`, `BackupEntryValues`

- [ ] **Step 1: Write failing tests for conversion + commit gate helper behavior**

```python
class TestBackupEntriesToChangeEvents(unittest.TestCase):
	def test_move_and_dir_flags(self):
		entries = {
			'/tmp/a': rv.BackupEntryValues('t', 'modify', None),
			'/tmp/d/': rv.BackupEntryValues('t', 'create', None),
			'/tmp/b': rv.BackupEntryValues('t', 'move', '/tmp/a'),
		}
		events = rv.backup_entries_to_change_events(entries)
		by_path = {e.path: e for e in events}
		self.assertFalse(by_path['/tmp/a'].is_dir)
		self.assertTrue(by_path['/tmp/d/'].is_dir)
		self.assertEqual(by_path['/tmp/b'].event, 'move')
		self.assertEqual(by_path['/tmp/b'].moved_from, '/tmp/a')
```

Also add a focused test that simulates the commit gate with a tiny temp vault: call an extracted check or document that Step 3’s `do_backup` path is covered by integration-style unittest that clears `GREEN_LIGHT` before commit section — prefer testing the pure conversion first; for commit gate, add:

```python
class TestDoBackupCommitGate(unittest.TestCase):
	def test_incomplete_flag_skips_content_file(self):
		# Minimal: monkeypatch do_reverb_backup / initial path is heavy.
		# Instead verify helper used by backuper on abort:
		entries = {'/tmp/x': rv.BackupEntryValues('t', 'modify', None)}
		events = rv.backup_entries_to_change_events(entries)
		self.assertEqual(len(events), 1)
		self.assertEqual(events[0].event, 'modify')
```

(Full commit-skip wiring is verified in Step 4 by reading that content-file write is behind `if committed` / `if GREEN_LIGHT.is_set()`.)

- [ ] **Step 2: Run tests — expect FAIL on missing `backup_entries_to_change_events`**

Run: `python -m unittest tests.test_crash_safety.TestBackupEntriesToChangeEvents -v`

Expected: FAIL `AttributeError`

- [ ] **Step 3: Implement conversion + commit gate**

Add:

```python
def backup_entries_to_change_events(backup_entries: dict) -> list:
	'''
	Convert in-flight backup entries back to ChangeEvents for pending persistence.
	'''
	events = []
	base = time.monotonic()
	for i, (path, values) in enumerate(backup_entries.items()):
		is_dir = path.endswith('/')
		moved_from = values.source_path if values.event == 'move' else None
		events.append(ChangeEvent(base + (i * 0.001), is_dir, values.event, path, moved_from))
	return events
```

Update `do_reverb_backup` so the final wait does not treat early stop as success. After the wait loop, if copies still running or `GREEN_LIGHT` cleared, still return `TrackingFilesFolders` but callers must check `GREEN_LIGHT`.

Change `do_backup` return to three values. After `do_reverb_backup` / initial complete copy waits:

```python
	backup_finished = GREEN_LIGHT.is_set()
	# For initial complete path: also require mcae finished with GREEN_LIGHT set
	if not backup_finished:
		backuperTeeLogToTl(job_name, f'Backup incomplete for {backup_folder}; not writing content file', error=True)
		if vaultInfo is None:
			vaultInfo = VaultInfo(vault_info_dict, vault_size, vault_inodes)
		if trackingFilesFolders is None:
			trackingFilesFolders = TrackingFilesFolders([], [])
		return vaultInfo, trackingFilesFolders, False

	# existing content file + current_version update ...
	return VaultInfo(...), trackingFilesFolders, True
```

For empty vault initial path: same gate after the `mcae` wait — if `not GREEN_LIGHT.is_set()`, return `..., False` without content file / symlink.

Update `backuper`:

```python
		try:
			while GREEN_LIGHT.is_set():
				...
				vaultInfo, trackingFilesFolders, committed = do_backup(...)
				if not committed:
					# re-queue in-flight entries for pending persist on exit
					with to_process_lock:
						for event in reversed(backup_entries_to_change_events(backupEntries)):
							to_process.appendleft(event)
					backupEntries.clear()
					break  # exit loop; GREEN_LIGHT likely cleared; finally persists
				backupEntries.clear()
				...
		except Exception:
			import traceback
			backuperTeeLogToTl(job_name, traceback.format_exc(), error=True)
			GREEN_LIGHT.clear()
		finally:
			persist_pending_transactions(...)
```

(Exception handler may be Task 6; if touching `backuper` now, add the try/except here to avoid a second pass — acceptable to include in this task.)

- [ ] **Step 4: Run unit tests + doctest smoke**

Run:

```bash
python -m unittest tests.test_crash_safety -v
./docTest.sh
```

Expected: unittest PASS; doctest PASS (update any doctests that assumed 2-tuple `do_backup` if present — there should be none).

- [ ] **Step 5: Commit**

```bash
git add reverberator.py tests/test_crash_safety.py
git commit -m "Skip committing incomplete backups and re-queue in-flight entries."
```

---

### Task 4: Skip creating a version when `backup_entries` is empty after delta

**Files:**
- Modify: `reverberator.py` (`do_backup` ~1559–1605)
- Modify: `tests/test_crash_safety.py` (doctest-style or unittest with mocks if needed)

**Interfaces:**
- Consumes: `delta_generate_backup_entries`, existing `VaultInfo`
- Produces: early return `(vaultInfo, trackingFilesFolders, True)` with **no** new `V*` when still empty after delta (`committed=True` means “no failed partial”; no new version was required)

- [ ] **Step 1: Write failing test**

Prefer a unittest that builds a committed V0 in a temp job vault matching monitor contents, then calls `do_backup` with empty entries (will delta-generate). If monitor == vault contents, entries stay empty and no V1 should appear:

```python
class TestEmptyBackupSkip(unittest.TestCase):
	def test_no_new_version_when_delta_empty(self):
		with tempfile.TemporaryDirectory() as root:
			monitor = os.path.join(root, 'mon')
			vault = os.path.join(root, 'vault')
			job = 'job'
			os.makedirs(monitor)
			open(os.path.join(monitor, 'a.txt'), 'w').write('hi')
			job_vault = os.path.join(vault, job)
			v0 = os.path.join(job_vault, 'V0--2021-01-01_00-00-00_-0800')
			os.makedirs(v0)
			open(os.path.join(v0, 'a.txt'), 'w').write('hi')
			# size/inode strings must parse; use recalculate path by creating matching content file via get_vault_info(recalculate=True) first
			# Simpler approach: call do_backup with pre-built VaultInfo pointing at v0 and empty dict after patching delta to no-op empty — 
			# Direct: invoke the skip branch by passing non-empty vaultInfo and empty backup_entries while monkeypatching delta_generate_backup_entries to leave dict empty.
			original = rv.delta_generate_backup_entries
			try:
				rv.delta_generate_backup_entries = lambda backupEntries, latest_version_info, monitor_path: rv.TrackingFilesFolders([], [])
				vault_info = rv.VaultInfo(
					__import__('collections').OrderedDict([
						(0, rv.VaultEntry(0, v0, 0, 1, 1))
					]),
					1,
					1,
				)
				rv.GREEN_LIGHT.set()
				info, tracking, committed = rv.do_backup(
					{},
					job_name=job,
					monitor_path=monitor,
					vault_path=vault,
					keep_one_complete_backup=True,
					only_sync_attributes=True,
					keep_n_versions=0,
					backup_size_limit='0',
					log_journal=False,
					vaultInfo=vault_info,
					trackingFilesFolders=rv.TrackingFilesFolders(['a.txt'], []),
				)
				self.assertTrue(committed)
				versions = [p for p in os.listdir(job_vault) if p.startswith('V') and os.path.isdir(os.path.join(job_vault, p))]
				self.assertEqual(versions, ['V0--2021-01-01_00-00-00_-0800'])
			finally:
				rv.delta_generate_backup_entries = original
```

- [ ] **Step 2: Run test — expect FAIL** (V1 created today)

Run: `python -m unittest tests.test_crash_safety.TestEmptyBackupSkip -v`

Expected: FAIL — more than one version dir or new V1 present.

- [ ] **Step 3: Implement skip**

In `do_backup`, after:

```python
		if not backup_entries:
			...
			trackingFilesFolders = delta_generate_backup_entries(...)
```

add:

```python
		if not backup_entries:
			backuperTeeLogToTl(job_name, 'No differences after delta; skipping new version', ok=True)
			if vaultInfo is None:
				vaultInfo = VaultInfo(vault_info_dict, vault_size, vault_inodes)
			if trackingFilesFolders is None:
				trackingFilesFolders = TrackingFilesFolders([], [])
			return vaultInfo, trackingFilesFolders, True
```

Place this **before** size-limit stepping and `os.makedirs(backup_folder)`.

- [ ] **Step 4: Run tests**

Run: `python -m unittest tests.test_crash_safety -v`

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add reverberator.py tests/test_crash_safety.py
git commit -m "Skip creating a vault version when delta finds no changes."
```

---

### Task 5: Harden `decrement_stepper`

**Files:**
- Modify: `reverberator.py` (`decrement_stepper` ~2301–2395; add `refresh_vault_entry_size_metadata` helper)
- Modify: `tests/test_crash_safety.py`

**Interfaces:**
- Produces: `refresh_vault_entry_size_metadata(entry: VaultEntry) -> VaultEntry` (updated size/inode; renames content file if present)
- Produces: `decrement_stepper` abort-safe behavior per spec
- Consumes: `vault_info_dict: OrderedDict`, `os.rename`, `get_path_size`, `get_path_inodes`

- [ ] **Step 1: Write failing tests**

```python
class TestDecrementStepperAbort(unittest.TestCase):
	def _make_pair(self, root):
		# V0 real file, V1 symlink to V0 file
		v0 = os.path.join(root, 'V0--2021-01-01_00-00-00_-0800')
		v1 = os.path.join(root, 'V1--2021-01-02_00-00-00_-0800')
		os.makedirs(v0)
		os.makedirs(v1)
		open(os.path.join(v0, 'a.txt'), 'w').write('data')
		os.symlink(os.path.join(v0, 'a.txt'), os.path.join(v1, 'a.txt'))
		# content files with parseable names (use get_path_size after)
		for path, ver in ((v0, 0), (v1, 1)):
			sz = rv.get_path_size(path)
			ino = rv.get_path_inodes(path)
			sz_s = rv.format_bytes(sz, use_1024_bytes=True, to_str=True).replace(' ', '_')
			ino_s = rv.format_bytes(ino, use_1024_bytes=False, to_str=True).replace(' ', '')
			open(f'{path}--{sz_s}B-{ino_s}_ino{rv.CONTENT_FILE_EXTENSION_NAME}', 'w').write(
				'path\tiso_time\tevent\tsource_path\n'
			)
		from collections import OrderedDict
		d = OrderedDict([
			(0, rv.VaultEntry(0, v0, 0, rv.get_path_size(v0), rv.get_path_inodes(v0))),
			(1, rv.VaultEntry(1, v1, 1, rv.get_path_size(v1), rv.get_path_inodes(v1))),
		])
		return d, v0, v1

	def test_successful_step_removes_oldest(self):
		with tempfile.TemporaryDirectory() as root:
			d, v0, v1 = self._make_pair(root)
			removed_size, removed_inodes = rv.decrement_stepper(d)
			self.assertFalse(os.path.isdir(v0))
			self.assertTrue(os.path.isfile(os.path.join(v1, 'a.txt')))
			self.assertFalse(os.path.islink(os.path.join(v1, 'a.txt')))
			self.assertNotIn(0, d)
			self.assertGreater(removed_size + removed_inodes, 0)

	def test_materialize_failure_keeps_oldest_and_restores_dict(self):
		with tempfile.TemporaryDirectory() as root:
			d, v0, v1 = self._make_pair(root)
			real_rename = os.rename
			def boom(src, dst):
				if os.path.basename(src) == 'a.txt' or os.path.basename(dst) == 'a.txt':
					raise OSError('simulated')
				return real_rename(src, dst)
			os.rename = boom
			try:
				removed_size, removed_inodes = rv.decrement_stepper(d)
			finally:
				os.rename = real_rename
			self.assertEqual((removed_size, removed_inodes), (0, 0))
			self.assertTrue(os.path.isdir(v0))
			self.assertIn(0, d)
			self.assertTrue(os.path.islink(os.path.join(v1, 'a.txt')))
```

- [ ] **Step 2: Run tests — failure case may PASS today for wrong reasons; success case should work. Force expected FAIL on abort semantics if today still rm -rf after continue.**

Run: `python -m unittest tests.test_crash_safety.TestDecrementStepperAbort -v`

Expected: `test_materialize_failure_keeps_oldest_and_restores_dict` FAIL if V0 deleted or `0 not in d`.

- [ ] **Step 3: Implement hardened stepper**

Add helper:

```python
def refresh_vault_entry_size_metadata(entry: VaultEntry) -> VaultEntry:
	'''Recalculate size/inode from disk and rename content file to match.'''
	new_size = get_path_size(entry.path)
	new_inode = get_path_inodes(entry.path)
	old_size_str = format_bytes(entry.size, use_1024_bytes=True, to_str=True).replace(' ', '_')
	old_inode_str = format_bytes(entry.inode, use_1024_bytes=False, to_str=True).replace(' ', '')
	old_content = f'{entry.path}--{old_size_str}B-{old_inode_str}_ino{CONTENT_FILE_EXTENSION_NAME}'
	new_size_str = format_bytes(new_size, use_1024_bytes=True, to_str=True).replace(' ', '_')
	new_inode_str = format_bytes(new_inode, use_1024_bytes=False, to_str=True).replace(' ', '')
	new_content = f'{entry.path}--{new_size_str}B-{new_inode_str}_ino{CONTENT_FILE_EXTENSION_NAME}'
	if os.path.lexists(old_content) and old_content != new_content:
		try:
			os.rename(old_content, new_content)
		except Exception as e:
			backuperTeeLogToTl(entry.path, f'Error renaming content file {old_content} -> {new_content}: {e}', error=True)
	elif not os.path.lexists(new_content) and not os.path.lexists(old_content):
		# leave missing; do not invent empty journal of changes
		pass
	return VaultEntry(entry.version_number, entry.path, entry.timestamp, new_size, new_inode)
```

Rewrite materialize + abort path in `decrement_stepper`:

1. `popitem(last=False)` as today; keep `referenceVersionNumber, referenceVaultEntry` locals.
2. Loop symlinks; on match use **only** `os.rename(linkTarget, file)` (no `os.remove` first).
3. Track `materialize_failed = False`. On rename exception: set flag, log, **break** (or continue marking failed — prefer **break** after first failure to avoid more partial moves once aborting; OR continue attempting remaining — spec says abort purge; continuing materialize is OK for idempotent retry. Prefer **continue** attempting other files, then abort purge if any failed.)
4. If `materialize_failed`:
   - Do not update content file from partial `new_size`.
   - `vault_info_dict[referenceVersionNumber] = referenceVaultEntry` then re-sort/re-insert at start: since OrderedDict, restore with:

```python
		new_dict = OrderedDict()
		new_dict[referenceVersionNumber] = referenceVaultEntry
		new_dict.update(vault_info_dict)
		vault_info_dict.clear()
		vault_info_dict.update(new_dict)
```

   - Refresh both entries:

```python
		vault_info_dict[referenceVersionNumber] = refresh_vault_entry_size_metadata(vault_info_dict[referenceVersionNumber])
		vault_info_dict[applyingVersionNumber] = refresh_vault_entry_size_metadata(vault_info_dict[applyingVersionNumber])
```

   - `return 0, 0`
5. Only if success: existing size content rename for applying, then `rm -rf` reference, return removed sizes.

Update doctest examples at top of `decrement_stepper` if behavior of empty dict unchanged.

- [ ] **Step 4: Run tests**

Run: `python -m unittest tests.test_crash_safety.TestDecrementStepperAbort -v`

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add reverberator.py tests/test_crash_safety.py
git commit -m "Make decrement_stepper abort-safe with atomic rename and size refresh."
```

---

### Task 6: Fail closed on watcher init failure and backuper exceptions; docs + version

**Files:**
- Modify: `reverberator.py` (`watcher` ~719–728, `SAMPLE_REVERB_RULE_FILE` ~166, `get_backup_limits_from_str` docstring ~2233, `__version__`, maybe `README.md`)
- Modify: `pyproject.toml` version → `0.23`
- Modify: `reverb_rule.tsv` comment row if it still says bigger-wins

**Interfaces:**
- Consumes: `GREEN_LIGHT`
- Produces: cleared `GREEN_LIGHT` on hard failures; corrected docs

- [ ] **Step 1: Write failing test for watcher stop behavior**

```python
class TestWatcherInitFailure(unittest.TestCase):
	def test_watcher_clears_green_light_when_watchfolder_fails(self):
		rv.GREEN_LIGHT.set()
		flag = __import__('threading').Event()
		flag.set()
		original = rv.watchFolder
		try:
			rv.watchFolder = lambda *a, **k: False
			# watcher loops while GREEN_LIGHT — with watchFolder always False it would spin;
			# after fix it should clear GREEN_LIGHT and return.
			rv.watcher(flag, '/nonexistent', __import__('collections').deque(), __import__('threading').Lock(), __import__('threading').Event(), rv.inotify_resource_manager())
			self.assertFalse(rv.GREEN_LIGHT.is_set())
		finally:
			rv.watchFolder = original
			rv.GREEN_LIGHT.set()
```

- [ ] **Step 2: Run — expect FAIL** (busy-loop or GREEN_LIGHT still set / hang). Use a timeout wrapper if needed:

Run with care: `python -m unittest tests.test_crash_safety.TestWatcherInitFailure -v`

If it hangs under old code, interrupt and proceed to implement (document hang as the failure mode).

- [ ] **Step 3: Implement fail-closed + docs**

`watcher`:

```python
def watcher(...):
	global GREEN_LIGHT
	while GREEN_LIGHT.is_set():
		while GREEN_LIGHT.is_set() and not monitor_fs_flag.is_set():
			monitor_fs_flag.wait(3)
		if not GREEN_LIGHT.is_set():
			watcherTeeLogToTl(monitor_path, f'Exiting watcher thread for {monitor_path}', ok=True)
			return False
		ok = watchFolder(...)
		if not ok:
			watcherTeeLogToTl(monitor_path, f'Watch init/loop failed for {monitor_path}; requesting shutdown', error=True)
			GREEN_LIGHT.clear()
			return False
```

Ensure `backuper` wraps `do_backup` in `try/except` that logs and `GREEN_LIGHT.clear()` (if not done in Task 3).

Docs — replace “Bigger ones take precedence” with “Stricter (smaller) limits take precedence” in:
- `SAMPLE_REVERB_RULE_FILE` header comment
- `get_backup_limits_from_str` docstring
- `reverb_rule.tsv` comment line if present

Add to `SAMPLE_REVERB_RULE_FILE` comment block (or README):

```
# Incomplete V* directories (no .modified_contents.nsv) are removed on startup.
# If you need data from a partial backup after a crash/stop, copy it out before restarting.
```

Bump `__version__ = 0.23` and `pyproject.toml` `version = "0.23"`.

- [ ] **Step 4: Run full verification**

```bash
python -m unittest tests.test_crash_safety -v
./docTest.sh
```

Expected: all PASS

- [ ] **Step 5: Commit**

```bash
git add reverberator.py pyproject.toml tests/test_crash_safety.py reverb_rule.tsv README.md
git commit -m "Fail closed on watch/backup errors; fix limit docs; bump to 0.23."
```

---

## Spec coverage checklist

| Spec requirement | Task |
|------------------|------|
| No content file ⇒ not committed; skip write on early stop | Task 3 |
| Leave incomplete `V*` on shutdown; delete on startup | Tasks 1–2 |
| Do not invent empty content for orphans | Task 2 |
| Re-queue in-flight `backupEntries` into pending | Task 3 |
| Pending mtime gate unchanged | (no task — leave code) |
| `decrement_stepper` atomic rename + abort restore + size refresh | Task 5 |
| Skip empty version after delta | Task 4 |
| Watcher init failure clears `GREEN_LIGHT` | Task 6 |
| Backuper exception clears `GREEN_LIGHT` | Task 3 or 6 |
| Docs: stricter limits; incomplete cleanup warning | Task 6 |
| Attrib / keep_one_complete unchanged | (no task) |

## Placeholder / consistency self-review

- No TBD steps; helpers named consistently: `remove_incomplete_vault_versions`, `backup_entries_to_change_events`, `refresh_vault_entry_size_metadata`.
- `do_backup` returns `(VaultInfo, TrackingFilesFolders, bool)` everywhere after Task 3.
- Empty skip returns `committed=True` (success, nothing to do); incomplete abort returns `committed=False`.
