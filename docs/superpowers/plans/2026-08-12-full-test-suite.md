# Full Test Suite Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a layered pytest suite (unit, live inotify, process, optional privileged) plus thin `POLL_WAIT_SECONDS` hooks so reverberator’s behavior catalog is testable without rewriting the daemon.

**Architecture:** Keep `reverberator.py` as the single production module. Tests live under `tests/` with a shared harness for vault on-disk layout. Production gains `POLL_WAIT_SECONDS` (default 3, env `REVERB_POLL_WAIT_SECONDS`) and uses it in place of hardcoded 3-second waits. Pytest markers separate fast unit tests from inotify/process/privileged layers.

**Tech Stack:** Python 3.7+, pytest>=7, existing `inotify_simple` / `multiCMD` / `TSVZ` / `xxhash`, stdlib `subprocess`/`tempfile`/`threading`. Canonical runner: `uv run --extra test pytest`.

## Global Constraints

- Spec: `docs/superpowers/specs/2026-08-12-full-test-suite-design.md`
- Default command `uv run --extra test pytest` runs all unprivileged tests; privileged tests skip unless `os.geteuid() == 0` or env `REVERB_PRIVILEGED=1`
- Fast loop: `uv run --extra test pytest -m unit`
- Do not split `reverberator.py`; no INotify factory; no `--test-mode` CLI flag; no pytest-cov gate; no pytest-timeout plugin
- Do not read or write repo `reverb_rule.tsv`
- Do not change pending mtime-gate policy, attrib-through-symlink, or `keep_one_complete_backup=False` referenced-V0 semantics
- Doctests in `reverberator.py` stay; pytest collects them via `--doctest-modules`
- New tests are pytest functions with module-level `pytestmark`; Linux-only for `inotify` and `process`
- If a catalog test fails, fix the test unless production contradicts the spec; do not invent new daemon policy
- Tabs for indentation in `reverberator.py` and existing tests (match the file)

## File map

| File | Responsibility |
|------|----------------|
| `reverberator.py` | Daemon + `POLL_WAIT_SECONDS` / `apply_poll_wait_from_env()` |
| `pyproject.toml` | `optional-dependencies.test`, `[tool.pytest.ini_options]` |
| `docTest.sh` | Wrapper around `uv run --extra test pytest` |
| `tests/conftest.py` | Autouse GREEN_LIGHT/poll restore; `job`; `poll_fast`; `process_env`; `run_reverberator`; non-Linux skips |
| `tests/harness.py` | `JobPaths` and vault/rule/pending helpers |
| `tests/test_crash_safety.py` | Existing crash-safety cases + `pytestmark = unit` |
| `tests/test_backup_replay_ordering.py` | Existing replay-ordering cases + `pytestmark = unit` |
| `tests/test_helpers_cli.py` | Poll-wait, slugify, bidict, get_args, hash_file, signal_handler |
| `tests/test_parse_rules.py` | Rule TSV parsing on tmp copies |
| `tests/test_events.py` | `change_events_to_backup_entries` branches |
| `tests/test_vault.py` | Incomplete V* + `get_vault_info` |
| `tests/test_pending.py` | Persist/load + mtime gate via `os.utime` |
| `tests/test_backup.py` | V0, `do_backup` / `do_reverb_backup`, journal |
| `tests/test_delta.py` | Delta / `check_duplicate` |
| `tests/test_retention.py` | keep N, size/inode limits, stepper |
| `tests/test_inotify.py` | Live `watchFolder` |
| `tests/test_process.py` | CLI subprocess |
| `tests/test_privileged.py` | Bind-mount unmount |

---

### Task 1: Pytest config and `POLL_WAIT_SECONDS`

**Files:**
- Modify: `pyproject.toml` (append optional-deps + pytest ini)
- Modify: `reverberator.py` (add poll-wait helper next to `DEFAULT_SNAPSHOT_DELAY`; replace hardcoded `3` waits listed below; call helper at import and at start of `main`; bump `__version__` and pyproject version to `0.26`)
- Create: `tests/conftest.py` (autouse restore only)
- Create: `tests/test_helpers_cli.py` (poll-wait tests only in this task)

**Interfaces:**
- Consumes: `os.environ['REVERB_POLL_WAIT_SECONDS']`
- Produces:
  - `DEFAULT_POLL_WAIT_SECONDS = 3.0`
  - `POLL_WAIT_SECONDS: float` (module global)
  - `apply_poll_wait_from_env() -> float` — reads env, sets `POLL_WAIT_SECONDS`, returns it. Missing/blank/non-float → `3.0`

Hardcoded `3` sites to replace with `POLL_WAIT_SECONDS` (do not change `signal_handler`’s `time.sleep(0.1)` or `MOVE_PAIR_TIMEOUT_SECONDS`):

- `watcher` line ~732: `monitor_fs_flag.wait(3)` → `wait(POLL_WAIT_SECONDS)`
- `watchFolder` line ~767: `max(min(3,min_snapshot_delay_seconds),0.00001)` → `max(min(POLL_WAIT_SECONDS, min_snapshot_delay_seconds), 0.00001)`
- `backuper` ~1195, ~1197, ~1217, ~1234: `.wait(3)` → `.wait(POLL_WAIT_SECONDS)`
- `do_backup` ~1589–1590: `mcae.wait(timeout=3)` and `mcae.cleanup(timeout=3)` → `timeout=POLL_WAIT_SECONDS`
- `do_reverb_backup` `wait_for_async_commands` ~2628: `mcae.wait(timeout=3)` → `timeout=POLL_WAIT_SECONDS`

- [ ] **Step 1: Write the failing tests**

Create `tests/test_helpers_cli.py`:

```python
import os
import pytest
import reverberator as rv

pytestmark = pytest.mark.unit


def test_apply_poll_wait_default_when_env_missing(monkeypatch):
	monkeypatch.delenv('REVERB_POLL_WAIT_SECONDS', raising=False)
	assert rv.apply_poll_wait_from_env() == 3.0
	assert rv.POLL_WAIT_SECONDS == 3.0


def test_apply_poll_wait_reads_env_float(monkeypatch):
	monkeypatch.setenv('REVERB_POLL_WAIT_SECONDS', '0.05')
	assert rv.apply_poll_wait_from_env() == 0.05
	assert rv.POLL_WAIT_SECONDS == 0.05


def test_apply_poll_wait_invalid_env_uses_default(monkeypatch):
	monkeypatch.setenv('REVERB_POLL_WAIT_SECONDS', 'nope')
	assert rv.apply_poll_wait_from_env() == 3.0
	assert rv.POLL_WAIT_SECONDS == 3.0


def test_apply_poll_wait_blank_env_uses_default(monkeypatch):
	monkeypatch.setenv('REVERB_POLL_WAIT_SECONDS', '  ')
	assert rv.apply_poll_wait_from_env() == 3.0
```

Create `tests/conftest.py`:

```python
import pytest
import reverberator as rv


@pytest.fixture(autouse=True)
def restore_runtime_globals():
	old_poll = rv.POLL_WAIT_SECONDS
	rv.GREEN_LIGHT.set()
	yield
	rv.POLL_WAIT_SECONDS = old_poll
	rv.GREEN_LIGHT.set()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run --extra test pytest tests/test_helpers_cli.py -v`  
(If pytest is not installed yet, add the pyproject extra in step 3 first, then re-run this step expecting `AttributeError: module 'reverberator' has no attribute 'apply_poll_wait_from_env'`.)

Expected: FAIL with `AttributeError` for `apply_poll_wait_from_env` or `POLL_WAIT_SECONDS`.

- [ ] **Step 3: Pytest config + poll-wait implementation**

Append to `pyproject.toml` (keep existing `[project]` / scripts; set version to `"0.26"`):

```toml
[project.optional-dependencies]
test = ["pytest>=7"]

[tool.pytest.ini_options]
testpaths = ["tests", "reverberator.py"]
addopts = ["--doctest-modules", "-ra"]
norecursedirs = [".venv", "dist", ".git"]
markers = [
	"unit: fast in-process tests",
	"inotify: live kernel inotify",
	"process: spawn reverberator CLI",
	"privileged: requires root or REVERB_PRIVILEGED=1",
]
```

In `reverberator.py`, set `__version__ = 0.26`. After `DEFAULT_BACKUP_SIZE_LIMIT = '5%'`, add:

```python
DEFAULT_POLL_WAIT_SECONDS = 3.0
POLL_WAIT_SECONDS = DEFAULT_POLL_WAIT_SECONDS

def apply_poll_wait_from_env():
	'''Set POLL_WAIT_SECONDS from REVERB_POLL_WAIT_SECONDS. Invalid/missing → 3.0.'''
	global POLL_WAIT_SECONDS
	raw = os.environ.get('REVERB_POLL_WAIT_SECONDS')
	if raw is None or not str(raw).strip():
		POLL_WAIT_SECONDS = DEFAULT_POLL_WAIT_SECONDS
		return POLL_WAIT_SECONDS
	try:
		POLL_WAIT_SECONDS = float(raw)
	except (TypeError, ValueError):
		POLL_WAIT_SECONDS = DEFAULT_POLL_WAIT_SECONDS
	return POLL_WAIT_SECONDS

apply_poll_wait_from_env()
```

At the start of `main()`, after the `global` block, call `apply_poll_wait_from_env()`.

Replace the hardcoded wait sites listed in this task with `POLL_WAIT_SECONDS`. Functions that only *read* the global do not need a `global POLL_WAIT_SECONDS` statement.

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run --extra test pytest tests/test_helpers_cli.py -v`  
Expected: PASS (4 tests)

Also run: `uv run --extra test pytest tests/test_crash_safety.py tests/test_backup_replay_ordering.py -v`  
Expected: PASS (existing tests still work; they have no pytestmark yet)

- [ ] **Step 5: Commit**

```bash
git add pyproject.toml reverberator.py tests/conftest.py tests/test_helpers_cli.py
git commit -m "$(cat <<'EOF'
Add POLL_WAIT_SECONDS hook and pytest extra.

EOF
)"
```

---

### Task 2: Harness and remaining fixtures

**Files:**
- Create: `tests/harness.py`
- Modify: `tests/conftest.py` (add `job`, `poll_fast`, `process_env`, `run_reverberator`, non-Linux skip)
- Modify: `tests/test_helpers_cli.py` (add harness smoke tests)

**Interfaces:**
- Consumes: `reverberator.REVERB_RULE_TSV_HEADER`, `CONTENT_FILE_EXTENSION_NAME`, `PENDING_TRANSACTIONS_FILE_NAME`, `CHANGED_EVENT_HEADER`, `ChangeEvent`, `format_bytes`, `get_path_size`, `get_path_inodes`
- Produces (all in `tests/harness.py`):

```python
JobPaths = namedtuple('JobPaths', ['root', 'monitor', 'vault', 'job_name', 'job_vault', 'rule_path'])

def create_job(root: str, job_name: str = 'job') -> JobPaths: ...
def write_tree(root: str, tree: dict) -> None: ...
def seed_monitor(job: JobPaths, tree: dict) -> None: ...
def write_rule(job: JobPaths, min_snapshot: str = '1', max_snapshot: str = '86400',
	mon_fs_signature: str = 'N/A', vault_fs_signature: str = 'N/A',
	keep_one_complete_backup: str = 'True', only_sync_attributes: str = 'True',
	keep_n_versions: str = '0', backup_size_limit: str = '0') -> str: ...
def content_file_path(version_dir: str) -> str: ...
def write_committed_version(job: JobPaths, version: int, tree: dict,
	timestamp: str = '2021-01-01_00-00-00_-0800', current: bool = True) -> str: ...
def write_incomplete_version(job: JobPaths, version: int, tree: dict,
	timestamp: str = '2021-01-02_00-00-00_-0800') -> str: ...
def write_pending(job: JobPaths, events: list) -> str: ...
def committed_versions(job: JobPaths) -> list: ...
def wait_until(predicate, timeout: float = 10.0, interval: float = 0.05, message: str = 'condition not met') -> None: ...
def wait_for_committed_count(job: JobPaths, count: int, timeout: float = 10.0) -> list: ...
def reverberator_script() -> str: ...
```

`tree` maps relative paths to file contents (`str`) or `None` for a directory. Directory keys may end with `/`.

`write_rule` writes a TSV with header `REVERB_RULE_TSV_HEADER` and one data row. It does not call `parse_rules`.

`content_file_path(version_dir)` uses the same formula as `do_backup`:

```python
size_s = rv.format_bytes(rv.get_path_size(version_dir), use_1024_bytes=True, to_str=True).replace(' ', '_')
ino_s = rv.format_bytes(rv.get_path_inodes(version_dir), use_1024_bytes=False, to_str=True).replace(' ', '')
return f'{version_dir}--{size_s}B-{ino_s}_ino{rv.CONTENT_FILE_EXTENSION_NAME}'
```

`write_committed_version` creates `job_vault/V{n}--{timestamp}/`, writes `tree`, writes a content file with header `path\tiso_time\tevent\tsource_path\n`, and if `current` then sets `job_vault/current_version` as a relative symlink to that version directory basename.

`write_pending` writes `job_vault/.reverberator_pending_transactions.nsv` via `TSVZ.appendLinesTabularFile` with `CHANGED_EVENT_HEADER` (or equivalent tab-separated header + rows). `events` is a list of `ChangeEvent`. Empty `moved_from` is written as `''`.

- [ ] **Step 1: Write the failing harness tests**

Append to `tests/test_helpers_cli.py`:

```python
from tests.harness import create_job, seed_monitor, write_rule, write_committed_version, write_incomplete_version, committed_versions


def test_harness_write_committed_and_incomplete(tmp_path):
	job = create_job(str(tmp_path))
	seed_monitor(job, {'a.txt': 'hello'})
	v0 = write_committed_version(job, 0, {'a.txt': 'hello'})
	assert os.path.isdir(v0)
	assert os.path.isfile(os.path.join(job.job_vault, 'current_version')) or os.path.islink(os.path.join(job.job_vault, 'current_version'))
	assert committed_versions(job) == [v0]
	orphan = write_incomplete_version(job, 1, {'a.txt': 'x'})
	assert os.path.isdir(orphan)
	assert committed_versions(job) == [v0]


def test_harness_write_rule_explicit_columns(tmp_path):
	job = create_job(str(tmp_path))
	path = write_rule(job)
	assert os.path.isfile(path)
	text = open(path, encoding='utf-8').read()
	assert job.monitor in text
	assert 'N/A' in text
	assert '\tauto\t' not in text
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run --extra test pytest tests/test_helpers_cli.py::test_harness_write_committed_and_incomplete -v`  
Expected: FAIL with `ModuleNotFoundError: No module named 'tests.harness'` (or import error for `create_job`).

- [ ] **Step 3: Implement harness and fixtures**

Create `tests/harness.py`:

```python
import os
import time
from collections import namedtuple

import TSVZ
import reverberator as rv

JobPaths = namedtuple('JobPaths', ['root', 'monitor', 'vault', 'job_name', 'job_vault', 'rule_path'])


def create_job(root: str, job_name: str = 'job') -> JobPaths:
	monitor = os.path.join(root, 'monitor')
	vault = os.path.join(root, 'vault')
	os.makedirs(monitor, exist_ok=True)
	os.makedirs(vault, exist_ok=True)
	return JobPaths(root, monitor, vault, job_name, os.path.join(vault, job_name), os.path.join(root, 'rule.tsv'))


def write_tree(root: str, tree: dict) -> None:
	os.makedirs(root, exist_ok=True)
	for rel, content in tree.items():
		rel_norm = rel.rstrip('/')
		dest = os.path.join(root, rel_norm)
		if content is None or rel.endswith('/'):
			os.makedirs(dest, exist_ok=True)
			continue
		parent = os.path.dirname(dest)
		if parent:
			os.makedirs(parent, exist_ok=True)
		with open(dest, 'w', encoding='utf-8') as f:
			f.write(content)


def seed_monitor(job: JobPaths, tree: dict) -> None:
	write_tree(job.monitor, tree)


def write_rule(job: JobPaths, min_snapshot: str = '1', max_snapshot: str = '86400',
		mon_fs_signature: str = 'N/A', vault_fs_signature: str = 'N/A',
		keep_one_complete_backup: str = 'True', only_sync_attributes: str = 'True',
		keep_n_versions: str = '0', backup_size_limit: str = '0') -> str:
	header = rv.REVERB_RULE_TSV_HEADER
	row = [
		job.job_name, job.monitor, job.vault, mon_fs_signature, min_snapshot, max_snapshot,
		keep_one_complete_backup, only_sync_attributes, keep_n_versions, backup_size_limit,
		vault_fs_signature,
	]
	os.makedirs(os.path.dirname(job.rule_path) or '.', exist_ok=True)
	with open(job.rule_path, 'w', encoding='utf-8') as f:
		f.write('\t'.join(header) + '\n')
		f.write('\t'.join(row) + '\n')
	return job.rule_path


def content_file_path(version_dir: str) -> str:
	size_s = rv.format_bytes(rv.get_path_size(version_dir), use_1024_bytes=True, to_str=True).replace(' ', '_')
	ino_s = rv.format_bytes(rv.get_path_inodes(version_dir), use_1024_bytes=False, to_str=True).replace(' ', '')
	return f'{version_dir}--{size_s}B-{ino_s}_ino{rv.CONTENT_FILE_EXTENSION_NAME}'


def write_committed_version(job: JobPaths, version: int, tree: dict,
		timestamp: str = '2021-01-01_00-00-00_-0800', current: bool = True) -> str:
	os.makedirs(job.job_vault, exist_ok=True)
	version_dir = os.path.join(job.job_vault, f'V{version}--{timestamp}')
	write_tree(version_dir, tree)
	content = content_file_path(version_dir)
	with open(content, 'w', encoding='utf-8') as f:
		f.write('path\tiso_time\tevent\tsource_path\n')
	if current:
		link = os.path.join(job.job_vault, 'current_version')
		if os.path.lexists(link):
			os.remove(link)
		os.symlink(os.path.basename(version_dir), link, target_is_directory=True)
	return version_dir


def write_incomplete_version(job: JobPaths, version: int, tree: dict,
		timestamp: str = '2021-01-02_00-00-00_-0800') -> str:
	os.makedirs(job.job_vault, exist_ok=True)
	version_dir = os.path.join(job.job_vault, f'V{version}--{timestamp}')
	write_tree(version_dir, tree)
	return version_dir


def write_pending(job: JobPaths, events: list) -> str:
	os.makedirs(job.job_vault, exist_ok=True)
	path = os.path.join(job.job_vault, rv.PENDING_TRANSACTIONS_FILE_NAME)
	if os.path.exists(path):
		os.remove(path)
	rows = [[
		event.monotonic_time,
		event.is_dir,
		event.event,
		event.path,
		event.moved_from if event.moved_from is not None else '',
	] for event in events]
	TSVZ.appendLinesTabularFile(
		path, rows, header=rv.CHANGED_EVENT_HEADER,
		createIfNotExist=True, verifyHeader=True, strict=False, teeLogger=rv.tl, verbose=False,
	)
	return path


def committed_versions(job: JobPaths) -> list:
	if not os.path.isdir(job.job_vault):
		return []
	found = []
	for name in sorted(os.listdir(job.job_vault)):
		if not (name.startswith('V') and '--' in name):
			continue
		if rv.CONTENT_FILE_EXTENSION_NAME in name:
			continue
		path = os.path.join(job.job_vault, name)
		if not os.path.isdir(path):
			continue
		if os.path.isfile(content_file_path(path)):
			found.append(path)
	return found


def wait_until(predicate, timeout: float = 10.0, interval: float = 0.05, message: str = 'condition not met') -> None:
	deadline = time.monotonic() + timeout
	while time.monotonic() < deadline:
		if predicate():
			return
		time.sleep(interval)
	raise AssertionError(message)


def wait_for_committed_count(job: JobPaths, count: int, timeout: float = 10.0) -> list:
	wait_until(
		lambda: len(committed_versions(job)) >= count,
		timeout=timeout,
		message=f'expected >= {count} committed versions, got {committed_versions(job)} in {job.job_vault}',
	)
	return committed_versions(job)


def reverberator_script() -> str:
	return os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'reverberator.py'))
```

Replace `tests/conftest.py` with:

```python
import os
import signal
import subprocess
import sys
import pytest
import reverberator as rv
from tests.harness import create_job, reverberator_script


@pytest.fixture(autouse=True)
def restore_runtime_globals():
	old_poll = rv.POLL_WAIT_SECONDS
	rv.GREEN_LIGHT.set()
	yield
	rv.POLL_WAIT_SECONDS = old_poll
	rv.GREEN_LIGHT.set()


@pytest.fixture
def job(tmp_path):
	return create_job(str(tmp_path))


@pytest.fixture
def poll_fast():
	rv.POLL_WAIT_SECONDS = 0.05
	return 0.05


@pytest.fixture
def process_env():
	env = os.environ.copy()
	env['REVERB_POLL_WAIT_SECONDS'] = '0.05'
	env['PYTHONUNBUFFERED'] = '1'
	return env


@pytest.fixture
def run_reverberator(tmp_path, process_env):
	procs = []
	log_dir = str(tmp_path / 'proc_logs')
	os.makedirs(log_dir, exist_ok=True)

	def _run(rule_path, extra_args=()):
		p = subprocess.Popen(
			[sys.executable, reverberator_script(), '--no_log', '-ld', log_dir, *list(extra_args), str(rule_path)],
			env=process_env,
			stdout=subprocess.PIPE,
			stderr=subprocess.PIPE,
			text=True,
		)
		procs.append(p)
		return p

	yield _run
	for p in procs:
		if p.poll() is None:
			p.send_signal(signal.SIGTERM)
			try:
				p.wait(timeout=2)
			except subprocess.TimeoutExpired:
				p.kill()
				p.wait()


def pytest_collection_modifyitems(config, items):
	if sys.platform == 'linux':
		return
	skip = pytest.mark.skip(reason='inotify/process tests require Linux')
	for item in items:
		if item.get_closest_marker('inotify') or item.get_closest_marker('process'):
			item.add_marker(skip)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run --extra test pytest tests/test_helpers_cli.py -v`  
Expected: PASS including harness tests.

- [ ] **Step 5: Commit**

```bash
git add tests/harness.py tests/conftest.py tests/test_helpers_cli.py
git commit -m "$(cat <<'EOF'
Add temp-job test harness and pytest fixtures.

EOF
)"
```

---

### Task 3: Mark existing tests as `unit`

**Files:**
- Modify: `tests/test_crash_safety.py` (add `pytestmark` after imports; keep every existing test method)
- Modify: `tests/test_backup_replay_ordering.py` (same)

**Interfaces:**
- Consumes: pytest markers from Task 1
- Produces: both modules collect under `-m unit`

Do not delete or rewrite assertions. `unittest.TestCase` may stay; pytest runs it. Add only:

```python
import pytest
pytestmark = pytest.mark.unit
```

Place `pytestmark` after the existing imports.

- [ ] **Step 1: Add pytestmark to both files** as shown above.

- [ ] **Step 2: Run marker selection**

Run: `uv run --extra test pytest -m unit -v`  
Expected: existing crash-safety + replay-ordering + helpers_cli tests selected; no collection errors.

Run: `uv run --extra test pytest tests/test_crash_safety.py tests/test_backup_replay_ordering.py -v`  
Expected: PASS, same test count as before this task.

- [ ] **Step 3: Commit**

```bash
git add tests/test_crash_safety.py tests/test_backup_replay_ordering.py
git commit -m "$(cat <<'EOF'
Mark existing tests as pytest unit.

EOF
)"
```

---

### Task 4: Helpers and CLI tests

**Files:**
- Modify: `tests/test_helpers_cli.py` (append catalog cases; keep poll-wait and harness tests)

**Interfaces:**
- Consumes: `rv.slugify`, `rv.bidict`, `rv.get_args`, `rv.hash_file`, `rv.check_fs_signature`, `rv.signal_handler`, `rv.GREEN_LIGHT`
- Produces: unit coverage listed below

These tests target **existing** production code. Write them, run expecting PASS. If FAIL, fix the test unless production contradicts the spec.

- [ ] **Step 1: Append tests**

```python
import io
import sys
from collections import deque


def test_slugify_dirty_and_unicode():
	assert rv.slugify('My Job Name!') == 'my-job-name'
	assert 'uber' in rv.slugify('über') or 'uber' in rv.slugify('über').replace('ü', 'u')
	assert rv.slugify('café', allow_unicode=True) == 'café' or 'caf' in rv.slugify('café', allow_unicode=True)


def test_bidict_overwrite_and_delete():
	d = rv.bidict({1: '/a', 2: '/b'})
	assert d.inverse['/a'] == 1
	d[1] = '/c'
	assert '/a' not in d.inverse
	assert d.inverse['/c'] == 1
	del d[2]
	assert '/b' not in d.inverse


def test_get_args_defaults_and_flags():
	args, _ = rv.get_args([])
	assert args.rule_path == 'reverb_rule.tsv'
	assert args.journal is False
	assert rv.get_args(['--journal'])[0].journal is True
	assert rv.get_args(['-t', '0'])[0].threads == 0
	assert rv.get_args(['-t', '-2'])[0].threads == -2
	assert rv.get_args(['-t', '4'])[0].threads == 4
	assert rv.get_args(['--drop_sample_reverb_rule_file', 'out.tsv'])[0].drop_sample_reverb_rule_file is True
	assert rv.get_args(['--verbose'])[0].verbose is True


def test_hash_file_full_vs_partial(tmp_path):
	p = tmp_path / 'blob.bin'
	p.write_bytes(b'x' * (rv.HASH_SIZE + 100) + b'TAIL')
	full = rv.hash_file(str(p), full_hash=True)
	part = rv.hash_file(str(p), full_hash=False)
	assert len(full) == 16
	assert len(part) == 16
	assert full != part


def test_check_fs_signature_mismatch(tmp_path):
	assert rv.check_fs_signature(str(tmp_path), 'N/A') is True
	assert rv.check_fs_signature(str(tmp_path), 'this-signature-cannot-match-zzzz') is False


def test_signal_handler_first_clears_green_light_second_exits(monkeypatch):
	rv.GREEN_LIGHT.set()
	exited = []
	monkeypatch.setattr(sys, 'exit', lambda code: exited.append(code))
	monkeypatch.setattr(rv.time, 'sleep', lambda s: None)
	rv.signal_handler(None, None)
	assert rv.GREEN_LIGHT.is_set() is False
	rv.signal_handler(None, None)
	assert exited == [1]
```

For `test_slugify_dirty_and_unicode`, assert the **actual** current `slugify` doctest values rather than the loose `in` checks:

```python
def test_slugify_dirty_and_unicode():
	assert rv.slugify('My Job Name!') == 'my-job-name'
	assert rv.slugify('  spaces--and___underscores  ') == 'spaces-and___underscores'
	assert rv.slugify('über') == 'uber'
	assert rv.slugify('café', allow_unicode=True) == 'café'
```

(`strip_*` / `as_folder_entry` stay doctest-only. Do not duplicate them.)

- [ ] **Step 2: Run tests**

Run: `uv run --extra test pytest tests/test_helpers_cli.py -v`  
Expected: PASS. If `get_args(['--drop_sample_reverb_rule_file', 'out.tsv'])` fails because argparse treats `out.tsv` as `rule_path`, use `rv.get_args(['--drop_sample_reverb_rule_file'])` and assert the flag True with default `rule_path`.

- [ ] **Step 3: Commit**

```bash
git add tests/test_helpers_cli.py
git commit -m "$(cat <<'EOF'
Add helper and CLI unit tests.

EOF
)"
```

---

### Task 5: `parse_rules` tests

**Files:**
- Create: `tests/test_parse_rules.py`

**Interfaces:**
- Consumes: `rv.parse_rules`, `rv.REVERB_RULE_TSV_HEADER`, `job` fixture, `write_rule`
- Produces: tmp-only rule parsing tests (`pytestmark = unit`)

`parse_rules` calls `sys.exit(1)` when the file is missing or empty. Test with `pytest.raises(SystemExit)`.

- [ ] **Step 1: Write tests**

```python
import os
import pytest
import reverberator as rv
from tests.harness import write_rule

pytestmark = pytest.mark.unit


def test_parse_rules_missing_file_exits(tmp_path):
	with pytest.raises(SystemExit) as exc:
		rv.parse_rules(str(tmp_path / 'nope.tsv'))
	assert exc.value.code == 1


def test_parse_rules_header_only_exits(tmp_path):
	p = tmp_path / 'empty.tsv'
	p.write_text('\t'.join(rv.REVERB_RULE_TSV_HEADER) + '\n', encoding='utf-8')
	with pytest.raises(SystemExit) as exc:
		rv.parse_rules(str(p))
	assert exc.value.code == 1


def test_parse_rules_empty_job_name_ignored(job):
	write_rule(job)
	lines = open(job.rule_path, encoding='utf-8').read().splitlines()
	blank = '\t'.join([''] + [job.monitor, job.vault, 'N/A', '1', '86400', 'True', 'True', '0', '0', 'N/A'])
	with open(job.rule_path, 'w', encoding='utf-8') as f:
		f.write(lines[0] + '\n' + blank + '\n')
	assert rv.parse_rules(job.rule_path) == []


def test_parse_rules_missing_monitor_ignored(job):
	write_rule(job)
	text = open(job.rule_path, encoding='utf-8').read().replace(job.monitor, str(os.path.join(job.root, 'does-not-exist')))
	open(job.rule_path, 'w', encoding='utf-8').write(text)
	assert rv.parse_rules(job.rule_path) == []


def test_parse_rules_vault_subpath_of_monitor_ignored(job):
	nested_vault = os.path.join(job.monitor, 'inside')
	os.makedirs(nested_vault, exist_ok=True)
	write_rule(job)
	text = open(job.rule_path, encoding='utf-8').read().replace(job.vault, nested_vault)
	open(job.rule_path, 'w', encoding='utf-8').write(text)
	assert rv.parse_rules(job.rule_path) == []


def test_parse_rules_slugifies_job_name_and_appends(job):
	write_rule(job)
	text = open(job.rule_path, encoding='utf-8').read().replace('\tjob\t', '\tMy Job!\t', 1)
	# header uses "Job Name" not the value; replace the data-row job name:
	lines = open(job.rule_path, encoding='utf-8').read().splitlines()
	cols = lines[1].split('\t')
	cols[0] = 'My Job!'
	open(job.rule_path, 'w', encoding='utf-8').write(lines[0] + '\n' + '\t'.join(cols) + '\n')
	rules = rv.parse_rules(job.rule_path)
	assert len(rules) == 1
	assert rules[0].job_name == 'my-job'
	updated = open(job.rule_path, encoding='utf-8').read()
	assert 'my-job' in updated


def test_parse_rules_na_signatures_unchanged(job):
	write_rule(job, mon_fs_signature='N/A', vault_fs_signature='N/A')
	rules = rv.parse_rules(job.rule_path)
	assert rules[0].mon_fs_signature == 'N/A'
	assert rules[0].vault_fs_signature == 'N/A'


def test_parse_rules_auto_fills_when_signatures_returned(job, monkeypatch):
	write_rule(job, mon_fs_signature='auto', vault_fs_signature='auto')
	monkeypatch.setattr(rv, 'get_fs_signatures', lambda path: ['fake-uuid'])
	rules = rv.parse_rules(job.rule_path)
	assert rules[0].mon_fs_signature == 'fake-uuid'
	assert rules[0].vault_fs_signature == 'fake-uuid'


def test_parse_rules_auto_keeps_auto_when_signatures_empty(job, monkeypatch):
	write_rule(job, mon_fs_signature='auto', vault_fs_signature='auto')
	monkeypatch.setattr(rv, 'get_fs_signatures', lambda path: [])
	rules = rv.parse_rules(job.rule_path)
	assert rules[0].mon_fs_signature == 'auto'
	assert rules[0].vault_fs_signature == 'auto'


def test_parse_rules_none_and_auto_defaults(job):
	write_rule(job)
	lines = open(job.rule_path, encoding='utf-8').read().splitlines()
	cols = lines[1].split('\t')
	# min, max, keep_one, only_sync, keep_n, size_limit
	cols[4] = 'none'
	cols[5] = 'auto'
	cols[6] = 'auto'
	cols[7] = 'none'
	cols[8] = 'none'
	cols[9] = 'auto'
	open(job.rule_path, 'w', encoding='utf-8').write(lines[0] + '\n' + '\t'.join(cols) + '\n')
	rules = rv.parse_rules(job.rule_path)
	assert rules[0].min_shapshot_time == '0'
	assert rules[0].max_shapshot_time == str(rv.DEFAULT_MAX_DELAY)
	assert rules[0].keep_one_complete_backup == str(rv.DEFAULT_KEEP_ONE_COMPLETE_BACKUP)
	assert rules[0].only_sync_attributes == str(rv.DEFAULT_ONLY_SYNC_ATTRIBUTES)
	assert rules[0].keep_n_versions == '0'
	assert rules[0].backup_size_limit == rv.DEFAULT_BACKUP_SIZE_LIMIT
```

Column indexes must match `REVERB_RULE_HEADER` / TSV header order: job_name, mon_path, vault_path, mon_fs_signature, min, max, keep_one, only_sync, keep_n, backup_size_limit, vault_fs_signature.

- [ ] **Step 2: Run tests**

Run: `uv run --extra test pytest tests/test_parse_rules.py -v`  
Expected: PASS. Adjust column indexes or empty-file behavior to match actual `TSVZ.readTabularFile` (if header-only does not `sys.exit`, assert whatever current code does: empty list vs exit).

- [ ] **Step 3: Commit**

```bash
git add tests/test_parse_rules.py
git commit -m "$(cat <<'EOF'
Add parse_rules unit tests on temp TSV files.

EOF
)"
```

---

### Task 6: Event coalescing tests

**Files:**
- Create: `tests/test_events.py`

**Interfaces:**
- Consumes: `rv.change_events_to_backup_entries`, `rv.backup_entries_to_change_events`, `rv.ChangeEvent`
- Produces: branch coverage beyond doctest. Prune/order/`prepare` stay in `tests/test_backup_replay_ordering.py`.

Use fixed absolute paths like `/tmp/reverb_events/...` (no need for the files to exist).

- [ ] **Step 1: Write tests**

```python
from collections import deque
import pytest
import reverberator as rv

pytestmark = pytest.mark.unit

P = '/tmp/reverb_events'


def _ev(t, is_dir, event, path, moved_from=None):
	return rv.ChangeEvent(float(t), is_dir, event, path, moved_from)


def test_chain_moves_keep_original_source():
	entries = rv.change_events_to_backup_entries(deque([
		_ev(1, False, 'move', f'{P}/b', f'{P}/a'),
		_ev(2, False, 'move', f'{P}/c', f'{P}/b'),
	]))
	assert f'{P}/c' in entries
	assert entries[f'{P}/c'].event == 'move'
	assert entries[f'{P}/c'].source_path == f'{P}/a'


def test_virgin_move_becomes_create():
	entries = rv.change_events_to_backup_entries(deque([
		_ev(1, False, 'move', f'{P}/a', None),
	]))
	assert entries[f'{P}/a'].event == 'create'


def test_delete_before_move_from_is_ignored():
	entries = rv.change_events_to_backup_entries(deque([
		_ev(1, False, 'delete', f'{P}/a', None),
		_ev(2, False, 'move', f'{P}/b', f'{P}/a'),
	]))
	assert f'{P}/a' not in entries or entries.get(f'{P}/a') is None
	assert entries[f'{P}/b'].event == 'move'
	assert entries[f'{P}/b'].source_path == f'{P}/a'


def test_attrib_then_move_escalates_dest():
	entries = rv.change_events_to_backup_entries(deque([
		_ev(1, False, 'attrib', f'{P}/a', None),
		_ev(2, False, 'move', f'{P}/b', f'{P}/a'),
	]))
	assert entries[f'{P}/b'].event in ('move', 'modify')
	assert entries[f'{P}/b'].source_path == f'{P}/a'


def test_create_then_delete_cancels():
	entries = rv.change_events_to_backup_entries(deque([
		_ev(1, False, 'create', f'{P}/new', None),
		_ev(2, False, 'delete', f'{P}/new', None),
	]))
	assert entries == rv.OrderedDict() or len(entries) == 0


def test_create_then_modify_stays_create():
	entries = rv.change_events_to_backup_entries(deque([
		_ev(1, False, 'create', f'{P}/new', None),
		_ev(2, False, 'modify', f'{P}/new', None),
	]))
	assert entries[f'{P}/new'].event == 'create'


def test_dir_paths_get_trailing_slash():
	entries = rv.change_events_to_backup_entries(deque([
		_ev(1, True, 'create', f'{P}/d', None),
	]))
	assert f'{P}/d/' in entries


def test_self_destruct_skipped():
	entries = rv.change_events_to_backup_entries(deque([
		_ev(1, True, 'self_destruct', P, None),
	]))
	assert len(entries) == 0


def test_backup_entries_round_trip_move_and_dir():
	original = rv.change_events_to_backup_entries(deque([
		_ev(1, True, 'create', f'{P}/d', None),
		_ev(2, False, 'move', f'{P}/b', f'{P}/a'),
	]))
	events = rv.backup_entries_to_change_events(original)
	by_path = {e.path.rstrip('/') + ('/' if e.is_dir else ''): e for e in events}
	assert by_path[f'{P}/d/'].is_dir is True
	assert by_path[f'{P}/d/'].event == 'create'
	assert by_path[f'{P}/b'].event == 'move'
	assert by_path[f'{P}/b'].moved_from == f'{P}/a'
```

Import `OrderedDict` from `collections` if using `rv.OrderedDict` fails (`OrderedDict` is imported in `reverberator.py` but not necessarily re-exported as attribute — use `from collections import OrderedDict` and `len(entries) == 0`).

- [ ] **Step 2: Run tests**

Run: `uv run --extra test pytest tests/test_events.py -v`  
Expected: PASS. If chain-move or attrib-escalation differs, assert the **actual** coalescer result and add a comment; do not change coalescer policy.

- [ ] **Step 3: Commit**

```bash
git add tests/test_events.py
git commit -m "$(cat <<'EOF'
Add change-event coalescing branch tests.

EOF
)"
```

---

### Task 7: Vault scan tests

**Files:**
- Create: `tests/test_vault.py`

**Interfaces:**
- Consumes: `rv.remove_incomplete_vault_versions`, `rv.get_vault_info`, `write_committed_version`, `write_incomplete_version`, `content_file_path`
- Produces: unit tests for commit marker = content file

Existing crash-safety tests already cover the simple orphan delete. This module adds `get_vault_info` indexing and `recalculate=True`.

- [ ] **Step 1: Write tests**

```python
import os
import pytest
import reverberator as rv
from tests.harness import write_committed_version, write_incomplete_version, content_file_path

pytestmark = pytest.mark.unit


def test_get_vault_info_indexes_committed_only(job):
	v0 = write_committed_version(job, 0, {'a.txt': 'x'})
	write_incomplete_version(job, 1, {'a.txt': 'y'})
	info = rv.get_vault_info(job.job_vault)
	assert 0 in info.vault_info_dict
	assert 1 not in info.vault_info_dict
	assert info.vault_info_dict[0].path == v0
	assert not os.path.isdir(os.path.join(job.job_vault, 'V1--2021-01-02_00-00-00_-0800'))


def test_content_file_path_matches_production_formula(job):
	v0 = write_committed_version(job, 0, {'a.txt': 'hello'})
	expected = content_file_path(v0)
	assert os.path.isfile(expected)


def test_get_vault_info_recalculate_refreshes_size(job):
	v0 = write_committed_version(job, 0, {'a.txt': 'hello'})
	info = rv.get_vault_info(job.job_vault, recalculate=True)
	assert 0 in info.vault_info_dict
	assert info.vault_info_dict[0].size == rv.get_path_size(v0)
	assert info.vault_info_dict[0].inode == rv.get_path_inodes(v0)
```

- [ ] **Step 2: Run tests**

Run: `uv run --extra test pytest tests/test_vault.py -v`  
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add tests/test_vault.py
git commit -m "$(cat <<'EOF'
Add vault scan and content-file unit tests.

EOF
)"
```

---

### Task 8: Pending transaction tests

**Files:**
- Create: `tests/test_pending.py`

**Interfaces:**
- Consumes: `rv.persist_pending_transactions`, `rv.load_pending_transactions_for_resume`, `write_pending`, `os.utime`
- Produces: mtime-gate tests **without** sleeping 1s+ (use `os.utime`)

Resume condition in production: `latest_monitor_change <= pending_mtime - 1.0`.

- [ ] **Step 1: Write tests**

```python
import os
from collections import deque
import pytest
import reverberator as rv
from tests.harness import seed_monitor, write_pending

pytestmark = pytest.mark.unit


def test_persist_writes_rows_empty_deque_writes_nothing(job):
	os.makedirs(job.job_vault, exist_ok=True)
	rv.persist_pending_transactions(job.job_name, job.vault, deque())
	pending = os.path.join(job.job_vault, rv.PENDING_TRANSACTIONS_FILE_NAME)
	assert not os.path.exists(pending)
	events = deque([rv.ChangeEvent(1.0, False, 'modify', os.path.join(job.monitor, 'a.txt'), None)])
	rv.persist_pending_transactions(job.job_name, job.vault, events)
	assert os.path.isfile(pending)


def test_load_resume_when_pending_newer_than_monitor(job):
	seed_monitor(job, {'a.txt': 'x'})
	a = os.path.join(job.monitor, 'a.txt')
	os.utime(job.monitor, (1000, 1000))
	os.utime(a, (1000, 1000))
	pending_path = write_pending(job, [rv.ChangeEvent(1.0, False, 'modify', a, None)])
	os.utime(pending_path, (2000, 2000))
	to_process = deque()
	ok = rv.load_pending_transactions_for_resume(job.job_name, job.monitor, job.vault, to_process)
	assert ok is True
	assert len(to_process) == 1
	assert to_process[0].event == 'modify'
	assert not os.path.exists(pending_path)


def test_load_discard_when_monitor_not_older(job):
	seed_monitor(job, {'a.txt': 'x'})
	a = os.path.join(job.monitor, 'a.txt')
	pending_path = write_pending(job, [rv.ChangeEvent(1.0, False, 'modify', a, None)])
	now = 5000
	os.utime(pending_path, (now, now))
	os.utime(job.monitor, (now, now))
	os.utime(a, (now, now))
	to_process = deque()
	ok = rv.load_pending_transactions_for_resume(job.job_name, job.monitor, job.vault, to_process)
	assert ok is False
	assert len(to_process) == 0
	assert not os.path.exists(pending_path)


def test_load_corrupt_pending_clears(job):
	seed_monitor(job, {'a.txt': 'x'})
	os.makedirs(job.job_vault, exist_ok=True)
	pending_path = os.path.join(job.job_vault, rv.PENDING_TRANSACTIONS_FILE_NAME)
	open(pending_path, 'w', encoding='utf-8').write('not a valid nsv\x00\x00')
	os.utime(job.monitor, (1000, 1000))
	os.utime(os.path.join(job.monitor, 'a.txt'), (1000, 1000))
	os.utime(pending_path, (2000, 2000))
	to_process = deque()
	ok = rv.load_pending_transactions_for_resume(job.job_name, job.monitor, job.vault, to_process)
	assert ok is False
	assert len(to_process) == 0
	assert not os.path.exists(pending_path)
```

- [ ] **Step 2: Run tests**

Run: `uv run --extra test pytest tests/test_pending.py -v`  
Expected: PASS. If TSVZ refuses the corrupt file without deleting it, assert current behavior (no crash; deque empty). If `get_monitor_path_most_recent_change_time` still sees a newer mtime (e.g. `job_vault` creation), set **all** scanned monitor paths’ mtimes, not the vault (load only stats `monitor_path`).

- [ ] **Step 3: Commit**

```bash
git add tests/test_pending.py
git commit -m "$(cat <<'EOF'
Add pending-transaction persist and mtime-gate tests.

EOF
)"
```

---

### Task 9: Backup V0 and reverb replay tests

**Files:**
- Create: `tests/test_backup.py`

**Interfaces:**
- Consumes: `rv.do_backup`, `rv.do_reverb_backup`, `rv.BackupEntryValues`, `rv.VaultEntry`, `rv.TrackingFilesFolders`, `poll_fast`, `job`
- Produces: V0 complete vs referenced, attrib/move/create/delete, journal, rename-fail fallback

Abort / empty-delta / dir-delete tracking already live in `test_crash_safety.py`. Do not copy those tests; add a one-line comment pointing at them.

- [ ] **Step 1: Write tests**

```python
import os
from collections import OrderedDict
import pytest
import reverberator as rv
from tests.harness import seed_monitor, write_committed_version, committed_versions

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def _fast(poll_fast):
	return poll_fast


def test_v0_complete_copy_is_not_symlink_into_monitor(job):
	seed_monitor(job, {'a.txt': 'hello'})
	info, tracking, committed = rv.do_backup(
		{}, job_name=job.job_name, monitor_path=job.monitor, vault_path=job.vault,
		keep_one_complete_backup=True, only_sync_attributes=True,
		keep_n_versions=0, backup_size_limit='0',
	)
	assert committed is True
	versions = committed_versions(job)
	assert len(versions) == 1
	dest = os.path.join(versions[0], 'a.txt')
	assert os.path.isfile(dest)
	assert not os.path.islink(dest)
	assert open(dest).read() == 'hello'
	assert 'a.txt' in tracking.files


def test_v0_referenced_copy_symlinks_into_monitor(job):
	seed_monitor(job, {'a.txt': 'hello'})
	info, tracking, committed = rv.do_backup(
		{}, job_name=job.job_name, monitor_path=job.monitor, vault_path=job.vault,
		keep_one_complete_backup=False, only_sync_attributes=True,
		keep_n_versions=0, backup_size_limit='0',
	)
	assert committed is True
	dest = os.path.join(committed_versions(job)[0], 'a.txt')
	assert os.path.islink(dest)
	assert os.path.realpath(dest) == os.path.realpath(os.path.join(job.monitor, 'a.txt'))


def test_journal_written_when_enabled(job):
	seed_monitor(job, {'a.txt': 'hello'})
	rv.do_backup(
		{}, job_name=job.job_name, monitor_path=job.monitor, vault_path=job.vault,
		keep_one_complete_backup=True, only_sync_attributes=True,
		keep_n_versions=0, backup_size_limit='0', log_journal=True,
	)
	assert os.path.isfile(os.path.join(job.job_vault, 'journal.tsv'))


def test_reverb_create_modify_delete_attrib_move_file_and_dir(job):
	seed_monitor(job, {'keep.txt': 'k', 'old.txt': 'o', 'sub/x.txt': 'x'})
	v0 = write_committed_version(job, 0, {'keep.txt': 'k', 'old.txt': 'o', 'sub/x.txt': 'x'})
	os.makedirs(os.path.join(job.monitor, 'newdir'), exist_ok=True)
	open(os.path.join(job.monitor, 'newdir', 'n.txt'), 'w').write('n')
	open(os.path.join(job.monitor, 'keep.txt'), 'w').write('k2')
	os.remove(os.path.join(job.monitor, 'old.txt'))
	os.rename(os.path.join(job.monitor, 'sub'), os.path.join(job.monitor, 'moved'))
	os.chmod(os.path.join(job.monitor, 'keep.txt'), 0o640)
	v1 = os.path.join(job.job_vault, 'V1--2021-01-02_00-00-00_-0800')
	os.makedirs(v1)
	entries = OrderedDict([
		(os.path.join(job.monitor, 'keep.txt'), rv.BackupEntryValues('t', 'modify', None)),
		(os.path.join(job.monitor, 'old.txt'), rv.BackupEntryValues('t', 'delete', None)),
		(os.path.join(job.monitor, 'newdir') + '/', rv.BackupEntryValues('t', 'create', None)),
		(os.path.join(job.monitor, 'moved') + '/', rv.BackupEntryValues('t', 'move', os.path.join(job.monitor, 'sub') + '/')),
	])
	latest = rv.VaultEntry(0, v0, 0, 1, 1)
	tracking = rv.TrackingFilesFolders(['keep.txt', 'old.txt', 'sub/x.txt'], ['sub/'])
	rv.GREEN_LIGHT.set()
	result = rv.do_reverb_backup(entries, v1, latest, True, tracking, job.monitor)
	assert os.path.isfile(os.path.join(v1, 'keep.txt'))
	assert open(os.path.join(v1, 'keep.txt')).read() == 'k2'
	assert not os.path.lexists(os.path.join(v1, 'old.txt'))
	assert os.path.isfile(os.path.join(v1, 'newdir', 'n.txt'))
	assert os.path.lexists(os.path.join(v1, 'moved', 'x.txt'))
	assert 'old.txt' not in result.files
	assert 'keep.txt' in result.files


def test_attrib_only_sync_vs_copy(job):
	seed_monitor(job, {'a.txt': 'same'})
	v0 = write_committed_version(job, 0, {'a.txt': 'same'})
	os.chmod(os.path.join(job.monitor, 'a.txt'), 0o600)
	for only_sync, label in ((True, 'sync'), (False, 'copy')):
		v = os.path.join(job.job_vault, f'V-{label}')
		os.makedirs(v)
		entries = OrderedDict([
			(os.path.join(job.monitor, 'a.txt'), rv.BackupEntryValues('t', 'attrib', None)),
		])
		latest = rv.VaultEntry(0, v0, 0, 1, 1)
		rv.do_reverb_backup(entries, v, latest, only_sync, rv.TrackingFilesFolders(['a.txt'], []), job.monitor)
		assert os.path.lexists(os.path.join(v, 'a.txt'))


def test_move_rename_failure_falls_back_to_copy_delete(job, monkeypatch):
	seed_monitor(job, {'a.txt': 'data'})
	v0 = write_committed_version(job, 0, {'a.txt': 'data'})
	os.rename(os.path.join(job.monitor, 'a.txt'), os.path.join(job.monitor, 'b.txt'))
	v1 = os.path.join(job.job_vault, 'V1--2021-01-02_00-00-00_-0800')
	os.makedirs(v1)
	real_rename = os.rename

	def boom(src, dst):
		if os.path.basename(dst) == 'b.txt':
			raise OSError('simulated')
		return real_rename(src, dst)

	monkeypatch.setattr(os, 'rename', boom)
	entries = OrderedDict([
		(os.path.join(job.monitor, 'b.txt'), rv.BackupEntryValues('t', 'move', os.path.join(job.monitor, 'a.txt'))),
	])
	rv.do_reverb_backup(
		entries, v1, rv.VaultEntry(0, v0, 0, 1, 1), True,
		rv.TrackingFilesFolders(['a.txt'], []), job.monitor,
	)
	assert os.path.isfile(os.path.join(v1, 'b.txt'))
	assert open(os.path.join(v1, 'b.txt')).read() == 'data'
```

- [ ] **Step 2: Run tests**

Run: `uv run --extra test pytest tests/test_backup.py -v`  
Expected: PASS. If combined create/move batch is too coupled, split into separate tests that still cover create, modify, delete, attrib, file move, and dir move.

- [ ] **Step 3: Commit**

```bash
git add tests/test_backup.py
git commit -m "$(cat <<'EOF'
Add V0 and reverb-backup unit tests.

EOF
)"
```

---

### Task 10: Delta tests

**Files:**
- Create: `tests/test_delta.py`

**Interfaces:**
- Consumes: `rv.delta_generate_backup_entries`, `rv.check_duplicate`, `rv.VaultEntry`
- Produces: unchanged / changed / new / deleted entries

- [ ] **Step 1: Write tests**

```python
import os
from collections import OrderedDict
import pytest
import reverberator as rv
from tests.harness import seed_monitor, write_committed_version

pytestmark = pytest.mark.unit


def test_delta_unchanged_file_not_added(job):
	seed_monitor(job, {'a.txt': 'hello'})
	v0 = write_committed_version(job, 0, {'a.txt': 'hello'})
	os.utime(os.path.join(job.monitor, 'a.txt'), ns=(os.lstat(os.path.join(v0, 'a.txt')).st_atime_ns, os.lstat(os.path.join(v0, 'a.txt')).st_mtime_ns))
	entries = OrderedDict()
	latest = rv.VaultEntry(0, v0, 0, 1, 1)
	rv.delta_generate_backup_entries(entries, latest, job.monitor)
	assert os.path.join(job.monitor, 'a.txt') not in entries


def test_delta_changed_content_is_modify(job):
	seed_monitor(job, {'a.txt': 'hello'})
	v0 = write_committed_version(job, 0, {'a.txt': 'hello'})
	open(os.path.join(job.monitor, 'a.txt'), 'w').write('world')
	entries = OrderedDict()
	rv.delta_generate_backup_entries(entries, rv.VaultEntry(0, v0, 0, 1, 1), job.monitor)
	assert entries[os.path.join(job.monitor, 'a.txt')].event == 'modify'


def test_delta_new_and_deleted(job):
	seed_monitor(job, {'keep.txt': 'k'})
	v0 = write_committed_version(job, 0, {'keep.txt': 'k', 'gone.txt': 'g'})
	open(os.path.join(job.monitor, 'new.txt'), 'w').write('n')
	entries = OrderedDict()
	rv.delta_generate_backup_entries(entries, rv.VaultEntry(0, v0, 0, 1, 1), job.monitor)
	assert entries[os.path.join(job.monitor, 'new.txt')].event == 'create'
	assert entries[os.path.join(job.monitor, 'gone.txt')].event == 'delete'
```

If unchanged files still appear because mtime/hash differ after `write_committed_version` (copy vs original), set mtime with `os.utime` from the vault file onto the monitor file as in the first test, or copy the vault bytes back. Assert whatever `check_duplicate` actually emits when size+mtime+hash match.

- [ ] **Step 2: Run tests**

Run: `uv run --extra test pytest tests/test_delta.py -v`  
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add tests/test_delta.py
git commit -m "$(cat <<'EOF'
Add delta-generate backup entry tests.

EOF
)"
```

---

### Task 11: Retention and stepper tests

**Files:**
- Create: `tests/test_retention.py`

**Interfaces:**
- Consumes: `rv.do_backup`, `rv.decrement_stepper` (existing abort/success tests stay in crash-safety)
- Produces: `keep_n_versions=2` with V0 real + V1 symlink; size limit `'1'` still creates next version if stepper returns `(0,0)`

- [ ] **Step 1: Write tests**

```python
import os
from collections import OrderedDict
import pytest
import reverberator as rv
from tests.harness import seed_monitor, write_committed_version, committed_versions, content_file_path

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def _fast(poll_fast):
	return poll_fast


def _two_versions_symlink_pair(job):
	'''V0 real file, V1 symlink to V0 file, both committed.'''
	seed_monitor(job, {'a.txt': 'data'})
	v0 = write_committed_version(job, 0, {'a.txt': 'data'}, timestamp='2021-01-01_00-00-00_-0800', current=False)
	v1 = os.path.join(job.job_vault, 'V1--2021-01-02_00-00-00_-0800')
	os.makedirs(v1)
	os.symlink(os.path.join(v0, 'a.txt'), os.path.join(v1, 'a.txt'))
	with open(content_file_path(v1), 'w', encoding='utf-8') as f:
		f.write('path\tiso_time\tevent\tsource_path\n')
	link = os.path.join(job.job_vault, 'current_version')
	if os.path.lexists(link):
		os.remove(link)
	os.symlink(os.path.basename(v1), link, target_is_directory=True)
	return v0, v1


def test_keep_n_versions_2_steps_before_v2(job):
	v0, v1 = _two_versions_symlink_pair(job)
	open(os.path.join(job.monitor, 'a.txt'), 'w').write('data2')
	entries = OrderedDict([
		(os.path.join(job.monitor, 'a.txt'), rv.BackupEntryValues('t', 'modify', None)),
	])
	info = rv.get_vault_info(job.job_vault)
	tracking = rv.TrackingFilesFolders(['a.txt'], [])
	rv.do_backup(
		entries, job_name=job.job_name, monitor_path=job.monitor, vault_path=job.vault,
		keep_one_complete_backup=True, only_sync_attributes=True,
		keep_n_versions=2, backup_size_limit='0',
		vaultInfo=info, trackingFilesFolders=tracking,
	)
	assert not os.path.isdir(v0)
	names = [os.path.basename(p) for p in committed_versions(job)]
	assert any(n.startswith('V1') or n.startswith('V2') for n in names)


def test_tiny_size_limit_still_creates_version_if_stepper_cannot_free(job, monkeypatch):
	seed_monitor(job, {'a.txt': 'hello'})
	write_committed_version(job, 0, {'a.txt': 'hello'})
	monkeypatch.setattr(rv, 'decrement_stepper', lambda d: (0, 0))
	open(os.path.join(job.monitor, 'a.txt'), 'w').write('hello2')
	entries = OrderedDict([
		(os.path.join(job.monitor, 'a.txt'), rv.BackupEntryValues('t', 'modify', None)),
	])
	info = rv.get_vault_info(job.job_vault)
	rv.do_backup(
		entries, job_name=job.job_name, monitor_path=job.monitor, vault_path=job.vault,
		keep_one_complete_backup=True, only_sync_attributes=True,
		keep_n_versions=0, backup_size_limit='1',
		vaultInfo=info, trackingFilesFolders=rv.TrackingFilesFolders(['a.txt'], []),
	)
	assert len(committed_versions(job)) >= 2


def test_inode_limit_i1_attempts_stepper(job, monkeypatch):
	called = []
	seed_monitor(job, {'a.txt': 'hello'})
	write_committed_version(job, 0, {'a.txt': 'hello'})
	real = rv.decrement_stepper

	def wrap(d):
		called.append(True)
		return real(d)

	monkeypatch.setattr(rv, 'decrement_stepper', wrap)
	open(os.path.join(job.monitor, 'a.txt'), 'w').write('hello2')
	entries = OrderedDict([
		(os.path.join(job.monitor, 'a.txt'), rv.BackupEntryValues('t', 'modify', None)),
	])
	rv.do_backup(
		entries, job_name=job.job_name, monitor_path=job.monitor, vault_path=job.vault,
		keep_one_complete_backup=True, only_sync_attributes=True,
		keep_n_versions=0, backup_size_limit='i1',
		vaultInfo=rv.get_vault_info(job.job_vault),
		trackingFilesFolders=rv.TrackingFilesFolders(['a.txt'], []),
	)
	assert called
```

Empty/single-version `decrement_stepper` stays doctest-only. Success/abort stay in `test_crash_safety.py`.

- [ ] **Step 2: Run tests**

Run: `uv run --extra test pytest tests/test_retention.py -v`  
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add tests/test_retention.py
git commit -m "$(cat <<'EOF'
Add keep-N and size-limit retention tests.

EOF
)"
```

---

### Task 12: Live inotify tests

**Files:**
- Create: `tests/test_inotify.py`

**Interfaces:**
- Consumes: `rv.watchFolder`, `rv.inotify_resource_manager`, `poll_fast`, `job`, `wait_until`
- Produces: real kernel watches; `pytestmark = inotify`; `min_snapshot_delay_seconds=0`

Init-failure and fake UNMOUNT stay in `test_crash_safety.py`.

- [ ] **Step 1: Write tests**

```python
import os
import threading
from collections import deque
import pytest
import reverberator as rv
from tests.harness import wait_until

pytestmark = pytest.mark.inotify


def _start_watch(job, to_process, to_process_flag):
	lock = threading.Lock()
	irm = rv.inotify_resource_manager()
	thread = threading.Thread(
		target=rv.watchFolder,
		kwargs=dict(
			monitor_path=job.monitor,
			to_process=to_process,
			to_process_lock=lock,
			to_process_flag=to_process_flag,
			irm=irm,
			min_snapshot_delay_seconds=0,
			max_shapshot_delay_seconds=60,
		),
		daemon=True,
	)
	thread.start()
	return thread, lock


def _events(to_process, lock):
	with lock:
		return list(to_process)


def test_file_create_modify_delete_attrib(job, poll_fast):
	to_process = deque()
	flag = threading.Event()
	thread, lock = _start_watch(job, to_process, flag)
	try:
		path = os.path.join(job.monitor, 'f.txt')
		open(path, 'w').write('a')
		wait_until(lambda: any(e.event == 'create' and e.path.endswith('f.txt') for e in _events(to_process, lock)), message='no create')
		open(path, 'w').write('ab')
		wait_until(lambda: any(e.event == 'modify' and e.path.endswith('f.txt') for e in _events(to_process, lock)), message='no modify')
		os.chmod(path, 0o600)
		wait_until(lambda: any(e.event == 'attrib' and e.path.endswith('f.txt') for e in _events(to_process, lock)), message='no attrib')
		os.remove(path)
		wait_until(lambda: any(e.event == 'delete' and e.path.endswith('f.txt') for e in _events(to_process, lock)), message='no delete')
	finally:
		rv.GREEN_LIGHT.clear()
		thread.join(timeout=2)
		rv.GREEN_LIGHT.set()


def test_file_rename_move_or_equivalent(job, poll_fast):
	open(os.path.join(job.monitor, 'a.txt'), 'w').write('x')
	to_process = deque()
	flag = threading.Event()
	thread, lock = _start_watch(job, to_process, flag)
	try:
		os.rename(os.path.join(job.monitor, 'a.txt'), os.path.join(job.monitor, 'b.txt'))
		def ok():
			evs = _events(to_process, lock)
			moves = [e for e in evs if e.event == 'move' and e.path.endswith('b.txt')]
			if moves and moves[0].moved_from and moves[0].moved_from.endswith('a.txt'):
				return True
			creates = [e for e in evs if e.event == 'create' and e.path.endswith('b.txt')]
			deletes = [e for e in evs if e.event == 'delete' and e.path.endswith('a.txt')]
			return bool(creates or deletes)
		wait_until(ok, message='rename produced neither move nor delete+create')
	finally:
		rv.GREEN_LIGHT.clear()
		thread.join(timeout=2)
		rv.GREEN_LIGHT.set()


def test_mkdir_p_watches_child_create(job, poll_fast):
	to_process = deque()
	flag = threading.Event()
	thread, lock = _start_watch(job, to_process, flag)
	try:
		nested = os.path.join(job.monitor, 'd', 'e')
		os.makedirs(nested)
		child = os.path.join(nested, 'z.txt')
		open(child, 'w').write('z')
		wait_until(
			lambda: any(e.event == 'create' and e.path.endswith('z.txt') for e in _events(to_process, lock)),
			message='child create not seen under mkdir -p',
		)
	finally:
		rv.GREEN_LIGHT.clear()
		thread.join(timeout=2)
		rv.GREEN_LIGHT.set()


def test_queue_overflow_full_scan_or_skip(job, poll_fast):
	to_process = deque()
	flag = threading.Event()
	thread, lock = _start_watch(job, to_process, flag)
	try:
		for i in range(20000):
			open(os.path.join(job.monitor, f'f{i}.txt'), 'w').write('x')
		evs = _events(to_process, lock)
		if not any(e.event == 'full_scan' for e in evs):
			pytest.skip('could not fill inotify queue on this kernel')
	finally:
		rv.GREEN_LIGHT.clear()
		thread.join(timeout=5)
		rv.GREEN_LIGHT.set()
```

- [ ] **Step 2: Run tests**

Run: `uv run --extra test pytest tests/test_inotify.py -v`  
Expected: create/modify/delete/attrib, rename, mkdir-p PASS; overflow SKIP or PASS.

- [ ] **Step 3: Commit**

```bash
git add tests/test_inotify.py
git commit -m "$(cat <<'EOF'
Add live inotify watcher tests.

EOF
)"
```

---

### Task 13: Process-level CLI tests

**Files:**
- Create: `tests/test_process.py`

**Interfaces:**
- Consumes: `run_reverberator`, `write_rule`, `seed_monitor`, `wait_for_committed_count`, `write_incomplete_version`, `write_pending`, `process_env`
- Produces: `pytestmark = process`; SIGTERM once; 10s waits; `--no_log` and temp `-ld` already in fixture

- [ ] **Step 1: Write tests**

```python
import os
import signal
import pytest
import reverberator as rv
from tests.harness import (
	write_rule, seed_monitor, wait_for_committed_count, committed_versions,
	write_incomplete_version, write_pending, wait_until,
)

pytestmark = pytest.mark.process


def test_drop_sample_writes_file_and_exits(job, run_reverberator):
	rule = write_rule(job)
	os.remove(rule)
	proc = run_reverberator(job.rule_path, extra_args=('--drop_sample_reverb_rule_file',))
	assert proc.wait(timeout=10) == 0
	text = open(job.rule_path, encoding='utf-8').read()
	assert 'Job Name (Unique Key)' in text
	assert 'Incomplete V*' in text


def test_start_creates_v0(job, run_reverberator):
	seed_monitor(job, {'a.txt': 'hello'})
	write_rule(job)
	run_reverberator(job.rule_path)
	versions = wait_for_committed_count(job, 1, timeout=10)
	assert os.path.isfile(os.path.join(versions[0], 'a.txt'))


def test_file_write_creates_second_version(job, run_reverberator):
	seed_monitor(job, {'a.txt': 'hello'})
	write_rule(job)
	run_reverberator(job.rule_path)
	wait_for_committed_count(job, 1, timeout=10)
	open(os.path.join(job.monitor, 'b.txt'), 'w').write('new')
	versions = wait_for_committed_count(job, 2, timeout=10)
	assert any(os.path.isfile(os.path.join(v, 'b.txt')) for v in versions)


def test_sigterm_does_not_commit_incomplete(job, run_reverberator):
	seed_monitor(job, {'a.txt': 'hello'})
	write_rule(job)
	proc = run_reverberator(job.rule_path)
	wait_for_committed_count(job, 1, timeout=10)
	open(os.path.join(job.monitor, 'c.txt'), 'w').write('c')
	proc.send_signal(signal.SIGTERM)
	proc.wait(timeout=5)
	for name in os.listdir(job.job_vault) if os.path.isdir(job.job_vault) else []:
		if not name.startswith('V'):
			continue
		path = os.path.join(job.job_vault, name)
		if os.path.isdir(path) and rv.CONTENT_FILE_EXTENSION_NAME not in name:
			from tests.harness import content_file_path
			if not os.path.isfile(content_file_path(path)):
				link = os.path.join(job.job_vault, 'current_version')
				if os.path.lexists(link):
					assert os.path.basename(os.path.realpath(link)) != name


def test_restart_deletes_incomplete_keeps_committed(job, run_reverberator):
	seed_monitor(job, {'a.txt': 'hello'})
	write_rule(job)
	proc = run_reverberator(job.rule_path)
	wait_for_committed_count(job, 1, timeout=10)
	proc.send_signal(signal.SIGTERM)
	proc.wait(timeout=5)
	orphan = write_incomplete_version(job, 99, {'junk': 'x'}, timestamp='2021-12-31_00-00-00_-0800')
	run_reverberator(job.rule_path)
	wait_until(lambda: not os.path.isdir(orphan), timeout=10, message='incomplete V99 not removed')
	assert len(committed_versions(job)) >= 1


def test_pending_resume_and_discard(job, run_reverberator):
	seed_monitor(job, {'a.txt': 'hello'})
	write_rule(job)
	a = os.path.join(job.monitor, 'a.txt')
	os.makedirs(job.job_vault, exist_ok=True)
	pending = write_pending(job, [rv.ChangeEvent(1.0, False, 'modify', a, None)])
	os.utime(job.monitor, (1000, 1000))
	os.utime(a, (1000, 1000))
	os.utime(pending, (2000, 2000))
	run_reverberator(job.rule_path)
	wait_for_committed_count(job, 1, timeout=10)
	wait_until(lambda: not os.path.exists(pending), timeout=10, message='pending file not consumed')
```

`--drop_sample_reverb_rule_file` argparse dest may be `drop_sample_reverb_rule_file`. Extra_args must be the CLI flag string from `get_args`: `'--drop_sample_reverb_rule_file'`.

If `test_pending_resume_and_discard` races with V0 (empty vault always creates V0), that is enough to prove startup ran `load_pending`; keep the pending-file-consumed assertion. A second test that writes pending **after** V0 exists is optional; if added, SIGTERM the first process, write pending + utime, start again.

- [ ] **Step 2: Run tests**

Run: `uv run --extra test pytest tests/test_process.py -v`  
Expected: PASS within ~10s per wait. On timeout, fail with stdout/stderr:

After a failed `wait_for_committed_count`, read `proc.stdout` / `proc.stderr` if still captured. Extend `run_reverberator` only if needed to stash `communicate` after exit; do not hang.

- [ ] **Step 3: Commit**

```bash
git add tests/test_process.py tests/conftest.py tests/harness.py
git commit -m "$(cat <<'EOF'
Add process-level reverberator CLI tests.

EOF
)"
```

---

### Task 14: Privileged unmount tests and `docTest.sh`

**Files:**
- Create: `tests/test_privileged.py`
- Modify: `docTest.sh`

**Interfaces:**
- Consumes: `rv.watchFolder`, bind-mount via `mount --bind`
- Produces: skip unless root or `REVERB_PRIVILEGED=1`; unmount must not delete vault history as a recursive delete

- [ ] **Step 1: Write privileged tests + wrapper**

`tests/test_privileged.py`:

```python
import os
import subprocess
import threading
from collections import deque
import pytest
import reverberator as rv
from tests.harness import write_committed_version, wait_until, committed_versions

pytestmark = [
	pytest.mark.privileged,
	pytest.mark.skipif(
		os.geteuid() != 0 and os.environ.get('REVERB_PRIVILEGED') != '1',
		reason='requires root or REVERB_PRIVILEGED=1',
	),
]


def test_unmount_self_destruct_does_not_delete_vault(job, poll_fast, tmp_path):
	real = str(tmp_path / 'real_mon')
	os.makedirs(real)
	open(os.path.join(real, 'a.txt'), 'w').write('keep')
	subprocess.check_call(['mount', '--bind', real, job.monitor])
	try:
		v0 = write_committed_version(job, 0, {'a.txt': 'keep'})
		to_process = deque()
		lock = threading.Lock()
		flag = threading.Event()
		irm = rv.inotify_resource_manager()
		result = []

		def run():
			result.append(rv.watchFolder(
				monitor_path=job.monitor,
				to_process=to_process,
				to_process_lock=lock,
				to_process_flag=flag,
				irm=irm,
				min_snapshot_delay_seconds=0,
				max_shapshot_delay_seconds=60,
			))

		t = threading.Thread(target=run, daemon=True)
		t.start()
		wait_until(lambda: t.is_alive(), timeout=2, message='watcher did not start')
		subprocess.check_call(['umount', job.monitor])
		t.join(timeout=5)
		assert result == [rv.WATCH_RESULT_SELF_DESTRUCT]
		assert os.path.isdir(v0)
		assert committed_versions(job) == [v0]
		with lock:
			assert any(e.event == 'self_destruct' for e in to_process)
	finally:
		rv.GREEN_LIGHT.clear()
		subprocess.call(['umount', job.monitor])
		rv.GREEN_LIGHT.set()
```

Replace `docTest.sh` with:

```bash
#!/bin/bash
uv run --extra test pytest
```

Keep it executable (`chmod +x docTest.sh`).

- [ ] **Step 2: Run tests**

Run: `uv run --extra test pytest tests/test_privileged.py -v`  
Expected: SKIP when not root and `REVERB_PRIVILEGED` unset.

Run as root or with `REVERB_PRIVILEGED=1` only on a machine where bind-mount works. Expected: PASS. If `watchFolder` returns `'self_destruct'` vs `WATCH_RESULT_SELF_DESTRUCT`, assert the constant already defined in `reverberator.py` (`WATCH_RESULT_SELF_DESTRUCT = 'self_destruct'`).

Run: `uv run --extra test pytest -m unit -q`  
Expected: unit tests PASS.

Run: `uv run --extra test pytest -q`  
Expected: unprivileged suite PASS; privileged SKIP; doctests collected.

- [ ] **Step 3: Commit**

```bash
git add tests/test_privileged.py docTest.sh
git commit -m "$(cat <<'EOF'
Add optional privileged unmount tests and pytest docTest wrapper.

EOF
)"
```

---

## Self-review (plan vs spec)

| Spec section | Task |
|--------------|------|
| Architecture, markers, pyproject, doctest collection | 1, 3, 14 |
| `POLL_WAIT_SECONDS` / env / all hardcoded `3` wait sites | 1 |
| GREEN_LIGHT autouse restore | 1–2 |
| Harness `JobPaths`, rule TSV, committed/incomplete/pending, wait | 2 |
| Existing tests kept + `unit` marker | 3 |
| Helpers/CLI (no duplicate strip_*; drop-sample e2e in process) | 4, 13 |
| `parse_rules` | 5 |
| Event coalescing branches | 6 |
| Vault scan / content file | 7 |
| Pending mtime gate via `os.utime` | 8 |
| V0 complete vs referenced, reverb events, journal, rename fallback | 9 |
| Delta | 10 |
| keep N / size / inode; stepper abort stays crash-safety | 11 |
| Live inotify; overflow skip | 12 |
| Process CLI, SIGTERM, restart incomplete cleanup, drop-sample | 13 |
| Privileged skip gate; `docTest.sh` wrapper | 14 |
| No pytest-cov, no pytest-timeout, no INotify factory, no repo rule file | all |

No TBD/TODO placeholders. Types: `JobPaths` namedtuple fields and helper signatures are defined in Task 2 and reused by name in later tasks.
