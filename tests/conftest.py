import os
import resource
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import pytest
import reverberator as rv
from tests import harness
from tests.harness import FakePool, create_job, reverberator_script

# the chain-link ground truth over the whole suite (REVERB_CHAIN_GROUND_TRUTH=0 turns it off), and what each committed version
# reads around every batch on design R (REVERB_VIEW_GROUND_TRUTH=0)
pytest_plugins = ['tests.chain_ground_truth', 'tests.version_view_ground_truth', 'tests.legacy054']

# the 0.54 code that stays for a later release: tests/legacy054.py builds their vaults, as the product's writer no longer does
STILL_054 = {
	'test_prune_power_loss.py', 'test_prune_threads.py', 'test_vault_chain_hop.py', 'test_vault_chain_hop_oracle.py', 'test_restore_pool.py',
	'test_chain_links.py',
}

# the real helper and binding, for the tests that run them: isolated_runtime() replaces them for every test. the real
# syncfs only ever on a scratch image's own mount (tests/scratch_images.py)
REAL_SYNC_VAULT_FILESYSTEMS = rv.sync_vault_filesystems
REAL_LIBC_SYNCFS = rv.LIBC_SYNCFS


def syncfs_stand_in(fd:int) -> int:
	'''The syncfs(2) binding without the syncfs: an fd that is not open raises, as the call would fail; else 0, done.'''
	os.fstat(fd)
	return 0


@pytest.fixture(autouse=True)
def restore_runtime_globals(request, tmp_path):
	# the isolation below has a monkeypatch of its own: a test's monkeypatch.undo() would otherwise drop it too
	with pytest.MonkeyPatch.context() as isolation:
		if request.node.get_closest_marker('on_054') is not None or request.path.name in STILL_054:
			isolation.setattr(harness, 'LEGACY', request.getfixturevalue('v054'))
		yield from isolated_runtime(tmp_path, isolation)


def isolated_runtime(tmp_path, monkeypatch):
	old_poll = rv.POLL_WAIT_SECONDS
	rv.GREEN_LIGHT.set()
	# a test may write a version's change list again after its moves were read
	rv.VERSION_MOVES.clear()
	rv.VERSION_MOVES_WARNED.clear()
	# a test's aborted prunes must not hold back another's FAILED marker
	rv.PRUNE_ABORTED.clear()
	# and a test's warning that pruning has no secret must not hold back another's
	rv.PRUNE_SALT_MISSING.clear()
	# and a test's vault seen with versions must not make a later scan of a new vault at that path fail
	rv.VAULTS_WITH_VERSIONS.clear()
	rv.RESTORE_STOP.clear()
	# and a test's lock that could not be checked must not hold back another's FAILED marker
	rv.JOB_LOCK_UNCHECKED.clear()
	# the daemon publishes status files: keep them out of /run/reverberator
	monkeypatch.setenv('REVERB_STATE_DIR', str(tmp_path / 'state'))
	# and never writes the host's sysctls: a sudo sysctl is answered as refused (a test that fakes run_command itself
	# replaces this)
	monkeypatch.setattr(rv.multiCMD, 'run_command', refuse_sudo_sysctl(rv.multiCMD.run_command))
	# a real syncfs would flush the whole (ext4) filesystem under /tmp for every comparison that checks a copy; tests that count
	# or fail syncs patch it themselves
	monkeypatch.setattr(rv, 'sync_vault_filesystems', lambda job_vault, job_name: {})
	# nor anything else: a restore syncs its target, and the filesystem under a basetemp can hold live trees. never a real
	# syncfs: the stand-in is the binding itself, so every function above it runs
	monkeypatch.setattr(rv, 'LIBC_SYNCFS', syncfs_stand_in)
	# and never reads the host's fstab: a missing file, which a test writes with write_fstab() when it means to
	monkeypatch.setattr(rv, 'FSTAB_PATH', str(tmp_path / 'fstab'))
	yield
	rv.STATUS_BOARD = None
	rv.POLL_WAIT_SECONDS = old_poll
	stop_fs_signature_monitor()
	rv.GREEN_LIGHT.set()


class RefusedTask:
	'''What multiCMD.run_command returns with return_object=True, for a command that was not run.'''
	def __init__(self):
		self.stdout = []
		self.stderr = ['the test suite never writes host sysctls']
		self.returncode = 1


def refuse_sudo_sysctl(run_command):
	def guarded(command, *args, **kwargs):
		if list(command[:2]) == ['sudo', 'sysctl']:
			return RefusedTask()
		return run_command(command, *args, **kwargs)
	return guarded


def stop_fs_signature_monitor():
	'''
	End the fs signature monitor's thread a test started: GREEN_LIGHT set again would keep it running into the next
	tests, whose memory measures would take in its passes over the mount table. A later register() starts it again.
	'''
	with rv.FS_SIGNATURE_MONITOR.lock:
		thread = rv.FS_SIGNATURE_MONITOR.thread
	if thread is None or not thread.is_alive():
		return
	rv.GREEN_LIGHT.clear()
	rv.FS_SIGNATURE_MONITOR.wake()
	thread.join(timeout=10)
	assert not thread.is_alive(), 'the fs signature monitor did not stop'


@pytest.fixture
def job(tmp_path):
	return create_job(str(tmp_path))


@pytest.fixture
def fake_pool(tmp_path, monkeypatch):
	'''
	mergerfs pools in a fake mount table that current_mount_table and a fresh shared monitor read, with a patched branch
	reader, statx and f2fs sysfs. Every pool check runs, as POOL_CHECK_SECONDS is 0.
	'''
	monitor = rv.fs_signature_monitor(mountinfo_path=str(tmp_path / 'fake_mountinfo'))
	pool = FakePool(tmp_path, monkeypatch, monitor)
	monkeypatch.setattr(rv, 'MOUNTINFO_PATH', pool.mountinfo_path)
	monkeypatch.setattr(rv, 'FS_SIGNATURE_MONITOR', monitor)
	monkeypatch.setattr(rv, 'read_pool_branches', pool.read)
	monkeypatch.setattr(rv, 'statx_mount', pool.statx_mount)
	monkeypatch.setattr(rv, 'F2FS_SYSFS_PATH', pool.f2fs_sysfs)
	monkeypatch.setattr(rv, 'SYS_DEV_BLOCK_PATH', pool.sys_dev_block)
	monkeypatch.setattr(rv, 'F2FS_UNTOLD', set())
	monkeypatch.setattr(rv, 'POOL_CHECK_SECONDS', 0)
	return pool


@pytest.fixture
def errseq(monkeypatch):
	'''
	The kernel's writeback error rule at the syncfs binding (tests/errseq.py), with the real vault sync helper above it: every
	vault sync of the test goes through the handles its unit opened, and fail() and seen_elsewhere() say what the kernel met.
	'''
	from tests.errseq import Errseq
	model = Errseq(monkeypatch)
	monkeypatch.setattr(rv, 'sync_vault_filesystems', REAL_SYNC_VAULT_FILESYSTEMS)
	return model


@pytest.fixture
def other_filesystem(tmp_path):
	'''A folder on a filesystem other than tmp_path's: in /dev/shm, a tmpfs. Removed at the end.'''
	if not os.path.isdir('/dev/shm') or os.stat('/dev/shm').st_dev == os.stat(str(tmp_path)).st_dev:
		pytest.skip('needs /dev/shm on a filesystem other than the basetemp\'s')
	folder = tempfile.mkdtemp(prefix='reverb-', dir='/dev/shm')
	yield folder
	shutil.rmtree(folder, ignore_errors=True)


@pytest.fixture
def poll_fast():
	rv.POLL_WAIT_SECONDS = 0.05
	return 0.05


@pytest.fixture
def process_env(tmp_path):
	env = os.environ.copy()
	env['REVERB_STATE_DIR'] = str(tmp_path / 'state')
	env['REVERB_POLL_WAIT_SECONDS'] = '0.05'
	env['PYTHONUNBUFFERED'] = '1'
	return env


@pytest.fixture
def run_reverberator(tmp_path, process_env):
	procs = []
	log_dir = str(tmp_path / 'proc_logs')
	os.makedirs(log_dir, exist_ok=True)

	def _drain(stream, buf):
		try:
			for line in iter(stream.readline, ''):
				buf.append(line)
		except Exception:
			pass

	def _run(rule_path, extra_args=()):
		p = subprocess.Popen(
			[sys.executable, reverberator_script(), '--no_log', '-ld', log_dir, *list(extra_args), str(rule_path)],
			env=process_env,
			stdout=subprocess.PIPE,
			stderr=subprocess.PIPE,
			text=True,
			# a byte that is not UTF-8 must show in the capture, not end the reading of it
			errors='surrogateescape',
		)
		p._out_buf = []
		p._err_buf = []
		p._drain_threads = (
			threading.Thread(target=_drain, args=(p.stdout, p._out_buf), daemon=True),
			threading.Thread(target=_drain, args=(p.stderr, p._err_buf), daemon=True),
		)
		for t in p._drain_threads:
			t.start()
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
		for t in getattr(p, '_drain_threads', ()):
			t.join(timeout=1)
		out = ''.join(getattr(p, '_out_buf', []))
		err = ''.join(getattr(p, '_err_buf', []))
		if out:
			print('--- reverberator stdout ---')
			print(out)
		if err:
			print('--- reverberator stderr ---')
			print(err)


def pytest_configure(config):
	config.addinivalue_line('markers', 'on_054: this test is of a vault on 0.54: run_backup() and the vaults it writes are the 0.54 daemon\'s (tests/legacy054.py)')
	# every process of the suite runs with the open file limit the daemon gives itself at start (soft raised to hard), so no
	# test depends on whether an earlier one in its worker built the daemon's limits: a 1,500 folder deep tree's rmtree
	# holds an fd per level, over the 1,024 a login shell starts with (2026-11-09, VM gate, EMFILE). The commands (status,
	# history, restore) raise no limit of their own: out of the suite they run with the one they are started with
	soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
	if soft < hard:
		resource.setrlimit(resource.RLIMIT_NOFILE, (hard, hard))


def pytest_collection_modifyitems(config, items):
	if sys.platform == 'linux':
		return
	skip = pytest.mark.skip(reason='inotify/process tests require Linux')
	for item in items:
		if item.get_closest_marker('inotify') or item.get_closest_marker('process'):
			item.add_marker(skip)
