'''
Real 0.54 vaults for the tests of the migration: the session fixture v054 loads reverberator.py as tagged v0.54.1 from git, under
the name reverberator054, and v054.build(job, batches) runs that module's own do_backup, so the format is exact and no
hand-written vault can drift from it. A tag, as history gets rewritten and every hash changes. It skips with a reason when
the tag is gone.

The module is a second copy of the daemon: what isolated_runtime() patches on rv does not reach it, above all
sync_vault_filesystems, and a real syncfs would flush the live filesystem under /tmp. So the stub goes on at load, and what
isolated_runtime() patches for one test goes on at each build.
'''
import importlib.util
import os
import subprocess
import sys
import time
from collections import deque, OrderedDict

import pytest

import reverberator as rv
from tests.crash_batches import OPTIONS
from tests.crash_child import failing_copy_command

TAG = 'v0.54.1'
MODULE_NAME = 'reverberator054'
# what isolated_runtime() clears on rv between tests, as far as 0.54.1 has it
# what the fake_pool fixture patches on rv: a fake pool must show to this module too, as to a daemon on that vault
POOL_SEAM = ('MOUNTINFO_PATH', 'FS_SIGNATURE_MONITOR', 'read_pool_branches', 'statx_mount', 'F2FS_SYSFS_PATH', 'SYS_DEV_BLOCK_PATH', 'F2FS_UNTOLD', 'POOL_CHECK_SECONDS')
REMEMBERED = ('VERSION_MOVES', 'VERSION_MOVES_WARNED', 'PRUNE_ABORTED', 'PRUNE_SALT_MISSING', 'VAULTS_WITH_VERSIONS', 'UNRECORDED_FAILED_DISKS', 'JOB_LOCK_UNCHECKED')


def refused_syncfs(path):
	raise AssertionError(f'a real syncfs of {path} from the 0.54 module of the tests')


def load_module(folder: str):
	'''The module of TAG, written into folder and imported, its flushes stubbed before anything can call them. None when git has no such tag.'''
	source = subprocess.run(['git', '-C', os.path.dirname(os.path.abspath(rv.__file__)), 'show', f'{TAG}:reverberator.py'], capture_output=True)
	if source.returncode != 0:
		return None
	path = os.path.join(folder, f'{MODULE_NAME}.py')
	with open(path, 'wb') as f:
		f.write(source.stdout)
	spec = importlib.util.spec_from_file_location(MODULE_NAME, path)
	module = importlib.util.module_from_spec(spec)
	sys.modules[MODULE_NAME] = module
	spec.loader.exec_module(module)
	module.sync_vault_filesystems = lambda job_vault: {}
	module.syncfs_folder = refused_syncfs
	# a test's pytest.raises(rv.JobFailure) catches this module's failures too
	for name in ('JobFailure', 'VaultScanError', 'PoolNotReady'):
		setattr(module, name, getattr(rv, name))
	return module


class Legacy054:
	def __init__(self, module):
		self.module = module
		self.real_copy_command = module.copy_command
		self.own = {name: getattr(module, name) for name in POOL_SEAM}

	def isolate(self) -> None:
		'''The module as isolated_runtime() leaves rv for this test: the environment and multiCMD it shares with rv, the rest set here.'''
		module = self.module
		module.GREEN_LIGHT.set()
		for name in REMEMBERED:
			getattr(module, name).clear()
		module.RESTORE_STOP.clear()
		module.FSTAB_PATH = rv.FSTAB_PATH
		module.POLL_WAIT_SECONDS = rv.POLL_WAIT_SECONDS
		module.STATUS_BOARD = None
		module.copy_command = failing_copy_command(self.real_copy_command)
		faked = rv.MOUNTINFO_PATH != self.own['MOUNTINFO_PATH']
		for name in POOL_SEAM:
			setattr(module, name, getattr(rv, name) if faked else self.own[name])

	def stop_monitor(self) -> None:
		'''End the thread of the module's fs signature monitor, as stop_fs_signature_monitor() does for rv.'''
		monitor = self.own['FS_SIGNATURE_MONITOR']
		with monitor.lock:
			thread = monitor.thread
		if thread is not None and thread.is_alive():
			self.module.GREEN_LIGHT.clear()
			monitor.wake()
			thread.join(timeout=10)
			assert not thread.is_alive(), 'the fs signature monitor of the 0.54 module did not stop'
		self.module.GREEN_LIGHT.set()

	def run(self, job, entries, **kwargs) -> None:
		kwargs.setdefault('matched_since', time.time_ns())
		_, manifest, committed = self.module.do_backup(entries, job_name=job.job_name, monitor_path=job.monitor, vault_path=job.vault, **kwargs)
		manifest.close()
		assert committed is True

	def backup(self, job, entries=None, **options) -> None:
		'''One committed backup of entries, as harness.run_backup() runs one on rv, with its options: empty entries compare the whole tree.'''
		self.isolate()
		try:
			self.run(job, OrderedDict() if entries is None else entries, **{**dict(keep_one_complete_backup=True, only_sync_attributes=True, keep_n_versions=0, backup_size_limit='0'), **options})
		finally:
			self.stop_monitor()

	def build(self, job, batches, **options) -> None:
		'''
		A 0.54 vault in job: each of batches, a function of the monitored folder, changes that folder, and the first version is backed
		up whole. Any other gives the events of its change, as (is_dir, event, rel, moved_from rel or None), run as the backuper runs
		a fresh batch. options go over OPTIONS. A name ending UNREADABLE cannot be read, as in the crash child.
		'''
		module = self.module
		self.isolate()
		options = {**OPTIONS, **options}
		os.makedirs(job.job_vault, exist_ok=True)
		try:
			batches[0](job.monitor)
			self.run(job, OrderedDict(), **options)
			for change in batches[1:]:
				events = change(job.monitor)
				raw = deque(module.ChangeEvent(float(i), is_dir, event, os.path.join(job.monitor, rel), None if source is None else os.path.join(job.monitor, source))
					for i, (is_dir, event, rel, source) in enumerate(events, 1))
				self.run(job, module.change_events_to_backup_entries(deque(raw), job.monitor), touched=module.touched_scopes(raw, job.monitor), **options)
		finally:
			self.stop_monitor()


@pytest.fixture(scope='session')
def v054(tmp_path_factory):
	module = load_module(str(tmp_path_factory.mktemp('legacy054')))
	if module is None:
		pytest.skip(f'git has no {TAG}, the tag the 0.54 vaults are built by')
	yield Legacy054(module)
	sys.modules.pop(MODULE_NAME, None)


