'''
Round 20: a read of an older version while a batch records under it (spec section 4.2). The batch runs in a forked child and
makes one change of the vault each time the reader is about to look at something; the reader reads every file and link of
versions 1 and 2, from each starting point of the batch. Every read must be what the version held, read by the oracle before
the batch: the reader holds no lock the batch needs, so only the recheck of the links it followed can give that. The second
test takes the recheck away, to show this one can fail.

REVERB_CRASH_FULL=1 starts at every change of the batch; by default a stride of them.
'''
import os
import select
import shutil
import tempfile
import threading
import time

import pytest

import reverberator as rv
from tests import vault_oracle
from tests.crash_batches import batch3_of, prepare, restore
from tests.crash_child import KillPoints, in_child, kill_run, run_do_backup
from tests.vault_oracle import entry_view

pytestmark = pytest.mark.skipif(os.geteuid() != 0, reason='the root record is a trusted.* attribute, and a file is chowned')

DEFAULT_STARTS = 30
# how long a read of the pipe may wait for the batch: past it, the child is stuck
STEP_SECONDS = 120
PREPARED = {}


@pytest.fixture
def crash_vault(r_layout, tmp_path_factory):
	'''The crash vault on design R, as batch 2 left it. Outside tmp_path, whose vaults the ground truth plugins read: they see no fork's links.'''
	if 'vault' not in PREPARED:
		place = os.environ.get('REVERB_CRASH_ROOT')
		root = tempfile.mkdtemp(prefix='reverb-recheck-', dir=place) if place else str(tmp_path_factory.mktemp('recheck'))
		PREPARED['vault'] = prepare(root, only_sync_attributes=False)
		PREPARED['root'] = root
	restore(PREPARED['vault'])
	return PREPARED['vault']


@pytest.fixture(scope='module', autouse=True)
def remove_the_root():
	yield
	if os.environ.get('REVERB_CRASH_ROOT') and 'root' in PREPARED:
		shutil.rmtree(PREPARED['root'])
	PREPARED.clear()


class Lockstep:
	'''
	The batch in its child, one change of the vault at a time: the child stops before each change, and advance() lets it make
	that one. finished once the batch ended. The reader is this process; the child is forked by a thread, as in_child() waits for
	it, so nothing patched here (after start()) reaches it.
	'''
	def __init__(self, job):
		self.job = job
		self.go_read, self.go_write = os.pipe()
		self.stop_read, self.stop_write = os.pipe()
		self.finished = False
		self.outcome = None
		self.thread = threading.Thread(target=self.run)

	def stop_at_each_change(self, module):
		lockstep = self
		def step(points, kind):
			with points.lock:
				points.counts[kind] += 1
				os.write(lockstep.stop_write, b's')
				os.read(lockstep.go_read, 1)
		KillPoints.step = step

	def run(self):
		def work():
			try:
				entries, touched = batch3_of(self.job)
				return run_do_backup(self.job, entries, touched=touched, matched_since=time.time_ns(), options={'only_sync_attributes': False})
			finally:
				os.write(self.stop_write, b'e')
		self.outcome = in_child(self.job, None, work, self.stop_at_each_change)

	def wait(self):
		ready, _, _ = select.select([self.stop_read], [], [], STEP_SECONDS)
		assert ready, 'the batch made no step'
		if os.read(self.stop_read, 1) == b'e':
			self.finished = True

	def start(self):
		self.thread.start()
		self.wait()

	def advance(self):
		if not self.finished:
			os.write(self.go_write, b'g')
			self.wait()

	def end(self):
		while not self.finished:
			self.advance()
		self.thread.join()
		for fd in (self.go_read, self.go_write, self.stop_read, self.stop_write):
			os.close(fd)
		assert self.outcome.error is None, self.outcome.error
		assert self.outcome.committed is True


def wrong_reads(vault, offset, monkeypatch) -> list:
	'''The reads of versions 1 and 2 that differ from the oracle, the batch started offset changes before the first.'''
	restore(vault)
	lockstep = Lockstep(vault.job)
	lockstep.start()
	for _ in range(offset):
		lockstep.advance()
	wrong = []
	real_lstat, real_readlink, real_sha = os.lstat, os.readlink, vault_oracle.sha256_of
	def stepping(real):
		def call(*args, **kwargs):
			lockstep.advance()
			return real(*args, **kwargs)
		return call
	def read(walked):
		return None if walked.kind in ('missing', 'dangling') else entry_view(walked.path)
	try:
		with monkeypatch.context() as patched:
			patched.setattr(os, 'lstat', stepping(real_lstat))
			patched.setattr(os, 'readlink', stepping(real_readlink))
			patched.setattr(vault_oracle, 'sha256_of', stepping(real_sha))
			for number in (1, 2):
				for rel, want in sorted(vault.base[number].items()):
					if want.kind not in ('f', 'l'):
						continue
					try:
						got = rv.read_checked(vault.job.job_vault, number, rel, read, backward=False)
					except OSError as e:
						wrong.append((number, rel, e, want))
						continue
					if want.kind == 'l':
						# a link's own time and owner are not what a version promises
						same = got is not None and (got.kind, got.data) == (want.kind, want.data)
					else:
						same = got == want
					if not same:
						wrong.append((number, rel, got, want))
	finally:
		# a failed read must not leave the child stopped at a change, or the run waits for it for ever
		lockstep.end()
	return wrong


def batch_changes(vault) -> int:
	'''How many changes of the vault the batch makes.'''
	restore(vault)
	total = kill_run(vault.job).steps
	assert total > 100
	return total


def starts(vault) -> list:
	'''Every starting point of the batch, one before each of its changes, or a stride of them.'''
	total = batch_changes(vault)
	every = list(range(total + 1))
	if os.environ.get('REVERB_CRASH_FULL'):
		return every
	return every[::max(1, total // DEFAULT_STARTS)]


def test_no_read_is_wrong_while_a_batch_runs(crash_vault, monkeypatch):
	wrong = {}
	points = starts(crash_vault)
	for offset in points:
		found = wrong_reads(crash_vault, offset, monkeypatch)
		if found:
			wrong[offset] = found
	print(f'recheck on: {len(points)} starts, {len(wrong)} with a wrong read')
	assert not wrong, (len(wrong), next(iter(wrong.items())))


def test_without_the_recheck_some_reads_are_wrong(crash_vault, monkeypatch):
	monkeypatch.setattr(rv, 'followed_unchanged', lambda followed: True)
	# few starts give a wrong read (9 of 330, measured), and a stride can pass them all: this one goes through them all, until
	# it finds one in a default run
	full = bool(os.environ.get('REVERB_CRASH_FULL'))
	wrong = runs = 0
	for offset in range(batch_changes(crash_vault) + 1):
		wrong += len(wrong_reads(crash_vault, offset, monkeypatch))
		runs += 1
		if wrong and not full:
			break
	print(f'recheck off: {runs} starts, {wrong} wrong reads')
	assert wrong > 0
