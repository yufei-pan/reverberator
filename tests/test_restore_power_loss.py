'''
0.55.2: a restore's sync against a real power loss, behind REVERB_SCRATCH: the restore writes onto a fresh f2fs loop image with
the live disks' features and mount options, the filesystem stops with no checkpoint (f2fs_io shutdown 2), and is mounted again.
A restore that returned holds every file whole and no marker; one cut after its copies and before its sync leaves its marker,
which says its copies are not known to be on disk, and the same restore run again copies everything again and finishes it. One
stopped by a signal after its copies writes them out on its way out: the cut after loses none of them, and the same restore run
again keeps them. The control shows the cut loses what no sync wrote out.

The real syncfs(2) binding runs here only around the restore, whose syncs reach the loop image alone (its target is on it). The
shutdown and the flush go through tests/scratch_images.py, which refuses anything but a loop image this process attached under
REVERB_SCRATCH.
'''
import os
import signal

import pytest

import reverberator as rv
from tests.conftest import REAL_LIBC_SYNCFS
from tests.harness import create_job, run_backup, seed_monitor, write_rule
from tests.scratch_images import flush_scratch, LoopImage, needs_f2fs, SCRATCH, shut_down_scratch

pytestmark = needs_f2fs

# the loop image: a sparse file, so what the restore writes is all it takes
IMAGE_MIB = 256
# files past f2fs's inline size (about 3.4 KB), each of its own bytes, so a file the cut empties or cuts short shows
FILES = {f'proj/{folder}f{i}': os.urandom(64 << 10 << (i % 4)) for i, folder in enumerate(('', 'sub/', 'sub/', 'deep/er/', ''))}


@pytest.fixture(autouse=True)
def _fast(poll_fast):
	return poll_fast


@pytest.fixture
def backed_up(tmp_path):
	job = create_job(str(tmp_path / 'side'))
	for rel, data in FILES.items():
		path = os.path.join(job.monitor, rel)
		os.makedirs(os.path.dirname(path), exist_ok=True)
		with open(path, 'wb') as f:
			f.write(data)
	run_backup(job)
	write_rule(job)
	return job


@pytest.fixture
def image():
	with LoopImage(os.path.join(SCRATCH, 'restore-power-loss'), IMAGE_MIB) as image:
		yield image


def restore(job, dest, monkeypatch):
	'''The restore of proj into dest, with the real binding: its syncs reach the loop image dest is on.'''
	with monkeypatch.context() as real:
		real.setattr(rv, 'LIBC_SYNCFS', REAL_LIBC_SYNCFS)
		return rv.run_command(['restore', f'{job.monitor}/proj', dest, '--version', '0', '--rule', job.rule_path, '--state_dir', os.path.join(job.root, 'state')])


def destination(image):
	dest = os.path.join(image.mount_point, 'out')
	os.mkdir(dest)
	# the folder to restore into is on the disk before the restore begins
	flush_scratch(dest)
	return dest


def lost(dest):
	'''The files of FILES that are not there whole with their bytes in dest's proj.'''
	missing = []
	for rel, data in FILES.items():
		try:
			with open(os.path.join(dest, rel), 'rb') as f:
				if f.read() != data:
					missing.append(rel)
		except OSError:
			missing.append(rel)
	return missing


def test_a_restore_that_returned_survives_a_power_loss(backed_up, image, monkeypatch):
	dest = destination(image)
	assert restore(backed_up, dest, monkeypatch) == 0
	shut_down_scratch(image.mount_point)
	image.remount()
	assert lost(dest) == []
	assert not os.path.lexists(os.path.join(dest, 'proj', rv.RESTORE_MARKER_NAME))


def test_without_its_sync_a_restore_loses_files_at_a_power_loss(backed_up, image, monkeypatch):
	# the control: with no sync of the target, the same cut loses what the restore wrote, so the test above can see a missing sync
	dest = destination(image)
	monkeypatch.setattr(rv, 'sync_restore', lambda *args, **kwargs: True)
	assert restore(backed_up, dest, monkeypatch) == 0
	shut_down_scratch(image.mount_point)
	image.remount()
	assert lost(dest), 'the cut lost nothing that no sync wrote out: this image cannot show a missing sync'


def test_a_cut_before_the_first_sync_leaves_the_marker_and_a_run_again_finishes(backed_up, image, monkeypatch):
	dest = destination(image)
	target = os.path.join(dest, 'proj')
	sync_restore = rv.sync_restore
	cut = []

	def cutting(disks, folder, report, rel, **kwargs):
		# the power goes after the copies, before their sync
		if not cut:
			cut.append(folder)
			shut_down_scratch(image.mount_point)
		return sync_restore(disks, folder, report, rel, **kwargs)
	monkeypatch.setattr(rv, 'sync_restore', cutting)
	assert restore(backed_up, dest, monkeypatch) == rv.EXIT_COMMAND_FAILED
	assert cut == [target]
	monkeypatch.setattr(rv, 'sync_restore', sync_restore)
	image.remount()
	# the marker was on the disk before the first copy, saying its copies are not known to be on disk, so a run again copies
	# everything again
	marker = rv.read_restore_marker(target)
	assert 'unsynced' in marker and rv.marker_recopy(marker) == 'cut'
	copied = []
	copy_command = rv.copy_command
	monkeypatch.setattr(rv, 'copy_command', lambda source, dest_path: copied.append(source) or copy_command(source, dest_path))
	assert restore(backed_up, dest, monkeypatch) == 0
	# everything copied again, whatever the cut left of it
	assert len(copied) == len(FILES)
	shut_down_scratch(image.mount_point)
	image.remount()
	assert lost(dest) == []
	assert not os.path.lexists(os.path.join(target, rv.RESTORE_MARKER_NAME))


def test_a_restore_stopped_after_its_copies_writes_them_out_and_a_run_again_keeps_them(backed_up, image, monkeypatch):
	dest = destination(image)
	target = os.path.join(dest, 'proj')
	copy_command = rv.copy_command
	started = []

	def stopping(source, dest_path):
		# a Ctrl-C as the third copy starts, once the first two are in place
		started.append(source)
		if len(started) == 3:
			os.kill(os.getpid(), signal.SIGINT)
		return copy_command(source, dest_path)
	with monkeypatch.context() as stopped:
		stopped.setattr(rv, 'RESTORE_COPY_BATCH', 2)
		stopped.setattr(rv, 'copy_command', stopping)
		assert restore(backed_up, dest, monkeypatch) == rv.EXIT_COMMAND_FAILED
	kept = sorted(rel for rel in FILES if os.path.lexists(os.path.join(dest, rel)))
	assert len(kept) == 2
	# the power goes right after the stop: what it restored was written out on its way out, and its marker says so
	shut_down_scratch(image.mount_point)
	image.remount()
	assert sorted(set(FILES) - set(lost(dest))) == kept
	marker = rv.read_restore_marker(target)
	assert marker is not None and rv.marker_recopy(marker) is None
	copied = []
	monkeypatch.setattr(rv, 'copy_command', lambda source, dest_path: copied.append(source) or copy_command(source, dest_path))
	assert restore(backed_up, dest, monkeypatch) == 0
	# the run again keeps them and copies the rest
	assert len(copied) == len(FILES) - len(kept)
	shut_down_scratch(image.mount_point)
	image.remount()
	assert lost(dest) == []
	assert not os.path.lexists(os.path.join(target, rv.RESTORE_MARKER_NAME))
