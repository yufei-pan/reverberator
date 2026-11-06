'''
The power loss model of the crash runs (spec section 9), behind REVERB_SCRATCH: a fresh f2fs loop image with the live disks'
features and mount options; a child runs batch 3 and at step c the filesystem stops with no checkpoint (f2fs_io shutdown 2);
then umount, mount, the scan and a retry, and the oracle reads every version. A vault's comparisons flush the loop image for real
here, as a checked row means its bytes are on the disk.

The shutdown and the flush go through tests/scratch_images.py, which refuses anything but a loop image this process attached
under REVERB_SCRATCH: this host holds many live f2fs mounts, and a shutdown of one takes a production filesystem down.
REVERB_CRASH_FULL=1 runs every step; by default a stride.
'''
import os
import re
import sqlite3
import subprocess
import tempfile
from collections import Counter

import pytest

import reverberator as rv
from tests import scratch_images, version_view_ground_truth as view_truth
from tests.crash_batches import after_retries, prepare, restore
from tests.crash_child import kill_run, retry
from tests.scratch_images import flush_scratch, LoopImage, needs_f2fs, NotOurLoopImage, our_mount_point, SCRATCH, shut_down_scratch
from tests.test_crash_harness import kill_points
from tests.vault_oracle import check_vault, version_number

# the loop image of a run: a sparse file, so what the vault writes is all it takes of tmpfs
IMAGE_MIB = 512


def flushing_for_real(module):
	'''The vault's comparisons flush the loop image, through the one helper: a stub would record copies checked that a power loss loses.'''
	module.sync_vault_filesystems = lambda job_vault: (flush_scratch(job_vault), {})[1]


def recorded_version(job_vault):
	try:
		connection = sqlite3.connect(f'file:{os.path.join(job_vault, rv.MANIFEST_FILE_NAME)}?mode=ro', uri=True)
		try:
			row = connection.execute("SELECT value FROM meta WHERE key = 'version'").fetchone()
		finally:
			connection.close()
	except sqlite3.Error as e:
		return f'unreadable: {e}'
	return None if row is None else row[0]


def state_after(job_vault, old_list_of_2):
	'''What the remount left, in words: which of the commit's steps a power loss kept.'''
	names = os.listdir(job_vault)
	folders = {version_number(name): name for name in names if version_number(name) is not None}
	lists = {number: [name for name in names if rv.change_list_names(name, folder)] for number, folder in folders.items()}
	manifest_names_3 = (rv.vault_version_number(recorded_version(job_vault) or '') or 0) >= 3
	private = any(name.startswith(rv.CHANGE_LIST_FOLDER_PREFIX) for name in names)
	if 3 not in folders:
		return 'no version 3 folder; manifest names 3' if manifest_names_3 else ('V0 still there' if 0 in folders else 'V0 pruned, no version 3 folder')
	if not lists[3]:
		if manifest_names_3:
			held = 'list in its private folder' if private else 'list nowhere'
			return f'manifest names 3, {held}, previous list ' + ('under its old name' if old_list_of_2 in lists.get(2, ()) else 'renamed')
		return 'skeleton or tree of version 3, not committed' + (', a private list' if private else '')
	placed_old_name = old_list_of_2 in lists.get(2, ())
	return 'list of 3 placed, previous list under its old name' if placed_old_name else 'list of 3 placed, previous list renamed'


def test_the_helper_refuses_all_but_a_loop_image_of_this_test(tmp_path, monkeypatch):
	ran = []
	real_run = subprocess.run
	def recording(command, *args, **kwargs):
		ran.append(command[0])
		return real_run(command, *args, **kwargs)
	monkeypatch.setattr(scratch_images.subprocess, 'run', recording)
	monkeypatch.delenv('REVERB_SCRATCH', raising=False)
	for call in (flush_scratch, shut_down_scratch):
		with pytest.raises(NotOurLoopImage):
			call(str(tmp_path))
	monkeypatch.setenv('REVERB_SCRATCH', 'relative/path')
	with pytest.raises(NotOurLoopImage):
		our_mount_point(str(tmp_path))
	# outside the scratch folder, a live disk's path among them: not even looked at
	scratch = tmp_path / 'scratch'
	scratch.mkdir()
	monkeypatch.setenv('REVERB_SCRATCH', str(scratch))
	for path in ('/', '/mnt/pool_disks/254', '/mnt/fast2', str(tmp_path)):
		for call in (flush_scratch, shut_down_scratch):
			with pytest.raises(NotOurLoopImage):
				call(path)
	assert ran == []
	# under it, on the filesystem under tmp_path, which is no loop device: only findmnt runs
	for call in (flush_scratch, shut_down_scratch):
		with pytest.raises(NotOurLoopImage):
			call(str(scratch))
	assert set(ran) == {'findmnt'}


def test_the_helper_refuses_a_loop_device_of_someone_else(monkeypatch, tmp_path):
	# as findmnt answers for a path under the scratch folder: a loop device this test never attached, and one holding another image
	scratch = tmp_path / 'scratch'
	scratch.mkdir()
	monkeypatch.setenv('REVERB_SCRATCH', str(scratch))
	answers = {'findmnt': f'/dev/loop7 {scratch}/mnt\n', 'losetup': '/elsewhere/image\n'}
	ran = []
	def answering(command, *args, **kwargs):
		ran.append(command[0])
		return subprocess.CompletedProcess(command, 0, answers.get(command[0], ''), '')
	monkeypatch.setattr(scratch_images.subprocess, 'run', answering)
	monkeypatch.setattr(scratch_images, 'ATTACHED', {})
	with pytest.raises(NotOurLoopImage):
		shut_down_scratch(str(scratch))
	monkeypatch.setattr(scratch_images, 'ATTACHED', {'/dev/loop7': f'{scratch}/image'})
	with pytest.raises(NotOurLoopImage):
		shut_down_scratch(str(scratch))
	answers['findmnt'] = '/dev/nvme0n1 /mnt/fast2\n'
	with pytest.raises(NotOurLoopImage):
		flush_scratch(str(scratch))
	assert 'f2fs_io' not in ran and 'sync' not in ran


def test_no_test_calls_f2fs_io_or_syncfs_but_through_the_helper():
	tests = os.path.dirname(os.path.abspath(__file__))
	for name in sorted(os.listdir(tests)):
		if not name.endswith('.py') or name in ('scratch_images.py', os.path.basename(__file__)):
			continue
		with open(os.path.join(tests, name), encoding='utf-8') as f:
			text = f.read()
		assert not re.search(r"""['"]f2fs_io['"]|['"]sync['"],\s*['"]-f['"]""", text), name


@needs_f2fs
def test_the_helper_refuses_a_loop_image_it_did_not_attach():
	# mounted as the other tests mount it, by mount -o loop: not attached here
	with scratch_images.f2fs_mount(os.path.join(SCRATCH, 'unattached'), 64) as mount_point:
		with pytest.raises(NotOurLoopImage):
			shut_down_scratch(mount_point)
		with pytest.raises(NotOurLoopImage):
			flush_scratch(mount_point)
		# and it still works: nothing went down
		with open(os.path.join(mount_point, 'alive'), 'w') as f:
			f.write('alive')


@needs_f2fs
def test_the_helper_takes_only_while_attached():
	with LoopImage(os.path.join(SCRATCH, 'attached'), 64) as image:
		assert our_mount_point(image.mount_point) == os.path.realpath(image.mount_point)
		flush_scratch(image.mount_point)
		path = image.mount_point
	with pytest.raises(NotOurLoopImage):
		flush_scratch(path)


@pytest.fixture(params=[False, True], ids=['attributes_copied', 'only_sync_attributes'])
def only_sync(request):
	return request.param


def old_list_name(job_vault, number):
	folder = next(name for name in os.listdir(job_vault) if version_number(name) == number)
	return next(name for name in os.listdir(job_vault) if rv.change_list_names(name, folder))


def sweep(only_sync, tmp_name, flush_step=None):
	"""
	Batch 3 at each step, the power going there; a retry, and the oracle. flush_step(step) names the step before which the
	filesystem was last checkpointed, None to have none: with none, most steps only roll back to before the batch.
	"""
	options = {'only_sync_attributes': only_sync}
	with LoopImage(os.path.join(SCRATCH, tmp_name), IMAGE_MIB) as image:
		root = tempfile.mkdtemp(prefix='reverb-crash-', dir=image.mount_point)
		vault = prepare(root, **options)
		job = vault.job
		def fresh():
			restore(vault)
			flush_scratch(root)
			return old_list_name(job.job_vault, 2)
		fresh()
		total = kill_run(job, fault=flushing_for_real, options=options).steps
		assert total > 0
		wrong = []
		states = Counter()
		points = kill_points(total)
		for point in points:
			old_list = fresh()
			flush_at = None if flush_step is None else (flush_step(point), lambda: flush_scratch(root))
			cut = kill_run(job, point, fault=flushing_for_real, options=options, before_kill=lambda: shut_down_scratch(image.mount_point), flush_at=flush_at)
			if not cut.killed:
				# past the end: the power goes right after the batch
				shut_down_scratch(image.mount_point)
			image.remount()
			state = state_after(job.job_vault, old_list)
			states[state] += 1
			again = retry(job, fault=flushing_for_real, options=options)
			if (point <= total and not cut.killed) or again.error is not None or again.committed is not True:
				wrong.append((point, state, cut, again))
				continue
			problems = check_vault(job.job_vault, after_retries(job.job_vault, vault.expected), {3}, free_file_meta=only_sync) + view_truth.wrong_lists(job.job_vault)
			if problems:
				wrong.append((point, state, problems[:8]))
		print(f'power loss: {len(points)} of {total} steps run, {len(wrong)} wrong; what the remount left: {dict(states)}')
		assert not wrong, f'{len(wrong)} of {len(points)} steps wrong: {wrong[:4]}'


@needs_f2fs
def test_every_step_survives_a_power_loss(only_sync):
	sweep(only_sync, 'power-loss')


@needs_f2fs
@pytest.mark.parametrize('flush_step', [lambda step: max(1, step // 2), lambda step: max(1, step - 1)], ids=['midway', 'just_before'])
def test_every_step_survives_a_power_loss_after_a_checkpoint(only_sync, flush_step):
	# with no checkpoint the run mostly rolls back to before the batch: here the state at an earlier step is on the disk, and what came after it is lost
	sweep(only_sync, 'power-loss-checkpoint', flush_step)


def keeping_the_placement_and_losing_the_rename(job_vault):
	def fault(module):
		flushing_for_real(module)
		real_rename = module.os.rename
		def rename(source, dest, **kwargs):
			# the previous version's list only: its old name stays, and the placement goes on
			if rv.change_list_names(os.path.basename(source), next(name for name in os.listdir(job_vault) if version_number(name) == 2)) and os.path.basename(dest) != os.path.basename(source):
				return None
			return real_rename(source, dest, **kwargs)
		module.os.rename = rename
	return fault


@needs_f2fs
def test_a_power_loss_that_keeps_the_placement_and_loses_the_rename_is_finished():
	# a kernel may keep them in either order, as nothing syncs between them: this f2fs never showed this one by itself
	with LoopImage(os.path.join(SCRATCH, 'power-loss-order'), IMAGE_MIB) as image:
		root = tempfile.mkdtemp(prefix='reverb-crash-', dir=image.mount_point)
		vault = prepare(root)
		job = vault.job
		restore(vault)
		flush_scratch(root)
		old_list = old_list_name(job.job_vault, 2)
		cut = kill_run(job, fault=keeping_the_placement_and_losing_the_rename(job.job_vault))
		assert cut.error is None and cut.committed is True, cut
		shut_down_scratch(image.mount_point)
		image.remount()
		assert state_after(job.job_vault, old_list) == 'list of 3 placed, previous list under its old name'
		manifest = rv.VaultManifest(job.job_vault)
		try:
			rv.get_vault_info(job.job_vault, manifest=manifest)
		finally:
			manifest.close()
		assert old_list not in os.listdir(job.job_vault)
		assert check_vault(job.job_vault, vault.expected, set()) == [] and view_truth.wrong_lists(job.job_vault) == []
