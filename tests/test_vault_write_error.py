'''
A real write error, on ext4 over dm-linear (tests/scratch_images.py, FailingDisk): the kernel's rule the flush round rests on, and a
batch's commit flush hearing an error another program's sync met first. The other tests' stand-in (tests/errseq.py) restates the
rule as read in the kernel's source; this checks it on the kernel, where a wrong reading would leave every other test passing
and the alarm deaf. It needs root, dm-mod and REVERB_SCRATCH, so it runs in the test VM, where a skip counts as a failure.

Why ext4 and not f2fs: f2fs writes out of place, so no fixed range of the device is a file's next write. The rule belongs to the
VFS (mapping_set_error() sets the superblock's error, which syncfs reports), and f2fs records a data write error the same way.
'''
import ctypes
import errno
import os
import random
import tempfile

import pytest

import reverberator as rv
from tests.conftest import REAL_SYNC_VAULT_FILESYSTEMS
from tests.crash_batches import backup_events
from tests.harness import committed_versions, create_job
from tests.scratch_images import extents_of, FailingDisk, needs_dm, SCRATCH
from tests.test_vault_units import at_the_commit_flush, base, disk_of, KEPT, lists_of, manifest_version, modify_big, tree_of, vault_write_errors

pytestmark = needs_dm

# the image: a job's few small versions; sparse, so what the disk holds is all it takes of REVERB_SCRATCH
DISK_MIB = 64


def syncfs_errno(disk, fd):
	'''What syncfs(2) through fd answers: 0, or its errno.'''
	return 0 if disk.syncfs(fd) == 0 else ctypes.get_errno()


def test_the_kernel_reports_a_write_error_to_a_handle_opened_before_it_and_not_to_one_opened_after_another_sync_saw_it():
	with FailingDisk(os.path.join(SCRATCH, 'write-error-rule'), DISK_MIB) as disk:
		path = os.path.join(disk.mount_point, 'file')
		with open(path, 'wb') as f:
			f.write(random.Random(0).randbytes(1 << 20))
		extents = extents_of(path)
		before = os.open(disk.mount_point, os.O_RDONLY | os.O_DIRECTORY)
		try:
			disk.fail(extents)
			try:
				# another program's sync writes the file out and meets the error first
				assert disk.sync_elsewhere() == 1
			finally:
				disk.heal()
			assert syncfs_errno(disk, before) == errno.EIO
			after = os.open(disk.mount_point, os.O_RDONLY | os.O_DIRECTORY)
			try:
				# 0.55.2's blind spot: a handle opened once the error was seen hears nothing
				assert syncfs_errno(disk, after) == 0
			finally:
				os.close(after)
			# a file's own error is not marked seen by a syncfs: an fsync through a new fd hears it, as the per-file fsyncs need
			fd = os.open(path, os.O_RDONLY)
			try:
				with pytest.raises(OSError) as failed:
					os.fsync(fd)
				assert failed.value.errno == errno.EIO
			finally:
				os.close(fd)
		finally:
			os.close(before)


def test_a_batchs_commit_flush_hears_a_real_write_error_another_sync_met_first(monkeypatch, capsys):
	with FailingDisk(os.path.join(SCRATCH, 'write-error-batch'), DISK_MIB) as disk:
		job = create_job(tempfile.mkdtemp(prefix='reverb-', dir=disk.mount_point))
		# the real helper and the real binding, which syncs this disk only
		monkeypatch.setattr(rv, 'sync_vault_filesystems', REAL_SYNC_VAULT_FILESYSTEMS)
		monkeypatch.setattr(rv, 'LIBC_SYNCFS', disk.syncfs)
		base(job)
		before, lists = committed_versions(job), lists_of(job)
		met = []
		def the_copy_fails_under_another_sync():
			# the batch's copy, still dirty: its next write fails, another program's sync meets that, and the disk heals
			disk.fail(extents_of(os.path.join(tree_of(job), 'big.txt')))
			try:
				met.append(disk.sync_elsewhere())
			finally:
				disk.heal()
		ran = at_the_commit_flush(monkeypatch, the_copy_fails_under_another_sync)
		capsys.readouterr()
		with pytest.raises(rv.JobFailure) as failed:
			backup_events(job, modify_big(job), **KEPT)
		assert ran and met == [1]
		alerts = vault_write_errors(capsys.readouterr().out)
		assert len(alerts) == 1 and f'VAULT WRITE ERROR: disk {disk_of(job.job_vault)} failed a sync (' in alerts[0], alerts
		assert 'no version of this job is' in failed.value.reason
		# nothing commits: the manifest names the version before, and no list is placed
		assert manifest_version(job) == os.path.basename(before[-1]) and lists_of(job) == lists and committed_versions(job) == before
