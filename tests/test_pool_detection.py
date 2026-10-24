import ctypes
import errno
import os
import sys
import pytest
import reverberator as rv


@pytest.fixture
def counted_signatures(monkeypatch):
	calls = []
	monkeypatch.setattr(rv, 'get_fs_signatures', lambda path: calls.append(path) or ['sig'])
	return calls


@pytest.fixture
def pool(tmp_path, fake_pool):
	'''A pool at tmp_path/vault over the disks a and b: (vault, a, b).'''
	vault = str(tmp_path / 'vault')
	a, b = fake_pool.add(vault, ['a', 'b'])
	return vault, a, b


@pytest.mark.unit
def test_read_pool_branches_reads_the_control_file_xattr(tmp_path):
	control = tmp_path / rv.MERGERFS_CONTROL_FILE
	control.write_text('')
	try:
		os.setxattr(str(control), rv.MERGERFS_BRANCHES_XATTR, b'/a:/b')
	except OSError as e:
		if e.errno in (errno.ENOTSUP, errno.EPERM):
			pytest.skip(f'no user xattrs here: {e}')
		raise
	assert rv.read_pool_branches(str(tmp_path)) == ['/a', '/b']


@pytest.mark.unit
def test_a_path_off_any_pool_reads_no_branch_list(tmp_path, fake_pool, pool):
	assert rv.pool_state(str(tmp_path)) is None
	assert rv.pool_problem(str(tmp_path)) is None
	assert fake_pool.reads == 0


@pytest.mark.unit
def test_a_whole_pool_has_no_problem(pool):
	vault, a, b = pool
	assert rv.pool_problem(vault) is None
	state = rv.pool_state(vault)
	assert state.pool == vault and state.problem is None
	assert [branch for branch, _ in state.ids] == [a, b]
	assert all(mount_id is not None for _, mount_id in state.ids)


@pytest.mark.unit
def test_a_missing_disk_is_named(fake_pool, pool):
	vault, a, b = pool
	fake_pool.drop(a)
	assert rv.pool_problem(vault) == f'disk {a} of pool {vault} is not mounted'
	fake_pool.drop(b)
	assert rv.pool_problem(vault) == f'disks {a}, {b} of pool {vault} are not mounted'


@pytest.mark.unit
def test_a_failed_disk_still_mounted_is_named(fake_pool, pool, monkeypatch):
	# a shut-down XFS stays mounted, and its statfs still answers: its statx fails
	vault, a, _ = pool
	monkeypatch.setattr(os, 'statvfs', lambda path: (_ for _ in ()).throw(AssertionError('statvfs is no probe')))
	fake_pool.fail_disk(a)
	assert rv.pool_problem(vault) == f'disk {a} of pool {vault} cannot be read: {os.strerror(errno.EIO)}'
	assert dict(rv.pool_state(vault).ids)[a] is None


@pytest.fixture
def f2fs_pool(tmp_path, fake_pool):
	'''A pool at tmp_path/klein over the f2fs disks c and d: (pool, c, d).'''
	klein = str(tmp_path / 'klein')
	c, d = fake_pool.add(klein, ['c', 'd'], fstype='f2fs')
	return klein, c, d


@pytest.mark.unit
def test_a_failed_f2fs_disk_is_told_by_its_checkpoint(fake_pool, f2fs_pool):
	# f2fs keeps a dead disk mounted and answers statx and readdir from cache; only its checkpoint flags say so
	klein, c, d = f2fs_pool
	assert rv.pool_problem(klein) is None
	# the source is a /dev/mapper link: the sysfs folder is named after the device it resolves to
	assert os.path.basename(os.path.dirname(os.path.dirname(fake_pool.f2fs_status(c)))).startswith('dm-')
	fake_pool.fail_disk(c)
	assert rv.pool_problem(klein) == f'disk {c} of pool {klein} has failed: its f2fs checkpoint reports an error'
	assert dict(rv.pool_state(klein).ids)[c] is None
	fake_pool.recover(c)
	assert rv.pool_problem(klein) is None


@pytest.mark.unit
def test_an_f2fs_disk_without_its_checkpoint_status_cannot_be_read(fake_pool, f2fs_pool):
	klein, c, _ = f2fs_pool
	os.remove(fake_pool.f2fs_status(c))
	assert rv.pool_problem(klein) == f'disk {c} of pool {klein} cannot be read: {os.strerror(errno.ENOENT)}'


@pytest.mark.unit
def test_an_unreadable_branch_list_names_the_pool(fake_pool, pool):
	vault, _, _ = pool
	fake_pool.unreadable(vault)
	assert rv.pool_problem(vault) == f'the disks of pool {vault} cannot be listed: {os.strerror(errno.ENOTSUP)}'


@pytest.mark.unit
def test_a_disk_mounted_again_counts_against_the_ids_taken_before(fake_pool, pool):
	vault, a, _ = pool
	guard = rv.PoolGuard([vault])
	assert guard.problem() is None
	fake_pool.drop(a)
	fake_pool.mount(a)
	assert guard.problem() == f'disk {a} of pool {vault} was mounted again during this step'
	with pytest.raises(rv.PoolNotReady) as raised:
		guard.require()
	assert isinstance(raised.value, rv.JobFailure)
	assert raised.value.reason == guard.problem() and not raised.value.permanent


@pytest.mark.unit
def test_a_disk_mounted_again_with_its_old_mountinfo_id_is_caught(fake_pool, pool):
	# the kernel reuses mountinfo ids; statx's unique mount ids are never reused
	vault, a, _ = pool
	guard = rv.PoolGuard([vault])
	fake_pool.drop(a)
	fake_pool.mount(a, same_id=True)
	assert guard.problem() == f'disk {a} of pool {vault} was mounted again during this step'


@pytest.mark.unit
def test_a_pool_unmounted_during_a_step_is_a_problem(fake_pool, pool):
	# a lazy umount of the pool leaves the empty mount folder on the root disk
	vault, _, _ = pool
	guard = rv.PoolGuard([vault])
	fake_pool.drop(vault)
	assert rv.pool_state(vault) is None
	assert guard.problem() == f'pool {vault} is not mounted'
	with pytest.raises(rv.PoolNotReady):
		guard.require()


@pytest.mark.unit
@pytest.mark.parametrize('same_id', [False, True])
def test_a_pool_mounted_again_during_a_step_is_a_problem(fake_pool, pool, same_id):
	vault, _, _ = pool
	guard = rv.PoolGuard([vault])
	fake_pool.drop(vault)
	fake_pool.mount(vault, same_id=same_id)
	assert guard.problem() == f'pool {vault} was mounted again during this step'


@pytest.mark.unit
def test_an_unreadable_mount_table_is_a_problem(tmp_path, fake_pool, pool, monkeypatch):
	vault, _, _ = pool
	guard = rv.PoolGuard([vault])
	monkeypatch.setattr(rv, 'MOUNTINFO_PATH', str(tmp_path / 'no_mountinfo'))
	problem = f'the mount table cannot be read: {os.strerror(errno.ENOENT)}'
	assert guard.problem() == problem
	assert rv.pool_problem(vault) == problem
	# a guard taken while it cannot be read fails too, as which paths are on a pool is not known
	assert rv.PoolGuard([vault]).problem() == problem
	# what reads the table for other uses still gets an empty one
	assert rv.current_mount_table() == []


@pytest.mark.unit
def test_a_guard_taken_while_the_mount_table_cannot_be_read_fails_its_step(tmp_path, fake_pool, pool, monkeypatch):
	# with no baseline, a disk dropped and mounted again later in the step could not be seen
	vault, a, _ = pool
	monkeypatch.setattr(rv, 'MOUNTINFO_PATH', str(tmp_path / 'no_mountinfo'))
	guard = rv.PoolGuard([vault])
	monkeypatch.setattr(rv, 'MOUNTINFO_PATH', fake_pool.mountinfo_path)
	assert guard.problem() == f'the mount table cannot be read: {os.strerror(errno.ENOENT)}'
	fake_pool.drop(a)
	fake_pool.mount(a)
	assert guard.problem() == f'the mount table cannot be read: {os.strerror(errno.ENOENT)}'
	# the next attempt's guard has its baseline
	assert rv.PoolGuard([vault]).problem() is None


@pytest.mark.unit
def test_a_guard_taken_with_a_failed_disk_fails_its_step(fake_pool, pool):
	vault, a, _ = pool
	fake_pool.fail_disk(a)
	guard = rv.PoolGuard([vault])
	fake_pool.recover(a)
	assert guard.problem() == f'disk {a} of pool {vault} cannot be read: {os.strerror(errno.EIO)}'
	assert rv.PoolGuard([vault]).problem() is None


@pytest.mark.unit
def test_a_pool_id_unknown_at_the_start_is_no_remount(fake_pool, pool):
	# a statx error on the pool's own mount point leaves its id unknown; known later, it is not a new mount
	vault, _, _ = pool
	fake_pool.fail_disk(vault)
	guard = rv.PoolGuard([vault])
	fake_pool.recover(vault)
	assert guard.problem() is None


@pytest.mark.unit
def test_without_unique_mount_ids_the_mount_table_is_used(fake_pool, pool, monkeypatch):
	# statx missing, or a kernel not reporting STATX_MNT_ID_UNIQUE: mountinfo's ids and mount points
	vault, a, b = pool
	monkeypatch.setattr(rv, 'statx_mount', lambda path: None)
	assert rv.pool_problem(vault) is None
	guard = rv.PoolGuard([vault])
	fake_pool.drop(a)
	assert guard.problem() == f'disk {a} of pool {vault} is not mounted'
	fake_pool.mount(a)
	assert guard.problem() == f'disk {a} of pool {vault} was mounted again during this step'


def fake_statx(mask:int, attributes:int, attributes_mask:int, mount_id:int, result:int = 0, err:int = 0):
	'''A stand-in for libc's statx that fills the buffer as the kernel does.'''
	def statx(dirfd, path, flags, want, buffer):
		if result:
			ctypes.set_errno(err)
			return result
		raw = bytearray(256)
		raw[0:4] = mask.to_bytes(4, sys.byteorder)
		raw[8:16] = attributes.to_bytes(8, sys.byteorder)
		raw[56:64] = attributes_mask.to_bytes(8, sys.byteorder)
		raw[144:152] = mount_id.to_bytes(8, sys.byteorder)
		ctypes.memmove(buffer, bytes(raw), 256)
		return 0
	return statx


@pytest.mark.unit
def test_statx_mount_reads_the_unique_id_and_the_mount_root_flag(monkeypatch):
	monkeypatch.setattr(rv, 'LIBC_STATX', fake_statx(rv.STATX_MNT_ID_UNIQUE, rv.STATX_ATTR_MOUNT_ROOT, rv.STATX_ATTR_MOUNT_ROOT, 2147484088))
	assert rv.statx_mount('/x') == (2147484088, True)
	monkeypatch.setattr(rv, 'LIBC_STATX', fake_statx(rv.STATX_MNT_ID_UNIQUE, 0, rv.STATX_ATTR_MOUNT_ROOT, 7))
	assert rv.statx_mount('/x') == (7, False)
	# the unique id or the mount root flag not reported: no answer, so the mount table is used
	monkeypatch.setattr(rv, 'LIBC_STATX', fake_statx(0x1000, rv.STATX_ATTR_MOUNT_ROOT, rv.STATX_ATTR_MOUNT_ROOT, 265))
	assert rv.statx_mount('/x') is None
	monkeypatch.setattr(rv, 'LIBC_STATX', fake_statx(rv.STATX_MNT_ID_UNIQUE, 0, 0, 7))
	assert rv.statx_mount('/x') is None
	monkeypatch.setattr(rv, 'LIBC_STATX', fake_statx(0, 0, 0, 0, result=-1, err=errno.ENOSYS))
	assert rv.statx_mount('/x') is None
	monkeypatch.setattr(rv, 'LIBC_STATX', None)
	assert rv.statx_mount('/x') is None
	monkeypatch.setattr(rv, 'LIBC_STATX', fake_statx(0, 0, 0, 0, result=-1, err=errno.EIO))
	with pytest.raises(OSError) as raised:
		rv.statx_mount('/x')
	assert raised.value.errno == errno.EIO


@pytest.mark.unit
def test_statx_mount_on_this_kernel(tmp_path):
	root = rv.statx_mount('/')
	if root is None:
		pytest.skip('no unique mount ids on this kernel')
	assert root[1] is True
	assert rv.statx_mount(str(tmp_path))[1] == os.path.ismount(str(tmp_path))
	with pytest.raises(FileNotFoundError):
		rv.statx_mount(str(tmp_path / 'missing'))


@pytest.mark.unit
def test_branches_and_paths_are_resolved(tmp_path, fake_pool):
	disk = tmp_path / 'disks' / 'real_a'
	disk.mkdir(parents=True)
	branch_link = tmp_path / 'branch_link'
	branch_link.symlink_to(disk)
	vault = tmp_path / 'vault'
	fake_pool.add(str(vault), [str(branch_link)])
	vault_link = tmp_path / 'vault_link'
	vault_link.symlink_to(vault)
	assert rv.pool_problem(str(vault_link) + '/') is None
	assert rv.pool_state(str(vault_link) + '/').ids[0][0] == str(disk)
	fake_pool.drop(str(disk))
	assert rv.pool_problem(str(vault_link) + '/') == f'disk {disk} of pool {vault} is not mounted'


@pytest.mark.unit
def test_poll_checks_at_most_once_a_period(monkeypatch, fake_pool, pool):
	vault, a, _ = pool
	monkeypatch.setattr(rv, 'POOL_CHECK_SECONDS', 10)
	now = [0]
	guard = rv.PoolGuard([vault], clock=lambda: now[0])
	after_init = fake_pool.reads
	for now[0] in (0, 5, 9):
		guard.poll()
	assert fake_pool.reads == after_init + 1
	fake_pool.drop(a)
	now[0] = 10
	with pytest.raises(rv.PoolNotReady):
		guard.poll()
	assert fake_pool.reads == after_init + 2


@pytest.mark.unit
def test_a_guard_off_any_pool_reads_nothing(tmp_path, fake_pool, pool):
	guard = rv.PoolGuard([str(tmp_path / 'elsewhere')])
	guard.poll()
	guard.require()
	assert guard.problem() is None
	assert fake_pool.reads == 0


@pytest.mark.unit
def test_the_monitor_clears_and_sets_a_flag_on_a_branch_change(monkeypatch, fake_pool, pool, counted_signatures):
	vault, a, _ = pool
	monitor = fake_pool.monitor
	# no background thread: the test drives check_changed() itself
	monkeypatch.setattr(monitor, 'start', lambda: None)
	flag = monitor.register(vault, 'N/A')
	signed = monitor.register(vault, 'sig')
	monitor.check_changed()
	assert flag.is_set() and signed.is_set()
	assert len(counted_signatures) == 1
	fake_pool.drop(a)
	monitor.check_changed()
	assert not flag.is_set() and not signed.is_set()
	# the failed pairs' periodic re-check runs no df while the pool is missing a disk
	monitor.check_changed(recheck_failed=True)
	assert not signed.is_set()
	assert len(counted_signatures) == 1
	fake_pool.mount(a)
	monitor.check_changed()
	assert flag.is_set() and signed.is_set()
	assert len(counted_signatures) == 2


@pytest.mark.unit
def test_the_monitor_leaves_pool_flags_alone_on_an_unreadable_table(tmp_path, monkeypatch, fake_pool, pool, counted_signatures):
	vault, a, _ = pool
	monitor = fake_pool.monitor
	monkeypatch.setattr(monitor, 'start', lambda: None)
	flag = monitor.register(vault, 'sig')
	monitor.check_changed()
	assert flag.is_set()
	fake_pool.drop(a)
	monitor.check_changed()
	assert not flag.is_set()
	# the signature alone would set it while the disk is out
	monkeypatch.setattr(monitor, 'mountinfo_path', str(tmp_path / 'no_mountinfo'))
	monitor.check_changed(recheck_failed=True)
	assert not flag.is_set()
	monkeypatch.setattr(monitor, 'mountinfo_path', fake_pool.mountinfo_path)
	fake_pool.mount(a)
	monitor.check_changed()
	assert flag.is_set()
	# nor is a set flag cleared for that pass
	monkeypatch.setattr(monitor, 'mountinfo_path', str(tmp_path / 'no_mountinfo'))
	monitor.check_changed(recheck_failed=True)
	assert flag.is_set()


@pytest.mark.unit
def test_the_monitor_logs_the_pool_problem(monkeypatch, fake_pool, pool):
	vault, a, _ = pool
	lines = []
	monkeypatch.setattr(rv, 'watcherTeeLogToTl', lambda path, message, **kwargs: lines.append(message))
	monkeypatch.setattr(fake_pool.monitor, 'start', lambda: None)
	fake_pool.monitor.register(vault, 'N/A')
	fake_pool.monitor.check_changed()
	fake_pool.drop(a)
	fake_pool.monitor.check_changed()
	assert lines[-1] == f'{vault}: disk {a} of pool {vault} is not mounted, pausing.'


@pytest.mark.unit
def test_mount_table_fingerprints_carry_the_fstype():
	table = rv.parse_mount_table(b'22 1 8:1 / / rw shared:1 - ext4 /dev/sda1 rw\n'
		b'40 22 8:17 /data /mnt/my\\040disk rw - xfs /dev/sdb1 rw\n')
	assert table[1][1] == (b'40', b'8:17', b'/data', b'/dev/sdb1', b'xfs')
	assert rv.mergerfs_mount(table, '/mnt/my disk/x') is None
	pooled = rv.parse_mount_table(b'60 35 0:42 / /reverb_test_pool rw,relatime shared:15 - fuse.mergerfs klein rw,allow_other\n')
	assert rv.mergerfs_mount(pooled, '/reverb_test_pool/a') == '/reverb_test_pool'
	# tests' short fake fingerprints are never mergerfs
	assert rv.mergerfs_mount([('/', ('1',))], '/x') is None
