import errno
import os
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
def test_a_failed_disk_still_mounted_is_named(fake_pool, pool):
	vault, a, _ = pool
	fake_pool.fail_statvfs(a)
	assert rv.pool_problem(vault).startswith(f'disk {a} of pool {vault} cannot be read: ')


@pytest.mark.unit
def test_an_unreadable_branch_list_names_the_pool(fake_pool, pool):
	vault, _, _ = pool
	fake_pool.unreadable(vault)
	assert rv.pool_problem(vault).startswith(f'the disks of pool {vault} cannot be listed: ')


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
