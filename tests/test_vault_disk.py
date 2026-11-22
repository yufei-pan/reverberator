import errno
import json
import os
import shutil
import threading
import time
import pytest
import reverberator as rv
from tests.harness import seed_monitor, wait_until, write_fstab

pytestmark = pytest.mark.unit


def not_mounted(mount_point):
	return f'{mount_point} is not mounted ({rv.FSTAB_PATH} names it)'


def test_parse_fstab_reads_field_two_decoded_and_absolute():
	content = (b'# /dev/old /mnt/old xfs defaults 0 0\n\n   \n'
		b'UUID=1 /mnt/my\\040disk xfs defaults 0 0\n'
		b'none swap sw 0 0\n'
		b'/dev/sdb1\t/mnt/vaults/\tfuse.mergerfs\tnofail 0 0\n'
		b'/dev/sdc1 /mnt/a\\134b\\011c xfs noauto 0 0\n'
		b'lonely\n'
		b'  /dev/sdd1 /mnt/indented xfs defaults\n'
		b'/dev/sde1 relative xfs defaults\n')
	assert rv.parse_fstab(content) == ['/mnt/my disk', '/mnt/vaults', '/mnt/a\\b\tc', '/mnt/indented']


def test_a_vault_under_an_unmounted_fstab_mount_is_not_there(tmp_path, fake_pool):
	vaults = str(tmp_path / 'vaults')
	write_fstab(vaults)
	vault = os.path.join(vaults, 'reverbs')
	assert rv.vault_disk_problem(vault) == not_mounted(vaults)
	os.makedirs(vault)                       # a bare folder on the disk below changes nothing
	assert rv.vault_disk_problem(vault) == not_mounted(vaults)
	fake_pool.add_mount(vaults)
	assert rv.vault_disk_problem(vault) is None and rv.vault_disk_problem(vaults) is None


def test_fstab_mount_points_match_by_path_component(tmp_path, fake_pool):
	vaults, data = str(tmp_path / 'vaults'), str(tmp_path / 'vaults_data' / 'a')
	write_fstab(vaults, data)
	fake_pool.add_mount(data)
	assert rv.vault_disk_problem(os.path.join(data, 'reverbs')) is None
	assert rv.vault_disk_problem(str(tmp_path / 'vaults_data' / 'reverbs')) is None
	assert rv.vault_disk_problem(str(tmp_path / 'vaultsx' / 'reverbs')) is None
	assert rv.vault_disk_problem(os.path.join(vaults, 'reverbs')) == not_mounted(vaults)


def test_the_longest_fstab_mount_point_decides(tmp_path, fake_pool):
	outer, inner = str(tmp_path / 'pool'), str(tmp_path / 'pool' / 'disk')
	write_fstab(outer, inner)
	fake_pool.add_mount(inner)
	assert rv.vault_disk_problem(os.path.join(inner, 'v')) is None
	assert rv.vault_disk_problem(os.path.join(outer, 'v')) == not_mounted(outer)


@pytest.mark.parametrize('fstype', ['xfs', 'ext4', 'tmpfs'])
def test_whatever_is_mounted_under_an_unmounted_fstab_point_is_not_there(tmp_path, fake_pool, fstype):
	# fstab names data (not mounted); a disk mounted by hand below it, a bind mount of a root-disk folder (ext4) or a
	# tmpfs: the mount table cannot tell them apart, and none of them is the fstab disk
	data, x = str(tmp_path / 'data'), str(tmp_path / 'data' / 'x')
	write_fstab(data)
	fake_pool.add_mount(x, fstype)
	for path in (os.path.join(x, 'v'), x, str(tmp_path / 'data' / 'y'), data):
		assert rv.vault_disk_problem(path) == not_mounted(data), path
	fake_pool.add_mount(data)
	assert rv.vault_disk_problem(os.path.join(x, 'v')) is None


def test_an_escaped_fstab_mount_point_matches_the_mount_table(tmp_path, fake_pool):
	disk = str(tmp_path / 'my disk\tA')
	write_fstab(disk)
	assert rv.vault_disk_problem(os.path.join(disk, 'v')) == not_mounted(disk)
	fake_pool.add_mount(disk)
	assert rv.vault_disk_problem(os.path.join(disk, 'v')) is None


def test_a_commented_fstab_line_names_nothing(tmp_path, fake_pool):
	vaults = str(tmp_path / 'vaults')
	with open(rv.FSTAB_PATH, 'w') as f:
		f.write(f'# /dev/fake {vaults} xfs defaults 0 0\n  #/dev/fake {vaults} xfs defaults 0 0\n')
	assert rv.vault_disk_problem(os.path.join(vaults, 'v')) is None


@pytest.mark.parametrize('fstab', ['missing', 'a folder'])
def test_an_fstab_that_cannot_be_read_is_a_problem_and_a_missing_one_names_nothing(tmp_path, fake_pool, fstab):
	# 'missing' is a pin; 'a folder' (EISDIR, a read that fails other than with ENOENT) named nothing before 0.55.6
	if fstab == 'a folder':
		os.makedirs(rv.FSTAB_PATH)
	expected = None if fstab == 'missing' else unreadable(errno.EISDIR)
	assert rv.vault_disk_problem(str(tmp_path / 'vaults' / 'v')) == expected


def unreadable(err:int = errno.EIO) -> str:
	return f'{rv.FSTAB_PATH} cannot be read: {os.strerror(err)}'


class FailingRead:
	'''An open file whose read fails with err.'''
	def __init__(self, err:int):
		self.err = err

	def __enter__(self):
		return self

	def __exit__(self, *exc):
		return False

	def read(self, *args):
		raise OSError(self.err, os.strerror(self.err))


def fstab_read_fails(monkeypatch, err:int = errno.EIO) -> dict:
	'''
	FSTAB_PATH opens and its read fails with err, as on a root disk going bad: a stand-in on reverberator's open for that
	path alone, failing while the dict returned says so ('failing').
	'''
	state = {'failing': True}
	real = open
	def opener(path, *args, **kwargs):
		if state['failing'] and path == rv.FSTAB_PATH:
			return FailingRead(err)
		return real(path, *args, **kwargs)
	monkeypatch.setattr(rv, 'open', opener, raising=False)
	return state


def test_an_fstab_that_cannot_be_read_makes_the_job_wait(job, poll_fast, monkeypatch, tmp_path, capsys):
	# fails on main (makes the job's folder and backs up): fstab names the vault's disk, which is not mounted, and its
	# read fails with EIO: the job's first wait, for its Vault Path, waits on the read with the FAILED: waiting marker and
	# its status saying so, and makes nothing; once the read answers, its answer decides (the disk is not mounted)
	seed_monitor(job, {'a.txt': 'a'})
	write_fstab(job.vault)
	reads = fstab_read_fails(monkeypatch)
	monkeypatch.setattr(rv, 'DISK_WAIT_GRACE_SECONDS', 0.1)
	rv.STATUS_BOARD = rv.StatusBoard(str(tmp_path / 'state'), '/r.tsv')
	control = rv.JobControl(job.job_name)
	control.start_attempt()
	ready = threading.Event()
	ready.set()
	thread = threading.Thread(target=rv.backuper, args=(job.job_name, rv.ChangeEventQueue(job.monitor), threading.Lock(), job.monitor,
		job.vault, 'N/A', threading.Event(), ready), kwargs=dict(job=control), daemon=True)
	thread.start()
	printed = ''
	def status() -> dict:
		try:
			with open(tmp_path / 'state' / f'job-{job.job_name}.json') as f:
				return json.load(f)
		except (OSError, ValueError):
			return {}
	def waiting(reason) -> bool:
		nonlocal printed
		out = capsys.readouterr()
		printed += out.out + out.err
		return f'reverberator job {job.job_name} FAILED: waiting 0 min for {job.vault}: {reason}' in printed
	try:
		wait_until(lambda: waiting(unreadable()) or control.committed.is_set() or control.failure is not None, timeout=10,
			message='the job neither waited nor backed up')
		assert control.failure is None and not control.committed.is_set() and not os.path.lexists(job.job_vault)
		assert [wait[1:3] for wait in control._waits] == [[job.vault, unreadable()]]
		wait_until(lambda: status().get('state') == 'waiting', timeout=5, message='no waiting status')
		assert status()['detail'] == f'{job.vault}: {unreadable()}'
		time.sleep(0.3)
		assert thread.is_alive() and control.failure is None and not os.path.lexists(job.job_vault)
		reads['failing'] = False
		wait_until(lambda: [wait[2] for wait in control._waits] == [not_mounted(job.vault)], timeout=5,
			message='the wait never took the answer of the read')
		assert not os.path.lexists(job.job_vault)
	finally:
		control.fail('test done')
		thread.join(timeout=5)
	assert not thread.is_alive()


def test_a_missing_fstab_names_nothing(tmp_path, fake_pool):
	# pin: no fstab is an answer, none named: no disk problem off a pool or on one, and a wait does not wait
	pool = str(tmp_path / 'pool')
	fake_pool.add(pool, ['a', 'b'])
	assert not os.path.lexists(rv.FSTAB_PATH)
	for path in (str(tmp_path / 'vaults' / 'v'), os.path.join(pool, 'v')):
		assert rv.vault_disk_problem(path) is None, path
	assert rv.pool_state(os.path.join(pool, 'v')).problem is None
	control = rv.JobControl('job')
	control.start_attempt()
	waits = []
	real = control.begin_wait
	control.begin_wait = lambda *args: waits.append(args) or real(*args)
	os.makedirs(os.path.join(pool, 'v'))
	assert rv.wait_for_path(control, None, os.path.join(pool, 'v'), 'vault filesystem not ready') is True
	assert waits == []


def test_a_pool_state_with_fstab_unreadable_says_so(tmp_path, fake_pool, monkeypatch):
	# fails on main (no problem): which pool holds the path and its disks' ids are known; fstab's points are not, so a
	# disk fstab names under a pool's disk cannot be told, and the state's problem says why
	pool = str(tmp_path / 'pool')
	a, b = fake_pool.add(pool, ['a', 'b'])
	path = os.path.join(pool, 'v')
	fstab_read_fails(monkeypatch)
	state = rv.pool_state(path)
	assert state.pool == os.path.realpath(pool) and [branch for branch, _ in state.ids] == [a, b]
	assert all(mount_id is not None for _, mount_id in state.ids)
	assert state.problem == unreadable()
	assert rv.pool_problem(path) == unreadable() and rv.vault_disk_problem(path) == unreadable()
	fake_pool.drop(a)
	assert rv.pool_problem(path) == f'disk {a} of pool {os.path.realpath(pool)} is not mounted; {unreadable()}'


def test_a_guard_checks_against_the_fstab_its_batch_began_with(tmp_path, fake_pool, monkeypatch):
	# a disk fstab names under a pool's disk at the path's place, mounted when the batch looked; then fstab loses its line
	# and the disk goes: the guard's checks answer by the points its look read, and read no fstab
	pool = str(tmp_path / 'pool')
	a, _ = fake_pool.add(pool, ['a', 'b'])
	path = os.path.join(pool, 'v')
	place = fake_pool.add_mount(os.path.join(a, 'v'))
	write_fstab(place)
	table = rv.read_mount_table()
	guard = rv.PoolGuard([path], mount_table=table, fstab=rv.fstab_mount_points(table))
	guard.require()
	write_fstab()
	fake_pool.drop(place)
	reads = []
	real = rv.parse_fstab
	monkeypatch.setattr(rv, 'parse_fstab', lambda content: reads.append(content) or real(content))
	with pytest.raises(rv.PoolNotReady) as failed:
		guard.require()
	assert failed.value.args[0] == f'disk {place} of pool {os.path.realpath(pool)} is not mounted ({rv.FSTAB_PATH} names it)'
	assert reads == []
	# a check with no points kept reads fstab now, which names no disk there
	assert rv.pool_problem(path) is None and len(reads) == 1


def test_a_mount_table_that_cannot_be_read_means_not_there(tmp_path, monkeypatch):
	monkeypatch.setattr(rv, 'MOUNTINFO_PATH', str(tmp_path / 'no-mountinfo'))
	assert rv.vault_disk_problem(str(tmp_path / 'v')).startswith('the mount table cannot be read: ')


def test_a_disk_that_cannot_be_looked_at_is_not_called_one_that_is_not_there(tmp_path, monkeypatch, fake_pool):
	# review of Task 11 (Haiku tests): signature_folder_problem() wrapped every reason in "is on a disk that is not there", and its start
	# waited for "the disk is there": an unreadable fstab or mount table says nothing of the disk. A failed disk is still one that is not
	# there (the test of a plain disk that failed)
	folder = str(tmp_path / 'v')
	os.makedirs(folder)
	os.makedirs(rv.FSTAB_PATH)
	assert rv.signature_folder_problem(folder) == (f'is on a disk that cannot be looked at: {unreadable(errno.EISDIR)}', 'the disk can be looked at')
	os.rmdir(rv.FSTAB_PATH)
	assert rv.signature_folder_problem(folder) is None
	monkeypatch.setattr(rv, 'MOUNTINFO_PATH', str(tmp_path / 'no-mountinfo'))
	why = rv.signature_folder_problem(folder)
	assert why[0].startswith('is on a disk that cannot be looked at: the mount table cannot be read: ') and why[1] == 'the disk can be looked at'


def test_an_fstab_mount_point_under_a_symlinked_folder_is_checked_by_its_real_path(tmp_path, fake_pool):
	os.makedirs(tmp_path / 'real' / 'vaults')
	os.symlink(tmp_path / 'real', tmp_path / 'link')
	real_vaults = str(tmp_path / 'real' / 'vaults')
	write_fstab(str(tmp_path / 'link' / 'vaults'))
	for vault in (tmp_path / 'link' / 'vaults' / 'v', tmp_path / 'real' / 'vaults' / 'v'):
		assert rv.vault_disk_problem(str(vault)) == not_mounted(real_vaults)
	fake_pool.add_mount(real_vaults)
	for vault in (tmp_path / 'link' / 'vaults' / 'v', tmp_path / 'real' / 'vaults' / 'v'):
		assert rv.vault_disk_problem(str(vault)) is None


def test_an_fstab_mount_point_that_is_a_symlink_is_checked_by_its_real_path(tmp_path, fake_pool):
	os.makedirs(tmp_path / 'disk')
	os.symlink(tmp_path / 'disk', tmp_path / 'vaults')
	disk = str(tmp_path / 'disk')
	write_fstab(str(tmp_path / 'vaults'))
	assert rv.vault_disk_problem(str(tmp_path / 'vaults' / 'v')) == not_mounted(disk)
	assert rv.vault_disk_problem(str(tmp_path / 'disk' / 'v')) == not_mounted(disk)
	fake_pool.add_mount(disk)
	assert rv.vault_disk_problem(str(tmp_path / 'vaults' / 'v')) is None
	assert rv.vault_disk_problem(str(tmp_path / 'disk' / 'v')) is None


def test_an_fstab_escape_above_octal_377_is_masked_to_a_byte():
	# libmount reads \500 as '@' (0x140 & 0xff); one such line must not break the others
	assert rv.parse_fstab(b'/dev/a /mnt/a\\500b xfs defaults\n/dev/b /mnt/c\\777d xfs defaults\n/dev/c /mnt/ok xfs defaults\n') \
		== ['/mnt/a@b', os.fsdecode(b'/mnt/c\xffd'), '/mnt/ok']
	table = rv.parse_mount_table(b'22 1 8:1 / /mnt/x\\500y rw - ext4 /dev/sda1 rw\n')
	assert table[0][0] == '/mnt/x@y'


def test_a_leading_double_slash_in_an_fstab_mount_point_reads_as_one(tmp_path):
	assert rv.parse_fstab(b'/dev/a //mnt/a xfs defaults\n/dev/b ///mnt/b/ xfs defaults\n') == ['/mnt/a', '/mnt/b']


def test_a_listed_fstab_mount_point_is_never_resolved(tmp_path, fake_pool, monkeypatch):
	# resolving one would ask the mounted filesystem, which blocks when it hangs
	vaults, other = str(tmp_path / 'vaults'), str(tmp_path / 'other')
	write_fstab(vaults, other)
	fake_pool.add_mount(vaults)
	asked = []
	real_realpath = os.path.realpath
	monkeypatch.setattr(os.path, 'realpath', lambda p, *a, **k: asked.append(os.fspath(p)) or real_realpath(p, *a, **k))
	# the disk check's statx of the mount (plain_disk_problem()) asks it, as a pool's check asks each disk; the fake's own
	# realpath is not the fstab's
	fake_statx = rv.statx_mount
	monkeypatch.setattr(rv, 'statx_mount', lambda path: (1000, True) if path == vaults else fake_statx(path))
	assert rv.vault_disk_problem(os.path.join(vaults, 'v')) is None
	assert vaults not in asked and other in asked


def test_an_fstab_nul_escape_cuts_the_mount_point_there(tmp_path):
	assert rv.parse_fstab(b'/dev/a /mnt/n\\000ul xfs defaults\n') == ['/mnt/n']
	with open(rv.FSTAB_PATH, 'wb') as f:
		f.write(b'/dev/a /mnt/n\\000ul xfs defaults\n')
	assert rv.vault_disk_problem(str(tmp_path / 'v')) is None


def test_a_pool_missing_a_disk_is_not_there(tmp_path, fake_pool):
	pool = str(tmp_path / 'pool')
	a, _ = fake_pool.add(pool, ['a', 'b'])
	fake_pool.drop(a)
	assert rv.vault_disk_problem(os.path.join(pool, 'v')) == f'disk {a} of pool {os.path.realpath(pool)} is not mounted'


def test_a_dead_mergerfs_in_fstab_is_not_there(tmp_path, fake_pool):
	pool = str(tmp_path / 'vaults')
	fake_pool.add(pool, ['a', 'b'])
	write_fstab(pool)
	fake_pool.unreadable(pool, errno.ENOTCONN)
	assert rv.vault_disk_problem(os.path.join(pool, 'reverbs')) == \
		f'the disks of pool {os.path.realpath(pool)} cannot be listed: {os.strerror(errno.ENOTCONN)}'


@pytest.mark.parametrize('fstype', ['f2fs', 'xfs'])
def test_a_plain_disk_that_failed_is_not_there_as_a_pool_disk_is_not(tmp_path, fake_pool, fstype):
	# a vault on one disk, no pool: an f2fs whose checkpoint reports an error, or a shut-down XFS whose statx fails, is
	# the same problem a pool's disk has, and the job waits for it the same way
	disk = fake_pool.add_mount(str(tmp_path / 'ssd'), fstype)
	vault = os.path.join(disk, 'backup', 'reverb')
	assert rv.vault_disk_problem(vault) is None
	fake_pool.fail_disk(disk)
	expected = (f'disk {disk} has failed: its f2fs checkpoint reports an error' if fstype == 'f2fs'
		else f'disk {disk} cannot be read: {os.strerror(errno.EIO)}')
	assert rv.vault_disk_problem(vault) == expected
	assert rv.signature_folder_problem(disk) == (f'is on a disk that is not there: {expected}', 'the disk is there')
	fake_pool.recover(disk)
	assert rv.vault_disk_problem(vault) is None


def test_the_monitor_pauses_a_plain_disk_that_failed(tmp_path, monkeypatch, fake_pool):
	disk = fake_pool.add_mount(str(tmp_path / 'ssd'), 'f2fs')
	vault = os.path.join(disk, 'reverb')
	os.makedirs(vault)
	lines = []
	monkeypatch.setattr(rv, 'watcherTeeLogToTl', lambda path, message, **kwargs: lines.append(message))
	monkeypatch.setattr(fake_pool.monitor, 'start', lambda: None)
	flag = fake_pool.monitor.register(vault, 'N/A')
	fake_pool.monitor.check_changed()
	assert flag.is_set()
	fake_pool.fail_disk(disk)
	fake_pool.monitor.check_changed()
	assert not flag.is_set()
	assert lines[-1] == f'{vault}: disk {disk} has failed: its f2fs checkpoint reports an error, pausing.'
	fake_pool.recover(disk)
	fake_pool.monitor.check_changed()
	assert flag.is_set()


def test_a_disk_of_a_pool_is_checked_by_the_pool_alone(tmp_path, fake_pool):
	# a pool's own mount is never taken for the plain disk: its branches are checked, each once
	pool = str(tmp_path / 'pool')
	a, _ = fake_pool.add(pool, ['a', 'b'], fstype='f2fs')
	fake_pool.fail_disk(a)
	assert rv.vault_disk_problem(os.path.join(pool, 'v')) == f'disk {a} of pool {os.path.realpath(pool)} has failed: its f2fs checkpoint reports an error'


def f2fs_mount_named_by_its_device(tmp_path, fake_pool, source, device):
	'''An f2fs disk whose mount source is source, whatever its device is called: sysfs knows it as device, by its major:minor.'''
	real = os.path.realpath(os.makedirs(str(tmp_path / 'ssd'), exist_ok=True) or str(tmp_path / 'ssd'))
	line = fake_pool.line(real, 'f2fs', source)
	fake_pool.lines.append(line)
	fake_pool.add_block_device(f'0:{line[2]}', device)
	os.makedirs(os.path.join(fake_pool.f2fs_sysfs, device, 'stat'))
	status = os.path.join(fake_pool.f2fs_sysfs, device, 'stat', 'cp_status')
	with open(status, 'w') as f:
		f.write(f'{fake_pool.F2FS_WHOLE:x}\n')
	fake_pool.write()
	return real, status


def test_an_f2fs_disk_is_found_in_sysfs_by_its_major_minor_not_by_its_source(tmp_path, fake_pool):
	# a root f2fs shows /dev/root as its source, which is no name in /sys/fs/f2fs
	disk, status = f2fs_mount_named_by_its_device(tmp_path, fake_pool, '/dev/root', 'sda2')
	vault = os.path.join(disk, 'reverb')
	assert rv.vault_disk_problem(vault) is None
	with open(status, 'w') as f:
		f.write(f'{fake_pool.F2FS_WHOLE | 0x8:x}\n')
	assert rv.vault_disk_problem(vault) == f'disk {disk} has failed: its f2fs checkpoint reports an error'


def test_an_f2fs_disk_without_a_checkpoint_status_is_taken_for_whole_and_warned_of_once(tmp_path, monkeypatch, fake_pool):
	# a kernel without stat/cp_status: nothing says the disk failed, so its jobs do not wait for it
	disk, status = f2fs_mount_named_by_its_device(tmp_path, fake_pool, '/dev/sda2', 'sda2')
	os.remove(status)
	warnings = []
	monkeypatch.setattr(rv, 'backuperTeeLogToTl', lambda path, message, **kwargs: warnings.append((message, kwargs)))
	vault = os.path.join(disk, 'reverb')
	assert rv.vault_disk_problem(vault) is None and rv.vault_disk_problem(vault) is None
	assert len(warnings) == 1 and warnings[0][1] == {'warning': True}
	assert 'Cannot tell whether the f2fs disk' in warnings[0][0] and status in warnings[0][0]


def test_a_plain_f2fs_disk_whose_device_is_gone_is_named_even_with_its_error_flag_set(tmp_path, fake_pool):
	# a SAS disk dropped off its HBA: /sys/fs/f2fs/sdn stays with CP_ERROR_FLAG, /sys/dev/block/<major:minor> goes
	disk, status = f2fs_mount_named_by_its_device(tmp_path, fake_pool, '/dev/sdn', 'sdn')
	vault = os.path.join(disk, 'reverb')
	assert rv.vault_disk_problem(vault) is None
	major_minor = f'0:{fake_pool.mounted_as[disk][2]}'
	os.remove(os.path.join(fake_pool.sys_dev_block, major_minor))
	with open(status, 'w') as f:
		f.write(f'{fake_pool.F2FS_WHOLE | 0x8:x}\n')
	assert rv.vault_disk_problem(vault) == f'disk {disk} cannot be read: its device {major_minor} is gone'


def test_a_plain_f2fs_disk_with_no_sysfs_folder_cannot_be_read(tmp_path, fake_pool):
	disk, status = f2fs_mount_named_by_its_device(tmp_path, fake_pool, '/dev/sda2', 'sda2')
	shutil.rmtree(os.path.dirname(os.path.dirname(status)))
	assert rv.vault_disk_problem(os.path.join(disk, 'reverb')) == f'disk {disk} cannot be read: {os.strerror(errno.ENOENT)}'
