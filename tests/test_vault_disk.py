import errno
import os
import pytest
import reverberator as rv
from tests.harness import write_fstab

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
def test_an_fstab_that_cannot_be_read_names_nothing(tmp_path, fake_pool, fstab):
	if fstab == 'a folder':
		os.makedirs(rv.FSTAB_PATH)
	assert rv.vault_disk_problem(str(tmp_path / 'vaults' / 'v')) is None


def test_a_mount_table_that_cannot_be_read_means_not_there(tmp_path, monkeypatch):
	monkeypatch.setattr(rv, 'MOUNTINFO_PATH', str(tmp_path / 'no-mountinfo'))
	assert rv.vault_disk_problem(str(tmp_path / 'v')).startswith('the mount table cannot be read: ')


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
