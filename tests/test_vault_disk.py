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
		b'/dev/sdb1\t/mnt/jank/\tfuse.mergerfs\tnofail 0 0\n'
		b'/dev/sdc1 /mnt/a\\134b\\011c xfs noauto 0 0\n'
		b'lonely\n'
		b'  /dev/sdd1 /mnt/indented xfs defaults\n'
		b'/dev/sde1 relative xfs defaults\n')
	assert rv.parse_fstab(content) == ['/mnt/my disk', '/mnt/jank', '/mnt/a\\b\tc', '/mnt/indented']


def test_a_vault_under_an_unmounted_fstab_mount_is_not_there(tmp_path, fake_pool):
	jank = str(tmp_path / 'jank')
	write_fstab(jank)
	vault = os.path.join(jank, 'reverbs')
	assert rv.vault_disk_problem(vault) == not_mounted(jank)
	os.makedirs(vault)                       # a bare folder on the disk below changes nothing
	assert rv.vault_disk_problem(vault) == not_mounted(jank)
	fake_pool.add_mount(jank)
	assert rv.vault_disk_problem(vault) is None and rv.vault_disk_problem(jank) is None


def test_fstab_mount_points_match_by_path_component(tmp_path, fake_pool):
	jank, data = str(tmp_path / 'jank'), str(tmp_path / 'jank_data' / 'a')
	write_fstab(jank, data)
	fake_pool.add_mount(data)
	assert rv.vault_disk_problem(os.path.join(data, 'reverbs')) is None
	assert rv.vault_disk_problem(str(tmp_path / 'jank_data' / 'reverbs')) is None
	assert rv.vault_disk_problem(str(tmp_path / 'jankx' / 'reverbs')) is None
	assert rv.vault_disk_problem(os.path.join(jank, 'reverbs')) == not_mounted(jank)


def test_the_longest_fstab_mount_point_decides(tmp_path, fake_pool):
	outer, inner = str(tmp_path / 'pool'), str(tmp_path / 'pool' / 'disk')
	write_fstab(outer, inner)
	fake_pool.add_mount(inner)
	assert rv.vault_disk_problem(os.path.join(inner, 'v')) is None
	assert rv.vault_disk_problem(os.path.join(outer, 'v')) == not_mounted(outer)


def test_an_escaped_fstab_mount_point_matches_the_mount_table(tmp_path, fake_pool):
	disk = str(tmp_path / 'my disk\tA')
	write_fstab(disk)
	assert rv.vault_disk_problem(os.path.join(disk, 'v')) == not_mounted(disk)
	fake_pool.add_mount(disk)
	assert rv.vault_disk_problem(os.path.join(disk, 'v')) is None


def test_a_commented_fstab_line_names_nothing(tmp_path, fake_pool):
	jank = str(tmp_path / 'jank')
	with open(rv.FSTAB_PATH, 'w') as f:
		f.write(f'# /dev/fake {jank} xfs defaults 0 0\n  #/dev/fake {jank} xfs defaults 0 0\n')
	assert rv.vault_disk_problem(os.path.join(jank, 'v')) is None


@pytest.mark.parametrize('fstab', ['missing', 'a folder'])
def test_an_fstab_that_cannot_be_read_names_nothing(tmp_path, fake_pool, fstab):
	if fstab == 'a folder':
		os.makedirs(rv.FSTAB_PATH)
	assert rv.vault_disk_problem(str(tmp_path / 'jank' / 'v')) is None


def test_a_mount_table_that_cannot_be_read_means_not_there(tmp_path, monkeypatch):
	monkeypatch.setattr(rv, 'MOUNTINFO_PATH', str(tmp_path / 'no-mountinfo'))
	assert rv.vault_disk_problem(str(tmp_path / 'v')).startswith('the mount table cannot be read: ')


def test_an_fstab_mount_point_through_a_symlink_never_matches(tmp_path, fake_pool):
	os.makedirs(tmp_path / 'real' / 'jank')
	os.symlink(tmp_path / 'real', tmp_path / 'link')
	write_fstab(str(tmp_path / 'link' / 'jank'))
	assert rv.vault_disk_problem(str(tmp_path / 'link' / 'jank' / 'v')) is None


def test_a_pool_missing_a_disk_is_not_there(tmp_path, fake_pool):
	pool = str(tmp_path / 'pool')
	a, _ = fake_pool.add(pool, ['a', 'b'])
	fake_pool.drop(a)
	assert rv.vault_disk_problem(os.path.join(pool, 'v')) == f'disk {a} of pool {os.path.realpath(pool)} is not mounted'


def test_a_dead_mergerfs_in_fstab_is_not_there(tmp_path, fake_pool):
	pool = str(tmp_path / 'jank')
	fake_pool.add(pool, ['a', 'b'])
	write_fstab(pool)
	fake_pool.unreadable(pool, errno.ENOTCONN)
	assert rv.vault_disk_problem(os.path.join(pool, 'reverbs')) == \
		f'the disks of pool {os.path.realpath(pool)} cannot be listed: {os.strerror(errno.ENOTCONN)}'
