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


def test_an_fstab_mount_point_under_a_symlinked_folder_is_checked_by_its_real_path(tmp_path, fake_pool):
	os.makedirs(tmp_path / 'real' / 'jank')
	os.symlink(tmp_path / 'real', tmp_path / 'link')
	real_jank = str(tmp_path / 'real' / 'jank')
	write_fstab(str(tmp_path / 'link' / 'jank'))
	for vault in (tmp_path / 'link' / 'jank' / 'v', tmp_path / 'real' / 'jank' / 'v'):
		assert rv.vault_disk_problem(str(vault)) == not_mounted(real_jank)
	fake_pool.add_mount(real_jank)
	for vault in (tmp_path / 'link' / 'jank' / 'v', tmp_path / 'real' / 'jank' / 'v'):
		assert rv.vault_disk_problem(str(vault)) is None


def test_an_fstab_mount_point_that_is_a_symlink_is_checked_by_its_real_path(tmp_path, fake_pool):
	os.makedirs(tmp_path / 'disk')
	os.symlink(tmp_path / 'disk', tmp_path / 'jank')
	disk = str(tmp_path / 'disk')
	write_fstab(str(tmp_path / 'jank'))
	assert rv.vault_disk_problem(str(tmp_path / 'jank' / 'v')) == not_mounted(disk)
	assert rv.vault_disk_problem(str(tmp_path / 'disk' / 'v')) == not_mounted(disk)
	fake_pool.add_mount(disk)
	assert rv.vault_disk_problem(str(tmp_path / 'jank' / 'v')) is None
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
	jank, other = str(tmp_path / 'jank'), str(tmp_path / 'other')
	write_fstab(jank, other)
	fake_pool.add_mount(jank)
	asked = []
	real_realpath = os.path.realpath
	monkeypatch.setattr(os.path, 'realpath', lambda p, *a, **k: asked.append(os.fspath(p)) or real_realpath(p, *a, **k))
	assert rv.vault_disk_problem(os.path.join(jank, 'v')) is None
	assert jank not in asked and other in asked


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
	pool = str(tmp_path / 'jank')
	fake_pool.add(pool, ['a', 'b'])
	write_fstab(pool)
	fake_pool.unreadable(pool, errno.ENOTCONN)
	assert rv.vault_disk_problem(os.path.join(pool, 'reverbs')) == \
		f'the disks of pool {os.path.realpath(pool)} cannot be listed: {os.strerror(errno.ENOTCONN)}'
