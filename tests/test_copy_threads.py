'''
Round 18: the rule file's column 15, Copy threads, sets the threads of a job's referenced copy and prune. A whole number
of 1 or more is itself (1 runs them with no thread pool); blank or auto goes by the vault's disks in sysfs (8 when any is
a hard disk, else 2, and 2 when that cannot be told); anything else is auto after one warning. A 14 column rule file is
read as before.
'''
import os
from collections import OrderedDict
import pytest
import reverberator as rv
from tests.harness import event_entry, rule_row, run_backup, seed_monitor
from tests.test_parse_rules import HEADER_14, _rule_file

pytestmark = pytest.mark.unit


@pytest.fixture
def warnings(monkeypatch):
	lines = []
	real = rv.tl.teelog
	def teelog(message, *args, **kwargs):
		lines.append(str(message))
		return real(message, *args, **kwargs)
	monkeypatch.setattr(rv.tl, 'teelog', teelog)
	return lines


@pytest.mark.parametrize('cell, threads, warned', [
	('', 5, False), ('auto', 5, False), ('AUTO', 5, False), (' Auto ', 5, False), (' 3 ', 3, False), ('1', 1, False),
	('0', 5, True), ('-2', 5, True), ('x', 5, True), ('2.5', 5, True)])
def test_copy_threads_cells(monkeypatch, warnings, cell, threads, warned):
	monkeypatch.setattr(rv, 'vault_disk_problem', lambda path: None)
	monkeypatch.setattr(rv, 'copy_threads_auto', lambda path: (5, 'auto: told'))
	assert rv.read_copy_threads(cell, 'j', '/v')[0] == threads
	said = [line for line in warnings if 'Copy threads' in line]
	assert bool(said) == warned
	if warned:
		assert len(said) == 1 and 'Rule j ' in said[0] and cell in said[0]


def test_a_number_wins_over_auto(monkeypatch):
	def never(path):
		raise AssertionError('auto was asked')
	monkeypatch.setattr(rv, 'copy_threads_auto', never)
	monkeypatch.setattr(rv, 'vault_disk_problem', never)
	assert rv.read_copy_threads('4', 'j', '/v') == (4, 'Copy threads column')


def test_auto_waits_for_a_vault_disk_that_is_not_there(monkeypatch):
	monkeypatch.setattr(rv, 'vault_disk_problem', lambda path: '/mnt/x is not mounted')
	assert rv.read_copy_threads('', 'j', '/mnt/x/v') == (0, 'auto, told once the vault is there: /mnt/x is not mounted')


def test_a_14_column_rule_file_reads_no_copy_threads(job):
	_rule_file(job, '\t'.join(rv.REVERB_RULE_TSV_HEADER[:14]), rule_row(job) + ['', '20'])
	before = open(job.rule_path, newline='').read()
	rule, = rv.parse_rules(job.rule_path)
	assert (rule.chain_length, rule.copy_threads) == ('20', '')
	assert open(job.rule_path, newline='').read() == before


def test_a_15_column_rule_file_reads_its_copy_threads(job):
	_rule_file(job, HEADER_14, rule_row(job) + ['', '', '3'])
	rule, = rv.parse_rules(job.rule_path)
	assert rule.copy_threads == '3'


# --- auto, by a fake sysfs ---

def fake_sysfs(tmp_path, monkeypatch):
	'''
	A sysfs with sda (a hard disk) and its partition sda1, nvme0n1 (an SSD), dm-0 over sda1, and dm-1 over nvme0n1, as
	/sys/dev/block names them: 8:0, 8:1, 259:0, 253:0, 253:1.
	'''
	devices = tmp_path / 'sys' / 'devices'
	def disk(name, rotational):
		(devices / name / 'queue').mkdir(parents=True)
		(devices / name / 'queue' / 'rotational').write_text(f'{rotational}\n')
	disk('sda', 1)
	(devices / 'sda' / 'sda1').mkdir()
	(devices / 'sda' / 'sda1' / 'partition').write_text('1\n')
	disk('nvme0n1', 0)
	for name, under in (('dm-0', 'sda/sda1'), ('dm-1', 'nvme0n1')):
		disk(name, 0)
		(devices / name / 'slaves').mkdir()
		os.symlink(devices / under, devices / name / 'slaves' / os.path.basename(under))
	block = tmp_path / 'sys' / 'dev' / 'block'
	block.mkdir(parents=True)
	for number, device in (('8:0', 'sda'), ('8:1', 'sda/sda1'), ('259:0', 'nvme0n1'), ('253:0', 'dm-0'), ('253:1', 'dm-1')):
		os.symlink(devices / device, block / number)
	monkeypatch.setattr(rv, 'SYS_DEV_BLOCK_PATH', str(block))


def mounts(monkeypatch, table, branches=None):
	monkeypatch.setattr(rv, 'read_mount_table', lambda: [('/', (b'1', b'253:1', b'/', b'/dev/root', b'ext4'))] +
		[(point, (str(i).encode(), number.encode(), b'/', b'src', fstype)) for i, (point, number, fstype) in enumerate(table, 2)])
	monkeypatch.setattr(rv, 'read_pool_branches', lambda pool: branches[pool])


@pytest.mark.parametrize('vault, threads, why', [
	('/rct/ssd/v', 2, 'auto: /rct/ssd/v is on an SSD'),
	('/rct/hdd/v', 8, 'auto: /rct/hdd/v is on a hard disk'),
	('/rct/dm_hdd/v', 8, 'auto: /rct/dm_hdd/v is on a hard disk'),
	('/rct/dm_ssd/v', 2, 'auto: /rct/dm_ssd/v is on an SSD'),
	('/rct/pool/v', 8, 'auto: /rct/b2 of pool /rct/pool is a hard disk'),
	('/rct/ssd_pool/v', 2, 'auto: every disk of pool /rct/ssd_pool is an SSD'),
])
def test_auto_goes_by_the_vaults_disks(tmp_path, monkeypatch, vault, threads, why):
	fake_sysfs(tmp_path, monkeypatch)
	mounts(monkeypatch, [('/rct/ssd', '259:0', b'f2fs'), ('/rct/hdd', '8:1', b'xfs'), ('/rct/dm_hdd', '253:0', b'xfs'), ('/rct/dm_ssd', '253:1', b'ext4'),
		('/rct/b1', '259:0', b'f2fs'), ('/rct/b2', '8:0', b'xfs'), ('/rct/pool', '0:50', rv.MERGERFS_FSTYPE), ('/rct/ssd_pool', '0:51', rv.MERGERFS_FSTYPE)],
		{'/rct/pool': ['/rct/b1', '/rct/b2'], '/rct/ssd_pool': ['/rct/b1', '/rct/ssd']})
	assert rv.copy_threads_auto(vault) == (threads, why)


@pytest.mark.parametrize('vault, reason', [
	('/rct/nfs/v', 'is on no disk'),
	('/rct/gone/v', 'No such file'),
	('/rct/pool/v', 'cannot be listed'),
])
def test_auto_that_cannot_tell_takes_two_and_says_why(tmp_path, monkeypatch, vault, reason):
	fake_sysfs(tmp_path, monkeypatch)
	mounts(monkeypatch, [('/rct/nfs', '0:60', b'nfs4'), ('/rct/gone', '8:99', b'xfs'), ('/rct/pool', '0:50', rv.MERGERFS_FSTYPE)], {})
	def unlisted(pool):
		raise OSError(5, 'Input/output error')
	monkeypatch.setattr(rv, 'read_pool_branches', unlisted)
	threads, why = rv.copy_threads_auto(vault)
	assert threads == rv.SSD_COPY_THREADS == 2 and why.startswith(f'auto: cannot tell the disks of {vault}: ') and reason in why


def test_auto_without_a_mount_table_takes_two(monkeypatch):
	def unreadable():
		raise OSError(2, 'No such file or directory')
	monkeypatch.setattr(rv, 'read_mount_table', unreadable)
	assert rv.copy_threads_auto('/v')[0] == 2


# --- the count reaches the copy and the prune ---

@pytest.fixture
def logged(monkeypatch):
	lines = []
	real = rv.backuperTeeLogToTl
	def record(path, message, **kwargs):
		lines.append(str(message))
		return real(path, message, **kwargs)
	monkeypatch.setattr(rv, 'backuperTeeLogToTl', record)
	return lines


def three_backups(job, **kwargs):
	seed_monitor(job, {'a': 'a', 'd/b': 'b', 'keep': 'k'})
	run_backup(job, keep_n_versions=2, **kwargs)
	for i in (1, 2):
		with open(os.path.join(job.monitor, 'keep'), 'w') as f:
			f.write(f'v{i}')
		versions = run_backup(job, OrderedDict([event_entry(job, 'keep', 'modify')]), keep_n_versions=2, **kwargs)
	return versions


def test_the_count_reaches_the_copy_and_the_prune(job, logged):
	versions = three_backups(job, copy_threads=3)
	assert len(versions) == 2
	assert [line for line in logged if line.startswith('Made the referenced copy of ')] and all(line.endswith(', 3 threads')
		for line in logged if line.startswith('Made the referenced copy of '))
	pruned = [line for line in logged if line.startswith('Pruned ')]
	assert pruned and pruned[0].endswith(', 3 threads')


def test_one_thread_runs_without_a_pool(job, logged, monkeypatch):
	real = rv.ThreadPoolExecutor
	def pool(max_workers=None, *args, **kwargs):
		# the comparisons keep their own pools: only the copy's and the prune's are counted
		pool.sizes.append(max_workers)
		return real(max_workers, *args, **kwargs)
	pool.sizes = []
	monkeypatch.setattr(rv, 'ThreadPoolExecutor', pool)
	versions = three_backups(job, copy_threads=1)
	assert len(versions) == 2
	assert 1 not in pool.sizes and rv.REFERENCED_COPY_THREADS not in pool.sizes, pool.sizes
	assert any(line.endswith(', 1 thread') for line in logged if line.startswith('Made the referenced copy of '))
	assert any(line.endswith(', 1 thread') for line in logged if line.startswith('Pruned '))
	assert os.path.isfile(os.path.join(versions[0], 'a')) and not os.path.islink(os.path.join(versions[0], 'a'))


def test_in_row_order_without_a_pool_works_and_handles_in_order():
	got = []
	rv.in_row_order(None, range(5), lambda row: row * 2, lambda row, outcome: got.append((row, outcome)), None)
	assert got == [(0, 0), (1, 2), (2, 4), (3, 6), (4, 8)]
