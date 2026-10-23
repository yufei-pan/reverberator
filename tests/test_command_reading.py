import errno
import os
from collections import OrderedDict
import pytest
import TSVZ
import reverberator as rv
from tests.harness import seed_monitor, write_rule, rule_row, write_committed_version, run_backup, create_job, event_entry

pytestmark = pytest.mark.unit

T = '2021-01-01_00-00-00_-0800'


@pytest.fixture(autouse=True)
def _fast(poll_fast):
	return poll_fast


def more_versions(job, count):
	'''count more versions, each changing only the file keep, so a/x is chained to the version below.'''
	for i in range(count):
		with open(os.path.join(job.monitor, 'keep'), 'w') as f:
			f.write(f'k{len(os.listdir(job.job_vault))}')
		paths = run_backup(job, OrderedDict([event_entry(job, 'keep', 'modify')]))
	return paths


def three_versions(job):
	'''V0 holds the real copy of a/x, V1 and V2 chain to it.'''
	seed_monitor(job, {'a/x': 'x', 'keep': 'k'})
	run_backup(job)
	return more_versions(job, 2)


def versions_of(job):
	return rv.list_versions(job.job_vault)


def test_read_only_parse_leaves_the_rule_file_unchanged(job):
	# an 11 column rule file (header without Skip List File), signatures 'auto', blank keep_n_versions, vault missing
	missing_vault = os.path.join(job.root, 'not_made_yet')
	row = rule_row(job, mon_fs_signature='auto', vault_fs_signature='auto', keep_n_versions='')[:-1]
	row[2] = missing_vault
	with open(job.rule_path, 'w', encoding='utf-8') as f:
		f.write('\t'.join(rv.REVERB_RULE_TSV_HEADER[:-1]) + '\n' + '\t'.join(row) + '\n')
	before = open(job.rule_path, 'rb').read()
	rules = rv.parse_rules(job.rule_path, read_only=True)
	assert open(job.rule_path, 'rb').read() == before
	assert rules[0].mon_fs_signature == 'auto' and rules[0].skip_list_file == ''
	assert rules[0].vault_fs_signature == 'auto' and rules[0].keep_n_versions == '0'
	assert not os.path.exists(missing_vault)
	assert sorted(os.listdir(job.root)) == ['monitor', 'rule.tsv', 'vault']


def test_read_only_parse_raises_for_a_missing_file(tmp_path):
	with pytest.raises(rv.RuleFileError):
		rv.parse_rules(str(tmp_path / 'none.tsv'), read_only=True)


def test_read_only_parse_raises_for_an_empty_file(tmp_path):
	path = tmp_path / 'empty.tsv'
	path.write_text('\t'.join(rv.REVERB_RULE_TSV_HEADER) + '\n')
	with pytest.raises(rv.RuleFileError):
		rv.parse_rules(str(path), read_only=True)


def test_command_error_defaults_to_usage():
	error = rv.CommandError('no')
	assert (error.message, error.code, rv.EXIT_USAGE) == ('no', 2, 2)
	assert rv.CommandError('no', rv.EXIT_COMMAND_FAILED).code == 1


def test_list_versions_is_read_only(job):
	write_committed_version(job, 0, {'a': 'a'}, timestamp='2021-01-01_00-00-00_-0800')
	write_committed_version(job, 1, {'a': 'b'}, timestamp='2021-01-02_00-00-00_-0800')
	orphan = os.path.join(job.job_vault, 'V2--2021-01-03_00-00-00_-0800')
	os.makedirs(orphan)
	stray = os.path.join(job.job_vault, 'V9--2021-01-09_00-00-00_-0800--1.00_KiB-1_ino' + rv.CONTENT_FILE_EXTENSION_NAME)
	open(stray, 'w').close()
	before = sorted(os.listdir(job.job_vault))
	versions = rv.list_versions(job.job_vault)
	assert [v.number for v in versions] == [0, 1]
	assert versions[0].name == f'V0--{T}' and versions[0].path == os.path.join(job.job_vault, versions[0].name)
	assert versions[0].change_list.endswith(rv.CONTENT_FILE_EXTENSION_NAME) and os.path.isfile(versions[0].change_list)
	assert os.path.isdir(orphan) and os.path.isfile(stray)
	assert sorted(os.listdir(job.job_vault)) == before


def test_list_versions_missing_vault(tmp_path):
	assert rv.list_versions(str(tmp_path / 'nothing')) == []


def test_list_versions_reads_size_and_inodes(job):
	paths = three_versions(job)
	versions = versions_of(job)
	info = rv.get_vault_info(job.job_vault).vault_info_dict
	assert [v.number for v in versions] == [0, 1, 2]
	assert [(v.size, v.inodes, v.path) for v in versions] == [(info[n].size, info[n].inode, paths[n]) for n in range(3)]
	assert all(isinstance(v.timestamp, float) for v in versions)


def test_parse_change_list_name():
	name = f'V3--{T}--1.50_KiB-12_ino' + rv.CONTENT_FILE_EXTENSION_NAME
	parsed = rv.parse_change_list_name(name)
	assert parsed[:2] == (3, f'V3--{T}')
	assert rv.parse_change_list_name('V3--garbage' + rv.CONTENT_FILE_EXTENSION_NAME) is None
	assert rv.parse_change_list_name(f'V3--{T}') is None


def test_resolve_follows_chains(job):
	paths = three_versions(job)
	assert os.path.islink(os.path.join(paths[2], 'a/x'))
	got = rv.resolve_version_entry(job.job_vault, paths[2], 'a/x', job.monitor)
	assert got.kind == 'file' and got.path == os.path.join(paths[0], 'a/x')
	assert rv.resolve_version_entry(job.job_vault, paths[2], 'a', job.monitor).kind == 'folder'


def test_resolve_missing_entry(job):
	paths = three_versions(job)
	assert rv.resolve_version_entry(job.job_vault, paths[2], 'nothing', job.monitor).kind == 'missing'


def test_resolve_dangling_chain(job):
	paths = three_versions(job)
	os.rename(paths[1], paths[1] + '.gone')
	got = rv.resolve_version_entry(job.job_vault, paths[2], 'a/x', job.monitor)
	assert got.kind == 'dangling' and 'V1' in got.detail


def test_resolve_chain_to_a_pruned_entry_is_dangling(job):
	paths = three_versions(job)
	os.remove(os.path.join(paths[0], 'a/x'))
	got = rv.resolve_version_entry(job.job_vault, paths[2], 'a/x', job.monitor)
	assert got.kind == 'dangling' and 'a/x' in got.detail


def test_resolve_old_absolute_link_to_a_removed_version_is_a_symlink(job):
	# shaped as daemons before 0.38 linked an unchanged entry; since 0.44 no absolute link is a chain link, as no kept
	# version holds one while a user's symlink to a backed-up copy has that form
	v0 = write_committed_version(job, 0, {'a/x': 'x'}, timestamp=T, current=False)
	write_committed_version(job, 1, {'a/': None}, timestamp=T, current=False)
	v2 = write_committed_version(job, 2, {'a/': None}, timestamp=T)
	text = os.path.join(v0, 'a/x')
	os.symlink(text, os.path.join(v2, 'a/x'))
	got = rv.resolve_version_entry(job.job_vault, v2, 'a/x', job.monitor)
	assert got == ('symlink', os.path.join(v2, 'a/x'), text)
	os.rename(v0, v0 + '.gone')
	# a command runs in a process of its own, which has not seen V0's folders
	rv.REAL_VAULT_FOLDERS.clear()
	got = rv.resolve_version_entry(job.job_vault, v2, 'a/x', job.monitor)
	assert got == ('symlink', os.path.join(v2, 'a/x'), text)


def test_resolve_user_symlink(job):
	seed_monitor(job, {'lib/target': 't'})
	os.symlink('target', os.path.join(job.monitor, 'lib/x'))
	paths = run_backup(job)
	got = rv.resolve_version_entry(job.job_vault, paths[0], 'lib/x', job.monitor)
	assert got.kind == 'symlink' and got.path == os.path.join(paths[0], 'lib/x')


def test_resolve_user_symlink_shaped_like_a_chain_link_is_a_symlink(job):
	# names a version that exists, but not the one just below its own
	paths = three_versions(job)
	link = os.path.join(paths[2], 'user')
	os.symlink(f'../{os.path.basename(paths[0])}/a/x', link)
	got = rv.resolve_version_entry(job.job_vault, paths[2], 'user', job.monitor)
	assert got.kind == 'symlink' and got.path == link


def test_resolve_referenced_link(job):
	paths = three_versions(job)
	link = os.path.join(paths[2], 'ref')
	os.symlink(os.path.join(job.monitor, 'ref'), link)
	got = rv.resolve_version_entry(job.job_vault, paths[2], 'ref', job.monitor)
	assert got.kind == 'referenced'


@pytest.mark.parametrize('typed', ['{root}/./monitor', '{root}//monitor/', '{root}/monitor/../monitor'])
def test_resolve_referenced_link_for_a_monitored_path_kept_as_typed(job, typed):
	# a rule keeps a monitored path that is missing as it was typed, as it cannot be resolved
	paths = three_versions(job)
	os.symlink(os.path.join(job.monitor, 'ref'), os.path.join(paths[2], 'ref'))
	got = rv.resolve_version_entry(job.job_vault, paths[2], 'ref', typed.format(root=job.root))
	assert got.kind == 'referenced'


def test_resolve_chain_longer_than_the_kernel_limit(job):
	# V1..V45 each link to the one below, as the daemon writes them: more than the 40 links the kernel follows
	v0 = write_committed_version(job, 0, {'a/x': 'x'}, timestamp='2021-01-01_00-00-00_-0800')
	previous = v0
	for n in range(1, 46):
		folder = write_committed_version(job, n, {'a/': None}, timestamp=f'2021-01-01_00-00-{n:02d}_-0800')
		os.symlink(f'../../{os.path.basename(previous)}/a/x', os.path.join(folder, 'a/x'))
		previous = folder
	got = rv.resolve_version_entry(job.job_vault, previous, 'a/x', job.monitor)
	assert got.kind == 'file' and got.path == os.path.join(v0, 'a/x')


def test_resolve_through_a_user_folder_symlink_is_missing(job):
	# lib is a user symlink to a folder outside the vault, chained through V1 and V2
	outside = os.path.join(job.root, 'outside')
	os.makedirs(outside)
	open(os.path.join(outside, 'secret'), 'w').write('live')
	seed_monitor(job, {'keep': 'k'})
	os.symlink(outside, os.path.join(job.monitor, 'lib'))
	run_backup(job)
	paths = more_versions(job, 2)
	assert os.path.islink(os.path.join(paths[2], 'lib'))
	got = rv.resolve_version_entry(job.job_vault, paths[2], 'lib/secret', job.monitor)
	assert got.kind == 'missing' and 'lib is a symlink' in got.detail
	assert rv.resolve_version_entry(job.job_vault, paths[2], 'lib', job.monitor).kind == 'symlink'


def test_resolve_through_a_relative_user_folder_symlink_is_missing(job):
	paths = three_versions(job)
	os.symlink('a', os.path.join(paths[2], 'rel'))
	got = rv.resolve_version_entry(job.job_vault, paths[2], 'rel/x', job.monitor)
	assert got.kind == 'missing' and 'rel is a symlink' in got.detail
	assert rv.resolve_version_entry(job.job_vault, paths[2], 'a/x', job.monitor).kind == 'file'


def test_resolve_unreadable_link(job, monkeypatch):
	paths = three_versions(job)
	def refuse(*args):
		raise rv.UncheckedVaultLink(OSError(errno.EIO, 'Input/output error'))
	monkeypatch.setattr(rv, 'strict_chain_hop', refuse)
	got = rv.resolve_version_entry(job.job_vault, paths[2], 'a/x', job.monitor)
	assert got.kind == 'unreadable' and 'Input/output error' in got.detail


def test_resolve_unreadable_folder_on_the_way(job, monkeypatch):
	paths = three_versions(job)
	real_lstat = os.lstat
	def lstat(path, *args, **kwargs):
		if path == os.path.join(paths[1], 'a'):
			raise OSError(errno.EIO, 'Input/output error')
		return real_lstat(path, *args, **kwargs)
	monkeypatch.setattr(os, 'lstat', lstat)
	rv.REAL_VAULT_FOLDERS.clear()
	assert rv.resolve_version_entry(job.job_vault, paths[2], 'a/x', job.monitor).kind == 'unreadable'


def test_resolve_link_broken_by_an_old_move(job):
	# the text of a link from another folder depth, which older daemons left in place after a move
	paths = three_versions(job)
	link = os.path.join(paths[2], 'a/x')
	os.remove(link)
	os.symlink(f'../../../../{os.path.basename(paths[1])}/a/x', link)
	got = rv.resolve_version_entry(job.job_vault, paths[2], 'a/x', job.monitor)
	assert got.kind == 'file' and got.path == os.path.join(paths[0], 'a/x')


def test_iter_change_list_round_trips_names(tmp_path):
	path = str(tmp_path / 'c.nsv')
	names = ['/m/a b', '/m/café', '/m/new\nline', '/m/x<LF>y', '/m/x<sep>y', '/m/folder/']
	TSVZ.appendLinesTabularFile(path, [[n, 't', 'create', 'None'] for n in names], header=['path'] + rv.BACKUP_ENTRY_VALUES_HEADER, createIfNotExist=True, verifyHeader=True, strict=False)
	assert [row.path for row in rv.iter_change_list(path)] == names
	assert all(row.source_path is None for row in rv.iter_change_list(path))
	assert all((row.iso_time, row.event) == ('t', 'create') for row in rv.iter_change_list(path))


def test_iter_change_list_keeps_a_source_path(tmp_path):
	path = str(tmp_path / 'c.nsv')
	TSVZ.appendLinesTabularFile(path, [['/m/b ', 't', 'move', '/m/a ']], header=['path'] + rv.BACKUP_ENTRY_VALUES_HEADER, createIfNotExist=True, verifyHeader=True, strict=False)
	row, = rv.iter_change_list(path)
	assert row == rv.ChangeRow('/m/b ', 't', 'move', '/m/a ')


def test_unescape_change_list_field():
	assert rv.unescape_change_list_field('a</sep/>b</LF/>c<LF>d<sep>e ') == 'a<sep>b<LF>c\nd\0e '


@pytest.fixture
def two_jobs(tmp_path):
	top = create_job(str(tmp_path / 'one'), 'top')
	sub = create_job(str(tmp_path / 'two'), 'sub')
	os.makedirs(os.path.join(top.monitor, 'sub'))
	sub = sub._replace(monitor=os.path.join(top.monitor, 'sub'))
	rules = [rv.ReverbRule(*rule_row(top)), rv.ReverbRule(*rule_row(sub))]
	return rules, top, sub


def test_find_job_longest_prefix(two_jobs, monkeypatch):
	rules, top, sub = two_jobs
	def find(path, **kwargs):
		rule, rel = rv.find_job(rules, path, **kwargs)
		return rule.job_name, rel
	m = top.monitor
	assert find(m + '/sub/x') == ('sub', 'x')
	os.makedirs(m + '/subway')
	assert find(m + '/subway/x') == ('top', 'subway/x')
	assert find(m + '/sub/') == ('sub', '') and find(m + '/sub') == ('sub', '')
	assert find(m) == ('top', '')
	monkeypatch.chdir(m + '/sub')
	assert find('x') == ('sub', 'x')
	assert rv.find_job(rules, 'x', job_name='top')[1] == 'x'
	assert rv.job_vault_path(rules[0]) == top.job_vault
	with pytest.raises(rv.CommandError) as e:
		rv.find_job(rules, '/elsewhere')
	assert e.value.code == rv.EXIT_USAGE and m + '/sub' in e.value.message and m in e.value.message


def test_find_job_unknown_name_and_path_outside_the_job(two_jobs):
	rules, top, sub = two_jobs
	with pytest.raises(rv.CommandError) as e:
		rv.find_job(rules, 'x', job_name='nope')
	assert 'top' in e.value.message and 'sub' in e.value.message
	with pytest.raises(rv.CommandError):
		rv.find_job(rules, '/elsewhere/x', job_name='top')


def test_resolve_a_version_root_and_a_top_level_entry(job):
	paths = three_versions(job)
	got = rv.resolve_version_entry(job.job_vault, paths[2], '', job.monitor)
	assert got.kind == 'folder' and got.path == paths[2]
	got = rv.resolve_version_entry(job.job_vault, paths[2], 'keep', job.monitor)
	assert got.kind == 'file' and got.path == os.path.join(paths[2], 'keep')


def test_find_job_resolves_a_symlinked_parent(two_jobs, tmp_path):
	rules, top, sub = two_jobs
	os.symlink(top.monitor, str(tmp_path / 'link'))
	# typed through a symlink above the monitored path, the file need not exist
	for typed in (str(tmp_path / 'link/sub/x'), str(tmp_path / 'link/sub/deep/new.txt')):
		rule, rel = rv.find_job(rules, typed)
		assert (rule.job_name, rel) == ('sub', typed.partition('/sub/')[2])
	assert rv.find_job(rules, 'sub/x', job_name='top')[1] == 'sub/x'
	with pytest.raises(rv.CommandError):
		rv.find_job(rules, str(tmp_path / 'link/../elsewhere'))


def test_unescape_change_list_field_without_an_escape_reads_nothing(monkeypatch):
	class Boom:
		def sub(self, *args):
			raise AssertionError('the pattern was run')
	monkeypatch.setattr(rv, 'CHANGE_LIST_ESCAPE_PATTERN', Boom())
	assert rv.unescape_change_list_field('plain name.txt ') == 'plain name.txt '


def test_an_unnumbered_version_follows_its_whole_chain(job, monkeypatch):
	seed_monitor(job, {'a': 'x', 'k': 'k0'})
	run_backup(job)
	for number in (1, 2):
		with open(f'{job.monitor}/k', 'w') as f:
			f.write(f'k{number}')
		run_backup(job, OrderedDict([event_entry(job, 'k', 'modify')]))
	versions = rv.list_versions(job.job_vault)
	assert os.path.islink(os.path.join(versions[2].path, 'a'))
	# a version folder whose name carries no number, as the first look at it sees it (a chain link needs the number, so
	# only the bound on the hops is in question): two hops back to the real copy
	real, first = rv.vault_version_number, []
	def number(name):
		if name == versions[2].name and not first:
			first.append(name)
			return None
		return real(name)
	monkeypatch.setattr(rv, 'vault_version_number', number)
	resolved = rv.resolve_version_entry(job.job_vault, versions[2].path, 'a', job.monitor)
	assert first and (resolved.kind, resolved.path) == ('file', os.path.join(versions[0].path, 'a'))
