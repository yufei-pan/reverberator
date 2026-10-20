import fcntl
import os
import shutil
from collections import OrderedDict
import pytest
import TSVZ
import reverberator as rv
from tests.harness import seed_monitor, run_backup, event_entry, write_rule, rule_row, write_committed_version

pytestmark = pytest.mark.unit

T0 = '2021-01-01_00-00-00_-0800'
T1 = '2021-01-02_00-00-00_-0800'
T2 = '2021-01-03_00-00-00_-0800'


@pytest.fixture(autouse=True)
def _fast(poll_fast):
	return poll_fast


def write(job, rel, content):
	path = os.path.join(job.monitor, rel)
	os.makedirs(os.path.dirname(path), exist_ok=True)
	with open(path, 'w', encoding='utf-8') as f:
		f.write(content)


def backup(job, *entries, **kwargs):
	'''One backup of the entries, each (rel, event) or (rel, 'move', source rel).'''
	return run_backup(job, OrderedDict(event_entry(job, *entry) for entry in entries), **kwargs)


def versions(job):
	return rv.list_versions(job.job_vault)


def hist(job, rel):
	return rv.file_history(job.job_vault, versions(job), job.monitor, rel)


def folder_hist(job, rel, **kwargs):
	return rv.folder_history(job.job_vault, versions(job), job.monitor, rel, **kwargs)


def events(rows):
	return [(row.version.number, row.event) for row in rows]


def moves(rows):
	return [(row.version.number, row.event, row.source) for row in rows]


def state_dir(tmp_path):
	return str(tmp_path / 'state')


def history(tmp_path, capsys, path, *extra):
	# what building the vault logged is not the command's output
	capsys.readouterr()
	code = rv.run_command(['history', path, '--rule', str(tmp_path / 'rule.tsv'), '--state_dir', state_dir(tmp_path), *extra])
	captured = capsys.readouterr()
	return code, captured.out, captured.err


def at(job, number):
	return rv.show_time({v.number: v for v in versions(job)}[number].timestamp)


def a_txt_lifetime(job):
	'''V0 seed keep.txt (and the folder b); V1 create a.txt; V2 modify a.txt; V3 move a.txt -> b/a.txt; V4 delete b/a.txt.'''
	seed_monitor(job, {'keep.txt': 'k', 'b/': None})
	run_backup(job)
	write(job, 'a.txt', 'a1')
	backup(job, ('a.txt', 'create'))
	write(job, 'a.txt', 'a22')
	backup(job, ('a.txt', 'modify'))
	os.rename(f'{job.monitor}/a.txt', f'{job.monitor}/b/a.txt')
	backup(job, ('b/a.txt', 'move', 'a.txt'))
	os.remove(f'{job.monitor}/b/a.txt')
	backup(job, ('b/a.txt', 'delete'))


def test_file_history_create_modify_move_delete(job):
	a_txt_lifetime(job)
	assert [(r.version.number, r.event) for r in hist(job, 'a.txt')] == [(3, 'moved_away'), (2, 'modify'), (1, 'create')]
	assert [(r.version.number, r.event) for r in hist(job, 'b/a.txt')] == [(4, 'delete'), (3, 'move')]
	away, modified, created = hist(job, 'a.txt')
	assert (away.source, away.size) == (f'{job.monitor}/b/a.txt', None)
	assert (modified.size, created.size, modified.source, created.source) == (3, 2, None, None)
	deleted, moved = hist(job, 'b/a.txt')
	assert (moved.source, moved.size) == (f'{job.monitor}/a.txt', 3)
	assert (deleted.source, deleted.size) == (None, None)
	assert all(row.counts is None and row.files is None for row in hist(job, 'a.txt') + hist(job, 'b/a.txt'))
	assert rv.path_kind(job.job_vault, versions(job), job.monitor, 'a.txt') == 'file'
	assert rv.path_kind(job.job_vault, versions(job), job.monitor, 'b') == 'folder'
	assert rv.path_kind(job.job_vault, versions(job), job.monitor, 'nothing') is None


def test_attribute_change_is_listed(job):
	seed_monitor(job, {'a.txt': 'a'})
	run_backup(job)
	os.chmod(f'{job.monitor}/a.txt', 0o600)
	v1 = backup(job, ('a.txt', 'attrib'))[-1]
	# with Only Sync Attributes the version holds a link to the shared copy: only the change list shows the change
	assert os.path.islink(os.path.join(v1, 'a.txt'))
	rows = hist(job, 'a.txt')
	assert events(rows) == [(1, 'attrib'), (0, 'oldest')]
	assert rows[0].size == 1


def test_oldest_kept_copy(job):
	seed_monitor(job, {'a.txt': 'a', 'keep.txt': 'k'})
	run_backup(job)
	write(job, 'keep.txt', 'k1')
	backup(job, ('keep.txt', 'modify'))
	rows = hist(job, 'a.txt')
	assert events(rows) == [(0, 'oldest')] and rows[-1].size == 1
	write(job, 'a.txt', 'a22')
	backup(job, ('a.txt', 'modify'))
	# V0 is pruned: the oldest kept version now holds the real copy
	write(job, 'keep.txt', 'k3')
	backup(job, ('keep.txt', 'modify'), keep_n_versions=3)
	assert [v.number for v in versions(job)] == [1, 2, 3]
	rows = hist(job, 'a.txt')
	assert events(rows) == [(2, 'modify'), (1, 'oldest')]
	assert (rows[0].size, rows[1].size) == (3, 1)


def test_folder_history_counts_and_files(job):
	seed_monitor(job, {'proj/a.py': 'a', 'proj/b.py': 'b', 'other.txt': 'o'})
	run_backup(job)
	write(job, 'proj/a.py', 'a1')
	write(job, 'proj/c.py', 'c')
	os.remove(f'{job.monitor}/proj/b.py')
	write(job, 'other.txt', 'o1')
	backup(job, ('proj/a.py', 'modify'), ('proj/c.py', 'create'), ('proj/b.py', 'delete'), ('other.txt', 'modify'))
	write(job, 'other.txt', 'o2')
	backup(job, ('other.txt', 'modify'))
	write(job, 'proj/sub/d.py', 'd')
	os.chmod(f'{job.monitor}/proj/a.py', 0o600)
	backup(job, ('proj/sub/', 'create'), ('proj/a.py', 'attrib'))
	rows = folder_hist(job, 'proj')
	assert events(rows) == [(3, 'changed'), (1, 'changed'), (0, 'oldest')]
	assert rows[0].counts == {'create': 1, 'modify': 0, 'attrib': 1, 'move': 0, 'delete': 0}
	assert rows[0].files == [('create', 'sub/'), ('attrib', 'a.py')]
	assert rows[1].counts == {'create': 1, 'modify': 1, 'attrib': 0, 'move': 0, 'delete': 1}
	assert rows[1].files == [('modify', 'a.py'), ('create', 'c.py'), ('delete', 'b.py')]
	assert (rows[2].counts, rows[2].files) == ({'create': 0, 'modify': 0, 'attrib': 0, 'move': 0, 'delete': 0}, [])
	assert all(row.size is None and row.source is None for row in rows)
	root = folder_hist(job, '')
	assert events(root) == [(3, 'changed'), (2, 'changed'), (1, 'changed'), (0, 'oldest')]
	assert root[1].files == [('modify', 'other.txt')]
	assert root[0].files == [('create', 'proj/sub/'), ('attrib', 'proj/a.py')]
	assert [row.files for row in folder_hist(job, 'proj', list_files=False)] == [None, None, None]
	rule = rv.ReverbRule(*rule_row(job))
	assert rv.format_history(rule, job.job_vault, rows, 'folder', True).split('\n') == [
		f'job {job.job_name}, vault {job.job_vault}',
		f'V3  {at(job, 3)}  1 created, 0 modified, 0 deleted, 1 attributes changed',
		'    create sub/',
		'    attrib a.py',
		f'V1  {at(job, 1)}  1 created, 1 modified, 1 deleted',
		'    modify a.py',
		'    create c.py',
		'    delete b.py',
		f'V0  {at(job, 0)}  oldest kept copy',
	]
	assert rv.format_history(rule, job.job_vault, rows, 'folder', False).split('\n')[1:] == [
		f'V3  {at(job, 3)}  1 created, 0 modified, 0 deleted, 1 attributes changed',
		f'V1  {at(job, 1)}  1 created, 1 modified, 1 deleted',
		f'V0  {at(job, 0)}  oldest kept copy',
	]


def test_folder_history_boundary(job):
	seed_monitor(job, {'proj/a': 'a', 'project/b': 'b'})
	run_backup(job)
	write(job, 'project/b', 'b1')
	backup(job, ('project/b', 'modify'))
	assert events(folder_hist(job, 'proj')) == [(0, 'oldest')]
	assert events(folder_hist(job, 'project')) == [(1, 'changed'), (0, 'oldest')]


def test_folder_created_moved_and_deleted_whole(job):
	# a folder created, moved or deleted as a whole has one change list row, for the folder itself
	seed_monitor(job, {'keep': 'k'})
	run_backup(job)
	write(job, 'proj/f', 'f')
	write(job, 'proj/sub/g', 'g')
	backup(job, ('proj/', 'create'))
	os.rename(f'{job.monitor}/proj', f'{job.monitor}/moved')
	backup(job, ('moved/', 'move', 'proj/'))
	os.chmod(f'{job.monitor}/moved', 0o700)
	backup(job, ('moved/', 'attrib'))
	shutil.rmtree(f'{job.monitor}/moved')
	backup(job, ('moved/', 'delete'))
	m = job.monitor
	assert moves(folder_hist(job, 'proj')) == [(2, 'moved_away', f'{m}/moved'), (1, 'create', None)]
	moved = folder_hist(job, 'moved')
	assert moves(moved) == [(4, 'delete', None), (3, 'attrib', None), (2, 'move', f'{m}/proj')]
	# the folder's own row is not counted under it
	assert all(not any(row.counts.values()) and row.files == [] for row in moved)
	assert moves(folder_hist(job, 'moved/sub')) == [(4, 'delete', None), (2, 'move', f'{m}/proj/sub')]
	# the files went along with their folder
	assert moves(hist(job, 'moved/sub/g')) == [(4, 'delete', None), (2, 'move', f'{m}/proj/sub/g')]
	assert moves(hist(job, 'proj/sub/g')) == [(2, 'moved_away', f'{m}/moved/sub/g'), (1, 'create', None)]
	rule = rv.ReverbRule(*rule_row(job))
	assert rv.format_history(rule, job.job_vault, moved, 'folder', True).split('\n')[1:] == [
		f'V4  {at(job, 4)}  deleted',
		f'V3  {at(job, 3)}  attributes changed',
		f'V2  {at(job, 2)}  moved from {m}/proj',
	]


def test_history_of_versions_without_change_rows(job):
	# the version folders are the truth: a real copy is a change, a link chained to the same path is not
	write_committed_version(job, 0, {'a': 'x'}, timestamp=T0, current=False)
	write_committed_version(job, 1, {'a': 'xy'}, timestamp=T1, current=False)
	v2 = write_committed_version(job, 2, {}, timestamp=T2)
	os.symlink(f'../V1--{T1}/a', os.path.join(v2, 'a'))
	# a chain link to a path the version below does not hold
	os.symlink(f'../V1--{T1}/gone', os.path.join(v2, 'b'))
	assert [(r.version.number, r.event, r.size) for r in hist(job, 'a')] == [(1, 'changed', 2), (0, 'oldest', 1)]
	assert [(r.version.number, r.event, r.size) for r in hist(job, 'b')] == [(2, 'changed', None)]
	assert rv.path_kind(job.job_vault, versions(job), job.monitor, 'b') == 'file'


def test_history_root_and_trailing_slash(job, tmp_path, capsys):
	seed_monitor(job, {'proj/a': 'a', 'keep': 'k'})
	run_backup(job)
	write(job, 'proj/a', 'a1')
	backup(job, ('proj/a', 'modify'))
	write_rule(job)
	assert rv.path_kind(job.job_vault, versions(job), job.monitor, '') == 'folder'
	for path in (job.monitor, job.monitor + '/', job.monitor + '/proj/', job.monitor + '/proj'):
		code, out, err = history(tmp_path, capsys, path, '--files')
		assert (code, err) == (0, '')
		lines = out.split('\n')
		assert lines[1] == f'V1  {at(job, 1)}  0 created, 1 modified, 0 deleted'
		assert lines[2] == ('    modify proj/a' if path.rstrip('/') == job.monitor else '    modify a')
		assert lines[3] == f'V0  {at(job, 0)}  oldest kept copy'


def test_history_never_backed_up(job, tmp_path, capsys):
	skip_file = tmp_path / 'skip.txt'
	skip_file.write_text('build/\n')
	seed_monitor(job, {'keep': 'k', 'build/x': 'x'})
	run_backup(job, skip_list=rv.SkipList(job.monitor, ['build/']))
	write_rule(job, skip_list_file=str(skip_file))
	code, out, err = history(tmp_path, capsys, f'{job.monitor}/build/x')
	assert (code, err) == (0, '')
	assert out.split('\n')[:2] == [f'job {job.job_name}, vault {job.job_vault}',
		f'{job.monitor}/build/x was never backed up; it matches the skip pattern build/']
	code, out, err = history(tmp_path, capsys, f'{job.monitor}/nothing.txt')
	assert (code, err) == (0, '')
	assert out.split('\n')[1] == f'{job.monitor}/nothing.txt was never backed up'
	# a skip list that cannot be read only leaves the pattern out
	write_rule(job, skip_list_file=str(tmp_path / 'missing.txt'))
	code, out, err = history(tmp_path, capsys, f'{job.monitor}/build/x')
	assert code == 0 and out.split('\n')[1] == f'{job.monitor}/build/x was never backed up'


def test_skip_list_deciding_pattern():
	skip = rv.SkipList('/m', ['build/', '*.tmp', '!keep.tmp', 'cache/', '!cache/keep'])
	assert skip.deciding_pattern('build/x/y', False) == 'build/'
	# the walk never goes into a skipped folder, so a pattern taking a path back below it does not count
	assert skip.deciding_pattern('cache/keep', False) == 'cache/'
	assert skip.deciding_pattern('a/b.tmp', False) == '*.tmp'
	assert skip.deciding_pattern('a/keep.tmp', False) is None
	assert (skip.deciding_pattern('build', True), skip.deciding_pattern('build', False)) == ('build/', None)
	assert skip.deciding_pattern('', True) is None
	assert rv.SkipList('/m').deciding_pattern('a', False) is None


def test_history_streams_change_lists(job, tmp_path, capsys, monkeypatch):
	a_txt_lifetime(job)
	write_rule(job)
	for name in ('readTabularFile', 'readTSV'):
		reader = getattr(TSVZ, name)

		def no_change_lists(path, *args, reader=reader, **kwargs):
			if rv.CONTENT_FILE_EXTENSION_NAME in str(path):
				raise RuntimeError(f'a change list was loaded whole: {path}')
			return reader(path, *args, **kwargs)
		monkeypatch.setattr(TSVZ, name, no_change_lists)
	read = []
	iter_change_list = rv.iter_change_list
	monkeypatch.setattr(rv, 'iter_change_list', lambda path: read.append(path) or iter_change_list(path))
	newer = sorted(version.change_list for version in versions(job)[1:])
	for path, extra in ((f'{job.monitor}/a.txt', ()), (job.monitor, ('--files',))):
		read.clear()
		code, out, err = history(tmp_path, capsys, path, *extra)
		assert (code, err) == (0, '')
		# each change list once, and the oldest version's not at all: it is shown as the oldest copy, not as a change
		assert sorted(read) == newer
	assert f'V3  {at(job, 3)}  0 created, 0 modified, 0 deleted, 1 moved' in out


def test_history_command_output(job, tmp_path, capsys):
	a_txt_lifetime(job)
	write_rule(job)
	code, out, err = history(tmp_path, capsys, f'{job.monitor}/a.txt')
	assert (code, err) == (0, '')
	assert out.split('\n') == [
		f'job {job.job_name}, vault {job.job_vault}',
		f'V3  {at(job, 3)}  moved to {job.monitor}/b/a.txt',
		f'V2  {at(job, 2)}  modified  {rv.show_size(3)}',
		f'V1  {at(job, 1)}  created  {rv.show_size(2)}',
		'',
	]
	code, out, err = history(tmp_path, capsys, 'b/a.txt', '--job', job.job_name)
	assert (code, err) == (0, '')
	assert out.split('\n')[1:] == [
		f'V4  {at(job, 4)}  deleted',
		f'V3  {at(job, 3)}  moved from {job.monitor}/a.txt  {rv.show_size(3)}',
		'',
	]


def test_history_labels():
	version = rv.KeptVersion(7, '/v/V7', 'V7', 0.0, 0, 0, '/v/V7.nsv')
	labels = [rv.history_label(rv.HistoryRow(version, event, None, source, None, None)) for event, source in (
		('create', None), ('modify', None), ('attrib', None), ('move', '/m/old'), ('moved_away', '/m/new'),
		('delete', None), ('changed', None), ('oldest', None))]
	assert labels == ['created', 'modified', 'attributes changed', 'moved from /m/old', 'moved to /m/new', 'deleted',
		'changed', 'oldest kept copy']


def snapshot(top):
	found = {}
	for folder, names, files in os.walk(top):
		for name in names + files:
			path = os.path.join(folder, name)
			st = os.lstat(path)
			found[path] = (st.st_mode, st.st_size, st.st_mtime_ns, os.readlink(path) if os.path.islink(path) else None)
	return found


def test_history_writes_nothing(job, tmp_path, capsys):
	a_txt_lifetime(job)
	write_rule(job)
	before = snapshot(job.vault), snapshot(job.monitor), open(job.rule_path, 'rb').read()
	for path, extra in ((f'{job.monitor}/a.txt', ()), (job.monitor, ('--files',)), (f'{job.monitor}/b', ()), (f'{job.monitor}/none', ())):
		assert history(tmp_path, capsys, path, *extra)[0] == 0
	# no manifest opened (sqlite would leave files beside it), nothing in the vault or the rule file touched
	assert (snapshot(job.vault), snapshot(job.monitor), open(job.rule_path, 'rb').read()) == before
	assert os.listdir(state_dir(tmp_path)) == [f'job-{job.job_name}.restore.lock']


def test_history_holds_the_restore_lock_while_reading(job, tmp_path, capsys, monkeypatch):
	a_txt_lifetime(job)
	write_rule(job)
	held = []
	list_versions = rv.list_versions

	def checking(job_vault):
		fd = os.open(rv.restore_lock_path(job.job_name, state_dir(tmp_path)), os.O_RDWR)
		try:
			fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
			held.append(False)
		except BlockingIOError:
			held.append(True)
		finally:
			os.close(fd)
		return list_versions(job_vault)
	monkeypatch.setattr(rv, 'list_versions', checking)
	assert history(tmp_path, capsys, f'{job.monitor}/a.txt')[0] == 0
	assert held == [True]


def test_history_lock_it_cannot_take_is_an_error(job, tmp_path, capsys, monkeypatch):
	a_txt_lifetime(job)
	write_rule(job)

	def refuse(self):
		raise PermissionError(13, 'Permission denied', rv.restore_lock_path(self.job_name, self.state_dir))
	monkeypatch.setattr(rv.RestoreLock, '__enter__', refuse)
	code, out, err = history(tmp_path, capsys, f'{job.monitor}/a.txt')
	assert (code, out) == (rv.EXIT_COMMAND_FAILED, '')
	assert 'restore lock' in err and 'Permission denied' in err and 'Traceback' not in err


def test_history_vault_it_cannot_read_is_an_error(job, tmp_path, capsys, monkeypatch):
	a_txt_lifetime(job)
	write_rule(job)

	def unreadable(job_vault):
		raise OSError(107, 'Transport endpoint is not connected', job_vault)
	monkeypatch.setattr(rv, 'list_versions', unreadable)
	code, out, err = history(tmp_path, capsys, f'{job.monitor}/a.txt')
	assert (code, out) == (rv.EXIT_COMMAND_FAILED, '')
	assert f'The vault {job.job_vault} cannot be read: ' in err and 'not connected' in err


def test_history_of_a_stale_vault_mount_is_an_error(job, tmp_path, capsys, monkeypatch):
	a_txt_lifetime(job)
	write_rule(job)
	real_stat = os.stat

	def stale(path, *args, **kwargs):
		if str(path) == job.job_vault:
			raise OSError(107, 'Transport endpoint is not connected', path)
		return real_stat(path, *args, **kwargs)
	monkeypatch.setattr(os, 'stat', stale)
	code, out, err = history(tmp_path, capsys, f'{job.monitor}/a.txt')
	assert (code, out) == (rv.EXIT_COMMAND_FAILED, '')
	assert f'The vault {job.job_vault} cannot be read: ' in err and 'not connected' in err


def test_history_says_when_the_vault_is_not_there(job, tmp_path, capsys):
	a_txt_lifetime(job)
	write_rule(job)
	# the vault's disk not mounted: its mount point is an empty folder
	shutil.rmtree(job.vault)
	os.makedirs(job.vault)
	code, out, err = history(tmp_path, capsys, f'{job.monitor}/a.txt')
	assert (code, out) == (rv.EXIT_COMMAND_FAILED, '')
	assert err == f'The vault {job.job_vault} is not there (is its disk mounted?)\n'
	# a vault that is there with no versions yet: nothing was backed up
	os.makedirs(job.job_vault)
	code, out, err = history(tmp_path, capsys, f'{job.monitor}/a.txt')
	assert (code, err) == (0, '')
	assert out.split('\n')[1] == f'{job.monitor}/a.txt was never backed up'


def test_folder_history_counts_what_moved_out_as_deleted(job):
	seed_monitor(job, {'proj/a': 'a', 'proj/sub/b': 'b', 'proj/keep': 'k', 'other/': None})
	run_backup(job)
	os.rename(f'{job.monitor}/proj/a', f'{job.monitor}/other/a')
	backup(job, ('other/a', 'move', 'proj/a'))
	os.rename(f'{job.monitor}/proj/sub', f'{job.monitor}/other/sub')
	backup(job, ('other/sub/', 'move', 'proj/sub/'))
	rows = folder_hist(job, 'proj')
	assert events(rows) == [(2, 'changed'), (1, 'changed'), (0, 'oldest')]
	assert [(row.counts['delete'], row.files) for row in rows[:2]] == [(1, [('moved_away', 'sub/')]), (1, [('moved_away', 'a')])]
	assert [(row.counts['move'], row.files) for row in folder_hist(job, 'other')[:2]] == [(1, [('move', 'sub/')]), (1, [('move', 'a')])]
	rule = rv.ReverbRule(*rule_row(job))
	assert rv.format_history(rule, job.job_vault, rows, 'folder', True).split('\n')[1:5] == [
		f'V2  {at(job, 2)}  0 created, 0 modified, 1 deleted',
		'    moved_away sub/',
		f'V1  {at(job, 1)}  0 created, 0 modified, 1 deleted',
		'    moved_away a',
	]


def test_history_shows_odd_names_escaped(job, tmp_path, capsys):
	# monitored names are anyone's to choose: a name must not drive the terminal or pass for another line
	seed_monitor(job, {'keep': 'k'})
	run_backup(job)
	write(job, 'evil\x1b[31m.txt', 'e')
	backup(job, ('evil\x1b[31m.txt', 'create'))
	os.rename(f'{job.monitor}/evil\x1b[31m.txt', f'{job.monitor}/two\nlines.txt')
	backup(job, ('two\nlines.txt', 'move', 'evil\x1b[31m.txt'))
	write_rule(job)
	code, out, err = history(tmp_path, capsys, job.monitor, '--files')
	assert (code, err) == (0, '')
	assert out.split('\n')[1:5] == [
		f'V2  {at(job, 2)}  0 created, 0 modified, 0 deleted, 1 moved',
		'    move two\\x0alines.txt',
		f'V1  {at(job, 1)}  1 created, 0 modified, 0 deleted',
		'    create evil\\x1b[31m.txt',
	]
	code, out, err = history(tmp_path, capsys, f'{job.monitor}/two\nlines.txt')
	assert (code, err) == (0, '')
	assert out.split('\n')[1] == f'V2  {at(job, 2)}  moved from {job.monitor}/evil\\x1b[31m.txt  {rv.show_size(1)}'
	code, out, err = history(tmp_path, capsys, f'{job.monitor}/never\x1b]0;title\x07')
	assert code == 0 and out.split('\n')[1] == f'{job.monitor}/never\\x1b]0;title\\x07 was never backed up'
	# and what a command refuses with
	code, out, err = history(tmp_path, capsys, '/elsewhere/\x1b[2J')
	assert code == rv.EXIT_USAGE and err.startswith('/elsewhere/\\x1b[2J is not under')
	assert '\x1b' not in out + err


def test_history_prints_a_name_that_is_not_utf8(job, tmp_path, capsys):
	name = os.fsdecode(b'bad\xff.txt')
	write_committed_version(job, 0, {'keep': 'k'}, timestamp=T0, current=False)
	v1 = write_committed_version(job, 1, {'keep': 'k'}, timestamp=T1)
	with open(os.path.join(os.fsencode(v1), b'bad\xff.txt'), 'w') as f:
		f.write('x')
	change_list = versions(job)[1].change_list
	with open(change_list, 'ab') as f:
		f.write(os.fsencode(job.monitor) + b'/bad\xff.txt\x002021-01-02T00:00:00\x00create\x00None\n')
	write_rule(job)
	code, out, err = history(tmp_path, capsys, job.monitor, '--files')
	assert (code, err) == (0, '')
	assert '    create bad\\xff.txt' in out.split('\n')
	code, out, err = history(tmp_path, capsys, f'{job.monitor}/{name}')
	assert (code, err) == (0, '')
	assert out.split('\n')[1] == f'V1  {at(job, 1)}  created  {rv.show_size(1)}'
	code, out, err = history(tmp_path, capsys, f'{job.monitor}/other{name}')
	assert code == 0 and out.split('\n')[1] == f'{job.monitor}/otherbad\\xff.txt was never backed up'
