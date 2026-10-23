import errno
from collections import OrderedDict
import os
import pytest
import TSVZ
import reverberator as rv
from tests.harness import write_committed_version, write_change_list, run_backup, seed_monitor

pytestmark = pytest.mark.unit

T0 = '2021-01-01_00-00-00_-0800'
T1 = '2021-01-02_00-00-00_-0800'
V0 = f'V0--{T0}'


@pytest.fixture(autouse=True)
def _fresh_folders():
	# conftest forgets the versions' moves for each test
	rv.REAL_VAULT_FOLDERS.clear()


def two_versions(job, v0_tree, v1_tree, rows, monitor=None):
	'''V0 holding v0_tree, and V1 holding v1_tree with rows as its change list.'''
	v0 = write_committed_version(job, 0, v0_tree, timestamp=T0, current=False)
	v1 = write_committed_version(job, 1, v1_tree, timestamp=T1, rows=rows, monitor=monitor)
	return v0, v1


def link(v1, rel, text):
	os.symlink(text, os.path.join(v1, rel))
	return os.path.join(v1, rel)


def hop(job, v1, rel, moves=None):
	'''vault_chain_hop() of V1's link at rel, with V1's committed moves unless moves is given.'''
	path = os.path.join(v1, rel)
	if moves is None:
		moves = rv.VersionMoves.of_committed(job.job_vault, v1, job.monitor)
	return rv.vault_chain_hop(job.job_vault, path, os.readlink(path), moves)


def hop_or_cannot_tell(job, v1, rel, monitor):
	try:
		return hop(job, v1, rel, rv.VersionMoves.of_committed(job.job_vault, v1, monitor))
	except rv.UnexplainedChainLink as e:
		# the hop the text names, for pruning and reading to follow
		assert e.target == rv.strict_chain_hop(job.job_vault, os.path.join(v1, rel), os.readlink(os.path.join(v1, rel)))
		return 'cannot tell'


def no_rows_read(monkeypatch):
	def refuse(path):
		raise AssertionError(f'read {path}')
	monkeypatch.setattr(rv, 'iter_change_list', refuse)


def test_an_unmoved_link_at_its_own_depth_is_a_chain_link(job, monkeypatch):
	v0, v1 = two_versions(job, {'a/x': 'x', 'y': 'y'}, {'a/': None, 'other': 'o'}, [('other', 'modify', None)])
	link(v1, 'a/x', f'../../{V0}/a/x')
	link(v1, 'y', f'../{V0}/y')
	# the text the referenced copy writes needs no rows
	no_rows_read(monkeypatch)
	assert hop(job, v1, 'a/x') == f'{v0}/a/x'
	assert hop(job, v1, 'y') == f'{v0}/y'


@pytest.mark.parametrize('ups', ['../', '../../'])
def test_a_user_link_naming_another_rel_is_not_a_chain_link(job, ups):
	# the repro 1.1 link: a/U names V0's D/secret, at one ../ (the kernel's own reading stays in V1) or at a/U's depth
	v0, v1 = two_versions(job, {'D/secret': 's', 'keep': 'k'}, {'a/': None, 'keep': 'k'}, [('a/', 'create', None)])
	link(v1, 'a/U', f'{ups}{V0}/D/secret')
	assert hop(job, v1, 'a/U') is None
	# so is a move that took D/secret anywhere else
	moves = rv.VersionMoves.applied([('D/secret', 'b/secret', False)])
	assert hop(job, v1, 'a/U', moves) is None


MOVED = {
	'file': ({'a/x': 'x'}, {'deep/er/': None}, [('deep/er/x', 'move', 'a/x')], 'deep/er/x', 'a/x'),
	'folder': ({'sub/inner/y': 'y'}, {'deep/sub/inner/': None}, [('deep/sub/', 'move', 'sub/')], 'deep/sub/inner/y', 'sub/inner/y'),
	'two_moves': ({'a/x': 'x'}, {'b/': None, 'c/': None}, [('b/', 'move', 'a/'), ('c/x', 'move', 'b/x')], 'c/x', 'a/x'),
	'mkdir_and_mv': ({'gone': 'g'}, {'d/': None}, [('d/', 'create', None), ('d/came', 'move', 'gone')], 'd/came', 'gone'),
}


@pytest.mark.parametrize('case', sorted(MOVED))
def test_a_moved_link_is_a_chain_link_when_the_moves_take_it_there(job, case, monkeypatch):
	v0_tree, v1_tree, rows, rel, named = MOVED[case]
	v0, v1 = two_versions(job, v0_tree, v1_tree, rows)
	# retargeted to its new depth, and as a failed retarget or a daemon before 0.39 left it
	link(v1, rel, os.path.relpath(f'{v0}/{named}', os.path.dirname(f'{v1}/{rel}')))
	old_depth = 'old_' + os.path.basename(rel)
	link(v1, os.path.join(os.path.dirname(rel), old_depth), '../' * (named.count('/') + 1) + f'{V0}/{named}')
	moves = rv.VersionMoves.of_committed(job.job_vault, v1, job.monitor)
	assert moves.usable
	assert hop(job, v1, rel) == f'{v0}/{named}'
	# the old-depth link sits beside rel, where no move took named. A row of V1 landing on a folder above it (a moved
	# or created folder) accounts for it, so it is no chain link; with none, rows of a monitored path changed since
	# could be shifted, so that cannot be told (a user's link always has a row)
	old_rel = os.path.join(os.path.dirname(rel), old_depth)
	if case in ('folder', 'mkdir_and_mv'):
		assert moves.explains(old_rel) and hop(job, v1, old_rel) is None
	else:
		with pytest.raises(rv.UncheckedVaultLink):
			hop(job, v1, old_rel)
	os.remove(f'{v1}/{rel}')
	link(v1, rel, '../' * (named.count('/') + 1) + f'{V0}/{named}')
	assert hop(job, v1, rel) == f'{v0}/{named}'
	# the version being written gives the same answers from the replay's own list
	applied = rv.VersionMoves.applied([(source, dest, dest.endswith('/')) for dest, event, source in rows if event == 'move'])
	assert applied.usable and hop(job, v1, rel, applied) == f'{v0}/{named}'
	# the change list was parsed once, for every link and every VersionMoves of the version
	no_rows_read(monkeypatch)
	assert hop(job, v1, rel) == f'{v0}/{named}'


def test_away_and_back_with_a_failed_retarget_is_a_chain_link(job):
	# mv x d/x; mv d e; mv e/x x, the last retarget failing: x keeps the text it had at e/x
	rows = [('d/x', 'move', 'x'), ('e/', 'move', 'd/'), ('x', 'move', 'e/x')]
	v0, v1 = two_versions(job, {'x': 'x'}, {'e/': None}, rows)
	link(v1, 'x', f'../../{V0}/x')
	assert hop(job, v1, 'x') == f'{v0}/x'
	moves = rv.VersionMoves.of_committed(job.job_vault, v1, job.monitor)
	assert moves.takes('x', 'x') is True and moves.touches('x')


def test_a_depth_off_without_a_move_is_not_a_chain_link(job):
	# x has a row of its own, as the version that copied a user's link has
	v0, v1 = two_versions(job, {'x': 'x', 'y': 'y'}, {'other': 'o'}, [('x', 'create', None), ('z', 'move', 'y')])
	link(v1, 'x', f'../../{V0}/x')
	assert hop(job, v1, 'x') is None
	moves = rv.VersionMoves.of_committed(job.job_vault, v1, job.monitor)
	assert moves.takes('x', 'x') is True and not moves.touches('x')
	# with no row landing on x, shifted rows of a changed monitored path cannot be ruled out
	v2 = write_committed_version(job, 2, {'other': 'o'}, timestamp='2021-01-03_00-00-00_-0800', rows=[('other', 'modify', None)])
	os.symlink(f'../../V1--{T1}/x', f'{v2}/x')
	assert hop_or_cannot_tell(job, v2, 'x', job.monitor) == 'cannot tell'


def test_absolute_links_are_never_chain_links(job, tmp_path):
	v0, v1 = two_versions(job, {'a/x': 'x'}, {'a/': None, 'b/': None}, [('b/x', 'move', 'a/x')])
	link(v1, 'a/x', f'{v0}/a/x')
	link(v1, 'b/x', f'{v0}/a/x')
	for rel in ('a/x', 'b/x'):
		assert hop(job, v1, rel) is None
		assert hop(job, v1, rel, rv.VersionMoves.applied([('a/x', 'b/x', False)])) is None
		assert rv.strict_chain_hop(job.job_vault, f'{v1}/{rel}', f'{v0}/a/x') is None
	# rows that cannot be used fall back to the text, which never takes an absolute link either
	os.remove(rv.list_versions(job.job_vault)[1].change_list)
	rv.VERSION_MOVES.clear()
	assert hop(job, v1, 'a/x') is None
	# nor does a version since removed make one dangling
	assert rv.chain_form_missing_version(job.job_vault, f'{v1}/a/x', f'{job.job_vault}/V0--2020-01-01_00-00-00_-0800/a/x') is None


@pytest.mark.parametrize('usable', [True, False])
def test_a_link_naming_a_folder_is_not_a_chain_link(job, usable):
	rows = [('other', 'modify', None), ('M', 'move', 'E'), ('N', 'move', None)]
	v0, v1 = two_versions(job, {'D/f': 'f', 'E/f': 'f'}, {'other': 'o'}, rows if usable else [])
	# D's own chain text, a "move" from E, and a move without a source onto N: the daemon links files only, which is
	# told before any row, so a forged row cannot make pruning rename a folder onto a link
	link(v1, 'D', f'../{V0}/D')
	link(v1, 'M', f'../{V0}/E')
	link(v1, 'N', f'../{V0}/E')
	for rel in ('D', 'M', 'N'):
		assert hop(job, v1, rel) is None


def test_escalated_rows_with_a_source_are_not_moves(job):
	# git writes X.lock and renames it onto X: an escalated create of X, carrying its source
	v0, v1 = two_versions(job, {'X.lock': 'l', 'Y': 'y'}, {'Y': 'y'}, [('X', 'create', 'X.lock'), ('Z', 'modify', 'Y')])
	link(v1, 'X', f'../{V0}/X.lock')
	link(v1, 'Z', f'../{V0}/Y')
	moves = rv.VersionMoves.of_committed(job.job_vault, v1, job.monitor)
	assert moves.usable and moves.moves == []
	assert not moves.touches('X.lock') and moves.takes('X.lock', 'X') is False
	assert hop(job, v1, 'X') is None
	assert hop(job, v1, 'Z') is None


@pytest.mark.parametrize('how', ['empty', 'missing', 'unreadable', 'other_monitor'])
def test_rows_that_cannot_be_used_fall_back_to_the_text(job, how, monkeypatch):
	rows = [('deep/er/x', 'move', 'a/x'), ('deep/er/y', 'move', 'a/y')]
	monitor = os.path.join(job.root, 'old_monitor') if how == 'other_monitor' else None
	v0, v1 = two_versions(job, {'a/x': 'x', 'a/y': 'y'}, {'deep/er/': None}, [] if how == 'empty' else rows, monitor=monitor)
	change_list = rv.list_versions(job.job_vault)[1].change_list
	if how == 'missing':
		os.remove(change_list)
	elif how == 'unreadable':
		os.chmod(change_list, 0)
		if os.geteuid() == 0:
			# root reads it all the same
			def unopenable(path, *args, **kwargs):
				if os.path.abspath(path) == change_list:
					raise PermissionError(13, os.strerror(13), path)
				return open(path, *args, **kwargs)
			monkeypatch.setattr(rv, 'open', unopenable, raising=False)
	warnings = []
	real_log = rv.backuperTeeLogToTl
	def record(path, message, error=False, ok=False, warning=False, debug=False):
		if warning:
			warnings.append(message)
		return real_log(path, message, error=error, ok=ok, warning=warning, debug=debug)
	monkeypatch.setattr(rv, 'backuperTeeLogToTl', record)
	# retargeted, and at the old depth: both followed by the text alone
	link(v1, 'deep/er/x', f'../../../{V0}/a/x')
	link(v1, 'deep/er/y', f'../../{V0}/a/y')
	for _ in range(2):
		assert not rv.VersionMoves.of_committed(job.job_vault, v1, job.monitor).usable
		assert hop(job, v1, 'deep/er/x') == f'{v0}/a/x'
		assert hop(job, v1, 'deep/er/y') == f'{v0}/a/y'
	assert len(warnings) == 1 and os.path.basename(v1) in warnings[0]
	if how == 'unreadable':
		os.chmod(change_list, 0o644)


@pytest.mark.parametrize('rows,text', [
	([('deep/x', 'move', None)], f'../../{V0}/a/x'),
	([('deep/', 'move', None)], f'../../{V0}/a/x'),
	# told before the moves that do take a/x there
	([('deep/x', 'move', 'a/x'), ('deep/x', 'move', None)], f'../../{V0}/a/x'),
	# and before the rule for a link at its own path at another depth
	([('deep/x', 'move', None)], f'../../../{V0}/deep/x'),
], ids=['onto_it', 'onto_a_folder_above', 'after_a_move_there', 'own_path_depth_off'])
def test_a_move_row_without_a_source_cannot_be_told(job, rows, text):
	v0, v1 = two_versions(job, {'a/x': 'x', 'deep/x': 'x'}, {'deep/': None}, rows)
	link(v1, 'deep/x', text)
	with pytest.raises(rv.UnexplainedChainLink) as raised:
		hop(job, v1, 'deep/x')
	assert raised.value.target == rv.strict_chain_hop(job.job_vault, f'{v1}/deep/x', text)
	# one landing elsewhere tells, by the create row of deep/
	v2 = write_committed_version(job, 2, {'deep/': None}, timestamp='2021-01-03_00-00-00_-0800', rows=[('deep/', 'create', None), ('other', 'move', None)])
	os.symlink(f'../../V1--{T1}/a/x', f'{v2}/deep/x')
	assert rv.vault_chain_hop(job.job_vault, f'{v2}/deep/x', os.readlink(f'{v2}/deep/x'),
		rv.VersionMoves.of_committed(job.job_vault, v2, job.monitor)) is None


SHIFTED = {
	# the job's monitored path widened to a parent, and narrowed to a child, since V1 was written
	'widened': ('a', '', [('deep/x', 'move', 'x')], 'deep/x', 'x'),
	'narrowed': ('', 'sub', [('sub/deep/x', 'move', 'sub/x'), ('sub/', 'attrib', None)], 'sub/deep/x', 'sub/x'),
}


@pytest.mark.parametrize('case', sorted(SHIFTED))
def test_rows_of_a_changed_monitored_path_never_refuse_a_moved_chain_link(job, case):
	old, new, rows, rel, named = SHIFTED[case]
	old_monitor, new_monitor = (os.path.join(job.monitor, sub) if sub else job.monitor for sub in (old, new))
	v0, v1 = two_versions(job, {named: 'x'}, {os.path.dirname(rel) + '/': None}, rows, monitor=old_monitor)
	link(v1, rel, '../' * (rel.count('/') + 1) + f'{V0}/{named}')
	# every row starts with the new path, so the rows look usable, but each rel is shifted
	assert rv.VersionMoves.of_committed(job.job_vault, v1, new_monitor).usable
	assert hop_or_cannot_tell(job, v1, rel, new_monitor) in (f'{v0}/{named}', 'cannot tell')
	assert hop_or_cannot_tell(job, v1, rel, old_monitor) == f'{v0}/{named}'


CUT_ROW_AT = ['inside_the_monitored_path', 'inside_the_path', 'after_the_path', 'inside_the_event', 'after_the_event', 'inside_the_source']


@pytest.mark.parametrize('cut', CUT_ROW_AT)
def test_a_change_list_cut_short_falls_back_to_the_text(job, cut):
	v0, v1 = two_versions(job, {'a/x': 'x'}, {'deep/er/': None}, [('deep/', 'create', None), ('deep/er/x', 'move', 'a/x')])
	link(v1, 'deep/er/x', f'../../../{V0}/a/x')
	change_list = rv.list_versions(job.job_vault)[1].change_list
	data = open(change_list, 'rb').read()
	start = data.rindex(b'\n', 0, len(data) - 1) + 1
	fields = data[start:-1].split(b'\0')
	ends = [start + len(b'\0'.join(fields[:i + 1])) for i in range(len(fields))]
	at = {'inside_the_monitored_path': start + len(job.monitor) - 2, 'inside_the_path': ends[0] - 3, 'after_the_path': ends[0], 'inside_the_event': ends[2] - 2,
		'after_the_event': ends[2], 'inside_the_source': ends[3] - 3}[cut]
	# a crash in the middle of the append
	with open(change_list, 'wb') as f:
		f.write(data[:at])
	moves = rv.VersionMoves.of_committed(job.job_vault, v1, job.monitor)
	# told before any row is looked at, so a path cut short is not taken for one outside the monitored path
	assert not moves.usable and 'cut short' in moves.why
	assert hop(job, v1, 'deep/er/x') == f'{v0}/a/x'
	# read in full, so kept
	assert rv.VersionMoves.of_committed(job.job_vault, v1, job.monitor) is moves


@pytest.mark.parametrize('header', ['whole', 'cut'])
def test_a_version_with_two_change_lists_reads_the_one_with_rows(job, header):
	v0, v1 = two_versions(job, {'a/x': 'x'}, {'deep/': None}, [('deep/x', 'move', 'a/x')])
	# as pruning makes one when the name it works out from the recorded sizes is not there; it sorts first. One cut
	# in its header has no rows either
	empty = f'{v1}--1.00_B-1_ino{rv.CONTENT_FILE_EXTENSION_NAME}'
	write_change_list(empty, job.monitor, [])
	if header == 'cut':
		with open(empty, 'rb+') as f:
			f.truncate(10)
	assert sorted(name for name in os.listdir(job.job_vault) if name.startswith(os.path.basename(v1) + '--'))[0] == os.path.basename(empty)
	link(v1, 'deep/x', f'../../{V0}/a/x')
	moves = rv.VersionMoves.of_committed(job.job_vault, v1, job.monitor)
	assert moves.usable and moves.moves == [('a/x', 'deep/x', False)]
	assert hop(job, v1, 'deep/x') == f'{v0}/a/x'


def test_rows_under_a_monitored_path_spelled_with_dots_are_usable(job):
	# the rule's monitored path as typed, with ./ and a doubled /
	v0, v1 = two_versions(job, {'a/x': 'x'}, {'deep/': None}, [('deep/x', 'move', 'a/x')], monitor=job.monitor + '/./')
	link(v1, 'deep/x', f'../../{V0}/a/x')
	for monitor in (job.monitor, job.monitor + '/.'):
		moves = rv.VersionMoves.of_committed(job.job_vault, v1, monitor)
		assert moves.usable and moves.moves == [('a/x', 'deep/x', False)]
		assert hop(job, v1, 'deep/x', moves) == f'{v0}/a/x'


def test_a_new_change_list_is_synced_with_its_folder(job, monkeypatch):
	seed_monitor(job, {'a': 'a'})
	synced = []
	real_fsync = os.fsync
	def recording_fsync(fd):
		synced.append(os.path.realpath(f'/proc/self/fd/{fd}'))
		return real_fsync(fd)
	monkeypatch.setattr(rv.os, 'fsync', recording_fsync)
	run_backup(job)
	change_list = rv.list_versions(job.job_vault)[-1].change_list
	# the commit marker, synced before it is renamed into place, then the folder holding its name
	written = os.path.realpath(rv.unfinished_change_list_path(change_list))
	assert written in synced
	assert synced.index(os.path.realpath(job.job_vault)) > synced.index(written)


def record_monitor_paths(job, pairs):
	manifest = rv.VaultManifest(job.job_vault)
	manifest.begin()
	for number, path in pairs:
		manifest.note_monitor_path(number, path)
	manifest.commit()
	manifest.close()


COLLIDING = {
	# widened from /src/proj to /src, the repo holding a folder of its own name: the old root's own row, a row on a top
	# folder, and a modify of a top file all land on the moved link's rel or a folder above it, read under /src
	'widened_root_row': ('proj', '', [('', 'attrib', None), ('proj/b/x', 'move', 'proj/y')]),
	'widened_folder_row': ('proj', '', [('b/', 'attrib', None), ('proj/b/x', 'move', 'proj/y')]),
	'widened_file_row': ('proj', '', [('b/x', 'modify', None), ('proj/b/x', 'move', 'proj/y')]),
	# narrowed from /src to /src/proj, every row under proj/
	'narrowed': ('', 'proj', [('proj/proj/', 'attrib', None), ('proj/b/x', 'move', 'proj/y')]),
}


@pytest.mark.parametrize('case', sorted(COLLIDING))
def test_rows_are_read_under_the_monitored_path_their_version_was_written_under(job, case):
	old, new, rows = COLLIDING[case]
	old_monitor, new_monitor = (os.path.join(job.monitor, sub) if sub else job.monitor for sub in (old, new))
	v0, v1 = two_versions(job, {'proj/y': 'y'}, {'proj/b/': None, 'b/': None}, rows, monitor=old_monitor)
	link(v1, 'proj/b/x', f'../../../{V0}/proj/y')
	# with no record, the shifted rows explain the link: what a vault written before 0.44 still does
	assert hop_or_cannot_tell(job, v1, 'proj/b/x', new_monitor) is None
	record_monitor_paths(job, [(0, old_monitor), (1, old_monitor), (2, new_monitor)])
	# recorded since V1 was read, which a daemon never does
	rv.VERSION_MOVES.clear()
	assert rv.VersionMoves.of_committed(job.job_vault, v1, new_monitor).moves == [('proj/y', 'proj/b/x', False)]
	assert hop_or_cannot_tell(job, v1, 'proj/b/x', new_monitor) == f'{v0}/proj/y'
	# given by the caller, as a backup holding the manifest does
	rv.VERSION_MOVES.clear()
	moves = rv.VersionMoves.of_committed(job.job_vault, v1, new_monitor, monitor_paths=[(0, old_monitor), (2, new_monitor)])
	assert hop(job, v1, 'proj/b/x', moves) == f'{v0}/proj/y'


def test_backups_record_the_monitored_path_each_version_was_written_under(job, tmp_path):
	seed_monitor(job, {'a': 'a'})
	run_backup(job)
	open(os.path.join(job.monitor, 'a'), 'w').write('a1')
	run_backup(job)
	moved = job._replace(monitor=str(tmp_path / 'elsewhere'))
	seed_monitor(moved, {'a': 'a2'})
	run_backup(moved)
	manifest = rv.VaultManifest(job.job_vault)
	try:
		assert manifest.monitor_paths == [(0, job.monitor), (2, moved.monitor)]
	finally:
		manifest.close()
	assert rv.recorded_monitor_paths(job.job_vault) == [(0, job.monitor), (2, moved.monitor)]
	# an unreadable manifest is started over, and with no record each version is read under the current path
	with open(os.path.join(job.job_vault, rv.MANIFEST_FILE_NAME), 'wb') as f:
		f.write(b'not a database' * 100)
	assert not rv.recorded_monitor_paths(job.job_vault)
	rv.VaultManifest(job.job_vault).close()
	assert rv.recorded_monitor_paths(job.job_vault) == []


def test_a_change_list_appears_whole_or_not_at_all(job, monkeypatch):
	seed_monitor(job, {'a': 'a'})
	run_backup(job)
	written = []
	real_append = TSVZ.appendLinesTabularFile
	def recording_append(path, *args, **kwargs):
		written.append(os.path.basename(path))
		return real_append(path, *args, **kwargs)
	monkeypatch.setattr(TSVZ, 'appendLinesTabularFile', recording_append)
	real_replace = os.replace
	def crashing_replace(source, dest, *args, **kwargs):
		if str(dest).endswith(rv.CONTENT_FILE_EXTENSION_NAME):
			raise OSError(errno.EIO, os.strerror(errno.EIO), dest)
		return real_replace(source, dest, *args, **kwargs)
	monkeypatch.setattr(rv.os, 'replace', crashing_replace)
	open(os.path.join(job.monitor, 'a'), 'w').write('a1')
	with pytest.raises(OSError):
		rv.do_backup(OrderedDict(), job_name=job.job_name, monitor_path=job.monitor, vault_path=job.vault,
			keep_one_complete_backup=True, only_sync_attributes=True, keep_n_versions=0, backup_size_limit='0')
	monkeypatch.undo()
	# rows go to a name no reader takes for a change list, and the crash before the rename leaves V1 uncommitted
	lists = [name for name in written if name.endswith(rv.CONTENT_FILE_EXTENSION_NAME)]
	assert lists and all(rv.parse_change_list_name(name) is None for name in lists)
	assert [version.number for version in rv.list_versions(job.job_vault)] == [0]
	# a crash, unlike the error, leaves what was written of the list: the next start removes it with the version
	v1 = [os.path.join(job.job_vault, name) for name in os.listdir(job.job_vault) if name.startswith('V1--')]
	assert len(v1) == 1
	leftover = rv.unfinished_change_list_path(f'{v1[0]}--8.00_KiB-2_ino{rv.CONTENT_FILE_EXTENSION_NAME}')
	with open(leftover, 'w') as f:
		f.write('path')
	assert [version.number for version in rv.list_versions(job.job_vault)] == [0]
	removed = rv.remove_incomplete_vault_versions(job.job_vault)
	assert [os.path.basename(path).partition('--')[0] for path in removed] == ['V1']
	assert sorted(name for name in os.listdir(job.job_vault) if name.startswith(('V1', '.V1')) ) == []


def test_unexplained_links_are_told_from_ones_that_cannot_be_looked_at(job, monkeypatch):
	v0, v1 = two_versions(job, {'a/b/x': 'x'}, {'deep/': None}, [('other', 'modify', None)])
	link(v1, 'deep/x', f'../../{V0}/a/b/x')
	with pytest.raises(rv.UnexplainedChainLink):
		hop(job, v1, 'deep/x')
	lstat = os.lstat
	def lstat_failing_on_a(path, *args, **kwargs):
		if path == f'{v0}/a':
			raise OSError(errno.EIO, os.strerror(errno.EIO), path)
		return lstat(path, *args, **kwargs)
	rv.REAL_VAULT_FOLDERS.clear()
	monkeypatch.setattr(rv.os, 'lstat', lstat_failing_on_a)
	with pytest.raises(rv.UncheckedVaultLink) as raised:
		hop(job, v1, 'deep/x')
	assert not isinstance(raised.value, rv.UnexplainedChainLink)


def test_the_moves_kept_are_bounded_by_rows_and_forgotten_with_their_version(job, monkeypatch):
	monkeypatch.setattr(rv, 'VERSION_MOVES_ROWS_KEPT', 5)
	v0 = write_committed_version(job, 0, {'a/x': 'x'}, timestamp=T0, current=False)
	versions = [write_committed_version(job, n, {'deep/': None}, timestamp=f'2021-01-0{n + 1}_00-00-00_-0800',
		rows=[('deep/', 'create', None), ('deep/x', 'move', 'a/x')]) for n in (1, 2, 3)]
	for version in versions:
		assert rv.VersionMoves.of_committed(job.job_vault, version, job.monitor).usable
	# two rows each: the oldest read goes first
	assert [key[0] for key in rv.VERSION_MOVES] == [os.path.abspath(path) for path in versions[1:]]
	rv.forget_version_moves(versions[1])
	assert [key[0] for key in rv.VERSION_MOVES] == [os.path.abspath(versions[2])]
	# one version alone over the bound is still kept, as its reader goes on asking
	monkeypatch.setattr(rv, 'VERSION_MOVES_ROWS_KEPT', 1)
	rv.VERSION_MOVES.clear()
	assert rv.VersionMoves.of_committed(job.job_vault, versions[0], job.monitor).usable
	assert len(rv.VERSION_MOVES) == 1
