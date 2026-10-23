import os
import pytest
import reverberator as rv
from tests.harness import write_committed_version

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
	# the old-depth link sits beside rel, where no move took named: not a chain link
	assert hop(job, v1, os.path.join(os.path.dirname(rel), old_depth)) is None
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
	v0, v1 = two_versions(job, {'x': 'x', 'y': 'y'}, {'other': 'o'}, [('other', 'modify', None), ('z', 'move', 'y')])
	link(v1, 'x', f'../../{V0}/x')
	assert hop(job, v1, 'x') is None
	moves = rv.VersionMoves.of_committed(job.job_vault, v1, job.monitor)
	assert moves.takes('x', 'x') is True and not moves.touches('x')


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
	v0, v1 = two_versions(job, {'D/f': 'f', 'E/f': 'f'}, {'other': 'o'}, [('other', 'modify', None), ('M', 'move', 'E')] if usable else [])
	# D's own chain text, and a "move" from E: the daemon links files only
	link(v1, 'D', f'../{V0}/D')
	link(v1, 'M', f'../{V0}/E')
	assert hop(job, v1, 'D') is None
	assert hop(job, v1, 'M') is None


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


@pytest.mark.parametrize('dest', ['deep/x', 'deep/'])
def test_a_move_row_without_a_source_cannot_be_told(job, dest):
	v0, v1 = two_versions(job, {'a/x': 'x'}, {'deep/': None}, [(dest, 'move', None)])
	link(v1, 'deep/x', f'../../{V0}/a/x')
	with pytest.raises(rv.UncheckedVaultLink):
		hop(job, v1, 'deep/x')
	# one landing elsewhere tells
	v2 = write_committed_version(job, 2, {'deep/': None}, timestamp='2021-01-03_00-00-00_-0800', rows=[('other', 'move', None)])
	os.symlink(f'../../V1--{T1}/a/x', f'{v2}/deep/x')
	assert rv.vault_chain_hop(job.job_vault, f'{v2}/deep/x', os.readlink(f'{v2}/deep/x'),
		rv.VersionMoves.of_committed(job.job_vault, v2, job.monitor)) is None
