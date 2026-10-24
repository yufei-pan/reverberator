'''
pytest plugin: the ground truth for which links in a vault are the daemon's chain links, checked over the whole suite.

Every symlink made under a frame of reverberator.py is recorded by its inode and text as it is made, which a rename
keeps, by the first frame of reverberator.py or of the tests found walking up the stack (so a copy shutil makes for the
daemon is the daemon's): a link do_referenced_copy() makes with relative text is a chain link, one retarget_chain_link()
makes is what the link it replaces was, and any other the daemon makes (a copy of a user's symlink, a referenced
backup's absolute link) is a user link, as is a link no frame recorded (cp -a). One a test makes with os.symlink is left
out, as a test can forge any vault. vault_chain_hop() is judged:
- during each do_backup() and decrement_stepper() call, on every link the daemon asks it about (the replay's retargets,
  the reads, the attribute sync, the verification, the prune's walk), with the moves the daemon hands it, as it
  answers and before the daemon acts on the answer: the plugin reads nothing of its own there (no rows, no record),
  so a test that counts the daemon's reads sees only the daemon's. Moves a prune's walk is handed that are not its
  version's own fail the test too. Nothing is judged while tracemalloc traces, so a memory test measures the daemon
  alone;
- at each test's end (once its monkeypatch is undone), on every link of every kept version of each job vault under
  its tmp_path that the test backed up or pruned in this process, or that holds a link this process's daemon code
  made, with the moves read under the record the manifest holds. Vaults written by a daemon subprocess, or by the
  test alone, are not checked: no truth is known for their links.
The test fails when a daemon link is refused, or a user link accepted, unless its
chain_ground_truth_allows(kind, ..., reason=..., rels=...) marker names how; rels, a list of paths in their version,
limits the marker to them. Each kind is told again here, from the vault and the moves, not taken from the test:
- 'unusable_rows': a user link accepted by its text, as its version's rows cannot be used (a change list blank, cut,
  missing or unreadable, rows under an old monitored path, a record that cannot be read);
- 'cannot_tell': a user link the rows cannot tell (UnexplainedChainLink), which pruning and reading follow;
- 'blind_spot': a user link the rule itself takes, its text exactly its own path's chain text (or, with a move, its
  pre-move path's): the documented blind spot;
- 'refused_chain': a daemon link refused whose named version folder is gone (removed or renamed by hand);
- 'refused_by_rows': a daemon link refused with its version there, as by forged rows; it needs rels.
A link accepted in any other way ('beyond_the_rule'), or judged by another version's moves ('wrong_moves'), is never
allowed. A link that cannot be looked at (UncheckedVaultLink, an OSError) is not judged: pruning keeps the oldest
version for it. The end-of-test check puts back the caches it fills (VERSION_MOVES, VERSION_MOVES_WARNED,
REAL_VAULT_FOLDERS) and logs no warning of the daemon's. REVERB_CHAIN_GROUND_TRUTH=0 turns the plugin off.
'''
import contextlib
import os
import stat
import sys
import tracemalloc
from collections import OrderedDict
import pytest
import reverberator as rv

ENABLED = os.environ.get('REVERB_CHAIN_GROUND_TRUTH', '1').strip().lower() not in ('0', 'off', 'no', 'false')
MARKER = 'chain_ground_truth_allows'
KINDS = ('unusable_rows', 'cannot_tell', 'blind_spot', 'refused_chain', 'refused_by_rows')
TESTS_DIR = os.path.dirname(os.path.abspath(__file__)) + os.sep

# (st_dev, st_ino) -> (its truth: 'chain', 'user' or 'test', its text), for the running test
MADE = {}
# job vault -> the monitored path it was last backed up or pruned under, for the running test
MONITORS = {}
# what the running test's checks found: (where, kind, path, rel, text) for each link judged wrong
FOUND = []
TOTALS = {'links': 0, 'chain': 0, 'user': 0, 'test_made': 0, 'unchecked': 0, 'prune_calls': 0, 'prune_links': 0, 'backup_links': 0,
	'allowed': 0, 'violations': 0, 'skipped_vaults': 0, 'vaults_by_links': 0}

_real_symlink = os.symlink
_real_do_backup = rv.do_backup
_real_decrement = rv.decrement_stepper
# taken now, so a test's patch of the classifier or the record read leaves the end-of-test check alone
_real_vault_chain_hop = rv.vault_chain_hop
_real_read_record = rv.read_recorded_monitor_paths


def maker_frame():
	'''The first frame of reverberator.py or of the tests above os.symlink's caller; None for a test's.'''
	frame = sys._getframe(2)
	while frame is not None:
		name = frame.f_code.co_filename
		if name == rv.__file__:
			return frame
		if name.startswith(TESTS_DIR):
			return None
		frame = frame.f_back
	return None


def truth(st, text):
	''''chain' or 'user' for a link the test did not make, None for one it did.'''
	made = MADE.get((st.st_dev, st.st_ino))
	if made is None or made[1] != text:
		return 'user'
	return None if made[0] == 'test' else made[0]


def recording_symlink(src, dst, *args, **kwargs):
	frame = maker_frame()
	text = os.fsdecode(src)
	if frame is None:
		made = 'test'
	elif frame.f_code.co_name == 'do_referenced_copy':
		# a referenced backup's link is absolute, and no chain link
		made = 'user' if os.path.isabs(text) else 'chain'
	elif frame.f_code.co_name == 'retarget_chain_link':
		# what the link it is about to replace was, not the daemon's own verdict on it
		link_path = frame.f_locals.get('link_path')
		try:
			made = truth(os.lstat(link_path), os.readlink(link_path)) or 'test'
		except (OSError, TypeError, ValueError):
			made = 'test'
	else:
		made = 'user'
	_real_symlink(src, dst, *args, **kwargs)
	try:
		st = os.lstat(dst, dir_fd=kwargs.get('dir_fd'))
	except (OSError, TypeError, ValueError):
		return
	MADE[(st.st_dev, st.st_ino)] = (made, text)


def place(job_vault, path):
	'''(the version folder holding path, path's rel in it).'''
	vault = os.path.abspath(job_vault)
	version_name, _, rel = os.path.abspath(path)[len(vault) + 1:].partition('/')
	return os.path.join(vault, version_name), rel


def committed_moves(moves):
	'''The VersionMoves behind moves (a CommittedMoves made one already, or None), without making one.'''
	if isinstance(moves, rv.CommittedMoves):
		return vars(moves).get('_moves')
	return moves


def moves_version(moves):
	'''The version folder moves are the moves of, None for moves of no version, without reading anything.'''
	if isinstance(moves, rv.CommittedMoves):
		return os.path.abspath(vars(moves)['_version_path'])
	key = vars(moves).get('key')
	return None if key is None else key[0]


def how_accepted(job_vault, path, text, moves, reads=True):
	'''
	The kind of a user link vault_chain_hop() took, by the rule told again here: 'blind_spot' when the rule itself takes
	it, 'unusable_rows' when its version's rows cannot be used, 'cannot_tell' when they cannot tell, else None (no rule
	takes it). Without reads, rows not read yet count as none: the rule reads them before it takes a link off its own
	path.
	'''
	parsed = None if os.path.isabs(text) else rv.parse_chain_text(job_vault, text, path)
	if parsed is None:
		return None
	name, named_parts, ups = parsed
	vault = os.path.abspath(job_vault)
	target = os.path.join(vault, name, *named_parts)
	if not rv.is_real_folder_under(os.path.join(vault, name), os.path.dirname(target)):
		return None
	if os.path.isdir(target) and not os.path.islink(target):
		return None
	version, rel = place(job_vault, path)
	named = '/'.join(named_parts)
	if named == rel and ups == rel.count('/') + 1:
		return 'blind_spot'
	if not reads:
		moves = committed_moves(moves)
		if moves is None or vars(moves).get('_job_vault') is not None:
			return None
	if not moves.usable:
		return 'unusable_rows'
	verdict = moves.tells(named, rel, os.path.basename(version))[0]
	return {True: 'blind_spot', None: 'cannot_tell'}.get(verdict)


def refusal_kind(job_vault, text):
	''''refused_chain' when the version folder a chain link's text names is gone, else 'refused_by_rows'.'''
	parts = text.split('/')
	while parts and parts[0] == '..':
		parts.pop(0)
	folder = os.path.join(os.path.abspath(job_vault), parts[0]) if parts and parts[0] else None
	if folder is None or os.path.islink(folder) or not os.path.isdir(folder):
		return 'refused_chain'
	return 'refused_by_rows'


def judge(where, job_vault, path, text, moves, accepted, unexplained, reads):
	'''Judge one answer of vault_chain_hop() for the link at path with text: accepted, or not.'''
	try:
		st = os.lstat(path)
	except OSError:
		TOTALS['unchecked'] += 1
		return
	TOTALS['links'] += 1
	if where != 'end':
		TOTALS[where + '_links'] += 1
	real = truth(st, text)
	if real is None:
		TOTALS['test_made'] += 1
		return
	TOTALS[real] += 1
	version, rel = place(job_vault, path)
	if where == 'prune' and moves_version(moves) != version:
		FOUND.append((where, 'wrong_moves', path, rel, text))
	elif real == 'chain' and not accepted:
		FOUND.append((where, refusal_kind(job_vault, text), path, rel, text))
	elif real == 'user' and accepted:
		if unexplained:
			kind = 'cannot_tell'
		else:
			try:
				kind = how_accepted(job_vault, path, text, moves, reads)
			except (rv.UncheckedVaultLink, OSError):
				kind = None
		FOUND.append((where, kind or 'beyond_the_rule', path, rel, text))


@contextlib.contextmanager
def caches_kept():
	'''The daemon's caches as they were once the check is done; real folders are looked at afresh meanwhile.'''
	with rv.VERSION_MOVES_LOCK:
		moves, warned = OrderedDict(rv.VERSION_MOVES), OrderedDict(rv.VERSION_MOVES_WARNED)
	with rv.REAL_VAULT_FOLDERS_LOCK:
		folders = OrderedDict(rv.REAL_VAULT_FOLDERS)
		rv.REAL_VAULT_FOLDERS.clear()
	try:
		yield
	finally:
		with rv.VERSION_MOVES_LOCK:
			for table, kept in ((rv.VERSION_MOVES, moves), (rv.VERSION_MOVES_WARNED, warned)):
				table.clear()
				table.update(kept)
		with rv.REAL_VAULT_FOLDERS_LOCK:
			rv.REAL_VAULT_FOLDERS.clear()
			rv.REAL_VAULT_FOLDERS.update(folders)


# where the daemon's calls of vault_chain_hop() are being judged now: 'backup' or 'prune', None when they are not
JUDGING = [None]


def judged_hop(job_vault, link_path, link_text, moves):
	'''vault_chain_hop() as the daemon finds it (a test's patch of it included), each answer judged as it is given.'''
	hop, where = JUDGED_HOP[0] or _real_vault_chain_hop, JUDGING[0]
	try:
		target = hop(job_vault, link_path, link_text, moves)
	except rv.UnexplainedChainLink:
		if where is not None and not tracemalloc.is_tracing():
			judge(where, job_vault, link_path, link_text, moves, True, True, reads=False)
		raise
	if where is not None and not tracemalloc.is_tracing():
		judge(where, job_vault, link_path, link_text, moves, target is not None, False, reads=False)
	return target

# the vault_chain_hop() judged_hop() calls, while it is in place
JUDGED_HOP = [None]


@contextlib.contextmanager
def judging(where):
	'''The daemon's answers of vault_chain_hop() judged as where while in it; a prune in a backup is judged as one.'''
	installed = rv.vault_chain_hop is not judged_hop
	if installed:
		JUDGED_HOP[0] = rv.vault_chain_hop
		rv.vault_chain_hop = judged_hop
	outer = JUDGING[0]
	JUDGING[0] = where
	try:
		yield
	finally:
		JUDGING[0] = outer
		if installed:
			# a patch a test made meanwhile is left as it is
			if rv.vault_chain_hop is judged_hop:
				rv.vault_chain_hop = JUDGED_HOP[0]
			JUDGED_HOP[0] = None


def recording_do_backup(backup_entries, job_name, monitor_path, vault_path, *args, **kwargs):
	'''do_backup(), its vault noted for the end-of-test check, and each answer vault_chain_hop() gives it judged.'''
	MONITORS[os.path.abspath(os.path.join(vault_path, job_name))] = os.path.abspath(monitor_path)
	with judging('backup'):
		return _real_do_backup(backup_entries, job_name, monitor_path, vault_path, *args, **kwargs)


def checking_decrement(vault_info_dict, job_name, monitor_path, *args, **kwargs):
	'''decrement_stepper(), each link its walk asks vault_chain_hop() about judged by the answer it acts on.'''
	if len(vault_info_dict) >= 2:
		TOTALS['prune_calls'] += 1
		if monitor_path is not None:
			job_vault = os.path.dirname(os.path.abspath(next(iter(vault_info_dict.values())).path))
			MONITORS.setdefault(job_vault, os.path.abspath(monitor_path))
	with judging('prune'):
		return _real_decrement(vault_info_dict, job_name, monitor_path, *args, **kwargs)


def classify(job_vault, version_path, moves):
	'''Judge every link of the version at version_path, told by moves (its VersionMoves), for the end-of-test check.'''
	try:
		key = moves.key
	except (OSError, rv.UncheckedVaultLink):
		key = None
	if key is not None:
		# the check logs no warning of the daemon's: the warned table is put back afterwards
		rv.VERSION_MOVES_WARNED[key] = None
	for path, _, is_dir in rv.iter_tree_entries(version_path, errors=[]):
		if is_dir:
			continue
		try:
			if not stat.S_ISLNK(os.lstat(path).st_mode):
				continue
			text = os.readlink(path)
		except OSError:
			TOTALS['unchecked'] += 1
			continue
		try:
			target, unexplained = _real_vault_chain_hop(job_vault, path, text, moves), False
		except rv.UnexplainedChainLink:
			target, unexplained = True, True
		except (rv.UncheckedVaultLink, OSError):
			TOTALS['unchecked'] += 1
			continue
		judge('end', job_vault, path, text, moves, target is not None, unexplained, reads=True)


def job_vaults(top):
	for folder, names, files in os.walk(top):
		if any(rv.parse_change_list_name(name) for name in files):
			yield folder
			names[:] = []


def holds_daemon_links(versions):
	'''Whether a version of versions holds a link this process's daemon code made.'''
	for version in versions:
		for path, _, is_dir in rv.iter_tree_entries(version.path, errors=[]):
			if is_dir:
				continue
			try:
				st = os.lstat(path)
			except OSError:
				continue
			made = MADE.get((st.st_dev, st.st_ino))
			if stat.S_ISLNK(st.st_mode) and made is not None and made[0] != 'test':
				return True
	return False


def check_vaults(top):
	for job_vault in job_vaults(top):
		monitor = MONITORS.get(os.path.abspath(job_vault))
		try:
			versions = [version for version in rv.list_versions(job_vault) if not os.path.islink(version.path)]
		except OSError:
			TOTALS['skipped_vaults'] += 1
			continue
		if monitor is None:
			if not holds_daemon_links(versions):
				# written by a daemon process, or by the test alone: no truth for its links here
				TOTALS['skipped_vaults'] += 1
				continue
			# backed up by a call this plugin does not see: the record alone says where its rows were written
			TOTALS['vaults_by_links'] += 1
		with caches_kept():
			vault = rv.VaultMoves(job_vault, monitor, read_record=lambda path: _real_read_record(path)[0])
			# a version folder that is a link is no version: the scan refuses a vault that has one, and its links are
			# judged in their own version
			for version in versions:
				try:
					classify(job_vault, version.path, vault.of(version.path))
				except OSError:
					TOTALS['unchecked'] += 1


def allowances(item):
	'''(kinds, rels or None) for each marker of item.'''
	found = []
	for mark in item.iter_markers(MARKER):
		kinds, rels = set(mark.args), mark.kwargs.get('rels')
		if (kinds - set(KINDS) or not kinds or not mark.kwargs.get('reason') or set(mark.kwargs) - {'reason', 'rels'}
				or ('refused_by_rows' in kinds and not rels)):
			raise pytest.UsageError(f'{item.nodeid}: {MARKER} takes kinds of {KINDS}, a reason and rels (which '
				f'refused_by_rows needs), not {mark.args} {mark.kwargs}')
		found.append((kinds, None if rels is None else set(rels)))
	return found


def pytest_configure(config):
	config.addinivalue_line('markers', f'{MARKER}(*kinds, reason, rels=None): the chain-link ground truth lets these '
		f'kinds of verdict pass in this test (at rels alone, when given), out of {", ".join(KINDS)} (tests/chain_ground_truth.py)')


@pytest.hookimpl(wrapper=True)
def pytest_runtest_makereport(item, call):
	report = yield
	if call.when == 'call':
		item.chain_ground_truth_call_failed = report.failed
	return report


@pytest.fixture(autouse=True)
def chain_ground_truth(request, tmp_path):
	# set up before the conftest's fixtures, as a plugin's: its check runs once their monkeypatch is undone, so a test's
	# patch of os or of reverberator never reaches it
	if not ENABLED:
		yield
		return
	MADE.clear()
	MONITORS.clear()
	FOUND.clear()
	# for the test alone, so the doctest collection still finds decrement_stepper()'s own
	os.symlink, rv.do_backup, rv.decrement_stepper = recording_symlink, recording_do_backup, checking_decrement
	try:
		yield
	finally:
		os.symlink, rv.do_backup, rv.decrement_stepper = _real_symlink, _real_do_backup, _real_decrement
	if getattr(request.node, 'chain_ground_truth_call_failed', None) is None:
		# skipped, or failed at its setup
		return
	if not request.node.chain_ground_truth_call_failed:
		# a vault a failed test left half done is not judged; the answers the daemon acted on while it ran still are
		check_vaults(str(tmp_path))
	allowed = allowances(request.node)
	wrong = [found for found in FOUND
		if not any(found[1] in kinds and (rels is None or found[3] in rels) for kinds, rels in allowed)]
	TOTALS['allowed'] += len(FOUND) - len(wrong)
	TOTALS['violations'] += len(wrong)
	if wrong:
		lines = '\n'.join(f'  {where}: {kind}: {path} -> {text}' for where, kind, path, _, text in wrong[:20])
		more = f'\n  and {len(wrong) - 20} more' if len(wrong) > 20 else ''
		pytest.fail(f'chain-link ground truth: {len(wrong)} link(s) judged wrong by vault_chain_hop() '
			f'(see tests/chain_ground_truth.py; a test that makes such links on purpose marks them with {MARKER}):\n{lines}{more}', pytrace=False)


def pytest_terminal_summary(terminalreporter, exitstatus, config):
	if ENABLED and os.environ.get('REVERB_CHAIN_GROUND_TRUTH_TOTALS'):
		terminalreporter.write_line('chain ground truth: ' + ', '.join(f'{key} {value}' for key, value in TOTALS.items()))
