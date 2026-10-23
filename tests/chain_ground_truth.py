'''
pytest plugin: the ground truth for which links in a vault are the daemon's chain links, checked over the whole suite.

Every symlink a frame of reverberator.py makes (do_referenced_copy(), retarget_chain_link()) is recorded by its inode
and text as it is made, which a rename keeps. Any other link in a version is a copy of a user's symlink, a user link;
one a test makes with os.symlink is left out, as a test can forge any vault. Each link is classified by
vault_chain_hop():
- at each decrement_stepper() call, before its walk acts, every link of the version it materialises, with the moves
  pruning reads (VaultMoves, by the monitored path and record it is given);
- at each test's end, every link of every kept version of each job vault the test backed up or pruned under its
  tmp_path, with the moves read under the record the manifest holds.
The test fails when a daemon link is refused, or a user link (or a referenced backup's link) accepted, unless its
chain_ground_truth_allows(kind, ..., reason=...) marker names how:
- 'unusable_rows': a user link accepted by its text, as its version's rows cannot be used (a change list blank, cut,
  missing or unreadable, rows under an old monitored path, a record that cannot be read);
- 'cannot_tell': a user link the rows cannot tell (UnexplainedChainLink), which pruning and reading follow;
- 'blind_spot': a user link the rule itself takes, its text exactly its own path's chain text (or, with a move, its
  pre-move path's): the documented blind spot;
- 'refused_chain': a daemon link refused, in a vault the test changed by hand (a version removed or renamed, rows
  forged).
A link accepted in any other way (its text no chain text at all) is never allowed. A link that cannot be looked at
(UncheckedVaultLink, an OSError) is not judged: pruning keeps the oldest version for it.
The check reads the vaults only, and leaves the caches it fills (VERSION_MOVES, VERSION_MOVES_WARNED,
REAL_VAULT_FOLDERS) as they were, so no warning or read of the daemon's is done for it. REVERB_CHAIN_GROUND_TRUTH=0
turns it off.
'''
import contextlib
import os
import stat
import sys
from collections import OrderedDict
import pytest
import reverberator as rv

ENABLED = os.environ.get('REVERB_CHAIN_GROUND_TRUTH', '1').strip().lower() not in ('0', 'off', 'no', 'false')
MARKER = 'chain_ground_truth_allows'
KINDS = ('unusable_rows', 'cannot_tell', 'blind_spot', 'refused_chain')
# the frames of reverberator.py whose links are the daemon's chain links
CHAIN_MAKERS = ('do_referenced_copy', 'retarget_chain_link')

# (st_dev, st_ino) -> (the frame of reverberator.py that made it, or 'test', its text), for the running test
MADE = {}
# job vault -> the monitored path it was last backed up or pruned under, for the running test
MONITORS = {}
# what the running test's checks found: (where, kind, path, text) for each link judged wrong
FOUND = []
TOTALS = {'links': 0, 'chain': 0, 'user': 0, 'test_made': 0, 'unchecked': 0, 'prune_calls': 0, 'prune_links': 0,
	'allowed': 0, 'violations': 0, 'skipped_vaults': 0}

_real_symlink = os.symlink
_real_do_backup = rv.do_backup
_real_decrement = rv.decrement_stepper
# taken now, so a test's patch of the classifier or the record read leaves the end-of-test check alone
_real_vault_chain_hop = rv.vault_chain_hop
_real_read_record = rv.read_recorded_monitor_paths


def recording_symlink(src, dst, *args, **kwargs):
	_real_symlink(src, dst, *args, **kwargs)
	frame = sys._getframe(1)
	try:
		st = os.lstat(dst, dir_fd=kwargs.get('dir_fd'))
	except (OSError, TypeError, ValueError):
		return
	kind = frame.f_code.co_name if frame.f_code.co_filename == rv.__file__ else 'test'
	MADE[(st.st_dev, st.st_ino)] = (kind, os.fsdecode(src))


def recording_do_backup(backup_entries, job_name, monitor_path, vault_path, *args, **kwargs):
	MONITORS[os.path.abspath(os.path.join(vault_path, job_name))] = os.path.abspath(monitor_path)
	return _real_do_backup(backup_entries, job_name, monitor_path, vault_path, *args, **kwargs)


def truth(path, st, text):
	''''chain' for the daemon's chain link, 'user' for any other link the test did not make, None for one it did.'''
	made = MADE.get((st.st_dev, st.st_ino))
	if made is None or made[1] != text:
		return 'user'
	if made[0] == 'test':
		return None
	# a referenced backup's link is absolute, and no chain link
	return 'chain' if made[0] in CHAIN_MAKERS and not os.path.isabs(text) else 'user'


def how_accepted(job_vault, path, text, moves):
	'''
	The kind of a link vault_chain_hop() took, by the rule told again here: 'blind_spot' when the rule itself takes it,
	'unusable_rows' when its version's rows cannot be used, 'cannot_tell' when they cannot tell, else None (no rule
	takes it).
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
	version_name, _, rel = os.path.abspath(path)[len(vault) + 1:].partition('/')
	named = '/'.join(named_parts)
	if named == rel and ups == rel.count('/') + 1:
		return 'blind_spot'
	if not moves.usable:
		return 'unusable_rows'
	verdict = moves.tells(named, rel, version_name)[0]
	return {True: 'blind_spot', None: 'cannot_tell'}.get(verdict)


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


def classify(where, job_vault, version_path, moves, hop):
	'''Judge every link of the version at version_path, told by moves (its VersionMoves) with hop.'''
	try:
		key = moves.key
	except (OSError, rv.UncheckedVaultLink):
		key = None
	if key is not None:
		# the check logs no warning of the daemon's: the warned table is put back afterwards
		rv.VERSION_MOVES_WARNED[key] = None
	errors = []
	for path, _, is_dir in rv.iter_tree_entries(version_path, errors=errors):
		if is_dir:
			continue
		try:
			st = os.lstat(path)
			if not stat.S_ISLNK(st.st_mode):
				continue
			text = os.readlink(path)
		except OSError:
			TOTALS['unchecked'] += 1
			continue
		TOTALS['links'] += 1
		if where == 'prune':
			TOTALS['prune_links'] += 1
		real = truth(path, st, text)
		if real is None:
			TOTALS['test_made'] += 1
			continue
		TOTALS[real] += 1
		try:
			target = hop(job_vault, path, text, moves)
		except rv.UnexplainedChainLink:
			target = True
		except (rv.UncheckedVaultLink, OSError):
			TOTALS['unchecked'] += 1
			continue
		if real == 'chain' and target is None:
			FOUND.append((where, 'refused_chain', path, text))
		elif real == 'user' and target is not None:
			try:
				kind = how_accepted(job_vault, path, text, moves)
			except (rv.UncheckedVaultLink, OSError):
				kind = None
			FOUND.append((where, kind or 'beyond_the_rule', path, text))


def checking_decrement(vault_info_dict, job_name, monitor_path, monitor_paths=None, *args, **kwargs):
	'''decrement_stepper(), its next version's links judged first, with the moves its walk is about to use.'''
	if len(vault_info_dict) >= 2:
		TOTALS['prune_calls'] += 1
		numbers = list(vault_info_dict)
		job_vault = os.path.dirname(os.path.abspath(vault_info_dict[numbers[0]].path))
		applying = os.path.abspath(vault_info_dict[numbers[1]].path)
		if monitor_path is not None:
			MONITORS.setdefault(job_vault, os.path.abspath(monitor_path))
		with caches_kept():
			try:
				if os.path.isdir(applying) and not os.path.islink(applying):
					moves = rv.VaultMoves(job_vault, monitor_path, monitor_paths).of(applying)
					# the classifier as the walk calls it, a test's patch of it included
					classify('prune', job_vault, applying, moves, rv.vault_chain_hop)
			except Exception:
				# a test's patch of os, say: the walk meets it next, and the test sees what it does
				TOTALS['unchecked'] += 1
	return _real_decrement(vault_info_dict, job_name, monitor_path, monitor_paths, *args, **kwargs)


def job_vaults(top):
	for folder, names, files in os.walk(top):
		if any(rv.parse_change_list_name(name) for name in files):
			yield folder
			names[:] = []


def check_vaults(top):
	for job_vault in job_vaults(top):
		monitor = MONITORS.get(os.path.abspath(job_vault))
		if monitor is None:
			# written by a daemon process, or by the test alone: no truth for its links here
			TOTALS['skipped_vaults'] += 1
			continue
		with caches_kept():
			vault = rv.VaultMoves(job_vault, monitor, read_record=lambda path: _real_read_record(path)[0])
			try:
				versions = rv.list_versions(job_vault)
			except OSError:
				TOTALS['skipped_vaults'] += 1
				continue
			for version in versions:
				if os.path.islink(version.path):
					# no version: the scan refuses a vault that has one, and its links are judged in their own version
					continue
				try:
					classify('end', job_vault, version.path, vault.of(version.path), _real_vault_chain_hop)
				except OSError:
					TOTALS['unchecked'] += 1


def allowed_kinds(item):
	kinds = set()
	for mark in item.iter_markers(MARKER):
		unknown = set(mark.args) - set(KINDS)
		if unknown or not mark.args or not mark.kwargs.get('reason'):
			raise pytest.UsageError(f'{item.nodeid}: {MARKER} takes kinds of {KINDS} and a reason, not {mark.args} {mark.kwargs}')
		kinds.update(mark.args)
	return kinds


def pytest_configure(config):
	config.addinivalue_line('markers', f'{MARKER}(*kinds, reason): the chain-link ground truth lets these kinds of '
		f'verdict pass in this test, out of {", ".join(KINDS)} (tests/chain_ground_truth.py)')


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
	if getattr(request.node, 'chain_ground_truth_call_failed', True):
		return
	check_vaults(str(tmp_path))
	allowed = allowed_kinds(request.node)
	wrong = [found for found in FOUND if found[1] not in allowed]
	TOTALS['allowed'] += len(FOUND) - len(wrong)
	TOTALS['violations'] += len(wrong)
	if wrong:
		lines = '\n'.join(f'  {where}: {kind}: {path} -> {text}' for where, kind, path, text in wrong[:20])
		more = f'\n  and {len(wrong) - 20} more' if len(wrong) > 20 else ''
		pytest.fail(f'chain-link ground truth: {len(wrong)} link(s) judged wrong by vault_chain_hop() '
			f'(see tests/chain_ground_truth.py; a test that makes such links on purpose marks them with {MARKER}):\n{lines}{more}', pytrace=False)


def pytest_terminal_summary(terminalreporter, exitstatus, config):
	if ENABLED and os.environ.get('REVERB_CHAIN_GROUND_TRUTH_TOTALS'):
		terminalreporter.write_line('chain ground truth: ' + ', '.join(f'{key} {value}' for key, value in TOTALS.items()))
