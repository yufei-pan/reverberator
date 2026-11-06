'''
pytest plugin: around every do_backup() in the suite on a design R vault, each version committed before the batch reads the
same after it, whatever the batch did and however it ended. Reading is the oracle's (tests/vault_oracle.py), which imports
nothing of the daemon.

Only file metadata under Only Sync Attributes may differ, as spec section 2.4 has an attribute change reach every version
sharing the file. A link that led nowhere before may be gone after: the version read as holding nothing there both ways. A
version pruned by the batch is not compared. A vault with no staging folder is on the 0.54 layout: one lexists and no read,
so the suite's cost stays flat. A tree of more than MAX_ENTRIES is not read either, and nothing is checked while tracemalloc
traces, so a memory test measures the daemon alone. REVERB_VIEW_GROUND_TRUTH=0 turns the plugin off.

A test that means to break a version (a negative control) takes the lines out of WRONG, having looked at them.
'''
import os
import tracemalloc
import pytest
import reverberator as rv
from tests.vault_oracle import STAGING, VERSION_LIST, compared, read_view, version_number

ENABLED = os.environ.get('REVERB_VIEW_GROUND_TRUTH', '1') != '0'
MAX_ENTRIES = 5000
TOTALS = {'batches': 0, 'versions': 0, 'too_big': 0}
# what differs, for this test: failed at its end, as a daemon thread may have run the batch
WRONG = []
# the do_backup() this plugin stands in front of, for the running test
_wrapped = None


def committed_folders(job_vault: str) -> list:
	'''The names of job_vault's folders that have a change list, the newest first: its committed versions.'''
	names = os.listdir(job_vault)
	listed = {match[1] for match in map(VERSION_LIST.fullmatch, names) if match is not None}
	return sorted((name for name in names if name in listed and version_number(name) is not None), key=version_number, reverse=True)


def views_of(job_vault: str):
	'''{folder name: read_view()} of the committed versions, None when the tree is past MAX_ENTRIES.'''
	views = {}
	for name in committed_folders(job_vault):
		views[name] = read_view(job_vault, name)
		if len(views[name]) > MAX_ENTRIES:
			TOTALS['too_big'] += 1
			return None
	return views


def differences(job_vault: str, before: dict, only_sync_attributes: bool) -> list:
	'''What each version of before reads differently now, as lines.'''
	lines = []
	for name, view in before.items():
		if not os.path.lexists(os.path.join(job_vault, name)):
			continue
		TOTALS['versions'] += 1
		now = read_view(job_vault, name)
		for rel in sorted(set(view) | set(now)):
			was, held = view.get(rel), now.get(rel)
			if was is not None and was.kind == 'dangling' and held is None:
				continue
			if compared(was, True, only_sync_attributes) != compared(held, True, only_sync_attributes):
				lines.append(f'{name}:{rel!r}: read {was} before the batch, {held} after it')
	return lines


def checking_do_backup(backup_entries, job_name, monitor_path, vault_path, *args, **kwargs):
	job_vault = os.path.join(vault_path, job_name)
	if tracemalloc.is_tracing() or not os.path.lexists(os.path.join(job_vault, STAGING)):
		return _wrapped(backup_entries, job_name, monitor_path, vault_path, *args, **kwargs)
	before = views_of(job_vault)
	only_sync_attributes = args[1] if len(args) > 1 else kwargs.get('only_sync_attributes')
	try:
		return _wrapped(backup_entries, job_name, monitor_path, vault_path, *args, **kwargs)
	finally:
		if before is not None:
			TOTALS['batches'] += 1
			WRONG.extend(differences(job_vault, before, bool(only_sync_attributes)))


@pytest.fixture(autouse=True)
def version_view_ground_truth(chain_ground_truth):
	# after the chain plugin's, whose do_backup this one stands in front of
	global _wrapped
	if not ENABLED:
		yield
		return
	WRONG.clear()
	_wrapped = rv.do_backup
	rv.do_backup = checking_do_backup
	try:
		yield
	finally:
		rv.do_backup = _wrapped
	if WRONG:
		pytest.fail('version view ground truth (tests/version_view_ground_truth.py): ' + '; '.join(WRONG[:10]), pytrace=False)


def pytest_terminal_summary(terminalreporter, exitstatus, config):
	if ENABLED and os.environ.get('REVERB_VIEW_GROUND_TRUTH_TOTALS'):
		terminalreporter.write_line('version view ground truth: ' + ', '.join(f'{key} {value}' for key, value in TOTALS.items()))
