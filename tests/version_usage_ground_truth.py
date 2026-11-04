'''
pytest plugin: the size record of every version measured in the suite is checked against a full measure.

measure_version_usage() takes what the links of a referenced copy take from the copy itself (round 16), and looks at
only the folders and the rows changed since. Each call the daemon makes in any test is checked here: 0c4ff66's measure
(oracle_measure_version_usage(), which looks at every row) runs first, on the same version and rows, its lines kept out
of the log, and the test fails when the two (bytes, inodes) differ. Nothing is checked while tracemalloc traces, so a
memory test measures the daemon alone. REVERB_USAGE_GROUND_TRUTH=0 turns the plugin off.
'''
import os
import tracemalloc
import types
import pytest
import reverberator as rv

ENABLED = os.environ.get('REVERB_USAGE_GROUND_TRUTH', '1') != '0'
TOTALS = {'measured': 0, 'by_the_copy': 0}
# the measures of this test that differ: failed at its end, as a daemon thread may have made them
WRONG = []


def measure_version_usage(manifest, version_path):
	'''measure_version_usage() as 0c4ff66 (0.51) had it: every row looked at.'''
	def allocated(rel:str):
		try:
			return os.lstat(os.path.join(version_path, rel)).st_blocks * 512
		except OSError:
			backuperTeeLogToTl(path=version_path, message=f'{rel} is missing from the version, not counted')
			return None
	try:
		total_bytes = os.lstat(version_path).st_blocks * 512
	except OSError:
		return 0, 0
	inodes = 1
	def rows():
		yield from manifest.iter_folders()
		yield from manifest.iter_files()
	with ThreadPoolExecutor(max_workers=COMPARE_THREADS) as pool:
		batch = []
		for rel in rows():
			batch.append(rel)
			if len(batch) >= MANIFEST_BATCH_SIZE:
				total_bytes, inodes = count_batch(pool, batch, allocated, total_bytes, inodes)
				batch = []
		total_bytes, inodes = count_batch(pool, batch, allocated, total_bytes, inodes)
	return total_bytes, inodes


def oracle_measure_version_usage(manifest, version_path, quiet=True):
	'''The oracle, with reverberator's globals as they are now, its lines left out when quiet.'''
	scope = dict(rv.__dict__)
	if quiet:
		scope['backuperTeeLogToTl'] = lambda *args, **kwargs: None
	return types.FunctionType(measure_version_usage.__code__, scope, 'oracle_measure_version_usage')(manifest, version_path)


_real_measure = rv.measure_version_usage


def checking_measure(manifest, version_path, copied=None):
	if tracemalloc.is_tracing():
		return _real_measure(manifest, version_path, copied)
	by_the_copy = copied is not None and copied.usable and manifest.changes() is not None
	expected = oracle_measure_version_usage(manifest, version_path)
	got = _real_measure(manifest, version_path, copied)
	TOTALS['measured'] += 1
	TOTALS['by_the_copy'] += by_the_copy
	if got != expected:
		WRONG.append(f'{version_path} measured {got} (bytes, inodes), a full measure {expected} (sizes from the copy: {by_the_copy})')
	return got


@pytest.fixture(autouse=True)
def version_usage_ground_truth():
	if not ENABLED:
		yield
		return
	WRONG.clear()
	rv.measure_version_usage = checking_measure
	try:
		yield
	finally:
		rv.measure_version_usage = _real_measure
	if WRONG:
		pytest.fail('version usage ground truth (tests/version_usage_ground_truth.py): ' + '; '.join(WRONG[:5]), pytrace=False)


def pytest_terminal_summary(terminalreporter, exitstatus, config):
	if ENABLED and os.environ.get('REVERB_USAGE_GROUND_TRUTH_TOTALS'):
		terminalreporter.write_line('version usage ground truth: ' + ', '.join(f'{key} {value}' for key, value in TOTALS.items()))
