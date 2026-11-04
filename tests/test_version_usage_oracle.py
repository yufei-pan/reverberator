'''
Round 16: measure_version_usage() takes what the links of a referenced copy take from the copy, and looks at only the
folders and the rows changed since. On random batches (creates, modifies, deletes, moves of files and folders,
attribute changes alone, hard linked and sparse files, links of the user's, files copied again as their chains grow),
replayed with their verification or found by a comparison, every version's record stays the full measure's
(tests/version_usage_ground_truth.py, 0c4ff66's measure of every row).
'''
import os
import random
from collections import deque
import pytest
import reverberator as rv
import shutil
from tests.harness import create_job, seed_monitor, run_backup
from tests.version_usage_ground_truth import oracle_measure_version_usage

pytestmark = pytest.mark.unit

SEEDS = int(os.environ.get('ORACLE_SEEDS', 500))
NAMES = ['a', 'b', 'c d', '..x', 'é', 'n\nl', 'long' * 20]


@pytest.fixture(autouse=True)
def _fast(poll_fast):
	return poll_fast


def entries(monitor, rng):
	'''The files and folders of monitor, as rels (a folder's ending with /).'''
	files, folders = [], []
	for folder, names, rels in os.walk(monitor):
		rel = os.path.relpath(folder, monitor)
		rel = '' if rel == '.' else rel + '/'
		folders.extend(rel + name + '/' for name in names if not os.path.islink(os.path.join(folder, name)))
		files.extend(rel + name for name in rels + [name for name in names if os.path.islink(os.path.join(folder, name))])
	return sorted(files), sorted(folders)


def new_name(rng, folders):
	return rng.choice([''] + folders) + rng.choice(NAMES) + str(rng.randint(0, 99))


def random_steps(monitor, rng):
	'''Change monitor at random: the watcher's events of the changes, (is_dir, event, rel, moved_from rel or None).'''
	events = []
	for _ in range(rng.randint(1, 8)):
		files, folders = entries(monitor, rng)
		roll = rng.random()
		at = new_name(rng, folders)
		path = os.path.join(monitor, at)
		if os.path.lexists(path):
			continue
		if roll < 0.2:
			with open(path, 'w') as f:
				f.write('x' * rng.choice([0, 10, 5000, 70000]))
			events += [(False, 'create', at, None), (False, 'modify', at, None)]
		elif roll < 0.3:
			os.mkdir(path)
			events.append((True, 'create', at, None))
		elif roll < 0.35:
			# sparse: a length far past its blocks
			with open(path, 'w') as f:
				f.truncate(rng.choice([1, 10 ** 6]))
			events += [(False, 'create', at, None), (False, 'modify', at, None)]
		elif roll < 0.4 and files:
			source = os.path.join(monitor, rng.choice(files))
			if os.path.isfile(source) and not os.path.islink(source):
				os.link(source, path)
				events.append((False, 'create', at, None))
		elif roll < 0.45:
			os.symlink(rng.choice(['a', '../x', '/etc/hostname', 'long' * 30]), path)
			events.append((False, 'create', at, None))
		elif roll < 0.6 and files:
			rel = rng.choice(files)
			if not os.path.islink(os.path.join(monitor, rel)):
				with open(os.path.join(monitor, rel), 'a') as f:
					f.write('y' * rng.choice([1, 9000]))
				events.append((False, 'modify', rel, None))
		elif roll < 0.7 and files:
			rel = rng.choice(files)
			os.remove(os.path.join(monitor, rel))
			events.append((False, 'delete', rel, None))
		elif roll < 0.8 and files:
			rel = rng.choice(files)
			os.rename(os.path.join(monitor, rel), path)
			events.append((False, 'move', at, rel))
		elif roll < 0.88 and folders:
			rel = rng.choice(folders)
			if not at.startswith(rel):
				os.rename(os.path.join(monitor, rel), path)
				events.append((True, 'move', at, rel.rstrip('/')))
		elif roll < 0.93 and folders:
			rel = rng.choice(folders)
			shutil.rmtree(os.path.join(monitor, rel))
			events.append((True, 'delete', rel.rstrip('/'), None))
		elif files or folders:
			rel = rng.choice(files + folders)
			target = os.path.join(monitor, rel.rstrip('/'))
			if not os.path.islink(target):
				os.chmod(target, rng.choice([0o600, 0o755, 0o700]))
				os.chown(target, rng.randint(0, 3), rng.randint(0, 3))
				events.append((rel.endswith('/'), 'attrib', rel.rstrip('/'), None))
	return events


def test_random_batches_keep_the_full_measure(tmp_path, monkeypatch):
	measured = {'by_the_copy': 0, 'in_all': 0}
	real = rv.measure_version_usage
	def checking(manifest, version_path, copied=None):
		expected = oracle_measure_version_usage(manifest, version_path)
		measured['in_all'] += 1
		measured['by_the_copy'] += copied is not None and copied.tracking and copied.usable
		got = real(manifest, version_path, copied)
		assert got == expected, (seed, version_path)
		return got
	monkeypatch.setattr(rv, 'measure_version_usage', checking)
	for seed in range(SEEDS):
		rng = random.Random(seed)
		job = create_job(str(tmp_path / f's{seed}'))
		monitor = job.monitor
		seed_monitor(job, {f'{rng.choice(["", "d/", "d/e/", "f/"])}{rng.choice(NAMES)}{i}': 'z' * rng.choice([0, 100, 9000]) for i in range(rng.randint(1, 12))})
		chain_length = rng.choice([None, 3, 4])
		run_backup(job, keep_one_complete_backup=rng.random() < 0.8, chain_length=chain_length)
		for _ in range(rng.randint(1, 4)):
			events = random_steps(monitor, rng)
			if not events or rng.random() < 0.15:
				# a comparison finds what changed
				run_backup(job, chain_length=chain_length)
				continue
			raw = deque(rv.ChangeEvent(float(i), is_dir, event, f'{monitor}/{rel}', None if source is None else f'{monitor}/{source}')
				for i, (is_dir, event, rel, source) in enumerate(events, 1))
			touched = rv.touched_scopes(raw, monitor) if rng.random() < 0.8 else None
			run_backup(job, rv.change_events_to_backup_entries(deque(raw), monitor), touched=touched, chain_length=chain_length,
				only_sync_attributes=rng.random() < 0.7)
		shutil.rmtree(str(tmp_path / f's{seed}'))
	assert measured['by_the_copy'] >= SEEDS, measured
