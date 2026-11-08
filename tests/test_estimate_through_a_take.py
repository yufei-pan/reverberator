'''
The size estimate's put-back for what a batch writes under a folder carried into a created folder, through the one route the
watcher leaves to it: a take that lands inside the read holding the folder's create, so the create goes to the next batch while
the watcher's next read clears newDirWDs, and the move into it read later is a move. The estimate must count what the replay
writes (the bytes of what is written, the inodes it makes) and no more: written <= estimate <= what the vault grew by.
'''
import os

import pytest

import reverberator as rv
from tests.harness import wait_until
from tests.test_moves_into_new_folders import (ATTRIB_ROWS, ESTIMATE_ROWS, SEED, live_view, session, take_at_append,  # noqa: F401 (fixture)
	vault_bytes, version_view)

pytestmark = pytest.mark.inotify

ROWS = ESTIMATE_ROWS + [
	# a file under a subfolder of the carried folder rewritten, and a chmod there (no copy under Only Sync Attributes)
	('a deep file rewritten and a chmod', [('write', 'n/big/sub/b', 'y' * (5 << 20)), ('chmod', 'n/big/a', 0o600)], 5 << 20, 2),
	# a new folder inside a new folder inside the carried folder, files at both levels
	('nested new folders', [('mkdir', 'n/big/s1'), ('write', 'n/big/s1/p', 'p' * (3 << 20)), ('mkdir', 'n/big/s1/s2'),
		('write', 'n/big/s1/s2/q', 'q' * (3 << 20))], 6 << 20, 6),
]


def spy_on_estimates(monkeypatch):
	estimates = []
	real = rv.get_backup_size_inode
	def spy(*args, **kwargs):
		result = real(*args, **kwargs)
		entries = kwargs.get('backup_entries', args[0] if args else None)
		estimates.append((result, {os.path.relpath(path, kwargs['monitor_path']) + ('/' if path.endswith('/') else ''): values.event for path, values in entries.items()}))
		return result
	monkeypatch.setattr(rv, 'get_backup_size_inode', spy)
	return estimates


def create_then_take(one, job, monkeypatch):
	'''mkdir n read in the same read as a marker, a take right after the marker is queued: the create goes to the next batch.'''
	marker = os.path.join(job.monitor, 'marker')
	taken = take_at_append(one, monkeypatch, lambda event: event.path == marker)
	with one.unread():
		one.apply(('write', 'marker', 'm'))
		one.apply(('mkdir', 'n'))
	wait_until(lambda: taken, message='no take')
	one.flag.clear()
	one.back_up(taken[0])
	# the watcher reads again, sees the take and clears newDirWDs: what comes in n from now on is recorded
	one.settle()


@pytest.mark.parametrize('patterns', [(), ('no_such_folder/',)], ids=['du', 'walk'])
@pytest.mark.parametrize('row,writes,written,made', ROWS, ids=[row[0] for row in ROWS])
def test_the_put_back_through_a_take(session, job, monkeypatch, patterns, row, writes, written, made):
	one = session(patterns=patterns)
	estimates = spy_on_estimates(monkeypatch)
	create_then_take(one, job, monkeypatch)
	size = vault_bytes(job)
	estimates.clear()
	one.run([('mv', 'big', 'n/big')] + writes, 'apart')
	one.back_up_next()
	assert len(estimates) == 1, estimates
	(est_size, est_inodes), entries = estimates[0]
	# the route: the batch holds the create of n and the move into it
	assert entries.get('n/') == 'create' and entries.get('n/big/') == 'move', entries
	grew = vault_bytes(job) - size
	probes = sum(1 for rel, event in entries.items() if rel.startswith('.probe') and event == 'create')
	print(f'ROW {row} {patterns}: estimate {est_size} inodes {est_inodes}, written {written}, grew {grew}, probes {probes}, entries {entries}')
	assert version_view(job) == live_view(job)
	assert written <= est_size <= grew, (est_size, written, grew)
	# made counts n and one probe: the batch has one probe more (the settle after the take)
	assert est_inodes == made + probes - 1, (est_inodes, made, probes)


@pytest.mark.parametrize('patterns', [(), ('no_such_folder/',)], ids=['du', 'walk'])
@pytest.mark.parametrize('row,changes,only_sync_attributes', [(row, changes, osa) for row, changes, settings in ATTRIB_ROWS for osa in settings],
	ids=[f'{row}-{"osa" if osa else "no_osa"}' for row, _, settings in ATTRIB_ROWS for osa in settings])
def test_the_attrib_put_back_through_a_take(session, job, monkeypatch, patterns, row, changes, only_sync_attributes):
	one = session({**SEED, **{f'big/{name}': name * (5 << 19) for name in ('h1', 'h2', 'h3')}}, patterns=patterns, only_sync_attributes=only_sync_attributes)
	estimates = spy_on_estimates(monkeypatch)
	create_then_take(one, job, monkeypatch)
	size = vault_bytes(job)
	estimates.clear()
	one.run([('mv', 'big', 'n/big')] + changes, 'apart')
	one.back_up_next()
	assert len(estimates) == 1, estimates
	(est_size, est_inodes), entries = estimates[0]
	assert entries.get('n/') == 'create' and entries.get('n/big/') == 'move', entries
	grew = vault_bytes(job) - size
	print(f'ROW {row} {patterns} osa={only_sync_attributes}: estimate {est_size} inodes {est_inodes}, grew {grew}, entries {entries}')
	assert version_view(job) == live_view(job)
	assert 15 << 20 <= est_size <= grew, (est_size, grew)


FILE_ROWS = [
	# a file carried into the new folder, then rewritten: one key, so the batch holds the move or the modify, not both
	('file carried then rewritten', [('mv', 'f.txt', 'n/f.txt'), ('write', 'n/f.txt', 'w' * (5 << 20))], 5 << 20),
	# a file carried into the carried folder, then rewritten
	('file into carried then rewritten', [('mv', 'big', 'n/big'), ('mv', 'g.txt', 'n/big/g'), ('write', 'n/big/g', 'w' * (5 << 20))], 5 << 20),
	# a folder carried in, then a file in it replaced by a move from elsewhere and rewritten
	('folder carried, file moved over', [('mv', 'big', 'n/big'), ('mv', 'g.txt', 'n/big/a'), ('append', 'n/big/a', 'w' * (5 << 20))], 5 << 20),
]


@pytest.mark.parametrize('patterns', [(), ('no_such_folder/',)], ids=['du', 'walk'])
@pytest.mark.parametrize('row,steps,written', FILE_ROWS, ids=[row[0] for row in FILE_ROWS])
def test_file_rows_through_a_take(session, job, monkeypatch, patterns, row, steps, written):
	one = session(patterns=patterns)
	estimates = spy_on_estimates(monkeypatch)
	create_then_take(one, job, monkeypatch)
	size = vault_bytes(job)
	estimates.clear()
	one.run(steps, 'apart')
	one.back_up_next()
	(est_size, est_inodes), entries = estimates[0]
	grew = vault_bytes(job) - size
	print(f'ROW {row} {patterns}: estimate {est_size} inodes {est_inodes}, written {written}, grew {grew}, entries {entries}')
	assert version_view(job) == live_view(job)
	assert written <= est_size <= grew, (est_size, written, grew)
