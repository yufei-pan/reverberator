import errno
import os
from collections import OrderedDict
import pytest
import reverberator as rv
from tests.harness import seed_monitor, run_backup, event_entry, write_committed_version

pytestmark = pytest.mark.unit

T = '2021-01-01_00-00-00_-0800'
BAD = 'bad\udcff.txt'


@pytest.fixture(autouse=True)
def _fast(poll_fast):
	return poll_fast


def copy_versions(job):
	'''{rel: recorded copy version} of every file the vault database tracks.'''
	manifest = rv.VaultManifest(job.job_vault)
	try:
		return dict(manifest.iter_files_with_copy_version())
	finally:
		manifest.close()


def assert_recorded_matches_vault(job):
	'''Every file's effective copy version is the version its chain ends in, as walking the chain finds it.'''
	versions = rv.list_versions(job.job_vault)
	oldest, latest = versions[0].number, versions[-1].path
	recorded = copy_versions(job)
	assert recorded and None not in recorded.values()
	for rel, version in recorded.items():
		assert rv.effective_copy_version(version, oldest) == rv.learn_copy_version(job.job_vault, latest, rel), rel
	return recorded


def test_copies_record_their_version(job):
	seed_monitor(job, {'a.txt': 'a', 'b.txt': 'b', 'c.txt': 'c', 'over.txt': 'o', 'n.txt': 'n', 'd/e.txt': 'e', 'd/f/g.txt': 'g', BAD: 'x'})
	os.symlink('a.txt', f'{job.monitor}/u')
	run_backup(job)
	assert copy_versions(job) == dict.fromkeys(['a.txt', 'b.txt', 'c.txt', 'over.txt', 'n.txt', 'd/e.txt', 'd/f/g.txt', BAD, 'u'], 0)
	# V1: created files, and the files of a created folder, are copies
	seed_monitor(job, {'new.txt': 'n', 'k/h.txt': 'h'})
	run_backup(job, OrderedDict([event_entry(job, 'new.txt', 'create'), event_entry(job, 'k/', 'create')]))
	# V2: c.txt is copied again; a.txt's attributes are synced onto its link, which stays a link
	seed_monitor(job, {'c.txt': 'c2'})
	os.chmod(f'{job.monitor}/a.txt', 0o600)
	run_backup(job, OrderedDict([event_entry(job, 'c.txt', 'modify'), event_entry(job, 'a.txt', 'attrib')]))
	# V3: a modify; a move onto a tracked file and a folder move keep the moved entries' numbers; n.txt is written,
	# renamed to n2.txt and written again, so the copy V3 makes of it is what the first move of the backup moves
	seed_monitor(job, {'b.txt': 'b3', BAD: 'x3', 'n.txt': 'n3'})
	os.replace(f'{job.monitor}/c.txt', f'{job.monitor}/over.txt')
	os.rename(f'{job.monitor}/d', f'{job.monitor}/m')
	os.rename(f'{job.monitor}/n.txt', f'{job.monitor}/n2.txt')
	seed_monitor(job, {'n.txt': 'n3 again'})
	run_backup(job, OrderedDict([event_entry(job, 'b.txt', 'modify'), event_entry(job, BAD, 'modify'), event_entry(job, 'n.txt', 'modify'),
		event_entry(job, 'n2.txt', 'move', 'n.txt'), event_entry(job, 'over.txt', 'move', 'c.txt'), event_entry(job, 'm/', 'move', 'd/')]))
	assert copy_versions(job) == {'a.txt': 0, 'b.txt': 3, BAD: 3, 'over.txt': 2, 'n2.txt': 3, 'm/e.txt': 0, 'm/f/g.txt': 0, 'u': 0,
		'new.txt': 1, 'k/h.txt': 1}
	# V4: attributes copied with the file (only_sync_attributes False) are a copy too
	os.chmod(f'{job.monitor}/a.txt', 0o644)
	run_backup(job, OrderedDict([event_entry(job, 'a.txt', 'attrib')]), only_sync_attributes=False)
	assert copy_versions(job)['a.txt'] == 4
	assert_recorded_matches_vault(job)


def test_a_referenced_backup_counts_as_version_0(job):
	# a referenced V0 links each file to the monitored tree: the chains of later versions end in it all the same
	seed_monitor(job, {'a.txt': 'a', 'b.txt': 'b', 'd/e.txt': 'e'})
	run_backup(job, keep_one_complete_backup=False)
	assert copy_versions(job) == dict.fromkeys(['a.txt', 'b.txt', 'd/e.txt'], 0)
	seed_monitor(job, {'b.txt': 'b1'})
	run_backup(job, OrderedDict([event_entry(job, 'b.txt', 'modify')]), keep_one_complete_backup=False)
	assert assert_recorded_matches_vault(job) == {'a.txt': 0, 'b.txt': 1, 'd/e.txt': 0}


def test_a_failed_version_records_no_copy_version(job, monkeypatch):
	seed_monitor(job, {'a.txt': 'a', 'b.txt': 'b'})
	run_backup(job)
	seed_monitor(job, {'a.txt': 'a1', 'b.txt': 'b1'})
	copy_command = rv.copy_command
	# a.txt copies; writing b.txt's copy into the vault fails, so the version is not committed
	monkeypatch.setattr(rv, 'copy_command', lambda source, dest: ['false'] if source.endswith('b.txt') else copy_command(source, dest))
	with pytest.raises(rv.JobFailure):
		run_backup(job, OrderedDict([event_entry(job, 'a.txt', 'modify'), event_entry(job, 'b.txt', 'modify')]))
	assert copy_versions(job) == {'a.txt': 0, 'b.txt': 0}


def test_copy_version_follows_retention(job):
	seed_monitor(job, {f'f{i}.txt': str(i) for i in range(6)})
	run_backup(job, keep_n_versions=3)
	# one change per version, so the other files' copies move up into the oldest kept version as versions are pruned
	changes = ['f1.txt', 'f2.txt', ('g3.txt', 'f3.txt'), 'f4.txt', 'f1.txt', 'f0.txt', 'f5.txt']
	for change in changes:
		if isinstance(change, tuple):
			os.rename(f'{job.monitor}/{change[1]}', f'{job.monitor}/{change[0]}')
			entry = event_entry(job, change[0], 'move', change[1])
		else:
			seed_monitor(job, {change: f'{change} changed'})
			entry = event_entry(job, change, 'modify')
		run_backup(job, OrderedDict([entry]), keep_n_versions=3)
		assert_recorded_matches_vault(job)
	versions = rv.list_versions(job.job_vault)
	assert [version.number for version in versions] == [5, 6, 7]
	assert copy_versions(job) == {'f0.txt': 6, 'f1.txt': 5, 'f2.txt': 2, 'g3.txt': 0, 'f4.txt': 4, 'f5.txt': 7}


def test_learn_copy_version_past_39_links(job):
	versions = [write_committed_version(job, number, {'a/x': 'x'} if number == 0 else {}, timestamp=T) for number in range(45)]
	# a user's symlink backed up as one is where its chain ends, as is a referenced backup's link
	os.symlink('x', f'{versions[0]}/a/u')
	os.symlink(f'{job.monitor}/r', f'{versions[0]}/a/r')
	for number in range(1, 45):
		os.makedirs(f'{versions[number]}/a')
		for name in ('x', 'u', 'r'):
			os.symlink(f'../../V{number - 1}--{T}/a/{name}', f'{versions[number]}/a/{name}')
	# a link naming a file the previous version does not hold, and a file copied in V44
	os.symlink(f'../../V43--{T}/a/gone', f'{versions[44]}/a/gone')
	open(f'{versions[44]}/a/new', 'w').close()
	with pytest.raises(OSError) as raised:
		open(f'{versions[44]}/a/x')
	assert raised.value.errno == errno.ELOOP
	assert [rv.learn_copy_version(job.job_vault, versions[44], f'a/{name}') for name in ('x', 'u', 'r', 'new', 'gone', 'missing')] == [0, 0, 0, 44, None, None]
	assert rv.learn_copy_version(job.job_vault, versions[20], 'a/x') == 0
