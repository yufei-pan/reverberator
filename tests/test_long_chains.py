import errno
import itertools
import os
import shutil
import sqlite3
import stat
from collections import OrderedDict
import pytest
import reverberator as rv
from tests.harness import seed_monitor, run_backup, event_entry, write_committed_version, latest_version
from tests.test_names import write_schema_1, contents as database_contents

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


# --- copying a file again before its chain passes its threshold ---

def backup(job, *changed, events=(), **kwargs):
	'''
	One committed version as the backuper makes it: events (event_entry() pairs) and a modify of each rel of changed, given
	new contents first; with neither, a full comparison (the complete first version of a new vault). Returns the newest
	KeptVersion, without measuring every version as run_backup() does.
	'''
	entries = OrderedDict(events)
	for rel in changed:
		seed_monitor(job, {rel: f'{rel} as of {len(rv.list_versions(job.job_vault))}'})
		entries.update([event_entry(job, rel, 'modify')])
	options = dict(keep_one_complete_backup=True, only_sync_attributes=True, keep_n_versions=0, backup_size_limit='0')
	options.update(kwargs)
	_, manifest, committed = rv.do_backup(entries, job_name=job.job_name, monitor_path=job.monitor, vault_path=job.vault, **options)
	manifest.close()
	assert committed is True
	return rv.list_versions(job.job_vault)[-1]


def name_with_threshold(threshold, stem='f'):
	'''The first name stem<n>.txt that is copied again once its chain would pass threshold links.'''
	return next(f'{stem}{n}.txt' for n in itertools.count() if rv.recopy_threshold(f'{stem}{n}.txt') == threshold)


def chain_length(path):
	'''How many links the kernel follows from path to the file it opens.'''
	hops = 0
	while os.path.islink(path):
		path = os.path.normpath(os.path.join(os.path.dirname(path), os.readlink(path)))
		hops += 1
	return hops


def changes(job, version):
	'''(rel, event) of each row of version's change list.'''
	return [(os.path.relpath(row.path, job.monitor), row.event) for row in rv.iter_change_list(version.change_list)]


def lookup(job, rel):
	manifest = rv.VaultManifest(job.job_vault)
	try:
		return manifest.lookup(rel)
	finally:
		manifest.close()


def forget_copy_versions(job):
	'''The vault database as an upgrade from 0.39 leaves it: no row knows where its copy is.'''
	conn = sqlite3.connect(os.path.join(job.job_vault, rv.MANIFEST_FILE_NAME), isolation_level=None)
	try:
		conn.execute('UPDATE entries SET copy_version = NULL')
	finally:
		conn.close()


def as_schema_1(job):
	'''The vault database as 0.39 left it, keeping its rows and meta.'''
	rows, meta = database_contents(job)
	os.remove(os.path.join(job.job_vault, rv.MANIFEST_FILE_NAME))
	write_schema_1(job, [row[:10] for row in rows], {key: value for key, value in meta if key != 'schema'})


def test_no_chain_passes_38_hops(job):
	# a name for each threshold, at the top and a folder down
	names = [name_with_threshold(threshold, stem) for threshold in range(rv.RECOPY_MIN_HOPS, rv.RECOPY_MAX_HOPS + 1) for stem in ('f', 'd/f')]
	seed_monitor(job, {**{name: name for name in names}, 'c.txt': 'c'})
	backup(job)
	for _ in range(45):
		version = backup(job, 'c.txt')
		for name in names:
			assert chain_length(os.path.join(version.path, name)) <= rv.recopy_threshold(name), (version.number, name)
	assert version.number == 45
	for name in names:
		with open(os.path.join(version.path, name)) as f:
			assert f.read() == name
	# each was copied again in the version its chain would have passed its threshold in, and only then
	assert copy_versions(job) == {**{name: rv.recopy_threshold(name) + 1 for name in names}, 'c.txt': 45}


def test_recopy_at_its_own_threshold(job):
	name, later = name_with_threshold(34), name_with_threshold(35)
	seed_monitor(job, {name: 'kept', later: 'kept too', 'c.txt': 'c'})
	backup(job)
	for _ in range(34):
		version = backup(job, 'c.txt')
	# V34 links to V0's copy through 34 links, as many as this name may have
	assert version.number == 34 and chain_length(os.path.join(version.path, name)) == 34
	version = backup(job, 'c.txt')
	assert not os.path.islink(os.path.join(version.path, name)) and chain_length(os.path.join(version.path, later)) == 35
	assert changes(job, version) == [(name, 'recopy'), ('c.txt', 'modify')]
	assert copy_versions(job) == {name: 35, later: 0, 'c.txt': 35}
	version = backup(job, 'c.txt')
	assert chain_length(os.path.join(version.path, name)) == 1 and not os.path.islink(os.path.join(version.path, later))
	assert changes(job, version) == [(later, 'recopy'), ('c.txt', 'modify')]
	with open(os.path.join(version.path, name)) as f:
		assert f.read() == 'kept'


def test_recopy_comes_from_the_vault(job):
	name = name_with_threshold(32)
	seed_monitor(job, {name: 'backed up', 'c.txt': 'c'})
	live = os.path.join(job.monitor, name)
	os.chmod(live, 0o640)
	os.utime(live, ns=(1_000_000_000, 1_000_000_000))
	copy = os.lstat(os.path.join(backup(job).path, name))
	# a full comparison finding nothing new checks the copies, so the record is the vault copy's, checked
	backup(job)
	record = lookup(job, name)
	assert record.unchecked == 0 and record.mtime_ns == 1_000_000_000
	for _ in range(32):
		backup(job, 'c.txt')
	# the monitored file changes, and no event for it has come yet
	with open(live, 'w') as f:
		f.write('changed since')
	os.chmod(live, 0o600)
	version = backup(job, 'c.txt')
	assert version.number == 33 and changes(job, version) == [(name, 'recopy'), ('c.txt', 'modify')]
	recopied = os.lstat(os.path.join(version.path, name))
	assert stat.S_ISREG(recopied.st_mode) and recopied.st_ino != copy.st_ino
	assert (recopied.st_mode, recopied.st_mtime_ns, recopied.st_size) == (copy.st_mode, copy.st_mtime_ns, copy.st_size)
	with open(os.path.join(version.path, name)) as f:
		assert f.read() == 'backed up'
	# recorded as the copy it came from, unchecked as any new copy is: the next comparison reads it back, and finds
	# only the monitored change
	assert lookup(job, name) == record._replace(unchecked=1)
	found = OrderedDict()
	rv.delta_generate_backup_entries(found, latest_version(job), job.monitor).close()
	assert [(path, values.event) for path, values in found.items()] == [(live, 'modify')]


def test_recopy_keeps_a_user_symlink_and_a_referenced_link(job):
	referenced, user = name_with_threshold(32, 'r'), name_with_threshold(32, 'u')
	seed_monitor(job, {referenced: 'r', 'c.txt': 'c'})
	# a referenced first version links each file to the monitored one; V1 copies a user's symlink as one
	backup(job, keep_one_complete_backup=False)
	os.symlink(referenced, os.path.join(job.monitor, user))
	backup(job, 'c.txt', events=[event_entry(job, user, 'create')], keep_one_complete_backup=False)
	# a full comparison finding nothing new reads what V0 holds
	backup(job, keep_one_complete_backup=False)
	records = {name: lookup(job, name) for name in (referenced, user)}
	assert (records[referenced].kind, records[user].kind) == ('r', 'l')
	for _ in range(32):
		version = backup(job, 'c.txt', keep_one_complete_backup=False)
	assert version.number == 33 and changes(job, version) == [(referenced, 'recopy'), ('c.txt', 'modify')]
	# the link V0 holds, as it is: not the monitored file it names
	entry = os.path.join(version.path, referenced)
	assert os.path.islink(entry) and os.readlink(entry) == os.path.join(job.monitor, referenced)
	version = backup(job, 'c.txt', keep_one_complete_backup=False)
	assert changes(job, version) == [(user, 'recopy'), ('c.txt', 'modify')]
	entry = os.path.join(version.path, user)
	assert os.path.islink(entry) and os.readlink(entry) == referenced
	assert copy_versions(job) == {referenced: 33, user: 34, 'c.txt': 34}
	assert {name: lookup(job, name) for name in (referenced, user)} == records


def test_short_jobs_never_recopy(job, monkeypatch):
	seed_monitor(job, {'a.txt': 'a', 'c.txt': 'c'})
	backup(job)
	# keeping 33 versions, no chain is longer than 32 links however many versions are made
	learned = []
	learn_copy_version = rv.learn_copy_version
	monkeypatch.setattr(rv, 'learn_copy_version', lambda *args: learned.append(args) or learn_copy_version(*args))
	for _ in range(40):
		version = backup(job, 'c.txt', keep_n_versions=33)
		assert 'recopy' not in [event for _, event in changes(job, version)]
	assert version.number == 40 and chain_length(os.path.join(version.path, 'a.txt')) == 32 and learned == []
	# an upgraded vault knows no copy version, and still nothing is read: the live vaults keep 3 to 5 versions
	forget_copy_versions(job)
	looked = []
	lstat = os.lstat
	monkeypatch.setattr(os, 'lstat', lambda *args, **kwargs: looked.append(args) or lstat(*args, **kwargs))
	manifest = rv.VaultManifest(job.job_vault)
	try:
		assert rv.recopy_rels(manifest, 213, 209, job.job_vault, version.path) == []
		assert rv.recopy_rels(manifest, 41, 41 - rv.RECOPY_MIN_HOPS, job.job_vault, version.path) == []
		assert learned == [] and looked == []
		# a version further, the copies are looked for
		rv.recopy_rels(manifest, 41, 40 - rv.RECOPY_MIN_HOPS, job.job_vault, version.path)
	finally:
		manifest.close()
	assert sorted(args[2] for args in learned) == ['a.txt', 'c.txt'] and looked


def test_upgraded_long_vault_recopies_only_past_threshold(job, monkeypatch):
	# (threshold, the version that last copied it): 40 versions from it, the first three have passed their thresholds
	files = {name_with_threshold(32, 'p'): 0, name_with_threshold(38, 'q'): 0, name_with_threshold(34, 's'): 5,
		name_with_threshold(36, 't'): 5, name_with_threshold(38, 'u'): 3}
	seed_monitor(job, {**{name: name for name in files}, 'c.txt': 'c'})
	# 0.39 made these versions, linking every unchanged file
	monkeypatch.setattr(rv, 'recopy_rels', lambda *args: [])
	backup(job)
	for number in range(1, 40):
		version = backup(job, 'c.txt', *[name for name, copied in files.items() if copied == number])
	assert version.number == 39 and chain_length(os.path.join(version.path, list(files)[0])) == 39
	monkeypatch.undo()
	as_schema_1(job)
	version = backup(job, 'c.txt')
	past = list(files)[:3]
	assert sorted(changes(job, version)) == sorted([(name, 'recopy') for name in past] + [('c.txt', 'modify')])
	assert {name: os.path.islink(os.path.join(version.path, name)) for name in files} == {name: name not in past for name in files}
	# what was learned walking the chains is kept
	assert copy_versions(job) == {**files, **dict.fromkeys(past, 40), 'c.txt': 40}
	for name in files:
		with open(os.path.join(version.path, name)) as f:
			assert f.read().startswith(name)


def test_size_estimate_counts_recopies(job, monkeypatch):
	big = name_with_threshold(32, 'big')
	seed_monitor(job, {big: 'x' * 256 * 1024, 'c.txt': 'c'})
	# a vault 0.39 made, whose chains to big now pass its threshold
	monkeypatch.setattr(rv, 'recopy_rels', lambda *args: [])
	backup(job)
	for _ in range(35):
		backup(job, 'c.txt')
	monkeypatch.undo()
	# room for the change, not for copying big again
	limit = rv.get_vault_info(job.job_vault).vault_size + 64 * 1024
	version = backup(job, 'c.txt', backup_size_limit=str(limit))
	# removing V0 to V3 moved big's copy up to V4, so its chain no longer passes its threshold: big is linked, and
	# no more versions are removed than that took
	assert version.number == 36 and rv.list_versions(job.job_vault)[0].number == 36 - rv.RECOPY_MIN_HOPS
	assert rv.get_vault_info(job.job_vault).vault_size <= limit
	assert chain_length(os.path.join(version.path, big)) == rv.RECOPY_MIN_HOPS and changes(job, version) == [('c.txt', 'modify')]


def test_history_and_picker_skip_recopies(job):
	name = name_with_threshold(32, 'd/f')
	seed_monitor(job, {name: 'kept', 'c.txt': 'c'})
	backup(job)
	for _ in range(33):
		backup(job, 'c.txt')
	versions = rv.list_versions(job.job_vault)
	assert changes(job, versions[33]) == [(name, 'recopy'), ('c.txt', 'modify')]
	history = lambda rel, folder: [(row.version.number, row.event) for row in (rv.folder_history if folder else rv.file_history)(job.job_vault, versions, job.monitor, rel)]
	picker = lambda rel, kind: [row.version.number for row in rv.restore_candidates(job.job_vault, versions, job.monitor, rel, kind)]
	assert history(name, False) == history('d', True) == [(0, 'oldest')]
	assert picker(name, 'file') == picker('d', 'folder') == [0]
	root = rv.folder_history(job.job_vault, versions, job.monitor, '')[0]
	assert (root.version.number, root.files) == (33, [('modify', 'c.txt')]) and sum(root.counts.values()) == 1
	# a change after the re-copy is listed as ever
	backup(job, name)
	versions = rv.list_versions(job.job_vault)
	assert history(name, False) == [(34, 'modify'), (0, 'oldest')] and picker(name, 'file') == [34, 0]


def test_retention_in_the_same_backup_spares_a_recopy(job):
	# keeping 34 versions, a version's chains are 33 links at most once the oldest is removed to make room for it
	spared, due = name_with_threshold(33), name_with_threshold(32)
	seed_monitor(job, {spared: 'spared', due: 'due', 'c.txt': 'c'})
	backup(job)
	for _ in range(40):
		version = backup(job, 'c.txt', keep_n_versions=34)
		assert chain_length(os.path.join(version.path, spared)) <= 33 and chain_length(os.path.join(version.path, due)) <= 32
		assert (spared, 'recopy') not in changes(job, version)
		assert ((due, 'recopy') in changes(job, version)) == (version.number == 33)
	assert rv.list_versions(job.job_vault)[0].number == 7
	# the copy V0 made has moved up to V7, the oldest kept, as removing each version moved it
	assert copy_versions(job) == {spared: 0, due: 33, 'c.txt': 40}


def test_a_chain_through_a_folder_symlink_is_not_followed(job):
	seed_monitor(job, {'d/x': 'live'})
	version = write_committed_version(job, 3, {'e/x': 'vault'}, timestamp=T)
	# a version's folder that is a symlink leads out of the vault, here to the monitored folder
	os.symlink(os.path.join(job.monitor, 'd'), os.path.join(version, 'd'))
	assert rv.chain_end(job.job_vault, version, 'd/x') is None and rv.learn_copy_version(job.job_vault, version, 'd/x') is None
	end = rv.chain_end(job.job_vault, version, 'e/x')
	assert (end.number, end.path, stat.S_ISREG(end.st.st_mode)) == (3, os.path.join(version, 'e/x'), True)


def test_a_recopy_is_checked_like_any_copy(job, monkeypatch):
	kept, lost = name_with_threshold(32, 'k'), name_with_threshold(32, 'l')
	seed_monitor(job, {kept: 'kept', lost: 'lost', 'c.txt': 'c'})
	backup(job)
	backup(job)
	records = {name: lookup(job, name) for name in (kept, lost)}
	for _ in range(33):
		version = backup(job, 'c.txt')
	assert sorted(changes(job, version)) == sorted([(kept, 'recopy'), (lost, 'recopy'), ('c.txt', 'modify')])
	assert {name: lookup(job, name) for name in (kept, lost)} == {name: record._replace(unchecked=1) for name, record in records.items()}
	# a crash soon after can leave a copy its size and mtime, but not its bytes
	path = os.path.join(version.path, lost)
	st = os.lstat(path)
	with open(path, 'r+b') as f:
		f.write(bytes(st.st_size))
	os.utime(path, ns=(st.st_atime_ns, st.st_mtime_ns))
	reads = []
	read_vault_record = rv.read_vault_record
	monkeypatch.setattr(rv, 'read_vault_record', lambda *args: reads.append(args[1]) or read_vault_record(*args))
	version = backup(job)
	assert {kept, lost} <= set(reads)
	assert version.number == 34 and changes(job, version) == [(lost, 'modify')]
	with open(os.path.join(version.path, lost)) as f:
		assert f.read() == 'lost'
	assert lookup(job, kept) == records[kept]


def test_a_failed_recopy_keeps_the_link_and_the_recorded_copy_version(job, monkeypatch):
	name = name_with_threshold(32)
	seed_monitor(job, {name: 'kept', 'c.txt': 'c'})
	backup(job)
	for _ in range(32):
		backup(job, 'c.txt')
	assert copy_versions(job)[name] == 0
	copy_command = rv.copy_command
	# a cp that cannot read its source and exits non-zero, for the file due for a copy only
	failing = ['sh', '-c', 'echo "cp: error reading \'$1\': Input/output error" >&2; exit 1', 'sh']
	monkeypatch.setattr(rv, 'copy_command', lambda source, dest: failing + [source] if os.path.basename(source) == name else copy_command(source, dest))
	before = chain_length(os.path.join(latest_version(job).path, name))
	version = backup(job, 'c.txt')
	assert version.number == 33
	path = os.path.join(version.path, name)
	assert os.path.islink(path) and chain_length(path) == before + 1
	with open(path) as f:
		assert f.read() == 'kept'
	assert changes(job, version) == [('c.txt', 'modify')]
	assert copy_versions(job)[name] == 0
	assert not [entry for entry in os.listdir(version.path) if entry.endswith('.reverberator-partial')]


def test_a_batch_s_own_changes_to_a_due_file(job):
	modified, deleted, moved, gone = (name_with_threshold(32, stem) for stem in ('m', 'd', 'v', 'g'))
	vault_size = fast_forward_to_32(job, {modified: BIG, deleted: 'd', moved: 'v', gone: 'gone'})
	# room for the new contents of modified, not for its old copy as well, overwritten as soon as it is made
	limit = vault_size + 320 * 1024
	seed_monitor(job, {modified: 'y' * 256 * 1024})
	os.remove(os.path.join(job.monitor, deleted))
	os.rename(os.path.join(job.monitor, moved), os.path.join(job.monitor, 'w.txt'))
	# gone is modified, then removed before the backup copies it
	os.remove(os.path.join(job.monitor, gone))
	version = backup(job, events=[event_entry(job, modified, 'modify'), event_entry(job, deleted, 'delete'),
		event_entry(job, 'w.txt', 'move', moved), event_entry(job, gone, 'modify')], backup_size_limit=str(limit))
	assert version.number == 33 and rv.list_versions(job.job_vault)[0].number == 0
	assert rv.get_vault_info(job.job_vault).vault_size <= limit
	# a deleted file is not copied again; a moved one takes its new copy along; one the batch writes is copied again all
	# the same, so a copy of it that fails leaves no chain past its threshold, but its own row says what the version did
	assert sorted(changes(job, version)) == sorted([(moved, 'recopy'), (modified, 'modify'), (deleted, 'delete'), ('w.txt', 'move'),
		(gone, 'modify')])
	assert not os.path.lexists(os.path.join(version.path, deleted)) and not os.path.islink(os.path.join(version.path, 'w.txt'))
	with open(os.path.join(version.path, modified)) as f:
		assert f.read() == 'y' * 256 * 1024
	with open(os.path.join(version.path, gone)) as f:
		assert not os.path.islink(os.path.join(version.path, gone)) and f.read() == 'gone'
	assert copy_versions(job) == {modified: 33, 'w.txt': 33, gone: 33, 'c.txt': 32}


def test_a_due_file_whose_chain_is_broken_is_named(job, monkeypatch):
	name = name_with_threshold(32)
	vault_size = fast_forward_to_32(job, {name: BIG})
	# the copy the chains of name lead to is lost from the vault
	os.remove(os.path.join(rv.list_versions(job.job_vault)[0].path, name))
	logged = []
	log = rv.backuperTeeLogToTl
	monkeypatch.setattr(rv, 'backuperTeeLogToTl', lambda *args, **kwargs: logged.append((args, kwargs)) or log(*args, **kwargs))
	# its record still holds its size, but nothing is copied, so nothing is counted
	version = backup(job, 'c.txt', backup_size_limit=str(vault_size + 64 * 1024))
	assert version.number == 33 and rv.list_versions(job.job_vault)[0].number == 0
	assert changes(job, version) == [('c.txt', 'modify')] and os.path.islink(os.path.join(version.path, name))
	errors = [kwargs.get('message', args[1] if len(args) > 1 else '') for args, kwargs in logged if kwargs.get('error')]
	assert any(name in message and 'cannot be followed' in message for message in errors), errors


BIG = 'x' * 256 * 1024


def fast_forward_to_32(job, tree):
	'''V0 holding tree and c.txt, then V1 to V32 changing c.txt only, so a threshold-32 file of tree is due in V33. Returns the vault's size.'''
	seed_monitor(job, {**tree, 'c.txt': 'c'})
	backup(job)
	for _ in range(32):
		backup(job, 'c.txt')
	return rv.get_vault_info(job.job_vault).vault_size


def oldest_kept(job):
	return rv.list_versions(job.job_vault)[0].number


def test_a_folder_the_batch_deletes(job):
	due = name_with_threshold(32, 'e/f')
	vault_size = fast_forward_to_32(job, {due: BIG})
	# only the folder's delete, as for a folder moved out of the tree
	shutil.rmtree(os.path.join(job.monitor, 'e'))
	version = backup(job, events=[event_entry(job, 'e/', 'delete')], backup_size_limit=str(vault_size + 64 * 1024))
	assert version.number == 33 and oldest_kept(job) == 0
	assert changes(job, version) == [('e', 'delete')] and not os.path.lexists(os.path.join(version.path, 'e'))


def test_a_folder_the_batch_copies_anew(job):
	due = name_with_threshold(32, 'e/f')
	vault_size = fast_forward_to_32(job, {due: BIG})
	# the folder is replaced in one go, as by one moved in from outside the tree: only the folder's own create
	shutil.rmtree(os.path.join(job.monitor, 'e'))
	seed_monitor(job, {due: 'y' * 256 * 1024})
	version = backup(job, events=[event_entry(job, 'e/', 'create')], backup_size_limit=str(vault_size + 320 * 1024))
	assert version.number == 33 and oldest_kept(job) == 0
	assert changes(job, version) == [('e', 'create')]
	with open(os.path.join(version.path, due)) as f:
		assert f.read() == 'y' * 256 * 1024
	# the new copy is a change, as history lists it
	versions = rv.list_versions(job.job_vault)
	assert [(row.version.number, row.event) for row in rv.file_history(job.job_vault, versions, job.monitor, due)] == [(33, 'changed'), (0, 'oldest')]


def test_a_file_the_batch_moves_onto(job):
	due, other = name_with_threshold(32, 'g'), name_with_threshold(36, 'h')
	vault_size = fast_forward_to_32(job, {due: BIG, other: 'moved'})
	os.replace(os.path.join(job.monitor, other), os.path.join(job.monitor, due))
	version = backup(job, events=[event_entry(job, due, 'move', other)], backup_size_limit=str(vault_size + 64 * 1024))
	assert version.number == 33 and oldest_kept(job) == 0
	assert changes(job, version) == [(due, 'move')]
	with open(os.path.join(version.path, due)) as f:
		assert f.read() == 'moved'


def test_a_file_the_batch_copies_for_its_attributes(job):
	due = name_with_threshold(32, 'a')
	vault_size = fast_forward_to_32(job, {due: BIG})
	os.chmod(os.path.join(job.monitor, due), 0o600)
	version = backup(job, events=[event_entry(job, due, 'attrib')], only_sync_attributes=False, backup_size_limit=str(vault_size + 320 * 1024))
	assert version.number == 33 and oldest_kept(job) == 0
	assert changes(job, version) == [(due, 'attrib')]
	copied = os.lstat(os.path.join(version.path, due))
	assert stat.S_ISREG(copied.st_mode) and stat.S_IMODE(copied.st_mode) == 0o600
