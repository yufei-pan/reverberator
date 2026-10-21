import json
import os
import sqlite3
from collections import OrderedDict
import pytest
import reverberator as rv
from tests.harness import seed_monitor, run_backup, latest_version

pytestmark = pytest.mark.unit

# the vault database as 0.39 and earlier created it
SCHEMA_1_ENTRIES = ('CREATE TABLE entries(path TEXT PRIMARY KEY, kind TEXT, size INTEGER, mtime_ns INTEGER, mode INTEGER, uid INTEGER, '
	'gid INTEGER, hash TEXT, link TEXT, unchecked INTEGER, dirty INTEGER NOT NULL DEFAULT 0) WITHOUT ROWID')
VERSION = 'V3--2021-01-01_00-00-00_-0800'


def database(job):
	return sqlite3.connect(os.path.join(job.job_vault, rv.MANIFEST_FILE_NAME), isolation_level=None)


def schema(job):
	conn = database(job)
	try:
		return conn.execute("SELECT value FROM meta WHERE key = 'schema'").fetchone()[0]
	finally:
		conn.close()


def columns(job):
	conn = database(job)
	try:
		return [row[1] for row in conn.execute('PRAGMA table_info(entries)')]
	finally:
		conn.close()


def copy_versions(job):
	conn = database(job)
	try:
		return {value for (value,) in conn.execute('SELECT copy_version FROM entries')}
	finally:
		conn.close()


def contents(job):
	'''Every row and meta pair the database holds, as stored.'''
	conn = database(job)
	try:
		return conn.execute('SELECT * FROM entries ORDER BY path').fetchall(), conn.execute('SELECT * FROM meta ORDER BY key').fetchall()
	finally:
		conn.close()


def write_schema_1(job, rows, meta):
	'''A schema '1' database holding rows (path, then the record's fields) and the meta pairs.'''
	os.makedirs(job.job_vault, exist_ok=True)
	conn = database(job)
	conn.execute('CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT) WITHOUT ROWID')
	conn.execute(SCHEMA_1_ENTRIES)
	conn.execute('CREATE INDEX dirty_entries ON entries(path) WHERE dirty')
	conn.executemany('INSERT INTO meta VALUES (?, ?)', [('schema', '1'), *meta.items()])
	conn.executemany('INSERT INTO entries(path, kind, size, mtime_ns, mode, uid, gid, hash, link, unchecked) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)', rows)
	conn.close()


def schema_1_job(job):
	'''A schema '1' database with records, names holding NAME_ESCAPE, a skip fingerprint and inner mounts.'''
	escape = rv.NAME_ESCAPE
	write_schema_1(job, [
		('a.txt', 'f', 5, 123, 0o100644, 0, 0, 'abcdef0123456789', None, 0),
		('sub/', 'd', None, None, 0o40755, 0, 0, None, None, 0),
		('sub/x' + escape + '\U0010ffff', None, None, None, None, None, None, None, None, None),
		# names differing only in how many NAME_ESCAPE they hold: doubled one by one, one would take the other's key
		('n' + escape, None, None, None, None, None, None, None, None, None),
		('n' + escape * 2, None, None, None, None, None, None, None, None, None),
		('link', 'l', None, None, 0o120777, 0, 0, None, 'to' + escape + '\U0010ff80', 0),
	], {'version': VERSION, 'skip_fingerprint': 'abc', 'inner_mounts': json.dumps(['mnt/', 'm' + escape + '\U0010ff80/'])})


def unverified():
	return rv.ManifestRecord(*[None] * len(rv.MANIFEST_RECORD_HEADER))


def test_manifest_round_trips_bad_names(job):
	folder, nested, other, name = 'd\udcff/', 'd\udcff/x\udc80', 'd\udcff/y.txt', 'bad\udcfe.txt'
	version_path = os.path.join(job.job_vault, VERSION)
	# a tree holding names that are not UTF-8, as the vault holds them
	os.makedirs(os.path.join(os.fsencode(version_path), b'd\xff'))
	for rel in (b'd\xff/x\x80', b'd\xff/y.txt', b'bad\xfe.txt'):
		open(os.path.join(os.fsencode(version_path), rel), 'w').close()
	manifest = rv.VaultManifest(job.job_vault)
	manifest.begin()
	manifest.rebuild(version_path)
	assert (manifest.folders, sorted(manifest.files)) == ([folder], sorted([nested, other, name]))
	manifest.reset(version_path)
	for rel in (folder, nested, other, name, 'café.txt'):
		manifest.add(rel, dirty=rel != 'café.txt')
	assert sorted(manifest.take_dirty(100)) == sorted([folder, nested, other, name])
	link = rv.ManifestRecord('l', None, None, 0o120777, 0, 0, None, 'target\udcff', 0)
	manifest.set_records([(name, link), (nested, None)])
	assert manifest.lookup(name) == link and manifest.lookup(nested) == unverified()
	assert sorted(manifest.take_dirty(100)) == [folder, other]
	assert list(manifest.iter_under(folder)) == sorted([nested, other]) and manifest.counts() == (4, 1)
	manifest.clear_seen()
	manifest.mark_seen([name])
	manifest.mark_seen_under(folder)
	assert manifest.unseen() == sorted(['café.txt', folder]) and manifest.unseen_under(folder) == [folder]
	manifest.set_inner_mounts([folder, 'mnt/'])
	assert manifest.inner_mounts == [folder, 'mnt/']
	manifest.move_tree(folder, 'e/f/')
	assert manifest.folders == ['e/f/'] and sorted(manifest.files) == sorted(['café.txt', name, 'e/f/x\udc80', 'e/f/y.txt'])
	manifest.move_tree('e/f/', 'g\udcfd/')
	assert manifest.folders == ['g\udcfd/'] and list(manifest.iter_under('g\udcfd/')) == ['g\udcfd/x\udc80', 'g\udcfd/y.txt']
	manifest.discard(name)
	manifest.discard_many(['g\udcfd/x\udc80'])
	manifest.commit(version_path)
	manifest.close()
	reopened = rv.VaultManifest(job.job_vault)
	assert reopened.describes(version_path) and reopened.inner_mounts == [folder, 'mnt/']
	assert (reopened.folders, sorted(reopened.files)) == (['g\udcfd/'], sorted(['café.txt', 'g\udcfd/y.txt']))
	reopened.begin()
	reopened.remove_tree('g\udcfd/')
	assert reopened.files == ['café.txt'] and reopened.folders == []
	reopened.close()


def test_manifest_round_trips_escape_lookalikes(job):
	escape = rv.NAME_ESCAPE
	# names holding the escape character or the code points it uses, next to the bad names they look like
	folder = 'f' + escape + '/'
	names = [escape, escape * 2, escape + 'a', 'y' + escape, 'x' + escape + '\U0010ff80', 'x\udc80', '\U0010ffff', 'x' + escape * 2 + '\U0010ffff',
		folder + escape + '\U0010ffff', folder + '\udcff']
	os.makedirs(job.job_vault)
	manifest = rv.VaultManifest(job.job_vault)
	manifest.begin()
	manifest.add(folder)
	for rel in names:
		manifest.add(rel, dirty=True)
	assert sorted(manifest.files) == sorted(names) and manifest.folders == [folder]
	assert sorted(manifest.take_dirty(100)) == sorted(names)
	link = rv.ManifestRecord('l', None, None, 0o120777, 0, 0, None, escape + '\U0010ff80' + escape, 0)
	manifest.set_records([(rel, link) for rel in names])
	assert all(manifest.lookup(rel) == link for rel in names)
	assert sorted(manifest.iter_under(folder)) == sorted([folder + escape + '\U0010ffff', folder + '\udcff'])
	manifest.clear_seen()
	manifest.mark_seen(names[:4])
	assert manifest.unseen() == sorted([folder, *names[4:]], key=rv.storable_name)
	manifest.set_inner_mounts([folder, escape + '/'])
	assert manifest.inner_mounts == [folder, escape + '/']
	manifest.move_tree(folder, 'g' + escape * 2 + '/')
	assert sorted(manifest.iter_under('g' + escape * 2 + '/')) == sorted(['g' + escape * 2 + '/' + escape + '\U0010ffff', 'g' + escape * 2 + '/\udcff'])
	for rel in names[:4]:
		manifest.discard(rel)
		assert manifest.lookup(rel) is None
	manifest.commit(os.path.join(job.job_vault, VERSION))
	manifest.close()
	reopened = rv.VaultManifest(job.job_vault)
	assert sorted(reopened.files) == sorted(names[4:8] + ['g' + escape * 2 + '/' + escape + '\U0010ffff', 'g' + escape * 2 + '/\udcff'])
	assert all(reopened.lookup(rel) == link for rel in names[4:8])
	assert reopened.inner_mounts == [folder, escape + '/']
	reopened.close()


def test_schema_1_upgrades_in_place(job):
	escape = rv.NAME_ESCAPE
	schema_1_job(job)
	manifest = rv.VaultManifest(job.job_vault)
	assert manifest.lookup('a.txt') == rv.ManifestRecord('f', 5, 123, 0o100644, 0, 0, 'abcdef0123456789', None, 0)
	assert manifest.skip_fingerprint == 'abc' and manifest.inner_mounts == ['mnt/', 'm' + escape + '\U0010ff80/']
	assert manifest.describes(os.path.join(job.job_vault, VERSION))
	assert manifest.folders == ['sub/'] and sorted(manifest.files) == sorted(['a.txt', 'sub/x' + escape + '\U0010ffff', 'n' + escape, 'n' + escape * 2, 'link'])
	assert manifest.lookup('sub/x' + escape + '\U0010ffff') == unverified() and manifest.lookup('link').link == 'to' + escape + '\U0010ff80'
	manifest.close()
	assert schema(job) == '2' and copy_versions(job) == {None} and columns(job)[-1] == 'copy_version'
	# the upgraded database is the one a new vault gets
	os.makedirs(os.path.join(job.root, 'fresh'))
	rv.VaultManifest(os.path.join(job.root, 'fresh')).close()
	fresh = sqlite3.connect(os.path.join(job.root, 'fresh', rv.MANIFEST_FILE_NAME))
	assert [row[1] for row in fresh.execute('PRAGMA table_info(entries)')] == columns(job)
	fresh.close()


def test_failed_upgrade_leaves_schema_1(job, monkeypatch):
	schema_1_job(job)
	before = contents(job)
	upgrade = rv.VaultManifest._upgrade_from_schema_1

	def failing(manifest):
		# every step runs, then the disk fails before the upgrade commits
		upgrade(manifest)
		raise sqlite3.OperationalError('disk I/O error')
	monkeypatch.setattr(rv.VaultManifest, '_upgrade_from_schema_1', failing)
	with pytest.raises(rv.JobFailure, match='disk I/O error'):
		rv.VaultManifest(job.job_vault)
	assert contents(job) == before and schema(job) == '1' and 'copy_version' not in columns(job)
	monkeypatch.undo()
	# the job's next attempt upgrades
	manifest = rv.VaultManifest(job.job_vault)
	assert manifest.skip_fingerprint == 'abc' and manifest.lookup('a.txt').size == 5
	manifest.close()
	assert schema(job) == '2'


def test_unknown_schema_is_started_over(job):
	schema_1_job(job)
	conn = database(job)
	conn.execute("UPDATE meta SET value = '0' WHERE key = 'schema'")
	conn.close()
	manifest = rv.VaultManifest(job.job_vault)
	assert manifest.files == [] and manifest.skip_fingerprint is None and manifest.inner_mounts == []
	manifest.close()
	assert schema(job) == '2'


def test_upgraded_database_reads_nothing_from_the_vault(job, monkeypatch):
	seed_monitor(job, {'a.txt': 'hello', 'sub/b.txt': 'world'})
	run_backup(job)
	# the second backup reads the copies back once, so every row is recorded and checked
	run_backup(job)
	rows, meta = contents(job)
	os.remove(os.path.join(job.job_vault, rv.MANIFEST_FILE_NAME))
	write_schema_1(job, [row[:10] for row in rows], {key: value for key, value in meta if key != 'schema'})
	reads = []
	read = rv.read_vault_record
	monkeypatch.setattr(rv, 'read_vault_record', lambda *args: reads.append(args) or read(*args))
	entries = OrderedDict()
	rv.delta_generate_backup_entries(entries, latest_version(job), job.monitor).close()
	assert entries == OrderedDict() and reads == []
	assert schema(job) == '2'
