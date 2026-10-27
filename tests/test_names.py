import json
import os
import sqlite3
import subprocess
import sys
from collections import deque, OrderedDict
import pytest
import reverberator as rv
from tests.harness import seed_monitor, run_backup, latest_version, event_entry, write_rule, write_committed_version, create_job, reverberator_script

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


def test_schema_1_without_its_entries_table_upgrades(job):
	# 0.39 created a new database's meta and its entries table in separate commits: a crash between them left this
	os.makedirs(job.job_vault)
	conn = database(job)
	conn.execute('CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT) WITHOUT ROWID')
	conn.executemany('INSERT INTO meta VALUES (?, ?)', [('schema', '1'), ('version', VERSION), ('skip_fingerprint', 'abc'), ('inner_mounts', '["mnt/"]')])
	conn.close()
	manifest = rv.VaultManifest(job.job_vault)
	assert (manifest.files, manifest.folders) == ([], [])
	assert manifest.describes(os.path.join(job.job_vault, VERSION)) and manifest.skip_fingerprint == 'abc' and manifest.inner_mounts == ['mnt/']
	manifest.close()
	assert schema(job) == '2' and columns(job)[-1] == 'copy_version'


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
	monkeypatch.setattr(rv, 'CHECKED_COPY_AGE_SECONDS', 0)   # this test's copies count as old
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


# --- names that are not UTF-8 through backups, change lists, pending transactions, the journal and the commands ---

T0 = '2021-01-01_00-00-00_-0800'
# how storable_name() writes the byte 0xff of a name, in UTF-8: NAME_ESCAPE, then U+10FFFF
STORED_FF = b'\xf4\x8f\xb8\x80\xf4\x8f\xbf\xbf'


def put(root, rel, content='x'):
	'''Write the file rel (bytes, relative to root) holding content.'''
	path = os.path.join(os.fsencode(root), rel)
	os.makedirs(os.path.dirname(path), exist_ok=True)
	with open(path, 'w', encoding='utf-8') as f:
		f.write(content)


def listing(root):
	'''What is under root by the bytes of each name: a file's text (through a link), None for a folder (ending with /).'''
	found = {}
	top = os.fsencode(root)
	for folder, names, files in os.walk(top):
		for name in names + files:
			path = os.path.join(folder, name)
			rel = os.path.relpath(path, top)
			if os.path.isdir(path) and not os.path.islink(path):
				found[rel + b'/'] = None
			else:
				with open(path, encoding='utf-8') as f:
					found[rel] = f.read()
	return found


def is_link(root, rel):
	return os.path.islink(os.path.join(os.fsencode(root), rel))


def backup(job, *entries, **kwargs):
	'''One backup of the entries, each (rel, event) or (rel, 'move', source rel), and the kept versions' folders after it.'''
	run_backup(job, OrderedDict(event_entry(job, *entry) for entry in entries), **kwargs)
	return [version.path for version in rv.list_versions(job.job_vault)]


def change_rows(version):
	return [(row.path, row.event, row.source_path) for row in rv.iter_change_list(version.change_list)]


def raw(path):
	with open(path, 'rb') as f:
		return f.read()


def stored(path):
	'''How a path is written into the files the daemon keeps: the bytes of its escaped form.'''
	return rv.storable_name(path).encode('utf-8')


def raw_rows(path):
	'''The rows of the NUL separated file at path as they are on disk, the header left out: each a list of its fields' bytes.'''
	return [line.split(b'\0') for line in raw(path).split(b'\n')[1:] if line]


def written(path):
	'''The fields of each row of the NUL separated file at path as TSVZ was given them: the file must be UTF-8 throughout.'''
	return [[rv.unescape_change_list_field(field.decode('utf-8')) for field in row] for row in raw_rows(path)]


def test_first_full_backup_of_a_bad_name(job):
	put(job.monitor, b'bad\xff.txt', 'bad')
	put(job.monitor, b'd\xff/x\xfe', 'nested')
	put(job.monitor, b'ok.txt', 'ok')
	expected = {b'bad\xff.txt': 'bad', b'd\xff/': None, b'd\xff/x\xfe': 'nested', b'ok.txt': 'ok'}
	[v0] = backup(job)
	assert listing(v0) == expected and not is_link(v0, b'bad\xff.txt')
	manifest = rv.VaultManifest(job.job_vault)
	assert manifest.describes(v0) and manifest.folders == ['d\udcff/'] and sorted(manifest.files) == sorted(['bad\udcff.txt', 'd\udcff/x\udcfe', 'ok.txt'])
	manifest.close()
	# a referenced first backup links each name to the monitored file of the same bytes
	other = create_job(os.path.join(job.root, 'referenced'))
	put(other.monitor, b'bad\xff.txt', 'bad')
	put(other.monitor, b'd\xff/x\xfe', 'nested')
	put(other.monitor, b'ok.txt', 'ok')
	[v0] = backup(other, keep_one_complete_backup=False)
	assert listing(v0) == expected and os.readlink(os.path.join(os.fsencode(v0), b'd\xff/x\xfe')) == os.fsencode(other.monitor) + b'/d\xff/x\xfe'


def test_events_on_bad_names(job, poll_fast):
	put(job.monitor, b'keep', 'k')
	os.makedirs(os.fsencode(job.monitor) + b'/d\xfe/sub')
	run_backup(job)
	monitor = os.fsencode(job.monitor)
	bad, moved = 'bad\udcff.txt', 'd\udcfe/sub/x\udcfd.txt'
	put(job.monitor, b'bad\xff.txt', 'one')
	v1 = backup(job, (bad, 'create'))[-1]
	assert listing(v1)[b'bad\xff.txt'] == 'one' and not is_link(v1, b'bad\xff.txt')
	put(job.monitor, b'bad\xff.txt', 'two!')
	v2 = backup(job, (bad, 'modify'))[-1]
	assert listing(v2)[b'bad\xff.txt'] == 'two!' and not is_link(v2, b'bad\xff.txt') and listing(v1)[b'bad\xff.txt'] == 'one'
	# moved two folders down, into a folder whose name is not UTF-8 either
	os.rename(monitor + b'/bad\xff.txt', monitor + b'/d\xfe/sub/x\xfd.txt')
	v3 = backup(job, (moved, 'move', bad))[-1]
	assert listing(v3) == {b'keep': 'k', b'd\xfe/': None, b'd\xfe/sub/': None, b'd\xfe/sub/x\xfd.txt': 'two!'}
	os.remove(monitor + b'/d\xfe/sub/x\xfd.txt')
	v4 = backup(job, (moved, 'delete'))[-1]
	assert listing(v4) == {b'keep': 'k', b'd\xfe/': None, b'd\xfe/sub/': None}
	kept = rv.list_versions(job.job_vault)
	path = lambda rel: os.path.join(job.monitor, rel)
	assert [change_rows(version) for version in kept[1:]] == [[(path(bad), 'create', None)], [(path(bad), 'modify', None)],
		[(path(moved), 'move', path(bad))], [(path(moved), 'delete', None)]]
	# the files hold each name's escaped form, never a replacement character
	assert stored(path(bad)) == os.fsencode(job.monitor) + b'/bad' + STORED_FF + b'.txt'
	assert [[(row[0], row[2], row[3]) for row in raw_rows(version.change_list)] for version in kept[1:]] == [
		[(stored(path(bad)), b'create', b'None')], [(stored(path(bad)), b'modify', b'None')],
		[(stored(path(moved)), b'move', stored(path(bad)))], [(stored(path(moved)), b'delete', b'None')]]
	manifest = rv.VaultManifest(job.job_vault)
	assert manifest.files == ['keep'] and manifest.folders == ['d\udcfe/', 'd\udcfe/sub/']
	manifest.close()
	# and the next comparison finds the tree as the vault holds it
	assert backup(job)[-1] == v4


def test_delta_generation_with_bad_names(job, poll_fast):
	seed_monitor(job, {'a.txt': 'hello', 'sub/b.txt': 'world'})
	run_backup(job)
	run_backup(job)
	# the vault as 0.39 left it: a schema '1' database
	rows, meta = contents(job)
	os.remove(os.path.join(job.job_vault, rv.MANIFEST_FILE_NAME))
	write_schema_1(job, [row[:10] for row in rows], {key: value for key, value in meta if key != 'schema'})
	put(job.monitor, b'bad\xff.txt', 'bad')
	put(job.monitor, b'sub/x\xfe', 'nested')
	put(job.monitor, b'd\xff/y\xfd', 'deeper')
	entries = OrderedDict()
	rv.delta_generate_backup_entries(entries, latest_version(job), job.monitor).close()
	assert schema(job) == '2'
	assert {path: values.event for path, values in entries.items()} == {os.path.join(job.monitor, 'bad\udcff.txt'): 'create',
		os.path.join(job.monitor, 'sub/x\udcfe'): 'create', os.path.join(job.monitor, 'd\udcff/'): 'create', os.path.join(job.monitor, 'd\udcff/y\udcfd'): 'create'}
	v1 = backup(job, log_journal=True)[-1]
	assert listing(v1) == {b'a.txt': 'hello', b'sub/': None, b'sub/b.txt': 'world', b'bad\xff.txt': 'bad', b'sub/x\xfe': 'nested',
		b'd\xff/': None, b'd\xff/y\xfd': 'deeper'}
	# its change list records what the comparison found
	assert sorted((path, event) for path, event, _ in change_rows(rv.list_versions(job.job_vault)[-1])) == sorted(
		(os.path.join(job.monitor, rel), 'create') for rel in ('bad\udcff.txt', 'sub/x\udcfe', 'd\udcff/', 'd\udcff/y\udcfd'))
	# and so does the journal, each name as it is stored
	journal = [line.split(b'\t') for line in raw(os.path.join(job.job_vault, 'journal.tsv')).split(b'\n')[1:] if line]
	assert sorted(row[0] for row in journal if row[2] == b'create') == sorted(stored(os.path.join(job.monitor, rel))
		for rel in ('bad\udcff.txt', 'sub/x\udcfe', 'd\udcff/', 'd\udcff/y\udcfd'))
	assert os.fsencode(job.monitor) + b'/bad' + STORED_FF + b'.txt' in [row[0] for row in journal]
	# a full comparison after the backup finds nothing to do, and finds a change made to such a name
	entries = OrderedDict()
	rv.delta_generate_backup_entries(entries, latest_version(job), job.monitor).close()
	assert entries == OrderedDict()
	put(job.monitor, b'd\xff/y\xfd', 'changed')
	entries = OrderedDict()
	rv.delta_generate_backup_entries(entries, latest_version(job), job.monitor).close()
	assert {path: values.event for path, values in entries.items()} == {os.path.join(job.monitor, 'd\udcff/y\udcfd'): 'modify'}


def test_change_list_round_trips_bad_names(job, poll_fast):
	escape = rv.NAME_ESCAPE
	put(job.monitor, b'keep', 'k')
	put(job.monitor, b'gone\xfb', 'g')
	run_backup(job)
	# names that are not UTF-8, ones holding the escape or what it escapes to, and the text TSVZ escapes itself
	names = ['bad\udcff.txt', 'two\nlines\udcfe', 'x' + escape, 'x' + escape + '\U0010ffff', 'x\U0010ff80', 'tab\there', '<sep><LF>\udc80']
	for name in names:
		put(job.monitor, os.fsencode(name), ascii(name))
	os.makedirs(os.fsencode(job.monitor) + b'/d\xff')
	os.rename(os.fsencode(job.monitor) + b'/gone\xfb', os.fsencode(job.monitor) + b'/d\xff/came\xfc')
	v1 = backup(job, *[(name, 'create') for name in names], ('d\udcff/', 'create'), ('d\udcff/came\udcfc', 'move', 'gone\udcfb'))[-1]
	assert all(listing(v1)[os.fsencode(name)] == ascii(name) for name in names)
	version = rv.list_versions(job.job_vault)[1]
	path = lambda rel: os.path.join(job.monitor, rel)
	assert sorted(change_rows(version)) == sorted([(path(name), 'create', None) for name in names] + [(path('d\udcff/'), 'create', None),
		(path('d\udcff/came\udcfc'), 'move', path('gone\udcfb'))])
	# on disk each is valid UTF-8, the escaped form of the name, never a replacement character
	assert b'?' not in raw(version.change_list)
	assert sorted((row[0], row[3]) for row in written(version.change_list)) == sorted([(rv.storable_name(path(name)), 'None') for name in names]
		+ [(rv.storable_name(path('d\udcff/')), 'None'), (rv.storable_name(path('d\udcff/came\udcfc')), rv.storable_name(path('gone\udcfb')))])
	# a change list as 0.39 wrote it reads as it did: names hold no escape
	with open(version.change_list, 'ab') as f:
		f.write(os.fsencode(job.monitor) + b'/old\xfa\x002021-01-02T00:00:00\x00create\x00None\n')
	assert change_rows(version)[-1] == (path('old\udcfa'), 'create', None)


def test_pending_transactions_round_trip_bad_names(job, tmp_path):
	escape = rv.NAME_ESCAPE
	put(job.monitor, b'bad\xff.txt')
	path = lambda rel: os.path.join(job.monitor, rel)
	events = [
		rv.ChangeEvent(5.0, False, 'create', path('bad\udcff.txt'), None),
		rv.ChangeEvent(5.0, False, 'move', path('d\udcff/x\udcfe'), path('bad\udcfd')),
		rv.ChangeEvent(6.0, True, 'delete', path('e\udcfc') + '/', None),
		rv.ChangeEvent(7.0, False, 'modify', path('two\nlines\udcfb'), None),
		rv.ChangeEvent(8.0, False, 'modify', path('x' + escape + '\U0010ffff'), None),
		rv.ChangeEvent(9.0, False, 'move', path('x\U0010ff80'), path('y' + escape)),
	]
	os.makedirs(job.job_vault)
	rv.persist_pending_transactions(job.job_name, job.vault, deque(events))
	pending = os.path.join(job.job_vault, rv.PENDING_TRANSACTIONS_FILE_NAME)
	assert b'?' not in raw(pending) and raw_rows(pending)[0][3] == os.fsencode(job.monitor) + b'/bad' + STORED_FF + b'.txt'
	assert [row[3:] for row in written(pending)] == [[rv.storable_name(event.path), rv.storable_name(event.moved_from or '')] for event in events]
	for folder, names, files in os.walk(job.monitor):
		for name in [folder] + [os.path.join(folder, name) for name in files]:
			os.utime(name, (1000, 1000))
	os.utime(pending, (2000, 2000))
	loaded = rv.ChangeEventQueue(job.monitor)
	assert rv.load_pending_transactions_for_resume(job.job_name, job.monitor, job.vault, loaded) is True
	assert [(event.event, event.is_dir, event.path, event.moved_from) for event in loaded] == [
		(event.event, event.is_dir, event.path, event.moved_from) for event in events]
	assert not os.path.exists(pending)
	# as 0.39 wrote them, with no escape in any name
	rv.persist_pending_transactions(job.job_name, job.vault, deque([rv.ChangeEvent(1.0, False, 'modify', path('café'), None)]))
	os.utime(pending, (2000, 2000))
	loaded = rv.ChangeEventQueue(job.monitor)
	assert rv.load_pending_transactions_for_resume(job.job_name, job.monitor, job.vault, loaded) is True
	assert [event.path for event in loaded] == [path('café')]


def test_retention_with_bad_names(job, poll_fast):
	put(job.monitor, b'bad\xff.txt', 'old')
	put(job.monitor, b'd\xff/x\xfe', 'nested')
	put(job.monitor, b'keep', 'k')
	v0 = backup(job)[-1]
	put(job.monitor, b'keep', 'k1')
	v1 = backup(job, ('keep', 'modify'))[-1]
	assert is_link(v1, b'bad\xff.txt') and is_link(v1, b'd\xff/x\xfe')
	put(job.monitor, b'keep', 'k22')
	backup(job, ('keep', 'modify'), keep_n_versions=2)
	# V0 is pruned: its copies move into V1 under their own bytes, and V2 still reaches them
	kept = rv.list_versions(job.job_vault)
	assert not os.path.lexists(v0) and [version.path for version in kept][:1] == [v1]
	assert not is_link(v1, b'bad\xff.txt') and not is_link(v1, b'd\xff/x\xfe')
	assert listing(v1) == {b'bad\xff.txt': 'old', b'd\xff/': None, b'd\xff/x\xfe': 'nested', b'keep': 'k1'}
	assert listing(kept[1].path) == {b'bad\xff.txt': 'old', b'd\xff/': None, b'd\xff/x\xfe': 'nested', b'keep': 'k22'}
	assert len(backup(job)) == 2


def test_nested_bad_names_survive_a_move_and_restore(job, tmp_path, capsys, poll_fast):
	put(job.monitor, b'keep', 'k')
	put(job.monitor, b'd\xff/x\xfe', 'nested')
	os.makedirs(os.fsencode(job.monitor) + b'/a/b')
	run_backup(job)
	monitor = os.fsencode(job.monitor)
	os.rename(monitor + b'/d\xff', monitor + b'/a/b/d\xff')
	v1 = backup(job, ('a/b/d\udcff/', 'move', 'd\udcff/'))[-1]
	assert listing(v1) == {b'keep': 'k', b'a/': None, b'a/b/': None, b'a/b/d\xff/': None, b'a/b/d\xff/x\xfe': 'nested'}
	write_rule(job)
	kept = rv.list_versions(job.job_vault)
	at = lambda number: rv.show_time(kept[number].timestamp)

	def command(*argv):
		capsys.readouterr()
		code = rv.run_command([*argv, '--rule', job.rule_path, '--state_dir', str(tmp_path / 'state')])
		captured = capsys.readouterr()
		return code, captured.out, captured.err
	code, out, err = command('history', f'{job.monitor}/a/b/d\udcff/x\udcfe')
	assert (code, err) == (0, '')
	assert out.split('\n')[1:] == [f'V1  {at(1)}  moved from {job.monitor}/d\\xff/x\\xfe  {rv.show_size(6)}', '']
	code, out, err = command('history', f'{job.monitor}/d\udcff/x\udcfe')
	assert (code, err) == (0, '')
	assert out.split('\n')[1:] == [f'V1  {at(1)}  moved to {job.monitor}/a/b/d\\xff/x\\xfe', f'V0  {at(0)}  oldest kept copy  {rv.show_size(6)}', '']
	code, out, err = command('history', f'{job.monitor}/a', '--files')
	assert (code, err) == (0, '') and '    move b/d\\xff/' in out.split('\n')
	# restored from either version, the folder and the file keep their bytes
	for number, rel in ((1, 'a/b/d\udcff'), (0, 'd\udcff')):
		out_dir = tmp_path / f'out{number}'
		out_dir.mkdir()
		code, out, err = command('restore', f'{job.monitor}/{rel}', str(out_dir), '--version', str(number))
		assert (code, err) == (0, '')
		assert listing(str(out_dir)) == {b'd\xff/': None, b'd\xff/x\xfe': 'nested'}
		assert out == f'Restored 2 entries ({rv.show_size(6)}) from V{number} to {out_dir}/d\\xff\n'
	# and in place, where it was, what is there now moved aside under a name keeping the bytes too
	put(job.monitor, b'a/b/d\xff/x\xfe', 'edited')
	code, out, err = command('restore', f'{job.monitor}/a/b/d\udcff', '--in-place', '--version', '1', '--yes')
	assert (code, err) == (0, '')
	[aside] = [name for name in os.listdir(monitor + b'/a/b') if name != b'd\xff']
	assert aside.startswith(b'd\xff.before-restore-')
	assert listing(job.monitor) == {b'keep': 'k', b'a/': None, b'a/b/': None, b'a/b/d\xff/': None, b'a/b/d\xff/x\xfe': 'nested',
		b'a/b/' + aside + b'/': None, b'a/b/' + aside + b'/x\xfe': 'edited'}
	assert out.split('\n')[0] == f'Moved {job.monitor}/a/b/d\\xff aside to {job.monitor}/a/b/d\\xff{os.fsdecode(aside[2:])}'
	os.remove(monitor + b'/a/b/d\xff/x\xfe')
	os.rmdir(monitor + b'/a/b/d\xff')
	code, out, err = command('restore', f'{job.monitor}/a/b/d\udcff', '--in-place', '--version', '1', '--yes')
	assert (code, err) == (0, '') and listing(os.path.join(job.monitor, 'a/b/d\udcff')) == {b'x\xfe': 'nested'}
	file_out = tmp_path / 'file'
	file_out.mkdir()
	code, out, err = command('restore', f'{job.monitor}/a/b/d\udcff/x\udcfe', str(file_out), '--version', '1')
	assert (code, err) == (0, '') and listing(str(file_out)) == {b'x\xfe': 'nested'}


def test_commands_take_bad_paths(job, tmp_path, capsys, process_env, poll_fast):
	put(job.monitor, b'keep', 'k')
	run_backup(job)
	put(job.monitor, b'bad\xff.txt', 'one')
	backup(job, ('bad\udcff.txt', 'create'))
	put(job.monitor, b'bad\xff.txt', 'two!')
	backup(job, ('bad\udcff.txt', 'modify'))
	write_rule(job)
	kept = rv.list_versions(job.job_vault)
	at = lambda number: rv.show_time(kept[number].timestamp)
	state = str(tmp_path / 'state')
	expected = [f'job {job.job_name}, vault {job.job_vault}', f'V2  {at(2)}  modified  {rv.show_size(4)}', f'V1  {at(1)}  created  {rv.show_size(3)}', '']
	for argv in (['history', f'{job.monitor}/bad\udcff.txt'], ['history', 'bad\udcff.txt', '--job', job.job_name]):
		capsys.readouterr()
		code = rv.run_command([*argv, '--rule', job.rule_path, '--state_dir', state])
		captured = capsys.readouterr()
		assert (code, captured.err) == (0, '') and captured.out.split('\n') == expected
	out_dir = tmp_path / 'out'
	out_dir.mkdir()
	capsys.readouterr()
	code = rv.run_command(['restore', 'bad\udcff.txt', str(out_dir), '--job', job.job_name, '--version', '1', '--rule', job.rule_path, '--state_dir', state])
	captured = capsys.readouterr()
	assert (code, captured.err) == (0, '') and listing(str(out_dir)) == {b'bad\xff.txt': 'one'}
	assert captured.out == f'Restored 1 entries ({rv.show_size(3)}) from V1 to {out_dir}/bad\\xff.txt\n'
	# the bytes as a shell passes them
	script = [sys.executable, reverberator_script()]
	ran = subprocess.run([*script, 'history', os.fsencode(job.monitor) + b'/bad\xff.txt', '--rule', job.rule_path, '--state_dir', state],
		env=dict(process_env, LC_ALL='C'), capture_output=True, timeout=60)
	assert (ran.returncode, ran.stderr) == (0, b'') and ran.stdout.decode('ascii').split('\n') == expected
	os.remove(os.path.join(os.fsencode(out_dir), b'bad\xff.txt'))
	ran = subprocess.run([*script, 'restore', os.fsencode(job.monitor) + b'/bad\xff.txt', str(out_dir), '--version', '2', '--rule', job.rule_path,
		'--state_dir', state], env=process_env, capture_output=True, timeout=60)
	assert (ran.returncode, ran.stderr) == (0, b'') and listing(str(out_dir)) == {b'bad\xff.txt': 'two!'}
	assert ran.stdout == f'Restored 1 entries ({rv.show_size(4)}) from V2 to {out_dir}/bad\\xff.txt\n'.encode('ascii')
	# what a command refuses with quotes the path escaped too
	capsys.readouterr()
	code = rv.run_command(['history', '/elsewhere/bad\udcff', '--rule', job.rule_path, '--state_dir', state])
	captured = capsys.readouterr()
	assert code == rv.EXIT_USAGE and captured.err.startswith('/elsewhere/bad\\xff is not under')


def test_status_and_marker_json_keep_bad_names(job, tmp_path):
	state = str(tmp_path / 'state')
	board = rv.StatusBoard(state, job.rule_path)
	detail = f'monitored filesystem not ready: {job.monitor}/d\udcff'
	board.write_job(job.job_name, {'job': job.job_name, 'state': 'waiting', 'detail': detail, 'since': 0, 'retry_at': None, 'failures': 0,
		'last_success': None, 'updated': 0})
	data = raw(os.path.join(state, f'job-{job.job_name}.json'))
	assert data.isascii() and b'd\\udcff' in data
	assert rv.read_status(state).jobs[job.job_name]['detail'] == detail
	assert rv.job_state_phrase(rv.read_status(state).jobs[job.job_name], False, None).endswith(detail)
	# a restore marker records the path as typed
	write_committed_version(job, 0, {'keep': 'k'}, timestamp=T0)
	[version] = rv.list_versions(job.job_vault)
	target = tmp_path / 'target'
	target.mkdir(mode=0o700)
	marker = rv.write_restore_marker(str(target), job.job_name, 'd\udcff/x\udcfe', version)
	assert raw(marker).isascii()
	assert rv.read_restore_marker(str(target)) == {'job': job.job_name, 'path': 'd\udcff/x\udcfe', 'version': version.name}
