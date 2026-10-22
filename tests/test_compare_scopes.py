import os
from collections import OrderedDict
import pytest
import reverberator as rv
from tests.harness import seed_monitor, run_backup, latest_version

pytestmark = pytest.mark.unit

T1 = '2021-01-02_00-00-00_-0800'


@pytest.fixture(autouse=True)
def _fast(poll_fast):
	return poll_fast


def backed_up(job, tree):
	'''The monitored tree seeded with tree and backed up as V0, and the job's manifest describing it.'''
	seed_monitor(job, tree)
	run_backup(job)
	return latest_version(job).path, rv.VaultManifest(job.job_vault)


def events(job, entries):
	return {path[len(job.monitor) + 1:]: values.event for path, values in entries.items()}


def compare(job, manifest, scopes, version_path=None, **kwargs):
	'''The events compare_scopes() finds, in a transaction rolled back afterwards, as the batch's would be on a failure.'''
	entries = OrderedDict()
	manifest.begin()
	try:
		rv.compare_scopes(entries, manifest, version_path or latest_version(job).path, job.monitor, scopes, **kwargs)
	finally:
		manifest.rollback()
	return events(job, entries)


def rows(manifest):
	return list(manifest.conn.execute('SELECT * FROM entries ORDER BY path'))


def test_a_single_path_reports_its_modify(job):
	_, manifest = backed_up(job, {'a.txt': 'hello', 'b.txt': 'b'})
	open(os.path.join(job.monitor, 'a.txt'), 'w').write('changed')
	# not named, so not compared
	open(os.path.join(job.monitor, 'b.txt'), 'w').write('changed too')
	assert compare(job, manifest, rv.TouchedScopes([], ['a.txt'])) == {'a.txt': 'modify'}


def test_a_subtree_reports_rows_the_tree_lacks(job):
	_, manifest = backed_up(job, {'D/old.txt': 'o', 'D/keep.txt': 'k', 'E/old.txt': 'e'})
	os.remove(os.path.join(job.monitor, 'D/old.txt'))
	os.remove(os.path.join(job.monitor, 'E/old.txt'))
	assert compare(job, manifest, rv.TouchedScopes(['D/'], [])) == {'D/old.txt': 'delete'}


def test_trusted_rels_are_not_read_from_the_vault(job, monkeypatch):
	v0, manifest = backed_up(job, {'D/a.txt': 'a', 'p.txt': 'p'})
	seed_monitor(job, {'D/new.txt': 'n', 'p.txt': 'p again'})
	manifest.begin()
	# rows the replay copied, the two of them gone from the tree since
	for rel in ('D/new.txt', 'D/gone.txt', 'p.txt', 'q.txt'):
		manifest.add(rel, dirty=True)
	trusted = manifest.dirty_rels()
	assert trusted == {'D/new.txt', 'D/gone.txt', 'p.txt', 'q.txt'}
	read = rv.read_vault_record

	def guarded(version_path, rel, monitor_path):
		assert rel not in trusted, f'{rel} was read from the vault'
		return read(version_path, rel, monitor_path)
	monkeypatch.setattr(rv, 'read_vault_record', guarded)
	entries = OrderedDict()
	rv.compare_scopes(entries, manifest, v0, job.monitor, rv.TouchedScopes(['D/'], ['p.txt', 'q.txt']), trusted=trusted)
	assert events(job, entries) == {'D/gone.txt': 'delete', 'q.txt': 'delete'}
	# not recorded, so the copies stay for the next comparison to read back
	assert manifest.dirty_rels() == trusted
	manifest.rollback()


def test_it_leaves_the_transaction_open(job, monkeypatch):
	v0, manifest = backed_up(job, {'a.txt': 'a', 'D/x.txt': 'x'})
	open(os.path.join(job.monitor, 'a.txt'), 'w').write('changed')
	before = rows(manifest)
	manifest.begin()

	def refused(*args, **kwargs):
		raise AssertionError('compare_scopes() must leave the transaction to its caller')
	for name in ('begin', 'commit', 'rollback', 'rebuild', 'prefetch', 'reset'):
		monkeypatch.setattr(manifest, name, refused)
	entries = OrderedDict()
	assert rv.compare_scopes(entries, manifest, v0, job.monitor, rv.TouchedScopes([''], [])) == len(before)
	monkeypatch.undo()
	assert events(job, entries) == {'a.txt': 'modify'}
	assert manifest.conn.in_transaction
	assert manifest.describes(v0)
	# the unchecked copies were read back and recorded, in the transaction
	assert rows(manifest) != before
	manifest.rollback()
	assert rows(manifest) == before


def test_it_reads_the_version_it_is_given(job, capsys):
	v0, manifest = backed_up(job, {'D/x.txt': 'x', 'D/y.txt': 'y'})
	# the batch's new version, a referenced copy of V0 whose D the replay renamed, as the tree's was
	v1 = os.path.join(job.job_vault, f'V1--{T1}')
	os.makedirs(v1)
	manifest.begin()
	assert rv.do_referenced_copy(v0, v1, manifest, relative=True)
	os.rename(os.path.join(v1, 'D'), os.path.join(v1, 'D2'))
	manifest.move_tree('D/', 'D2/')
	os.rename(os.path.join(job.monitor, 'D'), os.path.join(job.monitor, 'D2'))
	assert manifest.lookup('D2/x.txt').kind is None
	capsys.readouterr()
	scopes = rv.TouchedScopes(['D2/'], [])
	# the committed version has no D2 to read
	entries = OrderedDict()
	rv.compare_scopes(entries, manifest, v0, job.monitor, scopes)
	assert 'Cannot read' in capsys.readouterr().out
	assert set(events(job, entries).values()) == {'create'}
	entries = OrderedDict()
	assert rv.compare_scopes(entries, manifest, v1, job.monitor, scopes) == 3
	assert 'Cannot read' not in capsys.readouterr().out
	assert events(job, entries) == {}
	assert manifest.lookup('D2/x.txt').kind == 'f'
	manifest.rollback()


def test_attributes_false_leaves_attrib_out(job):
	_, manifest = backed_up(job, {'a.txt': 'a', 'D/': None})
	os.chmod(os.path.join(job.monitor, 'a.txt'), 0o600)
	os.chmod(os.path.join(job.monitor, 'D'), 0o700)
	whole = rv.TouchedScopes([''], [])
	assert compare(job, manifest, whole, attributes=False) == {}
	assert compare(job, manifest, whole, attributes=True) == {'a.txt': 'attrib', 'D/': 'attrib'}


def test_a_folder_path_is_compared_alone(job):
	_, manifest = backed_up(job, {'D/x.txt': 'x', 'E/y.txt': 'y'})
	os.chmod(os.path.join(job.monitor, 'D'), 0o700)
	open(os.path.join(job.monitor, 'D/x.txt'), 'w').write('changed')
	os.remove(os.path.join(job.monitor, 'E/y.txt'))
	os.rmdir(os.path.join(job.monitor, 'E'))
	# in neither the tree nor the manifest
	scopes = rv.TouchedScopes([], ['D/', 'E/', 'missing.txt', 'missing/'])
	assert compare(job, manifest, scopes) == {'D/': 'attrib', 'E/': 'delete'}


def test_a_path_that_changed_kind_is_compared_as_what_it_now_is(job):
	_, manifest = backed_up(job, {'f': 'f', 'D/x.txt': 'x'})
	os.remove(os.path.join(job.monitor, 'f'))
	os.mkdir(os.path.join(job.monitor, 'f'))
	os.remove(os.path.join(job.monitor, 'D/x.txt'))
	os.rmdir(os.path.join(job.monitor, 'D'))
	open(os.path.join(job.monitor, 'D'), 'w').write('now a file')
	scopes = rv.TouchedScopes([], ['f', 'D/'])
	assert compare(job, manifest, scopes) == {'f/': 'create', 'f': 'delete', 'D': 'create', 'D/': 'delete'}


def test_nested_scopes_are_compared_once(job):
	_, manifest = backed_up(job, {'D/x.txt': 'x', 'D/E/y.txt': 'y', 'z.txt': 'z'})
	os.remove(os.path.join(job.monitor, 'D/E/y.txt'))
	cases = (
		# D/, D/x.txt, D/E/ and z.txt are still in the tree
		(rv.TouchedScopes([''], []), 4),
		(rv.TouchedScopes(['D/E/', 'D/', ''], ['D/x.txt', 'z.txt', 'D/E/']), 4),
		(rv.TouchedScopes(['D/E/', 'D/', 'D/'], ['D/x.txt', 'D/E/', 'D']), 3),
	)
	for scopes, count in cases:
		entries = OrderedDict()
		manifest.begin()
		assert rv.compare_scopes(entries, manifest, latest_version(job).path, job.monitor, scopes) == count
		manifest.rollback()
		assert events(job, entries) == {'D/E/y.txt': 'delete'}


def test_an_unreadable_root_raises(job):
	v0, manifest = backed_up(job, {'D/x.txt': 'x'})
	os.rename(job.monitor, job.monitor + '.away')
	for scopes in (rv.TouchedScopes([''], []), rv.TouchedScopes(['D/'], []), rv.TouchedScopes([], ['D/x.txt'])):
		manifest.begin()
		with pytest.raises(rv.JobFailure):
			rv.compare_scopes(OrderedDict(), manifest, v0, job.monitor, scopes)
		# what to do with the transaction is the caller's call
		assert manifest.conn.in_transaction
		manifest.rollback()


def test_delta_generation_is_unchanged(job):
	'''Delta generation, scoped or not, finds what compare_scopes() finds, and commits the manifest describing the version.'''
	v0, manifest = backed_up(job, {'a.txt': 'a', 'gone.txt': 'g', 'D/x.txt': 'x', 'D/old.txt': 'o', 'm': 'm'})
	seed_monitor(job, {'new.txt': 'n', 'D/new.txt': 'n'})
	open(os.path.join(job.monitor, 'a.txt'), 'w').write('changed')
	os.chmod(os.path.join(job.monitor, 'D/x.txt'), 0o600)
	os.remove(os.path.join(job.monitor, 'gone.txt'))
	os.remove(os.path.join(job.monitor, 'D/old.txt'))
	expected = {'a.txt': 'modify', 'gone.txt': 'delete', 'new.txt': 'create', 'D/new.txt': 'create', 'D/x.txt': 'attrib', 'D/old.txt': 'delete'}
	assert compare(job, manifest, rv.TouchedScopes([''], [])) == expected
	assert compare(job, manifest, rv.TouchedScopes(['D/'], [])) == {rel: event for rel, event in expected.items() if rel.startswith('D/')}
	scoped = OrderedDict()
	assert rv.delta_generate_backup_entries(scoped, latest_version(job), job.monitor, manifest=manifest, scope_rel='D/') is manifest
	assert events(job, scoped) == {rel: event for rel, event in expected.items() if rel.startswith('D/')}
	assert not manifest.conn.in_transaction
	whole = OrderedDict()
	rv.delta_generate_backup_entries(whole, latest_version(job), job.monitor, manifest=manifest)
	assert events(job, whole) == expected
	assert not manifest.conn.in_transaction and manifest.describes(v0)
	manifest.close()
