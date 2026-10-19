from collections import OrderedDict
import os
import pytest
import reverberator as rv
from tests.harness import seed_monitor, write_tree, write_pending, committed_versions

pytestmark = pytest.mark.unit


def test_skips_gitignore_semantics(tmp_path):
	sl = rv.SkipList(str(tmp_path), ['build/', '*.log', '!keep.log', '/top', '# comment', ''])
	assert sl.skips('build/') and sl.skips('a/build/')
	assert not sl.skips('build')
	assert sl.skips('x.log') and not sl.skips('keep.log')
	assert sl.skips('top') and not sl.skips('a/top')
	assert sl.patterns == ['build/', '*.log', '!keep.log', '/top']


def test_root_is_never_skipped(tmp_path):
	sl = rv.SkipList(str(tmp_path), ['*'])
	assert sl.skips('a.txt') and sl.skips('d/')
	assert not sl.skips('') and not sl.skips_path(str(tmp_path), True)


def test_skips_path_and_folder_rel(tmp_path):
	root = str(tmp_path)
	sl = rv.SkipList(root, ['cache/'])
	assert sl.skips_path(os.path.join(root, 'cache'), True)
	assert sl.skips_path(os.path.join(root, 'cache') + '/', True)
	assert not sl.skips_path(os.path.join(root, 'cache'), False)
	assert not sl.skips_path('/elsewhere/cache', True)
	assert sl.folder_rel(root) == '' and sl.folder_rel(root + '/') == ''
	assert sl.folder_rel(os.path.join(root, 'a', 'b') + '/') == 'a/b/'


def test_empty_and_comment_only_lists_have_no_patterns(tmp_path):
	for lines in ([], ['', '# only a comment', '/']):
		sl = rv.SkipList(str(tmp_path), lines)
		assert not sl and sl.fingerprint == '' and not sl.skips('a')


def test_fingerprint_ignores_comments_and_blank_lines(tmp_path):
	a = rv.SkipList(str(tmp_path), ['*.tmp', 'cache/'])
	b = rv.SkipList(str(tmp_path), ['# header', '*.tmp', '', 'cache/'])
	assert a.fingerprint == b.fingerprint != ''
	assert a.fingerprint != rv.SkipList(str(tmp_path), ['cache/', '*.tmp']).fingerprint
	assert a.fingerprint == rv.SkipList('/elsewhere', ['*.tmp', 'cache/']).fingerprint


def test_location_dependent(tmp_path):
	for pattern in ['*.tmp', 'node_modules/', '**/cache/', '!keep.tmp', 'build']:
		assert not rv.SkipList(str(tmp_path), [pattern]).location_dependent, pattern
	for pattern in ['/scratch/', 'projects/*/build/', 'a/b', '!/top', '**/x/y', 'a/**']:
		assert rv.SkipList(str(tmp_path), [pattern]).location_dependent, pattern


def test_load_reads_crlf_and_bom_like_lf(tmp_path):
	lf = tmp_path / 'lf'
	lf.write_bytes(b'*.tmp\ncache/\n')
	crlf = tmp_path / 'crlf'
	crlf.write_bytes(b'\xef\xbb\xbf*.tmp\r\ncache/\r\n')
	a = rv.SkipList.load(str(tmp_path), str(lf))
	b = rv.SkipList.load(str(tmp_path), str(crlf))
	assert a.fingerprint == b.fingerprint
	assert b.skips('x.tmp') and b.skips('cache/') and b.source == str(crlf)


def test_load_splits_only_on_newlines(tmp_path):
	# str.splitlines() also splits on form feeds, file separators and U+2028
	path = tmp_path / 'odd'
	path.write_bytes('a\x0cb.tmp\nc\u2028d/\n'.encode())
	assert rv.SkipList.load(str(tmp_path), str(path)).patterns == ['a\x0cb.tmp', 'c\u2028d/']


def test_load_refuses_unreadable_lists(tmp_path):
	with pytest.raises(OSError):
		rv.SkipList.load(str(tmp_path), str(tmp_path / 'missing'))
	with pytest.raises(OSError):
		rv.SkipList.load(str(tmp_path), str(tmp_path))
	(tmp_path / 'bin').write_bytes(b'\xff\xfe\x00bad')
	with pytest.raises(ValueError):
		rv.SkipList.load(str(tmp_path), str(tmp_path / 'bin'))
	(tmp_path / 'bad').write_text('!\n')
	with pytest.raises(ValueError):
		rv.SkipList.load(str(tmp_path), str(tmp_path / 'bad'))


def test_bad_bracket_range_is_a_value_error(tmp_path):
	with pytest.raises(ValueError):
		rv.SkipList(str(tmp_path), ['[z-a]'])
	(tmp_path / 'range').write_text('**/[b-a]x\n')
	with pytest.raises(ValueError):
		rv.SkipList.load(str(tmp_path), str(tmp_path / 'range'))


def test_names_starting_with_hash_or_bang(tmp_path):
	sl = rv.SkipList(str(tmp_path), ['#notes', '\\#draft', '\\!important', 'my file.txt'])
	assert not sl.skips('#notes')
	assert sl.skips('#draft') and sl.skips('!important') and sl.skips('my file.txt')


@pytest.mark.parametrize('recorded,current,explicit_none,expected', [
	(None, '', False, 'unchanged'),
	(None, 'f1', False, 'changed'),
	('f1', 'f1', False, 'unchanged'),
	('', '', False, 'unchanged'),
	('f1', 'f2', False, 'changed'),
	('', 'f1', False, 'changed'),
	('f1', '', False, 'refuse'),
	('f1', '', True, 'changed'),
])
def test_skip_list_change(recorded, current, explicit_none, expected):
	assert rv.skip_list_change(recorded, current, explicit_none) == expected


def _backup(job, entries=None, skip_list=None, keep_one_complete_backup=True, backup_size_limit='0'):
	return rv.do_backup(
		OrderedDict() if entries is None else entries, job_name=job.job_name, monitor_path=job.monitor,
		vault_path=job.vault, keep_one_complete_backup=keep_one_complete_backup, only_sync_attributes=True,
		keep_n_versions=0, backup_size_limit=backup_size_limit, skip_list=skip_list,
	)


def test_iter_tree_entries_prunes_skipped_folders(tmp_path):
	write_tree(str(tmp_path), {'keep/a.txt': 'a', 'cache/deep/b.txt': 'b', 'x.tmp': 't'})
	sl = rv.SkipList(str(tmp_path), ['cache/', '*.tmp'])
	asked = []
	rels = sorted(rel for _, rel, _ in rv.iter_tree_entries(str(tmp_path), skip=lambda rel: asked.append(rel) or sl.skips(rel)))
	assert rels == ['keep/', 'keep/a.txt']
	assert 'cache/deep/' not in asked


def test_complete_v0_leaves_out_skipped(job, poll_fast):
	seed_monitor(job, {'a.txt': 'a', 'cache/x.bin': 'x', 'b.tmp': 't'})
	_, manifest, committed = _backup(job, skip_list=rv.SkipList(job.monitor, ['cache/', '*.tmp']))
	assert committed and manifest.files == ['a.txt'] and manifest.folders == []
	manifest.close()
	v0 = committed_versions(job)[0]
	assert os.path.isfile(os.path.join(v0, 'a.txt'))
	assert not os.path.lexists(os.path.join(v0, 'cache')) and not os.path.lexists(os.path.join(v0, 'b.tmp'))


def test_referenced_v0_leaves_out_skipped(job, poll_fast):
	seed_monitor(job, {'a.txt': 'a', 'cache/x.bin': 'x'})
	_, manifest, committed = _backup(job, skip_list=rv.SkipList(job.monitor, ['cache/']), keep_one_complete_backup=False)
	assert committed and manifest.files == ['a.txt']
	manifest.close()
	assert not os.path.lexists(os.path.join(committed_versions(job)[0], 'cache'))


def test_skip_everything_still_commits_v0(job, poll_fast):
	seed_monitor(job, {'a.txt': 'a', 'd/b.txt': 'b'})
	_, manifest, committed = _backup(job, skip_list=rv.SkipList(job.monitor, ['*']))
	assert committed and manifest.counts() == (0, 0)
	manifest.close()
	assert os.listdir(committed_versions(job)[0]) == []


def test_newly_skipped_dropped_from_new_version_kept_in_old(job, poll_fast):
	seed_monitor(job, {'a.txt': 'a', 'cache/x.bin': 'x'})
	_backup(job)[1].close()
	_backup(job, skip_list=rv.SkipList(job.monitor, ['cache/']))[1].close()
	v0, v1 = committed_versions(job)
	assert os.path.isfile(os.path.join(v0, 'cache', 'x.bin'))
	assert not os.path.lexists(os.path.join(v1, 'cache')) and os.path.lexists(os.path.join(v1, 'a.txt'))


def test_newly_unskipped_copied_into_new_version(job, poll_fast):
	seed_monitor(job, {'a.txt': 'a', 'cache/x.bin': 'x'})
	_backup(job, skip_list=rv.SkipList(job.monitor, ['cache/']))[1].close()
	_backup(job, skip_list=rv.SkipList(job.monitor, []))[1].close()
	v0, v1 = committed_versions(job)
	assert not os.path.lexists(os.path.join(v0, 'cache'))
	assert open(os.path.join(v1, 'cache', 'x.bin')).read() == 'x'


def test_new_folder_copy_leaves_out_skipped(job, poll_fast):
	seed_monitor(job, {'a.txt': 'a'})
	_backup(job)[1].close()
	write_tree(job.monitor, {'newdir/keep.txt': 'k', 'newdir/x.tmp': 't', 'newdir/cache/y': 'y'})
	entries = OrderedDict({os.path.join(job.monitor, 'newdir') + '/': rv.BackupEntryValues('t', 'create', None)})
	_, manifest, _ = _backup(job, entries, skip_list=rv.SkipList(job.monitor, ['*.tmp', 'cache/']))
	assert manifest.lookup('newdir/x.tmp') is None and manifest.lookup('newdir/cache/') is None
	manifest.close()
	v1 = committed_versions(job)[1]
	assert os.path.isfile(os.path.join(v1, 'newdir', 'keep.txt'))
	assert not os.path.lexists(os.path.join(v1, 'newdir', 'x.tmp'))
	assert not os.path.lexists(os.path.join(v1, 'newdir', 'cache'))


def _age_tree(job, skipped_file):
	for path in (job.monitor, os.path.join(job.monitor, 'a.txt'), os.path.join(job.monitor, 'cache')):
		os.utime(path, (1000, 1000))
	os.utime(skipped_file, (5000, 5000))


def test_resume_check_ignores_changes_in_skipped_paths(job):
	seed_monitor(job, {'a.txt': 'a', 'cache/x.bin': 'x'})
	_age_tree(job, os.path.join(job.monitor, 'cache', 'x.bin'))
	assert rv.get_monitor_path_most_recent_change_time(job.monitor) == 5000
	assert rv.get_monitor_path_most_recent_change_time(job.monitor, rv.SkipList(job.monitor, ['cache/'])) == 1000


def test_pending_resumes_when_only_skipped_paths_changed(job):
	seed_monitor(job, {'a.txt': 'a', 'cache/x.bin': 'x'})
	a = os.path.join(job.monitor, 'a.txt')
	pending = write_pending(job, [rv.ChangeEvent(1.0, False, 'modify', a, None)])
	_age_tree(job, os.path.join(job.monitor, 'cache', 'x.bin'))
	os.utime(pending, (2000, 2000))
	queue = rv.ChangeEventQueue(job.monitor)
	assert rv.load_pending_transactions_for_resume(job.job_name, job.monitor, job.vault, queue, rv.SkipList(job.monitor, ['cache/'])) is True
	assert [event.path for event in queue] == [a]


def test_manifest_skip_fingerprint_round_trip(job):
	os.makedirs(job.job_vault)
	manifest = rv.VaultManifest(job.job_vault)
	assert manifest.skip_fingerprint is None
	manifest.begin()
	manifest.set_skip_fingerprint('abc')
	manifest.rollback()
	assert manifest.skip_fingerprint is None
	manifest.begin()
	manifest.set_skip_fingerprint('abc')
	manifest.commit()
	manifest.close()
	reopened = rv.VaultManifest(job.job_vault)
	assert reopened.skip_fingerprint == 'abc'
	reopened.close()


def test_committed_version_records_fingerprint(job, poll_fast):
	seed_monitor(job, {'a.txt': 'a'})
	sl = rv.SkipList(job.monitor, ['*.tmp'])
	_, manifest, _ = _backup(job, skip_list=sl)
	assert manifest.skip_fingerprint == sl.fingerprint
	manifest.close()
	_, manifest, _ = _backup(job, {os.path.join(job.monitor, 'a.txt'): rv.BackupEntryValues('t', 'modify', None)})
	assert manifest.skip_fingerprint == ''
	manifest.close()


def test_delta_with_no_differences_records_new_fingerprint(job, poll_fast):
	seed_monitor(job, {'a.txt': 'a'})
	_backup(job)[1].close()
	sl = rv.SkipList(job.monitor, ['*.tmp'])
	_, manifest, committed = _backup(job, skip_list=sl)
	assert committed and len(committed_versions(job)) == 1
	assert manifest.skip_fingerprint == sl.fingerprint
	manifest.close()


def test_interrupted_delta_keeps_old_fingerprint(job, poll_fast, monkeypatch):
	seed_monitor(job, {'a.txt': 'a'})
	_backup(job)[1].close()
	original = rv.delta_generate_backup_entries
	def interrupted(*args, **kwargs):
		result = original(*args, **kwargs)
		rv.GREEN_LIGHT.clear()
		return result
	monkeypatch.setattr(rv, 'delta_generate_backup_entries', interrupted)
	_, manifest, committed = _backup(job, skip_list=rv.SkipList(job.monitor, ['*.tmp']))
	rv.GREEN_LIGHT.set()
	assert committed is False and manifest.skip_fingerprint == ''
	manifest.close()


def _move_entry(job, src_rel, dst_rel):
	src = os.path.join(job.monitor, src_rel)
	dst = os.path.join(job.monitor, dst_rel)
	os.makedirs(os.path.dirname(dst), exist_ok=True)
	os.rename(src, dst)
	return OrderedDict({dst + '/': rv.BackupEntryValues('t', 'move', src + '/')})


def test_folder_moved_out_of_location_pattern_copies_unskipped(job, poll_fast):
	sl = rv.SkipList(job.monitor, ['projects/*/build/'])
	seed_monitor(job, {'projects/foo/src.c': 's', 'projects/foo/build/a.o': 'o', 'archive/': None})
	_backup(job, skip_list=sl)[1].close()
	_, manifest, committed = _backup(job, _move_entry(job, 'projects/foo', 'archive/foo'), skip_list=sl)
	assert committed and manifest.lookup('archive/foo/build/a.o') is not None
	manifest.close()
	v0, v1 = committed_versions(job)
	assert not os.path.lexists(os.path.join(v0, 'projects', 'foo', 'build'))
	assert open(os.path.join(v1, 'archive', 'foo', 'build', 'a.o')).read() == 'o'
	assert os.path.lexists(os.path.join(v1, 'archive', 'foo', 'src.c'))


def test_folder_moved_into_location_pattern_drops_newly_skipped(job, poll_fast):
	sl = rv.SkipList(job.monitor, ['projects/*/build/'])
	seed_monitor(job, {'archive/foo/src.c': 's', 'archive/foo/build/a.o': 'o', 'projects/': None})
	_backup(job, skip_list=sl)[1].close()
	_, manifest, committed = _backup(job, _move_entry(job, 'archive/foo', 'projects/foo'), skip_list=sl)
	assert committed
	assert manifest.lookup('projects/foo/build/') is None and manifest.lookup('projects/foo/build/a.o') is None
	manifest.close()
	v0, v1 = committed_versions(job)
	assert os.path.isfile(os.path.join(v0, 'archive', 'foo', 'build', 'a.o'))
	assert not os.path.lexists(os.path.join(v1, 'projects', 'foo', 'build'))
	assert os.path.lexists(os.path.join(v1, 'projects', 'foo', 'src.c'))


def test_folder_moved_into_location_pattern_collapses_nested_skipped(job, poll_fast, monkeypatch):
	sl = rv.SkipList(job.monitor, ['projects/**/build/'])
	seed_monitor(job, {'archive/foo/src.c': 's', 'archive/foo/build/sub/build/deep.o': 'o', 'projects/': None})
	_backup(job, skip_list=sl)[1].close()
	removed = []
	original = rv.VaultManifest.remove_tree
	monkeypatch.setattr(rv.VaultManifest, 'remove_tree', lambda self, folder: removed.append(folder) or original(self, folder))
	_, manifest, committed = _backup(job, _move_entry(job, 'archive/foo', 'projects/foo'), skip_list=sl)
	assert committed
	# the nested build/ folder goes with its skipped parent, not on its own
	assert [folder for folder in removed if folder.startswith('projects/foo/build/')] == ['projects/foo/build/']
	assert list(manifest.iter_under('projects/foo/')) == ['projects/foo/src.c']
	manifest.close()
	v1 = committed_versions(job)[1]
	assert not os.path.lexists(os.path.join(v1, 'projects', 'foo', 'build'))


def test_file_moved_into_location_pattern_is_dropped(job, poll_fast):
	sl = rv.SkipList(job.monitor, ['projects/*/*.o'])
	seed_monitor(job, {'archive/foo/src.c': 's', 'archive/foo/a.o': 'o', 'projects/': None})
	_backup(job, skip_list=sl)[1].close()
	_, manifest, committed = _backup(job, _move_entry(job, 'archive/foo', 'projects/foo'), skip_list=sl)
	assert committed and manifest.lookup('projects/foo/a.o') is None and manifest.lookup('projects/foo/src.c') is not None
	manifest.close()
	v0, v1 = committed_versions(job)
	assert os.path.isfile(os.path.join(v0, 'archive', 'foo', 'a.o'))
	assert not os.path.lexists(os.path.join(v1, 'projects', 'foo', 'a.o'))
	assert os.path.lexists(os.path.join(v1, 'projects', 'foo', 'src.c'))


def test_unskipped_entries_below_a_tracked_folder_are_copied(job, poll_fast):
	sl = rv.SkipList(job.monitor, ['projects/**/build/', 'projects/**/*.o'])
	seed_monitor(job, {'projects/foo/lib/z.c': 'z', 'projects/foo/lib/x.o': 'x', 'projects/foo/lib/build/b.o': 'b',
		'projects/foo/lib/build/sub/c.o': 'c', 'projects/foo/lib/y.c': 'y', 'archive/': None})
	_backup(job, skip_list=sl)[1].close()
	_, manifest, committed = _backup(job, _move_entry(job, 'projects/foo', 'archive/foo'), skip_list=sl)
	assert committed
	assert list(manifest.iter_under('archive/foo/')) == ['archive/foo/lib/', 'archive/foo/lib/build/', 'archive/foo/lib/build/b.o',
		'archive/foo/lib/build/sub/', 'archive/foo/lib/build/sub/c.o', 'archive/foo/lib/x.o', 'archive/foo/lib/y.c', 'archive/foo/lib/z.c']
	manifest.close()
	lib = os.path.join(committed_versions(job)[1], 'archive', 'foo', 'lib')
	assert open(os.path.join(lib, 'x.o')).read() == 'x'
	assert open(os.path.join(lib, 'build', 'b.o')).read() == 'b'
	assert open(os.path.join(lib, 'build', 'sub', 'c.o')).read() == 'c'
	assert os.path.lexists(os.path.join(lib, 'y.c')) and os.path.lexists(os.path.join(lib, 'z.c'))


def test_failed_vault_rename_still_drops_newly_skipped(job, poll_fast, monkeypatch):
	sl = rv.SkipList(job.monitor, ['projects/*/build/'])
	seed_monitor(job, {'archive/foo/src.c': 's', 'archive/foo/build/a.o': 'o', 'projects/': None})
	_backup(job, skip_list=sl)[1].close()
	original = os.rename
	def rename(src, dst, *args, **kwargs):
		if str(src).startswith(job.job_vault) and os.path.basename(str(src).rstrip('/')) == 'foo':
			raise OSError(18, 'Invalid cross-device link')
		return original(src, dst, *args, **kwargs)
	entries = _move_entry(job, 'archive/foo', 'projects/foo')
	monkeypatch.setattr(os, 'rename', rename)
	# the vault rename fails, so the folder is copied from the source and the old one deleted
	_, manifest, committed = _backup(job, entries, skip_list=sl)
	monkeypatch.setattr(os, 'rename', original)
	assert committed
	assert manifest.lookup('projects/foo/build/') is None and manifest.lookup('projects/foo/build/a.o') is None
	assert manifest.lookup('projects/foo/src.c') is not None and manifest.lookup('archive/foo/') is None
	manifest.close()
	v1 = committed_versions(job)[1]
	assert not os.path.lexists(os.path.join(v1, 'projects', 'foo', 'build'))
	assert os.path.lexists(os.path.join(v1, 'projects', 'foo', 'src.c')) and not os.path.lexists(os.path.join(v1, 'archive', 'foo'))


def test_location_free_patterns_skip_the_recheck(job, poll_fast, monkeypatch):
	sl = rv.SkipList(job.monitor, ['*.tmp'])
	seed_monitor(job, {'a/x.txt': 'x', 'b/': None})
	_backup(job, skip_list=sl)[1].close()
	walked = []
	original = rv.iter_tree_entries
	monkeypatch.setattr(rv, 'iter_tree_entries', lambda path, *args, **kwargs: walked.append(path) or original(path, *args, **kwargs))
	_backup(job, _move_entry(job, 'a', 'b/a'), skip_list=sl)[1].close()
	assert not any(path.rstrip('/') == os.path.join(job.monitor, 'b', 'a') for path in walked)


def _write_random(path, size):
	os.makedirs(os.path.dirname(path), exist_ok=True)
	with open(path, 'wb') as f:
		# random bytes so a compressing filesystem still allocates every block
		f.write(os.urandom(size))


def _project_with_skipped_cache(job, cache_files=3, cache_file_size=1 << 20):
	proj = os.path.join(job.monitor, 'proj')
	write_tree(proj, {'src.c': 's'})
	for i in range(cache_files):
		_write_random(os.path.join(proj, 'node_modules', f'big{i}.bin'), cache_file_size)
	return proj


def test_size_estimate_walks_around_skipped_content(job):
	proj = _project_with_skipped_cache(job)
	entries = OrderedDict({proj + '/': rv.BackupEntryValues('t', 'create', None)})
	full_size, full_inodes = rv.get_backup_size_inode(entries, True, job.job_vault, job.monitor)
	assert full_size >= 3 << 20 and full_inodes == 6
	size, inodes = rv.get_backup_size_inode(entries, True, job.job_vault, job.monitor, rv.SkipList(job.monitor, ['node_modules/']))
	# proj/ and proj/src.c only
	assert inodes == 2
	assert 0 < size < 1 << 20
	assert size == sum(os.lstat(path).st_blocks * 512 for path in (proj, os.path.join(proj, 'src.c')))
	# a folder modify or attrib is sized by the same walk
	for event in ('modify', 'attrib'):
		entries = OrderedDict({proj + '/': rv.BackupEntryValues('t', event, None)})
		assert rv.get_backup_size_inode(entries, False, job.job_vault, job.monitor, rv.SkipList(job.monitor, ['node_modules/'])) == (size, 0)
	# no patterns keeps du
	assert rv.get_backup_size_inode(entries, False, job.job_vault, job.monitor, rv.SkipList(job.monitor, [])) == (full_size, 0)


def test_skipped_content_does_not_prune_history(job, poll_fast):
	sl = rv.SkipList(job.monitor, ['node_modules/'])
	seed_monitor(job, {'a.txt': 'a'})
	_backup(job, skip_list=sl, backup_size_limit='1M')[1].close()
	for i in range(3):
		path = os.path.join(job.monitor, f'f{i}.txt')
		open(path, 'w').write('x' * 100)
		_backup(job, OrderedDict({path: rv.BackupEntryValues('t', 'create', None)}), skip_list=sl, backup_size_limit='1M')[1].close()
	assert len(committed_versions(job)) == 4
	# a folder arrives already holding a skipped cache three times the size limit
	proj = _project_with_skipped_cache(job)
	entries = OrderedDict({proj + '/': rv.BackupEntryValues('t', 'create', None)})
	_, manifest, committed = _backup(job, entries, skip_list=sl, backup_size_limit='1M')
	manifest.close()
	versions = committed_versions(job)
	assert committed and len(versions) == 5
	assert os.path.isfile(os.path.join(versions[-1], 'proj', 'src.c'))
	assert not os.path.lexists(os.path.join(versions[-1], 'proj', 'node_modules'))


def _usage(paths):
	'''Bytes and inodes of paths as the replay copies them: each name on its own.'''
	return sum(os.lstat(path).st_blocks * 512 for path in paths), len(paths)


def _nested_tree(root, depth=6):
	leaf = os.path.join(root, *[f'd{i}' for i in range(depth)])
	_write_random(os.path.join(leaf, 'big.bin'), 1 << 20)
	write_tree(root, {'top.txt': 't', 'd0/mid.txt': 'm'})
	_write_random(os.path.join(root, 'd0', 'node_modules', 'cache.bin'), 1 << 20)
	return leaf


def _tree_entries(root, sl, event):
	# what delta generation queues for a tree it has not seen: an entry for the folder and each one below it
	entries = OrderedDict({root + '/': rv.BackupEntryValues('t', event, None)})
	for entry_path, _, _ in rv.iter_tree_entries(root, sl.folder_rel(root), skip=sl.skips):
		entries[entry_path] = rv.BackupEntryValues('t', event, None)
	return entries


def test_size_estimate_counts_nested_creates_once(job):
	proj = os.path.join(job.monitor, 'proj')
	_nested_tree(proj)
	sl = rv.SkipList(job.monitor, ['node_modules/'])
	entries = _tree_entries(proj, sl, 'create')
	assert len(entries) == 10
	expected = _usage([proj] + [path for path, _, _ in rv.iter_tree_entries(proj, 'proj/', skip=sl.skips)])
	assert expected[0] >= 1 << 20 and expected[1] == 10
	assert rv.get_backup_size_inode(entries, True, job.job_vault, job.monitor, sl) == expected
	single = OrderedDict({proj + '/': rv.BackupEntryValues('t', 'create', None)})
	assert rv.get_backup_size_inode(single, True, job.job_vault, job.monitor, sl) == expected


def test_size_estimate_counts_nested_folder_attribs_once(job):
	proj = os.path.join(job.monitor, 'proj')
	_nested_tree(proj)
	sl = rv.SkipList(job.monitor, ['node_modules/'])
	# chmod -R: an attrib for every folder and file, sized when attributes are not only synced
	entries = _tree_entries(proj, sl, 'attrib')
	expected_size = _usage([proj] + [path for path, _, _ in rv.iter_tree_entries(proj, 'proj/', skip=sl.skips)])[0]
	assert rv.get_backup_size_inode(entries, False, job.job_vault, job.monitor, sl) == (expected_size, 0)
	# without patterns du gets the same size: it counts nested arguments once
	no_cache = OrderedDict((path, values) for path, values in entries.items() if 'node_modules' not in path)
	import shutil
	shutil.rmtree(os.path.join(proj, 'd0', 'node_modules'))
	assert rv.get_backup_size_inode(no_cache, False, job.job_vault, job.monitor) == (expected_size, 0)


def test_size_estimate_counts_creates_inside_a_sized_folder(job):
	proj = os.path.join(job.monitor, 'proj')
	write_tree(proj, {'old.txt': 'o', 'new/f.txt': 'f'})
	sl = rv.SkipList(job.monitor, ['*.tmp'])
	entries = OrderedDict([
		(proj + '/', rv.BackupEntryValues('t', 'attrib', None)),
		(os.path.join(proj, 'new') + '/', rv.BackupEntryValues('t', 'create', None)),
		(os.path.join(proj, 'new', 'f.txt'), rv.BackupEntryValues('t', 'create', None)),
	])
	# the folder walk holds the bytes of what is new below it, but the new folder and its file are still new inodes
	size = _usage([proj, os.path.join(proj, 'old.txt'), os.path.join(proj, 'new'), os.path.join(proj, 'new', 'f.txt')])[0]
	assert rv.get_backup_size_inode(entries, False, job.job_vault, job.monitor, sl) == (size, 2)


def test_size_estimate_counts_each_hard_link_name(job):
	# the replay copies each name with its own cp, so a file with four names takes four copies in the new version
	new = os.path.join(job.monitor, 'new')
	_write_random(os.path.join(new, 'n0.bin'), 1 << 20)
	for i in range(1, 4):
		os.link(os.path.join(new, 'n0.bin'), os.path.join(new, f'n{i}.bin'))
	sl = rv.SkipList(job.monitor, ['*.tmp'])
	expected = _usage([new] + [os.path.join(new, f'n{i}.bin') for i in range(4)])
	assert expected[0] >= 4 << 20 and expected[1] == 5
	entries = _tree_entries(new, sl, 'create')
	assert len(entries) == 5
	assert rv.get_backup_size_inode(entries, True, job.job_vault, job.monitor, sl) == expected
	single = OrderedDict({new + '/': rv.BackupEntryValues('t', 'create', None)})
	assert rv.get_backup_size_inode(single, True, job.job_vault, job.monitor, sl) == expected


@pytest.mark.parametrize('patterns', [None, ['*.tmp']])
def test_full_comparison_of_a_nested_tree_keeps_history(job, poll_fast, patterns):
	sl = None if patterns is None else rv.SkipList(job.monitor, patterns)
	seed_monitor(job, {'a.txt': 'a'})
	_backup(job, skip_list=sl, backup_size_limit='3M')[1].close()
	for i in range(3):
		path = os.path.join(job.monitor, f'f{i}.txt')
		open(path, 'w').write('x' * 100)
		_backup(job, OrderedDict({path: rv.BackupEntryValues('t', 'create', None)}), skip_list=sl, backup_size_limit='3M')[1].close()
	# a full comparison finds a new tree six folders deep holding 1 MiB, and queues a create for each entry in it
	leaf = os.path.join(job.monitor, 'new', *[f'd{i}' for i in range(6)])
	_write_random(os.path.join(leaf, 'big.bin'), 1 << 20)
	_, manifest, committed = _backup(job, skip_list=sl, backup_size_limit='3M')
	manifest.close()
	versions = committed_versions(job)
	assert committed and len(versions) == 5
	assert os.path.isfile(os.path.join(versions[-1], 'new', *[f'd{i}' for i in range(6)], 'big.bin'))


def test_fingerprint_is_the_utf8_hash_of_the_patterns(tmp_path):
	import xxhash
	sl = rv.SkipList(str(tmp_path), ['*.tmp', 'ünïcode/'])
	assert sl.fingerprint == xxhash.xxh64('*.tmp\nünïcode/'.encode('utf-8')).hexdigest()
