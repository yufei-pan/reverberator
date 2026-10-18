import os
import pytest
import reverberator as rv

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
