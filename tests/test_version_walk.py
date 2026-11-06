'''
Round 20: the one walk through a version (spec section 4.1, plan S8). Each path part is looked at with lstat and nothing is
left to the kernel: a forward link of exactly the right text walks the same path again from the next version's root, and any
other link is a user's. The vaults here are hand-written (tests/vaults.py): no batch makes them. tests/test_history_recheck.py
reads under a running batch.
'''
import errno
import fcntl
import io
import os
import sqlite3
import threading
import time

import pytest

import reverberator as rv
from tests.crash_batches import build_base
from tests.harness import create_job
from tests.vault_oracle import forward_text, landing, version_number
from tests.vaults import FORWARD, Link, forward_chain, record_layout, version_name, write_version


@pytest.fixture
def vault(tmp_path):
	path = str(tmp_path / 'job')
	os.mkdir(path)
	return path


def at(vault, number, rel=''):
	return os.path.join(vault, version_name(number), rel) if rel else os.path.join(vault, version_name(number))


def test_each_component_is_lstated_and_nothing_followed_by_the_kernel(vault, monkeypatch):
	write_version(vault, 1, {'a/': None, 'a/b': FORWARD})
	write_version(vault, 2, {'a': FORWARD})
	write_version(vault, 3, {'a/b/c': 'held'})
	seen = []
	real_lstat = os.lstat
	def lstat(path, *args, **kwargs):
		seen.append(path)
		return real_lstat(path, *args, **kwargs)
	def never(path, *args, **kwargs):
		raise AssertionError(f'the kernel was asked to follow {path}')
	with monkeypatch.context() as patched:
		patched.setattr(os, 'lstat', lstat)
		patched.setattr(os, 'stat', never)
		patched.setattr(os.path, 'realpath', never)
		walked = rv.walk_version(vault, 1, 'a/b/c', False)
	assert seen == [at(vault, 1), at(vault, 1, 'a'), at(vault, 1, 'a/b'), at(vault, 2), at(vault, 2, 'a'),
		at(vault, 3), at(vault, 3, 'a'), at(vault, 3, 'a/b'), at(vault, 3, 'a/b/c')]
	# nothing above an entry looked at was a link: the kernel had none to follow
	for path in seen:
		assert not os.path.islink(os.path.dirname(path))
	assert (walked.kind, walked.path) == ('file', at(vault, 3, 'a/b/c'))
	assert walked.st.st_ino == os.lstat(at(vault, 3, 'a/b/c')).st_ino


@pytest.mark.parametrize('hops', [1, 2, 5, 41, 60])
def test_a_forward_link_lands_in_the_version_after(vault, hops):
	forward_chain(vault, 1, 1 + hops, {'d/e/f': 'held'})
	walked = rv.walk_version(vault, 1, 'd/e/f', False)
	assert (walked.kind, walked.path) == ('file', at(vault, 1 + hops, 'd/e/f'))
	assert walked.followed == [(at(vault, number, 'd'), forward_text('d', version_name(number + 1))) for number in range(1, 1 + hops)]
	folder = rv.walk_version(vault, 1, 'd/e', False)
	assert (folder.kind, folder.path) == ('folder', at(vault, 1 + hops, 'd/e'))


def test_a_forward_link_is_judged_at_every_depth(vault):
	write_version(vault, 1, {'a/b/c/': None, 'a/b/c/f': FORWARD})
	write_version(vault, 2, {'a/b/': None, 'a/b/c': FORWARD})
	write_version(vault, 3, {'a': FORWARD})
	write_version(vault, 4, {'a/b/c/f': 'held'})
	assert rv.walk_version(vault, 1, 'a/b/c/f', False).path == at(vault, 4, 'a/b/c/f')
	assert [path for path, _ in rv.walk_version(vault, 1, 'a/b/c/f', False).followed] == [at(vault, 1, 'a/b/c/f'), at(vault, 2, 'a/b/c'), at(vault, 3, 'a')]


def test_the_tree_of_a_cut_batch_is_walked_with_no_change_list(vault):
	# the next version comes from the link's text alone: a folder with no list is walked as any other
	write_version(vault, 1, {'a': FORWARD})
	write_version(vault, 2, {'a': 'in the tree'})
	assert not [name for name in os.listdir(vault) if name.endswith(rv.CONTENT_FILE_EXTENSION_NAME)]
	assert rv.walk_version(vault, 1, 'a', False).path == at(vault, 2, 'a')


def test_a_special_file_and_the_root_read_as_ever(vault):
	top = write_version(vault, 1, {'a/': None})
	os.mkfifo(os.path.join(top, 'pipe'))
	assert rv.walk_version(vault, 1, 'pipe', False).kind == 'file'
	root = rv.walk_version(vault, 1, '', False)
	assert (root.kind, root.path, root.followed) == ('folder', top, [])


@pytest.mark.parametrize('text', [
	'../V2--2030-01-01_00-00-00_+0000/other',
	'a',
	'../../V2--2030-01-01_00-00-00_+0000/l',
	'../V2--2030-01-01_00-00-00_+0000/./l',
	'../V2--2030-01-01_00-00-00_+0000/l/',
	'../V2--2030-01-01_00-00-00_+0000//l',
	'./../V2--2030-01-01_00-00-00_+0000/l',
	'../V2--notatime/l',
	'../V02--2030-01-01_00-00-00_+0000/l',
])
def test_a_users_link_is_never_followed(vault, text):
	write_version(vault, 1, {'l': Link(text)})
	write_version(vault, 2, {'l': 'held', 'other': 'held', 'a': 'held'})
	walked = rv.walk_version(vault, 1, 'l', False)
	assert (walked.kind, walked.path, walked.followed) == ('symlink', at(vault, 1, 'l'), [])
	assert walked.detail == text


def test_a_users_link_naming_a_later_versions_real_path_is_a_users_link(vault):
	# the absolute form of the very entry, and a relative one into a version further on
	write_version(vault, 1, {'abs': Link(at(vault, 2, 'abs')), 'far': Link(forward_text('far', version_name(3)))})
	write_version(vault, 2, {'abs': 'held', 'far': FORWARD})
	write_version(vault, 3, {'far': 'held'})
	assert rv.walk_version(vault, 1, 'abs', False)[:2] == ('symlink', at(vault, 1, 'abs'))
	assert rv.walk_version(vault, 1, 'far', False)[:2] == ('symlink', at(vault, 1, 'far'))


@pytest.mark.parametrize('number', [0, 1, 2, 4, 12])
def test_a_forward_text_for_another_number_is_a_users_link(vault, number):
	write_version(vault, 1, {'held': 'x'})
	write_version(vault, 3, {'held': 'x'})
	write_version(vault, 4, {'held': 'x'})
	write_version(vault, 2, {'l': Link(forward_text('l', version_name(number)))})
	walked = rv.walk_version(vault, 2, 'l', False)
	assert (walked.kind, walked.path, walked.followed) == ('symlink', at(vault, 2, 'l'), [])


def test_a_link_above_the_last_component_is_a_missing_path(vault):
	write_version(vault, 1, {'real/': None, 'real/x': 'x', 'rel': Link('real'), 'out': Link('/usr'), 'up': Link('../V2--2030-01-01_00-00-00_+0000/real'), 'f': 'file'})
	write_version(vault, 2, {'real/x': 'x'})
	for rel, part in (('rel/x', 'rel'), ('out/bin', 'out'), ('up/x', 'up')):
		walked = rv.walk_version(vault, 1, rel, False)
		assert walked.kind == 'missing', rel
		assert walked.path == at(vault, 1, rel)
		assert f'{part} is a symlink' in walked.detail
	assert rv.walk_version(vault, 1, 'f/x', False).kind == 'missing'
	# a forward link to a file above the last component too
	write_version(vault, 3, {'g': FORWARD})
	write_version(vault, 4, {'g': 'a file'})
	assert rv.walk_version(vault, 3, 'g/x', False).kind == 'missing'


def test_a_version_removed_by_hand_reads_as_missing_not_an_error(vault):
	forward_chain(vault, 1, 3, {'a/x': 'held'})
	os.rename(at(vault, 2), at(vault, 2) + '.gone')
	walked = rv.walk_version(vault, 1, 'a/x', False)
	assert walked.kind == 'missing' and walked.followed == [(at(vault, 1, 'a'), forward_text('a', version_name(2)))]
	assert rv.resolve_version_entry(vault, at(vault, 1), 'a/x', '/monitored').kind == 'missing'
	# the version asked for itself
	assert rv.walk_version(vault, 2, 'a/x', False).kind == 'missing'
	assert rv.walk_version(vault, 9, 'a/x', False).kind == 'missing'
	assert rv.walk_version(os.path.join(vault, 'no vault'), 1, 'a/x', False).kind == 'missing'


def test_an_entry_gone_from_the_tree_reads_as_missing(vault):
	forward_chain(vault, 1, 3, {'a/x': 'held'})
	os.remove(at(vault, 3, 'a/x'))
	assert rv.walk_version(vault, 1, 'a/x', False).kind == 'missing'


def test_a_folder_that_cannot_be_looked_at_is_unreadable(vault, monkeypatch):
	forward_chain(vault, 1, 3, {'a/x': 'held'})
	real_lstat = os.lstat
	def lstat(path, *args, **kwargs):
		if path == at(vault, 2, 'a'):
			raise OSError(errno.EIO, 'Input/output error')
		return real_lstat(path, *args, **kwargs)
	monkeypatch.setattr(os, 'lstat', lstat)
	walked = rv.walk_version(vault, 1, 'a/x', False)
	assert walked.kind == 'unreadable' and 'Input/output error' in walked.detail


def test_a_link_turned_real_as_it_is_read_is_walked_again(vault, monkeypatch):
	# a record: lstat saw the forward link, and readlink finds the folder it became
	forward_chain(vault, 1, 2, {'a/x': 'held'})
	real_readlink = os.readlink
	def readlink(path, *args, **kwargs):
		if path == at(vault, 1, 'a') and os.path.islink(path):
			os.remove(path)
			os.mkdir(path)
			with open(os.path.join(path, 'x'), 'w') as f:
				f.write('recorded')
		return real_readlink(path, *args, **kwargs)
	monkeypatch.setattr(os, 'readlink', readlink)
	walked = rv.walk_version(vault, 1, 'a/x', False)
	assert (walked.kind, walked.path, walked.followed) == ('file', at(vault, 1, 'a/x'), [])


def chain_vault(vault):
	'''A vault of 0.54: V1 holds the copies, V2 and V3 link back to them; a moved file's link names its old path.'''
	write_version(vault, 1, {'a/x': 'held', 'a/old': 'moved', 'folder/inside': 'in'})
	write_version(vault, 2, {'a/': None, 'a/x': Link(f'../../{version_name(1)}/a/x'), 'a/new': Link(f'../../{version_name(1)}/a/old')})
	write_version(vault, 3, {'a/': None, 'a/x': Link(f'../../{version_name(2)}/a/x'), 'b/': None, 'b/deep': Link(f'../{version_name(2)}/a/new')})


def test_an_unmigrated_vault_is_read_backward_by_text(vault):
	chain_vault(vault)
	walked = rv.walk_version(vault, 3, 'a/x', True)
	assert (walked.kind, walked.path) == ('file', at(vault, 1, 'a/x'))
	assert walked.followed == [(at(vault, 3, 'a/x'), f'../../{version_name(2)}/a/x'), (at(vault, 2, 'a/x'), f'../../{version_name(1)}/a/x')]
	# by the text, whatever path it names and however many ../ it starts with
	assert rv.walk_version(vault, 3, 'b/deep', True).path == at(vault, 1, 'a/old')
	assert rv.resolve_version_entry(vault, at(vault, 3), 'a/x', '/monitored')[:2] == ('file', at(vault, 1, 'a/x'))
	# on design R the same text is a user's link
	record_layout(vault, 'r')
	assert rv.walk_version(vault, 3, 'a/x', False)[:2] == ('symlink', at(vault, 3, 'a/x'))
	assert rv.resolve_version_entry(vault, at(vault, 3), 'a/x', '/monitored')[:2] == ('symlink', at(vault, 3, 'a/x'))


def test_a_chain_form_link_to_a_folder_or_through_a_link_is_a_users_link(vault):
	# the daemon links files only, and its copies sit under real folders
	write_version(vault, 1, {'folder/inside': 'in', 'real/x': 'x', 'via': Link('real')})
	write_version(vault, 2, {'l': Link(f'../{version_name(1)}/folder'), 'm': Link(f'../{version_name(1)}/via/x')})
	for rel in 'lm':
		walked = rv.walk_version(vault, 2, rel, True)
		assert (walked.kind, walked.path, walked.followed) == ('symlink', at(vault, 2, rel), [])


def test_a_chain_link_above_the_last_component_is_a_missing_path(vault):
	write_version(vault, 1, {'folder/inside': 'in'})
	write_version(vault, 2, {'l': Link(f'../{version_name(1)}/folder')})
	assert rv.walk_version(vault, 2, 'l/inside', True).kind == 'missing'


def test_a_chain_link_leading_nowhere_is_dangling(vault):
	write_version(vault, 1, {'other': 'x'})
	write_version(vault, 2, {'a/x': Link(f'../../{version_name(1)}/a/x')})
	walked = rv.walk_version(vault, 2, 'a/x', True)
	assert walked.kind == 'dangling' and 'a/x' in walked.detail
	assert rv.resolve_version_entry(vault, at(vault, 2), 'a/x', '/monitored').kind == 'dangling'


def test_any_other_chain_form_text_leading_nowhere_is_a_users_link(vault):
	# what the migration makes of it too: a dangling chain becomes the link itself. Refusing its restore would lose it
	write_version(vault, 1, {'other': 'x'})
	write_version(vault, 2, {'a/x': Link(f'../../{version_name(1)}/b/y'), 'a/y': Link(f'../{version_name(1)}/a/y')})
	for rel in ('a/x', 'a/y'):
		walked = rv.walk_version(vault, 2, rel, True)
		assert (walked.kind, walked.path, walked.followed) == ('symlink', at(vault, 2, rel), [])


def test_links_each_way_never_walk_for_ever(vault):
	# a user's link of chain form, in a vault whose manifest was lost: V1 forwards to it, and it names V1
	write_version(vault, 1, {'a': FORWARD})
	write_version(vault, 2, {'a': Link(f'../{version_name(1)}/a')})
	assert rv.walk_version(vault, 1, 'a', True)[:2] == ('symlink', at(vault, 2, 'a'))
	assert rv.walk_version(vault, 2, 'a', True)[:2] == ('symlink', at(vault, 2, 'a'))


def test_a_lost_manifest_reads_forward_links(vault):
	forward_chain(vault, 1, 3, {'a/x': 'held'})
	# no manifest at all, and one that is no database: forward links are read on any layout
	assert rv.read_vault_layout_for_command(vault) is None
	assert rv.resolve_version_entry(vault, at(vault, 1), 'a/x', '/monitored')[:2] == ('file', at(vault, 3, 'a/x'))
	with open(os.path.join(vault, rv.MANIFEST_FILE_NAME), 'w') as f:
		f.write('not a database, and long enough to be read as one' * 40)
	assert rv.read_vault_layout_for_command(vault) is None
	assert rv.resolve_version_entry(vault, at(vault, 1), 'a/x', '/monitored')[:2] == ('file', at(vault, 3, 'a/x'))


def test_the_layout_is_read_once_a_pass(vault):
	forward_chain(vault, 1, 3, {'a/x': 'held'})
	record_layout(vault, 'r')
	assert rv.read_vault_layout_for_command(vault) == 'r'
	path = os.path.join(vault, rv.MANIFEST_FILE_NAME)
	reading = rv.vault_reading(vault)
	assert reading.backward is False
	os.remove(path)
	assert rv.read_walked(vault, 1, 'a/x', reading).kind == 'file'
	assert reading.backward is False
	assert rv.vault_reading(vault).backward is True


def test_a_manifest_locked_for_a_moment_is_retried(vault):
	record_layout(vault, 'r')
	holder = sqlite3.connect(os.path.join(vault, rv.MANIFEST_FILE_NAME), check_same_thread=False)
	holder.execute('BEGIN EXCLUSIVE')
	stream = io.StringIO()
	got = []
	reader = threading.Thread(target=lambda: got.append(rv.read_vault_layout_for_command(vault, stream)))
	reader.start()
	while not stream.getvalue() and reader.is_alive():
		time.sleep(0.01)
	assert not got
	holder.rollback()
	holder.close()
	reader.join(30)
	assert got == ['r']
	assert stream.getvalue().count('Waiting for reverberator') == 1


def test_a_stop_ends_the_wait_for_a_locked_manifest(vault):
	record_layout(vault, 'r')
	holder = sqlite3.connect(os.path.join(vault, rv.MANIFEST_FILE_NAME))
	holder.execute('BEGIN EXCLUSIVE')
	rv.RESTORE_STOP.set()
	try:
		with pytest.raises(KeyboardInterrupt):
			rv.read_vault_layout_for_command(vault, io.StringIO())
	finally:
		rv.RESTORE_STOP.clear()
		holder.rollback()
		holder.close()


def test_a_manifest_that_cannot_be_asked_says_so(vault, monkeypatch):
	record_layout(vault, 'r')
	def refuse(*args, **kwargs):
		raise sqlite3.OperationalError('disk I/O error')
	monkeypatch.setattr(rv.sqlite3, 'connect', refuse)
	stream = io.StringIO()
	assert rv.read_vault_layout_for_command(vault, stream) is None
	assert 'cannot be read' in stream.getvalue()


def test_resolve_keeps_its_kinds_on_design_r(vault):
	write_version(vault, 1, {'f': FORWARD, 'd': FORWARD, 'u': FORWARD, 'r': FORWARD, 'gone': FORWARD})
	write_version(vault, 2, {'f': 'held', 'd/x': 'held', 'u': Link('elsewhere'), 'r': Link('/monitored/r')})
	record_layout(vault, 'r')
	top = at(vault, 1)
	assert rv.resolve_version_entry(vault, top, 'f', '/monitored') == ('file', at(vault, 2, 'f'), '')
	assert rv.resolve_version_entry(vault, top, 'd', '/monitored') == ('folder', at(vault, 2, 'd'), '')
	assert rv.resolve_version_entry(vault, top, 'd/x', '/monitored') == ('file', at(vault, 2, 'd/x'), '')
	assert rv.resolve_version_entry(vault, top, 'u', '/monitored') == ('symlink', at(vault, 2, 'u'), 'elsewhere')
	assert rv.resolve_version_entry(vault, top, 'r', '/monitored') == ('referenced', at(vault, 2, 'r'), '/monitored/r')
	assert rv.resolve_version_entry(vault, top, 'gone', '/monitored').kind == 'missing'
	assert rv.resolve_version_entry(vault, top, 'nothing', '/monitored').kind == 'missing'
	assert rv.resolve_version_entry(vault, top, 'u/x', '/monitored').kind == 'missing'
	assert rv.resolve_version_entry(vault, top, '', '/monitored') == ('folder', top, '')


def lock_backup(job_name='j'):
	'''The backup lock of job_name, held as a batch holds it, by an open file: close it to end the batch.'''
	path = rv.job_lock_path(job_name, 'backup')
	os.makedirs(os.path.dirname(path), exist_ok=True)
	fd = rv.open_job_lock(path)
	fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
	return fd


def test_backup_is_running_asks_the_lock_and_lets_it_go():
	assert rv.backup_is_running(None) is False
	assert rv.backup_is_running('never ran') is False
	assert not os.path.lexists(rv.job_lock_path('never ran', 'backup'))
	fd = lock_backup()
	assert rv.backup_is_running('j') is True
	os.close(fd)
	assert rv.backup_is_running('j') is False
	# no hold is left behind: a batch takes it at once
	fd = rv.open_job_lock(rv.job_lock_path('j', 'backup'))
	fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
	os.close(fd)


def read_text(walked):
	if walked.kind != 'file':
		return walked.kind
	with open(walked.path) as f:
		return f.read()


def test_read_checked_reads_the_landing(vault):
	forward_chain(vault, 1, 3, {'a/x': 'held'})
	assert rv.read_checked(vault, 1, 'a/x', read_text, backward=False) == 'held'
	assert rv.read_checked(vault, 1, 'nothing', read_text, backward=False) == 'missing'


def test_read_checked_finds_the_layout_itself(vault):
	chain_vault(vault)
	assert rv.read_checked(vault, 3, 'a/x', read_text) == 'held'
	record_layout(vault, 'r')
	assert rv.read_checked(vault, 3, 'a/x', read_text) == 'symlink'


def test_read_checked_walks_again_when_a_followed_link_changed(vault):
	# the batch records under the reader: V1's entry becomes real, and the tree's takes the new content
	forward_chain(vault, 1, 2, {'a': 'old'})
	reads = []
	def read(walked):
		text = read_text(walked)
		reads.append(text)
		if len(reads) == 1:
			os.remove(at(vault, 1, 'a'))
			with open(at(vault, 1, 'a'), 'w') as f:
				f.write('old, recorded')
			with open(at(vault, 2, 'a'), 'w') as f:
				f.write('new')
		return text
	assert rv.read_checked(vault, 1, 'a', read, backward=False) == 'old, recorded'
	assert reads == ['old', 'old, recorded']


def test_read_checked_walks_again_when_a_read_finds_the_entry_gone(vault):
	forward_chain(vault, 1, 2, {'a': 'held'})
	calls = []
	def read(walked):
		calls.append(walked.path)
		if len(calls) == 1:
			os.remove(at(vault, 1, 'a'))
			os.rename(at(vault, 2, 'a'), at(vault, 1, 'a'))
			raise FileNotFoundError(errno.ENOENT, 'gone', walked.path)
		return read_text(walked)
	assert rv.read_checked(vault, 1, 'a', read, backward=False) == 'held'
	assert calls == [at(vault, 2, 'a'), at(vault, 1, 'a')]


def test_read_checked_walks_again_past_a_folders_link_to_itself(vault):
	# a folder's record leaves a link naming itself in the tree for a moment, and the kernel gives ELOOP through it
	forward_chain(vault, 1, 2, {'a/x': 'held'})
	def read(walked):
		if walked.path == at(vault, 2, 'a/x'):
			os.remove(at(vault, 1, 'a'))
			os.rename(at(vault, 2, 'a'), at(vault, 1, 'a'))
			os.symlink(forward_text('a', version_name(2)), at(vault, 2, 'a'))
			with open(walked.path):
				pass
		return read_text(walked)
	assert rv.read_checked(vault, 1, 'a/x', read, backward=False) == 'held'


def test_a_read_failing_the_same_way_again_is_raised(vault):
	write_version(vault, 1, {'a': 'held'})
	def read(walked):
		raise FileNotFoundError(errno.ENOENT, 'a file the read itself wanted')
	with pytest.raises(FileNotFoundError):
		rv.read_checked(vault, 1, 'a', read, backward=False)


def test_a_missing_entry_waits_for_a_running_backup(vault, capsys):
	# a pool's hand-over: the version's folder is away for a moment, and the batch holds the lock
	write_version(vault, 1, {'a': 'held'})
	os.rename(at(vault, 1), at(vault, 1) + '.away')
	fd = lock_backup()
	got = []
	reader = threading.Thread(target=lambda: got.append(rv.read_checked(vault, 1, 'a', read_text, job='j', backward=False)))
	reader.start()
	reader.join(0.3)
	assert reader.is_alive() and not got
	os.rename(at(vault, 1) + '.away', at(vault, 1))
	os.close(fd)
	reader.join(30)
	assert got == ['held']
	assert capsys.readouterr().err.count('Waiting for reverberator to finish a backup of j') == 1


def test_a_missing_entry_with_no_backup_running_is_missing_at_once(vault):
	write_version(vault, 1, {'a': 'held'})
	assert rv.read_checked(vault, 1, 'nothing', read_text, job='j', backward=False) == 'missing'


def test_a_link_leading_nowhere_waits_too(vault):
	forward_chain(vault, 1, 2, {'a': 'held'})
	os.rename(at(vault, 2), at(vault, 2) + '.away')
	fd = lock_backup()
	got = []
	reader = threading.Thread(target=lambda: got.append(rv.read_checked(vault, 1, 'a', read_text, job='j', backward=False)))
	reader.start()
	reader.join(0.3)
	assert reader.is_alive()
	os.rename(at(vault, 2) + '.away', at(vault, 2))
	os.close(fd)
	reader.join(30)
	assert got == ['held']


def test_the_lock_is_asked_in_the_state_folder_a_command_is_told(vault, tmp_path):
	state = str(tmp_path / 'told')
	os.mkdir(state)
	fd = rv.open_job_lock(rv.job_lock_path('j', 'backup', state))
	fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
	assert rv.backup_is_running('j', state) is True
	assert rv.backup_is_running('j') is False
	os.close(fd)
	assert rv.backup_is_running('j', state) is False


def test_a_stop_ends_the_wait_for_a_backup(vault):
	fd = lock_backup()
	rv.RESTORE_STOP.set()
	try:
		with pytest.raises(KeyboardInterrupt):
			rv.read_checked(vault, 1, 'a', read_text, job='j', backward=False)
	finally:
		rv.RESTORE_STOP.clear()
		os.close(fd)


def test_a_users_link_recorded_between_the_lstat_and_the_readlink_comes_with_its_own_lstat(vault, monkeypatch):
	# the forward link read by the lstat, the user's link a record renamed over it by the readlink: its lstat would be the forward link's
	top = write_version(vault, 1, {'u': FORWARD})
	held = write_version(vault, 2, {'u': Link('elsewhere')})
	real = os.readlink
	def readlink(path, *args, **kwargs):
		if path == os.path.join(top, 'u') and os.path.lexists(os.path.join(held, 'u')):
			os.rename(os.path.join(held, 'u'), path)
		return real(path, *args, **kwargs)
	monkeypatch.setattr(os, 'readlink', readlink)
	walked = rv.walk_version(vault, 1, 'u', False)
	assert (walked.kind, walked.path, walked.detail) == ('symlink', at(vault, 1, 'u'), 'elsewhere')
	assert rv.same_inode(walked.st, os.lstat(at(vault, 1, 'u')))


def test_a_real_batch_vault_walks_as_the_oracle_reads(tmp_path, r_layout):
	# a vault of real batches: every version's every entry lands where the oracle's own rule lands
	job = create_job(str(tmp_path))
	build_base(job)
	folders = {version_number(name): name for name in os.listdir(job.job_vault) if version_number(name) is not None}
	assert len(folders) == 3
	checked = 0
	for number, name in folders.items():
		pending = list(os.listdir(os.path.join(job.job_vault, name)))
		while pending:
			rel = pending.pop()
			place = landing(job.job_vault, name, rel)
			walked = rv.walk_version(job.job_vault, number, rel, False)
			assert walked.path == os.path.join(job.job_vault, *place), rel
			checked += 1
			if walked.kind == 'folder':
				pending.extend(f'{rel}/{entry}' for entry in os.listdir(walked.path))
	assert checked > 100
