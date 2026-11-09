'''
Design R's records: before the newest tree changes at a path, the writer puts that path's old state in the previous version.
A record missed or made in the wrong order means a kept version silently reads wrong, so version n is read after every change
here, through the independent oracle (tests/vault_oracle.py), which shares no code with the writer.
'''
import errno
import json
import os
import random
import shutil
import stat
from collections import namedtuple
from types import SimpleNamespace

import pytest

import reverberator as rv
from tests import vault_oracle
from tests.crash_child import in_child
from tests.harness import copy_now, link_text_limit
from tests.scratch_images import SCRATCH, f2fs_mount, needs_f2fs
from tests.vault_oracle import landing, read_view, snapshot_tree

pytestmark = pytest.mark.skipif(os.geteuid() != 0, reason='the root record is a trusted.* attribute, and entries are chowned')

V1, V2, V3 = 'V1--old', 'V2--new', 'V3--newer'
ROOT_RECORD = 'trusted.reverberator.root'


def write_root_record(folder, mtime_ns=1):
	record = {'mode': 0o750, 'uid': 0, 'gid': 0, 'mtime_ns': mtime_ns, 'xattrs': {}}
	os.setxattr(folder, ROOT_RECORD, json.dumps(record).encode())


def give_old_times(top):
	'''Every folder under top, top too, a time of its own in the past: a time the batch bumps cannot match it by chance.'''
	for number, (folder, _, _) in enumerate(os.walk(top, topdown=False)):
		os.utime(folder, ns=(1_000_000_000_000_000_000 + number, 1_100_000_000_000_000_000 + number))


def a_vault(tmp, entries):
	'''(job_vault, V1's path), V1 holding entries: {rel: text of a file; None for a folder}. Folders above are made.'''
	job_vault = os.path.join(tmp, 'vault')
	newest = os.path.join(job_vault, V1)
	os.makedirs(newest)
	for rel, data in entries.items():
		path = os.path.join(newest, rel)
		if data is None:
			os.makedirs(path, exist_ok=True)
		else:
			os.makedirs(os.path.dirname(path), exist_ok=True)
			with open(path, 'w') as f:
				f.write(data)
	write_root_record(newest)
	give_old_times(newest)
	return job_vault, newest


def handed_over(tmp, entries):
	'''(writer, job_vault, version 1's view), the tree handed over from V1 to V2.'''
	job_vault, newest = a_vault(tmp, entries)
	before = read_view(job_vault, V1)
	writer = rv.hand_over(job_vault, newest, os.path.join(job_vault, V2))
	return writer, job_vault, before


def source_file(tmp, text='new', name='source'):
	path = os.path.join(tmp, name)
	with open(path, 'w') as f:
		f.write(text)
	return path


def read_through(job_vault, folder_name, rel):
	'''The contents of rel in a version, read as the oracle walks it.'''
	with open(os.path.join(job_vault, *landing(job_vault, folder_name, rel)), 'rb') as f:
		return f.read()


def staging_of(job_vault):
	return os.listdir(os.path.join(job_vault, rv.STAGING_NAME))


# --- the random model: what the batch does to the tree, version n read after each change ---

Task = namedtuple('Task', ['returncode', 'stderr'])
NAMES = ['a', 'b', 'c', 'name with space', 'bad\udcffbyte', 'new\nline']


class RunsAtOnce:
	'''An executor's place: what the writer queues runs here and now, in this process, so a random run spawns nothing.'''
	def run_command(self, command):
		if command[0] == 'rm':
			rv.remove_entry(command[-1])
		else:
			shutil.copy2(command[-2], command[-1], follow_symlinks=False)
		return Task(0, [])


def populate(rng, top, count):
	for _ in range(count):
		rel = random_rel(rng)
		path = os.path.join(top, rel)
		if not rv.real_folders_to(top, rel, missing_ok=True) or os.path.lexists(path):
			continue
		os.makedirs(os.path.dirname(path), exist_ok=True)
		kind = rng.choice('ffdddl')
		if kind == 'f':
			with open(path, 'w') as f:
				f.write(f'contents {rng.random()}')
			os.chmod(path, rng.choice((0o644, 0o600, 0o755)))
			os.utime(path, ns=(rng.randrange(10**18), rng.randrange(10**18)))
		elif kind == 'd':
			os.mkdir(path)
			os.chmod(path, rng.choice((0o755, 0o700, 0o2775)))
			os.chown(path, rng.choice((0, 1000)), 0)
		else:
			os.symlink(rng.choice(('a', 'gone', '/etc', '../b', '../V9--x/a')), path)
		if kind != 'l' and rng.random() < 0.3:
			os.setxattr(path, 'user.note', str(rng.random()).encode())


def random_rel(rng):
	return '/'.join(rng.choice(NAMES) for _ in range(rng.randint(1, 3)))


def existing_rel(rng, top):
	'''An entry of the tree at top, most often, so moves and folder changes meet something; else any path.'''
	held = [rel for rel in snapshot_tree(top) if rel]
	return rng.choice(held) if held and rng.random() < 0.8 else random_rel(rng)


def shape(top):
	'''The kinds, contents and link texts of the tree at top: what a batch leaves it holding.'''
	return {rel: (view.kind, view.data) for rel, view in snapshot_tree(top).items() if rel}


def is_folder(path):
	return os.path.isdir(path) and not os.path.islink(path)


def apply_random_change(rng, writer, shadow, tmp, log):
	'''One random change of the tree, through the writer's verbs as the replay checks and calls them, and on a plain folder, shadow, with plain calls.'''
	tree = writer.tree
	verb = rng.choice(('place', 'place', 'failed_copy', 'remove', 'remove_queued', 'rename', 'rename', 'make', 'folder_meta', 'folder_times'))
	rel = existing_rel(rng, tree)
	if not rv.real_folders_to(tree, rel, missing_ok=True):
		return
	path, mirror = os.path.join(tree, rel), os.path.join(shadow, rel)
	log.append((verb, rel))
	if verb in ('place', 'failed_copy'):
		source = source_file(tmp, f'new {rng.random()}')
		pending = []
		writer.copy(source, rel, RunsAtOnce(), pending)
		os.makedirs(os.path.dirname(mirror), exist_ok=True)
		if verb == 'place':
			writer.place(pending[0].temp_path, rel)
			rv.remove_entry(mirror)
			shutil.copy2(source, mirror)
		else:
			writer.discard_temp(pending[0].temp_path)
	elif verb in ('remove', 'remove_queued'):
		if verb == 'remove':
			writer.remove_now(rel)
		else:
			writer.remove_queued(rel, is_folder(path), RunsAtOnce(), [])
		rv.remove_entry(mirror)
	elif verb == 'rename':
		dst = random_rel(rng) if rng.random() < 0.7 else existing_rel(rng, tree)
		log.append(('to', dst))
		if dst == rel or not rv.real_folders_to(tree, dst, missing_ok=True):
			return
		mirror_dst = os.path.join(shadow, dst)
		can = os.path.lexists(mirror) and not dst.startswith(rel + '/') and rv.real_folders_to(shadow, dst)
		renamed = writer.rename(rel, dst)
		if can and rel.startswith(dst + '/'):
			# mv d/x d: the target goes with the source in it, and delete & copy brings it back
			assert renamed is False
			rv.remove_entry(mirror_dst)
			return
		assert renamed is can
		if renamed:
			rv.remove_entry(mirror_dst)
			os.rename(mirror, mirror_dst)
	elif verb == 'make':
		assert writer.make_folders(rel) is True
		assert writer.make_folder(rel) is True
		os.makedirs(os.path.dirname(mirror), exist_ok=True)
		if not is_folder(mirror):
			rv.remove_entry(mirror)
			os.mkdir(mirror)
	elif is_folder(path):
		source = os.path.join(tmp, 'source_folder')
		os.makedirs(source, exist_ok=True)
		os.chmod(source, rng.choice((0o711, 0o755)))
		os.utime(source, ns=(rng.randrange(10**18), rng.randrange(10**18)))
		st = os.lstat(source)
		if verb == 'folder_meta':
			assert writer.folder_meta(source, rel, st, []) is True
			assert stat.S_IMODE(os.lstat(path).st_mode) == stat.S_IMODE(st.st_mode)
		else:
			writer.folder_times(rel, st)
		assert os.lstat(path).st_mtime_ns == st.st_mtime_ns


def test_a_random_sequence_of_tree_changes_keeps_version_n_exact(tmp_path):
	for seed in range(200):
		rng = random.Random(seed)
		tmp = tmp_path / str(seed)
		job_vault, newest = a_vault(str(tmp), {})
		populate(rng, newest, 20)
		give_old_times(newest)
		shadow = str(tmp / 'shadow')
		shutil.copytree(newest, shadow, symlinks=True)
		kept = {V1: read_view(job_vault, V1)}
		log = []
		# two batches: the second reads version 1 through version 2's links, and version 2 through its own
		for previous, new in ((V1, V2), (V2, V3)):
			writer = rv.hand_over(job_vault, os.path.join(job_vault, previous), os.path.join(job_vault, new))
			log.append(('hand over', new))
			for name, view in kept.items():
				assert read_view(job_vault, name) == view, repr((seed, name, log))
			for _ in range(30):
				apply_random_change(rng, writer, shadow, str(tmp), log)
				for name, view in kept.items():
					assert read_view(job_vault, name) == view, repr((seed, name, log))
				assert shape(writer.tree) == shape(shadow), (seed, log)
			assert staging_of(job_vault) == [], (seed, log)
			write_root_record(writer.tree, seed + 2)
			kept[new] = read_view(job_vault, new)
		shutil.rmtree(tmp)


# --- the texts and the hand-over ---

def test_the_forward_text_is_exact():
	assert rv.forward_text('a', 'V2--x') == '../V2--x/a'
	assert rv.forward_text('a/b/c', 'V2--x') == '../../../V2--x/a/b/c'
	assert rv.forward_text('a/bad\udcff', 'V2--x') == '../../V2--x/a/bad\udcff'
	for rel in ('a', 'a/b/c', 'a/bad\udcff', 'new\nline/x'):
		assert rv.forward_text(rel, 'V2--x') == vault_oracle.forward_text(rel, 'V2--x')
	# and as a link, on bytes
	assert os.fsencode(rv.forward_text('bad\udcff', 'V2--x')) == b'../V2--x/bad\xff'


def test_hand_over_leaves_no_moment_without_the_tree(tmp_path):
	def attempt(kill_at, number):
		job_vault, newest = a_vault(str(tmp_path / str(number)), {'x': 'the contents', 'y': 'y', 'd/z': 'z'})
		job = SimpleNamespace(job_vault=job_vault)
		outcome = in_child(job, kill_at, lambda: rv.hand_over(job_vault, newest, os.path.join(job_vault, V2)) is not None)
		assert outcome.error is None
		with open(os.path.join(newest, 'x')) as f:
			assert f.read() == 'the contents', kill_at
		with open(os.path.join(newest, 'd', 'z')) as f:
			assert f.read() == 'z', kill_at
		return outcome
	uncut = attempt(None, 'uncut')
	# the one change that passes the tree over is one exchange: nothing is renamed away and back
	assert uncut.counts['exchange'] == 1 and 'rename' not in uncut.counts and 'remove' not in uncut.counts
	for kill_at in range(1, uncut.steps + 1):
		assert attempt(kill_at, kill_at).killed
	assert not attempt(uncut.steps + 1, 'past').killed


def test_the_skeleton_names_itself_until_its_exchange(tmp_path, monkeypatch):
	job_vault, newest = a_vault(str(tmp_path), {'x': 'x', 'd/y': 'y', 'bad\udcff': 'b'})
	new = os.path.join(job_vault, V2)
	real_exchange = rv.rename_exchange
	seen = []
	def exchange(a, b):
		assert (a, b) == (new, newest)
		seen.append({name: os.readlink(os.path.join(new, name)) for name in os.listdir(new)})
		assert all(not os.path.islink(os.path.join(newest, name)) for name in os.listdir(newest))
		real_exchange(a, b)
	monkeypatch.setattr(rv, 'rename_exchange', exchange)
	writer = rv.hand_over(job_vault, newest, new)
	assert seen == [{'x': f'../{V2}/x', 'd': f'../{V2}/d', 'bad\udcff': f'../{V2}/bad\udcff'}]
	# the same links are forward links, once they stand in the previous version
	assert {name: os.readlink(os.path.join(newest, name)) for name in os.listdir(newest)} == seen[0]
	assert (writer.tree, writer.previous, writer.job_vault) == (new, newest, job_vault)
	with open(os.path.join(new, 'x')) as f:
		assert f.read() == 'x'


def test_hand_over_fails_on_a_folder_already_there_and_changes_nothing(tmp_path):
	job_vault, newest = a_vault(str(tmp_path), {'x': 'x'})
	os.mkdir(os.path.join(job_vault, V2))
	with pytest.raises(FileExistsError):
		rv.hand_over(job_vault, newest, os.path.join(job_vault, V2))
	assert os.listdir(os.path.join(job_vault, V2)) == [] and not os.path.islink(os.path.join(newest, 'x'))


def test_hand_over_makes_staging_before_the_exchange(tmp_path, monkeypatch):
	# a vault whose manifest is lost reads as design R by its staging: the 0.54 rules would remove a cut batch's tree
	job_vault, newest = a_vault(str(tmp_path), {'x': 'x'})
	real_exchange = rv.rename_exchange
	def exchange(a, b):
		assert os.path.isdir(rv.staging_path(job_vault))
		real_exchange(a, b)
	monkeypatch.setattr(rv, 'rename_exchange', exchange)
	rv.hand_over(job_vault, newest, os.path.join(job_vault, V2))
	assert rv.staging_path(job_vault) == os.path.join(job_vault, '.reverberator_staging')


def test_hand_over_copies_the_root_record_and_times(tmp_path):
	job_vault, newest = a_vault(str(tmp_path), {'x': 'x'})
	write_root_record(newest, 77)
	os.utime(newest, ns=(1234, 5678))
	writer = rv.hand_over(job_vault, newest, os.path.join(job_vault, V2))
	st = os.lstat(newest)
	assert (st.st_atime_ns, st.st_mtime_ns) == (1234, 5678)
	assert json.loads(os.getxattr(newest, ROOT_RECORD))['mtime_ns'] == 77
	# a record in P, of a top entry, gives the root its time back too
	writer.record('x', False)
	assert os.lstat(newest).st_mtime_ns == 5678
	assert not os.path.islink(os.path.join(newest, 'x'))


def test_a_vault_with_no_root_record_hands_over(tmp_path):
	job_vault, newest = a_vault(str(tmp_path), {'x': 'x'})
	os.removexattr(newest, ROOT_RECORD)
	rv.hand_over(job_vault, newest, os.path.join(job_vault, V2))
	assert ROOT_RECORD not in os.listxattr(newest)


def test_rename_exchange_raises_oserror(tmp_path):
	with pytest.raises(FileNotFoundError):
		rv.rename_exchange(str(tmp_path / 'gone'), str(tmp_path / 'gone2'))
	(tmp_path / 'a').write_text('a')
	(tmp_path / 'b').mkdir()
	rv.rename_exchange(str(tmp_path / 'a'), str(tmp_path / 'b'))
	assert (tmp_path / 'a').is_dir() and (tmp_path / 'b').read_text() == 'a'


# --- the records ---

def test_a_file_replacing_a_folder_keeps_the_folder_until_placed(tmp_path, monkeypatch):
	entries = {'d/x': 'old x', 'd/sub/y': 'old y', 'keep': 'k'}
	writer, job_vault, before = handed_over(str(tmp_path), entries)
	source = source_file(str(tmp_path))
	# the copy fails: the tree still has the folder, and so has version 1
	monkeypatch.setattr(rv, 'copy_command', lambda source_path, dest_path: ['false'])
	assert copy_now(writer, source, 'd') == 1
	tree = writer.tree
	assert is_folder(os.path.join(tree, 'd')) and (tmp_path / 'vault' / V2 / 'd' / 'sub' / 'y').read_text() == 'old y'
	assert read_view(job_vault, V1) == before
	assert not os.path.islink(os.path.join(writer.previous, 'd'))
	monkeypatch.undo()
	# the copy works: the file takes the folder's place in the tree only
	assert copy_now(writer, source, 'd') == 0
	assert (tmp_path / 'vault' / V2 / 'd').read_text() == 'new'
	assert read_view(job_vault, V1) == before
	assert staging_of(job_vault) == []


def test_a_folder_copied_over_itself_records_per_entry(tmp_path, monkeypatch):
	entries = {'d/copied': 'old copied', 'd/unreadable': 'old unreadable', 'd/sub/deep': 'old deep', 'd/sub/deep2': 'old deep2', 'other': 'o'}
	writer, job_vault, before = handed_over(str(tmp_path), entries)
	source = source_file(str(tmp_path))
	real_command = rv.copy_command
	monkeypatch.setattr(rv, 'copy_command', lambda source_path, dest_path: ['false'] if source_path.endswith('unreadable') else real_command(source_path, dest_path))
	bad = source_file(str(tmp_path), 'cannot be read', 'unreadable')
	# the steps of copy_path() for a folder create over the folder there
	assert writer.make_folder('d') is True
	assert read_view(job_vault, V1) == before
	previous, tree = writer.previous, writer.tree
	assert is_folder(os.path.join(previous, 'd')) and os.path.islink(os.path.join(previous, 'd', 'copied'))
	assert copy_now(writer, source, 'd/copied') == 0
	assert copy_now(writer, bad, 'd/unreadable') == 1
	assert writer.make_folder('d/sub') is True
	assert os.path.islink(os.path.join(previous, 'd', 'sub', 'deep2'))
	assert copy_now(writer, source, 'd/sub/deep') == 0
	assert read_view(job_vault, V1) == before
	# the copy that failed keeps the last copy in both versions
	assert read_through(job_vault, V2, 'd/unreadable') == b'old unreadable'
	assert os.lstat(os.path.join(previous, 'd', 'unreadable')).st_ino == os.lstat(os.path.join(tree, 'd', 'unreadable')).st_ino
	assert read_through(job_vault, V2, 'd/copied') == b'new'
	# the folder itself never left the tree, and what no copy touched is still a forward link
	assert os.path.islink(os.path.join(previous, 'd', 'sub', 'deep2')) and os.path.islink(os.path.join(previous, 'other'))


def test_a_move_records_by_hard_link(tmp_path):
	writer, job_vault, before = handed_over(str(tmp_path), {'d/x': 'old x', 'd/sub/y': 'old y'})
	tree, previous = writer.tree, writer.previous
	inode = os.lstat(os.path.join(tree, 'd', 'x')).st_ino
	assert writer.rename('d', 'e') is True
	assert os.lstat(os.path.join(previous, 'd', 'x')).st_ino == inode == os.lstat(os.path.join(tree, 'e', 'x')).st_ino
	assert read_view(job_vault, V1) == before
	# mv d e; echo new > e/x: version 1 never held e, so nothing is recorded, and the new copy leaves the old inode in P/d/x
	assert copy_now(writer, source_file(str(tmp_path)), 'e/x') == 0
	assert os.lstat(os.path.join(tree, 'e', 'x')).st_ino != inode
	assert os.lstat(os.path.join(previous, 'd', 'x')).st_ino == inode
	assert read_view(job_vault, V1) == before
	assert not os.path.lexists(os.path.join(previous, 'e'))


def test_a_rename_with_nothing_to_rename_changes_nothing(tmp_path):
	writer, job_vault, before = handed_over(str(tmp_path), {'f': 'f', 'to': 'to', 'd/x': 'x'})
	assert writer.rename('gone', 'to') is False
	assert writer.rename('d', 'd/e') is False
	# the folder it goes into is not there: delete & copy makes it with all of the monitored folder's metadata
	assert writer.rename('f', 'none/f') is False
	assert (tmp_path / 'vault' / V2 / 'f').read_text() == 'f' and (tmp_path / 'vault' / V2 / 'to').read_text() == 'to'
	assert all(os.path.islink(os.path.join(writer.previous, name)) for name in ('f', 'to', 'd'))
	assert read_view(job_vault, V1) == before


def test_emlink_records_a_copy(tmp_path, monkeypatch):
	entries = {'keep': 'kept', 'moved': 'moved', 'd/x': 'in d', 'd/sub/y': 'in sub'}
	writer, job_vault, before = handed_over(str(tmp_path), entries)
	os.setxattr(os.path.join(writer.tree, 'keep'), 'user.note', b'held')
	os.utime(os.path.join(writer.tree, 'keep'), ns=(5, 6))
	before = {**before, 'keep': vault_oracle.entry_view(os.path.join(writer.tree, 'keep'))}
	def no_more_links(*args, **kwargs):
		raise OSError(errno.EMLINK, 'Too many links')
	monkeypatch.setattr(os, 'link', no_more_links)
	writer.record('keep', True)
	writer.hl_record('moved')
	writer.hl_record('d')
	assert read_view(job_vault, V1) == before
	for rel in ('keep', 'moved', 'd/x', 'd/sub/y'):
		kept, tree = os.lstat(os.path.join(writer.previous, rel)), os.lstat(os.path.join(writer.tree, rel))
		assert stat.S_ISREG(kept.st_mode) and kept.st_ino != tree.st_ino
		assert (kept.st_mtime_ns, kept.st_mode) == (tree.st_mtime_ns, tree.st_mode)
	assert staging_of(job_vault) == []


def test_another_link_error_fails_the_record_and_keeps_version_n(tmp_path, monkeypatch):
	writer, job_vault, before = handed_over(str(tmp_path), {'x': 'x'})
	def full(*args, **kwargs):
		raise OSError(errno.ENOSPC, 'No space left on device')
	monkeypatch.setattr(os, 'link', full)
	# no caller goes on as if the old state were kept
	with pytest.raises(rv.JobFailure, match='No space left'):
		writer.record('x', True)
	assert read_view(job_vault, V1) == before


def test_a_folder_an_rm_is_removing_needs_no_record(tmp_path, monkeypatch):
	# deletes run deepest first and their rm runs beside the replay: the record of a folder above can look at one the rm then takes
	writer, job_vault, before = handed_over(str(tmp_path), {'d/sub/x': 'x', 'd/y': 'y'})
	writer.record('d/sub/x', True)
	real_listdir = os.listdir
	def gone(path):
		if os.path.normpath(path).endswith('d/sub'):
			raise FileNotFoundError(errno.ENOENT, 'gone', path)
		return real_listdir(path)
	with monkeypatch.context() as patch:
		patch.setattr(os, 'listdir', gone)
		writer.record('d', False)
	assert read_view(job_vault, V1) == before


def test_a_metadata_copy_that_fails_fails_the_unfold_before_the_exchange(tmp_path, monkeypatch):
	writer, job_vault, before = handed_over(str(tmp_path), {'d/x': 'x'})
	def no_meta(source, dest, failed=None):
		failed.append(source)
		return False
	monkeypatch.setattr(rv, 'copy_file_meta', no_meta)
	with pytest.raises(rv.JobFailure):
		writer.ensure_real('d')
	assert os.path.islink(os.path.join(writer.previous, 'd'))
	assert read_view(job_vault, V1) == before


def test_a_forwarded_entry_missing_from_the_tree_fails_the_attempt_on_a_pool(tmp_path, monkeypatch):
	# a pool's disk gone: copying over it would make version 1 read the new copy, and it may come back
	writer, job_vault, _ = handed_over(str(tmp_path), {'x': 'x', 'd/y': 'y'})
	os.remove(os.path.join(writer.tree, 'x'))
	shutil.rmtree(os.path.join(writer.tree, 'd'))
	monkeypatch.setattr(rv, 'pool_state', lambda path, mount_table=None: (path,))
	with pytest.raises(rv.JobFailure, match='x'):
		writer.record('x', True)
	with pytest.raises(rv.JobFailure, match='d'):
		writer.record('d/y', True)
	with pytest.raises(rv.JobFailure, match='d'):
		writer.ensure_real('d')
	assert os.path.islink(os.path.join(writer.previous, 'x')) and os.path.islink(os.path.join(writer.previous, 'd'))


def test_a_forwarded_entry_missing_from_the_tree_goes_with_a_warning_on_one_filesystem(tmp_path, capsys):
	# only a hand can have removed it, and the version already reads as missing there
	writer, job_vault, before = handed_over(str(tmp_path), {'x': 'x', 'd/y': 'y', 'e/f/z': 'z', 'kept': 'k'})
	os.remove(os.path.join(writer.tree, 'x'))
	shutil.rmtree(os.path.join(writer.tree, 'd'))
	os.remove(os.path.join(writer.tree, 'e/f/z'))
	times = os.lstat(writer.previous).st_mtime_ns
	writer.record('x', True)
	writer.record('d/y', True)
	assert writer.ensure_real('d') is False
	writer.record('e/f/z', True)
	out = capsys.readouterr().out
	assert os.path.join(writer.previous, 'x') in out and os.path.join(writer.previous, 'd') in out
	assert not os.path.lexists(os.path.join(writer.previous, 'x')) and not os.path.lexists(os.path.join(writer.previous, 'd'))
	assert os.lstat(writer.previous).st_mtime_ns == times
	# a copy put there later does not show in the version
	with open(os.path.join(writer.tree, 'x'), 'w') as f:
		f.write('new')
	view = read_view(job_vault, V1)
	assert sorted(set(before) - set(view)) == ['d', 'd/y', 'e/f/z', 'x']
	# the hand's removal moved its folder's time, which the link still showed
	assert [rel for rel in view if view[rel] != before[rel]] == ['e/f']


def deep_vault(tmp, levels):
	'''A job vault whose V1 is levels folders 'd' deep, a file f in each saying its level; the last has a link and a folder too.'''
	job_vault = os.path.join(tmp, 'vault')
	path = os.path.join(job_vault, V1)
	os.makedirs(path)
	for level in range(1, levels + 1):
		path = os.path.join(path, 'd')
		os.mkdir(path)
		with open(os.path.join(path, 'f'), 'w') as f:
			f.write(str(level))
	os.symlink('f', os.path.join(path, 'user_link'))
	os.mkdir(os.path.join(path, 'last'))
	write_root_record(os.path.join(job_vault, V1))
	return job_vault, os.path.join(job_vault, V1)


def test_a_forward_text_too_long_is_recorded_real(tmp_path):
	levels = 1500
	job_vault, newest = deep_vault(str(tmp_path), levels)
	deepest = '/'.join(['d'] * levels)
	# the longest text the filesystem takes: 4,095 on ext4 and f2fs, 1,023 on XFS
	limit = link_text_limit(str(tmp_path))
	assert len(rv.forward_text(deepest + '/f', V2)) > limit
	mtime = os.lstat(os.path.join(newest, deepest)).st_mtime_ns
	writer = rv.hand_over(job_vault, newest, os.path.join(job_vault, V2))
	previous, tree = writer.previous, writer.tree
	source = source_file(str(tmp_path))
	# all the way down: the folders unfold while their entries' texts fit, and below that the entries are real
	assert copy_now(writer, source, deepest + '/f') == 0
	first_real = None
	for level in range(1, levels + 1):
		rel = '/'.join(['d'] * level) + '/f'
		kept = os.lstat(os.path.join(previous, rel))
		if stat.S_ISLNK(kept.st_mode):
			assert first_real is None and os.readlink(os.path.join(previous, rel)) == vault_oracle.forward_text(rel, V2)
		else:
			first_real = first_real or level
			if level < levels:
				assert kept.st_ino == os.lstat(os.path.join(tree, rel)).st_ino
	# the first level whose forward text is over what the filesystem takes (about 800 levels on ext4, 200 on XFS)
	assert first_real == next(level for level in range(1, levels + 1) if len(vault_oracle.forward_text('/'.join(['d'] * level) + '/f', V2)) > limit)
	# what it read, the oracle reads: forward links down to there, real entries below it
	for level in (1, 2, first_real - 1, first_real, first_real + 1, levels - 1):
		assert read_through(job_vault, V1, '/'.join(['d'] * level) + '/f') == str(level).encode()
	assert read_through(job_vault, V1, deepest + '/f') == str(levels).encode()
	assert read_through(job_vault, V2, deepest + '/f') == b'new'
	assert os.readlink(os.path.join(previous, deepest, 'user_link')) == 'f'
	assert is_folder(os.path.join(previous, deepest, 'last'))
	assert os.lstat(os.path.join(previous, deepest)).st_mtime_ns == mtime
	# a move of all of it needs no stack as deep as the tree
	assert writer.rename('d', 'e') is True
	assert read_through(job_vault, V1, deepest + '/f') == str(levels).encode()
	assert staging_of(job_vault) == []
	shutil.rmtree(job_vault)


def p_state(previous):
	'''All of P as stored, nothing followed: a record run again must change none of it. A link's access time is left out: reading its text here moves it (relatime).'''
	state = {}
	for folder, names, files in os.walk(previous):
		for name in ['.'] + names + files:
			path = os.path.normpath(os.path.join(folder, name))
			st = os.lstat(path)
			link = stat.S_ISLNK(st.st_mode)
			state[path] = (st.st_mode, st.st_ino, st.st_mtime_ns, None if link else st.st_atime_ns, os.readlink(path) if link else None)
	return state


@pytest.mark.parametrize('do', [
	lambda writer: writer.record('file', True),
	lambda writer: writer.record('file', False),
	lambda writer: writer.record('d', True),
	lambda writer: writer.record('d', False),
	lambda writer: writer.record('d/sub/deep', True),
	lambda writer: writer.record('d/sub/deep', False),
	lambda writer: writer.hl_record('file'),
	lambda writer: writer.hl_record('d'),
	lambda writer: writer.hl_record('d/sub'),
	lambda writer: writer.ensure_real('d/sub'),
	lambda writer: writer.record('not/in/version', True),
	lambda writer: writer.hl_record('not/in/version'),
	lambda writer: writer.record('file/below', True),
], ids=['file_keep', 'file_gone', 'folder_keep', 'folder_gone', 'deep_keep', 'deep_gone', 'hl_file', 'hl_folder', 'hl_sub', 'ensure_real', 'not_in', 'hl_not_in', 'below_file'])
def test_records_are_idempotent(tmp_path, do):
	writer, job_vault, before = handed_over(str(tmp_path), {'file': 'f', 'd/x': 'x', 'd/sub/deep': 'deep', 'd/sub/deep2': 'deep2'})
	do(writer)
	state = p_state(writer.previous)
	do(writer)
	assert p_state(writer.previous) == state
	# by a writer that has not seen it: the attempt after a cut
	do(rv.TreeWriter(writer.tree, previous=writer.previous, job_vault=job_vault))
	assert p_state(writer.previous) == state
	assert read_view(job_vault, V1) == before
	assert staging_of(job_vault) == []


def test_a_merge_records_what_still_forwards_and_nothing_else(tmp_path):
	writer, job_vault, before = handed_over(str(tmp_path), {'d/old': 'old', 'd/kept': 'kept', 'd/sub/x': 'x'})
	# P/d is real, one entry recorded: the removal of the folder records the others one by one
	assert copy_now(writer, source_file(str(tmp_path)), 'd/old') == 0
	assert copy_now(writer, source_file(str(tmp_path)), 'd/born') == 0
	writer.remove_now('d')
	assert not os.path.lexists(os.path.join(writer.tree, 'd'))
	assert read_view(job_vault, V1) == before
	assert not os.path.lexists(os.path.join(writer.previous, 'd', 'born'))
	assert not os.path.islink(os.path.join(writer.previous, 'd', 'sub'))


def test_pass_through_writes_only_the_tree(tmp_path):
	# previous None: V0 and the 0.54 layout. no record, no staging
	tree = tmp_path / 'tree'
	tree.mkdir()
	(tree / 'x').write_text('x')
	writer = rv.TreeWriter(str(tree))
	writer.record('x', True)
	writer.hl_record('x')
	assert writer.ensure_real('d') is False
	assert writer.make_folder('d') is True and (tree / 'd').is_dir()
	writer.folder_times('d', os.lstat(tree))
	writer.remove_now('x')
	assert sorted(os.listdir(tmp_path)) == ['tree'] and os.listdir(tree) == ['d']


# --- on the filesystem of the live vaults ---

@needs_f2fs
def test_unfold_gives_times_back_on_f2fs():
	with f2fs_mount(SCRATCH, 128) as mount_point:
		entries = {'top': 't', 'd/sub/x': 'x', 'd/sub/y': 'y', 'd/z': 'z', 'moved/a/b': 'b', 'gone/in/here': 'h', 'made/w': 'w'}
		job_vault, newest = a_vault(mount_point, entries)
		st = os.lstat(newest)
		before = read_view(job_vault, V1)
		writer = rv.hand_over(job_vault, newest, os.path.join(job_vault, V2))
		# the exchange keeps the root's times here too
		assert os.lstat(newest).st_mtime_ns == st.st_mtime_ns
		assert read_view(job_vault, V1) == before
		parent_mtime = before['d'].mtime_ns
		# an unfold into its parent, and that parent's own, and a folder exchanged in, and a hard-link tree
		assert copy_now(writer, source_file(mount_point), 'd/sub/x') == 0
		assert os.lstat(os.path.join(newest, 'd')).st_mtime_ns == parent_mtime
		assert os.lstat(os.path.join(newest, 'd', 'sub')).st_mtime_ns == before['d/sub'].mtime_ns
		assert read_view(job_vault, V1) == before
		writer.remove_now('gone')
		assert os.lstat(os.path.join(newest, 'gone')).st_mtime_ns == before['gone'].mtime_ns
		assert read_view(job_vault, V1) == before
		assert writer.rename('moved', 'moved2') is True
		assert os.lstat(os.path.join(newest, 'moved', 'a')).st_mtime_ns == before['moved/a'].mtime_ns
		assert read_view(job_vault, V1) == before
		assert copy_now(writer, source_file(mount_point), 'top') == 0
		assert os.lstat(newest).st_mtime_ns == st.st_mtime_ns
		assert writer.make_folder('made') is True
		writer.folder_times('made', os.lstat(newest))
		assert os.lstat(os.path.join(newest, 'made')).st_mtime_ns == before['made'].mtime_ns
		assert read_view(job_vault, V1) == before
		assert staging_of(job_vault) == []
