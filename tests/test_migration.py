'''
The one-time conversion of a 0.54 vault (spec section 7, plan S1): every version becomes a plain tree of hard links to the ends
of its chains, newest first, then a sizes pass, then the layout. It rewrites real backup history, so each version is read
before and after by the oracle (tests/vault_oracle.py), which shares no rule with the daemon, and by the commands' own walk at
every kill point.

The vaults are real: tests/legacy054.py builds them with the 0.54.1 module. REVERB_CRASH_FULL=1 runs every kill point of the
sweep; by default a stride of them.
'''
import errno
import os
import random
import shutil
import sqlite3
import subprocess
import tempfile
from collections import OrderedDict

import pytest

import reverberator as rv
from tests.crash_batches import apply_batch1, apply_batch2, backup_events, change_batch3, put_text, seed_base, T0
from tests.crash_child import in_child
from tests.harness import create_job
from tests.scratch_images import f2fs_mount, flush_scratch, LoopImage, needs_f2fs, SCRATCH, shut_down_scratch
from tests.vault_oracle import check_vault, daemon_links, entry_view, read_view, recorded_design_r, sizes_by_newest_holder, snapshot_tree, version_number
from tests.version_view_ground_truth import committed_folders, wrong_lists

pytestmark = pytest.mark.skipif(os.geteuid() != 0, reason='the root record is a trusted.* attribute, and a file is chowned')

KEEP = 4
DEFAULT_KILL_POINTS = 120
SALT, MARKER = rv.PRUNE_SALT_FILE_NAME, rv.PRUNE_MARKER_FILE_NAME
PREPARED = {}


def change_batch4(monitor):
	'''A chain three hops long, a file moved a second time to another depth, a special file, a file gone.'''
	put_text(monitor, 'a/x.txt', 'ax4')
	os.rename(os.path.join(monitor, 'g/h/other.txt'), os.path.join(monitor, 'g/moved.txt'))
	os.rename(os.path.join(monitor, 'chain3.txt'), os.path.join(monitor, 'a/chain4.txt'))
	os.mkfifo(os.path.join(monitor, 'pipe'))
	os.remove(os.path.join(monitor, 'e0.txt'))
	return [(False, 'modify', 'a/x.txt', None), (False, 'move', 'g/moved.txt', 'g/h/other.txt'), (False, 'move', 'a/chain4.txt', 'chain3.txt'),
		(False, 'create', 'pipe', None), (False, 'delete', 'e0.txt', None)]


# every item of spec section 9 that a 0.54 vault can hold, its first version pruned
EVERY_ITEM = [seed_base, apply_batch1, apply_batch2, change_batch3, change_batch4]


def small_seed(monitor):
	for rel, text in (('a.txt', 'a0'), ('b.txt', 'b0'), ('d/c.txt', 'c0'), ('d/e/f.txt', 'f0')):
		put_text(monitor, rel, text, T0)
	os.symlink('a.txt', os.path.join(monitor, 'lnk'))
	os.setxattr(os.path.join(monitor, 'd'), 'user.tag', b'folder')
	os.chmod(os.path.join(monitor, 'd', 'e'), 0o750)
	for folder in ('d/e', 'd', ''):
		os.utime(os.path.join(monitor, folder), ns=(T0, T0 + 7))


def small_batch1(monitor):
	put_text(monitor, 'b.txt', 'b1')
	return [(False, 'modify', 'b.txt', None)]


def small_batch2(monitor):
	put_text(monitor, 'd/c.txt', 'c2')
	return [(False, 'modify', 'd/c.txt', None)]


SMALL = [small_seed, small_batch1, small_batch2]


@pytest.fixture
def small(tmp_path, v054):
	'''A 0.54 vault of V0 whole and V1, V2 of chain links.'''
	job = create_job(str(tmp_path))
	v054.build(job, SMALL, keep_n_versions=9)
	return job


@pytest.fixture
def every_item(tmp_path, v054):
	job = create_job(str(tmp_path))
	v054.build(job, EVERY_ITEM, keep_n_versions=KEEP)
	return job


def folders_of(job):
	'''{version number: folder name}, the oldest first.'''
	return dict(sorted((version_number(name), name) for name in committed_folders(job.job_vault)))


def views(job):
	return {name: read_view(job.job_vault, name) for name in folders_of(job).values()}


def expected(job):
	'''views(), by number, as check_vault() takes them.'''
	return {number: read_view(job.job_vault, name) for number, name in folders_of(job).items()}


def walk_cli(job_vault, number, rel, backward):
	return rv.read_walked(job_vault, number, rel, rv.VaultReading(backward, None, None))


def cli_differences(job_vault, wanted):
	'''
	What the commands read differently from wanted, {version number: view}: each path by read_walked(), each version listed
	by iter_version_entries(), on the layout as a command reads it.
	'''
	backward = rv.read_vault_layout_for_command(job_vault) != 'r'
	lines = []
	for number, view in wanted.items():
		listed = {rel for rel, walked in rv.iter_version_entries(job_vault, number, '', backward) if rel}
		if listed != set(view) - {''}:
			lines.append(f'V{number} lists {sorted(listed ^ (set(view) - {""}))} apart from the oracle')
		for rel, entry in view.items():
			if not rel:
				continue
			walked = walk_cli(job_vault, number, rel, backward)
			if walked.kind not in ('file', 'folder', 'symlink'):
				lines.append(f'V{number}:{rel!r}: the commands read {walked.kind}')
			elif entry_view(walked.path) != entry:
				lines.append(f'V{number}:{rel!r}: the commands read {entry_view(walked.path)}, the oracle {entry}')
	return lines


def migrate(job, stop=None):
	'''The conversion as a first start runs it: the scan, then the migration when the layout says it is not done. Its answer.'''
	manifest = rv.VaultManifest(job.job_vault)
	try:
		rv.get_vault_info(job.job_vault, manifest=manifest)
		return True if manifest.layout() == 'r' else rv.migrate_job_vault(job.job_vault, manifest, job.job_name, stop)
	finally:
		manifest.close()


def layout_of(job):
	manifest = rv.VaultManifest(job.job_vault)
	try:
		return manifest.layout()
	finally:
		manifest.close()


def plain_links(job):
	return {name: daemon_links(job.job_vault, name) for name in folders_of(job).values()}


def test_the_054_module_cannot_flush_the_disks(tmp_path, v054, monkeypatch):
	# a real syncfs would flush the live filesystem under /tmp: the stub on rv does not reach a second module
	module = v054.module
	assert module.__name__ == 'reverberator054' and module.__version__ == '0.54.1'
	assert module.sync_vault_filesystems is not rv.sync_vault_filesystems
	assert module.sync_vault_filesystems.__code__ is not rv.sync_vault_filesystems.__code__
	assert module.sync_vault_filesystems.__module__ == 'tests.legacy054'
	assert module.sync_vault_filesystems(str(tmp_path)) == {}
	with pytest.raises(AssertionError):
		module.syncfs_folder(str(tmp_path))
	flushed = []
	monkeypatch.setattr(module, 'sync_vault_filesystems', lambda job_vault: flushed.append(job_vault) or {})
	job = create_job(str(tmp_path))
	v054.build(job, SMALL, keep_n_versions=2)
	# the prune of a build syncs through the stub, and syncfs_folder() would have failed the build
	assert set(flushed) <= {job.job_vault}


def test_a_built_vault_is_a_real_054_vault(small):
	names = folders_of(small)
	assert sorted(names) == [0, 1, 2]
	assert os.readlink(os.path.join(small.job_vault, names[2], 'a.txt')).startswith('../V1--')
	assert not os.path.islink(os.path.join(small.job_vault, names[2], 'd/c.txt'))
	assert layout_of(small) is None
	assert not os.path.lexists(rv.staging_path(small.job_vault))


def test_every_version_reads_the_same_after_conversion(every_item):
	before = expected(every_item)
	versions = folders_of(every_item)
	assert sorted(versions) == [1, 2, 3, 4]
	times = {name: os.lstat(os.path.join(every_item.job_vault, name)) for name in versions.values()}
	assert migrate(every_item) is True
	assert folders_of(every_item) == versions
	assert expected(every_item) == before
	assert check_vault(every_item.job_vault, before, set()) == []
	assert cli_differences(every_item.job_vault, before) == []
	for name, st in times.items():
		now = os.lstat(os.path.join(every_item.job_vault, name))
		assert (now.st_mtime_ns, now.st_mode, now.st_uid, now.st_gid) == (st.st_mtime_ns, st.st_mode, st.st_uid, st.st_gid)
	assert os.listdir(rv.staging_path(every_item.job_vault)) == []
	assert layout_of(every_item) == 'r'


def test_a_converted_version_holds_no_chain_link(every_item):
	assert any(plain_links(every_item).values())
	assert migrate(every_item) is True
	assert not any(plain_links(every_item).values())
	manifest = rv.VaultManifest(every_item.job_vault)
	assert manifest.migrated() == set(folders_of(every_item).values())
	manifest.close()


def test_the_files_of_a_converted_version_are_the_same_inodes(small):
	before, after = {}, {}
	for number, name in folders_of(small).items():
		before[number] = {}
		read_view(small.job_vault, name, before[number])
	assert migrate(small) is True
	for number, name in folders_of(small).items():
		after[number] = {}
		read_view(small.job_vault, name, after[number])
	assert after == before


def test_the_oldest_whole_version_is_left_alone(every_item):
	oldest = os.path.join(every_item.job_vault, next(iter(folders_of(every_item).values())))
	assert daemon_links(every_item.job_vault, os.path.basename(oldest)) == []
	inode = os.lstat(oldest).st_ino
	inner = {rel: os.lstat(os.path.join(oldest, rel)).st_ino for rel in ('a', 'a/sub', 'g/h')}
	assert migrate(every_item) is True
	assert os.lstat(oldest).st_ino == inode
	assert {rel: os.lstat(os.path.join(oldest, rel)).st_ino for rel in inner} == inner


def test_a_version_left_whole_gets_its_line_too(small):
	lines = []
	real = rv.backuperTeeLogToTl
	rv.backuperTeeLogToTl = lambda *args, **kwargs: (lines.append(args[1] if len(args) > 1 else kwargs.get('message')), real(*args, **kwargs))[1]
	try:
		assert migrate(small) is True
	finally:
		rv.backuperTeeLogToTl = real
	assert [line for line in lines if line.startswith('Converting ')] == ['Converting job vault: V2 (1 of 3)', 'Converting job vault: V1 (2 of 3)', 'Converting job vault: V0 (3 of 3)']


def test_a_dangling_chain_stays_the_link(small):
	names = folders_of(small)
	# the end of a's chain, gone by hand
	os.remove(os.path.join(small.job_vault, names[0], 'a.txt'))
	texts = {number: os.readlink(os.path.join(small.job_vault, names[number], 'a.txt')) for number in (1, 2)}
	assert rv.walk_version(small.job_vault, 2, 'a.txt', True).kind == 'dangling'
	before = expected(small)
	assert before[2]['a.txt'].kind == 'dangling'
	assert migrate(small) is True
	for number, text in texts.items():
		assert os.readlink(os.path.join(small.job_vault, names[number], 'a.txt')) == text
	# as a user's link from now on: the backward rule ended with the layout, and a restore gives the link
	after = expected(small)
	for number, text in texts.items():
		assert (after[number]['a.txt'].kind, after[number]['a.txt'].data) == ('l', text)
		after[number]['a.txt'] = before[number]['a.txt']
	assert after == before
	assert rv.walk_version(small.job_vault, 2, 'a.txt', False).kind == 'symlink'


def test_a_dangling_chain_is_logged_once_and_a_users_own_link_is_not(small):
	names = folders_of(small)
	os.remove(os.path.join(small.job_vault, names[0], 'a.txt'))
	# a user's own link that leads nowhere is no chain
	os.symlink('nowhere', os.path.join(small.job_vault, names[2], 'own'))
	lines = []
	real = rv.backuperTeeLogToTl
	rv.backuperTeeLogToTl = lambda *args, **kwargs: (lines.append((args[1] if len(args) > 1 else kwargs.get('message'), kwargs.get('error', False))), real(*args, **kwargs))[1]
	try:
		assert migrate(small) is True
	finally:
		rv.backuperTeeLogToTl = real
	dangling = [line for line, error in lines if error]
	assert len(dangling) == 2 and all('a.txt' in line for line in dangling)
	assert names[2] in dangling[0] and names[1] in dangling[1]


def long_rel(room):
	'''A relative path of exactly room bytes, in parts of 200.'''
	parts = []
	while room > 201:
		parts.append('d' * 200)
		room -= 201
	parts.append('f' * room)
	return '/'.join(parts)


def put_long(root, rel, text):
	'''A file at a path too long to name at once, made a folder at a time.'''
	fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
	parts = rel.split('/')
	for part in parts[:-1]:
		try:
			os.mkdir(part, dir_fd=fd)
		except FileExistsError:
			pass
		below = os.open(part, os.O_RDONLY | os.O_DIRECTORY, dir_fd=fd)
		os.close(fd)
		fd = below
	file_fd = os.open(parts[-1], os.O_WRONLY | os.O_CREAT, 0o644, dir_fd=fd)
	os.write(file_fd, text.encode())
	os.close(file_fd)
	os.close(fd)


@pytest.mark.parametrize('spare', [1, 12, 22])
def test_a_path_near_the_limit_converts(tmp_path, v054, spare):
	# the tree is built in staging, whose own name must not be longer than the version's: a path that fits in a version converts
	job = create_job(str(tmp_path))
	room = 4095 - len(os.path.join(job.job_vault, 'V0--2026-11-06_04-58-06_-0800', '')) - spare
	rel = long_rel(room)
	def seed(monitor):
		put_long(monitor, rel, 'long')

	def add(monitor):
		put_text(monitor, 'z', 'z')
		return [(False, 'create', 'z', None)]

	def change(monitor):
		put_text(monitor, 'z', 'z2')
		return [(False, 'modify', 'z', None)]
	v054.build(job, [seed, add, change], keep_n_versions=5)
	names = folders_of(job)
	newest = os.path.join(job.job_vault, names[max(names)], rel)
	assert 4072 <= len(newest) <= 4094 and os.path.islink(newest)
	before = expected(job)
	assert migrate(job) is True
	assert not os.path.islink(newest) and open(newest).read() == 'long'
	assert layout_of(job) == 'r'
	assert expected(job) == before
	assert cli_differences(job.job_vault, before) == []


def test_a_version_counts_as_done_only_after_a_flush_of_its_folder_time(small, monkeypatch):
	# including one that needs no plain tree (V0, or one a repair finished): its folder's time is set, and a second cut must not lose it
	# for a version the manifest calls done
	events = []
	real_utime, real_flush, real_add = os.utime, rv.flush_vault_disks, rv.VaultManifest.add_migrated
	def utime(path, *args, **kwargs):
		events.append(('utime', os.path.basename(path)))
		return real_utime(path, *args, **kwargs)
	monkeypatch.setattr(os, 'utime', utime)
	monkeypatch.setattr(rv, 'flush_vault_disks', lambda job_vault, job_name: events.append('flush') or real_flush(job_vault, job_name))
	monkeypatch.setattr(rv.VaultManifest, 'add_migrated', lambda self, name: events.append(('done', name)) or real_add(self, name))
	assert migrate(small) is True
	done = [number for number, event in enumerate(events) if isinstance(event, tuple) and event[0] == 'done']
	assert len(done) == 3
	for number in done:
		assert events[number - 1] == 'flush' and events[number - 2] == ('utime', events[number][1])


def test_folders_moved_aside_and_put_back_still_read_as_converting(small, tmp_path):
	# a conversion begun, the version folders moved away for a look, a start, and the folders put back: the layout stays unset, so
	# the conversion goes on and reads them as 0.54 trees (a scan that set 'r' while they were away would read their links as R's)
	before = expected(small)
	manifest = rv.VaultManifest(small.job_vault)
	rv.get_vault_info(small.job_vault, manifest=manifest)
	assert rv.migrate_job_vault(small.job_vault, manifest, small.job_name, lambda: True) is False
	assert manifest.conversion_unfinished() and manifest.layout() is None
	manifest.close()
	away = tmp_path / 'away'
	away.mkdir()
	moved = [name for name in os.listdir(small.job_vault) if name.startswith('V') or name == 'current_version']
	assert moved
	for name in moved:
		os.rename(os.path.join(small.job_vault, name), away / name)
	rv.VAULTS_WITH_VERSIONS.clear()
	assert dict(rv.get_vault_info(small.job_vault).vault_info_dict) == {}
	for name in moved:
		os.rename(away / name, os.path.join(small.job_vault, name))
	rv.VAULTS_WITH_VERSIONS.clear()
	assert len(rv.get_vault_info(small.job_vault).vault_info_dict) == 3
	assert layout_of(small) is None
	manifest = rv.VaultManifest(small.job_vault)
	try:
		assert rv.vault_layout(small.job_vault, manifest) == 'converting'
	finally:
		manifest.close()
	assert migrate(small) is True
	assert layout_of(small) == 'r'
	assert expected(small) == before


def test_a_prune_temp_is_left_out(small):
	names = folders_of(small)
	top = os.path.join(small.job_vault, names[2])
	end = os.path.realpath(os.path.join(top, 'a.txt'))
	temp = f'.{"a" * 32}{rv.PARTIAL_COPY_SUFFIX}'
	mine = f'.{"b" * 32}{rv.PARTIAL_COPY_SUFFIX}'
	os.link(end, os.path.join(top, temp))
	with open(os.path.join(top, mine), 'w') as f:
		f.write("a user's file of that form")
	before = expected(small)
	del before[2][temp]
	assert migrate(small) is True
	assert not os.path.lexists(os.path.join(top, temp))
	assert os.path.lexists(os.path.join(top, mine))
	assert expected(small) == before


def test_a_prune_temp_beside_a_copy_makes_a_version_with_no_chain_link_go_through(small):
	# what a cut on a pool leaves: the copy in the link's place, the temp on another disk
	names = folders_of(small)
	top = os.path.join(small.job_vault, names[0])
	temp = f'.{"a" * 32}{rv.PARTIAL_COPY_SUFFIX}'
	os.link(os.path.join(top, 'a.txt'), os.path.join(top, temp))
	before = expected(small)
	del before[0][temp]
	assert migrate(small) is True
	assert not os.path.lexists(os.path.join(top, temp))
	assert expected(small) == before


def test_a_users_link_with_chain_text_is_judged_by_text(small):
	# the accepted limitation: a user's link whose text is exactly a chain link's, naming a file, becomes that file
	names = folders_of(small)
	top = os.path.join(small.job_vault, names[2])
	to_a_file = f'../{names[1]}/b.txt'
	to_a_folder = f'../{names[1]}/d'
	to_nothing = f'../{names[1]}/nothing'
	for name, text in (('mine_file', to_a_file), ('mine_folder', to_a_folder), ('mine_nothing', to_nothing)):
		os.symlink(text, os.path.join(top, name))
	b_of_1 = read_view(small.job_vault, names[1])['b.txt']
	assert migrate(small) is True
	assert not os.path.islink(os.path.join(top, 'mine_file'))
	assert entry_view(os.path.join(top, 'mine_file')) == b_of_1
	# one naming a folder or nothing was a user's link all along
	assert os.readlink(os.path.join(top, 'mine_folder')) == to_a_folder
	assert os.readlink(os.path.join(top, 'mine_nothing')) == to_nothing


def test_a_file_at_its_hard_link_limit_is_copied(small, monkeypatch):
	before = expected(small)
	names = folders_of(small)
	real_link = os.link
	refused = []
	def link(source, dest, **kwargs):
		if os.path.basename(dest) == 'f.txt':
			refused.append(dest)
			raise OSError(errno.EMLINK, os.strerror(errno.EMLINK), source)
		return real_link(source, dest, **kwargs)
	monkeypatch.setattr(os, 'link', link)
	assert migrate(small) is True
	assert len(refused) == 2
	assert expected(small) == before
	inodes = {os.lstat(os.path.join(small.job_vault, names[number], 'd/e/f.txt')).st_ino for number in names}
	assert len(inodes) == 3


def test_a_link_that_fails_leaves_the_version_as_it_was(small, monkeypatch):
	before = expected(small)
	def failing(*args, **kwargs):
		raise OSError(errno.EIO, os.strerror(errno.EIO))
	with monkeypatch.context() as context:
		context.setattr(os, 'link', failing)
		with pytest.raises(OSError):
			migrate(small)
	assert expected(small) == before
	assert migrate(small) is True
	assert expected(small) == before


def test_a_copy_that_fails_leaves_the_version_as_it_was(small, monkeypatch):
	before = expected(small)
	def refused(*args, **kwargs):
		raise OSError(errno.EMLINK, os.strerror(errno.EMLINK))
	monkeypatch.setattr(os, 'link', refused)
	monkeypatch.setattr(rv, 'copy_command', lambda source, dest: ['false'])
	with pytest.raises(rv.JobFailure):
		migrate(small)
	assert expected(small) == before


def test_a_folder_whose_metadata_cannot_be_kept_stops_the_version(small, monkeypatch):
	before = expected(small)
	def losing(source, dest, st, failed):
		failed.append(source)
		return False
	monkeypatch.setattr(rv, 'copy_new_folder_meta', losing)
	with pytest.raises(rv.JobFailure):
		migrate(small)
	assert expected(small) == before
	assert any(plain_links(small).values())


def test_folders_keep_their_metadata_and_the_root_its_record(small):
	names = folders_of(small)
	newest = os.path.join(small.job_vault, names[2])
	record = os.getxattr(newest, rv.ROOT_META_XATTR)
	st = os.lstat(os.path.join(newest, 'd', 'e'))
	assert migrate(small) is True
	assert os.getxattr(newest, rv.ROOT_META_XATTR) == record
	assert os.getxattr(os.path.join(newest, 'd'), 'user.tag') == b'folder'
	now = os.lstat(os.path.join(newest, 'd', 'e'))
	assert (now.st_mode, now.st_mtime_ns, now.st_uid) == (st.st_mode, st.st_mtime_ns, st.st_uid)


def rows_of(job):
	conn = sqlite3.connect(os.path.join(job.job_vault, rv.MANIFEST_FILE_NAME))
	try:
		return conn.execute('SELECT * FROM entries ORDER BY path').fetchall()
	finally:
		conn.close()


def test_the_rows_still_describe_the_newest(small):
	rows = rows_of(small)
	names = folders_of(small)
	manifest = rv.VaultManifest(small.job_vault)
	matched = manifest.matched
	manifest.close()
	assert migrate(small) is True
	assert rows_of(small) == rows
	manifest = rv.VaultManifest(small.job_vault)
	assert manifest.describes(os.path.join(small.job_vault, names[2]))
	assert manifest.matched == matched
	manifest.close()
	checked = 0
	for rel, kind, size, mtime_ns, mode, uid, gid, _, link, *_ in rows:
		path = os.path.join(small.job_vault, names[2], rel)
		st = os.lstat(path)
		if kind == 'f':
			assert (size, mtime_ns, mode, uid, gid) == (st.st_size, st.st_mtime_ns, st.st_mode, st.st_uid, st.st_gid)
			checked += 1
		elif kind == 'l':
			assert link == os.readlink(path)
	assert checked >= 4
	# nothing differs: a whole comparison of the vault would make no version, and needs no row read again
	_, manifest, committed = rv.do_backup(OrderedDict(), job_name=small.job_name, monitor_path=small.monitor, vault_path=small.vault, only_sync_attributes=False, keep_n_versions=9, backup_size_limit='0')
	manifest.close()
	assert committed is True
	assert folders_of(small) == names


def lists_of(job):
	return sorted(name for name in os.listdir(job.job_vault) if name.endswith(rv.CONTENT_FILE_EXTENSION_NAME))


def test_sizes_pass_equals_newest_holder(every_item):
	assert migrate(every_item) is True
	assert wrong_lists(every_item.job_vault) == []
	sizes = sizes_by_newest_holder(every_item.job_vault)
	entries = rv.read_job_vault(every_item.job_vault).versions
	for number, (size, inodes) in sizes.items():
		assert entries[number].inode == inodes
		# as a list's name rounds it
		assert entries[number].size == pytest.approx(size, rel=0.01)


def test_sizes_pass_on_hand_made_sharing_counts_each_inode_in_the_newest_holder(small):
	assert migrate(small) is True
	names = folders_of(small)
	# a file only the oldest holds, and a file two versions share
	with open(os.path.join(small.job_vault, names[0], 'only'), 'w') as f:
		f.write('x' * 5000)
	with open(os.path.join(small.job_vault, names[1], 'shared'), 'w') as f:
		f.write('y' * 300)
	os.link(os.path.join(small.job_vault, names[1], 'shared'), os.path.join(small.job_vault, names[0], 'shared'))
	manifest = rv.VaultManifest(small.job_vault)
	rv.sizes_pass(small.job_vault)
	manifest.close()
	assert wrong_lists(small.job_vault) == []


def test_sizes_pass_twice_changes_nothing(small, monkeypatch):
	assert migrate(small) is True
	lists = lists_of(small)
	times = {name: os.lstat(os.path.join(small.job_vault, name)).st_mtime_ns for name in lists}
	renames = []
	real = os.rename
	monkeypatch.setattr(os, 'rename', lambda *args, **kwargs: (renames.append(args), real(*args, **kwargs))[1])
	manifest = rv.VaultManifest(small.job_vault)
	rv.sizes_pass(small.job_vault)
	manifest.close()
	assert renames == []
	assert lists_of(small) == lists
	assert {name: os.lstat(os.path.join(small.job_vault, name)).st_mtime_ns for name in lists} == times


def test_the_salt_and_the_marker_go_after_the_layout(small):
	job_vault = small.job_vault
	for name in (SALT, MARKER):
		with open(os.path.join(job_vault, name), 'w') as f:
			f.write('x')
	real = rv.VaultManifest.set_layout
	seen = []
	def set_layout(self, value):
		seen.append([os.path.lexists(os.path.join(job_vault, name)) for name in (SALT, MARKER)])
		return real(self, value)
	rv.VaultManifest.set_layout = set_layout
	try:
		assert migrate(small) is True
	finally:
		rv.VaultManifest.set_layout = real
	assert seen == [[True, True]]
	assert [name for name in (SALT, MARKER) if os.path.lexists(os.path.join(job_vault, name))] == []


def test_a_cut_after_the_layout_leaves_the_salt_to_the_next_scan(small):
	job_vault = small.job_vault
	assert migrate(small) is True
	for name in (SALT, MARKER):
		with open(os.path.join(job_vault, name), 'w') as f:
			f.write('x')
	# 0.54 rules long over, and nothing reads them: the scan of an R vault takes them
	assert migrate(small) is True
	assert [name for name in (SALT, MARKER) if os.path.lexists(os.path.join(job_vault, name))] == []


def prepared_vault(tmp_path_factory, v054):
	'''The EVERY_ITEM vault with a salt, built once by the first test wanting it, and a copy to go back to: (job, template, views by number).'''
	if 'job' not in PREPARED:
		root = str(tmp_path_factory.mktemp('migration'))
		job = create_job(root)
		v054.build(job, EVERY_ITEM, keep_n_versions=KEEP)
		with open(os.path.join(job.job_vault, SALT), 'wb') as f:
			f.write(b'0' * 16)
		template = os.path.join(root, 'template')
		subprocess.run(['cp', '-a', job.vault, template], check=True)
		PREPARED.update(job=job, template=template, before=expected(job), times=root_times(job))
	job = PREPARED['job']
	shutil.rmtree(job.vault)
	subprocess.run(['cp', '-a', PREPARED['template'], job.vault], check=True)
	return job, PREPARED['before']


def kill_points(total):
	if os.environ.get('REVERB_CRASH_FULL'):
		return list(range(1, total + 3))
	stride = max(1, total // DEFAULT_KILL_POINTS)
	return sorted({*range(1, total + 3, stride), total - 3, total - 2, total - 1, total, total + 1})


def steps_of(job):
	outcome = in_child(job, None, lambda: migrate(job))
	assert outcome.error is None and outcome.committed is True
	return outcome


def after_the_cut(job, before, point):
	'''What a cut conversion must show to every reader, its layout set only with every list right.'''
	wrong = []
	if recorded_design_r(job.job_vault):
		wrong += [f'the layout is set, but {line}' for line in wrong_lists(job.job_vault)]
	for number, name in folders_of(job).items():
		view = read_view(job.job_vault, name)
		if view != before[number]:
			wrong.append(f'V{number} reads differently from the oracle: {sorted(rel for rel in set(view) | set(before[number]) if view.get(rel) != before[number].get(rel))[:5]}')
	wrong += cli_differences(job.job_vault, before)
	return [f'kill at {point}: {line}' for line in wrong]


def root_times(job):
	'''{version folder name: its own mtime}, which no view holds.'''
	return {name: os.lstat(os.path.join(job.job_vault, name)).st_mtime_ns for name in folders_of(job).values()}


def moving_the_mtime(module):
	'''An exchange as f2fs makes it: the folder moved across folders gets a new mtime, as its .. changes. ext4, under the tests, keeps it.'''
	real = module.rename_exchange
	def exchange(a, b):
		real(a, b)
		os.utime(b)
	module.rename_exchange = exchange


def after_the_resume(job, before, times, point):
	wrong = check_vault(job.job_vault, before, set())
	if root_times(job) != times:
		wrong.append('a version folder has another mtime')
	wrong += cli_differences(job.job_vault, before)
	wrong += wrong_lists(job.job_vault)
	if not recorded_design_r(job.job_vault):
		wrong.append('no layout')
	if any(plain_links(job).values()):
		wrong.append('a chain link is left')
	if os.path.lexists(os.path.join(job.job_vault, SALT)):
		wrong.append('the salt is left')
	return [f'kill at {point}, resumed: {line}' for line in wrong]


def test_the_kill_sweep_covers_every_kind_of_step(tmp_path_factory, v054):
	job, _ = prepared_vault(tmp_path_factory, v054)
	counts = steps_of(job).counts
	for kind in ('mkdir', 'link', 'exchange', 'rename', 'commit', 'Popen', 'remove', 'utime'):
		assert counts.get(kind), f'no {kind} step in {counts}'


def test_a_kill_at_every_step_resumes_exact(tmp_path_factory, v054):
	job, before = prepared_vault(tmp_path_factory, v054)
	total = in_child(job, None, lambda: migrate(job), moving_the_mtime).steps
	assert total > 100
	wrong = []
	for point in kill_points(total):
		job, _ = prepared_vault(tmp_path_factory, v054)
		outcome = in_child(job, point, lambda: migrate(job), moving_the_mtime)
		assert outcome.error is None, outcome.error
		assert outcome.killed or point > total
		wrong += after_the_cut(job, before, point)
		resumed = in_child(job, None, lambda: migrate(job), moving_the_mtime)
		assert resumed.error is None and resumed.committed is True, resumed.error
		wrong += after_the_resume(job, before, PREPARED['times'], point)
	print(f'migration kill sweep: {len(kill_points(total))} of {total} steps run, {len(wrong)} wrong')
	assert wrong == []


def test_a_kill_during_the_resume_is_safe(tmp_path_factory, v054):
	job, before = prepared_vault(tmp_path_factory, v054)
	total = steps_of(job).steps
	pick = random.Random(20)
	wrong = []
	for _ in range(int(os.environ.get('REVERB_CRASH_DOUBLE', 25))):
		job, _ = prepared_vault(tmp_path_factory, v054)
		point = pick.randrange(1, total)
		first = in_child(job, point, lambda: migrate(job), moving_the_mtime)
		assert first.error is None and first.killed
		again = pick.randrange(1, total)
		second = in_child(job, again, lambda: migrate(job), moving_the_mtime)
		assert second.error is None, second.error
		wrong += after_the_cut(job, before, (point, again))
		last = in_child(job, None, lambda: migrate(job), moving_the_mtime)
		assert last.error is None and last.committed is True, last.error
		wrong += after_the_resume(job, before, PREPARED['times'], (point, again))
	assert wrong == []


def failing_rename_after(count):
	'''os.rename, failing as a disk would from the count-th rename of a change list on.'''
	real = os.rename
	seen = []
	def rename(source, dest, **kwargs):
		if os.fsdecode(dest).endswith(rv.CONTENT_FILE_EXTENSION_NAME):
			seen.append(dest)
			if len(seen) >= count:
				raise OSError(errno.EIO, os.strerror(errno.EIO), dest)
		return real(source, dest, **kwargs)
	return rename


def a_batch_is_refused(job):
	'''Whether a batch that would also prune fails its attempt, with the vault as it was.'''
	before = views(job)
	lists = lists_of(job)
	put_text(job.monitor, 'b.txt', 'a change')
	with pytest.raises(rv.JobFailure):
		rv.do_backup(OrderedDict(), job_name=job.job_name, monitor_path=job.monitor, vault_path=job.vault, only_sync_attributes=False, keep_n_versions=2, backup_size_limit='1')
	assert views(job) == before
	assert lists_of(job) == lists
	return True


def test_no_backup_or_prune_before_the_sizes_pass_ends(small, monkeypatch):
	# a stop between two versions: the newest is plain, the older still of links
	names = folders_of(small)
	assert migrate(small, lambda: not daemon_links(small.job_vault, names[2])) is False
	assert daemon_links(small.job_vault, names[1]) != []
	assert layout_of(small) is None
	assert a_batch_is_refused(small)
	# the sizes pass failing half way
	with monkeypatch.context() as context:
		context.setattr(os, 'rename', failing_rename_after(2))
		with pytest.raises(OSError):
			migrate(small)
	assert layout_of(small) is None
	assert a_batch_is_refused(small)
	assert migrate(small) is True
	assert layout_of(small) == 'r'
	assert wrong_lists(small.job_vault) == []


def test_the_conversion_runs_no_batch_of_its_own(small, monkeypatch):
	def refused(*args, **kwargs):
		raise AssertionError('a backup or a prune during the conversion')
	for name in ('do_backup', 'do_reverb_backup', 'prune_oldest', 'decrement_stepper', 'hand_over'):
		monkeypatch.setattr(rv, name, refused)
	assert migrate(small) is True


def test_a_vault_with_a_lost_manifest_is_no_conversion_to_refuse(tmp_path):
	# only a vault whose manifest says a conversion began waits for it: the scan and the roll-forward read one whose manifest is lost
	job = create_job(str(tmp_path))
	os.makedirs(job.job_vault)
	put_text(job.monitor, 'a.txt', 'a')
	_, manifest, committed = rv.do_backup(OrderedDict(), job_name=job.job_name, monitor_path=job.monitor, vault_path=job.vault, only_sync_attributes=False, keep_n_versions=3, backup_size_limit='0')
	manifest.close()
	assert committed is True
	os.remove(os.path.join(job.job_vault, rv.MANIFEST_FILE_NAME))
	put_text(job.monitor, 'a.txt', 'b')
	_, manifest, committed = rv.do_backup(OrderedDict(), job_name=job.job_name, monitor_path=job.monitor, vault_path=job.vault, only_sync_attributes=False, keep_n_versions=3, backup_size_limit='0')
	manifest.close()
	assert committed is True


def run_options(keep):
	return dict(only_sync_attributes=False, keep_n_versions=keep, backup_size_limit='0')


def test_the_first_prune_after_conversion_keeps_the_others_exact(every_item):
	assert migrate(every_item) is True
	before = expected(every_item)
	oldest = min(before)
	put_text(every_item.monitor, 'b/w.txt', 'after')
	backup_events(every_item, [(False, 'modify', 'b/w.txt', None)], keep_n_versions=KEEP)
	now = expected(every_item)
	assert sorted(now) == sorted(before)[1:] + [max(before) + 1]
	for number in now:
		if number in before:
			assert now[number] == before[number]
	assert oldest not in now
	assert wrong_lists(every_item.job_vault) == []


def test_the_first_batch_after_conversion_is_exact(every_item):
	assert migrate(every_item) is True
	before = expected(every_item)
	monitor = every_item.monitor
	put_text(monitor, 'a/x.txt', 'after')
	put_text(monitor, 'new.txt', 'new')
	os.remove(os.path.join(monitor, 'g/moved.txt'))
	os.rename(os.path.join(monitor, 'y'), os.path.join(monitor, 'moved_y'))
	backup_events(every_item, [(False, 'modify', 'a/x.txt', None), (False, 'create', 'new.txt', None), (False, 'delete', 'g/moved.txt', None), (False, 'move', 'moved_y', 'y')], keep_n_versions=KEEP + 1)
	now = expected(every_item)
	assert sorted(now) == sorted(before) + [max(before) + 1]
	for number, view in before.items():
		assert now[number] == view
	newest = now[max(now)]
	held = snapshot_tree(monitor)
	for rel in ('a/x.txt', 'new.txt', 'moved_y'):
		assert newest[rel] == held[rel]
	assert 'g/moved.txt' not in newest and 'y' not in newest
	assert wrong_lists(every_item.job_vault) == []
	# the version before it now links forward: the newest is the real tree, and the conversion left no chain link to walk
	assert cli_differences(every_item.job_vault, before) == []


def test_a_stop_during_conversion_goes_on_at_the_next_start(small):
	before = expected(small)
	polls = []
	assert migrate(small, lambda: len(polls) > 3 or polls.append(1)) is False
	staging = rv.staging_path(small.job_vault)
	assert os.listdir(staging) == ['m']
	assert layout_of(small) is None
	assert expected(small) == before
	assert cli_differences(small.job_vault, before) == []
	assert migrate(small) is True
	assert check_vault(small.job_vault, before, set()) == []
	assert layout_of(small) == 'r'
	assert not any(plain_links(small).values())


def test_a_stop_at_the_start_changes_no_version(small):
	before = expected(small)
	assert migrate(small, lambda: True) is False
	assert expected(small) == before
	assert any(plain_links(small).values())
	assert migrate(small) is True


def test_a_resume_passes_over_a_version_already_done(small, monkeypatch):
	polls = []
	real = rv.materialize_version
	done = []
	def counted(job_vault, name, stop=None):
		done.append(name)
		return real(job_vault, name, stop)
	monkeypatch.setattr(rv, 'materialize_version', counted)
	# stops once the newest is plain
	assert migrate(small, lambda: len(done) > 1) is False
	assert len(done) == 2
	first = done[0]
	done.clear()
	assert migrate(small) is True
	assert first not in done


def test_the_staging_folder_is_on_the_disk_first(small, monkeypatch):
	# a vault that has staging never gets the 0.54 rules again, so staging comes before the first change of a version
	real = rv.fsync_vault_folder
	order = []
	monkeypatch.setattr(rv, 'fsync_vault_folder', lambda path: (order.append(('fsync', os.path.lexists(rv.staging_path(small.job_vault)))), real(path))[1])
	real_build = rv.materialize_version
	monkeypatch.setattr(rv, 'materialize_version', lambda *args: (order.append('build'), real_build(*args))[1])
	assert migrate(small) is True
	assert ('fsync', True) in order[:order.index('build')]


def test_each_version_is_flushed_before_it_counts_as_done(small, monkeypatch):
	# a power cut must not keep the manifest's word that a version is plain and lose its exchange: that version would never be converted
	order = []
	real_add = rv.VaultManifest.add_migrated
	monkeypatch.setattr(rv.VaultManifest, 'add_migrated', lambda self, name: (order.append(('done', name)), real_add(self, name))[1])
	real_exchange = rv.rename_exchange
	monkeypatch.setattr(rv, 'rename_exchange', lambda a, b: (order.append(('exchange', os.path.basename(b))), real_exchange(a, b))[1])
	monkeypatch.setattr(rv, 'sync_vault_filesystems', lambda job_vault, job_name: order.append('flush') or {})
	assert migrate(small) is True
	for number, name in folders_of(small).items():
		if ('exchange', name) in order:
			assert order.index(('exchange', name)) < order.index('flush', order.index(('exchange', name))) < order.index(('done', name))


def test_a_flush_that_fails_stops_the_conversion(small, monkeypatch):
	monkeypatch.setattr(rv, 'sync_vault_filesystems', lambda job_vault, job_name: {'/dev/fake': OSError(errno.EIO, 'input/output error')})
	with pytest.raises(rv.JobFailure):
		migrate(small)
	assert layout_of(small) is None


@needs_f2fs
def test_a_conversion_on_f2fs_uses_exchange_and_keeps_times(v054, monkeypatch):
	exchanges = []
	real = rv.rename_exchange
	monkeypatch.setattr(rv, 'rename_exchange', lambda a, b: (exchanges.append(os.path.basename(b)), real(a, b))[1])
	with f2fs_mount(os.path.join(SCRATCH, 'migration'), 256) as mount:
		job = create_job(mount)
		v054.build(job, EVERY_ITEM, keep_n_versions=KEEP)
		before = expected(job)
		names = folders_of(job)
		links = [name for name in names.values() if daemon_links(job.job_vault, name)]
		times = {name: [os.lstat(os.path.join(folder, entry)).st_mtime_ns for folder, folders, _ in os.walk(os.path.join(job.job_vault, name)) for entry in folders] for name in names.values()}
		roots = {name: os.lstat(os.path.join(job.job_vault, name)).st_mtime_ns for name in names.values()}
		assert migrate(job) is True
		assert sorted(exchanges) == sorted(links)
		assert expected(job) == before
		assert check_vault(job.job_vault, before, set()) == []
		assert cli_differences(job.job_vault, before) == []
		assert wrong_lists(job.job_vault) == []
		for name in names.values():
			assert sorted(os.lstat(os.path.join(folder, entry)).st_mtime_ns for folder, folders, _ in os.walk(os.path.join(job.job_vault, name)) for entry in folders) == sorted(times[name])
			assert os.lstat(os.path.join(job.job_vault, name)).st_mtime_ns == roots[name]
		# a batch and its prune on what was converted
		put_text(job.monitor, 'b/w.txt', 'after')
		backup_events(job, [(False, 'modify', 'b/w.txt', None)], keep_n_versions=KEEP)
		assert wrong_lists(job.job_vault) == []
		for number, view in expected(job).items():
			if number in before:
				assert view == before[number]


def flushing_for_real(module):
	'''A conversion's flushes reach the loop image, through the one helper: a stub would count a version done that a power loss loses.'''
	module.sync_vault_filesystems = lambda job_vault, *job_name: (flush_scratch(job_vault), {})[1]


@needs_f2fs
def test_a_power_loss_during_conversion_resumes_exact(v054):
	# at each step the filesystem stops with no checkpoint; every other point has one from half way, so that state is what comes back
	with LoopImage(os.path.join(SCRATCH, 'migration-power-loss'), 512) as image:
		root = tempfile.mkdtemp(prefix='reverb-migration-', dir=image.mount_point)
		job = create_job(root)
		v054.build(job, EVERY_ITEM, keep_n_versions=KEEP)
		before = expected(job)
		template = os.path.join(root, 'template')
		subprocess.run(['cp', '-a', job.vault, template], check=True)
		times = root_times(job)
		def fresh():
			shutil.rmtree(job.vault)
			subprocess.run(['cp', '-a', template, job.vault], check=True)
			flush_scratch(root)
		fresh()
		total = in_child(job, None, lambda: migrate(job), flushing_for_real).steps
		wrong = []
		for index, point in enumerate(kill_points(total)):
			fresh()
			flush_at = (max(1, point // 2), lambda: flush_scratch(root)) if index % 2 else None
			cut = in_child(job, point, lambda: migrate(job), flushing_for_real, lambda: shut_down_scratch(image.mount_point), flush_at)
			assert cut.error is None, f'kill at {point} of {total}: {cut.error}'
			if not cut.killed:
				shut_down_scratch(image.mount_point)
			image.remount()
			wrong += after_the_cut(job, before, point)
			again = in_child(job, None, lambda: migrate(job), flushing_for_real)
			assert again.error is None and again.committed is True, f'resuming from {point} of {total}: {again.error}'
			wrong += after_the_resume(job, before, times, point)
		assert wrong == []
