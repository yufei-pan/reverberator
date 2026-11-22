'''
0.55.6 (spec section 5, D4): an entry whose path in the vault Linux would refuse (more than PATH_LIMIT, 4,095 bytes), or whose copy's
temporary path would (its folder's path plus PARTIAL_COPY_EXTRA, so a folder of 4,041 bytes and more), is left out of the version
before anything is written, with one NOT BACKED UP line a batch, and the rest of the batch is backed up; a folder left out takes all under
it. A delete of an entry the version already holds past the limit (V9's 4,095 bytes are V10's 4,096) leaves it there, with its line, and a
batch whose every entry is left out makes no version.

The vault stays short, as SQLite opens no database at a path of more than 512 bytes: the monitored tree is deep instead, in names of 200
bytes (deep_folder()), so an entry reaches the limit in the vault, whose version folder's path is 32 bytes longer than the monitored
root's, while its monitored path stays under it.
'''
import datetime
import os
from collections import OrderedDict, deque

import pytest

import reverberator as rv
from tests import version_view_ground_truth as view_truth
from tests.harness import committed_versions, event_entry, header_counter, run_backup, seed_monitor

pytestmark = pytest.mark.unit

TOO_LONG = 'its path in the vault would be longer than Linux takes (4,095 bytes); '
LEFT_OUT = TOO_LONG + 'left out of this version'
KEPT = TOO_LONG + 'this version keeps it'


@pytest.fixture(autouse=True)
def _fast(poll_fast):
	return poll_fast


def version_bytes(job, number=0):
	'''The length in bytes of the path of the job's version folder of number, whose timestamp has a fixed width.'''
	stamp = datetime.datetime.now().astimezone().strftime(rv.VAULT_TIMESTAMP_FORMAT)
	return len(os.fsencode(os.path.join(job.job_vault, f'V{number}--{stamp}')))


def deep_folder(job, length, number=0, name='d'):
	'''A monitored folder, made, of names of 200 bytes and a last one of up to 201, whose path in the job's version number is length bytes.'''
	room = length - version_bytes(job, number) - 1
	parts = []
	while room > 201:
		parts.append(name * 200)
		room -= 201
	parts.append(name * room)
	folder = os.path.join(job.monitor, *parts)
	os.makedirs(folder)
	assert version_bytes(job, number) + len(os.fsencode(folder)) - len(os.fsencode(job.monitor)) == length
	return folder


def rel_of(job, path):
	return os.path.relpath(path, job.monitor)


def backup(job, *entries, **options):
	return run_backup(job, OrderedDict(event_entry(job, *entry) for entry in entries), **options)


def listed(version, job, folder):
	'''The names the version holds in the folder of the monitored folder's place, listed through a handle, as a path past the limit names nothing.'''
	fd = os.open(os.path.join(version, rel_of(job, folder)), os.O_RDONLY | os.O_DIRECTORY)
	try:
		return sorted(os.listdir(fd))
	finally:
		os.close(fd)


def read_in(version, job, folder, name):
	'''The text of the file name the version holds in the folder of the monitored folder's place, read through the folder's handle.'''
	fd = os.open(os.path.join(version, rel_of(job, folder)), os.O_RDONLY | os.O_DIRECTORY)
	try:
		file_fd = os.open(name, os.O_RDONLY, dir_fd=fd)
		try:
			return os.read(file_fd, 1 << 16).decode()
		finally:
			os.close(file_fd)
	finally:
		os.close(fd)


def read(path):
	with open(path, encoding='utf-8') as f:
		return f.read()


def write(path, content):
	with open(path, 'w', encoding='utf-8') as f:
		f.write(content)


def not_backed_up(capsys):
	'''{path: [the rest of each NOT BACKED UP line of it]} of what was logged since the last read.'''
	out = capsys.readouterr()
	found = {}
	for line in (out.out + out.err).splitlines():
		if 'NOT BACKED UP: ' in line:
			path, _, rest = line.split('NOT BACKED UP: ', 1)[1].partition(': ')
			found.setdefault(path, []).append(rest)
	return found


def tracked(job, rel):
	manifest = rv.VaultManifest(job.job_vault)
	try:
		return manifest.lookup(rel) is not None
	finally:
		manifest.close()


def test_a_link_whose_vault_path_is_4096_bytes_is_left_out_and_the_batch_commits(job, capsys):
	# fails on main: "JobFailure: recording ... failed: [Errno 36] File name too long", at every attempt
	seed_monitor(job, {'a': 'a'})
	folder = deep_folder(job, 4000)
	run_backup(job)
	link = os.path.join(folder, 'l' * 95)
	os.symlink('target', link)
	write(os.path.join(job.monitor, 'a'), 'a2')
	capsys.readouterr()
	versions = backup(job, ('a', 'modify'), (rel_of(job, link), 'create'))
	assert len(versions) == 2 and read(os.path.join(versions[-1], 'a')) == 'a2'
	assert listed(versions[-1], job, folder) == [] and not tracked(job, rel_of(job, link))
	assert not_backed_up(capsys) == {link: [LEFT_OUT]}


def test_a_file_in_a_folder_whose_vault_path_is_4041_bytes_is_left_out(job, capsys):
	# fails on main: "JobFailure: copying ... into the vault failed: cp: cannot create regular file ...: File name too long". Its
	# attribute change later is left out too ( fails without the rule at the replay's attrib branch: its copy, as no record vouches )
	seed_monitor(job, {'a': 'a'})
	folder = deep_folder(job, 4041)
	run_backup(job)
	file = os.path.join(folder, 'f')
	write(file, 'f')
	write(os.path.join(job.monitor, 'a'), 'a2')
	capsys.readouterr()
	versions = backup(job, ('a', 'modify'), (rel_of(job, file), 'create'))
	assert len(versions) == 2 and read(os.path.join(versions[-1], 'a')) == 'a2'
	assert listed(versions[-1], job, folder) == [] and not tracked(job, rel_of(job, file))
	assert not_backed_up(capsys) == {file: [LEFT_OUT]}
	os.chmod(file, 0o600)
	write(os.path.join(job.monitor, 'a'), 'a3')
	versions = backup(job, ('a', 'modify'), (rel_of(job, file), 'attrib'))
	assert len(versions) == 3 and read(os.path.join(versions[-1], 'a')) == 'a3' and listed(versions[-1], job, folder) == []
	assert not_backed_up(capsys) == {file: [LEFT_OUT]}


def test_a_file_in_a_folder_at_4040_bytes_is_backed_up(job):
	# pin: its copy's temporary path is 4,095 bytes, which Linux takes
	seed_monitor(job, {'a': 'a'})
	folder = deep_folder(job, 4040)
	run_backup(job)
	file = os.path.join(folder, 'f')
	write(file, 'f')
	versions = backup(job, (rel_of(job, file), 'create'))
	assert len(versions) == 2 and read_in(versions[-1], job, folder, 'f') == 'f' and tracked(job, rel_of(job, file))


def test_a_first_version_leaves_both_out(job, capsys):
	# fails on main (no V0 ever: the link's copy is put in place at 4,096 bytes, the file's partial copy is refused): V0 commits without
	# them, one line each, and a folder past the limit is not walked into: one line for it, none for its file
	seed_monitor(job, {'a': 'a'})
	link_folder = deep_folder(job, 4000)
	link = os.path.join(link_folder, 'l' * 95)
	os.symlink('target', link)
	file_folder = deep_folder(job, 4041, name='e')
	file = os.path.join(file_folder, 'f')
	write(file, 'f')
	holder = deep_folder(job, 4000, name='g')
	past = os.path.join(holder, 'h' * 96)
	os.mkdir(past)
	write(os.path.join(past, 'x'), 'x')
	capsys.readouterr()
	versions = run_backup(job)
	assert len(versions) == 1 and read(os.path.join(versions[0], 'a')) == 'a'
	assert listed(versions[0], job, link_folder) == listed(versions[0], job, file_folder) == listed(versions[0], job, holder) == []
	assert not any(tracked(job, rel_of(job, path)) for path in (link, file)) and not tracked(job, rel_of(job, past) + '/')
	assert not_backed_up(capsys) == {link: [LEFT_OUT], file: [LEFT_OUT], past: [LEFT_OUT]}


@pytest.mark.parametrize('created', ['itself', 'in_a_new_folder'])
def test_a_folder_whose_vault_path_passes_the_limit_is_left_out_with_all_under_it(job, capsys, created):
	# fails on main: its folder made in the version at 4,097 bytes. Created itself (copy_path()'s rule) or in a new folder's copy walk
	# (the walk's: nothing under it copied, as under a folder that could not be made): none of it in the version, one line, for the folder
	seed_monitor(job, {'a': 'a'})
	holder = deep_folder(job, 4000)
	run_backup(job)
	if created == 'in_a_new_folder':
		top = os.path.join(holder, 'new')
		os.mkdir(top)
		write(os.path.join(top, 'kept'), 'k')
		past = os.path.join(top, 'h' * 92)
	else:
		past = os.path.join(holder, 'h' * 96)
	os.mkdir(past)
	write(os.path.join(past, 'x'), 'x')
	os.mkdir(os.path.join(past, 's'))
	write(os.path.join(past, 's', 'y'), 'y')
	write(os.path.join(job.monitor, 'a'), 'a2')
	capsys.readouterr()
	versions = backup(job, ('a', 'modify'), (rel_of(job, past if created == 'itself' else top) + '/', 'create'))
	assert len(versions) == 2 and read(os.path.join(versions[-1], 'a')) == 'a2'
	if created == 'itself':
		assert listed(versions[-1], job, holder) == []
	else:
		assert listed(versions[-1], job, holder) == ['new'] and listed(versions[-1], job, top) == ['kept']
		assert read_in(versions[-1], job, top, 'kept') == 'k'
	assert not tracked(job, rel_of(job, past) + '/') and not tracked(job, rel_of(job, os.path.join(past, 'x')))
	assert not_backed_up(capsys) == {past: [LEFT_OUT]}


@pytest.mark.parametrize('only', ['link', 'file', 'folder'])
def test_a_batch_of_only_an_entry_left_out_makes_no_version(job, capsys, only):
	# fails on main (fails the attempt): the check before the hand-over takes the rule first, with no syscall, and drops it with its line
	seed_monitor(job, {'a': 'a'})
	folder = deep_folder(job, 4041 if only == 'file' else 4000)
	versions = run_backup(job)
	if only == 'link':
		entry = os.path.join(folder, 'l' * 95)
		os.symlink('target', entry)
	elif only == 'file':
		entry = os.path.join(folder, 'f')
		write(entry, 'f')
	else:
		entry = os.path.join(folder, 'h' * 96)
		os.mkdir(entry)
		write(os.path.join(entry, 'x'), 'x')
	counter = header_counter(job.job_vault)
	capsys.readouterr()
	assert backup(job, (rel_of(job, entry) + ('/' if only == 'folder' else ''), 'create')) == versions
	assert header_counter(job.job_vault) == counter
	assert not_backed_up(capsys) == {entry: [LEFT_OUT]}


def test_a_full_comparison_meeting_only_an_entry_left_out_makes_no_version(job, capsys):
	# the comparison finds it untracked each time, and the check drops it with its line, once a batch
	seed_monitor(job, {'a': 'a'})
	folder = deep_folder(job, 4041)
	versions = run_backup(job)
	file = os.path.join(folder, 'f')
	# its folder's times kept, so the file is the only difference the comparison finds
	times = os.stat(folder)
	write(file, 'f')
	os.utime(folder, ns=(times.st_atime_ns, times.st_mtime_ns))
	capsys.readouterr()
	for _ in range(2):
		assert run_backup(job) == versions
		assert not_backed_up(capsys) == {file: [LEFT_OUT]}


def test_the_verification_of_a_batch_meets_what_it_left_out_and_logs_it_once(job, capsys):
	# fails on main ("JobFailure: recording ... failed: [Errno 36] File name too long"). As the daemon runs a batch: its touched scopes are
	# compared with the tree after the replay, which finds the entries left out untracked again: their fixes are left out by the same
	# rule, with no second line, and the batch commits the rest
	seed_monitor(job, {'a': 'a'})
	folder = deep_folder(job, 4000)
	run_backup(job)
	link = os.path.join(folder, 'l' * 95)
	os.symlink('target', link)
	past = os.path.join(folder, 'h' * 96)
	os.mkdir(past)
	write(os.path.join(past, 'x'), 'x')
	write(os.path.join(job.monitor, 'a'), 'a2')
	events = [rv.ChangeEvent(float(i), is_dir, event, path, None) for i, (event, path, is_dir) in
		enumerate([('modify', os.path.join(job.monitor, 'a'), False), ('create', link, False), ('create', past, True)])]
	capsys.readouterr()
	versions = run_backup(job, rv.change_events_to_backup_entries(deque(events), job.monitor), touched=rv.touched_scopes(events, job.monitor))
	assert len(versions) == 2 and read(os.path.join(versions[-1], 'a')) == 'a2' and listed(versions[-1], job, folder) == []
	assert not_backed_up(capsys) == {link: [LEFT_OUT], past: [LEFT_OUT]}

def test_a_move_to_a_path_past_the_limit_takes_its_source_out_and_leaves_it_out(job, capsys):
	# fails on main: "JobFailure: recording ... failed: [Errno 36] File name too long" at the rename's record of its target. A move one
	# of whose paths passes is replayed as the delete of its source and the copy to its target, each under the rule
	seed_monitor(job, {'a': 'a', 'x': 'x'})
	folder = deep_folder(job, 4000)
	run_backup(job)
	target = os.path.join(folder, 'm' * 95)
	os.rename(os.path.join(job.monitor, 'x'), target)
	capsys.readouterr()
	versions = backup(job, (rel_of(job, target), 'move', 'x'))
	assert len(versions) == 2 and not os.path.lexists(os.path.join(versions[-1], 'x')) and listed(versions[-1], job, folder) == []
	assert not tracked(job, 'x') and not tracked(job, rel_of(job, target))
	assert not_backed_up(capsys) == {target: [LEFT_OUT]}


@pytest.mark.parametrize('changed', ['nothing', 'mode'])
def test_a_file_moved_into_a_folder_at_4041_bytes_is_renamed_there(job, capsys, changed):
	# pin for 'nothing': a rename writes no temporary name, so its own path, which fits, is all the rule measures. With its mode changed
	# after the move, without Only Sync Attributes, the copy it would take is left out with its line ( fails without that: the copy's
	# temporary path passes the limit, "JobFailure: copying ... into the vault failed" ), and the version keeps the moved file
	seed_monitor(job, {'a': 'a', 'x': 'x'})
	folder = deep_folder(job, 4041)
	run_backup(job, only_sync_attributes=False)
	target = os.path.join(folder, 'r' * 20)
	os.rename(os.path.join(job.monitor, 'x'), target)
	if changed == 'mode':
		os.chmod(target, 0o600)
	capsys.readouterr()
	versions = backup(job, (rel_of(job, target), 'move', 'x'), only_sync_attributes=False)
	assert len(versions) == 2 and not os.path.lexists(os.path.join(versions[-1], 'x'))
	assert listed(versions[-1], job, folder) == ['r' * 20] and read_in(versions[-1], job, folder, 'r' * 20) == 'x' and tracked(job, rel_of(job, target))
	assert not_backed_up(capsys) == ({} if changed == 'nothing' else {target: [LEFT_OUT]})


def test_on_a_pool_nothing_left_out_is_recorded_before_the_batch(job, fake_pool, capsys):
	# fails without the rule in the records a pool's batch makes first ( pre_record() ): "JobFailure: recording in ... before the batch
	# writes ... failed: [Errno 36] File name too long", for the link and the move's target, before the replay asks the rule
	fake_pool.add(job.vault, ['a', 'b'])
	seed_monitor(job, {'a': 'a', 'x': 'x'})
	folder = deep_folder(job, 4000)
	run_backup(job)
	link = os.path.join(folder, 'l' * 95)
	os.symlink('target', link)
	target = os.path.join(folder, 'm' * 95)
	os.rename(os.path.join(job.monitor, 'x'), target)
	write(os.path.join(job.monitor, 'a'), 'a2')
	capsys.readouterr()
	versions = backup(job, ('a', 'modify'), (rel_of(job, link), 'create'), (rel_of(job, target), 'move', 'x'))
	assert len(versions) == 2 and read(os.path.join(versions[-1], 'a')) == 'a2' and not os.path.lexists(os.path.join(versions[-1], 'x'))
	assert listed(versions[-1], job, folder) == []
	assert not_backed_up(capsys) == {link: [LEFT_OUT], target: [LEFT_OUT]}


def held_at_4096_in_v10(job, monkeypatch):
	'''
	A file whose path in the vault is 4,095 bytes in V0 to V9 (a name of 100 bytes, so its copy's temporary path fits), then V10, made by a
	change elsewhere, where the same path is 4,096 bytes: (its folder, its monitored path). From V10 on the version view oracle is set
	aside: it reads each version by path, and V10 holds an entry no path names.
	'''
	seed_monitor(job, {'a': 'a'})
	folder = deep_folder(job, 4095 - 101)
	file = os.path.join(folder, 'f' * 100)
	write(file, 'kept')
	versions = run_backup(job)
	assert len(os.fsencode(os.path.join(versions[0], rel_of(job, file)))) == 4095
	for number in range(1, 10):
		write(os.path.join(job.monitor, 'a'), f'a{number}')
		versions = backup(job, ('a', 'modify'))
	monkeypatch.setattr(rv, 'do_backup', view_truth._wrapped)
	write(os.path.join(job.monitor, 'a'), 'a10')
	versions = backup(job, ('a', 'modify'))
	assert len(versions) == 11 and len(os.fsencode(os.path.join(versions[-1], rel_of(job, file)))) == 4096
	# the tree holds it as it is: the rule applies when it changes
	assert listed(versions[-1], job, folder) == ['f' * 100] and read_in(versions[-1], job, folder, 'f' * 100) == 'kept'
	return folder, file


def test_an_entry_at_4095_bytes_in_v9_stays_in_v10_and_its_delete_keeps_it(job, monkeypatch, capsys):
	# fails on main: "JobFailure: recording ... failed: [Errno 36] File name too long" at the delete's record. Alone, its delete makes no
	# version; beside a change, the version commits and still holds it; one line each time
	folder, file = held_at_4096_in_v10(job, monkeypatch)
	versions = committed_versions(job)
	os.remove(file)
	capsys.readouterr()
	assert backup(job, (rel_of(job, file), 'delete')) == versions
	assert not_backed_up(capsys) == {file: [KEPT]}
	assert listed(versions[-1], job, folder) == ['f' * 100] and tracked(job, rel_of(job, file))
	write(os.path.join(job.monitor, 'a'), 'a11')
	versions = backup(job, (rel_of(job, file), 'delete'), ('a', 'modify'))
	assert len(versions) == 12 and read(os.path.join(versions[-1], 'a')) == 'a11'
	assert listed(versions[-1], job, folder) == ['f' * 100] and read_in(versions[-1], job, folder, 'f' * 100) == 'kept'
	assert not_backed_up(capsys) == {file: [KEPT]}


def test_a_move_both_of_whose_paths_pass_the_limit_makes_no_version(job, monkeypatch, capsys):
	# fails on main ( "JobFailure: recording ... failed" ): its source's delete is left out, as the version keeps it, and its copy to the
	# target too, so the version is as it was: the check drops it, with a line for each path
	folder, file = held_at_4096_in_v10(job, monkeypatch)
	versions = committed_versions(job)
	moved = os.path.join(folder, 'g' * 100)
	os.rename(file, moved)
	capsys.readouterr()
	assert backup(job, (rel_of(job, moved), 'move', rel_of(job, file))) == versions
	assert not_backed_up(capsys) == {file: [KEPT], moved: [LEFT_OUT]}
	assert listed(versions[-1], job, folder) == ['f' * 100] and tracked(job, rel_of(job, file)) and not tracked(job, rel_of(job, moved))


def test_the_length_rule_counts_bytes_not_characters():
	# review focus 5: names of 3-byte UTF-8 characters, and of bytes that are not UTF-8, measured by os.fsencode(): a rule counting
	# characters would let all of these through
	euro = '€' * 60
	assert len(os.fsencode(euro)) == 180
	version = 95
	for name in (euro, os.fsdecode(b'\xff' * 180)):
		# 21 names of 180 bytes and their slashes, 3,800 bytes, then ASCII to the length wanted
		rel = '/'.join([name] * 21)
		assert len(os.fsencode(rel)) == 3800
		at_4095 = rel + '/' + 'f' * (4095 - version - 1 - len(os.fsencode(rel)) - 1)
		assert len(os.fsencode(at_4095)) + version + 1 == 4095
		assert rv.vault_path_too_long(version, at_4095, False) is False
		assert rv.vault_path_too_long(version, at_4095 + 'f', False) is True
		# a folder of 4,040 and 4,041 bytes, with a copy's temporary path of 4,095 and 4,096
		folder_4040 = rel + '/' + 'd' * (4040 - version - 1 - len(os.fsencode(rel)) - 1)
		assert rv.vault_path_too_long(version, folder_4040 + '/x', True) is False
		assert rv.vault_path_too_long(version, folder_4040 + 'd/x', True) is True
		assert rv.vault_path_too_long(version, folder_4040 + 'd/x', False) is False
