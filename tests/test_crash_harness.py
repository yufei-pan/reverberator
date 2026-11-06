'''
The crash harness and its oracle, proven on the 0.54 layout: the oracle finds each kind of damage, a batch uncut is exact,
and a batch killed before any of its changes of the vault is exact once retried. Everything of round 20 runs on these.

On design R the same kill points run with Only Sync Attributes off and on, then a kill during the retry, the monitored tree
changing after the crash, a full disk at each record, and two negative controls proving the oracle sees what each rule
of the roll-forward is there for. tests/test_crash_power_loss.py holds the power loss model.

REVERB_CRASH_FULL=1 runs every kill point; by default a stride of them, keeping the test under a minute. REVERB_CRASH_ROOT
places the job on a given mount.
'''
import fcntl
import json
import os
import random
import shutil
import sqlite3
import stat
import subprocess
import tempfile
import threading
import time
from collections import deque, OrderedDict

import pytest

import reverberator as rv
from tests import version_view_ground_truth as view_truth
from tests.crash_batches import after_retries, apply_batch3, batch3_of, build_base, expected_of, OPTIONS, prepare, put_text, raw_events, restore, restore_monitor, UNREADABLE
from tests.crash_child import failing_copy_command, in_child, kill_run, retry, run_do_backup
from tests.harness import create_job
from tests.vault_oracle import check_vault, compared, entry_view, forward_text, read_view, sizes_by_newest_holder, snapshot_tree, version_number

pytestmark = pytest.mark.skipif(os.geteuid() != 0, reason='the root record is a trusted.* attribute, and a file is chowned')

# a default run's kill points
DEFAULT_KILL_POINTS = 110
ROOT_RECORD = 'trusted.reverberator.root'
PREPARED = {}
ROOTS = []


@pytest.fixture
def crash_vault(tmp_path_factory):
	'''
	The crash vault as batch 2 left it, batch 3 applied to the monitored tree. Built once, by the first test wanting it, under
	that test's isolated_runtime() (a fixture wider than a test's would run the daemon with a real syncfs), outside
	tmp_path, whose vaults the ground truth plugins read: they see no fork's links.
	'''
	return prepared('0.54', tmp_path_factory)


def prepared(key, tmp_path_factory, **options):
	if key not in PREPARED:
		place = os.environ.get('REVERB_CRASH_ROOT')
		root = tempfile.mkdtemp(prefix='reverb-crash-', dir=place) if place else str(tmp_path_factory.mktemp('crash'))
		ROOTS.append(root)
		PREPARED[key] = prepare(root, **options)
	restore(PREPARED[key])
	return PREPARED[key]


@pytest.fixture(params=[False, True], ids=['attributes_copied', 'only_sync_attributes'])
def r_vault(request, tmp_path_factory):
	'''The crash vault on design R, batch 3 with its chmod of top.txt whose mtime did not move: under Only Sync Attributes that goes on the shared inode.'''
	return prepared(('r', request.param), tmp_path_factory, only_sync_attributes=request.param)


@pytest.fixture
def osa_r_vault(tmp_path_factory):
	return prepared(('r', True), tmp_path_factory, only_sync_attributes=True)


@pytest.fixture
def plain_r_vault(tmp_path_factory):
	return prepared(('r', False), tmp_path_factory, only_sync_attributes=False)


@pytest.fixture(scope='module', autouse=True)
def remove_a_crash_root():
	yield
	if os.environ.get('REVERB_CRASH_ROOT'):
		for root in ROOTS:
			shutil.rmtree(root)
	ROOTS.clear()
	PREPARED.clear()


def folder_of(job_vault, number):
	return next(name for name in os.listdir(job_vault) if version_number(name) == number)


def real_file(job_vault, number, rel):
	'''The path of rel in version number, followed down the chain of links to its copy.'''
	path = os.path.join(job_vault, folder_of(job_vault, number), rel)
	return os.path.realpath(path)


def damage_content(job_vault):
	path = real_file(job_vault, 1, 'a/sub/m.txt')
	st = os.lstat(path)
	with open(path, 'w') as f:
		f.write('XX')
	os.utime(path, ns=(st.st_atime_ns, st.st_mtime_ns))


def damage_mode(job_vault):
	os.chmod(real_file(job_vault, 1, 'b/y.txt'), 0o640)


def damage_file_mtime(job_vault):
	path = real_file(job_vault, 1, 'b/y.txt')
	os.utime(path, ns=(1, 1))


def damage_folder_mtime(job_vault):
	os.utime(os.path.join(job_vault, folder_of(job_vault, 1), 'g', 'h'), ns=(1, 1))


def damage_dangling_link(job_vault):
	# the copy version 2's chain ends in goes: its link leads nowhere
	os.remove(real_file(job_vault, 2, 'd/g'))


def damage_stray_partial(job_vault):
	with open(os.path.join(job_vault, folder_of(job_vault, 2), 'g', 'h', '.' + '0' * 32 + '.reverberator-partial'), 'w') as f:
		f.write('partial')


def damage_extra_version(job_vault):
	name = 'V3--2030-01-01_00-00-00_-0800'
	shutil.copytree(os.path.join(job_vault, folder_of(job_vault, 2)), os.path.join(job_vault, name), symlinks=True)
	with open(os.path.join(job_vault, f'{name}--1_B-1_ino.modified_contents.nsv'), 'w') as f:
		f.write('path\n')
	os.remove(os.path.join(job_vault, 'current_version'))
	os.symlink(name, os.path.join(job_vault, 'current_version'))


def damage_missing_list(job_vault):
	folder = folder_of(job_vault, 1)
	os.remove(os.path.join(job_vault, next(name for name in os.listdir(job_vault) if name.startswith(folder + '--'))))


def damage_wrong_current_version(job_vault):
	os.remove(os.path.join(job_vault, 'current_version'))
	os.symlink(folder_of(job_vault, 1), os.path.join(job_vault, 'current_version'))


def damage_root_record(job_vault):
	folder = os.path.join(job_vault, folder_of(job_vault, 1))
	record = json.loads(os.getxattr(folder, ROOT_RECORD))
	record['mode'] = 0o700
	os.setxattr(folder, ROOT_RECORD, json.dumps(record).encode())


def damage_version_root_mode(job_vault):
	os.chmod(os.path.join(job_vault, folder_of(job_vault, 1)), 0o700)


def damage_version_root_owner(job_vault):
	os.chown(os.path.join(job_vault, folder_of(job_vault, 1)), 1234, 1235)


DAMAGE = [damage_content, damage_mode, damage_file_mtime, damage_folder_mtime, damage_dangling_link, damage_stray_partial,
	damage_extra_version, damage_missing_list, damage_wrong_current_version, damage_root_record, damage_version_root_mode, damage_version_root_owner]


@pytest.mark.parametrize('damage', DAMAGE, ids=lambda damage: damage.__name__[len('damage_'):])
def test_the_oracle_finds_each_kind_of_damage(crash_vault, damage):
	job_vault = crash_vault.job.job_vault
	assert check_vault(job_vault, crash_vault.base, set()) == []
	damage(job_vault)
	assert check_vault(job_vault, crash_vault.base, set()) != []


def test_the_oracles_switches_leave_out_only_what_they_name(crash_vault):
	job_vault = crash_vault.job.job_vault
	damage_folder_mtime(job_vault)
	assert check_vault(job_vault, crash_vault.base, set(), folder_times=False) == []
	damage_file_mtime(job_vault)
	damage_mode(job_vault)
	assert check_vault(job_vault, crash_vault.base, set(), folder_times=False) != []


def committed_osa(vault):
	'''The Only Sync Attributes vault after batch 3, uncut: its chmod of top.txt went on the inode that versions 1 to 3 share.'''
	restore(vault)
	assert cut_batch(vault).committed is True
	return vault.job.job_vault


def test_free_file_meta_leaves_out_only_the_metadata_of_a_shared_inode(osa_r_vault):
	job_vault = committed_osa(osa_r_vault)
	expected = osa_r_vault.expected
	assert check_vault(job_vault, expected, set()) != []
	assert check_vault(job_vault, expected, set(), free_file_meta=True) == []
	damage_content(job_vault)
	assert check_vault(job_vault, expected, set(), free_file_meta=True) != []


@pytest.mark.parametrize('tamper', [lambda path: os.chmod(path, 0o640), lambda path: os.utime(path, ns=(1, 1)), lambda path: os.chown(path, 1234, 1235),
	lambda path: os.setxattr(path, 'user.tag', b'x')], ids=['mode', 'mtime', 'owner', 'xattr'])
@pytest.mark.parametrize('where', ['newest', 'unshared'])
def test_free_file_meta_still_compares_a_file_nothing_shares_and_the_newest_whole(osa_r_vault, where, tamper):
	job_vault = committed_osa(osa_r_vault)
	if where == 'newest':
		# top.txt of the newest version is the inode versions 1 and 2 read too: the newest is where it is told
		path = os.path.join(job_vault, folder_of(job_vault, 3), 'top.txt')
	else:
		# version 1's own copy of a file that later versions changed: no other version reads it
		path = real_file(job_vault, 1, 'a/x.txt')
		assert os.lstat(path).st_nlink == 1 and os.path.dirname(path).startswith(os.path.join(job_vault, folder_of(job_vault, 1)))
	assert check_vault(job_vault, osa_r_vault.expected, set(), free_file_meta=True) == []
	tamper(path)
	assert check_vault(job_vault, osa_r_vault.expected, set(), free_file_meta=True) != []


def test_free_file_meta_loosens_the_newest_listed_version_while_a_tree_is_cut(tmp_path):
	# f was rewritten in version 1, so version 0 keeps its own copy and only version 1 reads the inode it shares with the tree; the batch
	# after it puts a chmod on that inode. Cut after that, version 1 reads the tree's f with the new mode
	job = create_job(str(tmp_path))
	options = dict(only_sync_attributes=True)
	put_text(job.monitor, 'f', 'one', STAMP)
	put_text(job.monitor, 'g', 'g0', STAMP)
	expected = {0: snapshot_tree(job.monitor)}
	run_do_backup(job, OrderedDict(), options, matched_since=time.time_ns())
	put_text(job.monitor, 'f', 'two', STAMP + 1)
	expected[1] = snapshot_tree(job.monitor)
	raw = raw_events(job.monitor, [(False, 'modify', 'f', None)])
	run_do_backup(job, rv.change_events_to_backup_entries(deque(raw), job.monitor), options, touched=rv.touched_scopes(raw, job.monitor), matched_since=time.time_ns())
	template = str(tmp_path / 'template')
	subprocess.run(['cp', '-a', job.vault, template], check=True)
	os.chmod(os.path.join(job.monitor, 'f'), 0o600)
	put_text(job.monitor, 'g', 'g1', STAMP + 2)
	raw = raw_events(job.monitor, [(False, 'attrib', 'f', None), (False, 'modify', 'g', None)])
	def work():
		return run_do_backup(job, rv.change_events_to_backup_entries(deque(raw), job.monitor), options, touched=rv.touched_scopes(raw, job.monitor), matched_since=time.time_ns())
	seen = 0
	for point in range(1, 100):
		shutil.rmtree(job.vault)
		subprocess.run(['cp', '-a', template, job.vault], check=True)
		if not in_child(job, point, work).killed:
			break
		if rv.get_vault_info(job.job_vault).tree is None:
			continue
		if read_view(job.job_vault, folder_of(job.job_vault, 1))['f'].mode == 0o600:
			seen += 1
		listed = [line for line in check_vault(job.job_vault, expected, set(), folder_times=False, free_file_meta=True) if line.startswith(('V0:', 'V1:'))]
		assert listed == [], (point, listed)
	assert seen > 0


def test_a_loose_special_file_keeps_its_device_number_and_nothing_else(tmp_path):
	# an Only Sync Attributes change reaches every version sharing a device node, fifo or socket as it does a file
	device = tmp_path / 'dev'
	os.mknod(device, 0o600 | stat.S_IFCHR, os.makedev(1, 3))
	view = entry_view(str(device))
	other = view._replace(data=(stat.S_IFCHR, os.makedev(1, 5)))
	changed = view._replace(mode=0o640, uid=1234, gid=1235, mtime_ns=1, xattrs=(('user.x', b'y'),))
	assert view.kind == 'special'
	assert compared(changed, True, True) == compared(view, True, True)
	assert compared(changed, True, False) != compared(view, True, False)
	assert compared(other, True, True) != compared(view, True, True)


def test_a_backward_link_in_the_newest_version_of_an_r_vault_is_damage(plain_r_vault):
	# a walk reads such a link as a user's here, and the check names it all the same, as the monitored tree holds no such link
	job_vault = plain_r_vault.job.job_vault
	newest, older = (os.path.join(job_vault, folder_of(job_vault, number)) for number in (2, 1))
	assert check_vault(job_vault, plain_r_vault.base, set()) == []
	assert os.path.islink(os.path.join(older, 'r.txt')) and not os.path.islink(os.path.join(newest, 'r.txt'))
	os.remove(os.path.join(older, 'r.txt'))
	shutil.copy2(os.path.join(newest, 'r.txt'), os.path.join(older, 'r.txt'))
	os.remove(os.path.join(newest, 'r.txt'))
	os.symlink(os.path.join('..', folder_of(job_vault, 1), 'r.txt'), os.path.join(newest, 'r.txt'))
	assert read_view(job_vault, folder_of(job_vault, 2))['r.txt'].kind == 'l'
	problems = check_vault(job_vault, plain_r_vault.base, set())
	assert any("'r.txt'" in line and 'daemon link' in line for line in problems), problems


def test_a_device_replaced_by_another_is_damage(tmp_path):
	job = create_job(str(tmp_path))
	put_text(job.monitor, 'f', 'one')
	device = os.path.join(job.monitor, 'dev1')
	os.mknod(device, 0o600 | stat.S_IFCHR, os.makedev(1, 3))
	expected = {0: snapshot_tree(job.monitor)}
	_, manifest, committed = rv.do_backup(OrderedDict(), job_name=job.job_name, monitor_path=job.monitor, vault_path=job.vault, matched_since=time.time_ns(), **OPTIONS)
	manifest.close()
	assert committed is True
	path = os.path.join(job.job_vault, folder_of(job.job_vault, 0), 'dev1')
	assert stat.S_ISCHR(os.lstat(path).st_mode)
	assert check_vault(job.job_vault, expected, set()) == []
	st = os.lstat(path)
	os.remove(path)
	os.mknod(path, 0o600 | stat.S_IFCHR, os.makedev(1, 5))
	os.utime(path, ns=(st.st_atime_ns, st.st_mtime_ns))
	assert os.lstat(path).st_mode == st.st_mode and os.lstat(path).st_rdev != st.st_rdev
	assert check_vault(job.job_vault, expected, set()) != []


def test_a_number_in_allowed_new_may_be_missing_and_no_other(crash_vault):
	job_vault = crash_vault.job.job_vault
	assert check_vault(job_vault, {**crash_vault.base, 3: crash_vault.expected[3]}, {3}) == []
	assert check_vault(job_vault, {**crash_vault.base, 3: crash_vault.expected[3]}, set()) != []


def test_the_oracle_reads_hand_written_forward_links(tmp_path):
	# no real batch makes this layout yet: its reading is proven by hand, its damage too
	vault = tmp_path / 'hand'
	old, new = 'V1--2021-01-01_00-00-00_-0800', 'V2--2021-01-02_00-00-00_-0800'
	for folder in (f'{new}/deep/er', f'{old}/deep'):
		(vault / folder).mkdir(parents=True)
	(vault / new / 'whole').mkdir()
	(vault / new / 'whole' / 'in.txt').write_text('in')
	(vault / new / 'deep' / 'er' / 'f.txt').write_text('new')
	(vault / old / 'deep' / 'gone.txt').write_text('old')
	for rel in ('whole', 'deep/er'):
		os.symlink(forward_text(rel, new), vault / old / rel)
	os.symlink('../not/daemons', vault / old / 'user')
	(vault / new / 'user').symlink_to('../not/daemons')
	for name in (old, new):
		(vault / f'{name}--1_B-1_ino.modified_contents.nsv').write_text('path\n')
		os.setxattr(vault / name, ROOT_RECORD, json.dumps({'v': 1, 'uid': 0, 'gid': 0, 'mode': 0o755, 'mtime_ns': 5, 'atime_ns': 5, 'xattrs': {}}).encode())
	(vault / 'current_version').symlink_to(new)
	view = read_view(str(vault), old)
	# the newest's real entries, and what the older holds of its own
	assert {rel: entry.kind for rel, entry in view.items()} == {'': 'root', 'whole': 'd', 'whole/in.txt': 'f', 'deep': 'd', 'deep/er': 'd',
		'deep/er/f.txt': 'f', 'deep/gone.txt': 'f', 'user': 'l'}
	assert view['whole/in.txt'] == snapshot_tree(str(vault / new))['whole/in.txt']
	expected = {1: view, 2: read_view(str(vault), new)}
	assert check_vault(str(vault), expected, set()) == []
	# a link near the text is a user's link, and no version reads through it
	(vault / old / 'whole').unlink()
	(vault / old / 'whole').symlink_to(f'../../{new}/whole')
	near = read_view(str(vault), old)
	assert near['whole'].kind == 'l' and 'whole/in.txt' not in near
	assert check_vault(str(vault), expected, set()) != []
	# a forward link whose next version lost the path leads nowhere
	(vault / old / 'whole').unlink()
	os.symlink(forward_text('nothing', new), vault / old / 'nothing')
	assert read_view(str(vault), old)['nothing'].kind == 'dangling'


def test_the_newest_holder_counts_each_inode_once(tmp_path):
	vault = tmp_path / 'hand'
	old, new = 'V1--2021-01-01_00-00-00_-0800', 'V2--2021-01-02_00-00-00_-0800'
	(vault / new / 'd').mkdir(parents=True)
	(vault / old / 'd').mkdir(parents=True)
	(vault / new / 'd' / 'shared.txt').write_text('12345')
	(vault / new / 'only.txt').write_text('123')
	(vault / old / 'd' / 'mine.txt').write_text('1234567')
	os.link(vault / new / 'd' / 'shared.txt', vault / old / 'd' / 'shared.txt')
	os.symlink(forward_text('only.txt', new), vault / old / 'only.txt')
	assert sizes_by_newest_holder(str(vault)) == {2: (4096 + 5 + 3, 3), 1: (4096 + 7, 3)}


def wrong_contents(rv):
	real = rv.copy_command
	rv.copy_command = lambda source, dest: real(rv.os.path.join(rv.os.path.dirname(source), 'new1.txt') if rv.os.path.basename(source) == 'x.txt' else source, dest)


def no_root_record(rv):
	rv.record_root_meta = lambda monitor_path, version_path: True


def no_list_placed(rv):
	rv.place_change_list = lambda content_file_name, prepared_list: None


@pytest.mark.parametrize('fault', [wrong_contents, no_root_record, no_list_placed], ids=lambda fault: fault.__name__)
def test_a_daemon_gone_wrong_is_caught(crash_vault, fault):
	# the whole way, from a real run in the child to the check, on a fault of the daemon's own
	job = crash_vault.job
	assert kill_run(job, fault=fault).error is None
	assert check_vault(job.job_vault, crash_vault.expected, set()) != []


def test_the_uncut_batch_is_exact(crash_vault):
	job = crash_vault.job
	outcome = kill_run(job)
	assert outcome.error is None and outcome.committed is True
	# the prune of version 0 has no kill here, and gives back every folder time
	assert check_vault(job.job_vault, crash_vault.expected, set()) == []
	# what the batch's copy failures were to do
	folder = folder_of(job.job_vault, 3)
	view = read_view(job.job_vault, folder)
	assert view[f'w/x{UNREADABLE}'] == crash_vault.base[2][f'w/x{UNREADABLE}']
	assert f'w/fresh{UNREADABLE}' not in view
	# the monitored tree holds what the version does not, so the check above read a real difference
	assert snapshot_tree(job.monitor)[f'w/x{UNREADABLE}'] != view[f'w/x{UNREADABLE}']


def test_the_kill_points_cover_every_kind_of_call(crash_vault):
	outcome = kill_run(crash_vault.job)
	assert outcome.error is None
	assert outcome.steps == sum(outcome.counts.values())
	for kind in ('rename', 'mkdir', 'symlink', 'remove', 'commit', 'Popen'):
		assert outcome.counts.get(kind, 0) >= 1, (kind, outcome.counts)


def kill_points(total, default=DEFAULT_KILL_POINTS):
	'''Every kill point (two past the end, as a kill past the end must change nothing) or a stride of them with the tail.'''
	every = list(range(1, total + 3))
	if os.environ.get('REVERB_CRASH_FULL'):
		return every
	stride = max(1, total // default)
	return sorted({*every[::stride], *every[-5:]})


def test_every_kill_point_on_the_054_layout(crash_vault):
	job = crash_vault.job
	total = kill_run(job).steps
	assert total > 0
	wrong = []
	points = kill_points(total)
	for point in points:
		restore(crash_vault)
		cut = kill_run(job, point)
		if cut.error is not None:
			wrong.append((point, 'the cut run failed', cut.error))
			continue
		if point <= total and not cut.killed:
			wrong.append((point, 'not killed', cut))
			continue
		again = retry(job)
		if again.error is not None or again.committed is not True:
			wrong.append((point, 'the retry failed', again))
			continue
		if max(version_number(name) or 0 for name in os.listdir(job.job_vault)) < 3:
			wrong.append((point, 'no version 3 after the retry'))
			continue
		# 0.54 keeps its approved limitation: a prune killed leaves bumped folder times
		problems = check_vault(job.job_vault, after_retries(job.job_vault, crash_vault.expected), {3}, folder_times=False)
		if problems:
			wrong.append((point, problems[:8]))
	print(f'{len(points)} of {total} kill points run; {len(wrong)} wrong')
	assert not wrong, f'{len(wrong)} of {len(points)} kill points wrong: {wrong[:6]}'


def free_meta(vault):
	return bool(vault.options.get('only_sync_attributes'))


def cut_batch(vault, point=None, fault=None):
	return kill_run(vault.job, point, fault=fault, options=vault.options)


def retried(vault, point=None, fault=None):
	return retry(vault.job, point, fault=fault, options=vault.options)


def wrong_after_retry(vault, expected=None, allowed_new=frozenset({3})):
	'''What is wrong with the vault once a retry ran: every version read by the oracle, and each list against what the oracle counts.'''
	job_vault = vault.job.job_vault
	want = after_retries(job_vault, vault.expected) if expected is None else expected
	return check_vault(job_vault, want, set(allowed_new), free_file_meta=free_meta(vault)) + view_truth.wrong_lists(job_vault)


def sweep_points(vault, default=DEFAULT_KILL_POINTS):
	'''The kill points of batch 3 on this vault, restored.'''
	total = cut_batch(vault).steps
	assert total > 0
	restore(vault)
	return total, kill_points(total, default)


def test_batch_3_has_an_attribute_change_on_a_shared_inode(r_vault):
	# what the sweeps are to meet with Only Sync Attributes on: a chmod whose mtime did not move, which goes on the inode of the tree
	job_vault = r_vault.job.job_vault
	assert cut_batch(r_vault).committed is True
	previous, newest = (os.path.join(job_vault, folder_of(job_vault, number)) for number in (2, 3))
	assert os.lstat(os.path.join(newest, 'top.txt')).st_mode & 0o777 == 0o600
	assert read_view(job_vault, folder_of(job_vault, 3))['top.txt'].mtime_ns == r_vault.base[2]['top.txt'].mtime_ns
	if free_meta(r_vault):
		assert os.path.islink(os.path.join(previous, 'top.txt'))
		assert read_view(job_vault, folder_of(job_vault, 2))['top.txt'].mode == 0o600
	else:
		assert not os.path.islink(os.path.join(previous, 'top.txt'))
		assert read_view(job_vault, folder_of(job_vault, 2))['top.txt'].mode == r_vault.base[2]['top.txt'].mode


def test_every_kill_point_on_r(r_vault):
	total, points = sweep_points(r_vault)
	wrong = []
	for point in points:
		restore(r_vault)
		cut = cut_batch(r_vault, point)
		if cut.error is not None or (point <= total and not cut.killed):
			wrong.append((point, 'the cut run', cut))
			continue
		again = retried(r_vault)
		if again.error is not None or again.committed is not True:
			wrong.append((point, 'the retry', again))
			continue
		problems = wrong_after_retry(r_vault)
		if problems:
			wrong.append((point, problems[:8]))
	print(f'{len(points)} of {total} kill points run; {len(wrong)} wrong')
	assert not wrong, f'{len(wrong)} of {len(points)} kill points wrong: {wrong[:4]}'


def test_a_kill_during_the_retry_is_safe(r_vault):
	total = cut_batch(r_vault).steps
	generator = random.Random(19)
	runs = 500 if os.environ.get('REVERB_CRASH_FULL') else 40
	wrong = []
	for _ in range(runs):
		first, second = generator.randint(1, total + 2), generator.randint(1, 120)
		restore(r_vault)
		cut = cut_batch(r_vault, first)
		during = retried(r_vault, second)
		again = retried(r_vault)
		if cut.error is not None or during.error is not None or again.error is not None or again.committed is not True:
			wrong.append((first, second, cut, during, again))
			continue
		problems = wrong_after_retry(r_vault)
		if problems:
			wrong.append((first, second, problems[:8]))
	print(f'{runs} double kills; {len(wrong)} wrong')
	assert not wrong, f'{len(wrong)} of {runs} double kills wrong: {wrong[:4]}'


def rows_checked(job):
	'''Every file row checked, as a full comparison leaves a live vault's: only what the roll-forward marks is read back from the tree.'''
	connection = sqlite3.connect(os.path.join(job.job_vault, rv.MANIFEST_FILE_NAME))
	with connection:
		connection.execute("UPDATE entries SET unchecked = 0 WHERE kind = 'f'")
	connection.close()


def change_after_the_crash(job, base):
	'''
	The monitored tree changes while the daemon is down. Some of what the cut batch wrote the tree goes back to what version
	2 held, so a row vouches for what the tree no longer holds: contents with the old mtime, a file it removed, a folder's
	mode, a file's mode, a link's text, a folder it replaced by a file. A file it made goes, one it wrote changes again, a
	folder it removed comes back empty.
	'''
	def at(rel):
		return os.path.join(job.monitor, rel)
	rows_checked(job)
	put_text(job.monitor, 'c/z.txt', 'z0', base['c/z.txt'].mtime_ns)
	put_text(job.monitor, 'b/y.txt', 'y0', base['b/y.txt'].mtime_ns)
	os.remove(at('newf/sub/b.txt'))
	put_text(job.monitor, 'a/x.txt', 'ax4')
	os.mkdir(at('big'))
	os.chmod(at('b'), base['b'].mode)
	os.chmod(at('top.txt'), base['top.txt'].mode)
	os.remove(at('lnk'))
	os.symlink(base['lnk'].data, at('lnk'))
	# a link's own times are no change: no comparison looks at them
	os.utime(at('lnk'), ns=(base['lnk'].mtime_ns, base['lnk'].mtime_ns), follow_symlinks=False)
	os.remove(at('rr'))
	put_text(job.monitor, 'rr/inside.txt', 'rr0', base['rr/inside.txt'].mtime_ns)
	os.remove(at('n1.txt'))


def expected_after_the_change(vault):
	'''What each version must hold once a retry after change_after_the_crash() ran, the newest what the tree holds now.'''
	job_vault = vault.job.job_vault
	newest = max(number for number in map(version_number, os.listdir(job_vault)) if number is not None)
	now = expected_of(snapshot_tree(vault.job.monitor), vault.base[2])
	# a commit that was cut after its commit point keeps version 3 as the batch wrote it
	versions = {1: vault.base[1], 2: vault.base[2], 3: vault.expected[3]}
	return {number: now if number == newest else versions[number] for number in range(newest - 2, newest + 1)}


def test_the_tree_changed_after_the_crash(r_vault):
	total, points = sweep_points(r_vault, 55)
	wrong = []
	try:
		for point in points:
			restore(r_vault)
			restore_monitor(r_vault)
			cut = cut_batch(r_vault, point)
			change_after_the_crash(r_vault.job, r_vault.base[2])
			again = retried(r_vault)
			if cut.error is not None or again.error is not None or again.committed is not True:
				wrong.append((point, cut, again))
				continue
			problems = wrong_after_retry(r_vault, expected_after_the_change(r_vault), frozenset())
			if problems:
				wrong.append((point, problems[:8]))
	finally:
		restore_monitor(r_vault)
	print(f'{len(points)} of {total} kill points run with the tree changed after the crash; {len(wrong)} wrong')
	assert not wrong, f'{len(wrong)} of {len(points)} kill points wrong: {wrong[:4]}'


def cut_tree_of(job, new_name='V3--2030-01-01_00-00-00_-0800'):
	'''A batch cut right after its hand-over: the tree of the next version kept in its folder, and every link of the newest leading there.'''
	manifest = rv.VaultManifest(job.job_vault)
	try:
		info = rv.get_vault_info(job.job_vault, manifest=manifest)
		newest = info.vault_info_dict[next(reversed(info.vault_info_dict))]
		rv.hand_over(job.job_vault, newest.path, os.path.join(job.job_vault, new_name), manifest)
	finally:
		manifest.close()
	return new_name


def test_a_roll_forward_always_commits(tmp_path):
	job = create_job(str(tmp_path))
	base = build_base(job)
	name = cut_tree_of(job)
	# nothing differs: a batch would make no version, and this one must
	assert run_do_backup(job, OrderedDict(), matched_since=time.time_ns()) is True
	assert os.readlink(os.path.join(job.job_vault, 'current_version')) == name
	assert check_vault(job.job_vault, {1: base[1], 2: base[2], 3: base[2]}, set()) == []
	assert view_truth.wrong_lists(job.job_vault) == []


def test_a_roll_forward_never_prunes_the_previous_version(tmp_path):
	job = create_job(str(tmp_path))
	base = build_base(job)
	cut_tree_of(job)
	assert run_do_backup(job, OrderedDict(), {'keep_n_versions': 1}, matched_since=time.time_ns()) is True
	numbers = sorted(number for number in map(version_number, os.listdir(job.job_vault)) if number is not None)
	assert numbers[-2:] == [2, 3]
	assert check_vault(job.job_vault, {2: base[2], 3: base[2]}, set()) == []


def test_roll_forward_sizes_equal_a_clean_batch(plain_r_vault):
	vault = plain_r_vault
	job_vault = vault.job.job_vault
	# a clean batch: the counters named V2's list, and measuring gives the same
	outcome = cut_batch(vault)
	assert outcome.error is None and outcome.committed is True
	folders = {version_number(name): os.path.join(job_vault, name) for name in os.listdir(job_vault) if version_number(name) is not None}
	sizes = sizes_by_newest_holder(job_vault)
	assert view_truth.wrong_lists(job_vault) == []
	assert rv.measure_previous(folders[2], folders[3]) == sizes[2]
	# at every moment a cut can leave
	total, points = sweep_points(vault)
	measured = 0
	for point in points[::4]:
		restore(vault)
		cut_batch(vault, point)
		folders = {version_number(name): os.path.join(job_vault, name) for name in os.listdir(job_vault) if version_number(name) is not None}
		if 3 in folders and 2 in folders and not rv.is_skeleton(folders[3]):
			measured += 1
			assert rv.measure_previous(folders[2], folders[3]) == sizes_by_newest_holder(job_vault)[2], point
	assert measured > 0


def lock_taken_shared(job, kind):
	'''Whether a restore could take the job's lock of kind right now.'''
	fd = os.open(rv.job_lock_path(job.job_name, kind), os.O_RDWR | os.O_CREAT, 0o600)
	try:
		fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
		return True
	except BlockingIOError:
		return False
	finally:
		os.close(fd)


def wait_until(condition, seconds=30):
	deadline = time.monotonic() + seconds
	while not condition():
		assert time.monotonic() < deadline, 'it did not happen'
		time.sleep(0.01)


def test_the_locks_are_free_between_the_scan_and_the_roll_forward(plain_r_vault, monkeypatch):
	vault = plain_r_vault
	job, job_vault = vault.job, vault.job.job_vault
	os.makedirs(rv.state_dir_path(), exist_ok=True)
	# a cut with folders recorded in the previous version: past the first exchange of a folder
	total = cut_batch(vault).steps
	restore(vault)
	assert cut_batch(vault, total // 2).killed
	real_copy_command = rv.copy_command
	monkeypatch.setattr(rv, 'copy_command', failing_copy_command(real_copy_command))
	monitor_fs_flag = threading.Event()
	prepared_scans = []
	real_prepare = rv.prepare_roll_forward
	def preparing(*args):
		real_prepare(*args)
		prepared_scans.append(args[0].tree)
	monkeypatch.setattr(rv, 'prepare_roll_forward', preparing)
	real_wait = rv.wait_for_path
	waiting = threading.Event()
	def waits(job_control, flag, path, *args, **kwargs):
		if flag is monitor_fs_flag:
			waiting.set()
		return real_wait(job_control, flag, path, *args, **kwargs)
	monkeypatch.setattr(rv, 'wait_for_path', waits)
	to_process = rv.ChangeEventQueue(job.monitor)
	to_process.append(rv.ChangeEvent(time.monotonic(), False, 'full_scan', job.monitor, None))
	thread = threading.Thread(target=rv.backuper, args=(job.job_name, to_process, threading.Lock(), job.monitor, job.vault, 'N/A', threading.Event(), monitor_fs_flag),
		kwargs=dict(keep_one_complete_backup=True, only_sync_attributes=False, keep_n_versions=3, backup_size_limit='0'), daemon=True)
	thread.start()
	try:
		# the monitored path is missing, and the scan has run: a restore goes ahead, and reads exact versions
		wait_until(waiting.is_set)
		assert prepared_scans, 'the scan did not prepare the roll-forward before the wait'
		assert lock_taken_shared(job, 'backup') and lock_taken_shared(job, 'restore')
		for number, name in ((version, folder_of(job_vault, version)) for version in (1, 2)):
			assert read_view(job_vault, name) == vault.base[number]
		tree = prepared_scans[0]
		# it comes back: the batch takes the locks again and finishes
		monitor_fs_flag.set()
		wait_until(lambda: any(rv.change_list_names(name, os.path.basename(tree)) for name in os.listdir(job_vault)), 60)
	finally:
		rv.GREEN_LIGHT.clear()
		monitor_fs_flag.set()
		thread.join(30)
		rv.GREEN_LIGHT.set()
	assert not thread.is_alive()
	assert wrong_after_retry(vault) == []


def test_a_comparison_of_scanned_folders_leaves_a_cut_batch_to_the_whole_comparison(plain_r_vault):
	vault = plain_r_vault
	total = cut_batch(vault).steps
	restore(vault)
	assert cut_batch(vault, total // 2).killed
	entries = OrderedDict()
	info, manifest, full = rv.compare_scanned_folders(entries, [os.path.join(vault.job.monitor, 'a')], vault.job.job_name, vault.job.monitor, vault.job.vault)
	if manifest is not None:
		manifest.close()
	assert full is True and info.tree is not None and not entries


def test_a_cut_batch_that_held_moves_ends_exact_with_or_without_its_saved_entries(plain_r_vault):
	# the comparison of the whole tree says what the roll-forward replays: the entries the pending transactions give at the next start
	# change nothing, with or without them. batch 3 holds moves of files and folders, among them a swap
	vault = plain_r_vault
	job_vault = vault.job.job_vault
	total = cut_batch(vault).steps
	for point in (total // 3, total // 2, total - 3):
		for given in (True, False):
			restore(vault)
			assert cut_batch(vault, point).killed
			outcome = cut_batch(vault) if given else retried(vault)
			assert outcome.error is None and outcome.committed is True, outcome
			assert wrong_after_retry(vault) == [], (point, given)
			folder = folder_of(job_vault, 3)
			assert read_view(job_vault, folder)[f'w/x{UNREADABLE}'] == vault.base[2][f'w/x{UNREADABLE}']


BIG = 200 * 1024
STAMP = 1700000000_000000000


def canonical_monitor(monitor):
	'''The monitored tree the saved-entry tests start from, every mtime fixed, so a version made of it matches it again at each cut point.'''
	for rel in ('a.txt', 'dd', 'big.bin'):
		path = os.path.join(monitor, rel)
		if os.path.isdir(path) and not os.path.islink(path):
			shutil.rmtree(path)
		elif os.path.lexists(path):
			os.remove(path)
	put_text(monitor, 'a.txt', 'a0', STAMP)
	put_text(monitor, 'dd/f', 'f0', STAMP + 1)
	put_text(monitor, 'dd/g', 'g0', STAMP + 2)
	with open(os.path.join(monitor, 'big.bin'), 'wb') as f:
		f.write(b'x' * BIG)
	os.utime(os.path.join(monitor, 'big.bin'), ns=(STAMP + 3, STAMP + 3))
	# the rewrite of big.bin, from an earlier batch: renamed over it, it looks the same to a comparison
	with open(os.path.join(monitor, 'spare.bin'), 'wb') as f:
		f.write(rewritten_big())
	os.utime(os.path.join(monitor, 'spare.bin'), ns=(STAMP + 3, STAMP + 3))


def rewritten_big():
	return b'x' * 10 + b'NEW' + b'x' * (BIG - 13)


def rewrite_by_delete_and_create(monitor):
	'''big.bin removed and made again with rewrite_in_place()'s result, as cp -p --remove-destination would.'''
	path = os.path.join(monitor, 'big.bin')
	os.remove(path)
	with open(path, 'wb') as f:
		f.write(rewritten_big())
	os.utime(path, ns=(STAMP + 3, STAMP + 3))


def rewrite_in_place(monitor):
	'''big.bin changed in the middle at its size, its mtime put back: nothing but the watcher saw it, and a comparison reads only the end of a file.'''
	path = os.path.join(monitor, 'big.bin')
	with open(path, 'r+b') as f:
		f.seek(10)
		f.write(b'NEW')
	os.utime(path, ns=(STAMP + 3, STAMP + 3))


def file_becomes_folder(monitor):
	os.remove(os.path.join(monitor, 'dd/f'))
	put_text(monitor, 'dd/f/in', 'inside')


def folder_becomes_file(monitor):
	shutil.rmtree(os.path.join(monitor, 'dd'))
	put_text(monitor, 'dd', 'a file now')


def file_is_gone(monitor):
	os.remove(os.path.join(monitor, 'dd/f'))


# (what the batch changes, its events, what happens to the tree while the daemon is down); the saved entries are given again at the next start
SAVED_ENTRIES = {
	'rewrite': (lambda m: (put_text(m, 'a.txt', 'a1'), rewrite_in_place(m)), [(False, 'modify', 'a.txt', None), (False, 'modify', 'big.bin', None)], lambda m: None),
	'rewrite_by_delete_and_create': (rewrite_by_delete_and_create, [(False, 'delete', 'big.bin', None), (False, 'create', 'big.bin', None)], lambda m: None),
	'rewrite_by_rename_over': (lambda m: os.replace(os.path.join(m, 'spare.bin'), os.path.join(m, 'big.bin')), [(False, 'move', 'big.bin', 'spare.bin')], lambda m: None),
	'created_file_becomes_folder': (lambda m: put_text(m, 'dd/new', 'n'), [(False, 'create', 'dd/new', None)],
		lambda m: (os.remove(os.path.join(m, 'dd/new')), put_text(m, 'dd/new/in', 'inside'))),
	'modified_file_becomes_folder': (lambda m: put_text(m, 'dd/f', 'f1'), [(False, 'modify', 'dd/f', None)], file_becomes_folder),
	'parent_becomes_file': (lambda m: put_text(m, 'dd/g', 'g1'), [(False, 'modify', 'dd/g', None)], folder_becomes_file),
	'modified_file_is_gone': (lambda m: put_text(m, 'dd/f', 'f1'), [(False, 'modify', 'dd/f', None)], file_is_gone),
}


@pytest.mark.parametrize('scenario', SAVED_ENTRIES)
def test_a_cut_batch_is_rolled_forward_with_its_saved_entries_given_again(tmp_path, scenario):
	# a stop cuts the batch at each step; the tree changes while the daemon is down (or not); the next start is given the saved
	# entries again. The comparison says what the tree is, and of the entries only a plain file's change it cannot see is added
	change, events, after = SAVED_ENTRIES[scenario]
	job = create_job(str(tmp_path))
	canonical_monitor(job.monitor)
	before = snapshot_tree(job.monitor)
	run_do_backup(job, OrderedDict(), matched_since=time.time_ns())
	template = str(tmp_path / 'template')
	subprocess.run(['cp', '-a', job.vault, template], check=True)
	raw = None
	def work():
		entries = rv.change_events_to_backup_entries(deque(raw), job.monitor)
		return run_do_backup(job, entries, touched=rv.touched_scopes(raw, job.monitor), matched_since=time.time_ns())
	wrong = []
	rolled = 0
	for point in range(1, 200):
		shutil.rmtree(job.vault)
		subprocess.run(['cp', '-a', template, job.vault], check=True)
		canonical_monitor(job.monitor)
		change(job.monitor)
		raw = raw_events(job.monitor, events)
		cut = in_child(job, point, work)
		if cut.error is not None:
			wrong.append((point, cut))
			continue
		if not cut.killed:
			break
		if rv.get_vault_info(job.job_vault).tree is None:
			continue
		after(job.monitor)
		again = in_child(job, None, work)
		rolled += 1
		if again.error is not None or again.committed is not True:
			wrong.append((point, again))
			continue
		problems = check_vault(job.job_vault, {0: before, 1: snapshot_tree(job.monitor)}, set()) + view_truth.wrong_lists(job.job_vault)
		if problems:
			wrong.append((point, problems[:4]))
	assert rolled > 0
	print(f'{scenario}: {rolled} cuts with a tree; {len(wrong)} wrong')
	assert not wrong, [(point, (outcome.error or str(outcome)).strip().splitlines()[-1][:150] if hasattr(outcome, 'error') else outcome) for point, outcome in wrong[:5]]


def test_enospc_at_every_record_call_keeps_every_version_exact(r_vault):
	uncut = cut_batch(r_vault)
	total = sum(uncut.counts.get(kind, 0) for kind in ('link', 'symlink', 'mkdir'))
	assert total > 0
	every = list(range(1, total + 1))
	stride = 1 if os.environ.get('REVERB_CRASH_FULL') else max(1, total // 30)
	wrong = []
	failed = 0
	went_on = []
	for number in every[::stride]:
		restore(r_vault)
		cut = cut_batch(r_vault, fault=f'enospc:{number}')
		if cut.error is None:
			went_on.append(number)
		else:
			failed += 1
			# make_real_folder() has logged why
			if 'No space left' not in cut.error and 'in the version failed' not in cut.error:
				wrong.append((number, 'failed otherwise', cut.error))
				continue
		again = retried(r_vault)
		if again.error is not None or again.committed is not True:
			wrong.append((number, 'the retry', again))
			continue
		problems = wrong_after_retry(r_vault)
		if problems:
			wrong.append((number, problems[:8]))
	print(f'{len(every[::stride])} of {total} record calls failed with ENOSPC, {failed} attempts failed by it, those at {went_on} went on; {len(wrong)} wrong')
	assert failed > 0
	assert not wrong, wrong[:4]


def test_a_normal_stop_mid_batch_is_finished_at_the_next_start(plain_r_vault, monkeypatch):
	vault = plain_r_vault
	job, job_vault = vault.job, vault.job.job_vault
	monkeypatch.setattr(rv, 'copy_command', failing_copy_command(rv.copy_command))
	lines = []
	real_log = rv.backuperTeeLogToTl
	monkeypatch.setattr(rv, 'backuperTeeLogToTl', lambda path, message, **kwargs: (lines.append(message), real_log(path, message, **kwargs))[1])
	real_copy = rv.TreeWriter.copy
	def stopping(self, *args, **kwargs):
		rv.GREEN_LIGHT.clear()
		return real_copy(self, *args, **kwargs)
	monkeypatch.setattr(rv.TreeWriter, 'copy', stopping)
	entries, touched = batch3_of(job)
	try:
		assert run_do_backup(job, entries, vault.options, touched=touched, matched_since=time.time_ns()) is False
	finally:
		rv.GREEN_LIGHT.set()
		monkeypatch.setattr(rv.TreeWriter, 'copy', real_copy)
	tree = next(name for name in os.listdir(job_vault) if version_number(name) == 3)
	assert any(line == f'Backup incomplete for {os.path.join(job_vault, tree)}: the next attempt finishes it' for line in lines)
	# the versions read as they did, the tree stays, with no list
	for number in (1, 2):
		assert read_view(job_vault, folder_of(job_vault, number)) == vault.base[number]
	assert not any(rv.change_list_names(name, tree) for name in os.listdir(job_vault))
	# the next start
	assert run_do_backup(job, OrderedDict(), vault.options, matched_since=time.time_ns()) is True
	assert folder_of(job_vault, 3) == tree
	assert wrong_after_retry(vault) == []


def test_a_forward_link_whose_tree_entry_is_gone_goes_in_a_roll_forward(tmp_path, monkeypatch):
	job = create_job(str(tmp_path))
	base = build_base(job)
	name = cut_tree_of(job)
	# by hand, while the daemon was down; the monitored file stays, so it is copied again. only the newest of the kept versions held it
	os.remove(os.path.join(job.job_vault, name, 'e0.txt'))
	lines = []
	real_log = rv.backuperTeeLogToTl
	monkeypatch.setattr(rv, 'backuperTeeLogToTl', lambda path, message, **kwargs: (lines.append(message), real_log(path, message, **kwargs))[1])
	previous = os.path.join(job.job_vault, folder_of(job.job_vault, 2))
	assert run_do_backup(job, OrderedDict(), matched_since=time.time_ns()) is True
	# that version read as holding nothing there since the hand removed it: the view plugin saw it as a dangling link gone
	assert not os.path.lexists(os.path.join(previous, 'e0.txt'))
	assert any('forwards to' in line and 'removing the link' in line for line in lines)
	without = {rel: entry for rel, entry in base[2].items() if rel != 'e0.txt'}
	assert check_vault(job.job_vault, {1: base[1], 2: without, 3: base[2]}, set()) == []
	assert view_truth.wrong_lists(job.job_vault) == []


def test_a_refused_commit_is_finished_once_the_manifest_is_removed(plain_r_vault):
	vault = plain_r_vault
	job, job_vault = vault.job, vault.job.job_vault
	# the commit point passed, then a cut: the first swap of current_version
	uncut = cut_batch(vault)
	restore(vault)
	found = None
	total = uncut.steps
	for point in range(total, 0, -1):
		restore(vault)
		cut_batch(vault, point)
		manifest = rv.VaultManifest(job_vault)
		named = manifest.recorded_version()
		manifest.close()
		if rv.vault_version_number(named) == 3 and not any(rv.change_list_names(name, named) for name in os.listdir(job_vault)):
			found = point
			break
	assert found is not None
	# the list in its private folder is gone for good
	for name in os.listdir(job_vault):
		if name.startswith(rv.CHANGE_LIST_FOLDER_PREFIX):
			shutil.rmtree(os.path.join(job_vault, name))
	refused = retried(vault)
	assert refused.error is not None and 'removing' in refused.error
	# what the refusal says to do
	os.remove(os.path.join(job_vault, rv.MANIFEST_FILE_NAME))
	again = retried(vault)
	assert again.error is None and again.committed is True, again
	assert wrong_after_retry(vault) == []
	assert rv.vault_version_number(os.readlink(os.path.join(job_vault, 'current_version'))) == 3


@pytest.mark.parametrize('share', [3, 2], ids=['early', 'late'])
def test_a_lost_manifest_in_a_cut_batch_finishes_it(plain_r_vault, share):
	vault = plain_r_vault
	job_vault = vault.job.job_vault
	total = cut_batch(vault).steps
	restore(vault)
	assert cut_batch(vault, total // share).killed
	assert any(version_number(name) == 3 for name in os.listdir(job_vault))
	os.remove(os.path.join(job_vault, rv.MANIFEST_FILE_NAME))
	again = retried(vault)
	assert again.error is None and again.committed is True, again
	# a row with no record keeps a folder's time: a cut in its one call can leave it with the batch's (spec section 3)
	assert check_vault(job_vault, vault.expected, set(), folder_times=False) == []
	assert view_truth.wrong_lists(job_vault) == []


def wrong_at(vault, point, fault=None, change=None):
	'''What is wrong once a batch cut at point is retried, fault in the retry, change made between the two.'''
	restore(vault)
	restore_monitor(vault)
	cut = cut_batch(vault, point)
	if change is not None:
		change()
	again = retried(vault, fault=fault)
	assert cut.error is None and again.error is None, (point, cut, again)
	return wrong_after_retry(vault, expected_after_the_change(vault), frozenset()) if change is not None else wrong_after_retry(vault)


def first_wrong(vault, fault=None, change=None):
	'''The (kill point, problems) of the first kill point whose retry, fault in it, leaves something wrong, where the same retry without the fault leaves nothing wrong; None when none does.'''
	total, points = sweep_points(vault)
	try:
		for point in points:
			problems = wrong_at(vault, point, fault, change)
			if problems:
				assert wrong_at(vault, point, None, change) == [], point
				return point, problems
	finally:
		restore_monitor(vault)
	return None


def put_a_file_back(vault):
	'''What the cut batch wrote the tree goes back as version 2 held it, its mtime too: its row vouches for it, the tree holds the batch's copy.'''
	rows_checked(vault.job)
	base = vault.base[2]
	put_text(vault.job.monitor, 'a/x.txt', 'ax2', base['a/x.txt'].mtime_ns)


def test_no_unchecked_marks_fails_the_oracle(plain_r_vault):
	vault = plain_r_vault
	def no_marks(rv):
		rv.VaultManifest.mark_unchecked = lambda self, rels: None
	found = first_wrong(vault, no_marks, change=lambda: put_a_file_back(vault))
	assert found is not None and any("'a/x.txt'" in line for line in found[1]), found


def test_no_folder_times_from_rows_fails_the_oracle(plain_r_vault):
	vault = plain_r_vault
	def no_times(rv):
		real_utime = rv.os.utime
		def give_back(previous, manifest):
			rv.os.utime = lambda *args, **kwargs: None
			try:
				return real_give_back(previous, manifest)
			finally:
				rv.os.utime = real_utime
		real_give_back = rv.give_back_folder_times
		rv.give_back_folder_times = give_back
	found = first_wrong(vault, no_times)
	assert found is not None and any('mtime_ns' in line for line in found[1]), found
