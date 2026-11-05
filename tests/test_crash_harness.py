'''
The crash harness and its oracle, proven on the 0.54 layout: the oracle finds each kind of damage, a batch uncut is exact,
and a batch killed before any of its changes of the vault is exact once retried. Everything of round 20 runs on these.

REVERB_CRASH_FULL=1 runs every kill point; by default a stride of them, keeping the test under a minute. REVERB_CRASH_ROOT
places the job on a given mount.
'''
import json
import os
import shutil
import tempfile

import pytest

from tests.crash_batches import after_retries, prepare, restore, UNREADABLE
from tests.crash_child import kill_run, retry
from tests.vault_oracle import check_vault, forward_text, read_view, sizes_by_newest_holder, snapshot_tree, version_number

pytestmark = pytest.mark.skipif(os.geteuid() != 0, reason='the root record is a trusted.* attribute, and a file is chowned')

# a default run's kill points
DEFAULT_KILL_POINTS = 110
ROOT_RECORD = 'trusted.reverberator.root'
PREPARED = {}


@pytest.fixture
def crash_vault(tmp_path_factory):
	'''
	The crash vault as batch 2 left it, batch 3 applied to the monitored tree. Built once, by the first test wanting it, under
	that test's isolated_runtime() (a fixture wider than a test's would run the daemon with a real syncfs), outside
	tmp_path, whose vaults the ground truth plugins read: they see no fork's links.
	'''
	if 'vault' not in PREPARED:
		place = os.environ.get('REVERB_CRASH_ROOT')
		root = tempfile.mkdtemp(prefix='reverb-crash-', dir=place) if place else str(tmp_path_factory.mktemp('crash'))
		PREPARED['vault'] = prepare(root)
		PREPARED['root'] = root
	restore(PREPARED['vault'])
	return PREPARED['vault']


@pytest.fixture(scope='module', autouse=True)
def remove_a_crash_root():
	yield
	if os.environ.get('REVERB_CRASH_ROOT') and 'root' in PREPARED:
		shutil.rmtree(PREPARED['root'])
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


DAMAGE = [damage_content, damage_mode, damage_file_mtime, damage_folder_mtime, damage_dangling_link, damage_stray_partial,
	damage_extra_version, damage_missing_list, damage_wrong_current_version, damage_root_record]


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
	assert check_vault(job_vault, crash_vault.base, set(), folder_times=False, free_file_meta=True) == []
	damage_content(job_vault)
	assert check_vault(job_vault, crash_vault.base, set(), folder_times=False, free_file_meta=True) != []


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


def kill_points(total):
	'''Every kill point (two past the end, as a kill past the end must change nothing) or a stride of them with the tail.'''
	every = list(range(1, total + 3))
	if os.environ.get('REVERB_CRASH_FULL'):
		return every
	stride = max(1, total // DEFAULT_KILL_POINTS)
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
