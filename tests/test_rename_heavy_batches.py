# Batches where a file made or saved in the batch is moved into a folder, the folder is moved, and the file is moved on
# again: the collapse copies it where it ends, so the replay never renames a path the version does not hold.
import os
import pytest
from tests.harness import seed_monitor, run_backup
from tests.test_moves_then_changes import BAD_LINES, batch, logged, verified, assert_version_is_the_tree  # noqa: F401

pytestmark = pytest.mark.unit

NOT_IN_VERSION = 'is not in the version; copying it instead'


def fallbacks(lines:list) -> list:
	'''The first line of each logged line of an error, a traceback, or a rename or copy that found nothing.'''
	return [line.splitlines()[0] for line in lines if line.startswith('ERROR ') or
		any(word in line for word in ('Traceback', NOT_IN_VERSION, 'Not tracking', 'Cannot read', *BAD_LINES))]


def apply(monitor:str, steps:list) -> None:
	'''Make steps in monitor: ('w', rel, text), ('mv', a, b), ('mkdir', rel), ('rmdir', rel), ('rm', rel), ('chmod', rel).'''
	for kind, *args in steps:
		path = os.path.join(monitor, args[0])
		if kind == 'w':
			with open(path, 'w') as f:
				f.write(args[1])
		elif kind == 'mv':
			os.rename(path, os.path.join(monitor, args[1]))
		elif kind == 'mkdir':
			os.mkdir(path)
		elif kind == 'rmdir':
			os.rmdir(path)
		elif kind == 'rm':
			os.remove(path)
		elif kind == 'chmod':
			os.chmod(path, 0o600)
		else:
			raise AssertionError(kind)


CASES = {
	# name: (seed, steps, the watcher's events of the steps)
	'new_file': ({'d/': None}, [('w', 'f', 'new\n'), ('mv', 'f', 'd/g'), ('mv', 'd', 'D'), ('mv', 'D/g', 'h')],
		[(False, 'create', 'f', None), (False, 'move', 'd/g', 'f'), (True, 'move', 'D', 'd'), (False, 'move', 'h', 'D/g')]),
	'saved_file': ({'d/': None, 'f': 'old\n'}, [('w', 'f', 'saved\n'), ('mv', 'f', 'd/g'), ('mv', 'd', 'D'), ('mv', 'D/g', 'h')],
		[(False, 'modify', 'f', None), (False, 'move', 'd/g', 'f'), (True, 'move', 'D', 'd'), (False, 'move', 'h', 'D/g')]),
	'older_file_replaced': ({'d/g': 'OLD\n'}, [('w', 'f', 'new\n'), ('mv', 'f', 'd/g'), ('mv', 'd', 'D'), ('mv', 'D/g', 'h')],
		[(False, 'create', 'f', None), (False, 'move', 'd/g', 'f'), (True, 'move', 'D', 'd'), (False, 'move', 'h', 'D/g')]),
	'older_file_replaced_then_back_into_D': ({'d/g': 'OLD\n'},
		[('w', 'f', 'new\n'), ('mv', 'f', 'd/g'), ('mv', 'd', 'D'), ('mv', 'D/g', 'D/h')],
		[(False, 'create', 'f', None), (False, 'move', 'd/g', 'f'), (True, 'move', 'D', 'd'), (False, 'move', 'D/h', 'D/g')]),
	'two_folder_moves': ({'d/': None}, [('w', 'f', 'new\n'), ('mv', 'f', 'd/g'), ('mv', 'd', 'D'), ('mv', 'D', 'E'), ('mv', 'E/g', 'h')],
		[(False, 'create', 'f', None), (False, 'move', 'd/g', 'f'), (True, 'move', 'D', 'd'), (True, 'move', 'E', 'D'), (False, 'move', 'h', 'E/g')]),
	'moved_on_twice': ({'d/': None}, [('w', 'f', 'new\n'), ('mv', 'f', 'd/g'), ('mv', 'd', 'D'), ('mv', 'D/g', 'h'), ('mv', 'h', 'k')],
		[(False, 'create', 'f', None), (False, 'move', 'd/g', 'f'), (True, 'move', 'D', 'd'), (False, 'move', 'h', 'D/g'), (False, 'move', 'k', 'h')]),
	'moved_out_then_its_folder_moved': ({'d/': None, 'e/': None},
		[('w', 'f', 'new\n'), ('mv', 'f', 'd/g'), ('mv', 'd', 'D'), ('mv', 'D/g', 'e/h'), ('mv', 'e', 'E')],
		[(False, 'create', 'f', None), (False, 'move', 'd/g', 'f'), (True, 'move', 'D', 'd'), (False, 'move', 'e/h', 'D/g'), (True, 'move', 'E', 'e')]),
	'moved_out_then_removed': ({'d/': None}, [('w', 'f', 'new\n'), ('mv', 'f', 'd/g'), ('mv', 'd', 'D'), ('mv', 'D/g', 'h'), ('rm', 'h')],
		[(False, 'create', 'f', None), (False, 'move', 'd/g', 'f'), (True, 'move', 'D', 'd'), (False, 'move', 'h', 'D/g'), (False, 'delete', 'h', None)]),
	'chmod_between': ({'d/': None}, [('w', 'f', 'new\n'), ('mv', 'f', 'd/g'), ('mv', 'd', 'D'), ('chmod', 'D/g'), ('mv', 'D/g', 'h')],
		[(False, 'create', 'f', None), (False, 'move', 'd/g', 'f'), (True, 'move', 'D', 'd'), (False, 'attrib', 'D/g', None), (False, 'move', 'h', 'D/g')]),
	'save_between': ({'d/': None}, [('w', 'f', 'new\n'), ('mv', 'f', 'd/g'), ('mv', 'd', 'D'), ('w', 'D/g', 'again\n'), ('mv', 'D/g', 'h')],
		[(False, 'create', 'f', None), (False, 'move', 'd/g', 'f'), (True, 'move', 'D', 'd'), (False, 'modify', 'D/g', None), (False, 'move', 'h', 'D/g')]),
	'existing_file_control': ({'d/': None, 'f': 'old\n'}, [('mv', 'f', 'd/g'), ('mv', 'd', 'D'), ('mv', 'D/g', 'h')],
		[(False, 'move', 'd/g', 'f'), (True, 'move', 'D', 'd'), (False, 'move', 'h', 'D/g')]),
	# another file moved out of D/g before the copy's folder move reaches it
	'other_out_first_rmdir': ({'d/': None, 'D/g': 'OLD\n'},
		[('w', 'f', 'new\n'), ('mv', 'f', 'd/g'), ('mv', 'D/g', 'z'), ('rmdir', 'D'), ('mv', 'd', 'D'), ('mv', 'D/g', 'h')],
		[(False, 'create', 'f', None), (False, 'move', 'd/g', 'f'), (False, 'move', 'z', 'D/g'), (True, 'delete', 'D', None), (True, 'move', 'D', 'd'),
		(False, 'move', 'h', 'D/g')]),
	'other_out_first_onto_empty': ({'d/': None, 'D/g': 'OLD\n'},
		[('w', 'f', 'new\n'), ('mv', 'f', 'd/g'), ('mv', 'D/g', 'z'), ('mv', 'd', 'D'), ('mv', 'D/g', 'h')],
		[(False, 'create', 'f', None), (False, 'move', 'd/g', 'f'), (False, 'move', 'z', 'D/g'), (True, 'move', 'D', 'd'), (False, 'move', 'h', 'D/g')]),
	# the older file at d/g moved away before the new file takes its name, out of the folder or within it
	'older_moved_away_first': ({'d/g': 'OLD\n'},
		[('mv', 'd/g', 'x'), ('w', 'f', 'new\n'), ('mv', 'f', 'd/g'), ('mv', 'd', 'D'), ('mv', 'D/g', 'h')],
		[(False, 'move', 'x', 'd/g'), (False, 'create', 'f', None), (False, 'move', 'd/g', 'f'), (True, 'move', 'D', 'd'), (False, 'move', 'h', 'D/g')]),
	'older_moved_in_folder_first': ({'d/g': 'OLD\n'},
		[('mv', 'd/g', 'd/x'), ('w', 'f', 'new\n'), ('mv', 'f', 'd/g'), ('mv', 'd', 'D'), ('mv', 'D/g', 'h')],
		[(False, 'move', 'd/x', 'd/g'), (False, 'create', 'f', None), (False, 'move', 'd/g', 'f'), (True, 'move', 'D', 'd'), (False, 'move', 'h', 'D/g')]),
	'back_into_folder_then_folder_moves': ({'d/': None},
		[('w', 'f', 'new\n'), ('mv', 'f', 'd/g'), ('mv', 'd', 'D'), ('mv', 'D/g', 'D/h'), ('mv', 'D', 'E')],
		[(False, 'create', 'f', None), (False, 'move', 'd/g', 'f'), (True, 'move', 'D', 'd'), (False, 'move', 'D/h', 'D/g'), (True, 'move', 'E', 'D')]),
	# moved out, then a new file at D/g also moved out
	'two_files_through_D_g': ({'d/': None},
		[('w', 'f', 'new\n'), ('mv', 'f', 'd/g'), ('mv', 'd', 'D'), ('mv', 'D/g', 'h'), ('w', 'D/g', 'two\n'), ('mv', 'D/g', 'k')],
		[(False, 'create', 'f', None), (False, 'move', 'd/g', 'f'), (True, 'move', 'D', 'd'), (False, 'move', 'h', 'D/g'), (False, 'create', 'D/g', None),
		(False, 'move', 'k', 'D/g')]),
	'out_and_back': ({'d/': None},
		[('w', 'f', 'new\n'), ('mv', 'f', 'd/g'), ('mv', 'd', 'D'), ('mv', 'D/g', 'h'), ('mv', 'h', 'D/g')],
		[(False, 'create', 'f', None), (False, 'move', 'd/g', 'f'), (True, 'move', 'D', 'd'), (False, 'move', 'h', 'D/g'), (False, 'move', 'D/g', 'h')]),
	'onto_existing': ({'d/': None, 'h': 'OLDH\n'},
		[('w', 'f', 'new\n'), ('mv', 'f', 'd/g'), ('mv', 'd', 'D'), ('mv', 'D/g', 'h')],
		[(False, 'create', 'f', None), (False, 'move', 'd/g', 'f'), (True, 'move', 'D', 'd'), (False, 'move', 'h', 'D/g')]),
	'folder_moved_away_then_remade': ({'d/g': 'OLD\n'},
		[('mv', 'd', 'e'), ('mkdir', 'd'), ('w', 'f', 'new\n'), ('mv', 'f', 'd/g'), ('mv', 'd', 'D'), ('mv', 'D/g', 'h')],
		[(True, 'move', 'e', 'd'), (True, 'create', 'd', None), (False, 'create', 'f', None), (False, 'move', 'd/g', 'f'), (True, 'move', 'D', 'd'),
		(False, 'move', 'h', 'D/g')]),
	'saved_after_move_out': ({'d/': None},
		[('w', 'f', 'new\n'), ('mv', 'f', 'd/g'), ('mv', 'd', 'D'), ('mv', 'D/g', 'h'), ('w', 'h', 'again\n')],
		[(False, 'create', 'f', None), (False, 'move', 'd/g', 'f'), (True, 'move', 'D', 'd'), (False, 'move', 'h', 'D/g'), (False, 'modify', 'h', None)]),
	'chmod_after_move_out': ({'d/': None},
		[('w', 'f', 'new\n'), ('mv', 'f', 'd/g'), ('mv', 'd', 'D'), ('mv', 'D/g', 'h'), ('chmod', 'h')],
		[(False, 'create', 'f', None), (False, 'move', 'd/g', 'f'), (True, 'move', 'D', 'd'), (False, 'move', 'h', 'D/g'), (False, 'attrib', 'h', None)]),
	'into_moved_folder_again': ({'d/': None, 'e/': None},
		[('w', 'f', 'new\n'), ('mv', 'f', 'd/g'), ('mv', 'd', 'D'), ('mv', 'D/g', 'e/h'), ('mv', 'e', 'E'), ('mv', 'E/h', 'k')],
		[(False, 'create', 'f', None), (False, 'move', 'd/g', 'f'), (True, 'move', 'D', 'd'), (False, 'move', 'e/h', 'D/g'), (True, 'move', 'E', 'e'),
		(False, 'move', 'k', 'E/h')]),
	'move_onto_then_rm': ({'a': 'A\n', 'q': 'Q\n'}, [('mv', 'q', 'a'), ('rm', 'a')],
		[(False, 'move', 'a', 'q'), (False, 'delete', 'a', None)]),
	'moved_onto_first': ({'d/g': 'OLD\n', 'q': 'Q\n'},
		[('mv', 'q', 'd/g'), ('w', 'f', 'new\n'), ('mv', 'f', 'd/g'), ('mv', 'd', 'D'), ('mv', 'D/g', 'h')],
		[(False, 'move', 'd/g', 'q'), (False, 'create', 'f', None), (False, 'move', 'd/g', 'f'), (True, 'move', 'D', 'd'), (False, 'move', 'h', 'D/g')]),
	'folder_made_in_batch': ({},
		[('mkdir', 'd'), ('w', 'f', 'new\n'), ('mv', 'f', 'd/g'), ('mv', 'd', 'D'), ('mv', 'D/g', 'h')],
		[(True, 'create', 'd', None), (False, 'create', 'f', None), (False, 'move', 'd/g', 'f'), (True, 'move', 'D', 'd'), (False, 'move', 'h', 'D/g')]),
	# a folder made in the batch, with a new file in it, moved the same way
	'folder_escalated_new_inside': ({'d/': None},
		[('mkdir', 'x'), ('w', 'x/f', 'new\n'), ('mv', 'x', 'd/x'), ('mv', 'd', 'D'), ('mv', 'D/x', 'h')],
		[(True, 'create', 'x', None), (False, 'create', 'x/f', None), (True, 'move', 'd/x', 'x'), (True, 'move', 'D', 'd'), (True, 'move', 'h', 'D/x')]),
	'back_to_first_destination': ({'d/': None},
		[('w', 'f', 'new\n'), ('mv', 'f', 'd/g'), ('mv', 'd', 'D'), ('mv', 'D/g', 'x'), ('mv', 'D', 'd'), ('mv', 'x', 'd/g')],
		[(False, 'create', 'f', None), (False, 'move', 'd/g', 'f'), (True, 'move', 'D', 'd'), (False, 'move', 'x', 'D/g'), (True, 'move', 'd', 'D'),
		(False, 'move', 'd/g', 'x')]),
	'two_new_files_one_folder': ({'d/': None},
		[('w', 'f1', '1\n'), ('w', 'f2', '2\n'), ('mv', 'f1', 'd/a'), ('mv', 'f2', 'd/b'), ('mv', 'd', 'D'), ('mv', 'D/a', 'h1'), ('mv', 'D/b', 'h2')],
		[(False, 'create', 'f1', None), (False, 'create', 'f2', None), (False, 'move', 'd/a', 'f1'), (False, 'move', 'd/b', 'f2'), (True, 'move', 'D', 'd'),
		(False, 'move', 'h1', 'D/a'), (False, 'move', 'h2', 'D/b')]),
	'nested_folder_moves': ({'d/e/': None},
		[('w', 'f', 'new\n'), ('mv', 'f', 'd/e/g'), ('mv', 'd', 'D'), ('mv', 'D/e', 'E'), ('mv', 'E/g', 'h')],
		[(False, 'create', 'f', None), (False, 'move', 'd/e/g', 'f'), (True, 'move', 'D', 'd'), (True, 'move', 'E', 'D/e'), (False, 'move', 'h', 'E/g')]),
	'older_at_end_path': ({'d/': None, 'h': 'OLDH\n', 'k': 'K\n'},
		[('w', 'f', 'new\n'), ('mv', 'f', 'd/g'), ('mv', 'd', 'D'), ('mv', 'h', 'k'), ('mv', 'D/g', 'h')],
		[(False, 'create', 'f', None), (False, 'move', 'd/g', 'f'), (True, 'move', 'D', 'd'), (False, 'move', 'k', 'h'), (False, 'move', 'h', 'D/g')]),
}
# without the verification these keep the version's older file under a move onto it then removed ( mv q a; rm a ), left open
BARE_DIFFERS = {'move_onto_then_rm', 'moved_onto_first'}


@pytest.mark.parametrize('with_verification', [True, False], ids=['verified', 'bare'])
@pytest.mark.parametrize('name', sorted(CASES))
def test_a_file_made_in_the_batch_moved_through_folder_moves_is_copied_where_it_ends(job, logged, name, with_verification):
	seed, steps, events = CASES[name]
	seed_monitor(job, seed)
	run_backup(job)
	apply(job.monitor, steps)
	del logged[:]
	v = verified(job, *events) if with_verification else run_backup(job, batch(job, *events))[-1]
	assert not fallbacks(logged), fallbacks(logged)
	if with_verification or name not in BARE_DIFFERS:
		assert_version_is_the_tree(job, v)


def test_the_minimal_batch_copies_h_and_leaves_nothing_at_D_g(job, logged):
	# the investigation's reproduction: today the rename of D/g to h fails with a traceback and the fallback copies h
	seed_monitor(job, {'d/': None})
	run_backup(job)
	apply(job.monitor, [('w', 'f', 'new\n'), ('mv', 'f', 'd/g'), ('mv', 'd', 'D'), ('mv', 'D/g', 'h')])
	del logged[:]
	v = verified(job, (False, 'create', 'f', None), (False, 'move', 'd/g', 'f'), (True, 'move', 'D', 'd'), (False, 'move', 'h', 'D/g'))
	assert open(os.path.join(v, 'h')).read() == 'new\n'
	assert not os.path.lexists(os.path.join(v, 'D/g')) and os.path.isdir(os.path.join(v, 'D'))
	assert not fallbacks(logged), fallbacks(logged)


@pytest.mark.parametrize('with_verification', [True, False], ids=['verified', 'bare'])
def test_a_file_the_version_holds_moved_the_same_way_stays_a_link(job, logged, with_verification):
	seed_monitor(job, {'d/': None, 'f': 'old\n'})
	run_backup(job)
	apply(job.monitor, [('mv', 'f', 'd/g'), ('mv', 'd', 'D'), ('mv', 'D/g', 'h')])
	del logged[:]
	events = [(False, 'move', 'd/g', 'f'), (True, 'move', 'D', 'd'), (False, 'move', 'h', 'D/g')]
	v = verified(job, *events) if with_verification else run_backup(job, batch(job, *events))[-1]
	assert os.path.islink(os.path.join(v, 'h')) and open(os.path.join(v, 'h')).read() == 'old\n'
	assert not fallbacks(logged), fallbacks(logged)


# the probe's alpha writer log between its two backups ( its steps 1-71 ) and the watcher's events of the second batch
PROBE_STEPS = [
	'create empty/new1.txt', 'create sub/new3.txt', 'create new5.txt', 'create sub/deeper/new7.txt',
	'create empty/new9.txt', 'create empty/new11.txt', 'create sub/new13.txt', 'delete empty/new9.txt',
	'save sub/new13.txt', 'save sub/deeper/new7.txt', 'mkdir dir17/', 'delete empty/new11.txt',
	'create sub/new18.txt', 'rename z.bin -> dir17/mv20.txt', 'create new21.txt', 'create sub/new23.txt', 'noop',
	'save sub/new18.txt', 'rename a.txt -> sub/deeper/mv26.txt', 'delete sub/new13.txt', 'delete sub/new23.txt',
	'save sub/deeper/c.txt', 'mkdir dir28/', 'save sub/deeper/new7.txt', 'rename empty/new1.txt -> dir28/mv30.txt',
	'delete sub/b.txt', 'create sub/deeper/new31.txt', 'save sub/new18.txt', 'mkdir dir34/', 'save dir17/mv20.txt',
	'mkdir dir36/', 'create dir36/new37.txt', 'delete dir17/mv20.txt', 'rename new5.txt -> dir36/mv39.txt',
	'chmod new21.txt 0o755', 'save sub/deeper/new7.txt', 'delete sub/deeper/new7.txt', 'create dir17/new41.txt',
	'chmod dir17/new41.txt 0o664', 'rename dir28/mv30.txt -> sub/mv43.txt', 'delete dir36/new37.txt', 'noop',
	'create sub/deeper/new44.txt', 'create sub/deeper/new46.txt', 'rename folder dir28/ -> mvdir48/',
	'create new49.txt', 'create dir17/new51.txt', 'save sub/new18.txt', 'create sub/new54.txt',
	'chmod sub/new18.txt 0o664', 'chmod sub/deeper/new46.txt 0o755', 'mkdir dir56/', 'save sub/new54.txt',
	'rename dir17/new51.txt -> dir56/mv58.txt', 'rename folder sub/ -> mvdir59/',
	'rename new49.txt -> dir17/mv60.txt', 'create new61.txt', 'rename folder dir17/ -> mvdir63/',
	'save mvdir59/deeper/new31.txt', 'noop', 'rename folder mvdir48/ -> mvdir65/', 'create new66.txt',
	'create empty/new68.txt', 'delete dir36/mv39.txt', 'mkdir dir70/', 'rename mvdir63/mv60.txt -> empty/mv71.txt',
	'delete new61.txt', 'create dir36/new72.txt', 'create mvdir65/new74.txt',
	'rename mvdir59/deeper/c.txt -> dir36/mv76.txt', 'mkdir dir77/',
]
PROBE_EVENTS = [
	(False, 'create', 'sub/deeper/new44.txt', None),
	(False, 'create', 'sub/deeper/new46.txt', None),
	(True, 'move', 'mvdir48', 'dir28'),
	(False, 'create', 'new49.txt', None),
	(False, 'create', 'dir17/new51.txt', None),
	(False, 'create', 'sub/new18.txt', None),
	(False, 'create', 'sub/new54.txt', None),
	(False, 'attrib', 'sub/new18.txt', None),
	(False, 'attrib', 'sub/deeper/new46.txt', None),
	(True, 'create', 'dir56', None),
	(False, 'create', 'sub/new54.txt', None),
	(True, 'move', 'mvdir59', 'sub'),
	(False, 'move', 'dir17/mv60.txt', 'new49.txt'),
	(False, 'create', 'new61.txt', None),
	(True, 'move', 'mvdir63', 'dir17'),
	(False, 'create', 'mvdir59/deeper/new31.txt', None),
	(True, 'move', 'mvdir65', 'mvdir48'),
	(False, 'create', 'new66.txt', None),
	(False, 'create', 'empty/new68.txt', None),
	(False, 'delete', 'dir36/mv39.txt', None),
	(True, 'create', 'dir70', None),
	(False, 'move', 'empty/mv71.txt', 'mvdir63/mv60.txt'),
	(False, 'delete', 'new61.txt', None),
	(False, 'create', 'dir36/new72.txt', None),
	(False, 'create', 'mvdir65/new74.txt', None),
	(False, 'move', 'dir36/mv76.txt', 'mvdir59/deeper/c.txt'),
	(True, 'create', 'dir77', None),
	(False, 'delete', 'dir17/new51.txt', None),
]


def probe_step(monitor:str, what:str) -> None:
	'''Make one step of the probe's writer log in monitor.'''
	kind, _, rest = what.partition(' ')
	if kind in ('create', 'save'):
		with open(os.path.join(monitor, rest), 'w') as f:
			f.write(f'{what}\n')
	elif kind == 'chmod':
		rel, mode = rest.rsplit(' ', 1)
		os.chmod(os.path.join(monitor, rel), int(mode, 8))
	elif kind == 'delete':
		os.remove(os.path.join(monitor, rest))
	elif kind == 'rename':
		if rest.startswith('folder '):
			rest = rest[len('folder '):]
		a, b = rest.split(' -> ')
		os.rename(os.path.join(monitor, a.rstrip('/')), os.path.join(monitor, b.rstrip('/')))
	elif kind == 'mkdir':
		os.mkdir(os.path.join(monitor, rest.rstrip('/')))
	elif kind == 'rmdir':
		os.rmdir(os.path.join(monitor, rest.rstrip('/')))
	else:
		assert what == 'noop', what


def test_the_probe_batch_replays_without_a_rename_fallback(job, logged):
	# new49.txt is made, moved into dir17, dir17 moved to mvdir63, then the file moved on to empty/mv71.txt. the
	# watcher's late delete of dir17/new51.txt ( event 28, under its folder's old name ) still logs Not tracking
	# mvdir63/new51.txt, which is not this batch's rename
	seed_monitor(job, {'a.txt': 'a', 'sub/b.txt': 'b', 'sub/deeper/c.txt': 'c', 'empty/': None, 'z.bin': 'z' * 300})
	run_backup(job)
	for what in PROBE_STEPS[:41]:
		probe_step(job.monitor, what)
	run_backup(job)
	for what in PROBE_STEPS[41:]:
		probe_step(job.monitor, what)
	del logged[:]
	v = verified(job, *PROBE_EVENTS)
	assert_version_is_the_tree(job, v)
	assert open(os.path.join(v, 'empty/mv71.txt')).read() == 'create new49.txt\n'
	assert not [l for l in logged if 'Failed to move' in l or 'Traceback' in l or NOT_IN_VERSION in l or 'Not tracking mvdir63/mv60.txt' in l]
