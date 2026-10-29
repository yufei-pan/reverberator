# Batches where a file made or saved in the batch is moved into a folder, the folder is moved, and the file is moved on
# again: the collapse copies it where it ends, so the replay never renames a path the version does not hold.
import errno
import os
import pytest
import reverberator as rv
from tests.harness import seed_monitor, run_backup
from tests.test_moves_then_changes import BAD_LINES, batch, logged, verified, assert_version_is_the_tree  # noqa: F401

pytestmark = pytest.mark.unit

NOT_IN_VERSION = 'is not in the version; copying it instead'


def fallbacks(lines:list) -> list:
	'''The first line of each logged line of an error, a traceback, or a rename or copy that found nothing.'''
	return [line.splitlines()[0] for line in lines if line.startswith('ERROR ') or
		any(word in line for word in ('Traceback', NOT_IN_VERSION, 'Not tracking', 'Cannot read', *BAD_LINES))]


def warned(lines:list) -> list:
	'''The first line of each logged line of a rename that found nothing and was copied instead.'''
	return [line.splitlines()[0] for line in lines if NOT_IN_VERSION in line]


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
	# the older file at d/g, or its folder, moved away after the new file was made and before it took the name: an
	# editor's save with a backup, then the folder moved and the file out; and the same through a chain ( f -> x -> d/g )
	'backup_save_then_folder_moves': ({'d/g': 'OLD\n'},
		[('w', 'f', 'new\n'), ('mv', 'd/g', 'y'), ('mv', 'f', 'd/g'), ('mv', 'd', 'D'), ('mv', 'D/g', 'h')],
		[(False, 'create', 'f', None), (False, 'move', 'y', 'd/g'), (False, 'move', 'd/g', 'f'), (True, 'move', 'D', 'd'), (False, 'move', 'h', 'D/g')]),
	'older_folder_out_after_create': ({'d/g': 'OLD\n'},
		[('w', 'f', 'new\n'), ('mv', 'd', 'e'), ('mkdir', 'd'), ('mv', 'f', 'd/g'), ('mv', 'd', 'D'), ('mv', 'D/g', 'h')],
		[(False, 'create', 'f', None), (True, 'move', 'e', 'd'), (True, 'create', 'd', None), (False, 'move', 'd/g', 'f'), (True, 'move', 'D', 'd'),
		(False, 'move', 'h', 'D/g')]),
	'older_out_between_chain': ({'d/g': 'OLD\n'},
		[('w', 'f', 'new\n'), ('mv', 'f', 'x'), ('mv', 'd/g', 'y'), ('mv', 'x', 'd/g'), ('mv', 'd', 'D'), ('mv', 'D/g', 'h')],
		[(False, 'create', 'f', None), (False, 'move', 'x', 'f'), (False, 'move', 'y', 'd/g'), (False, 'move', 'd/g', 'x'), (True, 'move', 'D', 'd'),
		(False, 'move', 'h', 'D/g')]),
	'older_folder_out_between_chain': ({'d/g': 'OLD\n'},
		[('w', 'f', 'new\n'), ('mv', 'f', 'x'), ('mv', 'd', 'e'), ('mkdir', 'd'), ('mv', 'x', 'd/g'), ('mv', 'd', 'D'), ('mv', 'D/g', 'h')],
		[(False, 'create', 'f', None), (False, 'move', 'x', 'f'), (True, 'move', 'e', 'd'), (True, 'create', 'd', None), (False, 'move', 'd/g', 'x'),
		(True, 'move', 'D', 'd'), (False, 'move', 'h', 'D/g')]),
	# moved on and back to its first destination, which another folder took in the meantime
	'back_to_first_destination_in_another_folder': ({'e/': None, 'E/D/': None},
		[('w', 'e/g', 'new\n'), ('mv', 'e/g', 'e/d'), ('mv', 'e', 'E/g'), ('mv', 'E/g/d', 'E/D/d'), ('mv', 'E/D', 'e')],
		[(False, 'create', 'e/g', None), (False, 'move', 'e/d', 'e/g'), (True, 'move', 'E/g', 'e'), (False, 'move', 'E/D/d', 'E/g/d'), (True, 'move', 'e', 'E/D')]),
	# the same editor's save, then the copy removed after a folder move carried it; and with the older file's folder moved
	# away before the copy came, and with the folder moved before the save
	'backup_save_then_folder_moved_then_removed': ({'d/g': 'OLD\n'},
		[('w', 'f', 'new\n'), ('mv', 'd/g', 'y'), ('mv', 'f', 'd/g'), ('mv', 'd', 'D'), ('rm', 'D/g')],
		[(False, 'create', 'f', None), (False, 'move', 'y', 'd/g'), (False, 'move', 'd/g', 'f'), (True, 'move', 'D', 'd'), (False, 'delete', 'D/g', None)]),
	'older_folder_out_then_removed': ({'d/g': 'OLD\n'},
		[('w', 'f', 'new\n'), ('mv', 'd', 'e'), ('mkdir', 'd'), ('mv', 'f', 'd/g'), ('mv', 'd', 'D'), ('rm', 'D/g')],
		[(False, 'create', 'f', None), (True, 'move', 'e', 'd'), (True, 'create', 'd', None), (False, 'move', 'd/g', 'f'), (True, 'move', 'D', 'd'),
		(False, 'delete', 'D/g', None)]),
	'folder_moved_then_backup_save_then_removed': ({'d/g': 'OLD\n'},
		[('mv', 'd', 'D'), ('w', 'f', 'new\n'), ('mv', 'D/g', 'y'), ('mv', 'f', 'D/g'), ('rm', 'D/g')],
		[(True, 'move', 'D', 'd'), (False, 'create', 'f', None), (False, 'move', 'y', 'D/g'), (False, 'move', 'D/g', 'f'), (False, 'delete', 'D/g', None)]),
	# the new file overwritten after the version's file at its first destination was replaced and then moved out ( mv g a;
	# mv a D ), or moved out by a chain the save made a copy of: nothing renames the version's file, so its delete stays
	'replaced_then_moved_out_then_overwritten': ({'g': 'seed g\n', 'a': 'seed a\n', 'b': 'seed b\n'},
		[('w', 'g', 'save 1\n'), ('chmod', 'b'), ('mkdir', 'd'), ('w', 'h', 'new 5\n'), ('mv', 'g', 'a'), ('mv', 'a', 'D'), ('mv', 'h', 'a'), ('mv', 'D', 'a'),
		('mv', 'a', 'g'), ('w', 'b', 'save 14\n'), ('mv', 'g', 'd/g')],
		[(False, 'modify', 'g', None), (False, 'attrib', 'b', None), (True, 'create', 'd', None), (False, 'create', 'h', None), (False, 'move', 'a', 'g'),
		(False, 'move', 'D', 'a'), (False, 'move', 'a', 'h'), (False, 'move', 'a', 'D'), (False, 'move', 'g', 'a'), (False, 'modify', 'b', None),
		(False, 'move', 'd/g', 'g')]),
	'saved_moved_out_then_overwritten': ({'g': 'seed g\n', 'h': 'seed h\n', 'a': 'seed a\n'},
		[('w', 'd', 'new 2\n'), ('w', 'a', 'save 3\n'), ('mv', 'a', 'D'), ('rm', 'h'), ('chmod', 'g'), ('rm', 'g'), ('mv', 'd', 'a'), ('w', 'e', 'new 10\n'),
		('mv', 'D', 'a'), ('mv', 'a', 'b'), ('mv', 'e', 'E')],
		[(False, 'create', 'd', None), (False, 'modify', 'a', None), (False, 'move', 'D', 'a'), (False, 'delete', 'h', None), (False, 'attrib', 'g', None),
		(False, 'delete', 'g', None), (False, 'move', 'a', 'd'), (False, 'create', 'e', None), (False, 'move', 'a', 'D'), (False, 'move', 'b', 'a'),
		(False, 'move', 'E', 'e')]),
}
# where the older file of those cases is in the end: its own move keeps its chain link
OLDER_MOVED_AWAY = {'backup_save_then_folder_moves': 'y', 'older_folder_out_after_create': 'e/g', 'older_out_between_chain': 'y',
	'older_folder_out_between_chain': 'e/g', 'backup_save_then_folder_moved_then_removed': 'y', 'older_folder_out_then_removed': 'e/g',
	'folder_moved_then_backup_save_then_removed': 'y'}
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
	if name in OLDER_MOVED_AWAY:
		assert os.path.islink(os.path.join(v, OLDER_MOVED_AWAY[name])) and open(os.path.join(v, OLDER_MOVED_AWAY[name])).read() == 'OLD\n'


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


# a folder of the version that a file or folder is moved out of and that is then removed ( mv d/g y; rm -r d ): its
# delete replays after the moves out of it, so they rename what the version holds there
EMPTIED = {
	# name: (seed, steps, the watcher's events of the steps, the moved-out entries that keep their links)
	'file_out': ({'d/g': 'G\n', 'd/k': 'K\n'}, [('mv', 'd/g', 'y'), ('rm', 'd/k'), ('rmdir', 'd')],
		[(False, 'move', 'y', 'd/g'), (False, 'delete', 'd/k', None), (True, 'delete', 'd', None)], ['y']),
	'folder_out': ({'d/s/a': 'A\n', 'd/k': 'K\n'}, [('mv', 'd/s', 'z'), ('rm', 'd/k'), ('rmdir', 'd')],
		[(True, 'move', 'z', 'd/s'), (False, 'delete', 'd/k', None), (True, 'delete', 'd', None)], ['z/a']),
	'several_out': ({'d/g1': 'G1\n', 'd/g2': 'G2\n', 'd/s/a': 'A\n', 'd/k': 'K\n'},
		[('mv', 'd/g1', 'y1'), ('mv', 'd/s', 'z'), ('mv', 'd/g2', 'y2'), ('rm', 'd/k'), ('rmdir', 'd')],
		[(False, 'move', 'y1', 'd/g1'), (True, 'move', 'z', 'd/s'), (False, 'move', 'y2', 'd/g2'), (False, 'delete', 'd/k', None),
		(True, 'delete', 'd', None)], ['y1', 'y2', 'z/a']),
	'moved_in_then_carried_out': ({'d/s/a': 'A\n', 'd/k': 'K\n', 'e/f': 'F\n'},
		[('mv', 'e', 'd/s/b'), ('mv', 'd/s', 'z'), ('rm', 'd/k'), ('rmdir', 'd')],
		[(True, 'move', 'd/s/b', 'e'), (True, 'move', 'z', 'd/s'), (False, 'delete', 'd/k', None), (True, 'delete', 'd', None)], ['z/a', 'z/b/f']),
	'out_of_a_subfolder': ({'d/e/g': 'G\n', 'd/e/k': 'K\n', 'd/k': 'K\n'},
		[('mv', 'd/e/g', 'y'), ('rm', 'd/e/k'), ('rmdir', 'd/e'), ('rm', 'd/k'), ('rmdir', 'd')],
		[(False, 'move', 'y', 'd/e/g'), (False, 'delete', 'd/e/k', None), (True, 'delete', 'd/e', None), (False, 'delete', 'd/k', None),
		(True, 'delete', 'd', None)], ['y']),
	# the folder remade after: the collapse folds its delete into the folder's create, which keeps these as they were
	'remade_and_refilled': ({'d/g': 'G\n', 'd/k': 'K\n'},
		[('mv', 'd/g', 'y'), ('rm', 'd/k'), ('rmdir', 'd'), ('mkdir', 'd'), ('w', 'd/n', 'x\n')],
		[(False, 'move', 'y', 'd/g'), (False, 'delete', 'd/k', None), (True, 'delete', 'd', None), (True, 'create', 'd', None),
		(False, 'create', 'd/n', None)], ['y']),
	'moved_into_after': ({'d/g': 'G\n', 'd/k': 'K\n', 'q': 'Q\n'},
		[('mv', 'd/g', 'y'), ('rm', 'd/k'), ('rmdir', 'd'), ('mkdir', 'd'), ('mv', 'q', 'd/q')],
		[(False, 'move', 'y', 'd/g'), (False, 'delete', 'd/k', None), (True, 'delete', 'd', None), (True, 'create', 'd', None),
		(False, 'move', 'd/q', 'q')], ['y', 'd/q']),
	# a folder moved onto the removed one's parent after the delete, then a file moved out of the new folder at the
	# removed one's path ( rm -rf site; mv site.new site; mv site/assets/x elsewhere ): the delete is the old folder's
	'ancestor_moved_in_then_out': ({'d/s/g0': 'G0\n', 'x/s/g': 'XG\n', 'x/s/h': 'XH\n'},
		[('rm', 'd/s/g0'), ('rmdir', 'd/s'), ('rmdir', 'd'), ('mv', 'x', 'd'), ('mv', 'd/s/g', 'y')],
		[(False, 'delete', 'd/s/g0', None), (True, 'delete', 'd/s', None), (True, 'delete', 'd', None), (True, 'move', 'd', 'x'),
		(False, 'move', 'y', 'd/s/g')], ['y', 'd/s/h']),
	'ancestor_replaced_then_out': ({'d/s/g0': 'G0\n', 'd/k': 'K\n', 'x/s/g': 'XG\n', 'x/s/h': 'XH\n'},
		[('rm', 'd/s/g0'), ('rmdir', 'd/s'), ('mv', 'd', 'D'), ('mv', 'x', 'd'), ('mv', 'd/s/g', 'y')],
		[(False, 'delete', 'd/s/g0', None), (True, 'delete', 'd/s', None), (True, 'move', 'D', 'd'), (True, 'move', 'd', 'x'),
		(False, 'move', 'y', 'd/s/g')], ['y', 'd/s/h', 'D/k']),
	# a file made in the removed folder's place, which the collapse keeps beside the folder's delete
	'file_in_its_place': ({'d/g': 'G\n', 'd/k': 'K\n'}, [('mv', 'd/g', 'y'), ('rm', 'd/k'), ('rmdir', 'd'), ('w', 'd', 'x\n')],
		[(False, 'move', 'y', 'd/g'), (False, 'delete', 'd/k', None), (True, 'delete', 'd', None), (False, 'create', 'd', None)], ['y']),
}


@pytest.mark.parametrize('with_verification', [True, False], ids=['verified', 'bare'])
@pytest.mark.parametrize('name', sorted(EMPTIED))
def test_a_folder_emptied_by_moves_then_removed_lets_them_rename(job, logged, name, with_verification):
	seed, steps, events, linked = EMPTIED[name]
	seed_monitor(job, seed)
	run_backup(job)
	apply(job.monitor, steps)
	del logged[:]
	v = verified(job, *events) if with_verification else run_backup(job, batch(job, *events))[-1]
	assert not fallbacks(logged), fallbacks(logged)
	assert_version_is_the_tree(job, v)
	for rel in linked:
		assert os.path.islink(os.path.join(v, rel)), rel


@pytest.mark.parametrize('with_verification', [True, False], ids=['verified', 'bare'])
def test_a_delete_under_a_folder_moved_after_it_stays_at_the_front(job, logged, with_verification):
	# mv d/s/g t; rm -r d/s; mv d D; mv t y: the collapse merges the chain to y <- d/s/g across the move of d ( the
	# rename finds nothing there, as 6fa2c69's does: the chain merge across a folder move ). The delete of d/s stays
	# before the move of d, which would otherwise carry the version's d/s to D/s, out of its reach
	seed_monitor(job, {'d/s/g': 'G\n', 'd/s/h': 'H\n', 'd/k': 'K\n'})
	run_backup(job)
	apply(job.monitor, [('mv', 'd/s/g', 't'), ('rm', 'd/s/h'), ('rmdir', 'd/s'), ('mv', 'd', 'D'), ('mv', 't', 'y')])
	del logged[:]
	events = [(False, 'move', 't', 'd/s/g'), (False, 'delete', 'd/s/h', None), (True, 'delete', 'd/s', None), (True, 'move', 'D', 'd'),
		(False, 'move', 'y', 't')]
	v = verified(job, *events) if with_verification else run_backup(job, batch(job, *events))[-1]
	assert len(warned(logged)) == 1 and fallbacks(logged) == warned(logged)       # the rename of the chain merge finds nothing
	assert_version_is_the_tree(job, v)
	assert os.path.islink(os.path.join(v, 'D/k'))


@pytest.mark.parametrize('is_dir', [False, True], ids=['file', 'folder'])
@pytest.mark.parametrize('moved_on', [False, True], ids=['stays', 'moved_on'])
def test_a_move_whose_source_never_reached_the_version_is_copied(job, logged, is_dir, moved_on):
	# a live race: batch 1's create of sub/x finds nothing, as x moved on before its copy ran; batch 2 moves it
	seed_monitor(job, {'sub/': None, 'd/': None})
	run_backup(job)
	if is_dir:
		apply(job.monitor, [('mkdir', 'sub/x'), ('w', 'sub/x/in', 'in\n')])
	else:
		apply(job.monitor, [('w', 'sub/x', 'new\n')])
	apply(job.monitor, [('mv', 'sub/x', 'd/y')] + ([('mv', 'd', 'D')] if moved_on else []))
	del logged[:]
	verified(job, (is_dir, 'create', 'sub/x', None))
	del logged[:]
	v2 = verified(job, (is_dir, 'move', 'd/y', 'sub/x'), *([(True, 'move', 'D', 'd')] if moved_on else []))
	assert len(warned(logged)) == 1
	assert fallbacks(logged) == warned(logged)          # no traceback, no ERROR line: no Not tracking, no Cannot read
	assert_version_is_the_tree(job, v2)


WARNED_ONCE = {
	# a move into, or out of, a folder the version holds elsewhere (a folder made in the batch, a chain merged across a
	# folder move), and the approved entry of docs/limitations.md
	'mkdir_then_mv_into_then_folder_moved': ({'old': 'old\n'}, [('mkdir', 'x'), ('mv', 'old', 'x/f'), ('mv', 'x', 'y')],
		[(True, 'create', 'x', None), (False, 'move', 'x/f', 'old'), (True, 'move', 'y', 'x')]),
	'chain_merge_across_a_folder_move': ({'a/f': 'f\n', 'a/k': 'k\n'}, [('mv', 'a/f', 'g'), ('mv', 'a', 'A'), ('mv', 'g', 'h')],
		[(False, 'move', 'g', 'a/f'), (True, 'move', 'A', 'a'), (False, 'move', 'h', 'g')]),
	'chain_merge_across_a_folder_move_then_moved_on_again': ({'a/f': 'f\n', 'a/k': 'k\n', 'e/': None},
		[('mv', 'a/f', 'g'), ('mv', 'a', 'A'), ('mv', 'g', 'e/h'), ('mv', 'e', 'E')],
		[(False, 'move', 'g', 'a/f'), (True, 'move', 'A', 'a'), (False, 'move', 'e/h', 'g'), (True, 'move', 'E', 'e')]),
	'approved_entry_mv_d_e_mkdir_e_sub_mv_x_e_sub_x': ({'d/': None, 'x': 'x\n'},
		[('mv', 'd', 'e'), ('mkdir', 'e/sub'), ('mv', 'x', 'e/sub/x')],
		[(True, 'move', 'e', 'd'), (True, 'create', 'e/sub', None), (False, 'move', 'e/sub/x', 'x')]),
}


@pytest.mark.parametrize('name', sorted(WARNED_ONCE))
def test_a_move_into_or_out_of_a_folder_the_version_has_elsewhere_is_copied_with_one_warning(job, logged, name):
	seed, steps, events = WARNED_ONCE[name]
	seed_monitor(job, seed)
	run_backup(job)
	apply(job.monitor, steps)
	del logged[:]
	v = verified(job, *events)
	assert len(warned(logged)) == 1 and fallbacks(logged) == warned(logged)
	assert_version_is_the_tree(job, v)


def test_a_folder_made_in_the_batch_with_an_old_file_and_a_new_one(job, logged):
	# the folder is copied whole (Task 1); the old file's move into it finds nothing, and warns once
	seed_monitor(job, {'d/': None, 'old': 'old\n'})
	run_backup(job)
	apply(job.monitor, [('mkdir', 'x'), ('w', 'x/n', 'n\n'), ('mv', 'old', 'x/o'), ('mv', 'x', 'd/x'), ('mv', 'd', 'D'), ('mv', 'D/x', 'h')])
	del logged[:]
	v = verified(job, (True, 'create', 'x', None), (False, 'create', 'x/n', None), (False, 'move', 'x/o', 'old'), (True, 'move', 'd/x', 'x'),
		(True, 'move', 'D', 'd'), (True, 'move', 'h', 'D/x'))
	assert len(warned(logged)) == 1 and fallbacks(logged) == warned(logged)
	assert_version_is_the_tree(job, v)


@pytest.mark.parametrize('error', ['permission', 'not_the_renames'])
def test_any_other_rename_error_keeps_the_traceback(job, logged, monkeypatch, error):
	seed_monitor(job, {'f': 'f\n'})
	run_backup(job)
	apply(job.monitor, [('mv', 'f', 'h')])
	real_rename = os.rename
	def rename(src, dst, *args, **kwargs):
		if str(dst).endswith(os.sep + 'h'):
			if error == 'permission':
				raise PermissionError(errno.EACCES, 'refused', src, None, dst)
			raise FileNotFoundError(errno.ENOENT, 'gone')
		return real_rename(src, dst, *args, **kwargs)
	monkeypatch.setattr(rv.os, 'rename', rename)
	del logged[:]
	v = verified(job, (False, 'move', 'h', 'f'))
	assert any(l.startswith('ERROR Failed to move') for l in logged) and any('Traceback' in l for l in logged)
	assert 'Doing delete & copy instead' in logged and not warned(logged)
	assert open(os.path.join(v, 'h')).read() == 'f\n'
