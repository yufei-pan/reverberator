import threading
from collections import deque, OrderedDict
import pytest
import reverberator as rv

pytestmark = pytest.mark.unit

P = '/tmp/reverb_events'


def _ev(t, is_dir, event, path, moved_from=None):
	return rv.ChangeEvent(float(t), is_dir, event, path, moved_from)


def test_chain_moves_keep_original_source():
	entries = rv.change_events_to_backup_entries(deque([
		_ev(1, False, 'move', f'{P}/b', f'{P}/a'),
		_ev(2, False, 'move', f'{P}/c', f'{P}/b'),
	]))
	assert f'{P}/c' in entries
	assert entries[f'{P}/c'].event == 'move'
	assert entries[f'{P}/c'].source_path == f'{P}/a'


def test_virgin_move_becomes_create():
	entries = rv.change_events_to_backup_entries(deque([
		_ev(1, False, 'move', f'{P}/a', None),
	]))
	assert entries[f'{P}/a'].event == 'create'


def test_delete_before_move_from_keeps_dest_move():
	entries = rv.change_events_to_backup_entries(deque([
		_ev(1, False, 'delete', f'{P}/a', None),
		_ev(2, False, 'move', f'{P}/b', f'{P}/a'),
	]))
	# A delete immediately before move-from is spurious: the path was later
	# moved, so dest stays a move (which relocates the referenced copy).
	assert f'{P}/a' not in entries
	assert entries[f'{P}/b'].event == 'move'
	assert entries[f'{P}/b'].source_path == f'{P}/a'


def test_delete_then_create_becomes_create():
	entries = rv.change_events_to_backup_entries(deque([
		_ev(1, False, 'delete', f'{P}/a', None),
		_ev(2, False, 'create', f'{P}/a', None),
	]))
	assert entries[f'{P}/a'].event == 'create'


def test_delete_then_create_then_modify_becomes_create():
	entries = rv.change_events_to_backup_entries(deque([
		_ev(1, False, 'delete', f'{P}/a', None),
		_ev(2, False, 'create', f'{P}/a', None),
		_ev(3, False, 'modify', f'{P}/a', None),
	]))
	assert entries[f'{P}/a'].event == 'create'


def test_delete_then_create_then_move_deletes_source_creates_dest():
	entries = rv.change_events_to_backup_entries(deque([
		_ev(1, False, 'delete', f'{P}/a', None),
		_ev(2, False, 'create', f'{P}/a', None),
		_ev(3, False, 'move', f'{P}/b', f'{P}/a'),
	]))
	# Recreate-then-move: dest copies the new file; source must still be
	# deleted so the referenced copy of the old path does not leak.
	assert entries[f'{P}/b'].event == 'create'
	assert entries[f'{P}/a'].event == 'delete'


def test_delete_then_modify_then_move_keeps_dest_modify():
	entries = rv.change_events_to_backup_entries(deque([
		_ev(1, False, 'delete', f'{P}/a', None),
		_ev(2, False, 'modify', f'{P}/a', None),
		_ev(3, False, 'move', f'{P}/b', f'{P}/a'),
	]))
	assert entries[f'{P}/b'].event == 'modify'
	assert entries[f'{P}/a'].event == 'delete'


def test_attrib_then_move_stays_a_move():
	entries = rv.change_events_to_backup_entries(deque([
		_ev(1, False, 'attrib', f'{P}/a', None),
		_ev(2, False, 'move', f'{P}/b', f'{P}/a'),
	]))
	# the move's own step syncs the attributes onto the moved link ( round 9 ): the move stays a move, not a copy
	assert list(entries) == [f'{P}/b']
	assert entries[f'{P}/b'].event == 'move'
	assert entries[f'{P}/b'].source_path == f'{P}/a'


def test_create_then_delete_cancels():
	entries = rv.change_events_to_backup_entries(deque([
		_ev(1, False, 'create', f'{P}/new', None),
		_ev(2, False, 'delete', f'{P}/new', None),
	]))
	assert entries == OrderedDict() or len(entries) == 0


def test_create_then_modify_stays_create():
	entries = rv.change_events_to_backup_entries(deque([
		_ev(1, False, 'create', f'{P}/new', None),
		_ev(2, False, 'modify', f'{P}/new', None),
	]))
	assert entries[f'{P}/new'].event == 'create'


def test_dir_paths_get_trailing_slash():
	entries = rv.change_events_to_backup_entries(deque([
		_ev(1, True, 'create', f'{P}/d', None),
	]))
	assert f'{P}/d/' in entries


def test_self_destruct_skipped():
	entries = rv.change_events_to_backup_entries(deque([
		_ev(1, True, 'self_destruct', P, None),
	]))
	assert len(entries) == 0


def test_backup_entries_round_trip_move_and_dir():
	original = rv.change_events_to_backup_entries(deque([
		_ev(1, True, 'create', f'{P}/d', None),
		_ev(2, False, 'move', f'{P}/b', f'{P}/a'),
	]))
	events = rv.backup_entries_to_change_events(original)
	by_path = {e.path.rstrip('/') + ('/' if e.is_dir else ''): e for e in events}
	assert by_path[f'{P}/d/'].is_dir is True
	assert by_path[f'{P}/d/'].event == 'create'
	assert by_path[f'{P}/b'].event == 'move'
	assert by_path[f'{P}/b'].moved_from == f'{P}/a'


def test_full_scan_replaces_queued_events_and_absorbs_later_ones():
	# the backuper compares the whole tree for a batch holding a full scan, which covers every other event in it
	queue = rv.ChangeEventQueue('/m')
	lock = threading.Lock()
	rv.append_change_event(queue, lock, rv.ChangeEvent(1.0, False, 'create', '/m/a', None))
	rv.append_change_event(queue, lock, rv.ChangeEvent(2.0, False, 'full_scan', '/m', None))
	rv.append_change_event(queue, lock, rv.ChangeEvent(3.0, False, 'modify', '/m/b', None))
	assert list(queue) == [rv.ChangeEvent(2.0, False, 'full_scan', '/m', None)]
	queue.prepend([rv.ChangeEvent(0.5, False, 'modify', '/m/c', None)])
	assert list(queue) == [rv.ChangeEvent(2.0, False, 'full_scan', '/m', None)] and queue.full_scan_requested


def collapsed(*events):
	'''The collapse of events (is_dir, event, rel, moved_from rel or None) at times 1, 2, ..., as (rel, event, source rel).'''
	entries = rv.change_events_to_backup_entries(deque(_ev(t, is_dir, event, f'{P}/{rel}', None if source is None else f'{P}/{source}')
		for t, (is_dir, event, rel, source) in enumerate(events, 1)))
	strip = lambda path: path and path.replace(f'{P}/', '', 1)
	return [(strip(path), values.event, strip(values.source_path)) for path, values in entries.items()]


def watched(form, *events):
	'''events with a modify after each create of a file in form 'create_modify', as the watcher queues them for a file
	written with text; 'create' leaves them as they are, as for an empty file.'''
	if form == 'create':
		return events
	return tuple(e for event in events for e in ([event, (False, 'modify', event[2], None)] if event[:2] == (False, 'create') else [event]))


# the escalated move of a file written in the batch: create alone gives a create where it ends; with the watcher's
# modify after it, the move is escalated once, by the modify, and comes out as the saved file's does
ESCALATED = {
	# echo new > f; mv f d/g; mv d D; mv D/g h: nothing in the version is at D/g to rename
	'moved_through_a_folder_move_and_out': ([(False, 'create', 'f', None), (False, 'move', 'd/g', 'f'), (True, 'move', 'D', 'd'),
		(False, 'move', 'h', 'D/g')],
		[('D/', 'move', 'd/'), ('d/g', 'delete', None), ('h', 'create', 'f')],
		[('f', 'delete', None), ('D/', 'move', 'd/'), ('d/g', 'delete', None), ('h', 'modify', 'f')]),
	'follows_a_chain_merged_move_on_to_its_end': ([(False, 'create', 'f', None), (False, 'move', 'd/g', 'f'), (True, 'move', 'D', 'd'),
		(False, 'move', 'h', 'D/g'), (False, 'move', 'k', 'h')],
		[('D/', 'move', 'd/'), ('d/g', 'delete', None), ('k', 'create', 'f')],
		[('f', 'delete', None), ('D/', 'move', 'd/'), ('d/g', 'delete', None), ('k', 'modify', 'f')]),
	# the first destination's delete goes when an earlier move took what the version held there
	'after_an_earlier_move_out_of_its_first_destination': ([(False, 'move', 'x', 'd/g'), (False, 'create', 'f', None),
		(False, 'move', 'd/g', 'f'), (True, 'move', 'D', 'd'), (False, 'move', 'h', 'D/g')],
		[('x', 'move', 'd/g'), ('D/', 'move', 'd/'), ('h', 'create', 'f')],
		[('x', 'move', 'd/g'), ('f', 'delete', None), ('D/', 'move', 'd/'), ('h', 'modify', 'f')]),
	# echo new > f; mv f d/g; mv d D; rm D/g: nothing of it is copied, whichever content event escalates the move
	'removed_after_the_folder_move': ([(False, 'create', 'f', None), (False, 'move', 'd/g', 'f'), (True, 'move', 'D', 'd'),
		(False, 'delete', 'D/g', None)],
		[('d/g', 'delete', None), ('D/', 'move', 'd/'), ('D/g', 'delete', None)],
		[('f', 'delete', None), ('d/g', 'delete', None), ('D/', 'move', 'd/'), ('D/g', 'delete', None)]),
}


@pytest.mark.parametrize('form', ['create', 'create_modify'])
@pytest.mark.parametrize('name', sorted(ESCALATED))
def test_a_file_made_in_the_batch_and_moved_on_is_escalated_once(name, form):
	events, made, written = ESCALATED[name]
	assert collapsed(*watched(form, *events)) == (made if form == 'create' else written)
	if form == 'create_modify':
		# the create before the modify adds nothing: as for a file the version holds, saved once
		saved = [(False, 'modify', *e[2:]) if e[:2] == (False, 'create') else e for e in events]
		assert collapsed(*saved) == written


def test_a_file_saved_twice_then_moved_through_a_folder_move_and_removed_leaves_no_copy():
	assert collapsed((False, 'modify', 'f', None), (False, 'modify', 'f', None), (False, 'move', 'd/g', 'f'), (True, 'move', 'D', 'd'),
		(False, 'delete', 'D/g', None)) == [('f', 'delete', None), ('d/g', 'delete', None), ('D/', 'move', 'd/'), ('D/g', 'delete', None)]


def test_a_file_the_version_holds_keeps_its_moves():
	assert collapsed((False, 'move', 'd/g', 'f'), (True, 'move', 'D', 'd'), (False, 'move', 'h', 'D/g')) == \
		[('d/g', 'move', 'f'), ('D/', 'move', 'd/'), ('h', 'move', 'D/g')]
