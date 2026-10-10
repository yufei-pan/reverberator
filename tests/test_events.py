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


def test_attrib_then_move_escalates_dest():
	entries = rv.change_events_to_backup_entries(deque([
		_ev(1, False, 'attrib', f'{P}/a', None),
		_ev(2, False, 'move', f'{P}/b', f'{P}/a'),
	]))
	# Attrib immediately before a later move-from cannot stay a symlink-only
	# attrib on dest; coalescer escalates dest from 'move' to 'modify'.
	assert entries[f'{P}/b'].event == 'modify'
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
