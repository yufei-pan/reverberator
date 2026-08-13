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


def test_delete_before_move_from_is_ignored():
	entries = rv.change_events_to_backup_entries(deque([
		_ev(1, False, 'delete', f'{P}/a', None),
		_ev(2, False, 'move', f'{P}/b', f'{P}/a'),
	]))
	assert f'{P}/a' not in entries or entries.get(f'{P}/a') is None
	# Coalescer does not keep dest as 'move': a delete immediately before
	# move-from is skipped as its own source entry, then dest is escalated
	# to 'delete' while retaining the original source_path. Policy unchanged.
	assert entries[f'{P}/b'].event == 'delete'
	assert entries[f'{P}/b'].source_path == f'{P}/a'


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
