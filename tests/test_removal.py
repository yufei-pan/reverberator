'''
Round 20 took out the 0.54 writer: its names are gone, and the code a 0.54 vault still needs stays until the release that drops
the 0.54 reader (spec section 8). reverberator.py is read with ast, so a name that comes back, or goes too soon, fails here.
'''
import ast
import inspect
import signal

import pytest

import reverberator as rv
from tests.harness import rule_row, seed_monitor, wait_for_committed_count

# spec section 8's removed list, and what the plan's Task 16 adds to it
REMOVED = {
	'do_referenced_copy', 'recopy_rels', 'chain_form_missing_version', 'batch_rewrites', 'chain_end', 'measure_version_usage', 'copy_threads_auto',
	'retarget_moved_links', 'CopiedSizes', 'link_chain_end', 'retarget_chain_link', 'referenced_link_text', 'read_chain_length', 'kernel_cannot_follow',
	'command_monitor_paths', 'read_copy_threads', 'learn_copy_version', 'recopy_hops', 'recopy_threshold', 'sysfs_device_rotational', 'recopy_size',
	'effective_copy_version', 'block_device_rotational', 'manifest_monitor_paths', 'copied_hop', 'CopyInterrupted', 'NEW_VAULT_LAYOUT',
}
# spec section 8's kept list: all a 0.54 vault needs until its reader goes, remove_orphan and prune_oldest with it
KEPT = {
	'decrement_stepper', 'VersionMoves', 'vault_chain_hop', 'VaultMoves', 'rows_dropping', 'in_row_order', 'is_real_folder_under', 'PathHashes',
	'read_change_list_moves', 'write_prune_marker', 'undo_cut_off_commit', 'read_prune_marker', 'CommittedMoves', 'prune_link_path', 'remove_orphan',
	'read_recorded_monitor_paths', 'read_version_moves', 'remember_version_moves', 'written_under', 'forget_real_vault_folders', 'change_list_rows_ended',
	'UnexplainedChainLink', 'forget_version_moves', 'recorded_monitor_paths', 'UnreadablePruneMarker', 'vault_prune_salt', 'parse_chain_text',
	'is_prune_temp', 'is_previous_version_name', 'same_inode', 'prune_oldest',
}


def module_names() -> set:
	'''Every function, class and constant the module defines at its top level.'''
	with open(rv.__file__, encoding='utf-8') as f:
		tree = ast.parse(f.read())
	names = set()
	for node in tree.body:
		if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
			names.add(node.name)
		elif isinstance(node, ast.Assign):
			names.update(target.id for target in node.targets if isinstance(target, ast.Name))
	return names


def test_the_removed_names_are_gone():
	assert sorted(REMOVED & module_names()) == []


def test_the_kept_names_are_there():
	assert sorted(KEPT - module_names()) == []


def test_the_scan_no_longer_measures_with_du():
	assert 'recalculate' not in inspect.signature(rv.get_vault_info).parameters


def test_nothing_of_a_batch_takes_a_chain_length_or_copy_threads():
	for function in (rv.backuper, rv.do_backup):
		assert not {'chain_length', 'copy_threads'} & set(inspect.signature(function).parameters)


def test_columns_14_and_15_stay_in_the_rule_file():
	assert rv.REVERB_RULE_TSV_HEADER[13:15] == ['Chain Length', 'Copy threads']
	assert rv.REVERB_RULE_HEADER[-2:] == ['chain_length', 'copy_threads']


@pytest.mark.process
@pytest.mark.parametrize('cell', ['40', 'none', 'junk', ''])
def test_any_chain_length_or_copy_threads_cell_is_accepted_with_no_line(job, run_reverberator, cell):
	seed_monitor(job, {'a.txt': 'hello'})
	with open(job.rule_path, 'w', encoding='utf-8') as f:
		f.write('\t'.join(rv.REVERB_RULE_TSV_HEADER) + '\n')
		f.write('\t'.join(rule_row(job) + ['', cell, cell]) + '\n')
	proc = run_reverberator(job.rule_path, extra_args=('-v',))
	wait_for_committed_count(job, 1, timeout=15)
	proc.send_signal(signal.SIGTERM)
	proc.wait(timeout=15)
	output = ''.join(proc._out_buf + proc._err_buf).lower()
	assert 'started job' in output
	assert 'chain length' not in output and 'copy threads' not in output
