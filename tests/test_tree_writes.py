'''
Round 20: every write into a version's tree goes through class TreeWriter, as later tasks record a version's old state
inside it, and a write that goes round it becomes a version that silently loses data. reverberator.py is read with ast,
so a new write fails here on the day it is written, in code no test runs too.
'''
import ast
import os

import reverberator as rv
from tests.harness import copy_now

# what writes the filesystem directly
WRITE_CALLS = {'os.rename', 'os.replace', 'os.remove', 'os.unlink', 'os.mkdir', 'os.makedirs', 'os.rmdir', 'os.symlink', 'os.link',
	'os.utime', 'os.chmod', 'os.chown', 'os.lchown', 'os.setxattr', 'os.removexattr', 'os.truncate', 'os.mknod', 'os.mkfifo',
	'shutil.rmtree', 'shutil.move', 'shutil.copystat', 'shutil.copy', 'shutil.copy2', 'shutil.copyfile', 'shutil.copytree'}
# what writes the tree it is given: used only by the functions USERS names
WRITE_HELPERS = {'remove_entry', 'replace_entry', 'make_real_folder', 'copy_file_meta', 'copy_new_folder_meta', 'cp_af_copy_path',
	'record_root_meta', 'real_folders_to(make)', 'mcae.run_command'}

# the replay: these write a version's tree through a TreeWriter only, and so does all they call by name
THROUGH_THE_WRITER = ('do_reverb_backup', 'finish_copies', 'discard_copies', 'sweep_version_folder', 'sweep_entry', 'WrittenFolders.settle')
# what the replay names that writes, and is no write of the tree. the look ends here
NOT_FOLLOWED = {
	# a look unless made to make, which names_used() finds as real_folders_to(make)
	'real_folders_to',
	# the markers of failed syncs (check_vault_sync()): daemon state, in the state folder
	'mark_failed_sync', 'failed_sync_disks', 'failed_sync_markers',
}

# every function outside TreeWriter using a helper of WRITE_HELPERS, and which
USERS = {
	# V0 of a job: no previous version and nothing older to keep
	'do_backup': {'copy_file_meta', 'cp_af_copy_path', 'record_root_meta'},
	# the helpers themselves, on what their callers name
	'cp_af_copy_path': {'mcae.run_command'},
	'copy_new_folder_meta': {'copy_file_meta'},
	# the prune of a 0.54 vault, the one a conversion finishes
	'decrement_stepper': {'copy_file_meta'},
	# the conversion from 0.54: a plain tree built in staging, with the metadata of the version it replaces
	'materialize_version': {'copy_new_folder_meta'},
	# a roll-forward's repair of a name left of two kinds across a pool's disks, directly on each disk, before any writer runs
	'remove_mixed_names': {'remove_entry'},
	# never the vault: a restore writes its destination
	'finish_restore_copies': {'replace_entry'},
	'restore_entry': {'cp_af_copy_path'},
}


def names_used(node) -> set:
	'''The names of WRITE_CALLS and WRITE_HELPERS that node refers to, called or not (a write kept in a variable is still found).'''
	used = set()
	for sub in ast.walk(node):
		if isinstance(sub, ast.Attribute) and isinstance(sub.value, ast.Name):
			dotted = f'{sub.value.id}.{sub.attr}'
			if dotted in WRITE_CALLS or dotted in WRITE_HELPERS:
				used.add(dotted)
		elif isinstance(sub, ast.Name) and sub.id in WRITE_HELPERS:
			used.add(sub.id)
		elif isinstance(sub, ast.Call) and isinstance(sub.func, ast.Name) and sub.func.id == 'real_folders_to':
			by_keyword = any(keyword.arg == 'make' and not (isinstance(keyword.value, ast.Constant) and not keyword.value.value) for keyword in sub.keywords)
			if by_keyword or len(sub.args) > 2:
				used.add('real_folders_to(make)')
	return used


def module_functions(tree) -> dict:
	'''Each function of the module, a method as Class.name, a closure as part of the function around it.'''
	functions = {}
	for node in tree.body:
		if isinstance(node, ast.FunctionDef):
			functions[node.name] = node
		elif isinstance(node, ast.ClassDef):
			for sub in node.body:
				if isinstance(sub, ast.FunctionDef):
					functions[f'{node.name}.{sub.name}'] = sub
	return functions


def replay_offenders(tree) -> dict:
	'''{function: the writes it holds}, for the functions of THROUGH_THE_WRITER and every module function they name, as a helper that writes is a write.'''
	functions = module_functions(tree)
	offenders = {}
	seen = set()
	to_look_at = [name for name in THROUGH_THE_WRITER if name in functions]
	while to_look_at:
		name = to_look_at.pop()
		if name in seen or name in NOT_FOLLOWED:
			continue
		seen.add(name)
		used = names_used(functions[name])
		if used:
			offenders[name] = used
		to_look_at += [sub.id for sub in ast.walk(functions[name]) if isinstance(sub, ast.Name) and sub.id in functions]
	return offenders


def helper_users(tree) -> dict:
	'''{function: the helpers of WRITE_HELPERS it uses}, for every function outside class TreeWriter.'''
	users = {}
	for name, node in module_functions(tree).items():
		used = names_used(node) & WRITE_HELPERS
		if used and not name.startswith('TreeWriter.'):
			users[name] = used
	return users


def source_tree():
	with open(rv.__file__, encoding='utf-8') as f:
		return ast.parse(f.read())


def test_no_replay_function_writes_the_tree_but_the_writer():
	tree = source_tree()
	functions = module_functions(tree)
	assert [name for name in THROUGH_THE_WRITER if name not in functions] == []
	assert replay_offenders(tree) == {}


def test_helpers_that_write_the_tree_are_used_only_by_named_functions():
	assert helper_users(source_tree()) == USERS


def test_the_writer_is_where_the_writes_are():
	writer = {name: node for name, node in module_functions(source_tree()).items() if name.startswith('TreeWriter.')}
	verbs = ('make_folders', 'make_folder', 'copy', 'place', 'discard_temp', 'remove_now', 'remove_queued', 'rename',
		'folder_times', 'folder_meta', 'file_meta', 'root_meta')
	assert [verb for verb in verbs if f'TreeWriter.{verb}' not in writer] == []
	# the writes are here, so the lists above hold because they moved, not because a reading missed them
	assert names_used(writer['TreeWriter.rename']) >= {'os.rename', 'os.remove', 'remove_entry'}
	assert 'mcae.run_command' in names_used(writer['TreeWriter.remove_queued'])


def test_each_kind_of_write_put_back_is_found():
	# the tests above mean nothing if the reading misses a form a write can take
	for body in ('os.remove(x)', 'os.utime(x, ns=y)', 'remove = os.remove', 'mcae.run_command(["rm", x])', 'remove_entry(x)', 'copy_file_meta(a, b)',
			'real_folders_to(a, b, make=True)', 'real_folders_to(a, b, True)', 'def closure():\n\t\tshutil.rmtree(x)'):
		tree = ast.parse(f'def sweep_entry():\n\t{body}\n')
		assert replay_offenders(tree), body
	# through a helper of its own
	tree = ast.parse('def sweep_entry():\n\thelper()\ndef helper():\n\tos.rename(a, b)\n')
	assert replay_offenders(tree) == {'helper': {'os.rename'}}
	# what only looks at the tree is no write
	tree = ast.parse('def sweep_entry():\n\treal_folders_to(a, b, missing_ok=True)\n\treal_folders_to(a, b, make=False)\n\tos.lstat(a)\n')
	assert replay_offenders(tree) == {}
	# a new user of a helper anywhere in the file is told
	tree = ast.parse('class TreeWriter:\n\tdef place(self):\n\t\treplace_entry(a, b)\ndef elsewhere():\n\treplace_entry(a, b)\n')
	assert helper_users(tree) == {'elsewhere': {'replace_entry'}}


def test_a_rename_with_nothing_to_rename_returns_false(tmp_path):
	# the one verb whose answer the replay acts on: False sends the move to delete & copy
	tree = str(tmp_path)
	writer = rv.TreeWriter(tree)
	assert writer.rename('gone', 'there') is False
	os.mkdir(tmp_path / 'd')
	(tmp_path / 'f').write_text('f')
	# the folder it goes into is not there
	assert writer.rename('f', 'none/f') is False and (tmp_path / 'f').exists()
	# never into itself
	assert writer.rename('d', 'd/e') is False and (tmp_path / 'd').is_dir()
	assert writer.rename('f', 'd/f') is True and (tmp_path / 'd' / 'f').read_text() == 'f'


def test_a_rename_takes_the_place_of_what_is_there(tmp_path):
	writer = rv.TreeWriter(str(tmp_path))
	(tmp_path / 'a').write_text('a')
	(tmp_path / 'b').write_text('b')
	os.makedirs(tmp_path / 'folder' / 'sub')
	assert writer.rename('a', 'b') is True and (tmp_path / 'b').read_text() == 'a'
	assert writer.rename('b', 'folder') is True and (tmp_path / 'folder').read_text() == 'a'


def test_a_copy_run_now_makes_the_folders_and_puts_the_copy_in_place(tmp_path):
	source = tmp_path / 'source'
	source.write_text('new')
	tree = tmp_path / 'tree'
	tree.mkdir()
	writer = rv.TreeWriter(str(tree))
	assert copy_now(writer, str(source), 'a/b/f') == 0
	assert (tree / 'a' / 'b' / 'f').read_text() == 'new'
	assert os.listdir(tree / 'a' / 'b') == ['f']
	# a source already gone makes nothing
	assert copy_now(writer, str(tmp_path / 'gone'), 'c/f') is False and not (tree / 'c').exists()


def test_a_copy_never_makes_its_folders_through_a_link(tmp_path):
	source = tmp_path / 'source'
	source.write_text('new')
	outside = tmp_path / 'outside'
	outside.mkdir()
	tree = tmp_path / 'tree'
	tree.mkdir()
	os.symlink(outside, tree / 'link')
	try:
		copy_now(rv.TreeWriter(str(tree)), str(source), 'link/sub/f')
	except rv.NotARealFolder:
		pass
	else:
		raise AssertionError('copied through the link')
	assert os.listdir(outside) == []
