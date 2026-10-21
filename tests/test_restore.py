import io
import os
import re
import shutil
import signal
import stat
import sys
import time
from collections import OrderedDict
import pytest
import reverberator as rv
from tests.harness import seed_monitor, run_backup, event_entry, write_rule, rule_row, write_committed_version, create_job

pytestmark = pytest.mark.unit

T0 = '2021-01-01_00-00-00_-0800'
T1 = '2021-01-02_00-00-00_-0800'
T2 = '2021-01-03_00-00-00_-0800'


@pytest.fixture(autouse=True)
def _fast(poll_fast):
	return poll_fast


class Terminal(io.StringIO):
	'''A stream that says it is a terminal.'''
	def isatty(self):
		return True


def write(job, rel, content):
	path = os.path.join(job.monitor, rel)
	os.makedirs(os.path.dirname(path), exist_ok=True)
	with open(path, 'w', encoding='utf-8') as f:
		f.write(content)


def backup(job, *entries, **kwargs):
	'''One backup of the entries, each (rel, event) or (rel, 'move', source rel).'''
	return run_backup(job, OrderedDict(event_entry(job, *entry) for entry in entries), **kwargs)


def versions(job):
	return rv.list_versions(job.job_vault)


def version_path(job, number):
	return {v.number: v.path for v in versions(job)}[number]


def restore(tmp_path, capsys, path, *extra):
	# what building the vault logged is not the command's output
	capsys.readouterr()
	code = rv.run_command(['restore', path, *extra, '--rule', str(tmp_path / 'rule.tsv'), '--state_dir', str(tmp_path / 'state')])
	captured = capsys.readouterr()
	return code, captured.out, captured.err


def destination(tmp_path, name='out'):
	path = tmp_path / name
	path.mkdir()
	return str(path)


def tree(top):
	'''What is under top: a file's text, a symlink's ('->', text), None for a folder (its rel ending with /).'''
	found = {}
	for folder, names, files in os.walk(top):
		for name in names + files:
			path = os.path.join(folder, name)
			rel = os.path.relpath(path, top)
			if os.path.islink(path):
				found[rel] = ('->', os.readlink(path))
			elif os.path.isdir(path):
				found[rel + '/'] = None
			else:
				with open(path, encoding='utf-8') as f:
					found[rel] = f.read()
	return found


def marked_tree(top):
	'''tree(top) of a folder restore that did not complete, which keeps its marker at the top: without it.'''
	found = tree(top)
	assert found.pop(rv.RESTORE_MARKER_NAME, None) is not None, f'no marker in {top}'
	return found


def snapshot(top):
	found = {}
	for folder, names, files in os.walk(top):
		for name in names + files:
			path = os.path.join(folder, name)
			st = os.lstat(path)
			found[path] = (st.st_mode, st.st_size, st.st_mtime_ns, os.readlink(path) if os.path.islink(path) else None)
	return found


def partial_files(top):
	return [name for _, names, files in os.walk(top) for name in names + files if name.endswith(rv.PARTIAL_COPY_SUFFIX)]


def three_versions(job):
	'''V0, V1 and V2 a day apart, each with its own copy of a.txt (v0, v1, v2).'''
	write_committed_version(job, 0, {'a.txt': 'v0'}, timestamp=T0, current=False)
	write_committed_version(job, 1, {'a.txt': 'v1'}, timestamp=T1, current=False)
	write_committed_version(job, 2, {'a.txt': 'v2'}, timestamp=T2)
	write_rule(job)


def test_restore_file_to_a_destination(job, tmp_path, capsys):
	seed_monitor(job, {'a.txt': 'hello', 'b.txt': 'b'})
	path = f'{job.monitor}/a.txt'
	os.chmod(path, 0o640)
	os.utime(path, ns=(1_600_000_000_123_456_789, 1_600_000_000_123_456_789))
	if os.geteuid() == 0:
		os.chown(path, 1234, 2345)
	run_backup(job)
	write(job, 'b.txt', 'b1')
	backup(job, ('b.txt', 'modify'))
	write_rule(job)
	# V1 holds a.txt as a link chained to V0's copy
	assert os.path.islink(os.path.join(version_path(job, 1), 'a.txt'))
	out = destination(tmp_path)
	code, stdout, err = restore(tmp_path, capsys, path, out, '--version', '1')
	assert (code, err) == (0, '')
	restored = os.path.join(out, 'a.txt')
	st, copy = os.lstat(restored), os.lstat(os.path.join(version_path(job, 0), 'a.txt'))
	assert stat.S_ISREG(st.st_mode)
	with open(restored, encoding='utf-8') as f:
		assert f.read() == 'hello'
	assert (st.st_mode, st.st_mtime_ns, st.st_uid, st.st_gid) == (copy.st_mode, copy.st_mtime_ns, copy.st_uid, copy.st_gid)
	assert stdout == f'Restored 1 entries ({rv.show_size(5)}) from V1 to {restored}\n'
	assert os.listdir(out) == ['a.txt']


def test_restore_folder_to_a_destination(job, tmp_path, capsys):
	seed_monitor(job, {'proj/a.txt': 'a', 'proj/sub/b.txt': 'b', 'proj/empty/': None, 'other.txt': 'o'})
	os.symlink('sub/b.txt', f'{job.monitor}/proj/link')
	os.symlink('sub', f'{job.monitor}/proj/dirlink')
	os.chmod(f'{job.monitor}/proj/sub', 0o750)
	run_backup(job)
	write(job, 'proj/a.txt', 'a2')
	backup(job, ('proj/a.txt', 'modify'))
	write_rule(job)
	out = destination(tmp_path)
	code, stdout, err = restore(tmp_path, capsys, f'{job.monitor}/proj', out, '--version', '1')
	assert (code, err) == (0, '')
	target = os.path.join(out, 'proj')
	assert tree(target) == {'a.txt': 'a2', 'sub/': None, 'sub/b.txt': 'b', 'empty/': None,
		'link': ('->', 'sub/b.txt'), 'dirlink': ('->', 'sub')}
	held = os.path.join(version_path(job, 1), 'proj')
	for rel in ('', 'sub', 'empty'):
		st, copy = os.lstat(os.path.join(target, rel)), os.lstat(os.path.join(held, rel))
		assert (st.st_mode, st.st_mtime_ns, st.st_uid, st.st_gid) == (copy.st_mode, copy.st_mtime_ns, copy.st_uid, copy.st_gid), rel
	assert stdout == f'Restored 7 entries ({rv.show_size(3)}) from V1 to {target}\n'
	assert partial_files(out) == []


def test_restore_picks_by_number_and_time(job, tmp_path, capsys):
	three_versions(job)
	path = f'{job.monitor}/a.txt'

	def restored(name, *extra):
		out = destination(tmp_path, name)
		code, _, err = restore(tmp_path, capsys, path, out, *extra)
		if code:
			assert os.listdir(out) == []
			return code, err
		with open(os.path.join(out, 'a.txt'), encoding='utf-8') as f:
			return code, f.read()
	assert restored('number', '--version', '1') == (0, 'v1')
	assert restored('between', '--at', '2021-01-02_12-00-00_-0800') == (0, 'v1')
	assert restored('exactly', '--at', T2) == (0, 'v2')
	# a time without an offset is local time
	t1 = versions(job)[1].timestamp
	assert restored('local', '--at', time.strftime('%Y-%m-%d %H:%M', time.localtime(t1 + 3600))) == (0, 'v1')
	code, err = restored('before', '--at', '2020-12-31_00-00-00_-0800')
	assert code == rv.EXIT_USAGE and 'V0-V2' in err
	code, err = restored('not_kept', '--version', '7')
	assert code == rv.EXIT_USAGE and 'V7 is not kept' in err and 'V0-V2' in err
	code, err = restored('both', '--version', '1', '--at', T1)
	assert code == rv.EXIT_USAGE and 'not both' in err
	code, err = restored('unreadable_time', '--at', 'yesterday')
	assert code == rv.EXIT_USAGE and 'yesterday' in err


def test_restore_without_a_terminal_needs_a_version(job, tmp_path, capsys, monkeypatch):
	three_versions(job)
	monkeypatch.setattr(sys, 'stdin', io.StringIO('1\n'))
	out = destination(tmp_path)
	code, stdout, err = restore(tmp_path, capsys, f'{job.monitor}/a.txt', out)
	assert (code, stdout) == (rv.EXIT_USAGE, '')
	assert '--version' in err and '--at' in err
	assert os.listdir(out) == []


def test_restore_picker_reads_a_choice(job):
	three_versions(job)
	kept = versions(job)
	candidates = rv.restore_candidates(job.job_vault, kept, job.monitor, 'a.txt', 'file')
	assert [row.version.number for row in candidates] == [2, 1, 0]
	holds = lambda version: True
	shown = io.StringIO()
	assert rv.choose_version(candidates, kept, holds, stdin=Terminal('2\n'), stdout=shown) == kept[1]
	lines = shown.getvalue().split('\n')
	assert lines[1:4] == [f'  {number}  {rv.format_history_row(row, "file")}' for number, row in enumerate(candidates, 1)]
	assert lines[4].startswith('Restore which version?')
	# a wrong answer is asked again
	assert rv.choose_version(candidates, kept, holds, stdin=Terminal('9\nx\n3\n'), stdout=io.StringIO()) == kept[0]
	for answer in ('q\n', ''):
		with pytest.raises(rv.CommandError) as cancelled:
			rv.choose_version(candidates, kept, holds, stdin=Terminal(answer), stdout=io.StringIO())
		assert cancelled.value.code == rv.EXIT_COMMAND_FAILED
	# one candidate is used, and named
	shown = io.StringIO()
	assert rv.choose_version(candidates[:1], kept, holds, stdin=Terminal(''), stdout=shown) == kept[2]
	assert rv.format_history_row(candidates[0], 'file') in shown.getvalue()
	# a version that does not hold the path names the ones that do
	with pytest.raises(rv.CommandError) as refused:
		rv.choose_version(candidates, kept, lambda version: version.number != 1, version=1)
	assert refused.value.code == rv.EXIT_USAGE and 'V1 does not hold' in refused.value.message and 'V0, V2' in refused.value.message


def test_restore_refuses_an_existing_destination_name(job, tmp_path, capsys):
	three_versions(job)
	out = destination(tmp_path)
	with open(os.path.join(out, 'a.txt'), 'w', encoding='utf-8') as f:
		f.write('mine')
	code, stdout, err = restore(tmp_path, capsys, f'{job.monitor}/a.txt', out, '--version', '1')
	assert (code, stdout) == (rv.EXIT_USAGE, '')
	assert 'already exists' in err
	assert tree(out) == {'a.txt': 'mine'}
	# a link there that leads nowhere is something there too
	os.remove(os.path.join(out, 'a.txt'))
	os.symlink('nowhere', os.path.join(out, 'a.txt'))
	assert restore(tmp_path, capsys, f'{job.monitor}/a.txt', out, '--version', '1')[0] == rv.EXIT_USAGE
	assert tree(out) == {'a.txt': ('->', 'nowhere')}


def test_restore_refuses_destination_inside_vault(job, tmp_path, capsys):
	seed_monitor(job, {'a.txt': 'a'})
	run_backup(job)
	other = create_job(str(tmp_path / 'two'), 'two')
	write_rule(job, extra_rows=[rule_row(other)])
	os.symlink(job.vault, tmp_path / 'sneaky')
	before = snapshot(job.vault), snapshot(other.vault)
	for dest in (job.vault, job.job_vault, version_path(job, 0), str(tmp_path / 'sneaky'), other.vault):
		code, stdout, err = restore(tmp_path, capsys, f'{job.monitor}/a.txt', dest, '--version', '0')
		assert (code, stdout) == (rv.EXIT_USAGE, ''), dest
		assert 'inside the vault' in err, dest
	assert (snapshot(job.vault), snapshot(other.vault)) == before
	# a destination that is not a folder
	code, _, err = restore(tmp_path, capsys, f'{job.monitor}/a.txt', str(tmp_path / 'missing'), '--version', '0')
	assert code == rv.EXIT_USAGE and 'not a folder' in err


def test_restore_reports_an_old_absolute_link_to_a_removed_version(job, tmp_path, capsys):
	seed_monitor(job, {'proj/a.txt': 'a', 'proj/b.txt': 'b'})
	run_backup(job)
	write(job, 'proj/a.txt', 'a1')
	backup(job, ('proj/a.txt', 'modify'))
	write_rule(job)
	v0, v1 = version_path(job, 0), version_path(job, 1)
	# as an older daemon linked b.txt, to a version since removed by hand
	os.remove(os.path.join(v1, 'proj/b.txt'))
	os.symlink(os.path.join(job.job_vault, f'V0--2021-01-01_00-00-00_-0800/proj/b.txt'), os.path.join(v1, 'proj/b.txt'))
	out = destination(tmp_path)
	code, stdout, err = restore(tmp_path, capsys, f'{job.monitor}/proj', out, '--version', '1')
	assert code == rv.EXIT_COMMAND_FAILED and 'Traceback' not in err
	assert 'FAILED proj/b.txt: dangling vault link: V0--2021-01-01_00-00-00_-0800 is missing' in stdout.split('\n')
	assert not os.path.lexists(os.path.join(out, 'proj/b.txt'))
	assert os.path.isdir(v0)


def test_restore_reports_dangling_and_continues(job, tmp_path, capsys):
	seed_monitor(job, {'proj/a.txt': 'a', 'proj/b.txt': 'b', 'proj/c.txt': 'c'})
	run_backup(job)
	write(job, 'proj/c.txt', 'c1')
	backup(job, ('proj/c.txt', 'modify'))
	write_rule(job)
	# the copy V1's link for b.txt chains to is gone
	os.remove(os.path.join(version_path(job, 0), 'proj/b.txt'))
	out = destination(tmp_path)
	code, stdout, err = restore(tmp_path, capsys, f'{job.monitor}/proj', out, '--version', '1')
	assert code == rv.EXIT_COMMAND_FAILED
	assert 'Traceback' not in err
	lines = stdout.rstrip('\n').split('\n')
	assert lines[0].startswith('Restored 3 entries')
	assert lines[1].startswith('FAILED proj/b.txt: dangling vault link: proj/b.txt is missing from V0--')
	target = os.path.join(out, 'proj')
	# not everything is there: nobody else may look in, or put anything in for a later run to write through
	assert lines[2:] == [f'1 failed: run the same restore again to retry them, or again with --accept to keep the result as it is. {rv.unfinished_note(target)}']
	assert stat.S_IMODE(os.lstat(target).st_mode) == 0o700
	assert marked_tree(target) == {'a.txt': 'a', 'c.txt': 'c1'}
	assert partial_files(out) == []


def test_restore_reports_referenced_links(job, tmp_path, capsys):
	seed_monitor(job, {'proj/a.txt': 'a', 'proj/r.txt': 'live'})
	run_backup(job)
	write_rule(job)
	held = os.path.join(version_path(job, 0), 'proj/r.txt')
	# a referenced backup links the vault entry to the monitored file itself
	os.remove(held)
	os.symlink(f'{job.monitor}/proj/r.txt', held)
	out = destination(tmp_path)
	code, stdout, _ = restore(tmp_path, capsys, f'{job.monitor}/proj', out, '--version', '0')
	assert code == rv.EXIT_COMMAND_FAILED
	assert 'FAILED proj/r.txt: not held in the vault (referenced backup)' in stdout.split('\n')
	# never the live file in its place
	assert marked_tree(os.path.join(out, 'proj')) == {'a.txt': 'a'}
	out = destination(tmp_path, 'file')
	code, stdout, _ = restore(tmp_path, capsys, f'{job.monitor}/proj/r.txt', out, '--version', '0')
	assert code == rv.EXIT_COMMAND_FAILED
	assert stdout.split('\n')[:2] == [f'Restored 0 entries ({rv.show_size(0)}) from V0 to {out}/r.txt',
		'FAILED proj/r.txt: not held in the vault (referenced backup)']
	assert os.listdir(out) == []


def test_restore_reports_a_failed_copy(job, tmp_path, capsys, monkeypatch):
	seed_monitor(job, {'proj/a.txt': 'a', 'proj/bad.txt': 'b', 'proj/meta.txt': 'm'})
	run_backup(job)
	write_rule(job)
	copy_command = rv.copy_command

	def failing(source_path, dest_path):
		if source_path.endswith('bad.txt'):
			return ['sh', '-c', f'echo "cp: error reading \'{source_path}\': Input/output error" >&2; touch "{dest_path}"; exit 1']
		if source_path.endswith('meta.txt'):
			# the contents arrived, the owner could not be kept
			return ['sh', '-c', f'cp "{source_path}" "{dest_path}" && echo "cp: failed to preserve ownership for \'{dest_path}\': Operation not permitted" >&2; exit 1']
		return copy_command(source_path, dest_path)
	monkeypatch.setattr(rv, 'copy_command', failing)
	out = destination(tmp_path)
	code, stdout, err = restore(tmp_path, capsys, f'{job.monitor}/proj', out, '--version', '0')
	assert code == rv.EXIT_COMMAND_FAILED
	lines = stdout.rstrip('\n').split('\n')
	assert lines[0].startswith('Restored 3 entries')
	assert lines[1].startswith('WARNING proj/meta.txt: copied without all of its metadata: cp: failed to preserve ownership')
	assert lines[2].startswith('FAILED proj/bad.txt: cp: error reading') and lines[2].endswith('Input/output error')
	assert marked_tree(os.path.join(out, 'proj')) == {'a.txt': 'a', 'meta.txt': 'm'}
	assert partial_files(out) == []


def test_restore_never_writes_the_vault(job, tmp_path, capsys):
	seed_monitor(job, {'proj/a.txt': 'a', 'proj/sub/b.txt': 'b', 'c.txt': 'c'})
	os.symlink('a.txt', f'{job.monitor}/proj/link')
	run_backup(job)
	write(job, 'proj/a.txt', 'a1')
	backup(job, ('proj/a.txt', 'modify'))
	write_rule(job)
	before = snapshot(job.vault)
	for name, path in (('root', job.monitor), ('folder', f'{job.monitor}/proj'), ('file', f'{job.monitor}/proj/sub/b.txt'), ('link', f'{job.monitor}/proj/link')):
		assert restore(tmp_path, capsys, path, destination(tmp_path, name), '--version', '1')[0] == 0, name
	assert snapshot(job.vault) == before
	assert os.listdir(tmp_path / 'state') == [f'job-{job.job_name}.restore.lock']


def test_restore_names_with_spaces_and_unicode(job, tmp_path, capsys):
	seed_monitor(job, {'a b/café.txt': 'crème', 'a b/x.txt': 'x'})
	run_backup(job)
	write_rule(job)
	out = destination(tmp_path)
	assert restore(tmp_path, capsys, f'{job.monitor}/a b', out, '--version', '0')[0] == 0
	assert tree(os.path.join(out, 'a b')) == {'café.txt': 'crème', 'x.txt': 'x'}
	out = destination(tmp_path, 'file')
	assert restore(tmp_path, capsys, f'{job.monitor}/a b/café.txt', out, '--version', '0')[0] == 0
	assert tree(out) == {'café.txt': 'crème'}


def test_restore_reports_a_version_removed_mid_restore(job, tmp_path, monkeypatch, capsys):
	seed_monitor(job, {'proj/a.txt': 'a', 'proj/b.txt': 'b', 'proj/sub/c.txt': 'c'})
	run_backup(job)
	write(job, 'proj/a.txt', 'a1')
	backup(job, ('proj/a.txt', 'modify'))
	write_rule(job)
	v0 = version_path(job, 0)
	choose_version = rv.choose_version

	def choose_then_remove(*args, **kwargs):
		chosen = choose_version(*args, **kwargs)
		# what V1's unchanged files chain to goes, as a manual removal of the oldest version would take it
		shutil.rmtree(v0)
		return chosen
	monkeypatch.setattr(rv, 'choose_version', choose_then_remove)
	out = destination(tmp_path)
	code, stdout, err = restore(tmp_path, capsys, job.monitor, out, '--version', '1')
	assert code == rv.EXIT_COMMAND_FAILED
	assert 'Traceback' not in err
	lines = stdout.rstrip('\n').split('\n')
	assert lines[0] == f'Restored 4 entries ({rv.show_size(2)}) from V1 to {out}/monitor'
	assert sorted(line.partition(': ')[0] for line in lines[1:-1]) == ['FAILED proj/b.txt', 'FAILED proj/sub/c.txt']
	assert all(': dangling vault link: ' in line for line in lines[1:-1])
	assert lines[-1] == f'2 failed: run the same restore again to retry them, or again with --accept to keep the result as it is. {rv.unfinished_note(out + "/monitor")}'
	assert marked_tree(os.path.join(out, 'monitor')) == {'proj/': None, 'proj/a.txt': 'a1', 'proj/sub/': None}
	assert partial_files(out) == []


def test_restore_thousands_of_files(job, tmp_path, capsys, monkeypatch):
	files = {f'd{i:02}/f{j:03}.txt': f'{i}-{j}' for i in range(30) for j in range(100)}
	seed_monitor(job, files)
	run_backup(job)
	write_rule(job)
	# a progress line at every chance, rather than once a minute
	monkeypatch.setattr(rv, 'RESTORE_PROGRESS_LINE_SECONDS', 0)
	out = destination(tmp_path)
	code, stdout, err = restore(tmp_path, capsys, job.monitor, out, '--version', '0', '--threads', '4')
	assert code == 0, stdout[-2000:]
	expected = dict(files)
	expected.update({f'd{i:02}/': None for i in range(30)})
	assert tree(os.path.join(out, 'monitor')) == expected
	# 3000 files, 30 folders and the restored folder itself
	assert stdout.startswith('Restored 3031 entries (')
	assert re.search(r'^restored [1-9]\d* entries, ', err, re.M)
	assert partial_files(out) == []


def test_restore_progress_line():
	report = rv.RestoreReport()
	log = io.StringIO()
	# nothing in the first minute
	report.progress(log)
	assert log.getvalue() == ''
	report.progress_at -= rv.RESTORE_PROGRESS_LINE_SECONDS
	report.restored, report.bytes = 5, 2048
	report.progress(log)
	assert log.getvalue() == f'restored 5 entries, {rv.show_size(2048)}\n'
	terminal = Terminal()
	report = rv.RestoreReport()
	report.progress_at -= rv.RESTORE_PROGRESS_TERMINAL_SECONDS
	report.restored, report.bytes = 1, 1024 * 1024
	report.progress(terminal)
	report.progress_at -= rv.RESTORE_PROGRESS_TERMINAL_SECONDS
	report.restored, report.bytes = 2, 5
	report.progress(terminal)
	first, second = f'restored 1 entries, {rv.show_size(1024 * 1024)}', f'restored 2 entries, {rv.show_size(5)}'
	# rewritten in place, padded over the longer line before it, and ended once done
	report.progress(terminal, done=True)
	assert terminal.getvalue() == f'\r{first}\r{second.ljust(len(first))}\r{second.ljust(len(first))}\n'


def test_parse_at_time_forms():
	local = rv.datetime.datetime(2021, 1, 2, 3, 4, 5).timestamp()
	assert rv.parse_at_time('2021-01-02 03:04:05') == rv.parse_at_time('2021-01-02T03:04:05') == local
	assert rv.parse_at_time('2021-01-02 03:04') == rv.parse_at_time('2021-01-02T03:04') == local - 5
	assert rv.parse_at_time('2021-01-02') == local - 3 * 3600 - 4 * 60 - 5
	with pytest.raises(rv.CommandError) as e:
		rv.parse_at_time('2021-13-01')
	assert e.value.code == rv.EXIT_USAGE


def test_restore_needs_one_destination(job, tmp_path, capsys):
	three_versions(job)
	path = f'{job.monitor}/a.txt'
	out = destination(tmp_path)
	for extra in ((), (out, '--in-place'), (out, '--threads', '0'), ('--in-place', '--threads', '0')):
		code, stdout, err = restore(tmp_path, capsys, path, *extra, '--version', '1')
		assert (code, stdout) == (rv.EXIT_USAGE, ''), extra
		assert err, extra
	assert os.listdir(out) == []


def test_restore_stops_cleanly_on_a_signal(job, tmp_path, capsys, monkeypatch):
	files = {f'd{i}/f{j:02}.txt': f'{i}-{j}' for i in range(3) for j in range(40)}
	seed_monitor(job, files)
	run_backup(job)
	write_rule(job)
	handlers = {sig: signal.getsignal(sig) for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)}
	monkeypatch.setattr(rv, 'RESTORE_COPY_BATCH', 20)
	finished, signalled, raised_inside = [], [], []
	finish_restore_copies = rv.finish_restore_copies
	monkeypatch.setattr(rv, 'finish_restore_copies', lambda pending, report: finished.append(len(pending)) or finish_restore_copies(pending, report))
	wait = rv.multiCMD.AsyncExecutor.wait

	def signalled_wait(self, *args, **kwargs):
		try:
			if len(finished) >= 2 and not signalled:
				signalled.append(len(finished))
				# a Ctrl-C while the executor is waited on: raised in there, it can leave the executor waiting forever
				os.kill(os.getpid(), signal.SIGINT)
				time.sleep(0.05)
			return wait(self, *args, **kwargs)
		except KeyboardInterrupt:
			raised_inside.append(True)
			raise
	monkeypatch.setattr(rv.multiCMD.AsyncExecutor, 'wait', signalled_wait)
	out = destination(tmp_path)
	code, stdout, err = restore(tmp_path, capsys, job.monitor, out, '--version', '0', '--threads', '4')
	target = os.path.join(out, 'monitor')
	assert (code, stdout) == (rv.EXIT_COMMAND_FAILED, '')
	# what it left is marked for a re-run to pick up
	assert err == f'Interrupted: run the same restore again to pick it up, or again with --accept to keep what it restored as it is. {rv.unfinished_note(target)}\n'
	assert signalled and raised_inside == []
	# the batches put in place before it are whole, under their own names; nothing of the one under way is left
	restored = {rel: text for rel, text in marked_tree(target).items() if text is not None}
	assert len(restored) == 20 * len(finished) and all(files[rel] == text for rel, text in restored.items())
	assert partial_files(out) == []
	assert {sig: signal.getsignal(sig) for sig in handlers} == handlers
	# what it left stays private
	assert stat.S_IMODE(os.lstat(os.path.join(out, 'monitor')).st_mode) == 0o700


def test_restore_failure_reasons():
	version = rv.KeptVersion(3, '/v/job/V3--x', 'V3--x', 0.0, 0, 0, '/v/job/V3--x.nsv')
	entry = lambda kind, detail='': rv.restore_failure(rv.ResolvedEntry(kind, '/v/job/V3--x/a', detail), version)
	assert (entry('file'), entry('symlink')) == (None, None)
	assert entry('dangling', 'V2--y is missing') == 'dangling vault link: V2--y is missing'
	assert entry('referenced', '/m/a') == 'not held in the vault (referenced backup)'
	assert entry('unreadable', 'Input/output error') == 'unreadable in the vault: Input/output error'
	# met while walking a folder: a folder above it became a symlink, or the version went
	assert entry('missing', 'd is a symlink in V3--x') == 'not in V3: d is a symlink in V3--x'


def test_restore_folder_target_made_exclusively_and_private(job, tmp_path, capsys, monkeypatch):
	seed_monitor(job, {'proj/a.txt': 'a', 'proj/sub/b.txt': 'b'})
	os.chmod(f'{job.monitor}/proj', 0o751)
	if os.geteuid() == 0:
		# handed to another user only once everything else about it is set
		os.chown(f'{job.monitor}/proj', 65534, 65534)
	run_backup(job)
	write_rule(job)
	held = os.stat(os.path.join(version_path(job, 0), 'proj'))
	out = destination(tmp_path)
	target = os.path.join(out, 'proj')
	modes = []
	cp_af_copy_path = rv.cp_af_copy_path

	def watching(*args, **kwargs):
		modes.append(stat.S_IMODE(os.lstat(target).st_mode))
		return cp_af_copy_path(*args, **kwargs)
	monkeypatch.setattr(rv, 'cp_af_copy_path', watching)
	code, stdout, err = restore(tmp_path, capsys, f'{job.monitor}/proj', out, '--version', '0')
	assert (code, err) == (0, '')
	# private while it fills, the vault folder's own once complete
	assert modes and set(modes) == {0o700}
	st = os.lstat(target)
	assert (stat.S_IMODE(st.st_mode), st.st_uid, st.st_gid, st.st_mtime_ns) == (0o751, held.st_uid, held.st_gid, held.st_mtime_ns)
	# a target planted between the check and the making of it (here a symlink to another folder) is never written through
	out = destination(tmp_path, 'raced')
	target = os.path.join(out, 'proj')
	elsewhere = destination(tmp_path, 'elsewhere')
	mkdir = os.mkdir

	def planting(path, *args, **kwargs):
		if os.fspath(path) == target and not os.path.lexists(target):
			os.symlink(elsewhere, target)
		return mkdir(path, *args, **kwargs)
	monkeypatch.setattr(os, 'mkdir', planting)
	code, stdout, err = restore(tmp_path, capsys, f'{job.monitor}/proj', out, '--version', '0')
	assert (code, stdout) == (rv.EXIT_USAGE, '')
	assert f'{target} already exists' in err
	assert os.readlink(target) == elsewhere and os.listdir(elsewhere) == []
	assert sorted(os.listdir(out)) == ['proj']


def test_restore_file_never_replaces_what_appeared(job, tmp_path, capsys, monkeypatch):
	three_versions(job)
	# a user's symlink, held as one
	os.symlink('a.txt', os.path.join(version_path(job, 2), 'l'))
	out = destination(tmp_path)
	target = os.path.join(out, 'a.txt')
	finish_restore_copies = rv.finish_restore_copies

	def appearing(pending, report):
		with open(target, 'w', encoding='utf-8') as f:
			f.write('theirs')
		return finish_restore_copies(pending, report)
	monkeypatch.setattr(rv, 'finish_restore_copies', appearing)
	code, stdout, err = restore(tmp_path, capsys, f'{job.monitor}/a.txt', out, '--version', '1')
	assert code == rv.EXIT_COMMAND_FAILED
	assert stdout.split('\n')[1] == f'FAILED a.txt: {target} appeared while restoring; left untouched'
	assert tree(out) == {'a.txt': 'theirs'} and partial_files(out) == []
	monkeypatch.setattr(rv, 'finish_restore_copies', finish_restore_copies)
	# put in place as a hard link of the copy, a symlink as the symlink itself
	out = destination(tmp_path, 'links')
	assert restore(tmp_path, capsys, f'{job.monitor}/a.txt', out, '--version', '1')[0] == 0
	assert restore(tmp_path, capsys, f'{job.monitor}/l', out, '--version', '2')[0] == 0
	assert tree(out) == {'a.txt': 'v1', 'l': ('->', 'a.txt')} and partial_files(out) == []
	assert os.lstat(os.path.join(out, 'a.txt')).st_nlink == 1
	# where the filesystem has no hard links, a rename once the name is still free

	def no_links(*args, **kwargs):
		raise PermissionError(1, 'Operation not permitted')
	monkeypatch.setattr(os, 'link', no_links)
	out = destination(tmp_path, 'renamed')
	assert restore(tmp_path, capsys, f'{job.monitor}/a.txt', out, '--version', '1')[0] == 0
	assert tree(out) == {'a.txt': 'v1'}
	out = destination(tmp_path, 'renamed_raced')
	target = os.path.join(out, 'a.txt')
	monkeypatch.setattr(rv, 'finish_restore_copies', appearing)
	code, stdout, _ = restore(tmp_path, capsys, f'{job.monitor}/a.txt', out, '--version', '1')
	assert code == rv.EXIT_COMMAND_FAILED and 'appeared while restoring; left untouched' in stdout
	assert tree(out) == {'a.txt': 'theirs'} and partial_files(out) == []


def test_restore_refuses_a_destination_others_could_change(job, tmp_path, capsys):
	three_versions(job)
	path = f'{job.monitor}/a.txt'

	def under(name, mode, uid=None):
		folder = tmp_path / name
		(folder / 'out').mkdir(parents=True)
		os.chmod(folder, mode)
		if uid is not None:
			os.chown(folder, uid, uid)
		return str(folder), str(folder / 'out')
	# a folder anyone may write in, without the sticky bit: they could swap the destination out from under the restore
	cases = [under('open', 0o777)]
	if os.geteuid() == 0:
		# another user's folder
		cases.append(under('theirs', 0o755, uid=65534))
	for folder, out in cases:
		code, stdout, err = restore(tmp_path, capsys, path, out, '--version', '1')
		assert (code, stdout) == (rv.EXIT_USAGE, ''), folder
		assert folder in err and 'only you (or root) can write to' in err, err
		assert os.listdir(out) == []
		assert rv.unsafe_folder_on_path(out) == folder
	# the destination itself counts
	open_out = tmp_path / 'open_out'
	open_out.mkdir()
	os.chmod(open_out, 0o777)
	assert restore(tmp_path, capsys, path, str(open_out), '--version', '1')[0] == rv.EXIT_USAGE
	assert os.listdir(open_out) == []
	# as /tmp is: anyone may make entries there, but only remove or rename their own
	shared, out = under('shared', 0o1777)
	assert rv.unsafe_folder_on_path(out) is None
	assert restore(tmp_path, capsys, path, out, '--version', '1')[0] == 0
	assert tree(out) == {'a.txt': 'v1'}
	assert rv.unsafe_folder_on_path('/') is None


def test_restore_writes_only_into_the_destination_as_checked(job, tmp_path, capsys, monkeypatch):
	seed_monitor(job, {'proj/a.txt': 'a'})
	run_backup(job)
	write_rule(job)
	first, second = destination(tmp_path, 'first'), destination(tmp_path, 'second')
	link = str(tmp_path / 'link')
	restore_entry = rv.restore_entry

	def repointing(*args, **kwargs):
		# the typed path leads elsewhere once every check is done
		os.remove(link)
		os.symlink(second, link)
		return restore_entry(*args, **kwargs)
	monkeypatch.setattr(rv, 'restore_entry', repointing)
	for path, name in ((f'{job.monitor}/proj', 'proj'), (f'{job.monitor}/proj/a.txt', 'a.txt')):
		if os.path.lexists(link):
			os.remove(link)
		os.symlink(first, link)
		code, stdout, err = restore(tmp_path, capsys, path, link, '--version', '0')
		assert (code, err) == (0, ''), path
		assert stdout.startswith('Restored ') and stdout.rstrip('\n').endswith(f' to {first}/{name}')
	assert tree(first) == {'proj/': None, 'proj/a.txt': 'a', 'a.txt': 'a'}
	assert os.listdir(second) == []
	monkeypatch.setattr(rv, 'restore_entry', restore_entry)
	# <another user's folder>/<link>/.. is where the link leads, up one: never the other user's folder itself
	eve = tmp_path / 'eve'
	eve.mkdir()
	inner = tmp_path / 'safe' / 'inner'
	inner.mkdir(parents=True)
	os.symlink(inner, eve / 'link')
	if os.geteuid() == 0:
		os.chown(eve, 65534, 65534)
	code, stdout, err = restore(tmp_path, capsys, f'{job.monitor}/proj/a.txt', f'{eve}/link/..', '--version', '0')
	assert (code, err) == (0, '')
	assert os.listdir(eve) == ['link']
	assert tree(tmp_path / 'safe') == {'inner/': None, 'a.txt': 'a'}


def test_restore_folder_meta_hands_the_folder_over_last(tmp_path, monkeypatch):
	source, dest = tmp_path / 'source', tmp_path / 'dest'
	source.mkdir()
	dest.mkdir()
	os.chmod(source, 0o2751)
	try:
		os.setxattr(source, 'user.note', b'kept')
		xattrs = True
	except OSError:
		xattrs = False
	if os.geteuid() == 0:
		os.chown(source, 65534, 65534)
	os.utime(source, ns=(1_600_000_000_123_456_789, 1_600_000_000_123_456_789))
	calls = []

	def recording(name, real):
		return lambda target, *args, **kwargs: calls.append((name, target)) or real(target, *args, **kwargs)
	for name in ('chmod', 'utime', 'chown', 'setxattr'):
		monkeypatch.setattr(os, name, recording(name, getattr(os, name)))
	assert rv.restore_folder_meta(str(source), str(dest)) is True
	monkeypatch.undo()
	# all on the folder as opened, never by its path, and the owner handed over last
	assert calls and all(isinstance(target, int) for _, target in calls)
	names = [name for name, _ in calls]
	assert names[-1] == 'chown' and names.count('chown') == 1 and names.index('utime') < names.index('chown')
	st, held = os.lstat(dest), os.lstat(source)
	assert (stat.S_IMODE(st.st_mode), st.st_uid, st.st_gid, st.st_mtime_ns) == (stat.S_IMODE(held.st_mode), held.st_uid, held.st_gid, held.st_mtime_ns)
	if xattrs:
		assert os.getxattr(dest, 'user.note') == b'kept'
	# a symlink in the folder's place is not followed
	elsewhere = tmp_path / 'elsewhere'
	elsewhere.mkdir()
	before = os.lstat(elsewhere)
	os.symlink(elsewhere, tmp_path / 'swapped')
	assert rv.restore_folder_meta(str(source), str(tmp_path / 'swapped')) is False
	after = os.lstat(elsewhere)
	assert (after.st_mode, after.st_uid, after.st_mtime_ns) == (before.st_mode, before.st_uid, before.st_mtime_ns)
