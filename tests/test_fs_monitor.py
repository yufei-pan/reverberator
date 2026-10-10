import os
import subprocess
import pytest
import reverberator as rv
from tests.harness import write_rule, seed_monitor, wait_for_committed_count, wait_until

ROOT_LINE = '22 1 8:1 / / rw - ext4 /dev/sda1 rw\n'


def write_mountinfo(path, *extra_lines):
	with open(path, 'w', encoding='utf-8') as f:
		f.write(ROOT_LINE + ''.join(extra_lines))


@pytest.fixture
def counted_signatures(monkeypatch):
	calls = []
	result = {'value': ['sig']}

	def fake(path):
		calls.append(path)
		return result['value']
	monkeypatch.setattr(rv, 'get_fs_signatures', fake)
	return calls, result


@pytest.fixture
def manual_monitor(tmp_path, monkeypatch):
	# no background thread: the test drives check_changed() itself
	mountinfo = str(tmp_path / 'mountinfo')
	write_mountinfo(mountinfo)
	monitor = rv.fs_signature_monitor(mountinfo_path=mountinfo)
	monkeypatch.setattr(monitor, 'start', lambda: None)
	return monitor, mountinfo


def test_shared_pair_is_checked_once_with_independent_flags(manual_monitor, counted_signatures, tmp_path):
	monitor, _ = manual_monitor
	calls, _ = counted_signatures
	first = monitor.register(str(tmp_path), 'sig')
	second = monitor.register(str(tmp_path), 'sig')
	monitor.check_changed()
	assert len(calls) == 1
	assert first.is_set() and second.is_set()
	# a caller clearing its own flag (watcher self destruct) does not touch the other one
	first.clear()
	monitor.check_changed()
	assert len(calls) == 1
	assert not first.is_set() and second.is_set()
	# a late registrant for a known pair gets the last result without a new check
	assert monitor.register(str(tmp_path), 'sig').is_set()
	assert len(calls) == 1


def test_only_containing_mount_changes_trigger_recheck(manual_monitor, counted_signatures, tmp_path):
	monitor, mountinfo = manual_monitor
	calls, result = counted_signatures
	path = os.path.realpath(str(tmp_path))
	flag = monitor.register(path, 'sig')
	monitor.check_changed()
	assert flag.is_set() and len(calls) == 1
	write_mountinfo(mountinfo, '40 22 8:17 / /unrelated rw - xfs /dev/sdb1 rw\n')
	monitor.check_changed()
	assert len(calls) == 1
	# a new mount over the path: re-checked, and the signature no longer matches
	result['value'] = ['other']
	write_mountinfo(mountinfo, f'41 22 8:33 / {path} rw - xfs /dev/sdc1 rw\n')
	monitor.check_changed()
	assert len(calls) == 2
	assert not flag.is_set()


def test_unsigned_pair_sets_flag_without_running_commands(monkeypatch, poll_fast, tmp_path):
	def fail(path):
		raise AssertionError('unsigned pairs must not run df / lsblk')
	monkeypatch.setattr(rv, 'get_fs_signatures', fail)
	monitor = rv.fs_signature_monitor()
	flag = monitor.register(str(tmp_path), 'N/A')
	wait_until(flag.is_set, timeout=2, message='unsigned flag never set')
	monitor.unregister(str(tmp_path), 'N/A', flag)
	assert not monitor.flags


@pytest.mark.privileged
@pytest.mark.skipif(os.geteuid() != 0 and os.environ.get('REVERB_PRIVILEGED') != '1', reason='requires root or REVERB_PRIVILEGED=1')
def test_real_mount_and_umount_toggle_flag(poll_fast, tmp_path):
	target = tmp_path / 'mnt'
	target.mkdir()
	# df reports the tmpfs source name and lsblk cannot resolve it, so it is the signature
	signature = f'reverb_probe_{os.getpid()}'
	monitor = rv.fs_signature_monitor()
	flag = monitor.register(str(target), signature)
	assert monitor.thread is not None
	wait_until(lambda: monitor.states.get((str(target), signature)) is False, timeout=5, message='initial check did not run')
	assert not flag.is_set()
	subprocess.check_call(['mount', '-t', 'tmpfs', signature, str(target)])
	try:
		wait_until(flag.is_set, timeout=5, message='mount not noticed')
	finally:
		subprocess.check_call(['umount', str(target)])
	wait_until(lambda: not flag.is_set(), timeout=5, message='umount not noticed')


@pytest.mark.process
def test_daemon_keeps_no_child_processes(job, run_reverberator):
	seed_monitor(job, {'a.txt': 'hello'})
	write_rule(job)
	proc = run_reverberator(job.rule_path)
	wait_for_committed_count(job, 1, timeout=10)

	def children():
		found = []
		for tid in os.listdir(f'/proc/{proc.pid}/task'):
			with open(f'/proc/{proc.pid}/task/{tid}/children', encoding='utf-8') as f:
				found.extend(f.read().split())
		return found
	assert children() == []
