import reverberator as rv


class SysctlTask:
	'''What multiCMD.run_command returns with return_object=True: lists of output lines and a return code.'''
	def __init__(self, stdout=(), returncode=0):
		self.stdout = list(stdout)
		self.stderr = []
		self.returncode = returncode


def fake_sysctl(monkeypatch, reads):
	'''
	sysctl reads answer from reads (field -> value, or None for a read that times out, as under load); every sudo
	sysctl write is recorded and nothing runs.
	'''
	writes = []
	def run_command(command, **kwargs):
		if command[0] == 'sudo':
			writes.append(command[-1])
			return SysctlTask()
		value = reads.get(command[-1])
		if value is None:
			return SysctlTask(returncode=124)
		return SysctlTask([f'{command[-1]} = {value}'])
	monkeypatch.setattr(rv.multiCMD, 'run_command', run_command)
	return writes


def test_a_limit_whose_read_fails_is_never_written(monkeypatch):
	# the startup reads and every later read time out: doubling the unknown limit must not write 0 over the host's
	writes = fake_sysctl(monkeypatch, {})
	manager = rv.inotify_resource_manager()
	for _ in range(3):
		manager.increaseUserInstances()
		manager.increaseUserWatches()
	assert writes == []


def test_a_failed_startup_read_takes_the_value_a_later_read_gives(monkeypatch):
	reads = {}
	writes = fake_sysctl(monkeypatch, reads)
	manager = rv.inotify_resource_manager()
	reads['fs.inotify.max_user_instances'] = 65536
	manager.increaseUserInstances()
	assert writes == []
	assert manager.max_user_instances == 65536


def test_a_limit_is_never_written_at_or_below_its_current_value(monkeypatch):
	writes = fake_sysctl(monkeypatch, {'fs.inotify.max_user_instances': 65536})
	manager = rv.inotify_resource_manager()
	assert manager.setSysctlValues('fs.inotify.max_user_instances', 65536, 'max_user_instances') is False
	assert manager.setSysctlValues('fs.inotify.max_user_instances', 128, 'max_user_instances') is False
	assert writes == []
	assert manager.max_user_instances == 65536


def test_a_limit_below_what_is_needed_is_raised(monkeypatch):
	writes = fake_sysctl(monkeypatch, {'fs.inotify.max_user_instances': 2})
	manager = rv.inotify_resource_manager()
	manager.increaseUserInstances(2)
	assert writes == ['fs.inotify.max_user_instances=4']
	assert manager.max_user_instances == 4


def test_the_suite_never_writes_the_hosts_sysctls():
	# conftest's guard answers any sudo sysctl as refused without running it (a made-up key, so a missing guard
	# fails here rather than changing the host)
	task = rv.multiCMD.run_command(['sudo', 'sysctl', 'reverberator.test.never=1'], timeout=1, quiet=True, return_object=True)
	assert task.returncode == 1
	assert task.stderr == ['the test suite never writes host sysctls']
