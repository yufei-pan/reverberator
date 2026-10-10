import os
import subprocess
import threading
import pytest
import reverberator as rv
from tests.harness import write_committed_version, wait_until, committed_versions

pytestmark = [
	pytest.mark.privileged,
	pytest.mark.skipif(
		os.geteuid() != 0 and os.environ.get('REVERB_PRIVILEGED') != '1',
		reason='requires root or REVERB_PRIVILEGED=1',
	),
]


def test_unmount_self_destruct_does_not_delete_vault(job, poll_fast, tmp_path):
	# Spec: bind-mount onto monitor, or mount a tmpfs. Bind-umount does not
	# emit IN_UNMOUNT on this kernel; tmpfs umount does.
	subprocess.check_call(['mount', '-t', 'tmpfs', 'tmpfs', job.monitor])
	open(os.path.join(job.monitor, 'a.txt'), 'w').write('keep')
	try:
		v0 = write_committed_version(job, 0, {'a.txt': 'keep'})
		to_process = rv.ChangeEventQueue()
		lock = threading.Lock()
		flag = threading.Event()
		irm = rv.inotify_resource_manager()
		result = []

		def run():
			result.append(rv.watchFolder(
				monitor_path=job.monitor,
				to_process=to_process,
				to_process_lock=lock,
				to_process_flag=flag,
				irm=irm,
				min_snapshot_delay_seconds=0,
				max_shapshot_delay_seconds=60,
			))

		t = threading.Thread(target=run, daemon=True)
		t.start()
		probe = os.path.join(job.monitor, '.watch_ready')
		def ready():
			if os.path.exists(probe):
				os.remove(probe)
			open(probe, 'w').write('1')
			with lock:
				return any(e.event == 'create' and e.path.endswith('.watch_ready') for e in to_process)
		wait_until(ready, timeout=2, message='watcher did not start')
		subprocess.check_call(['umount', job.monitor])
		t.join(timeout=5)
		assert result == [rv.WATCH_RESULT_SELF_DESTRUCT]
		assert os.path.isdir(v0)
		assert committed_versions(job) == [v0]
		with lock:
			assert any(e.event == 'self_destruct' for e in to_process)
	finally:
		rv.GREEN_LIGHT.clear()
		subprocess.call(['umount', job.monitor])
		rv.GREEN_LIGHT.set()
