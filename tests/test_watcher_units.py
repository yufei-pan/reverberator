'''
The watcher's functions that need no kernel watch, with a stand-in for the inotify instance: in process, so unit, where the modules
that run them through a real watch are inotify.
'''
import errno
import os

import pytest

import reverberator as rv

pytestmark = pytest.mark.unit


def test_removing_a_watch_already_gone_does_nothing():
	class FakeINotify:
		def __init__(self):
			self.removed = []
		def rm_watch(self, wd):
			self.removed.append(wd)
	class FakeIrm:
		decreased = 0
		def decreaseUserWatches(self, count=1):
			self.decreased += count
	inotify_obj, irm, wd_dic, forgotten = FakeINotify(), FakeIrm(), {1: '/m/a/', 2: '/m/b/'}, []
	assert rv.remove_watches(inotify_obj, wd_dic, irm, [1, 3, 1], forgotten.append) == 1
	assert inotify_obj.removed == [1] and irm.decreased == 1 and wd_dic == {2: '/m/b/'} and forgotten == [1]


@pytest.mark.parametrize('error, logged_as_error', [(errno.ENOENT, False), (errno.ENOTDIR, False), (errno.EACCES, True)])
def test_a_watch_failing_for_a_folder_that_is_gone_logs_info(tmp_path, monkeypatch, error, logged_as_error):
	# a folder made and removed before its watch is added (pytest-cache-files-* folders) is a normal race that misses
	# nothing: an info line; any other failure stays an error
	monitor = tmp_path / 'm'
	(monitor / 'gone').mkdir(parents=True)
	gone = str(monitor / 'gone')
	class FakeINotify:
		def __init__(self):
			self.next = 1
		def add_watch(self, path, mask):
			if os.path.abspath(path).rstrip('/') == gone:
				raise OSError(error, os.strerror(error))
			self.next += 1
			return self.next
	class FakeIrm:
		def increaseUserWatches(self):
			pass
		def decreaseUserWatches(self):
			pass
	lines = []
	monkeypatch.setattr(rv, 'watcherTeeLogToTl', lambda monitor_path, message, error=False, ok=False: lines.append((message, error)))
	unwatched = set()
	rv.initializeFolderWatchers(FakeINotify(), str(monitor), {}, FakeIrm(), 0, unwatched=unwatched)
	failed = [(message, is_error) for message, is_error in lines if 'Failed to add watch' in message]
	assert failed == [(f'Failed to add watch for {gone}/: [Errno {error}] {os.strerror(error)}', logged_as_error)] or \
		failed == [(f'Failed to add watch for {gone}: [Errno {error}] {os.strerror(error)}', logged_as_error)], lines
	assert unwatched == ({gone} if logged_as_error else set())
