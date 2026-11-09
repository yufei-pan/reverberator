'''
The daemon as the tests start it in a process of its own (conftest.py's run_reverberator): reverberator.py's own entry
point, with syncfs_fd() standing in as isolated_runtime() has it. The filesystem under a basetemp can hold live trees,
and a test never syncs it.
'''
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

if __name__ == '__main__':
	sys.path.insert(0, ROOT)
	sys.argv[0] = os.path.join(ROOT, 'reverberator.py')
	import reverberator as rv
	# what syncfs_fd() checks without syncing: the fd is open
	rv.syncfs_fd = lambda fd, path=None: os.fstat(fd) and None
	rv.main()
