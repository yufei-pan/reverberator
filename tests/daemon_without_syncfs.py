'''
The daemon as the tests start it in a process of its own (conftest.py's run_reverberator): reverberator.py's own entry
point, with the syncfs(2) binding standing in as isolated_runtime() has it. The filesystem under a basetemp can hold live trees,
and a test never syncs it.
'''
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

if __name__ == '__main__':
	sys.path.insert(0, ROOT)
	sys.argv[0] = os.path.join(ROOT, 'reverberator.py')
	import reverberator as rv
	# conftest.syncfs_stand_in(): an fd that is not open raises, as the call would fail; else 0, done
	rv.LIBC_SYNCFS = lambda fd: os.fstat(fd) and 0
	rv.main()
