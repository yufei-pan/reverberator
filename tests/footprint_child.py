'''
The daemon as the footprint gate after a burst starts it (test_footprint.py): daemon_without_syncfs.py's launch, with the trim
after each commit (release_idle_memory()) stubbed out when the environment holds REVERB_FOOTPRINT_NO_COMMIT_TRIM=1, so the gate
shows it tells a daemon that lost that trim. Only this launcher reads the switch; the daemon never does.
'''
import os
import runpy
import sys

HERE = os.path.dirname(os.path.abspath(__file__))

if __name__ == '__main__':
	sys.path.insert(0, os.path.dirname(HERE))
	import reverberator as rv
	if os.environ.get('REVERB_FOOTPRINT_NO_COMMIT_TRIM') == '1':
		rv.release_idle_memory = lambda manifest: None
	# the launch imports the module patched above (sys.modules holds it) and runs its main()
	runpy.run_path(os.path.join(HERE, 'daemon_without_syncfs.py'), run_name='__main__')
