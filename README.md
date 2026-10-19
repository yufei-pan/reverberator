Design decision:
	When reverberator is in cold start, will not calculate hash to do space efficient move operations to vault.
	When restarting reverberator, will do one backup that will only handle create, modify, delete, attrib.
	The latest version's entries, with the size, mtime, mode, owner and tail hash of what the vault holds for each, are kept in .reverberator_manifest.sqlite in the job vault. Restarts compare the monitored tree against it, and read the vault only for entries it has no record of, and once for each file copied since the previous restart.
	Each job may name a gitignore style Skip List File in its rule row. It is read at start, once the job's disks are ready, and applied to everything read from the monitored path and never to the vault. A job which has used patterns needs the value none to back up everything.
	Change events waiting for a backup are kept compressed, events the backup would skip anyway are dropped as the queue grows, and the queue becomes one full scan only when memory runs short (stalls on memory, little available, or the queue holding a quarter of what is available).

Failure handling and log markers:
	A job that fails (an unreadable disk, a vault that is not ready, an error in a thread) is restarted by itself, while the other jobs keep running. The retry delay starts at 60 s, doubles on each failure, and stops at 1 h. It starts again from 60 s once an attempt has run for an hour before failing. While a disk the job needs is missing, the job waits for it, and logs a failure once the wait reaches 15 min, then once an hour while it lasts.
	A failed read is never taken as a deletion, and a failed copy into the vault never commits a version. A path that cannot be read keeps its last backed-up copy.
	Problems that only a change of the rule or skip list can fix (a skip list that lost its patterns without none, a skip pattern that does not parse, two rows whose names become one job name) stop that job for good, and are not retried.
	Each of these is logged at error level, in exactly this form:
		reverberator job <name> FAILED: <reason>; retrying in <N>s       the job failed and will retry
		reverberator job <name> FAILED: waiting <N> min for <path>: <reason>       a disk the job needs is still missing
		reverberator job <name> UNREADABLE: <path>: <error>; keeping its last backed-up copy       a path could not be read, reported once per backup that meets it
		reverberator job <name> STOPPED: <reason>       the job will not run again until its rule or skip list is fixed and reverberator restarted
		reverberator job <name> RECOVERED after <N> failed attempts       the job works again (informational)
		reverberator EXITING with error: <reason>       the daemon is exiting because of an error
	Exit codes: 0 after a signal (SIGTERM, SIGINT), 1 when the main thread fails, 3 when every job is STOPPED. reverberator.service has RestartPreventExitStatus=3, so systemd does not restart a daemon that would only stop again. Keep that line if you write your own unit file.
	firewatcher/reverberator.txt holds the patterns for the alerting markers (FAILED, UNREADABLE, STOPPED, EXITING); RECOVERED is left out. Copy it to /etc/firewatcher/patterns.d/reverberator.txt, which firewatcher loads from the service's journal.
	Inner mounts: a mount point under a monitored path (read from /proc/self/mountinfo) is backed up while it is mounted. When it is unmounted, its folder is paused: nothing under it is recorded as deleted, its last backed-up contents stay in new versions, and events under it are dropped. When it is mounted again only that subtree is compared with the vault. To retire an inner disk for good, remove the mount point folder, or put files of its own in it; the pause then ends and the folder is backed up as what it now is.
