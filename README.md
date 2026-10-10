Design decision:
	When reverberator is in cold start, will not calculate hash to do space efficient move operations to vault.
	When restarting reverberator, will do one backup that will only handle create, modify, delete, attrib.
	The latest version's entries, with the size, mtime, mode, owner and tail hash of what the vault holds for each, are kept in .reverberator_manifest.sqlite in the job vault. Restarts compare the monitored tree against it, and read the vault only for entries it has no record of, and once for each file copied since the previous restart.
