#! /usr/bin/env python3
import multiCMD
import TSVZ
from collections import deque
import time
from dataclasses import dataclass
import xxhash
import os
import inotify_simple

# for the lib wrapping aroung inotify, I tried
# wtr-wather, watchdog, watchfiles
# None of them seem to work well with the most basic tests
# I need it to work with:
# 1. able to notice changes recursively
# 2. able to notice changes in the folders
# 3. do not incorrectly group move events
# 4. recognize mkdir -p properly
# 5. notice umount events and notify properly
# 6. notice mount events and notify properly
# 7. compatible with symlink events 


__version__ = 0.01

## WIP

@dataclass
class ChangeEvent:
	monotonic_time:int
	# type can be file or dir.
	type:str
	# if type is dir, event can be create 
	#  ( need to recursively copy everything as inotifywait does not caputre mkdir -p properly for all sub folders),
	#  ,delete, attrib, move
	# if type is file, event can be delete, change, attrib, move
	# move detection will be handled by monitor if moved_from moved_to events were captured. 
	# it will use an tsv storing all the path inode number and hash to detect move.
	event:str
	path:str
	moved_from:str = None

def path_daemon(monitor_path:str,to_process:deque,vault_path:str):
	journalPath = os.path.join(vault_path,'journal.nsv')
	#inotifywaitObj = multiCMD.run_command(['inotifywait','-m','-r','-e','create,delete,move,attrib','-o',journalPath,monitor_path])
	inotify_obj = inotify_simple.INotify()
	


def backuper(to_process:deque,min_snapshot_delay_seconds:int = 60):
	prev_to_process_len = 0
	time_to_sleep = 0
	# to_process: deque([ChangedEvent:{'monotonic_time':'231241','event':'create','type':'file','path':'/path/to/file'},...])
	while True:
		time.sleep(time_to_sleep)
		if not to_process:
			time_to_sleep = min_snapshot_delay_seconds
			continue
		# if changes detected, continue waiting
		if len(to_process) > prev_to_process_len:
			# check the last change time, sleep for min_snapshot_delay_seconds - (now - last change time)
			last_change_time = to_process[-1]['monotonic_time']
			time_to_sleep = min_snapshot_delay_seconds - (time.monotonic() - last_change_time)
			prev_to_process_len = len(to_process)
			continue
		# If changes detected and after min_snapshot_time, no further changes detected,
		# we will do a snapshot
		process_list = to_process.copy()
		to_process.clear()
		prev_to_process_len = 0
		time_to_sleep = 0
		do_incremental_backup(process_list)
		

def do_incremental_backup(change_events:deque):
	# if there is no current, do a full backup
	#do_first_backup(monitor_path,vault_path)
	last_version, last_timestamp = get_vault_info(vault_path,last=True)
	this_version = last_version + 1
	this_timestamp = time.time()
	this_version_path = os.path.join(vault_path,f'V{this_version}-{this_timestamp}')
	# walk over {vault_path}/current/ and create a new version
	files, links , folders = get_file_list(os.path.join(vault_path,'current'))
	# sync the folders to this version to create dir structure
	sync_folders(folders,this_version_path)
	# update the folder metadata to this version
	sync_folders(folder_changed,this_version_path)
	for file in files + links - file_to_backup - file_to_delete - file_change_attr:
		# ln -srL files to this version path
	for file in file_to_backup:
		# cp --reflink=auto --sparse=always -af monitor path files to this version path
	for file in file_change_attr:
		# cp --reflink=auto --sparse=always -af vault path files to this version path
		# copy the attr only from monitor path to this version path
		# this is so on fs with CoW support, we can save space by only storing the attr