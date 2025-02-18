#! /usr/bin/env python3
import multiCMD
import TSVZ
import inotify_simple
import Tee_Logger
import argparse
import xxhash

from collections import deque
import time
from dataclasses import dataclass
import os
import threading
import sys
import signal

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

JOURNAL_HEADER = ['monotonic_time','event','type','path','moved_from']
# by defualt, set the max backup threads to 2* the number of cores
BACKUP_SEMAPHORE = threading.Semaphore(2*os.cpu_count())

DEFAULT_SNAPSHOT_DELAY = 60
DEFAULT_KEEP_ONE_COMPLETE_BACKUP = False
DEFAULT_ONLY_SYNC_ATTRIBUTES = False
DEFAULT_KEEP_N_VERSIONS = 30
DEFAULT_BACKUP_SIZE_LIMIT = '5%'

GREEN_LIGHT = threading.Event()
GREEN_LIGHT.set()

tl = Tee_Logger.teeLogger(systemLogFileDir='/dev/null', programName='reverberator', compressLogAfterMonths=0, deleteLogAfterYears=0, suppressPrintout=False,noLog=True)

def main():
	signal.signal(signal.SIGINT, signal_handler)
	args, argString = get_args()
	tl = Tee_Logger.teeLogger(systemLogFileDir=args.log_dir, programName=args.program_name, compressLogAfterMonths=args.log_compress_months, deleteLogAfterYears=args.log_delete_years, suppressPrintout=args.quiet)
	tl.teeprint('> ' + argString)
	if args.threads == 0:
		# set the max backup threads to 200k, which is usually about the max for a user set in ulimit. pratically unlimited.
		BACKUP_SEMAPHORE = threading.Semaphore(200000)
	elif args.threads < 0:
		# set the max backup threads to -threads * number of cores
		BACKUP_SEMAPHORE = threading.Semaphore(-args.threads * os.cpu_count())
	else:
		BACKUP_SEMAPHORE = threading.Semaphore(args.threads)
	# parse the rule file
	rules = parse_rules(args.rule_path)
	if not rules:
		tl.teeerror(f'Error: Rule file {args.rule_path} appears empty after parsing.')
		sys.exit(1)
	# start the main loop
	main_threads = []
	for rule in rules:
		job_name = rule[0]
		monitor_path = rule[1]
		monitor_path_signiture = rule[2]
		min_snapshot_delay_seconds = DEFAULT_SNAPSHOT_DELAY
		try:
			min_snapshot_delay_seconds = int(rule[3])
		except:
			tl.teeerror(f'Error: Rule {job_name} has invalid min_snapshot_delay_seconds value: {rule[3]}')
			tl.teeprint(f"Reverting to default value: {DEFAULT_SNAPSHOT_DELAY}")
		vault_path = rule[4]
		vault_path_signiture = rule[5]
		keep_one_complete_backup = rule[6].lower() in ['true','yes','1','t','y','on','enable','enabled','en','e']
		only_sync_attributes = rule[7].lower() in ['true','yes','1','t','y','on','enable','enabled','en','e']
		keep_n_versions = DEFAULT_KEEP_N_VERSIONS
		try:
			keep_n_versions = int(rule[8])
		except:
			tl.teeerror(f'Error: Rule {job_name} has invalid keep_n_versions value: {rule[8]}')
			tl.teeprint(f"Reverting to default value: {DEFAULT_KEEP_N_VERSIONS}")
		backup_size_limit = rule[9]
		vault_path_signiture = rule[10]
		to_process = deque()
		reverberatorThread = threading.Thread(target=reverberator,args=(job_name,monitor_path,monitor_path_signiture,to_process),daemon=True)
		tl.teeprint(f'Starting reverb monitor for {job_name} with monitor path {monitor_path}:{monitor_path_signiture}')
		reverberatorThread.start()
		main_threads.append(reverberatorThread)
		backup_thread = threading.Thread(target=backuper,args=(job_name,to_process,vault_path,vault_path_signiture,min_snapshot_delay_seconds,keep_one_complete_backup,only_sync_attributes,keep_n_versions,backup_size_limit),daemon=True)
		tl.teeprint(f'Starting backup thread for {job_name} with vault path {vault_path}:{vault_path_signiture}')
		tl.info(f'Backup thread will keep one complete backup: {keep_one_complete_backup}, only sync attributes: {only_sync_attributes}, keep n versions: {keep_n_versions}, backup size limit: {backup_size_limit}')
		backup_thread.start()
		main_threads.append(backup_thread)
	for thread in main_threads:
		thread.join()
	tl.teeok('All threads have exited. Exiting main thread.')

def signal_handler(sig, frame):
	'''
	Handle the Ctrl C signal

	Args:
		sig (int): The signal
		frame (frame): The frame

	Returns:
		None
	'''
	if GREEN_LIGHT.is_set():
		tl.teeerror('Ctrl C caught, exiting...')
		GREEN_LIGHT.clear()
	else:
		tl.teeerror('Ctrl C caught again, exiting immediately!')
		# wait for 0.1 seconds to allow the threads to exit
		time.sleep(0.1)
		sys.exit(1)

def get_args(args = None):
	lib_vers = f'inotify_simple {inotify_simple.__version__}; xxhash {xxhash.__version__}; Tee_Logger {Tee_Logger.__version__}; multiCMD {multiCMD.__version__}; TSVZ {TSVZ.__version__}'
	parser = argparse.ArgumentParser(description='Copy files from source to destination')
	parser.add_argument("-ld","--log_dir", type=str, help="Log directory. set to /dev/null to disable verbose file logging. (default:/dev/null)", default='/dev/null')
	parser.add_argument("-pn","--program_name", type=str, help="Program name for log dir (default:reverberator)", default='reverberator')
	parser.add_argument("-lcm","--log_compress_months", type=int, help="Compress verbose log files after months (default:2)", default=2)
	parser.add_argument("-ldy","--log_delete_years", type=int, help="Delete log files after years (default:2)", default=2)
	parser.add_argument('-q', '--quiet', action='store_true', help='Suppress all output to stdout.')
	parser.add_argument('-V', '--version', action='version', version=f"%(prog)s {__version__} with {lib_vers}; reverb (REcursive VERsioning Backup) generator by pan@zopyr.us")
	parser.add_argument('-t','--threads', type=int, help='Number of threads to use for backup. Use negative number for how many times of CPU count you want. Use 0 for 200k. (default: -2)', default=-2)
	parser.add_argument('rule_path', metavar='RULE_PATH', type=str, nargs='?', default='reverb_rule.tsv', help='Path to the rule definition tabular file')
	try:
		args = parser.parse_intermixed_args(args)
	except Exception as e:
		#eprint(f"Error while parsing arguments: {e!r}")
		# try to parse the arguments using parse_known_args
		args, unknown = parser.parse_known_args()
		# if there are unknown arguments, we will try to parse them again using parse_args
		if unknown:
			print(f"Warning: Unknown arguments, treating all as Source Path: {unknown!r}")
			args.rule_path = args.rule_path + unknown
	#print(f'Arguments: {vars(args)}')
	defualt_args_dict = vars(parser.parse_args([]))
	# format a long format argument of what the user supplied and echo it back
	startArgs = [f'> {sys.argv[0]}']
	for argumentName, value in vars(args).items():
		if value != defualt_args_dict[argumentName]:
			if argumentName == 'rule_path':
				continue
			if isinstance(value, list):
				for v in value:
					startArgs.append(f'--{argumentName}=\'{v}\'')
			else:
				startArgs.append(f'--{argumentName}=\'{value}\'')
	for values in args.rule_path:
		startArgs.append(f'\'{values}\'')
	return args, ' '.join(startArgs)

def parse_rules(rule_file:str):
	# will read and parse the rule file using tsvz.
	# this will also responsible for filling in the defaults and auto fields and generating actual rules
	# and append to the end if the rule is not "explicit"
	# explicit: no fields empty / auto
	# will also exit if the rule file is not valid ( broken beyond repair ) / does not exit
	pass

def reverberator(job_name:str,monitor_path:str,monitor_path_signiture:str,to_process:deque):
	# main monitoring function to deal with one reverb.
	monitor_fs_flag = threading.Event()
	monitor_fs_thread = threading.Thread(target=fs_flag_daemon,args=(monitor_path,monitor_path_signiture,monitor_fs_flag),daemon=True)
	monitor_fs_thread.start()
	monitor_fs_flag.wait()
	
	inotify_obj = inotify_simple.INotify()
	pass

def fs_flag_daemon(path:str,signiture:str,fsEvent:threading.Event):
	while GREEN_LIGHT.is_set():
		if check_fs_signiture(path,signiture):
			tl.teeprint(f'FS signiture for {path} verified.')
			fsEvent.set()
		else:
			fsEvent.clear()
		wait_fs_event(path,timeout = 0)

def check_fs_signiture(path:str,signiture:str):
	# not: as findmnt not garenteed to have inode number, and lsblk have more fileds anyway.
		# use findmnt --json --output SOURCE,TARGET,FSTYPE,LABEL,UUID,PARTLABEL,PARTUUID,SIZE,USE%,FSROOT --target 
		# if FS UUID is not available / not match, try part uuid, then fs label, then part label, then dev path
	# df --no-sync --output=source,ipcent,pcent,target for use percentage
	# lsblk --json --output=kname,label,model,name,partlabel,partuuid,uuid,path,serial,fstype,wwn <dev> for infos
	pass

def get_fs_signiture(path:str):
	pass

def wait_fs_event(path:str,timeout = 0):
	# this function waits for fs event
	# use findmnt --poll --first-only --target <path> to do event based wait
	pass

def backuper(job_name:str,to_process:deque,monitor_path:str,vault_path:str,vault_path_signiture:str,min_snapshot_delay_seconds:int = DEFAULT_SNAPSHOT_DELAY, keep_one_complete_backup:bool = DEFAULT_KEEP_ONE_COMPLETE_BACKUP, only_sync_attributes:bool = DEFAULT_ONLY_SYNC_ATTRIBUTES, keep_n_versions:int = DEFAULT_KEEP_N_VERSIONS, backup_size_limit:str = DEFAULT_BACKUP_SIZE_LIMIT, log_journal:bool = False):
	# main function for handling the backup for one reverb
	vault_fs_flag = threading.Event()
	vault_fs_thread = threading.Thread(target=fs_flag_daemon,args=(vault_path,vault_path_signiture,vault_fs_flag),daemon=True)
	vault_fs_thread.start()
	vault_fs_flag.wait()
	prev_to_process_len = 0
	time_to_sleep = 0
	# to_process: deque([ChangedEvent:{'monotonic_time':'231241','event':'create','type':'file','path':'/path/to/file'},...])
	while GREEN_LIGHT.is_set():
		time.sleep(time_to_sleep)
		vault_fs_flag.wait()
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
		if log_journal:
			journalPath = os.path.join(vault_path,job_name,'journal.nsv')
			log_events_to_journal(process_list,journalPath)
		prev_to_process_len = 0
		time_to_sleep = 0
		if GREEN_LIGHT.is_set():
			# appendTabularFile(fileName,lineToAppend,teeLogger = None,header = '',createIfNotExist = False,verifyHeader = True,verbose = False,encoding = 'utf8', strict = True, delimiter = ...)
			if log_journal:
				TSVZ.appendTabularFile(journalPath,[time.monotonic_ns(),'start','reverb',monitor_path,os.path.join(vault_path,job_name)],teeLogger=tl,header=JOURNAL_HEADER,createIfNotExist=True,verifyHeader=False,strict=False)
			do_incremental_backup(process_list,vault_fs_flag)
			if log_journal:
				TSVZ.appendTabularFile(journalPath,[time.monotonic_ns(),'end','reverb',monitor_path,os.path.join(vault_path,job_name)],teeLogger=tl,header=JOURNAL_HEADER,createIfNotExist=True,verifyHeader=False,strict=False)

def log_events_to_journal(change_events:deque,journal_path:str):
	# this function will log the journal of the changes
	# the journal will be a nsv file with the following fields:
	# monotonic_time, event, type, path
	# this will be used to recover the changes in the case of a crash
	pass

def do_incremental_backup(change_events:deque,vault_fs_flag:threading.Event):
	# # if there is no current, do a full backup
	# #do_first_backup(monitor_path,vault_path)
	# # calculate this backup size
	# # calculate vault size
	# # if this backup size + vault size > backup_size_limit
	# # invoke the stepper
	# last_version, last_timestamp = get_vault_info(vault_path,last=True)
	# this_version = last_version + 1
	# this_timestamp = time.time()
	# this_version_path = os.path.join(vault_path,f'V{this_version}-{this_timestamp}')
	# # walk over {vault_path}/current/ and create a new version
	# files, links , folders = get_file_list(os.path.join(vault_path,'current'))
	# # sync the folders to this version to create dir structure
	# sync_folders(folders,this_version_path)
	# # update the folder metadata to this version
	# sync_folders(folder_changed,this_version_path)
	# for file in files + links - file_to_backup - file_to_delete - file_change_attr:
	# 	# ln -srL files to this version path
	# 	pass
	# for file in file_to_backup:
	# 	# cp --reflink=auto --sparse=always -af monitor path files to this version path
	# 	pass
	# for file in file_change_attr:
	# 	# cp --reflink=auto --sparse=always -af vault path files to this version path
	# 	# copy the attr only from monitor path to this version path
	# 	# this is so on fs with CoW support, we can save space by only storing the attr
	with BACKUP_SEMAPHORE:
		# do the actual backup
		pass

def stepper():
	# this function remove the oldest reverb from path
	# stepper determines if it had been called from is there a v0 folder in the vault
	# if stepper had never been called before, it will need to redo the complete vault size calculation again
	#   if the vault size is about the same or bigger as the estimation, do the stepping normally
	#   if the vault size is much smaller than the estimated and smaller than the vault size limit, return
	pass

def get_path_size():
	# this function gets the actual size of a path
	pass