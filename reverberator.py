#! /usr/bin/env python3
import multiCMD
import TSVZ
import inotify_simple
import Tee_Logger
import argparse
import xxhash

from collections import deque
import time
from collections import namedtuple
from collections import OrderedDict
import os
import threading
import sys
import signal
import resource

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

# @dataclass
# class ChangeEvent:
# 	monotonic_time:int
# 	# type can be file or dir.
# 	type:str
# 	# if type is dir, event can be create 
# 	#  ( need to recursively copy everything as inotifywait does not caputre mkdir -p properly for all sub folders),
# 	#  ,delete, attrib, move
# 	# if type is file, event can be delete, change, attrib, move
# 	# move detection will be handled by monitor if moved_from moved_to events were captured. 
# 	# it will use an tsv storing all the path inode number and hash to detect move.
# 	event:str
# 	path:str
# 	moved_from:str = None


# if type is dir, event can be create 
#  ( need to recursively copy everything as inotifywait does not caputre mkdir -p properly for all sub folders),
#  ,delete, attrib, move
# if type is file, event can be delete, change, attrib, move
# move detection will be handled by monitor if moved_from moved_to events were captured. 
# it will use an tsv storing all the path inode number and hash to detect move.

ChangeEvent = namedtuple('ChangeEvent', ['monotonic_time', 'is_dir', 'event', 'path','moved_from'])

JOURNAL_HEADER = ['monotonic_time','event','type','path','moved_from']
# by defualt, set the max backup threads to 2* the number of cores
BACKUP_SEMAPHORE = threading.Semaphore(2*os.cpu_count())

DEFAULT_SNAPSHOT_DELAY = 60
DEFAULT_KEEP_ONE_COMPLETE_BACKUP = False
DEFAULT_ONLY_SYNC_ATTRIBUTES = False
DEFAULT_KEEP_N_VERSIONS = 30
DEFAULT_BACKUP_SIZE_LIMIT = '5%'

COOKIE_DICT_MAX_SIZE = 16384

GREEN_LIGHT = threading.Event()
GREEN_LIGHT.set()

DEBUG = True

tl = Tee_Logger.teeLogger(systemLogFileDir='/dev/null', programName='reverberator', compressLogAfterMonths=0, deleteLogAfterYears=0, suppressPrintout=False,noLog=True)

def main():
	global BACKUP_SEMAPHORE
	global tl
	global GREEN_LIGHT
	global DEFAULT_SNAPSHOT_DELAY
	global DEFAULT_KEEP_ONE_COMPLETE_BACKUP
	global DEFAULT_ONLY_SYNC_ATTRIBUTES
	global DEFAULT_KEEP_N_VERSIONS
	global DEFAULT_BACKUP_SIZE_LIMIT
	global DEBUG
	signal.signal(signal.SIGINT, signal_handler)
	args, argString = get_args()
	tl = Tee_Logger.teeLogger(systemLogFileDir=args.log_dir, programName=args.program_name, compressLogAfterMonths=args.log_compress_months, deleteLogAfterYears=args.log_delete_years, suppressPrintout=args.quiet)
	tl.teeprint('> ' + argString)
	if args.verbose:
		DEBUG = True
	# warn the user if reverberator is not run as root
	if os.geteuid() != 0:
		tl.teeerror('Warning: reverberator is not run as root, dynamic nofile tuning will not work. And file permissions can cause errors.')
	irm = inotify_resource_manager()
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
		if rule[6].lower() == 'none':
			keep_one_complete_backup = DEFAULT_KEEP_ONE_COMPLETE_BACKUP
		else:
			keep_one_complete_backup = rule[6].lower() in ['true','yes','1','t','y','on','enable','enabled','en','e']
		if rule[7].lower() == 'none':
			only_sync_attributes = DEFAULT_ONLY_SYNC_ATTRIBUTES
		else:
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
		to_process_flag = threading.Event()
		watcherThread = threading.Thread(target=watcher,args=(job_name,monitor_path,monitor_path_signiture,to_process,to_process_flag,irm),daemon=True)
		tl.teeprint(f'Starting reverb monitor for {job_name} with monitor path {monitor_path}:{monitor_path_signiture}')
		watcherThread.start()
		main_threads.append(watcherThread)
		backup_thread = threading.Thread(target=backuper,args=(job_name,to_process,vault_path,vault_path_signiture,to_process_flag,min_snapshot_delay_seconds,keep_one_complete_backup,only_sync_attributes,keep_n_versions,backup_size_limit),daemon=True)
		tl.teeprint(f'Starting backup thread for {job_name} with vault path {vault_path}:{vault_path_signiture}')
		tl.info(f'Backup thread will keep one complete backup: {keep_one_complete_backup}, only sync attributes: {only_sync_attributes}, keep n versions: {keep_n_versions}, backup size limit: {backup_size_limit}')
		backup_thread.start()
		main_threads.append(backup_thread)
	for thread in main_threads:
		thread.join()
	tl.teeok('All threads have exited. Exiting main thread.')

def signal_handler(sig, frame):
	global GREEN_LIGHT
	global tl
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
	'''
	Parse the arguments

	Args:
		args (list): The arguments

	Returns:
		args (Namespace): The parsed arguments
		argString (str): The non defualt arguments in string format

	Example:
		>>> get_args(['-ld','/tmp','--verbose','--threads=4','rule.tsv'])[0]
		Namespace(log_dir='/tmp', program_name='reverberator', log_compress_months=2, log_delete_years=2, quiet=False, verbose=True, threads=4, rule_path='rule.tsv')
		>>> get_args(['-ld','/tmp','-pn','reverb','--log_compress_months=3','--log_delete_years=3','--quiet','--verbose','--threads=4','rule.tsv'])[1].partition('--')[2]
		"log_dir=\'/tmp\' --program_name=\'reverb\' --log_compress_months=\'3\' --log_delete_years=\'3\' --quiet=\'True\' --verbose=\'True\' --threads=\'4\' \'rule.tsv\'"
	'''
	global __version__
	lib_vers = f'inotify_simple {inotify_simple.__version__}; xxhash {xxhash.VERSION}; Tee_Logger {Tee_Logger.__version__}; multiCMD {multiCMD.__version__}; TSVZ {TSVZ.__version__}'
	parser = argparse.ArgumentParser(description='Copy files from source to destination')
	parser.add_argument("-ld","--log_dir", type=str, help="Log directory. set to /dev/null to disable verbose file logging. (default:/dev/null)", default='/dev/null')
	parser.add_argument("-pn","--program_name", type=str, help="Program name for log dir (default:reverberator)", default='reverberator')
	parser.add_argument("-lcm","--log_compress_months", type=int, help="Compress verbose log files after months (default:2)", default=2)
	parser.add_argument("-ldy","--log_delete_years", type=int, help="Delete log files after years (default:2)", default=2)
	parser.add_argument('-q', '--quiet', action='store_true', help='Suppress all output to stdout.')
	parser.add_argument('-v','--verbose','--debug', action='store_true', help='Print debug logs.')
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
	default_args_dict = vars(parser.parse_args([]))
	# format a long format argument of what the user supplied and echo it back
	startArgs = [f'> {sys.argv[0]}']
	for argumentName, value in vars(args).items():
		if value != default_args_dict[argumentName]:
			if argumentName == 'rule_path':
				continue
			if isinstance(value, list):
				for v in value:
					startArgs.append(f'--{argumentName}=\'{v}\'')
			else:
				startArgs.append(f'--{argumentName}=\'{value}\'')
	startArgs.append(f'\'{args.rule_path}\'')
	return args, ' '.join(startArgs)

class inotify_resource_manager:
	def __init__(self):
		global DEBUG
		self.current_user_instances = 0
		self.current_user_watches = 0
		self.can_set_max_queued_events = True
		self.can_set_max_user_instances = True
		self.can_set_max_user_watches = True
		self.can_set_max_no_files = True
		self.can_set_max_no_files_user = True
		self.debug = DEBUG
		self.max_queued_events = self.getSysctlValues('fs.inotify.max_queued_events')
		self.max_user_instances = self.getSysctlValues('fs.inotify.max_user_instances')
		self.max_user_watches = self.getSysctlValues('fs.inotify.max_user_watches')
		self.max_no_files = self.getSysctlValues('fs.file-max')
		try:
			soft , hard = resource.getrlimit(resource.RLIMIT_NOFILE)
			if soft < hard:
				resource.setrlimit(resource.RLIMIT_NOFILE, (hard, hard))
			self.max_no_files_user = hard
		except:
			self.max_no_files_user = 0

	def __iter__(self):
		for key in self.__dict__.keys():
			yield key, getattr(self,key)

	def __str__(self):
		# do not include the can_set in the string representation
		return str(dict((k, v) for k, v in self.__dict__.items() if not k.startswith('can_set_')))
	
	def __repr__(self):
		return str(dict(self))

	def getSysctlValues(self,field):
		global tl
		try:
			rtn = multiCMD.run_command(['sysctl',field],timeout=1,quiet=not self.debug)
			if rtn and rtn[0]:
				return int(rtn[0].split('=')[-1].strip())
		except:
			import traceback
			tl.error(traceback.format_exc())
			tl.error(f'Failed to get {field} value')
		return 0
	
	def setSysctlValues(self,field,value,value_name):
		global tl
		try:
			if not getattr(self,f'can_set_{value_name}'):
				return False
			if value is ...:
				value = getattr(self,value_name)
			# check if the current value is less
			rtn = self.getSysctlValues(field)
			if rtn and rtn > value:
				tl.info(f'Current {field} is already higher than {value}')
				setattr(self,value_name,rtn)
				return False
			rc = multiCMD.run_command(['sudo','sysctl',f'{field}={value}'],timeout=1,quiet=not self.debug,return_code_only=True)
			if self.debug:
				tl.teeprint(f'sudo sysctl {field}={value} return code = {rc}')
			if rc:
				if self.debug:
					tl.teeprint(f'Failed to set {field} to {value}')
				else:
					tl.info(f'Failed to set {field} to {value}')
				setattr(self,f'can_set_{value_name}',False)
				if rtn:
					setattr(self,value_name,rtn)
				return False
			else:
				tl.teeok(f'Increased inotify {field} to {value}')
				setattr(self,value_name,value)
				return True
		except:
			try:
				import traceback
				tl.error(traceback.format_exc())
				tl.teeerror(f'Failed to set {field} = {value} for {value_name}')
				setattr(self,f'can_set_{value_name}',False)
				rtn = self.getSysctlValues(field)
				if rtn:
					setattr(self,value_name,rtn)
				else:
					setattr(self,value_name,-1)
			except:
				tl.teeerror(f'Failed to set {field} value')
		return False

	def increaseInotifyMaxQueueEvents(self,max_events:int = ...):
		if not self.can_set_max_queued_events:
			return False
		return self.setSysctlValues('fs.inotify.max_queued_events',max_events,'max_queued_events')

	def increaseInotifyMaxUserInstances(self,max_instances:int = ...):
		if not self.can_set_max_user_instances:
			return False
		return self.setSysctlValues('fs.inotify.max_user_instances',max_instances,'max_user_instances')

	def increaseInotifyMaxUserWatches(self,max_watches:int = ...):
		if not self.can_set_max_user_watches:
			return False
		rtn = self.setSysctlValues('fs.inotify.max_user_watches',max_watches,'max_user_watches')
		rtn2 = self.increaseNoFiles(max_watches)
		return rtn and rtn2

	def increaseNoFiles(self,nofile:int = ...):
		global tl
		if not self.can_set_max_no_files_user:
			return False
		if nofile is ...:
			nofile = self.max_no_files
		# attempt to increase the open file limit
		try:
			# check if the current value is less
			if resource.getrlimit(resource.RLIMIT_NOFILE)[0] > nofile:
				if self.debug:
					tl.teeprint(f'Current open file limit is already higher than {nofile}')
				else:
					tl.info(f'Current open file limit is already higher than {nofile}')
				self.max_no_files = resource.getrlimit(resource.RLIMIT_NOFILE)[0]
				return False
			rtn = self.__increaseSystemNoFiles(nofile)
			resource.setrlimit(resource.RLIMIT_NOFILE, (nofile, nofile))
			tl.teeok(f'Increased open file limit to {nofile}')
			self.max_no_files = nofile
			return rtn
		except:
			import traceback
			tl.error(traceback.format_exc())
			tl.teeerror(f'Failed to increase open file limit to {nofile}')
			self.can_set_max_no_files_user = False
			return False

	def __increaseSystemNoFiles(self,nofile:int):
		if not self.can_set_max_no_files:
			return False
		return self.setSysctlValues('fs.file-max',nofile,'max_no_files')

	def increaseUserInstances(self,count:int = 1):
		self.current_user_instances += count
		if self.max_user_instances <= self.current_user_instances:
			self.increaseInotifyMaxUserInstances(self.max_user_instances * 2)
		return self.current_user_instances
	
	def decreaseUserInstances(self,count:int = 1):
		self.current_user_instances -= count
		return self.current_user_instances
	
	def increaseUserWatches(self,count:int = 1):
		self.current_user_watches += count
		if self.max_user_watches <= self.current_user_watches:
			self.increaseInotifyMaxUserWatches(self.max_user_watches * 2)
		return self.current_user_watches
	
	def decreaseUserWatches(self,count:int = 1):
		self.current_user_watches -= count
		return self.current_user_watches

def parse_rules(rule_file:str):
	'''
	Parse the rule file using TSVZ and fill in the defaults and auto fields

	Args:
		rule_file (str): The rule file

	Returns:
		rules (list): The rules
	'''
	# will read and parse the rule file using tsvz.
	# this will also responsible for filling in the defaults and auto fields and generating actual rules
	# and append to the end if the rule is not "explicit"
	# explicit: no fields empty / auto
	# will also exit if the rule file is not valid ( broken beyond repair ) / does not exit
	global DEBUG
	global DEFAULT_SNAPSHOT_DELAY
	global DEFAULT_KEEP_ONE_COMPLETE_BACKUP
	global DEFAULT_ONLY_SYNC_ATTRIBUTES
	global DEFAULT_KEEP_N_VERSIONS
	global DEFAULT_BACKUP_SIZE_LIMIT
	global tl
	if not os.path.exists(rule_file):
		tl.teeerror(f'Error: Rule file {rule_file} does not exist.')
		sys.exit(1)
	header = ['Job Name (Unique Key)', 'Path Monitoring', 'Monitoring File System Signiture', 
		   'Minium snapshot time', 'Vault Path', 'Keep 1 Compelete Backup', 
		   'Only Sync Attributes (permissions)', 'Keep N versions', 'Backup Size Limit', 
		   'Vault File System Signiture']
	rules = TSVZ.readTabularFile(rule_file,header=header,verifyHeader=True,strict=False,verbose=DEBUG)
	if not rules:
		tl.teeerror(f'Error: Rule file {rule_file} appears empty after parsing.')
		sys.exit(1)
	# fill in empty / auto and append:
	rulesToRemove = []
	for ruleName in rules:
		ruleList = rules[ruleName]
		if DEBUG:
			tl.teeprint(f'Checking rule: {ruleList}')
		ruleUpdated = False
		if not ruleList[0]:
			tl.teelog(f'Warning: Rule {ruleName} has empty Job Name. Ignoring rule...',level='warning')
			rulesToRemove.append(ruleName)
			continue
		if not ruleList[1]:
			tl.teelog(f'Warning: Rule {ruleName} has empty Path Monitoring. Ignoring rule...',level='warning')
			rulesToRemove.append(ruleName)
			continue
		if not ruleList[2] or ruleList[2].lower() == 'auto':
			signitures = get_fs_signitures(ruleList[1])
			if signitures and signitures[0]:
				ruleList[2] = signitures[0]
				tl.teelog(f'Auto filled Monitoring File System Signiture for {ruleName}: {ruleList[2]}',level='info')
				ruleUpdated = True
			else:
				tl.teelog(f'Warning: Rule {ruleName} failed to get the fs signiture, disabling fs monitoring for this run...',level='warning')
				ruleList[2] = 'auto'
		if not ruleList[3] or ruleList[3].lower() == 'none':
			ruleList[3] = '0'
			tl.info(f'Zeroed Minium snapshot time for {ruleName}: {ruleList[3]}')
			ruleUpdated = True
		elif ruleList[3].lower() == 'auto':
			ruleList[3] = DEFAULT_SNAPSHOT_DELAY
			tl.info(f'Auto filled Minium snapshot time for {ruleName}: {ruleList[3]}')
			ruleUpdated = True
		if not ruleList[4]:
			tl.teelog(f'Warning: Rule {ruleName} has empty Vault Path. Ignoring rule...',level='warning')
			rulesToRemove.append(ruleName)
			continue
		if not ruleList[5] or ruleList[5].lower() == 'auto' or ruleList[5].lower() == 'none':
			ruleList[5] = str(DEFAULT_KEEP_ONE_COMPLETE_BACKUP)
			tl.info(f'Auto filled Keep 1 Compelete Backup for {ruleName}: {ruleList[5]}')
			ruleUpdated = True
		if not ruleList[6] or ruleList[6].lower() == 'auto' or ruleList[6].lower() == 'none':
			ruleList[6] = str(DEFAULT_ONLY_SYNC_ATTRIBUTES)
			tl.info(f'Auto filled Only Sync Attributes for {ruleName}: {ruleList[6]}')
			ruleUpdated = True
		if not ruleList[7] or ruleList[7].lower() == 'none':
			ruleList[7] = '0'
			tl.info(f'Zeroed Keep N versions for {ruleName}: {ruleList[7]}')
			ruleUpdated = True
		elif ruleList[7].lower() == 'auto':
			ruleList[7] = DEFAULT_KEEP_N_VERSIONS
			tl.info(f'Auto filled Keep N versions for {ruleName}: {ruleList[7]}')
			ruleUpdated = True
		if not ruleList[8] or ruleList[8].lower() == 'auto' or ruleList[8].lower() == 'none':
			ruleList[8] = DEFAULT_BACKUP_SIZE_LIMIT
			tl.info(f'Auto filled Backup Size Limit for {ruleName}: {ruleList[8]}')
			ruleUpdated = True
		if not ruleList[9] or ruleList[9].lower() == 'auto':
			signitures = get_fs_signitures(ruleList[4])
			if signitures and signitures[0]:
				ruleList[9] = signitures[0]
				tl.teelog(f'Auto filled Vault File System Signiture for {ruleName}: {ruleList[9]}',level='info')
				ruleUpdated = True
			else:
				tl.teelog(f'Warning: Rule {ruleName} failed to get the fs signiture, disabling fs monitoring for this run...',level='warning')
				ruleList[9] = 'auto'
		if ruleUpdated:
			tl.info(f'Updated rule {ruleName}: {ruleList}')
			# append to tsv as well
			TSVZ.appendTabularFile(rule_file,ruleList,header=header,createIfNotExist=False,verifyHeader=True,verbose=DEBUG,strict=False)
	# remove the rules that are invalid
	for ruleName in rulesToRemove:
		rules.remove(ruleName)
		tl.teeprint(f'Removed invalid rule: {ruleName}')
	return rules

def watcher(job_name:str,monitor_path:str,monitor_path_signiture:str,to_process:deque,to_process_flag:threading.Event,irm:inotify_resource_manager):
	global GREEN_LIGHT
	# main monitoring function to deal with one reverb.
	monitor_fs_flag = threading.Event()
	monitor_fs_thread = threading.Thread(target=fs_flag_daemon,args=(monitor_path,monitor_path_signiture,monitor_fs_flag),daemon=True)
	tl.teeprint(f'Starting path watcher {job_name} for {monitor_path}')
	monitor_fs_thread.start()
	while GREEN_LIGHT.is_set():
		monitor_fs_flag.wait()
		watchFolder(monitor_path=monitor_path,to_process=to_process,to_process_flag=to_process_flag,irm=irm)

def watchFolder(monitor_path:str,to_process:deque,to_process_flag:threading.Event,irm:inotify_resource_manager):
	global COOKIE_DICT_MAX_SIZE
	global tl
	global GREEN_LIGHT
	flags = inotify_simple.flags
	watch_flags = flags.MODIFY | flags.ATTRIB | flags.MOVED_FROM | flags.MOVED_TO | flags.CREATE | flags.DELETE | flags.DELETE_SELF | flags.MOVE_SELF | flags.UNMOUNT | flags.Q_OVERFLOW
	selfDestructMask = flags.UNMOUNT | flags.DELETE_SELF | flags.MOVE_SELF
	cookieDic = OrderedDict()
	wdDic = {}
	irm.increaseUserInstances()
	with inotify_simple.INotify() as inotify_obj:
		mainWatchDescriptor = initializeFolderWatchers(inotify_obj,monitor_path,wdDic,irm,watch_flags)
		while GREEN_LIGHT.is_set():
			events =  inotify_obj.read(read_delay=1)
			monTime = time.monotonic_ns()
			for event in events:
				if event.mask & flags.Q_OVERFLOW:
					tl.teeerror('Queue overflow, event maybe lost')
					tl.teeprint('Attempting to increase inotify max_queued_events')
					irm.increaseInotifyMaxQueueEvents(irm.max_queued_events * 2)
					continue
				if event.mask & selfDestructMask:
					if event.wd == mainWatchDescriptor:
						# if UNMOUNT or IGNORED or DELETE_SELF, MOVE_SELF, return false
						irm.decreaseUserWatches(len(wdDic))
						irm.decreaseUserInstances()
						return False
					elif event.mask & flags.DELETE_SELF:
						wdDic.pop(event.wd)
						irm.decreaseUserWatches()
						continue
					elif event.mask & flags.UNMOUNT:
						wdDic.pop(event.wd)
						wdDic[inotify_obj.add_watch(wdDic[event.wd], watch_flags)] = wdDic[event.wd]
						continue
				if not event.wd in wdDic:
					tl.teeerror('Watch descriptor not found in wdDic, ignoring event')
					continue
				if not event.name:
					continue
				eventPath = os.path.join(wdDic[event.wd],event.name)
				isDir = True if event.mask & flags.ISDIR else False
				if event.mask & flags.CREATE:
					if isDir:
						initializeFolderWatchers(inotify_obj,eventPath,wdDic,irm,watch_flags)
					to_process.append(ChangeEvent(monTime,isDir,'create',eventPath,None))
				elif event.mask & flags.DELETE:
					if isDir:
						inotify_obj.rm_watch(event.wd)
						del wdDic[event.wd]
						irm.decreaseUserWatches()
					to_process.append(ChangeEvent(monTime,isDir,'delete',eventPath,None))
				elif event.mask & flags.ATTRIB:
					to_process.append(ChangeEvent(monTime,isDir,'attrib',eventPath,None))
				elif event.mask & flags.MOVED_FROM:
					cookieDic[event.cookie] = (event.wd,eventPath,isDir)
					while len(cookieDic) > COOKIE_DICT_MAX_SIZE:
						cookie,value = cookieDic.popitem(last=False)
						# treat the move as a delete
						if value[2]:
							inotify_obj.rm_watch(value[0])
							del wdDic[value[0]]
							irm.decreaseUserWatches()
						to_process.append(ChangeEvent(monTime,isDir,'delete',value[1],None))
					to_process.append(ChangeEvent(monTime,isDir,'move',eventPath,None))
				elif event.mask & flags.MOVED_TO:
					if event.cookie in cookieDic:
						to_process.append(ChangeEvent(monTime,isDir,'move',eventPath,cookieDic[event.cookie][1]))
						cookieDic.pop(event.cookie)
					else:
						if isDir:
							initializeFolderWatchers(inotify_obj,eventPath,wdDic,irm,watch_flags)
						to_process.append(ChangeEvent(monTime,isDir,'create',eventPath,None))
				elif event.mask & flags.MODIFY:
					to_process.append(ChangeEvent(monTime,isDir,'modify',eventPath,None))
				# else:
				# 	tl.info(f'Unprocessed event {event}')
			to_process_flag.set()

def testWatchFolderOperation(testCMD:list,to_process:deque,to_process_flag:threading.Event):
	multiCMD.run_command(testCMD)
	to_process_flag.wait(1)
	print(to_process)
	to_process.clear()
	to_process_flag.clear()

def initializeFolderWatchers(inotify_obj:inotify_simple.INotify,monitor_path:str,wdDic:dict,irm:inotify_resource_manager,watch_flags:int):
	irm.increaseUserWatches()
	parentWatchDescriptor = inotify_obj.add_watch(monitor_path, watch_flags)
	wdDic[parentWatchDescriptor] = monitor_path
	allFolders = get_all_folders(monitor_path)
	irm.increaseUserWatches(len(allFolders))
	for folder in allFolders:
		wdDic[inotify_obj.add_watch(folder, watch_flags)] = folder
	return parentWatchDescriptor

def get_all_folders(path):
    folders = []
    try:
        with os.scandir(path) as entries:
            for entry in entries:
                if entry.is_dir(follow_symlinks=False):
                    folders.append(entry.path)
                    folders.extend(get_all_folders(entry.path))  # Recursive call
    except PermissionError:
        pass  # Skip folders without permission
    return folders

def fs_flag_daemon(path:str,signiture:str,fsEvent:threading.Event):
	global GREEN_LIGHT
	global tl
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
	# lsblk --raw --paths --output=kname,label,model,name,partlabel,partuuid,uuid,serial,fstype,wwn <dev> for infos
	if not signiture or signiture == 'N/A' or signiture == 'auto':
		return True
	pathSignitures = get_fs_signitures(path)
	if not pathSignitures:
		return False
	return signiture in pathSignitures

def get_fs_signitures(path:str) -> str:
	global DEBUG
	# df --no-sync --output=source,ipcent,pcent,target for use percentage
	# lsblk --raw --paths --output=kname,label,model,name,partlabel,partuuid,uuid,serial,fstype,wwn <dev> for infos
	rtnHost = multiCMD.run_command(['df','--no-sync','--output=source',path],timeout=60,quiet=DEBUG,return_object=True)
	if rtnHost.returncode != 0 or not rtnHost.stdout or not len(rtnHost.stdout) > 1:
		return None
	deviceName = rtnHost.stdout[1].split()[0]
	rtnHost = multiCMD.run_command(['lsblk','--raw','--output=uuid,label,partuuid,partlabel,wwn,serial,model,name,kname,pkname',deviceName],timeout=60,quiet=DEBUG,return_object=True)
	if rtnHost.returncode != 0 or not rtnHost.stdout or not len(rtnHost.stdout) > 1:
		return None
	fields = rtnHost.stdout[1].split()
	# lsblk do \x escape for some characters, we need to unescape them
	fields = [bytes(f, 'utf-8').decode('unicode_escape') for f in fields if f]
	return fields

def wait_fs_event(path:str,timeout = 0):
	global DEBUG
	global GREEN_LIGHT
	# this function waits for fs event
	# use findmnt --poll --first-only --target <path> to do event based wait
	command = ['findmnt','--poll','--first-only']
	timeout = int(timeout * 1000)
	if timeout > 0:
		command.append(f'--timeout={timeout}')
	command.append(f'--target={path}')
	rtnHost = multiCMD.run_command(command,timeout=timeout+1 if timeout > 0  else timeout,quiet=DEBUG,return_object=True,wait_for_return=False)
	while GREEN_LIGHT.is_set():
		rtnHost.thread.join(1)
		if not rtnHost.thread.is_alive():
			break
	# if the thread is still alive, we need to kill it
	rtnHost.stop = True
	rtnHost.thread.join(1)
	if rtnHost.returncode == 0:
		return True
	return False

def backuper(job_name:str,to_process:deque,monitor_path:str,vault_path:str,vault_path_signiture:str,to_process_flag:threading.Event,
			 min_snapshot_delay_seconds:int = DEFAULT_SNAPSHOT_DELAY, keep_one_complete_backup:bool = DEFAULT_KEEP_ONE_COMPLETE_BACKUP, 
			 only_sync_attributes:bool = DEFAULT_ONLY_SYNC_ATTRIBUTES, keep_n_versions:int = DEFAULT_KEEP_N_VERSIONS, 
			 backup_size_limit:str = DEFAULT_BACKUP_SIZE_LIMIT, log_journal:bool = False):
	global BACKUP_SEMAPHORE
	global JOURNAL_HEADER
	global tl
	# main function for handling the backup for one reverb
	vault_fs_flag = threading.Event()
	vault_fs_thread = threading.Thread(target=fs_flag_daemon,args=(vault_path,vault_path_signiture,vault_fs_flag),daemon=True)
	vault_fs_thread.start()
	vault_fs_flag.wait()
	prev_to_process_len = 0
	time_to_sleep = 0
	# to_process: deque([ChangedEvent:{'monotonic_time':'231241','event':'create','type':'file','path':'/path/to/file'},...])
	while GREEN_LIGHT.is_set():
		if time_to_sleep > 0:
			time.sleep(time_to_sleep)
		vault_fs_flag.wait()
		while not to_process:
			to_process_flag.wait()
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
		to_process_flag.clear()
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

def format_change_events(change_events:deque):
	...

def log_events_to_journal(change_events:deque,journal_path:str):
	# this function will log the journal of the changes
	# the journal will be a nsv file with the following fields:
	# monotonic_time, event, type, path
	# this will be used to recover the changes in the case of a crash
	...

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
	# 	...
	# for file in file_to_backup:
	# 	# cp --reflink=auto --sparse=always -af monitor path files to this version path
	# 	...
	# for file in file_change_attr:
	# 	# cp --reflink=auto --sparse=always -af vault path files to this version path
	# 	# copy the attr only from monitor path to this version path
	# 	# this is so on fs with CoW support, we can save space by only storing the attr
	with BACKUP_SEMAPHORE:
		# do the actual backup
		...

def stepper():
	# this function remove the oldest reverb from path
	# stepper determines if it had been called from is there a v0 folder in the vault
	# if stepper had never been called before, it will need to redo the complete vault size calculation again
	#   if the vault size is about the same or bigger as the estimation, do the stepping normally
	#   if the vault size is much smaller than the estimated and smaller than the vault size limit, return
	...

def get_path_size():
	# this function gets the actual size of a path
	...