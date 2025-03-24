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
import datetime
import unicodedata
import re
from shutil import copystat

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
# 	monotonic_time:float
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
CHANGED_EVENT_HEADER = ['monotonic_time', 'is_dir', 'event', 'path','moved_from']
BACKUP_ENTRY_VALUES_HEADER = ['iso_time','event','source_path']
BACKUP_JOURNAL_HEADER = ['at_path','iso_time','event','source_path']
REVERB_RULE_TSV_HEADER = ['Job Name (Unique Key)', 'Path Monitoring', 'Monitoring File System Signiture', 
		'Minium snapshot time', 'Vault Path', 'Keep 1 Compelete Backup', 
		'Only Sync Attributes (permissions)', 'Keep N versions', 'Backup Size Limit', 
		'Vault File System Signiture']
REVERB_RULE_HEADER = ['job_name', 'mon_path', 'mon_fs_signiture', 
		'min_shapshot_time', 'vault_path', 'keep_one_complete_backup', 
		'only_sync_attributes', 'keep_n_versions', 'backup_size_limit',
		'vault_fs_signiture']

ChangeEvent = namedtuple('ChangeEvent', CHANGED_EVENT_HEADER)
BackupEntryValues = namedtuple('BackupEntryValues', BACKUP_ENTRY_VALUES_HEADER)
ReverbRule = namedtuple('ReverbRule', REVERB_RULE_HEADER)

# by defualt, set the max backup threads to 2* the number of cores
BACKUP_SEMAPHORE = threading.Semaphore(2*os.cpu_count())

DEFAULT_SNAPSHOT_DELAY = 60
DEFAULT_KEEP_ONE_COMPLETE_BACKUP = False
DEFAULT_ONLY_SYNC_ATTRIBUTES = False
DEFAULT_KEEP_N_VERSIONS = 30
DEFAULT_BACKUP_SIZE_LIMIT = '5%'

COOKIE_DICT_MAX_SIZE = 16384
COOKIE_VALUE = namedtuple('COOKIE_VALUE',['wd','path','isDir'])

GREEN_LIGHT = threading.Event()
GREEN_LIGHT.set()

DEBUG = True

tl = Tee_Logger.teeLogger(systemLogFileDir='/dev/null', programName='reverberator', compressLogAfterMonths=0, deleteLogAfterYears=0, suppressPrintout=False,noLog=True)

#%% ---- Main CLI Functions ----
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
	tl = Tee_Logger.teeLogger(systemLogFileDir=args.log_dir, programName=args.program_name, compressLogAfterMonths=args.log_compress_months, deleteLogAfterYears=args.log_delete_years, suppressPrintout=args.quiet, noLog=args.no_log)
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
	for reverb_rule in rules:
		job_name = reverb_rule.job_name
		monitor_path = reverb_rule.mon_path
		monitor_path_signiture = reverb_rule.mon_fs_signiture
		min_snapshot_delay_seconds = DEFAULT_SNAPSHOT_DELAY
		try:
			min_snapshot_delay_seconds = int(reverb_rule.min_shapshot_time)
		except:
			tl.teeerror(f'Error: Rule {job_name} has invalid min_snapshot_delay_seconds value: {reverb_rule.min_shapshot_time}')
			tl.teeprint(f"Reverting to default value: {DEFAULT_SNAPSHOT_DELAY}")
		vault_path = reverb_rule.vault_path
		if reverb_rule.keep_one_complete_backup.lower() == 'none':
			keep_one_complete_backup = DEFAULT_KEEP_ONE_COMPLETE_BACKUP
		else:
			keep_one_complete_backup = reverb_rule.keep_one_complete_backup.lower() in ['true','yes','1','t','y','on','enable','enabled','en','e']
		if reverb_rule.only_sync_attributes.lower() == 'none':
			only_sync_attributes = DEFAULT_ONLY_SYNC_ATTRIBUTES
		else:
			only_sync_attributes = reverb_rule.only_sync_attributes.lower() in ['true','yes','1','t','y','on','enable','enabled','en','e']
		keep_n_versions = DEFAULT_KEEP_N_VERSIONS
		try:
			keep_n_versions = int(reverb_rule.keep_n_versions)
		except:
			tl.teeerror(f'Error: Rule {job_name} has invalid keep_n_versions value: {reverb_rule.keep_n_versions}')
			tl.teeprint(f"Reverting to default value: {DEFAULT_KEEP_N_VERSIONS}")
		backup_size_limit = reverb_rule.backup_size_limit
		vault_path_signiture = reverb_rule.vault_fs_signiture
		to_process = deque()
		to_process_flag = threading.Event()
		watcherThread = threading.Thread(target=watcher,args=(job_name,monitor_path,monitor_path_signiture,to_process,to_process_flag,irm,min_snapshot_delay_seconds),daemon=True)
		tl.teeprint(f'Starting reverb monitor for {job_name} with monitor path {monitor_path}:{monitor_path_signiture}')
		watcherThread.start()
		main_threads.append(watcherThread)
		backup_thread = threading.Thread(target=backuper,args=(job_name,to_process,vault_path,vault_path_signiture,to_process_flag,keep_one_complete_backup,only_sync_attributes,keep_n_versions,backup_size_limit,args.journal),daemon=True)
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
	parser.add_argument('-nl','--no_log', action='store_true', help='Do not log to file.')
	parser.add_argument('-v','--verbose','--debug', action='store_true', help='Print debug logs.')
	parser.add_argument('-V', '--version', action='version', version=f"%(prog)s {__version__} with {lib_vers}; reverb (REcursive VERsioning Backup) generator by pan@zopyr.us")
	parser.add_argument('-t','--threads', type=int, help='Number of threads to use for backup. Use negative number for how many times of CPU count you want. Use 0 for 200k. (default: -2)', default=-2)
	parser.add_argument('-j','--journal', action='store_true', help='Log backup actions to a journal file in the vault path.')
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
	global REVERB_RULE_TSV_HEADER
	if not os.path.exists(rule_file):
		tl.teeerror(f'Error: Rule file {rule_file} does not exist.')
		sys.exit(1)

	rules = TSVZ.readTabularFile(rule_file,header=REVERB_RULE_TSV_HEADER,verifyHeader=True,strict=False,verbose=DEBUG)
	if not rules:
		tl.teeerror(f'Error: Rule file {rule_file} appears empty after parsing.')
		sys.exit(1)
	# fill in empty / auto and append:
	rulesToUpdate = []
	returnReverbRules = []
	for ruleName in rules:
		ruleList = rules[ruleName]
		if DEBUG:
			tl.teeprint(f'Checking rule: {ruleList}')
		ruleUpdated = False
		if not ruleList[0]:
			tl.teelog(f'Warning: Rule {ruleName} has empty Job Name. Ignoring rule...',level='warning')
			continue
		cleanedJobName = slugify(ruleList[0])
		if cleanedJobName != ruleList[0]:
			tl.teelog(f'Warning: Rule {ruleName} has dirty Job Name. Changing to {cleanedJobName}',level='warning')
			ruleList[0] = cleanedJobName
			ruleUpdated = True
		if not ruleList[1]:
			tl.teelog(f'Warning: Rule {ruleName} has empty Path Monitoring. Ignoring rule...',level='warning')
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
			tl.info(f'Updating rule {ruleName}: {ruleList}')
			rulesToUpdate.append(ruleList)
		returnReverbRules.append(ReverbRule(*ruleList))
		# append to tsv as well
		TSVZ.appendLinesTabularFile(rule_file,rulesToUpdate,header=REVERB_RULE_TSV_HEADER,createIfNotExist=False,verifyHeader=True,verbose=DEBUG,strict=False)
	return returnReverbRules

def slugify(value, allow_unicode=False):
	"""
	Taken from https://github.com/django/django/blob/master/django/utils/text.py
	Convert to ASCII if 'allow_unicode' is False. Convert spaces or repeated
	dashes to single dashes. Remove characters that aren't alphanumerics,
	underscores, or hyphens. Convert to lowercase. Also strip leading and
	trailing whitespace, dashes, and underscores.
	"""
	value = str(value)
	if allow_unicode:
		value = unicodedata.normalize('NFKC', value)
	else:
		value = unicodedata.normalize('NFKD', value).encode('ascii', 'ignore').decode('ascii')
	value = re.sub(r'[^\w\s-]', '', value.lower())
	return re.sub(r'[-\s]+', '-', value).strip('-_')

#%% ---- IRM ----
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

#%% ---- Watcher ----
def watcher(job_name:str,monitor_path:str,monitor_path_signiture:str,to_process:deque,to_process_flag:threading.Event,irm:inotify_resource_manager,min_snapshot_delay_seconds:int=DEFAULT_SNAPSHOT_DELAY):
	global GREEN_LIGHT
	# main monitoring function to deal with one reverb.
	monitor_fs_flag = threading.Event()
	monitor_fs_thread = threading.Thread(target=fs_flag_daemon,args=(monitor_path,monitor_path_signiture,monitor_fs_flag),daemon=True)
	tl.teeprint(f'Starting path watcher {job_name} for {monitor_path}')
	monitor_fs_thread.start()
	while GREEN_LIGHT.is_set():
		monitor_fs_flag.wait()
		watchFolder(monitor_path=monitor_path,to_process=to_process,to_process_flag=to_process_flag,irm=irm,min_snapshot_delay_seconds=min_snapshot_delay_seconds)

def watchFolder(monitor_path:str,to_process:deque,to_process_flag:threading.Event,irm:inotify_resource_manager,discard_new_recursive_folder_events_until_read:bool = True,min_snapshot_delay_seconds:int=DEFAULT_SNAPSHOT_DELAY):
	global COOKIE_DICT_MAX_SIZE
	global tl
	global DEBUG
	flags = inotify_simple.flags
	watch_flags = flags.MODIFY | flags.ATTRIB | flags.MOVED_FROM | flags.MOVED_TO | flags.CREATE | flags.DELETE | flags.DELETE_SELF | flags.MOVE_SELF | flags.UNMOUNT | flags.Q_OVERFLOW
	selfDestructMask = flags.UNMOUNT | flags.DELETE_SELF | flags.MOVE_SELF
	cookieDic = OrderedDict()
	wdDic = bidict()
	pendingMoveFromEvents = OrderedDict()
	newDirWDs = set()
	processPending = False
	irm.increaseUserInstances()
	with inotify_simple.INotify() as inotify_obj:
		mainWatchDescriptor = initializeFolderWatchers(inotify_obj,monitor_path,wdDic,irm,watch_flags)
		if mainWatchDescriptor == -1:
			tl.teeerror(f'Failed to initialize folder watchers for {monitor_path}')
			return False
		while GREEN_LIGHT.is_set():
			events =  inotify_obj.read(timeout=min_snapshot_delay_seconds)
			if not events:
				# this means timeout have elapsed, we can signal the backuper to process
				if to_process:
					if DEBUG:
						tl.teeprint('Timeout elapsed, signaling backuper to process')
					to_process_flag.set()
					processPending = True
				continue
			if processPending and not to_process_flag.is_set():
				# this means the to_process was just processed
				newDirWDs.clear()
				processPending = False
			if DEBUG:
				tl.teeok(f'Events detected: {len(events)}')
				decodedEvents = [[event.wd, flags.from_mask(event.mask),event.cookie, event.name] for event in events]
				print(TSVZ.pretty_format_table(decodedEvents,header=['wd', 'mask','cookie','name']))
			monTime = time.monotonic()
			for event in events:
				if event.mask & flags.Q_OVERFLOW:
					tl.teeerror('Queue overflow, event maybe lost')
					tl.teeprint('Attempting to increase inotify max_queued_events')
					irm.increaseInotifyMaxQueueEvents(irm.max_queued_events * 2)
					continue
				isDir = True if event.mask & flags.ISDIR else False
				if event.mask & selfDestructMask:
					if event.wd == mainWatchDescriptor:
						# if UNMOUNT or IGNORED or DELETE_SELF, MOVE_SELF, return false
						if DEBUG:
							tl.teeprint('Main dir self destruct event detected, terminating')
						irm.decreaseUserWatches(len(wdDic))
						irm.decreaseUserInstances()
						to_process.append(ChangeEvent(monTime,isDir,'self_destruct',monitor_path,None))
						return False
					elif event.mask & flags.DELETE_SELF:
						if DEBUG:
							tl.teeprint(f'Sub dir delete self event detected, removing watch for {wdDic.get(event.wd,None)}')
						wdDic.pop(event.wd, None)
						irm.decreaseUserWatches()
						continue
					elif event.mask & flags.UNMOUNT:
						if event.wd in wdDic:
							if DEBUG:
								tl.teeprint(f'Sub dir unmount event detected, resetting watch for {wdDic.get(event.wd,None)}')
							wdDic.pop(event.wd, None)
							wdDic[inotify_obj.add_watch(wdDic[event.wd], watch_flags)] = wdDic[event.wd]
						else:
							if DEBUG:
								tl.teeerror(f'Sub dir unmount event detected, but watch not in wdDic found for {event.wd}')
						continue
					elif event.mask & flags.MOVE_SELF:
						if DEBUG:
							tl.teeprint('Sub dir move self event detected, skipping')
						continue
				if not event.name:
					if DEBUG:
						tl.teeprint('Event name not found, ignoring event')
					continue
				if event.wd not in wdDic:
					if DEBUG:
						tl.teeerror(f'Watch descriptor {event.wd} not found in wdDic {wdDic}, ignoring event')
					continue
				if discard_new_recursive_folder_events_until_read and event.wd in newDirWDs:
					if DEBUG:
						tl.teeprint(f'Discarding event for new recursive folder {wdDic[event.wd]}')
					continue
				eventPath = os.path.join(wdDic[event.wd],event.name)
				if event.mask & flags.CREATE:
					if DEBUG:
						tl.teeprint(f'Create event detected for {eventPath}')
					if isDir:
						initializeFolderWatchers(inotify_obj,eventPath,wdDic,irm,watch_flags,newDirWDs)
					to_process.append(ChangeEvent(monTime,isDir,'create',eventPath,None))
				elif event.mask & flags.DELETE:
					if DEBUG:
						tl.teeprint(f'Delete event detected for {eventPath}')
					# if isDir:
					# 	if DEBUG:
					# 		tl.teeprint(f'Deleting wd {event.wd} for {eventPath}')
					# 	wdDic.pop(event.wd, None)
					# 	try:
					# 		inotify_obj.rm_watch(event.wd)
					# 	except:
					# 		if DEBUG:
					# 			tl.teeerror(f'Failed to remove watch for {event.wd} (already removed?)')
					# 	irm.decreaseUserWatches()
					to_process.append(ChangeEvent(monTime,isDir,'delete',eventPath,None))
				elif event.mask & flags.ATTRIB:
					if DEBUG:
						tl.teeprint(f'Attrib event detected for {eventPath}')
					to_process.append(ChangeEvent(monTime,isDir,'attrib',eventPath,None))
				elif event.mask & flags.MOVED_FROM:
					if DEBUG:
						tl.teeprint(f'Move from event detected for {eventPath}')
					cookieDic[event.cookie] = COOKIE_VALUE(event.wd,eventPath,isDir)
					while len(cookieDic) > COOKIE_DICT_MAX_SIZE:
						if DEBUG:
							tl.teeprint('Cookie dictionary is full, popping oldest item')
						_,cookie_value = cookieDic.popitem(last=False)
						# treat the move as a delete
						# if cookie_value.isDir:
						# 	if DEBUG:
						# 		tl.teeprint(f'Deleting wd {cookie_value.wd} for {cookie_value.path}')
						# 	wdDic.pop(cookie_value.wd, None)
						# 	try:
						# 		inotify_obj.rm_watch(cookie_value.wd)
						# 	except:
						# 		if DEBUG:
						# 			tl.teeerror(f'Failed to remove watch for {cookie_value.wd} (already removed?)')
						# 	irm.decreaseUserWatches()
						if DEBUG:
							tl.teeprint(f'Adding delete event for {cookie_value.path}')
						to_process.append(ChangeEvent(monTime,isDir,'delete',cookie_value.path,None))
					#to_process.append(ChangeEvent(monTime,isDir,'move',eventPath,None))
					pendingMoveFromEvents[event.cookie] = ChangeEvent(monTime,isDir,'delete',eventPath,None)
				elif event.mask & flags.MOVED_TO:
					if DEBUG:
						tl.teeprint(f'Move to event detected for {eventPath}')
					if event.cookie in cookieDic:
						if DEBUG:
							tl.teeprint(f'Cookie found for {event.cookie}')
							tl.teeprint(f'Adding move event for {cookieDic[event.cookie].path} to {eventPath}')
						cookie_value = cookieDic.pop(event.cookie)
						pendingMoveFromEvents.pop(event.cookie,None)
						to_process.append(ChangeEvent(monTime,isDir,'move',eventPath,cookie_value.path))
						if isDir:
							# we need to update wdDic to reflect the new path
							if cookie_value.path in wdDic.inverse:
								if DEBUG:
									tl.teeprint(f'Updating all values of wdDic {wdDic.inverse[cookie_value.path]} for {cookie_value.path} to {eventPath}')
								wds = wdDic.inverse[cookie_value.path]
								for wd in wds:
									wdDic[wd] = eventPath
					else:
						if DEBUG:
							tl.teeprint(f'Cookie not found for {event.cookie}')
							tl.teeprint(f'Treating move as create event for {eventPath}')
						if isDir:
							initializeFolderWatchers(inotify_obj,eventPath,wdDic,irm,watch_flags,newDirWDs)
						to_process.append(ChangeEvent(monTime,isDir,'create',eventPath,None))
				elif event.mask & flags.MODIFY:
					if DEBUG:
						tl.teeprint(f'Modify event detected for {eventPath}')
					to_process.append(ChangeEvent(monTime,isDir,'modify',eventPath,None))
				elif DEBUG:
					tl.info(f'Unprocessed event {event}')
			if pendingMoveFromEvents:
				if DEBUG:
					tl.teeprint(f'Adding unmatched pending move_from events as deletes {pendingMoveFromEvents.keys()}')
				to_process.extend(pendingMoveFromEvents.values())
				pendingMoveFromEvents.clear()
	return True

class bidict(dict):
	# Credit: https://stackoverflow.com/users/1422096/basj
	# https://stackoverflow.com/questions/3318625/how-to-implement-an-efficient-bidirectional-hash-table
	def __init__(self, *args, **kwargs):
		super(bidict, self).__init__(*args, **kwargs)
		self.inverse = {}
		for key, value in self.items():
			self.inverse.setdefault(value, []).append(key) 

	def __setitem__(self, key, value):
		if key in self:
			self.inverse[self[key]].remove(key) 
		super(bidict, self).__setitem__(key, value)
		self.inverse.setdefault(value, []).append(key)        

	def __delitem__(self, key):
		self.inverse.setdefault(self[key], []).remove(key)
		if self[key] in self.inverse and not self.inverse[self[key]]: 
			del self.inverse[self[key]]
		super(bidict, self).__delitem__(key)

def testWatchFolderOperation(testCMD:list,to_process:deque,to_process_flag:threading.Event):
	multiCMD.run_command(testCMD)
	to_process_flag.wait(1)
	print(to_process)
	to_process.clear()
	to_process_flag.clear()

def initializeFolderWatchers(inotify_obj:inotify_simple.INotify,monitor_path:str,wdDic:dict,irm:inotify_resource_manager,watch_flags:int,newDirWds = None):
	global DEBUG
	if not os.path.exists(monitor_path):
		return -1
	irm.increaseUserWatches()
	if DEBUG:
		print(f'Adding watch for {monitor_path}')
	parentWatchDescriptor = inotify_obj.add_watch(monitor_path, watch_flags)
	if newDirWds is not None:
		newDirWds.add(parentWatchDescriptor)
	wdDic[parentWatchDescriptor] = monitor_path
	allFolders = get_all_folders(monitor_path)
	if DEBUG:
		print(f'Adding watch for {len(allFolders)} sub folders')
	irm.increaseUserWatches(len(allFolders))
	for folder in allFolders:
		childWd = inotify_obj.add_watch(folder, watch_flags)
		if newDirWds is not None:
			newDirWds.add(childWd)
		wdDic[childWd] = folder
	return parentWatchDescriptor

def get_all_folders(path):
	_, folders = get_all_files_and_folders(path)
	return folders

def get_all_files(path):
	files, _ = get_all_files_and_folders(path)
	return files

def get_all_files_and_folders(path):
	files = []
	folders = []
	try:
		with os.scandir(path) as entries:
			for entry in entries:
				if entry.is_dir(follow_symlinks=False):
					folders.append(entry.path)
					child_files, child_folders = get_all_files_and_folders(entry.path)
					files.extend(child_files)
					folders.extend(child_folders)
				else:
					files.append(entry.path)
	except PermissionError:
		pass
	return files, folders

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

def get_fs_signitures(path:str) -> list:
	global DEBUG
	# df --no-sync --output=source,ipcent,pcent,target for use percentage
	# lsblk --raw --paths --output=kname,label,model,name,partlabel,partuuid,uuid,serial,fstype,wwn <dev> for infos
	rtnHost = multiCMD.run_command(['df','--no-sync','--output=source',path],timeout=60,quiet=DEBUG,return_object=True)
	if rtnHost.returncode != 0 or not rtnHost.stdout or len(rtnHost.stdout) <= 1:
		return []
	deviceName = rtnHost.stdout[1].split()[0]
	rtnHost = multiCMD.run_command(['lsblk','--raw','--output=uuid,label,partuuid,partlabel,wwn,serial,model,name,kname,pkname',deviceName],timeout=60,quiet=DEBUG,return_object=True)
	if rtnHost.returncode != 0 or not rtnHost.stdout or len(rtnHost.stdout) <= 1:
		return []
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

#%% ---- Backup ----
def backuper(job_name:str,to_process:deque,monitor_path:str,vault_path:str,vault_path_signiture:str,to_process_flag:threading.Event,
			 keep_one_complete_backup:bool = DEFAULT_KEEP_ONE_COMPLETE_BACKUP, 
			 only_sync_attributes:bool = DEFAULT_ONLY_SYNC_ATTRIBUTES, keep_n_versions:int = DEFAULT_KEEP_N_VERSIONS, 
			 backup_size_limit:str = DEFAULT_BACKUP_SIZE_LIMIT, log_journal:bool = False):
	global BACKUP_SEMAPHORE
	global BACKUP_ENTRY_VALUES_HEADER
	global tl
	global DEBUG
	# main function for handling the backup for one reverb
	vault_fs_flag = threading.Event()
	vault_fs_thread = threading.Thread(target=fs_flag_daemon,args=(vault_path,vault_path_signiture,vault_fs_flag),daemon=True)
	vault_fs_thread.start()
	vault_fs_flag.wait()
	backupEntries = OrderedDict()
	# to_process: deque([ChangedEvent:{'monotonic_time':'231241','event':'create','type':'file','path':'/path/to/file'},...])
	while GREEN_LIGHT.is_set():
		vault_fs_flag.wait()
		do_backup(backupEntries,vault_fs_flag,job_name=job_name,monitor_path=monitor_path,vault_path=vault_path,vault_path_signiture=vault_path_signiture,
			  keep_one_complete_backup=keep_one_complete_backup,only_sync_attributes=only_sync_attributes, keep_n_versions=keep_n_versions, backup_size_limit=backup_size_limit, log_journal=log_journal)
		while not backupEntries:
			to_process_flag.wait()
			if DEBUG:
				tl.teeprint(f'Signaling backuper to process, {len(to_process)} events to process')
			to_process_temp = to_process.copy()
			to_process.clear()
			to_process_flag.clear()
			backupEntries = change_events_to_backup_entries(to_process_temp)
			if DEBUG:
				tl.teeprint(f'Converted {len(to_process_temp)} events to {len(backupEntries)} backup entries')
		if log_journal:
			journalPath = os.path.join(vault_path,job_name,'journal.nsv')
			log_events_to_journal(backupEntries,journalPath)

def change_events_to_backup_entries(change_events:deque) -> OrderedDict:
	# possibile events are create, delete, attrib, move, modify
	# CHANGED_EVENT_HEADER = ['monotonic_time', 'is_dir', 'event', 'path','moved_from']
	# BACKUP_ENTRY_VALUES_HEADER = ['iso_time','event','source_path']
	# collapse the change events
	# for a single file, only these events will be kept:
	# 	modify, attrib, move, delete ( create will be treated as modify as we will be copying the entire file )
	# 	modify will be exclusive to file
	# for a single directory, only the following kinds of events will be kept:
	# 	create, delete, attrib, move ( modify should not be possible but just in case, it will be treated as create )
	# 	folder create will recursively copy all its contents 
	# 	create should be exclusive to folder
	# New: we will now combine create and monify events and name it as taint
	# Only move what with a moved_from will be kept, all moves without moved_from will be treated as delete
	# will get the iso_time using (datetime.datetime.now() - datetime.timedelta(seconds=time.monotonic() - monTime)).isoformat())
	# will indicate if a path is a dir by making sure it ends with /
	# if it is a self_destruct event, we still keep it in 
	global DEBUG
	global tl
	if DEBUG:
		tl.teeprint('Converting the following change events to backup entries')
		tl.printTable(change_events,header = CHANGED_EVENT_HEADER)
	backup_entries = OrderedDict()
	newDirectories = set()
	pendingMoveSourceParents = set()
	moveSourceToDestDict = {}
	iso_time = ''
	for changeEvent in reversed(change_events):
		# get the absolute path
		to_add = True
		abs_path = os.path.abspath(changeEvent.path)
		if changeEvent.moved_from:
			abs_moved_from = os.path.abspath(changeEvent.moved_from)
			if changeEvent.is_dir:
				abs_moved_from += '/'
		else:
			abs_moved_from = None
		event = changeEvent.event
		if changeEvent.is_dir:
			abs_path += '/'
		if DEBUG:
			tl.teeprint('-'*80)
			tl.teeprint(f'Processing {event} on {abs_path} with source {abs_moved_from}')
		# pre handle move events
		if event == 'move':
			if abs_moved_from:
				pendingMoveSourceParents.add(abs_moved_from)
				if abs_path in moveSourceToDestDict:
					# chain move, we will modify the chronologically later move event's source to this event's source
					finialTarget = moveSourceToDestDict[abs_path]
					moveSourceToDestDict[abs_moved_from] = finialTarget
					del moveSourceToDestDict[abs_path]
					if finialTarget in backup_entries:
						backup_entries[finialTarget] = BackupEntryValues(backup_entries[finialTarget].iso_time,backup_entries[finialTarget].event,abs_moved_from)
						if DEBUG:
							if backup_entries[finialTarget].event != 'move':
								tl.teeprint(f'  Chain move (now {backup_entries[finialTarget].event}) from {abs_moved_from} through {abs_path} to {finialTarget}')
							else:
								tl.teeprint(f'  Chain move from {abs_moved_from} through {abs_path} to {finialTarget}')
					else:
						# this means the later move event was deleted, no need to update it
						if DEBUG:
							tl.teeprint(f'  Already removed chain move event from {abs_moved_from} through {abs_path} to {finialTarget}')
						if abs_path in backup_entries:
							if DEBUG:
								tl.teeprint(f'    Removing {backup_entries[abs_path].event} event on {abs_path}')
							del backup_entries[abs_path]
					to_add = False
				else:
					moveSourceToDestDict[abs_moved_from] = abs_path
			else:
				if abs_path in pendingMoveSourceParents:
					# we have handled this event's children, so we can ignore this event
					pendingMoveSourceParents.remove(abs_path)
					if DEBUG:
						tl.teeprint(f'Skipping child move event {abs_path}')
					to_add = False
				else:
					# virgin move, treat as create
					if DEBUG:
						tl.teeprint(f'Virgin move event {abs_path}')
					event = 'create'
		elif abs_path in moveSourceToDestDict:
			# This means the path was chronologically later moved.
			# the event can be 'create', 'modify', 'attrib', 'delete' at this point
			# in all cases, as we cannot simply perform a recursive link as a move in the backup, ( need to backup source data )
			# we will break the move event into a delete of source and a {event} of dest
			# here, escalate the current event to the chronologically later move
			if event == 'delete':
				# if the path was chronologically later moved from, then it must exist, thus this delete is likely invalid
				if DEBUG:
					tl.teeprint(f'Delete event detected immediately before a move with {abs_path} as source. Ignoring delete')
				to_add = False
			elif event == 'attrib':
				# escalate to check file content also as it is not possible to sync attrib only to a symlink 
				event = 'modify'
			moveDest = moveSourceToDestDict[abs_path]
			if DEBUG:
				tl.teeprint(f'  Seperating move event from {abs_path} to {moveDest}')
			if moveDest in backup_entries:
				if event == 'create':
					to_add = False
					escalated_event = 'taint'
				else:
					if event == 'modify':
						escalated_event = 'taint'
					else:
						escalated_event = event
					event = 'delete'
				if DEBUG:
					tl.teeprint(f'    Escalating {backup_entries[moveDest].event} to {escalated_event} at {backup_entries[moveDest].iso_time} on {moveDest}')
				backup_entries[moveDest] = BackupEntryValues(backup_entries[moveDest].iso_time,escalated_event,abs_path)
			else:
				if DEBUG:
					tl.teeprint(f'    Already removed event on {moveDest}, skipping escalating')
				if abs_path in backup_entries:
					if DEBUG:
						tl.teeprint(f'    Removing {backup_entries[abs_path].event} event on {abs_path}')
					del backup_entries[abs_path]
				continue
			
		# handle repeated events on the same path
		if abs_path in backup_entries:
			if DEBUG:
				tl.teeprint(f'  {abs_path} already exists in backup entries')
			# handle repeated events on the same path
			later_event_on_path = backup_entries[abs_path].event
			if event == 'create' and later_event_on_path == 'delete':
				# if the path was new and then chronologically later deleted, then we ignore both events
				if DEBUG:
					tl.teeprint(f'Skipping event as Creating {abs_path} that is later deleted.')
					tl.teeprint(f'  Removing delete event {abs_path}:{backup_entries[abs_path]} as it was created in this iteration')
				del backup_entries[abs_path]
				to_add = False
			elif later_event_on_path in ('delete','taint','move'):
				# if the path is chronologically later deleted, then we simply do not need to perform backups
				# if the path is chronologically later modified, because the current event can be modify / attrib / move / delete , in all cases we will ignore this event
				# if the path is chronologically later moved to, meaning it was later overwriiten moved to. We do not care what it had been done to before then.
				# in this version of reverberator, create is a complete file tree copy, so if it is chronologically later "created", all previoud events no longer matter.
				# in the case of move, because we are skipping this event without adding it to the move sources,
				# the next chronological move event of the source will be treated as a delete
				if event == 'move':
					# we also need to add a event to remove the source 
					if DEBUG:
						tl.teeprint(f'Moving to {abs_path} that is later {later_event_on_path}d.')
					if later_event_on_path == 'delete':
						if DEBUG:
							tl.teeprint(f'  Removing delete event {abs_path}:{backup_entries[abs_path]} as it was created by move in this iteration')
						del backup_entries[abs_path]
					abs_path = abs_moved_from
					abs_moved_from = None
					event = 'delete'
				else:
					if DEBUG:
						tl.teeprint(f'Skipping {event} on {abs_path}')
					to_add = False
			elif later_event_on_path == 'attrib':
				if event in ('attrib','delete'):
					# delete: the path was chronologically later attributed, so it must exist later, thus we ignore the delete
					if DEBUG:
						tl.teeprint(f'Skipping dup {event} on {abs_path}')
					to_add = False
				if event in ('modify', 'create', 'move','taint'):
					# we need to escalate the chronologically later event to modify / create / move as attrib only copies the metadata
					if DEBUG:
						tl.teeprint(f'Escalating attrib event to {event} on {abs_path}')
					del backup_entries[abs_path]
		if to_add:
			if event == 'create' or event == 'modify':
				event = 'taint'
			if not iso_time:
				iso_time = (datetime.datetime.now() - datetime.timedelta(seconds=time.monotonic() - changeEvent.monotonic_time)).isoformat()
			if DEBUG:
				tl.teeprint(f'Adding {event} on {abs_path} at {iso_time} with source {abs_moved_from}')
			backup_entries[abs_path] = BackupEntryValues(iso_time,event,abs_moved_from)
			backup_entries.move_to_end(abs_path,last=False)
	if DEBUG:
		tl.teeprint('Converted backup entries')
		tl.printTable(backup_entries,header = ['path'] + BACKUP_ENTRY_VALUES_HEADER)
	return backup_entries
	
def log_events_to_journal(backup_entries:dict,journal_path:str):
	# this function will log the journal of the changes
	# the journal will be a nsv file with the following fields:
	# monotonic_time, event, type, path
	# this will be used to recover the changes in the case of a crash
	global tl
	lines = [[path,entry.iso_time,entry.event,entry.source_path] for path,entry in backup_entries.items()]
	TSVZ.appendLinesTabularFile(journal_path,lines,header = BACKUP_JOURNAL_HEADER,createIfNotExist = True,verifyHeader = True,strict=False,teeLogger=tl)

def do_backup(backup_entries:dict,
			 job_name:str,monitor_path:str,vault_path:str,vault_path_signiture:str,
			 keep_one_complete_backup:bool , 
			 only_sync_attributes:bool, keep_n_versions:int , 
			 backup_size_limit:str,log_journal:bool = False):
	# remember to also sync attr from source for move events
	global DEBUG
	global tl
	job_vault = os.path.join(vault_path,job_name)
	if log_journal:
		journalPath = os.path.join(job_vault,'journal.nsv')
		TSVZ.appendTabularFile(journalPath,[monitor_path,datetime.datetime.now().isoformat(),'start_reverb_backup',os.path.join(vault_path,job_name)],teeLogger=tl,header=BACKUP_JOURNAL_HEADER,createIfNotExist=True,verifyHeader=True,strict=False)
	with BACKUP_SEMAPHORE:
		# do the actual backup
		# get the latest current version path
		current_version_path, vault_size , vault_inodes= get_vault_info(job_vault_path=job_vault)
		if not current_version_path:
			if DEBUG:
				tl.teeerror(f'Failed to get current version path for {job_vault}, treating the vault as new.')
			backup_folder = os.path.join(job_vault,f'V0--{datetime.datetime.now().astimezone().strftime('%Y-%m-%dT%H-%M-%SZ%z')}')
			if keep_one_complete_backup:
				do_complete_backup(monitor_path,backup_folder)
			else:
				do_referenced_copy(monitor_path,backup_folder)
		else:
			# get the size of the current backup
			estimated_backup_size, estimated_backup_inode = get_backup_size_inode(backup_entries)
			backup_limit_size, backup_limit_inode = get_backup_limits_from_str(backup_size_limit)
			if backup_limit_size:
				while vault_size + estimated_backup_size > backup_limit_size:
					if DEBUG:
						tl.teeprint(f'Vault size {vault_size} + estimated backup size {estimated_backup_size} exceeds backup size limit {backup_limit_size}')
					# we need to remove the oldest version
					removed_size, removed_inodes = stepper()
					vault_size -= removed_size
					vault_inodes -= removed_inodes
					if not removed_size and not removed_inodes:
						break
			if backup_limit_inode:
				while vault_inodes + estimated_backup_inode > backup_limit_inode:
					if DEBUG:
						tl.teeprint(f'Vault inodes {vault_inodes} + estimated backup inodes {estimated_backup_inode} exceeds backup inode limit {backup_limit_inode}')
					# we need to remove the oldest version
					removed_size, removed_inodes = stepper()
					vault_size -= removed_size
					vault_inodes -= removed_inodes
					if not removed_size and not removed_inodes:
						break
			# Now we have made sure the vault is within the size limit, we can proceed to do the backup
			
			
		# check the size of the backup
		backup_size_str = format_bytes(get_path_size(backup_folder),use_1024_bytes=True,to_str=True).replace(' ','_')
		backup_inode_str = format_bytes(get_path_inodes(backup_folder),use_1024_bytes=False,to_str=True).replace(' ','')
		backup_folder_with_size = f'{backup_folder}--{backup_size_str}B-{backup_inode_str}_ino'
		os.rename(backup_folder,backup_folder_with_size)
		if DEBUG:
			tl.teeok(f'Created new backup at {backup_folder_with_size}')
		# create the current version symlink
		if os.path.exists(os.path.join(job_vault,'current_version')):
			os.remove(os.path.join(job_vault,'current_version'))
		os.symlink(backup_folder_with_size,os.path.join(job_vault,'current_version'),target_is_directory=True)
	if log_journal:
		TSVZ.appendTabularFile(journalPath,[monitor_path,datetime.datetime.now().isoformat(),'end_reverb_backup',os.path.join(vault_path,job_name)],teeLogger=tl,header=BACKUP_JOURNAL_HEADER,createIfNotExist=True,verifyHeader=True,strict=False)

def get_vault_info(job_vault_path:str) -> tuple:
	# this function gets the latest version path
	# it will return the target of the link of current_version in the job vault.
	# if the link does not exist or broken, it will try to use rule to find the latest version folder
	# if it cannot find anything, it will return an empty string
	# job vault subfolder should follow: V{version}--{ISO8601ish time}--{size of this backup}-{inodes of this backup}
	# ex. V0--2021-01-01_00-00-00_-0800--1.3_GiB-4.2K_ino
	global DEBUG
	global tl
	if not os.path.exists(job_vault_path):
		tl.teeerror(f'Job vault path {job_vault_path} does not exist')
		return '', 0, 0
	current_version_symlink_path = os.path.join(job_vault_path,'current_version')
	if os.path.islink(current_version_symlink_path):
		link_target = os.readlink(current_version_symlink_path)
		if os.path.isdir(link_target) and is_subpath(link_target,job_vault_path):
			if DEBUG:
				tl.teeok(f'Current version symlink to {link_target}')
			return link_target
		else:
			tl.teeerror(f'Broken symlink {current_version_symlink_path} to {link_target}')
	# if the symlink is broken, we will try to find the latest version folder
	most_recent_version = 0
	most_recent_version_path = ''
	vault_size = 0
	vault_inodes = 0
	try:
		for entry in os.scandir(job_vault_path):
			if entry.is_dir() and entry.name.startswith('V') and '--' in entry.name:
				version_number_str = entry.name.lstrip('V').partition('--')[0]
				if version_number_str.isdigit():
					version_number = int(version_number_str)
					if version_number > most_recent_version:
						most_recent_version = version_number
						most_recent_version_path = entry.path
				try:
					entry_size_inode_str = entry.name.rpartition('--')[2]
					entry_size_str = entry_size_inode_str.partition('-')[0].replace('_',' ')
					entry_size = format_bytes(entry_size_str,to_int=True)
					entry_inode_str = entry_size_inode_str.rpartition('-')[2].replace('_',' ')
					entry_inode = format_bytes(entry_inode_str,to_int=True)
					vault_size += entry_size
					vault_inodes += entry_inode
				except:
					pass
	except PermissionError:
		tl.teeerror(f'Permission error while scanning {job_vault_path}')
	return most_recent_version_path, vault_size, vault_inodes

def is_subpath(child, parent):
    child = os.path.realpath(child)
    parent = os.path.realpath(parent)
    common = os.path.commonpath([child, parent])
    return common == parent

def do_complete_backup(source_path:str,backup_folder:str):
	global DEBUG
	multiCMD.run_command(['cp','-a','--reflink=auto','--sparse=always',source_path,backup_folder],quiet=DEBUG,return_code_only=True)

def do_referenced_copy(source_path:str,backup_folder:str):
	global DEBUG
	global tl
	global BACKUP_SEMAPHORE
	files, folders = get_all_files_and_folders(source_path)
	for folder in folders:
		try:
			rel_folder = os.path.relpath(folder,source_path)
			backup_folder_path = os.path.join(backup_folder,rel_folder)
			os.makedirs(backup_folder_path,exist_ok=True)
			# copy the folder metadata
			copystat(folder,backup_folder_path)
			st = os.stat(folder)
			if os.name == 'posix':
				os.chown(backup_folder_path, st.st_uid, st.st_gid)
			os.utime(backup_folder_path, (st.st_atime, st.st_mtime))
		except:
			tl.teeerror(f'Failed to copy folder {folder}')
	commands = []
	for file in files:
		# use ln -fsrLT to do a relative symlink
		# ln --symbolic --relative --logical --force --no-target-directory
		rel_file = os.path.relpath(file,source_path)
		backup_file_path = os.path.join(backup_folder,rel_file)
		commands.append(['ln','-fsrLT',file,backup_file_path])
	if commands:
		run_commands_with_semaphore(commands)

def run_commands_with_semaphore(commands:list):
	global BACKUP_SEMAPHORE
	global DEBUG
	# check if there is any free semaphores available
	# Use as much semaphore as possible
	remaining_semaphores = BACKUP_SEMAPHORE._value
	if remaining_semaphores < len(commands) // 2:
		threads_to_use = remaining_semaphores // 2
	else:
		threads_to_use = len(commands) // 2
	if threads_to_use > 1:
		[BACKUP_SEMAPHORE.acquire() for _ in range(threads_to_use)]
		multiCMD.run_commands(commands,quiet=DEBUG,return_code_only=True,max_threads=threads_to_use)
		BACKUP_SEMAPHORE.release(threads_to_use)
	else:
		multiCMD.run_commands(commands,quiet=DEBUG,return_code_only=True)

def get_path_size(path:str):
	# this function gets the actual size of a path
	# du --bytes -s <path>
	rtn = multiCMD.run_command(['du','--bytes','-s',path],quiet=True)
	if rtn and rtn[0] and rtn[0].partition('\t')[0].isdigit():
		return int(rtn[0].partition('\t')[0])
	else:
		return 0

def get_path_inodes(path:str):
	# this function gets the number of inodes in a path
	# df --inodes -s <path>
	rtn = multiCMD.run_command(['du','--inodes','-s',path],quiet=True)
	if rtn and rtn[0] and rtn[0].partition('\t')[0].isdigit():
		return int(rtn[0].partition('\t')[0])
	else:
		return 0

def format_bytes(size, use_1024_bytes=None, to_int=False, to_str=False,str_format='.2f'):
	"""
	Format the size in bytes to a human-readable format or vice versa.
	From hpcp: https://github.com/yufei-pan/hpcp

	Args:
		size (int or str): The size in bytes or a string representation of the size.
		use_1024_bytes (bool, optional): Whether to use 1024 bytes as the base for conversion. If None, it will be determined automatically. Default is None.
		to_int (bool, optional): Whether to convert the size to an integer. Default is False.
		to_str (bool, optional): Whether to convert the size to a string representation. Default is False.
		str_format (str, optional): The format string to use when converting the size to a string. Default is '.2f'.

	Returns:
		int or str: The formatted size based on the provided arguments.

	Examples:
		>>> format_bytes(1500)
		'1.50 KB'
		>>> format_bytes('1.5 GiB', to_int=True)
		1610612736
	"""
	if to_int or isinstance(size, str):
		if isinstance(size, int):
			return size
		elif isinstance(size, str):
			# Use regular expression to split the numeric part from the unit, handling optional whitespace
			match = re.match(r"(\d+(\.\d+)?)\s*([a-zA-Z]*)", size)
			if not match:
				print("Invalid size format. Expected format: 'number [unit]', e.g., '1.5 GiB' or '1.5GiB'")
				print(f"Got: {size}")
				return 0
			number, _, unit = match.groups()
			number = float(number)
			unit  = unit.strip().lower().rstrip('b')
			# Define the unit conversion dictionary
			if unit.endswith('i'):
				# this means we treat the unit as 1024 bytes if it ends with 'i'
				use_1024_bytes = True
			elif use_1024_bytes is None:
				use_1024_bytes = False
			unit  = unit.rstrip('i')
			if use_1024_bytes:
				power = 2**10
			else:
				power = 10**3
			unit_labels = {'': 0, 'k': 1, 'm': 2, 'g': 3, 't': 4, 'p': 5}
			if unit not in unit_labels:
				print(f"Invalid unit '{unit}'. Expected one of {list(unit_labels.keys())}")
				return 0
			# Calculate the bytes
			return int(number * (power ** unit_labels[unit]))
		else:
			try:
				return int(size)
			except Exception as e:
				return 0
	elif to_str or isinstance(size, int) or isinstance(size, float):
		if isinstance(size, str):
			try:
				size = size.lower().strip().rstrip('b')
				size = float(size)
			except Exception as e:
				return size
		# size is in bytes
		if use_1024_bytes or use_1024_bytes is None:
			power = 2**10
			n = 0
			power_labels = {0 : '', 1: 'Ki', 2: 'Mi', 3: 'Gi', 4: 'Ti', 5: 'Pi'}
			while size > power:
				size /= power
				n += 1
			return f"{size:{str_format}}{' '}{power_labels[n]}"
		else:
			power = 10**3
			n = 0
			power_labels = {0 : '', 1: 'K', 2: 'M', 3: 'G', 4: 'T', 5: 'P'}
			while size > power:
				size /= power
				n += 1
			return f"{size:{str_format}}{' '}{power_labels[n]}"
	else:
		try:
			return format_bytes(float(size), use_1024_bytes)
		except Exception as e:
			import traceback
			print(f"Error: {e}")
			print(traceback.format_exc())
			print(f"Invalid size: {size}")
		return 0

def get_backup_size_inode(backup_entries:dict):
	# this function gets the size of the backup entries
	...

def get_backup_limits_from_str(backup_size_limit):
	...

def stepper():
	# this function remove the oldest reverb from path
	# stepper determines if it had been called from is there a v0 folder in the vault
	# if stepper had never been called before, it will need to redo the complete vault size calculation again
	#   if the vault size is about the same or bigger as the estimation, do the stepping normally
	#   if the vault size is much smaller than the estimated and smaller than the vault size limit, return
	...

def get_path_fs

