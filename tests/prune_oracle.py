'''
decrement_stepper() as ade4bcd (0.50) had it, its walk on the calling thread alone: the oracle that round 15's walk on
threads is compared with (tests/test_prune_threads.py). It runs with reverberator's globals, so a test's patches of the
module and of os reach it as they reach the daemon's own.
'''
from __future__ import annotations
import time
import types
import reverberator as rv


def decrement_stepper(vault_info_dict:OrderedDict, job_name:str, monitor_path:str, monitor_paths:list = None, clock = time.monotonic,
		prune_salt:bytes = None) -> tuple:
	global DEBUG
	global CONTENT_FILE_EXTENSION_NAME
	# this function remove the oldest reverb from path
	if len(vault_info_dict) < 2:
		# we cannot step as there is less than 2 availble reverbs
		return 0 , 0
	backuperTeeLogToTl(path='decrement_stepper',message='Running stepper to remove oldest reverb',ok=True)
	referenceVersionNumber, referenceVaultEntry = vault_info_dict.popitem(last=False)
	referenceVaultPath = os.path.abspath(referenceVaultEntry.path)
	if referenceVaultPath == '/':
		backuperTeeLogToTl(path=referenceVaultPath,error=True,message='Attempting to remove root, skipping')
		backuperTeeLogToTl(path=referenceVaultPath,message=referenceVaultEntry)
		# still the oldest, so the caller sees nothing removed
		vault_info_dict[referenceVersionNumber] = referenceVaultEntry
		vault_info_dict.move_to_end(referenceVersionNumber, last=False)
		return 0 , 0
	backuperTeeLogToTl(path=referenceVaultPath,message=f'Recursively removing V{referenceVersionNumber}: {referenceVaultPath}')
	vaultInfoIter = iter(vault_info_dict)
	applyingVersionNumber = next(vaultInfoIter)
	applyingVaultEntry = vault_info_dict[applyingVersionNumber]
	job_vault = os.path.dirname(referenceVaultPath)
	# the books, each [bytes, inodes]: the copies the next version took from the reference vault, the entries it no
	# longer holds (the links replaced), and the copies made for it besides (for a second link naming a copy the walk
	# moved). a dangling link left as it is is in none
	transferred, unlinked, copied = [0, 0], [0, 0], [0, 0]
	def book(books:list, st:os.stat_result) -> None:
		books[0] += st.st_blocks * 512
		books[1] += 1
	# the copies hard linked into the next version this run, by inode, so two links naming one copy (one of them a user's
	# link the rows could not tell) book it once. one moved needs no note: another link naming it finds it gone, and
	# gets a copy of its own (copied), so the move path, which notes every copy it moves already, holds no more
	booked = PathHashes()
	if prune_salt is None and job_name not in PRUNE_SALT_MISSING:
		PRUNE_SALT_MISSING.add(job_name)
		backuperTeeLogToTl(path=referenceVaultPath,warning=True,message="The vault's secret for the names pruning links copies under cannot be had: they go by the copy's inode alone")
	# the records as the change lists' names hold them, and those lists (None for a version without one)
	reference_record, applying_record = referenceVaultEntry, applyingVaultEntry
	reference_list = applying_list = None
	# whether the records were written, once a call: None until they are
	records_written = None
	def there(path:str):
		# True when path is there, False when it is not (ENOTDIR too: a name above it is no folder), None when that cannot
		# be told
		try:
			os.lstat(path)
		except (FileNotFoundError, NotADirectoryError):
			return False
		except OSError:
			return None
		return True
	def change_list_of(entry:VaultEntry):
		# the change list holding entry's record: by the name the record makes, else the version's own found by listing
		# the job vault (as a rename that reported an error can leave it); None when it has none. raises OSError when
		# that cannot be told
		expected = change_list_path(entry.path, entry.size, entry.inode)
		try:
			os.lstat(expected)
			return expected
		except (FileNotFoundError, NotADirectoryError):
			pass
		name = os.path.basename(os.path.abspath(entry.path))
		found = sorted(listed for listed in os.listdir(job_vault) if (parse_change_list_name(listed) or (None, None))[1] == name)
		return os.path.join(job_vault, found[0]) if found else None
	def record(change_list:str, entry:VaultEntry, size:int, inodes:int):
		# change_list renamed for entry to record size and inodes: entry as it now records, None when that failed. a
		# version without a list (only the reference vault can be one: the prune stops for a next version without its
		# list) has no other record
		written = entry._replace(size=size, inode=inodes)
		new_path = change_list_path(entry.path, size, inodes)
		if change_list == new_path:
			return written
		if change_list is None:
			return written
		backuperTeeLogToTl(path=referenceVaultPath,message=f'Renaming {change_list} to {new_path}')
		try:
			os.rename(change_list,new_path)
		except OSError as e:
			# a rename that moved the list and then reported an error is done
			if not (there(change_list) is False and there(new_path)):
				backuperTeeLogToTl(path=referenceVaultPath,error=True,message=f'Error renaming {change_list} to {new_path}: {e}')
				return None
		return written
	def write_records() -> bool:
		# both records written, the next version's first on purpose: whether its was. a run cut off between the two
		# leaves only the reference vault's record high, by the copies it gave, and that is the version this prune is
		# removing; one of its that cannot be written stays high the same way until the removal takes it. when the next
		# version's cannot be written, neither is, and the removal aborts: both stay as they were, high by the links
		# replaced, an overstatement, which over-prunes by those links' blocks. that holds only until the rerun: it finds
		# those links replaced already, so it books neither them nor the copies they became, and once the reference vault
		# goes, the next version's record is low by the copies the aborted run linked (less the links' blocks), which
		# under-prunes by them
		nonlocal reference_record, applying_record, records_written
		if records_written is None:
			records_written = True
			if transferred[1] or unlinked[1] or copied[1]:
				written = record(applying_list, applyingVaultEntry,
					max(0, applyingVaultEntry.size - unlinked[0] + transferred[0] + copied[0]),
					max(0, applyingVaultEntry.inode - unlinked[1] + transferred[1] + copied[1]))
				if written is None:
					records_written = False
				else:
					applying_record = vault_info_dict[applyingVersionNumber] = written
					reference_record = record(reference_list, referenceVaultEntry, max(0, referenceVaultEntry.size - transferred[0]),
						max(0, referenceVaultEntry.inode - transferred[1])) or reference_record
		return records_written
	def went_down(kept:bool) -> tuple:
		# how far the two records went down in all, the reference vault's with it when it went, but never less than
		# nothing: a prune raising the caller's sums would remove more versions than the limit asks for
		size = applying_record.size + (reference_record.size if kept else 0)
		inodes = applying_record.inode + (reference_record.inode if kept else 0)
		return (max(0, referenceVaultEntry.size + applyingVaultEntry.size - size),
			max(0, referenceVaultEntry.inode + applyingVaultEntry.inode - inodes))
	def keep_oldest(why:str) -> tuple:
		# the reference vault stays, back at the front of vault_info_dict, with the records written, and the job's FAILED
		# marker says so
		backuperTeeLogToTl(path=referenceVaultPath,error=True,message=f'Aborting removal of {referenceVaultPath} because {why}')
		now = clock()
		if now >= PRUNE_ABORTED.get(job_name, now):
			job_log(job_name, f'FAILED: cannot remove {referenceVaultPath}, as {why}; it is kept, and the vault keeps growing')
			PRUNE_ABORTED[job_name] = now + DISK_WAIT_REPEAT_SECONDS
		write_records()
		new_dict = OrderedDict()
		new_dict[referenceVersionNumber] = reference_record
		new_dict.update(vault_info_dict)
		vault_info_dict.clear()
		vault_info_dict.update(new_dict)
		return went_down(True)
	def folder_gone() -> None:
		# the reference vault's folder went: nothing is kept of it in memory
		forget_real_vault_folders(referenceVaultPath)
		forget_version_moves(referenceVaultPath)
	def remove_lists(lists:list) -> bool:
		# the reference vault's change lists, once its folder went: whether they went too
		for path in lists:
			try:
				os.remove(path)
			except FileNotFoundError:
				pass
			except OSError as e:
				backuperTeeLogToTl(path=referenceVaultPath,error=True,message=f'Error removing {path}: {e}')
				return False
		PRUNE_ABORTED.pop(job_name, None)
		return True
	# a disk of either pool missing, or mounted again since here, can hide the reference vault, a link of the next
	# version into it (during the walk), or what is left of it (during its removal): nothing is taken for gone then
	guard = PoolGuard([job_vault, monitor_path])
	def require_pools() -> None:
		# the reference vault kept, and the attempt failed: its retry scans the vault again, so the caller's sums need not
		# be right
		problem = guard.problem()
		if problem:
			keep_oldest(problem)
			raise PoolNotReady(problem)
	folder_name = os.path.basename(referenceVaultPath)
	own_folder = os.path.join(job_vault, folder_name)
	def own_paths() -> tuple:
		# (whether the job vault lists the reference vault's folder, its change lists): its name, --, and a record
		# change_list_record() reads, regular files only, and nothing else named like them, such as a user's
		# V0--<timestamp>.stray beside it. raises OSError when the job vault cannot be listed or a list looked at
		names = os.listdir(job_vault)
		lists = sorted(os.path.join(job_vault, name) for name in names
			if change_list_names(name, folder_name) and stat.S_ISREG(os.lstat(os.path.join(job_vault, name)).st_mode))
		return folder_name in names, lists
	# only a folder that is not there is gone: one that cannot be looked at may hold every copy the next version links
	try:
		os.lstat(referenceVaultPath)
	except FileNotFoundError:
		# a removal cut short took the folder, once its links were all materialised and the records written: what is left
		# goes, and its record with it
		try:
			listed, lists = own_paths()
		except OSError as e:
			return keep_oldest(f'the job vault cannot be listed for what is left of it: {e}')
		if listed:
			# one ENOENT is no proof while the job vault still lists it: its links may not be materialised
			return keep_oldest('it was not there when looked at, though the job vault lists it')
		# nor while a disk is out, whose folder of it may be all of it
		require_pools()
		backuperTeeLogToTl(path=referenceVaultPath,error=True,message=f'{referenceVaultPath} is already gone: removing what is left of it')
		folder_gone()
		if not remove_lists(lists):
			return keep_oldest('what was left of it cannot be removed')
		return went_down(False)
	except OSError as e:
		return keep_oldest(f'it cannot be looked at: {e}')
	try:
		reference_list = change_list_of(referenceVaultEntry)
		applying_list = change_list_of(applyingVaultEntry)
	except OSError as e:
		return keep_oldest(f'its change list, or that of {applyingVaultEntry.path}, cannot be looked at: {e}')
	if applying_list is None:
		# its list may be only out of the listing (a mergerfs branch out): one made now would be a second when it is back
		return keep_oldest(f'the change list of {applyingVaultEntry.path} is not there')
	backuperTeeLogToTl(path=referenceVaultPath,message=f"Dealing with {applyingVersionNumber}: {applyingVaultEntry.path}")
	materialize_failed = False
	def failed(message:str) -> None:
		nonlocal materialize_failed
		materialize_failed = True
		backuperTeeLogToTl(path=referenceVaultPath,error=True,message=message)
	def remove_if_target(path:str, target_st:os.stat_result) -> None:
		# a name pruning linked to the copy, removed only while it is still the copy's
		with contextlib.suppress(OSError):
			if same_inode(os.lstat(path), target_st):
				os.remove(path)
	def share_moved_copy(copy:str, link:str, link_st:os.stat_result):
		# a copy of copy, with its metadata, put in place of link by a rename, while link is still the walk's symlink: its
		# lstat(), None when it failed
		temp_path = partial_copy_path(link)
		try:
			shutil.copyfile(copy,temp_path,follow_symlinks=False)
			if not copy_file_meta(copy,temp_path):
				return None
			made = os.lstat(temp_path)
			if not same_inode(os.lstat(link), link_st):
				backuperTeeLogToTl(path=referenceVaultPath,error=True,message=f'Not copying {copy} to {link}: it is no longer the link')
				return None
			os.replace(temp_path,link)
			return made
		except OSError as e:
			backuperTeeLogToTl(path=referenceVaultPath,error=True,message=f'Error copying {copy} to {link}: {e}')
			return None
		finally:
			with contextlib.suppress(OSError):
				os.remove(temp_path)
	# the copies a filesystem without hard links made this walk move out of the reference vault, so a second link
	# naming one gets its bytes too: one moved to the link at its own path by the hash of its path alone (PathHashes),
	# as every unchanged file of a big job is one, any other by target -> the link it now stands in place of
	moved_home = PathHashes()
	moved_away = {}
	def moved_to(target:str):
		# where this walk moved target, None when it did not
		if target in moved_away:
			return moved_away[target]
		if target in moved_home:
			return os.path.join(applyingVaultEntry.path, target[len(referenceVaultPath) + 1:])
		return None
	def note_moved(target:str, link:str):
		if link[len(applyingVaultEntry.path):] == target[len(referenceVaultPath):]:
			moved_home.add(target)
		else:
			moved_away[target] = link
	def meet_dangling(file:str, file_st:os.stat_result, linkTarget:str) -> None:
		# the target is gone: moved into this version by this walk for another link (one of the two a user's link the rows
		# could not tell), whose copy this one gets too; else the link was dangling before, and is left as it is. a chain
		# link whose copy is gone reads as missing either way, and a user's link of that form (the blind spot, as
		# a/U -> ../../<V0>/a/U with no a/U in V0) stays the user's in every kept version. nothing of it is transferred
		# or freed, so the books do not change
		taken = moved_to(linkTarget)
		if taken is not None:
			backuperTeeLogToTl(path=referenceVaultPath,error=True,message=f'{file} and {taken} both link to {linkTarget}: one is a user\'s link that cannot be told from a chain link, so both get its copy')
			made = share_moved_copy(taken, file, file_st)
			if made is None:
				failed(f'Error giving {file} the copy of {linkTarget} that {taken} took')
				return
			book(unlinked, file_st)
			book(copied, made)
			return
		backuperTeeLogToTl(path=referenceVaultPath,message=f'Leaving the dangling link {file} -> {linkTarget} as it is: its target is already missing')
	def move_copy(file:str, file_st:os.stat_result, linkTarget:str, target_st:os.stat_result) -> bool:
		# the copy moved in place of the link, for a filesystem that cannot hard link it: whether it is there now
		try:
			still_the_link = same_inode(os.lstat(file), file_st)
		except OSError as e:
			failed(f'Error looking at {file}: {e}')
			return False
		if not still_the_link:
			failed(f'Not moving {linkTarget} to {file}: it is no longer the link')
			return False
		try:
			os.rename(linkTarget,file)
		except Exception as e:
			try:
				landed = same_inode(os.lstat(file), target_st)
			except OSError:
				landed = False
			if not landed:
				# the copy may still be in the reference vault, which removing would destroy: kept, and tried again later
				failed(f'Error moving {linkTarget} to {file}: {e}')
				return False
			# the rename moved the copy and then reported an error: the copy is in place
			backuperTeeLogToTl(path=referenceVaultPath,message=f'Moving {linkTarget} to {file} reported {e}, but the copy is in place')
		note_moved(linkTarget, file)
		return True
	def link_copy(file:str, file_st:os.stat_result, linkTarget:str, target_st:os.stat_result):
		# the copy hard linked in place of the link: True when it is there, False when it failed and the walk aborts, None
		# when the filesystem cannot hard link it
		temp_path = prune_link_path(file, target_st, prune_salt)
		try:
			# the link itself when the copy is a user's symlink stored in the version
			os.link(linkTarget,temp_path,follow_symlinks=False)
		except FileExistsError:
			# its own link, from a run cut off before the rename; anything else is never removed: what it is cannot be told
			try:
				left_by_a_run = same_inode(os.lstat(temp_path), target_st)
			except OSError as e:
				failed(f'Error looking at {temp_path}: {e}')
				return False
			if not left_by_a_run:
				failed(f'Not linking {linkTarget} to {file}: {temp_path} is there already, and is not its copy')
				return False
			backuperTeeLogToTl(path=referenceVaultPath,message=f'Linking {linkTarget} to {file} again from {temp_path}, which an earlier run left')
		except OSError as e:
			if e.errno in NO_HARD_LINK_ERRNOS:
				return None
			failed(f'Error linking {linkTarget} to {temp_path}: {e}')
			return False
		try:
			if not same_inode(os.lstat(file), file_st):
				remove_if_target(temp_path, target_st)
				failed(f'Not linking {linkTarget} to {file}: it is no longer the link')
				return False
			os.rename(temp_path,file)
		except Exception as e:
			try:
				landed = same_inode(os.lstat(file), target_st)
			except OSError:
				landed = False
			if not landed:
				remove_if_target(temp_path, target_st)
				failed(f'Error linking {linkTarget} to {file}: {e}')
				return False
			backuperTeeLogToTl(path=referenceVaultPath,message=f'Linking {linkTarget} to {file} reported {e}, but the copy is in place')
		return True
	# the next version's rows, read once for the whole walk
	moves = VaultMoves(job_vault,monitor_path,monitor_paths).of(applyingVaultEntry.path)
	# walked instead of listed up front, as the next version links every tracked file (500k+ for big jobs).
	# each folder is read in full before its links are replaced, so a replaced link cannot make the walk skip another.
	# a folder that cannot be listed, or an entry that cannot be looked at, may hold this version's only way to a copy
	# in the reference vault, so the reference vault is kept
	walk_errors = []
	for file, _, is_dir in iter_tree_entries(applyingVaultEntry.path, list_folders_first=True, errors=walk_errors):
		if is_dir:
			continue
		try:
			file_st = os.lstat(file)
		except FileNotFoundError as e:
			if PARTIAL_COPY_NAME.fullmatch(os.path.basename(file)):
				# a name a cut off run linked a copy under, listed with its folder before this walk renamed it over its link
				continue
			failed(f'Error looking at {file}: {e}')
			continue
		except OSError as e:
			failed(f'Error looking at {file}: {e}')
			continue
		if not stat.S_ISLNK(file_st.st_mode):
			continue
		# a link an older daemon moved to another folder depth still names its version, though its text no longer reaches it.
		# a user's symlink is left as it is, however it is shaped, and so is a link naming a folder: the daemon links
		# files only, so no folder is ever put in place of a link
		try:
			linkTarget = vault_chain_hop(job_vault, file, os.readlink(file), moves)
		except UnexplainedChainLink as e:
			# the rows cannot tell: it may be this version's only way to its copy, which is kept as for a chain link
			linkTarget = e.target
		except (UncheckedVaultLink, OSError) as e:
			# it may be this version's only way to a file in the reference vault, so keep that
			failed(f'Error checking whether {file} links into {referenceVaultPath}: {e}')
			continue
		if linkTarget is None or not linkTarget.startswith(referenceVaultPath + '/'):
			if DEBUG:
				backuperTeeLogToTl(path=referenceVaultPath,message=f'Not materialising {file}: not a chain link into {referenceVaultPath}')
			continue
		try:
			target_st = os.lstat(linkTarget)
		except (FileNotFoundError, NotADirectoryError):
			# ENOTDIR: a name on the way to it is a file in the reference vault, so it is not there either
			meet_dangling(file, file_st, linkTarget)
			continue
		except OSError as e:
			failed(f'Error looking at {linkTarget}: {e}')
			continue
		if stat.S_ISDIR(target_st.st_mode):
			# never so for a link vault_chain_hop() takes: no folder is put in place of a link
			continue
		if DEBUG:
			backuperTeeLogToTl(path=referenceVaultPath,message=f'Materialising {linkTarget} at {file}')
		linked = link_copy(file, file_st, linkTarget, target_st)
		moved = linked is None
		if moved:
			linked = move_copy(file, file_st, linkTarget, target_st)
		if linked:
			# the copy is the next version's now, in place of the link
			if (target_st.st_dev, target_st.st_ino) not in booked:
				if not moved:
					booked.add((target_st.st_dev, target_st.st_ino))
				book(transferred, target_st)
			book(unlinked, file_st)
	for rel, error in walk_errors:
		failed(f'Error listing {unreadable_path(applyingVaultEntry.path, rel)}: {error}')
	if materialize_failed:
		return keep_oldest(f'materializing the links of {applyingVaultEntry.path} into it failed')
	# before the removal, so a run cut off from here on leaves records a restart reads true
	if not write_records():
		return keep_oldest(f'the change list of {applyingVaultEntry.path} cannot be renamed for what it now holds')
	backuperTeeLogToTl(path=referenceVaultPath,message=f'Removing {referenceVaultPath}')
	try:
		listed, lists = own_paths()
	except OSError as e:
		return keep_oldest(f'the job vault cannot be listed: {e}')
	if not listed:
		return keep_oldest('its folder was not found listing the job vault')
	# the folder first, its change lists only once it is gone: a removal cut short leaves a list whose folder went (a
	# stale list below the oldest, which the scan deletes) or the version committed, never a folder without a list,
	# which the scan could not tell from a version whose list a listing left out
	require_pools()
	removed = not multiCMD.run_command(['rm','-rf',own_folder],quiet=True,return_code_only=True)
	# a disk that dropped while it ran hides what is left of the folder on it, which a list must still name when it is back
	require_pools()
	gone = there(referenceVaultPath) is False
	if gone:
		folder_gone()
		# what is left of the version holds nothing, and the next prune finishes it if this one does not
		reference_record = reference_record._replace(size=0, inode=0)
	if not removed:
		return keep_oldest('rm -rf of its folder failed')
	if not gone:
		return keep_oldest('its folder is still there after rm -rf')
	if not remove_lists(lists):
		return keep_oldest('its change list cannot be removed')
	return went_down(False)


oracle_decrement_stepper = types.FunctionType(decrement_stepper.__code__, rv.__dict__, 'oracle_decrement_stepper',
	decrement_stepper.__defaults__, decrement_stepper.__closure__)
del decrement_stepper
