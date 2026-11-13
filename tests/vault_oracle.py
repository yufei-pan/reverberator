'''
The independent oracle of the crash runs: what a vault's kept versions hold, read with plain os calls and rules of its
own. It imports nothing from reverberator, so a wrong rule there cannot hide here.

A version is read through two kinds of daemon link, each by its exact text and nothing looser: the forward link of design
R ('../'*(depth) + next version's folder name + '/' + its own path) and the backward link of 0.54 (the same ups, the
previous version's folder name, and any path there, as a move keeps its old path). Any other link is a user's link and is
read as a link. A vault whose manifest says design R has no backward link left, nor does a walk that went forward meet one
(spec section 4.3): a link of that form there is a user's.

rows_match_vault(), the row oracle, reads the rows' names and tail hashes with the daemon's own functions, as those are in
its formats; nothing else here does.
'''
import base64
import hashlib
import json
import os
import re
import stat
from collections import Counter, namedtuple
# a name of its own, as a test that fails the daemon's opens of the manifest patches the module's
from sqlite3 import Error as SqliteError, connect as sqlite_connect

# what a version holds at a path, or the monitored tree. kind: 'f', 'd', 'l', 'special', 'root', or 'dangling' for a daemon
# link that leads nowhere. data: a file's sha256, a link's text, a dangling link's text, a special file's (type, device number). xattrs: sorted (name, value)
EntryView = namedtuple('EntryView', ['kind', 'data', 'mode', 'uid', 'gid', 'mtime_ns', 'xattrs'])

ROOT_RECORD = 'trusted.reverberator.root'
ROOT_RECORD_PREFIX = 'trusted.reverberator.'
LIST_SUFFIX = '.modified_contents.nsv'
VERSION_FOLDER = re.compile(r'V([0-9]+)--[^/]+')
VERSION_LIST = re.compile(r'(V[0-9]+--.+?)--[^/]*_ino' + re.escape(LIST_SUFFIX))
PARTIAL_SUFFIX = '.reverberator-partial'
STAGING = '.reverberator_staging'
# what a job vault holds besides its versions, their lists and staging, whatever a batch was doing when it was cut
KEPT_NAMES = {'current_version', '.reverberator_manifest.sqlite', '.reverberator_manifest.sqlite-journal',
	'.reverberator_manifest.sqlite-wal', '.reverberator_manifest.sqlite-shm', '.reverberator_prune_salt',
	'.reverberator_pending_transactions.nsv', 'journal.tsv'}


def forward_text(rel: str, next_name: str) -> str:
	'''
	The text of the forward link at rel in the version before the one whose folder is next_name.

	Examples:
		>>> forward_text('a', 'V2--x'), forward_text('a/b/c', 'V2--x')
		('../V2--x/a', '../../../V2--x/a/b/c')
	'''
	return '../' * (rel.count('/') + 1) + next_name + '/' + rel


def version_number(name: str):
	'''The number of the version folder called name; None when name is not one.'''
	match = VERSION_FOLDER.fullmatch(name)
	return None if match is None or name.endswith(LIST_SUFFIX) else int(match[1])


def linked_place(folder_name: str, rel: str, text: str, backward: bool = True):
	'''
	(version folder name, path in it) the link at rel in folder_name leads to, when its text is exactly a forward or, with
	backward, a 0.54 backward link's; else None, a user's link.

	Examples:
		>>> linked_place('V2--x', 'a/b', '../../V3--y/a/b'), linked_place('V2--x', 'a/b', '../../V1--y/moved/from')
		(('V3--y', 'a/b'), ('V1--y', 'moved/from'))
		>>> [linked_place('V2--x', 'a/b', text) for text in ('../V3--y/a/b', '../../../V3--y/a/b', '../../V3--y/a/c',
		...     '../../V4--y/a/b', '../../V0--y/a/b', '../../V1--y/a/../b', '../../V1--y/', '../../V1--y', '/v/V3--y/a/b', 'a/x')]
		[None, None, None, None, None, None, None, None, None, None]
		>>> linked_place('V2--x', 'a/b', '../../V3--y/a/b', False), linked_place('V2--x', 'a/b', '../../V1--y/moved/from', False)
		(('V3--y', 'a/b'), None)
	'''
	head = '../' * (rel.count('/') + 1)
	if not text.startswith(head):
		return None
	name, _, named = text[len(head):].partition('/')
	number = version_number(name)
	if number is None or not named:
		return None
	own = version_number(folder_name)
	if number == own + 1 and named == rel:
		return name, named
	if backward and number == own - 1 and not any(part in ('', '.', '..') for part in named.split('/')):
		return name, named
	return None


def landing(job_vault: str, folder_name: str, rel: str, backward: bool = None):
	'''
	(version folder name, path in it) that holds rel of folder_name once every daemon link on the way is followed, one
	path part at a time; the entry there may be a user's link. None when it leads nowhere. backward: whether a 0.54 link
	is one, by default as the manifest says; never once the walk went forward.
	'''
	if backward is None:
		backward = not recorded_design_r(job_vault)
	seen = set()
	while True:
		if (folder_name, rel) in seen:
			return None
		seen.add((folder_name, rel))
		parts = rel.split('/')
		for count in range(1, len(parts) + 1):
			here = '/'.join(parts[:count])
			path = os.path.join(job_vault, folder_name, here)
			try:
				mode = os.lstat(path).st_mode
			except (FileNotFoundError, NotADirectoryError):
				return None
			if stat.S_ISLNK(mode):
				place = linked_place(folder_name, here, os.readlink(path), backward)
				if place is None:
					if count == len(parts):
						return folder_name, rel
					# nothing of a version is read through a user's link
					return None
				backward = backward and version_number(place[0]) < version_number(folder_name)
				folder_name, rel = place[0], '/'.join((place[1], *parts[count:]))
				break
			if count < len(parts) and not stat.S_ISDIR(mode):
				return None
		else:
			return folder_name, rel


def xattrs_of(path: str, skip_prefix: str = None) -> tuple:
	try:
		names = os.listxattr(path, follow_symlinks=False)
	except OSError:
		return ()
	return tuple(sorted((name, os.getxattr(path, name, follow_symlinks=False)) for name in names
		if skip_prefix is None or not name.startswith(skip_prefix)))


def sha256_of(path: str) -> str:
	digest = hashlib.sha256()
	with open(path, 'rb') as f:
		for chunk in iter(lambda: f.read(1 << 20), b''):
			digest.update(chunk)
	return digest.hexdigest()


def entry_view(path: str) -> EntryView:
	st = os.lstat(path)
	mode = stat.S_IMODE(st.st_mode)
	if stat.S_ISDIR(st.st_mode):
		kind, data = 'd', None
	elif stat.S_ISLNK(st.st_mode):
		# a link's mode means nothing
		kind, data, mode = 'l', os.readlink(path), None
	elif stat.S_ISREG(st.st_mode):
		kind, data = 'f', sha256_of(path)
	else:
		kind, data = 'special', (stat.S_IFMT(st.st_mode), st.st_rdev)
	return EntryView(kind, data, mode, st.st_uid, st.st_gid, st.st_mtime_ns, xattrs_of(path))


def root_record_view(version_path: str) -> EntryView:
	'''What the version's record of the monitored root says, in the form snapshot_tree() gives the root.'''
	try:
		record = json.loads(os.getxattr(version_path, ROOT_RECORD, follow_symlinks=False))
		xattrs = tuple(sorted((name, base64.b64decode(value)) for name, value in record['xattrs'].items()))
		return EntryView('root', None, record['mode'], record['uid'], record['gid'], record['mtime_ns'], xattrs)
	except (OSError, ValueError, KeyError, TypeError) as e:
		return EntryView('root', f'no record: {e}', None, None, None, None, ())


def read_view(job_vault: str, folder_name: str, inodes: dict = None) -> dict:
	'''
	{rel: EntryView} of the version in folder_name, read through its daemon links; '' is its root record. With inodes, a dict
	to fill: {rel: (device, inode)} of each entry that is not a folder, as the links lead to it.
	'''
	view = {'': root_record_view(os.path.join(job_vault, folder_name))}
	top = os.path.join(job_vault, folder_name)
	backward = not recorded_design_r(job_vault)
	pending = [(name, folder_name, name) for name in os.listdir(top)]
	# a list, as a tree may be deeper than the interpreter's stack
	while pending:
		rel, version, at = pending.pop()
		place = landing(job_vault, version, at, backward)
		if place is None:
			text = os.readlink(os.path.join(job_vault, version, at)) if os.path.islink(os.path.join(job_vault, version, at)) else None
			view[rel] = EntryView('dangling', text, None, None, None, None, ())
			continue
		path = os.path.join(job_vault, *place)
		view[rel] = entry_view(path)
		if view[rel].kind == 'd':
			pending.extend((f'{rel}/{name}', place[0], f'{place[1]}/{name}') for name in os.listdir(path))
		elif inodes is not None:
			st = os.lstat(path)
			inodes[rel] = (st.st_dev, st.st_ino)
	return view


def snapshot_tree(path: str) -> dict:
	'''{rel: EntryView} of the tree at path, its links read as links; '' is its root, as a version's record gives it.'''
	st = os.lstat(path)
	view = {'': EntryView('root', None, stat.S_IMODE(st.st_mode), st.st_uid, st.st_gid, st.st_mtime_ns, xattrs_of(path, ROOT_RECORD_PREFIX))}
	pending = list(os.listdir(path))
	while pending:
		rel = pending.pop()
		view[rel] = entry_view(os.path.join(path, rel))
		if view[rel].kind == 'd':
			pending.extend(f'{rel}/{name}' for name in os.listdir(os.path.join(path, rel)))
	return view


def compared(view: EntryView, folder_times: bool, loose: bool) -> EntryView:
	'''view with what the check is told not to compare taken out; loose: a file, link or special file of a shared inode, whose metadata is not compared.'''
	if view is None:
		return None
	if view.kind == 'd' and not folder_times:
		return view._replace(mtime_ns=None)
	if view.kind in ('f', 'l', 'special') and loose:
		return view._replace(mode=None, uid=None, gid=None, mtime_ns=None, xattrs=None)
	return view


def recorded_design_r(job_vault: str) -> bool:
	'''Whether the manifest of job_vault says its layout is design R (its meta row 'layout'), read as it lies, whatever a cut left in its journal.'''
	path = os.path.join(job_vault, '.reverberator_manifest.sqlite')
	if not os.path.exists(path):
		return False
	conn = sqlite_connect(f'file:{path}?immutable=1', uri=True)
	try:
		row = conn.execute("SELECT value FROM meta WHERE key = 'layout'").fetchone()
	except SqliteError:
		return False
	finally:
		conn.close()
	return row is not None and row[0] == 'r'


def daemon_links(job_vault: str, folder_name: str) -> list:
	'''[(rel, text)] of the links in the folder of a version whose text is a daemon link's (linked_place()), forward or backward.'''
	found = []
	top = os.path.join(job_vault, folder_name)
	for folder, names, files in os.walk(top):
		for name in names + files:
			path = os.path.join(folder, name)
			if os.path.islink(path):
				rel = os.path.relpath(path, top)
				text = os.readlink(path)
				if linked_place(folder_name, rel, text) is not None:
					found.append((rel, text))
	return found


def check_vault(job_vault: str, expected: dict, allowed_new: set, folder_times: bool = True, free_file_meta: bool = False) -> list:
	'''
	What is wrong with job_vault, as lines; empty means exact.

	expected: {version number: its view (snapshot_tree() form)}, every version the vault may keep. A number in allowed_new
	may be missing, as a batch cut before its commit leaves it; any other must be there, and no other may. folder_times
	False leaves folder mtimes out; free_file_meta leaves out everything of a file but its contents, and of a user's link but
	its text (a special file's device number stays), as an Only Sync Attributes change reaches every version sharing it (spec
	section 2.4): in the versions before the newest, and only for an inode that more than one version reads. A file no other
	version shares, and every file of the newest version, are compared whole. A cut batch's tree, a version folder with no list,
	is no version read here, and it shares with the newest listed version, which is then loose as an older one. Limit: an inode
	read by one version only passes for never shared, but a batch that changes a file's attributes in place and then swaps
	it for a fresh copy, or drops it, leaves a version with the changed attributes on an inode no other version reads; that exact vault is
	reported, and the check is not widened for it. A version's own folder must have the mode and owner of the job vault's (the
	daemon makes both, and a version's root is recorded in its attribute instead). On design R the newest version is the real
	tree and holds no daemon link, of 0.54's kind or any, except a user's own link whose text has that form, which the
	monitored tree holds with that text (expected for the newest version).
	'''
	problems = []
	folders, lists = {}, {}
	for name in sorted(os.listdir(job_vault)):
		path = os.path.join(job_vault, name)
		listed = VERSION_LIST.fullmatch(name)
		number = version_number(name)
		if listed is not None:
			lists.setdefault(listed[1], []).append(name)
		elif number is not None:
			if os.path.islink(path) or not os.path.isdir(path):
				problems.append(f'{name}: a version folder that is not a real folder')
			elif number in folders:
				problems.append(f'{name}: a second folder of version {number}')
			else:
				folders[number] = name
		elif name == STAGING:
			held = os.listdir(path) if os.path.isdir(path) and not os.path.islink(path) else ['(not a folder)']
			if held:
				problems.append(f'left in staging: {sorted(held)}')
		elif name not in KEPT_NAMES:
			problems.append(f'left over in the job vault: {name}')
	for folder_name, names in lists.items():
		if version_number(folder_name) not in folders or folders[version_number(folder_name)] != folder_name:
			problems.append(f'a list with no version folder: {names}')
	for number, name in folders.items():
		count = len(lists.get(name, ()))
		if count != 1:
			problems.append(f'V{number}: {count} lists, not one')
	kept = sorted(folders)
	required = set(expected) - set(allowed_new)
	if required - set(kept):
		problems.append(f'versions missing: {sorted(required - set(kept))}')
	if set(kept) - set(expected):
		problems.append(f'versions not expected: {sorted(set(kept) - set(expected))}')
	if kept and kept != list(range(kept[0], kept[-1] + 1)):
		problems.append(f'versions not in a row: {kept}')
	if kept:
		try:
			current = os.readlink(os.path.join(job_vault, 'current_version'))
		except OSError as e:
			problems.append(f'current_version: {e}')
		else:
			if current != folders[kept[-1]]:
				problems.append(f'current_version names {current}, the newest is {folders[kept[-1]]}')
	for folder, names, files in os.walk(job_vault):
		for name in names + files:
			if name.endswith(PARTIAL_SUFFIX) or (name.startswith('.reverberator-change-list-') and folder != job_vault):
				problems.append(f'left over: {os.path.join(folder, name)!r}')
	vault_st = os.lstat(job_vault)
	for number in kept:
		st = os.lstat(os.path.join(job_vault, folders[number]))
		if (stat.S_IMODE(st.st_mode), st.st_uid, st.st_gid) != (stat.S_IMODE(vault_st.st_mode), vault_st.st_uid, vault_st.st_gid):
			problems.append(f'V{number}: the version folder has mode {stat.S_IMODE(st.st_mode):o}, owner {st.st_uid}:{st.st_gid}, not the job vault\'s')
	listed_versions = [number for number in kept if lists.get(folders[number])]
	# a folder after the newest listed one has no list: the tree of a cut batch, which the newest listed version links to
	cut_tree = bool(listed_versions) and kept[-1] != listed_versions[-1]
	if kept and not cut_tree and recorded_design_r(job_vault):
		held = expected.get(kept[-1], {})
		for rel, text in daemon_links(job_vault, folders[kept[-1]]):
			if held.get(rel) is None or held[rel].kind != 'l' or held[rel].data != text:
				problems.append(f'V{kept[-1]}:{rel!r}: a daemon link in the newest version of a design R vault')
	views, inodes = {}, {}
	for number in kept:
		if number in expected:
			inodes[number] = {}
			views[number] = read_view(job_vault, folders[number], inodes[number])
	readers = Counter(place for number in inodes for place in set(inodes[number].values()))
	for number, view in views.items():
		want = expected[number]
		newest = number == kept[-1]
		for rel in sorted(set(view) | set(want)):
			loose = free_file_meta and not newest and (readers[inodes[number].get(rel)] > 1 or (cut_tree and number == listed_versions[-1]))
			held = compared(view.get(rel), folder_times, loose)
			wanted = compared(want.get(rel), folder_times, loose)
			if held != wanted:
				problems.append(f'V{number}:{rel!r}: the vault holds {held}, expected {wanted}')
	return problems


def sizes_by_newest_holder(job_vault: str) -> dict:
	'''
	{version number: (size, inodes)} as spec section 6 defines them: every inode counted once, in the newest version that
	holds it. A file counts its size and one inode, a real folder 4 KiB and one inode, a link no bytes and one inode.
	A version's root folder is no row of it and is not counted.
	'''
	folders = {version_number(name): name for name in os.listdir(job_vault) if version_number(name) is not None}
	seen = set()
	sizes = {}
	for number in sorted(folders, reverse=True):
		size = inodes = 0
		pending = [os.path.join(job_vault, folders[number])]
		while pending:
			with os.scandir(pending.pop()) as entries:
				for entry in entries:
					st = entry.stat(follow_symlinks=False)
					if stat.S_ISDIR(st.st_mode):
						size += 4096
						inodes += 1
						pending.append(entry.path)
					elif stat.S_ISLNK(st.st_mode):
						inodes += 1
					elif (st.st_dev, st.st_ino) not in seen:
						seen.add((st.st_dev, st.st_ino))
						size += st.st_size
						inodes += 1
		sizes[number] = (size, inodes)
	return sizes


def rows_match_vault(job_vault: str) -> list:
	'''
	The rows of the manifest's version whose record does not describe the entry at their path in it, one line each: of the
	rows that hold a record and are checked (unchecked = 0), the entry's kind, mode, uid and gid; a file's size, mtime and
	tail hash; a link's text. A folder's mtime is left out, as its row's is the monitored one by the next comparison. A row
	of 0.54's referenced backups (kind 'r') is left out. [] when every such row matches, or when there is no manifest.

	The rows' names and their tail hash are in the daemon's own formats, so those two are read with its own functions
	(stored_name(), hash_file()): what is checked is which entry each record describes, not how a hash is made.
	'''
	import reverberator as rv
	path = os.path.join(job_vault, '.reverberator_manifest.sqlite')
	if not os.path.exists(path):
		return []
	conn = sqlite_connect(f'file:{path}?immutable=1', uri=True)
	try:
		version = conn.execute("SELECT value FROM meta WHERE key = 'version'").fetchone()
		rows = conn.execute('SELECT path, kind, size, mtime_ns, mode, uid, gid, hash, link FROM entries '
			"WHERE kind IS NOT NULL AND kind != 'r' AND unchecked = 0").fetchall()
	finally:
		conn.close()
	if version is None:
		return []
	top = os.path.join(job_vault, version[0])
	lines = []
	for stored, kind, size, mtime_ns, mode, uid, gid, file_hash, link in rows:
		rel = rv.stored_name(stored)
		entry = os.path.join(top, rel.rstrip('/'))
		try:
			st = os.lstat(entry)
		except OSError as e:
			lines.append(f'{rel!r}: its row records a {kind}, and the version holds nothing there ({e.strerror})')
			continue
		found = 'd' if stat.S_ISDIR(st.st_mode) else 'l' if stat.S_ISLNK(st.st_mode) else 'f' if stat.S_ISREG(st.st_mode) else 'o'
		wanted = (kind, mode, uid, gid)
		held = (found, st.st_mode, st.st_uid, st.st_gid)
		if found == 'f':
			wanted += (size, mtime_ns, file_hash)
			held += (st.st_size, st.st_mtime_ns, rv.hash_file(entry, st.st_size) if kind == 'f' and (st.st_size, st.st_mtime_ns) == (size, mtime_ns) else None)
		elif found == 'l':
			wanted += (link,)
			held += (os.readlink(entry),)
		if wanted != held:
			lines.append(f'{rel!r}: its row records {wanted}, the version holds {held}')
	return lines
