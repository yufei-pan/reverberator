'''
Round 16: do_referenced_copy() sets a folder it makes in a few requests (copy_new_folder_meta()) and puts each link's
text together as a string (referenced_link_text()). On random versions, every result stays the per-entry oracle's
(tests/test_referenced_copy.py, which calls copy_file_meta() and os.path.relpath() as 0c4ff66 did): each entry's type,
mode, owner, times, extended attributes and link text, the rows kept, the lines with their level, and unsynced, with
folders with and without extended attributes or ACLs, ones that cannot be read, owners that cannot be set, and odd names.
'''
import errno
import os
import random
import shutil
import stat
import pytest
import reverberator as rv
from tests.harness import tracked_manifest
from tests.test_referenced_copy import oracle_referenced_copy

pytestmark = pytest.mark.unit

V0 = 'V0--2021-01-01_00-00-00_-0800'
V1 = 'V1--2021-01-02_00-00-00_-0800'
SEEDS = int(os.environ.get("ORACLE_SEEDS", 500))
NAMES = ['a', 'b', 'a b', '..x', '.h', 'x..', 'n\nl', 'tab\tx', 'bad\udcff', 'é', 'noxa', 'nogx', 'noown', 'long' * 30, '-', '~', '*']
# an ACL giving user 1 rwx, as setfacl writes it ( system.posix_acl_access: version 2, then tag, perm, id entries )
# the snapshot reads with these, whatever a seed makes fail
LISTXATTR, GETXATTR = os.listxattr, os.getxattr
META_LINES = ('Failed to copy', 'Traceback ')
ACL = (b'\x02\x00\x00\x00' + b'\x01\x00\x07\x00\xff\xff\xff\xff' + b'\x02\x00\x07\x00\x01\x00\x00\x00'
	+ b'\x04\x00\x05\x00\xff\xff\xff\xff' + b'\x10\x00\x07\x00\xff\xff\xff\xff' + b'\x20\x00\x05\x00\xff\xff\xff\xff')


def random_version(rng, root):
	'''A random V0 under root: (path, folder rows, file rows), the rows naming missing entries and the other kind too.'''
	v0 = os.path.join(root, V0)
	os.makedirs(v0)
	folders, files = [], []
	def make(folder, rel, depth):
		for _ in range(rng.randint(0, 4)):
			name = rng.choice(NAMES) + ('' if rng.random() < 0.6 else str(rng.randint(0, 9)))
			path = os.path.join(folder, name)
			if os.path.lexists(path):
				continue
			if depth < 3 and rng.random() < 0.4:
				os.mkdir(path)
				folders.append(rel + name + '/')
				make(path, rel + name + '/', depth + 1)
				if rng.random() < 0.3:
					os.setxattr(path, 'user.k' + str(rng.randint(0, 2)), os.urandom(rng.randint(0, 9)))
				if rng.random() < 0.15:
					os.setxattr(path, 'system.posix_acl_access', ACL)
				if rng.random() < 0.1:
					os.setxattr(path, 'system.posix_acl_default', ACL)
				os.chmod(path, rng.choice([0o755, 0o700, 0o2775, 0o1777, 0o555, 0o751]))
				os.chown(path, rng.randint(0, 3), rng.randint(0, 3))
				os.utime(path, ns=(rng.randint(1, 2 ** 40) * 1000 + rng.randint(0, 999), rng.randint(1, 2 ** 40) * 1000 + rng.randint(0, 999)))
			elif rng.random() < 0.1:
				os.symlink(rng.choice(['a', '../a', '/etc']), path)
				if rng.random() < 0.5:
					folders.append(rel + name + '/')
				else:
					files.append(rel + name)
			else:
				with open(path, 'w') as f:
					f.write('x')
				files.append(rel + name)
	make(v0, '', 0)
	# rows of entries gone, and of the other kind
	for _ in range(rng.randint(0, 3)):
		files.append(rng.choice(NAMES) + 'ghost')
	for _ in range(rng.randint(0, 2)):
		folders.append(rng.choice(NAMES) + 'gone/')
	if folders and rng.random() < 0.3:
		files.append(rng.choice(folders).rstrip('/'))
	if files and rng.random() < 0.3:
		folders.append(rng.choice(files) + '/')
	return v0, sorted(set(folders)), sorted(set(files))


def snapshot(root):
	'''{rel: (type, mode, uid, gid, times, xattrs, link text)} of everything under root, each looked at before it is listed.'''
	found = {}
	def walk(folder, rel):
		for name in sorted(os.listdir(folder)):
			path = os.path.join(folder, name)
			st = os.lstat(path)
			link = stat.S_ISLNK(st.st_mode)
			xattrs = () if link else tuple(sorted((key, GETXATTR(path, key, follow_symlinks=False)) for key in LISTXATTR(path, follow_symlinks=False)))
			# a link's times are when it was made, and so is the mtime of a folder links were made in after its own
			emptied = stat.S_ISDIR(st.st_mode) and not os.listdir(path)
			times = None if link else (st.st_atime_ns, st.st_mtime_ns if emptied or not stat.S_ISDIR(st.st_mode) else None)
			if 'noxa' in name or 'nogx' in name:
				# its attributes may not be read: the copy of its metadata then stops before its times, made now
				times = None
			found[rel + name] = (stat.S_IFMT(st.st_mode), st.st_mode, st.st_uid, st.st_gid, times,
				xattrs, os.readlink(path) if link else None)
			if stat.S_ISDIR(st.st_mode):
				walk(path, rel + name + '/')
	walk(root, '')
	return found


@pytest.fixture
def logged(monkeypatch):
	lines = []
	def record(path, message, **kwargs):
		kind = 'error' if kwargs.get('error') else 'warning' if kwargs.get('warning') else 'info'
		lines.append((kind, str(message)))
	monkeypatch.setattr(rv, 'backuperTeeLogToTl', record)
	return lines


def failing_requests(monkeypatch, rng):
	'''Make listxattr, getxattr and chown fail for the names saying so, with an errno picked for this seed.'''
	# a listing's ENOSYS is left out: shutil.copystat() fails on it, as copy_file_meta() does, and the folder fast path takes it
	# for a filesystem without attributes, as xattr_names() does (test_a_filesystem_without_attributes_takes_the_fast_path)
	listing = rng.choice([errno.EACCES, errno.EIO, errno.ENOTSUP, errno.ENODATA])
	reading, owning = (rng.choice([errno.EACCES, errno.EIO, errno.ENOTSUP, errno.ENOSYS, errno.ENODATA]) for _ in range(2))
	real_list, real_get, real_chown = os.listxattr, os.getxattr, os.chown
	def named(path, part):
		return part in os.path.basename(os.fspath(path).rstrip('/'))
	def listxattr(path, *args, **kwargs):
		if named(path, 'noxa'):
			raise OSError(listing, os.strerror(listing), path)
		return real_list(path, *args, **kwargs)
	def getxattr(path, *args, **kwargs):
		if named(path, 'nogx'):
			raise OSError(reading, os.strerror(reading), path)
		return real_get(path, *args, **kwargs)
	def chown(path, *args, **kwargs):
		if named(path, 'noown'):
			raise OSError(owning, os.strerror(owning), path)
		return real_chown(path, *args, **kwargs)
	monkeypatch.setattr(os, 'listxattr', listxattr)
	monkeypatch.setattr(os, 'getxattr', getxattr)
	monkeypatch.setattr(os, 'chown', chown)


def test_random_copies_come_out_as_the_oracle_has_them(tmp_path, monkeypatch, logged):
	cases = {'xattrs': 0, 'plain': 0, 'nested': 0, 'absolute': 0}
	for seed in range(int(os.environ.get('ORACLE_FIRST', 0)), SEEDS):
		rng = random.Random(seed)
		root = os.path.join(str(tmp_path), f's{seed}')
		os.makedirs(root)
		v0, folders, files = random_version(rng, root)
		relative = rng.random() < 0.8
		nested = rng.random() < 0.1
		inherit = rng.random() < 0.15
		source = v0
		if rng.random() < 0.3:
			source = os.path.relpath(v0) + rng.choice(['', '/', '//', '/.', '/../' + V0])
		monkeypatch.setattr(rv, 'REFERENCED_COPY_CHUNK', rng.choice([1, 2, 3, 64]))
		monkeypatch.setattr(rv, 'REFERENCED_COPY_WINDOW', rng.choice([1, 2, 32]))
		with monkeypatch.context() as patched:
			if rng.random() < 0.5:
				failing_requests(patched, rng)
				# one thread: on threads, as 0c4ff66 has them, a folder can be made before the one above it has its default
				# ACL or set-group-ID bit, which its own metadata, when it fails, does not set right; it is in unsynced
				patched.setattr(rv, 'REFERENCED_COPY_THREADS', 1)
			outcomes = []
			for copy in (oracle_referenced_copy, rv.do_referenced_copy):
				v1 = os.path.join(v0, 'sub', V1) if nested else os.path.join(root, V1)
				if os.path.lexists(v1):
					shutil.rmtree(v1)
				os.makedirs(v1)
				if inherit:
					# a default ACL on the version folder: every folder made in it starts with ACLs of its own
					os.setxattr(v1, 'system.posix_acl_default', ACL)
				manifest = tracked_manifest(root, v0, files, folders)
				del logged[:]
				unsynced = []
				rv.GREEN_LIGHT.set()
				result = copy(source, v1, manifest, relative=relative, unsynced=unsynced)
				lines = [line for line in logged if not line[1].startswith('Made the referenced copy of ')]
				# copy_file_meta() writes its own lines on the thread it runs on, as 0c4ff66 has it: those come in any order
				lines = ([line for line in lines if not line[1].startswith(META_LINES)], sorted(line for line in lines if line[1].startswith(META_LINES)))
				outcomes.append((result, snapshot(v1), manifest.folders, manifest.files, lines, unsynced))
				manifest.close()
			if outcomes[1] != outcomes[0]:
				for part, (old, new) in enumerate(zip(*outcomes)):
					if old != new:
						if isinstance(old, dict):
							old, new = sorted(set(old.items()) - set(new.items())), sorted(set(new.items()) - set(old.items()))
						elif isinstance(old, (list, tuple)):
							old, new = [line for line in old if line not in new], [line for line in new if line not in old]
						pytest.fail(f'seed {seed}, part {part}: the oracle has {old!r}, the copy {new!r}')
		tree = outcomes[0][1]
		cases['xattrs'] += any(entry[5] for entry in tree.values())
		cases['plain'] += any(entry[0] == stat.S_IFDIR and not entry[5] for entry in tree.values())
		cases['nested'] += nested
		cases['absolute'] += not relative
		shutil.rmtree(root)
	# every kind came up often
	assert min(cases.values()) >= 30, cases
