'''
Round 16: vault_chain_hop() tells the plain chain link, the text the referenced copy writes, as text, without
parse_chain_text(). On random vaults its every answer and exception stays 0c4ff66's (tests/chain_hop_oracle.py): chain
links at every depth, user's links of every shape, moved links, links the rows cannot tell, odd names, depths and
spellings of the paths, folders on the way that are links, files or missing, and names too long; and so does the
whole prune (tests/prune_oracle.py, with the old hop, against decrement_stepper() with the new).
'''
import errno
import os
import random
import shutil
import pytest
import reverberator as rv
from tests.chain_hop_oracle import oracle_vault_chain_hop
from tests.prune_oracle import oracle_decrement_stepper
from tests import test_prune_threads

pytestmark = pytest.mark.unit

SEEDS = int(os.environ.get('ORACLE_SEEDS', 500))
V2 = 'V2--2021-01-01_00-00-00_-0800'
V3 = 'V3--2021-01-02_00-00-00_-0800'
V4 = 'V4--2021-01-03_00-00-00_-0800'
NAMES = ['a', 'b', 'a b', '..x', '.h', 'x..', 'n\nl', 'bad\udcff', 'é', V3, V4, 'V3--x', '-', 'long' * 70, '~']


def answer(hop, *args):
	'''What hop gives for args: ('ok', result) or ('raised', type, str, target, cause).'''
	try:
		return ('ok', hop(*args))
	except Exception as e:
		return ('raised', type(e), str(e), getattr(e, 'target', None), repr(e.__cause__))


def spellings(rng, path):
	'''path, or another spelling of it abspath() takes to the same place.'''
	roll = rng.random()
	if roll < 0.7:
		return path
	if roll < 0.8:
		return path + '/'
	if roll < 0.85:
		return '/' + path
	if roll < 0.9:
		head, _, tail = path.rpartition('/')
		return f'{head}/./{tail}'
	if roll < 0.95:
		return path.replace('/', '//', 1)
	return os.path.relpath(path)


def random_texts(rng, rel, rels):
	'''Texts of a link at rel: the plain chain link, and every near miss.'''
	ups = rel.count('/') + 1
	named = rng.choice([rel] * 3 + rels)
	texts = ['../' * ups + V3 + '/' + rel, '../' * (ups + rng.choice([-1, 1, 2])) + V3 + '/' + named,
		'../' * ups + rng.choice([V2, V4, 'V3--x', 'V03--2021-01-02_00-00-00_-0800', V3 + 'x', '..', '', '.']) + '/' + rel,
		'../' * ups + V3 + '/' + named, '../' * ups + V3 + '/' + rel + rng.choice(['/', '/.', '//', 'x', '/..']),
		'../' * ups + V3 + '//' + rel, '../' * ups + V3 + '/./' + rel, '/' + V3 + '/' + rel, rel, '../' * ups, '../' * ups + V3,
		'../' * ups + V3 + '/', '..' + '/..' * (ups - 1) + '/' + V3 + '/' + rel.replace('/', '/./'), '']
	return rng.sample(texts, rng.randint(3, len(texts)))


def random_moves(rng, rels):
	roll = rng.random()
	if roll < 0.3:
		return rv.BY_THE_TEXT
	if roll < 0.4:
		return rv.VersionMoves(moves=[], usable=False, why='cut short', key=(f'/k{rng.randint(0, 3)}', '/m'))
	moves = [(rng.choice(rels), rng.choice(rels), False) for _ in range(rng.randint(0, 3))]
	if rng.random() < 0.3:
		folder = rng.choice(rels).rpartition('/')[0]
		if folder:
			moves.append((folder + '/', rng.choice(['z/', 'a/', folder + 'x/']), True))
	if rng.random() < 0.2:
		moves.append((None, rng.choice(rels), False))
	if roll < 0.7:
		return rv.VersionMoves.applied(moves)
	return rv.VersionMoves(moves=moves, landed={rng.choice(rels) for _ in range(rng.randint(0, 3))} | ({'a/'} if rng.random() < 0.3 else set()))


def random_vault(rng, root):
	'''A job vault of V3 and V4 under root: (job vault, the rels of V4's links, all of their rels).'''
	job_vault = os.path.join(root, 'vault', 'job')
	v3, v4 = os.path.join(job_vault, V3), os.path.join(job_vault, V4)
	os.makedirs(v3)
	os.makedirs(v4)
	rels = []
	for _ in range(rng.randint(3, 12)):
		depth = rng.choice([0, 0, 1, 1, 2, 3])
		rels.append('/'.join(rng.choice(NAMES) for _ in range(depth + 1)))
	rels = sorted(set(rels))
	for rel in rels:
		place = os.path.join(v3, rel)
		folder = os.path.dirname(place)
		try:
			roll = rng.random()
			if roll < 0.05 and folder != v3:
				# a folder on the way that is a link, or a file
				if not os.path.lexists(folder):
					os.makedirs(os.path.dirname(folder), exist_ok=True)
					if rng.random() < 0.5:
						os.symlink(v3, folder)
					else:
						open(folder, 'w').close()
				continue
			os.makedirs(folder, exist_ok=True)
			if roll < 0.15:
				os.makedirs(place, exist_ok=True)
			elif roll < 0.85:
				with open(place, 'w') as f:
					f.write('x')
		except OSError as e:
			# a name too long, or a name taken by another kind
			assert e.errno in (errno.ENAMETOOLONG, errno.EEXIST, errno.ENOTDIR, errno.EISDIR), e
	return job_vault, rels


def test_every_link_is_told_as_the_oracle_tells_it(tmp_path, monkeypatch):
	lines = []
	monkeypatch.setattr(rv, 'backuperTeeLogToTl', lambda path, message, **kwargs: lines.append((path, str(message), tuple(sorted(kwargs.items())))))
	told = {'chain': 0, 'none': 0, 'raised': 0}
	for seed in range(SEEDS):
		rng = random.Random(seed)
		root = os.path.join(str(tmp_path), f's{seed}')
		job_vault, rels = random_vault(rng, root)
		asked = []
		for rel in rels:
			link_path = os.path.join(job_vault, rng.choice([V4] * 8 + [V3, 'current_version']), rel)
			for text in random_texts(rng, rel, rels):
				asked.append((spellings(rng, job_vault), spellings(rng, link_path), text, random_moves(rng, rels)))
		if rng.random() < 0.2:
			# a link outside the vault, and the vault at the root
			asked.append((job_vault, '/elsewhere/' + V4 + '/a', '../' + V3 + '/a', rv.BY_THE_TEXT))
			asked.append(('/', '/' + V4 + '/a', '../' + V3 + '/a', rv.BY_THE_TEXT))
		results = []
		for hop in (oracle_vault_chain_hop, rv.vault_chain_hop):
			for table in (rv.VERSION_MOVES_WARNED, rv.REAL_VAULT_FOLDERS):
				table.clear()
			del lines[:]
			results.append(([answer(hop, *args) for args in asked], list(lines)))
		assert results[1] == results[0], (seed, [(args, old, new) for args, old, new in zip(asked, results[0][0], results[1][0]) if old != new][:3])
		for result in results[0][0]:
			told['raised' if result[0] == 'raised' else 'none' if result[1] is None else 'chain'] += 1
		shutil.rmtree(root)
	assert min(told.values()) >= 100, told


def test_the_prune_with_the_new_hop_comes_out_as_with_the_old(tmp_path, monkeypatch):
	monkeypatch.setattr(rv, 'REFERENCED_COPY_CHUNK', 3)
	monkeypatch.setattr(rv, 'REFERENCED_COPY_WINDOW', 2)
	def old_prune(*args, **kwargs):
		with monkeypatch.context() as patched:
			patched.setattr(rv, 'vault_chain_hop', oracle_vault_chain_hop)
			return oracle_decrement_stepper(*args, **kwargs)
	root = str(tmp_path / 'vaults')
	for seed in range(SEEDS):
		old, _, how = test_prune_threads.run(old_prune, root, seed, monkeypatch)
		new, _, _ = test_prune_threads.run(rv.decrement_stepper, root, seed, monkeypatch)
		assert new == old, (seed, how, test_prune_threads.differences(old, new))
