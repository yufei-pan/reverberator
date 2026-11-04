'''
vault_chain_hop() as 0c4ff66 (0.51) had it, which reads every link's text by parse_chain_text(): the oracle that round
16's text rule for the plain chain link is compared with (tests/test_vault_chain_hop_oracle.py). It runs with
reverberator's globals, so a test's patches of the module and of os reach it as they reach the daemon's own.
'''
from __future__ import annotations
import types
import reverberator as rv


def vault_chain_hop(job_vault:str, link_path:str, link_text:str, moves:VersionMoves) -> 'str | None':
	'''0c4ff66's docstring holds what it does; its examples are reverberator's own.'''
	# the text rule, keeping the parse: relative, the previous version's whole name, real folders on the way
	parsed = None if os.path.isabs(link_text) else parse_chain_text(job_vault, link_text, link_path)
	if parsed is None:
		return None
	name, named_parts, ups = parsed
	vault = os.path.abspath(job_vault)
	target = os.path.join(vault, name, *named_parts)
	if not is_real_folder_under(os.path.join(vault, name), os.path.dirname(target)):
		return None
	# told before any row, so no row can make pruning rename a folder onto a link
	try:
		if stat.S_ISDIR(os.lstat(target).st_mode):
			# the daemon links files only, and makes every folder a real one
			return None
	except (FileNotFoundError, NotADirectoryError):
		# a chain link whose copy is gone is still one
		pass
	except OSError as e:
		if e.errno == errno.ENAMETOOLONG:
			# a name too long to use: the daemon reaches its copies by path, so none is behind it
			return None
		raise UncheckedVaultLink(e) from e
	except ValueError as e:
		raise UncheckedVaultLink(e) from e
	version_name, _, rel = os.path.abspath(link_path)[len(vault) + 1:].partition('/')
	named = '/'.join(named_parts)
	if named == rel and ups == rel.count('/') + 1:
		return target
	if not moves.usable:
		# a prune asks on several threads at once: one alone logs it
		if moves.key is not None and moves.key not in VERSION_MOVES_WARNED and remember_version_moves(VERSION_MOVES_WARNED, moves.key, None):
			backuperTeeLogToTl(path=moves.key[0],warning=True,message=f'Telling the moved links of {version_name} by their text alone, as its moves cannot be used: {moves.why}')
		return target
	verdict, why = moves.tells(named, rel, version_name)
	if verdict is None:
		raise UnexplainedChainLink(why, target)
	return target if verdict else None


oracle_vault_chain_hop = types.FunctionType(vault_chain_hop.__code__, rv.__dict__, 'oracle_vault_chain_hop',
	vault_chain_hop.__defaults__, vault_chain_hop.__closure__)
del vault_chain_hop
