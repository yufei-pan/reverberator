'''
Hand-written vaults of design R, for the read edge cases no batch makes: a version is written entry by entry, and a forward
link's text comes from the oracle's own forward_text(), so a wrong rule in the daemon cannot hide here. Any vault a batch can
make comes from harness.run_backup instead.
'''
import os
from collections import namedtuple

import reverberator as rv
from tests.vault_oracle import forward_text

STAMP = '2030-01-01_00-00-00_+0000'
# the forward link at an entry's path, to the version after the one written
FORWARD = object()
# a link with this text: a user's, whatever it looks like
Link = namedtuple('Link', ['text'])


def version_name(number: int) -> str:
	return f'V{number}--{STAMP}'


def write_version(job_vault: str, number: int, entries: dict) -> str:
	'''
	The folder of version number holding entries, in their order, and its path: {rel: what}, what being a file's text, FORWARD
	or a Link. A rel ending with / is a real folder, what is None; the folders above an entry are made real too.
	'''
	top = os.path.join(job_vault, version_name(number))
	os.makedirs(top, exist_ok=True)
	for rel, what in entries.items():
		path = os.path.join(top, rel)
		os.makedirs(os.path.dirname(path), exist_ok=True)
		if rel.endswith('/'):
			os.makedirs(path, exist_ok=True)
		elif what is FORWARD:
			os.symlink(forward_text(rel, version_name(number + 1)), path)
		elif isinstance(what, Link):
			os.symlink(what.text, path)
		else:
			with open(path, 'w') as f:
				f.write(what)
	return top


def forward_chain(job_vault: str, first: int, last: int, entries: dict) -> str:
	'''Versions first to last - 1 forwarding every top entry of entries, and version last holding entries; the path of version first.'''
	tops = {rel.partition('/')[0]: FORWARD for rel in entries}
	for number in range(first, last):
		write_version(job_vault, number, tops)
	write_version(job_vault, last, entries)
	return os.path.join(job_vault, version_name(first))


def record_layout(job_vault: str, layout: str) -> None:
	'''The manifest of job_vault, made when there is none, recording layout.'''
	manifest = rv.VaultManifest(job_vault)
	manifest.set_layout(layout)
	manifest.commit()
	manifest.close()
