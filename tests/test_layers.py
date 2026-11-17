'''
The collection check of tests/conftest.py: every collected test carries one of the four layer markers (the full-test-suite
spec's unit, inotify, process and privileged), so `pytest -m unit` runs every unit test. reverberator.py's doctests need none.
'''
from types import SimpleNamespace

import pytest
from _pytest.doctest import DoctestItem

from tests.conftest import LAYERS, unmarked_tests

pytestmark = pytest.mark.unit


def stand_in(nodeid:str, *markers:str) -> SimpleNamespace:
	'''A collected item as the check reads it: its node id, and the closest marker of a name, or None.'''
	return SimpleNamespace(nodeid=nodeid, get_closest_marker=lambda name: SimpleNamespace(name=name) if name in markers else None)


class UnmarkedDoctest(DoctestItem):
	'''A doctest that would be named if it were not one: it answers no marker.'''
	nodeid = 'reverberator.py::reverberator.slugify'

	def get_closest_marker(self, name):
		return None


def test_a_test_with_no_layer_marker_is_named():
	marked = stand_in('tests/test_a.py::test_marked', 'unit')
	bare = stand_in('tests/test_a.py::test_bare')
	assert unmarked_tests([marked, bare]) == [bare.nodeid]


def test_each_layer_counts_and_another_marker_does_not():
	marked = [stand_in(f'tests/test_a.py::test_{layer}', layer) for layer in LAYERS]
	other = stand_in('tests/test_a.py::test_on_054', 'on_054', 'parametrize')
	assert LAYERS == ('unit', 'inotify', 'process', 'privileged')
	assert unmarked_tests(marked + [other]) == [other.nodeid]


def test_doctests_need_no_marker():
	# made without its constructor, which pytest keeps for collection
	doctest_item = object.__new__(UnmarkedDoctest)
	assert unmarked_tests([doctest_item]) == []
