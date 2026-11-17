'''
The collection check of tests/conftest.py: every collected test carries one of the four layer markers (the full-test-suite
spec's unit, inotify, process and privileged), and only one, so `pytest -m unit` runs every unit test and no other.
reverberator.py's doctests need none.
'''
from types import SimpleNamespace

import pytest

from tests.conftest import LAYERS, multi_layer_tests, pytest_collection_modifyitems, unmarked_tests

pytestmark = pytest.mark.unit


def stand_in(nodeid:str, *markers:str) -> SimpleNamespace:
	'''A collected item as the checks read it: its node id, the closest marker of a name or None, and every marker of the chain
	(a name given twice is a module's mark and the test's own).'''
	return SimpleNamespace(nodeid=nodeid, get_closest_marker=lambda name: SimpleNamespace(name=name) if name in markers else None,
		iter_markers=lambda: iter([SimpleNamespace(name=name) for name in markers]))


def hook_reports(*items) -> list:
	'''What pytest_collection_modifyitems() hands the config's collect-report hook for these items, in order.'''
	reports = []
	config = SimpleNamespace(hook=SimpleNamespace(pytest_collectreport=lambda report: reports.append(report)))
	pytest_collection_modifyitems(config, list(items))
	return reports


class UnmarkedDoctest(pytest.DoctestItem):
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


def test_a_test_with_two_layers_is_named_and_one_layer_given_twice_is_not():
	one = stand_in('tests/test_a.py::test_one', 'unit', 'parametrize')
	twice = stand_in('tests/test_a.py::test_twice', 'unit', 'unit')
	two = stand_in('tests/test_a.py::test_two', 'unit', 'privileged')
	three = stand_in('tests/test_a.py::test_three', 'process', 'inotify', 'unit')
	bare = stand_in('tests/test_a.py::test_bare')
	assert multi_layer_tests([one, twice, two, three, bare]) == [two.nodeid, three.nodeid]


def test_the_hook_reports_each_module_with_an_unmarked_test_once_with_its_tests():
	items = [stand_in('tests/test_a.py::test_ok', 'unit'), stand_in('tests/test_a.py::test_bare'),
		stand_in('tests/test_b.py::test_ok', 'privileged'), stand_in('tests/test_c.py::test_bare'),
		stand_in('tests/test_a.py::test_bare_too')]
	reports = hook_reports(*items)
	assert [(report.nodeid, report.outcome, report.when) for report in reports] == [
		('tests/test_a.py', 'failed', 'collect'), ('tests/test_c.py', 'failed', 'collect')]
	assert reports[0].longrepr == ('tests with no layer marker (unit, inotify, process, privileged): '
		'tests/test_a.py::test_bare, tests/test_a.py::test_bare_too')
	assert reports[1].longrepr == 'tests with no layer marker (unit, inotify, process, privileged): tests/test_c.py::test_bare'


def test_the_hook_reports_each_module_with_a_two_layer_test_once_with_its_tests():
	items = [stand_in('tests/test_a.py::test_ok', 'unit'), stand_in('tests/test_a.py::test_two', 'unit', 'privileged'),
		stand_in('tests/test_b.py::test_twice', 'unit', 'unit'), stand_in('tests/test_c.py::test_two', 'privileged', 'process'),
		stand_in('tests/test_c.py::test_two_too', 'unit', 'process')]
	reports = hook_reports(*items)
	assert [(report.nodeid, report.outcome, report.when) for report in reports] == [
		('tests/test_a.py', 'failed', 'collect'), ('tests/test_c.py', 'failed', 'collect')]
	assert reports[0].longrepr == ('tests with more than one layer marker (unit, inotify, process, privileged): '
		'tests/test_a.py::test_two')
	assert reports[1].longrepr == ('tests with more than one layer marker (unit, inotify, process, privileged): '
		'tests/test_c.py::test_two, tests/test_c.py::test_two_too')


def test_the_hook_reports_nothing_when_every_test_has_one_layer():
	items = [stand_in('tests/test_a.py::test_ok', 'unit'), stand_in('tests/test_a.py::test_p', 'privileged', 'on_054'),
		stand_in('tests/test_b.py::test_ok', 'unit', 'parametrize')]
	assert hook_reports(*items) == []


def test_a_module_with_both_kinds_of_fault_gets_a_report_of_each_kind():
	items = [stand_in('tests/test_a.py::test_bare'), stand_in('tests/test_a.py::test_two', 'unit', 'process')]
	reports = hook_reports(*items)
	assert [report.longrepr.split(' (')[0] for report in reports] == [
		'tests with no layer marker', 'tests with more than one layer marker']
