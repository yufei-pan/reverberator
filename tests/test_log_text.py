import os
import re
import pytest
import reverberator as rv

pytestmark = pytest.mark.unit

FORGED = 'reverberator job x FAILED: y'
BAD_NAME = 'a\udcff\x1b[31m'


def firewatcher_patterns():
	path = os.path.join(os.path.dirname(rv.__file__), 'firewatcher', 'reverberator.regex')
	return [re.compile(line.strip()) for line in open(path) if line.strip()]


def alerting_lines(output):
	# as firewatcher reads the journal: each line is searched for the patterns, behind the journal's own prefix
	return [line for line in output.split('\n') if any(p.search(f'Oct 18 12:00:00 ksxx python[1]: {line}') for p in firewatcher_patterns())]


def test_marker_with_a_bad_name_is_one_line(capsys):
	line = rv.job_log('j', f'UNREADABLE: /m/a\n{FORGED}; keeping \udcff\x1b[31m')
	assert '\n' not in line and '\x1b' not in line
	out = capsys.readouterr().out
	assert len([l for l in out.split('\n') if l]) == 1
	assert len(alerting_lines(out)) == 1


def test_a_real_marker_still_matches_the_firewatcher_patterns(capsys):
	rv.job_log('j', 'FAILED: disk gone; retrying in 60s')
	rv.job_log('j', 'UNREADABLE: /m/café: [Errno 5] Input/output error')
	rv.job_log('j', 'STOPPED: bad pattern')
	rv.daemon_error_log('every job is stopped')
	assert len(alerting_lines(capsys.readouterr().out)) == 4


@pytest.mark.parametrize('log', [rv.backuperTeeLogToTl, rv.watcherTeeLogToTl])
def test_a_traceback_with_a_bad_name_cannot_start_a_line(capsys, log):
	log(f'/m/{BAD_NAME}\n{FORGED}', f'Traceback\n  File "/m/b\nreverberator EXITING with error: z", line 1\n{FORGED}', error=True)
	out = capsys.readouterr().out
	assert alerting_lines(out) == []
	assert '    ' + FORGED in out


@pytest.mark.parametrize('debug', [False, True])
@pytest.mark.parametrize('kind', ['error', 'ok', 'plain'])
@pytest.mark.parametrize('log', [rv.backuperTeeLogToTl, rv.watcherTeeLogToTl])
def test_logging_a_surrogate_name_does_not_raise(capsys, monkeypatch, log, kind, debug):
	monkeypatch.setattr(rv, 'DEBUG', debug)
	log(f'/m/{BAD_NAME}', f'Could not read /m/{BAD_NAME}', **{'error': kind == 'error', 'ok': kind == 'ok'})
	out = capsys.readouterr().out
	# without debug a plain line goes to the log file only
	if kind != 'plain' or debug:
		assert '\\xff\\x1b[31m' in out and '\x1b[31m' not in out.replace('\x1b[0m', '')


def test_a_name_with_an_escape_character_is_logged_escaped(capsys):
	rv.backuperTeeLogToTl('/m/e\x1b[31mred', 'Not copying /m/e\x1b[31mred', error=True)
	out = capsys.readouterr().out
	assert '/m/e\\x1b[31mred' in out
	assert '\x1b[31mred' not in out


def test_direct_log_calls_are_escaped(capsys):
	rv.tl.teeerror(rv.log_text(f'Cannot write status files in /m/{BAD_NAME}'))
	assert '\\xff' in capsys.readouterr().out


def test_log_text_keeps_line_structure():
	assert rv.log_text('a\nb\n') == 'a\n    b\n    '
	assert rv.log_text('café') == 'café'


def test_a_carriage_return_in_a_name_cannot_start_a_line(capsys):
	rv.backuperTeeLogToTl('/m/a\r' + FORGED, 'Not copying /m/a\r' + FORGED, error=True)
	rv.job_log('j', f'UNREADABLE: /m/a\r{FORGED}: gone')
	out = capsys.readouterr().out
	assert '\r' not in out
	assert len(alerting_lines(out)) == 1
