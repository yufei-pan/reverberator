import os
import pytest
import TSVZ
import reverberator as rv
from tests.harness import write_rule, rule_row, create_job, write_fstab

pytestmark = pytest.mark.unit


def test_parse_rules_missing_file_exits(tmp_path):
	with pytest.raises(SystemExit) as exc:
		rv.parse_rules(str(tmp_path / 'nope.tsv'))
	assert exc.value.code == rv.EXIT_ALL_STOPPED


def test_parse_rules_header_only_exits(tmp_path):
	p = tmp_path / 'empty.tsv'
	p.write_text('\t'.join(rv.REVERB_RULE_TSV_HEADER) + '\n', encoding='utf-8')
	with pytest.raises(SystemExit) as exc:
		rv.parse_rules(str(p))
	assert exc.value.code == rv.EXIT_ALL_STOPPED


def test_parse_rules_blank_only_key_exits(job):
	write_rule(job)
	lines = open(job.rule_path, encoding='utf-8').read().splitlines()
	blank = '\t'.join([''] + [job.monitor, job.vault, 'N/A', '1', '86400', 'True', 'True', '0', '0', 'N/A'])
	with open(job.rule_path, 'w', encoding='utf-8') as f:
		f.write(lines[0] + '\n' + blank + '\n')
	# TSVZ skips empty unique keys, so a blank-only file is empty after parse.
	with pytest.raises(SystemExit) as exc:
		rv.parse_rules(job.rule_path)
	assert exc.value.code == rv.EXIT_ALL_STOPPED


def test_parse_rules_empty_job_name_row_dropped_keeps_valid(job):
	write_rule(job)
	lines = open(job.rule_path, encoding='utf-8').read().splitlines()
	blank = '\t'.join([''] + [job.monitor, job.vault, 'N/A', '1', '86400', 'True', 'True', '0', '0', 'N/A'])
	with open(job.rule_path, 'w', encoding='utf-8') as f:
		f.write(lines[0] + '\n' + blank + '\n' + lines[1] + '\n')
	rules = rv.parse_rules(job.rule_path)
	assert len(rules) == 1
	assert rules[0].job_name == job.job_name


def test_parse_rules_empty_monitor_ignored(job):
	write_rule(job)
	lines = open(job.rule_path, encoding='utf-8').read().splitlines()
	cols = lines[1].split('\t')
	cols[1] = ''
	open(job.rule_path, 'w', encoding='utf-8').write(lines[0] + '\n' + '\t'.join(cols) + '\n')
	assert rv.parse_rules(job.rule_path) == []


def test_parse_rules_missing_monitor_is_kept_to_wait_for(job):
	write_rule(job)
	missing = os.path.join(job.root, 'not-mounted-yet')
	text = open(job.rule_path, encoding='utf-8').read().replace(job.monitor, missing)
	open(job.rule_path, 'w', encoding='utf-8').write(text)
	rules = rv.parse_rules(job.rule_path)
	assert [rule.mon_path for rule in rules] == [missing]


def test_parse_rules_vault_subpath_of_monitor_ignored(job):
	nested_vault = os.path.join(job.monitor, 'inside')
	os.makedirs(nested_vault, exist_ok=True)
	write_rule(job)
	text = open(job.rule_path, encoding='utf-8').read().replace(job.vault, nested_vault)
	open(job.rule_path, 'w', encoding='utf-8').write(text)
	assert rv.parse_rules(job.rule_path) == []


def test_parse_rules_slugifies_job_name_in_place(job):
	write_rule(job)
	lines = open(job.rule_path, encoding='utf-8').read().splitlines()
	cols = lines[1].split('\t')
	cols[0] = 'My Job!'
	dirty_line = '\t'.join(cols)
	open(job.rule_path, 'w', encoding='utf-8').write(lines[0] + '\n' + dirty_line + '\n')
	rules = rv.parse_rules(job.rule_path)
	assert len(rules) == 1
	assert rules[0].job_name == 'my-job'
	data_rows = open(job.rule_path, encoding='utf-8').read().splitlines()[1:]
	assert dirty_line not in data_rows
	assert len(data_rows) == 1
	assert data_rows[0].split('\t')[0] == 'my-job'


def test_parse_rules_realpath_monitor_in_place(job):
	write_rule(job)
	dirty = os.path.join(job.monitor, '..', 'monitor')
	canonical = os.path.realpath(dirty)
	assert dirty != canonical
	lines = open(job.rule_path, encoding='utf-8').read().splitlines()
	cols = lines[1].split('\t')
	cols[1] = dirty
	dirty_line = '\t'.join(cols)
	open(job.rule_path, 'w', encoding='utf-8').write(lines[0] + '\n' + dirty_line + '\n')
	rules = rv.parse_rules(job.rule_path)
	assert len(rules) == 1
	assert rules[0].mon_path == canonical
	data_rows = open(job.rule_path, encoding='utf-8').read().splitlines()[1:]
	assert dirty_line not in data_rows
	assert len(data_rows) == 1
	assert data_rows[0].split('\t')[1] == canonical


def test_parse_rules_na_signatures_unchanged(job):
	write_rule(job, mon_fs_signature='N/A', vault_fs_signature='N/A')
	rules = rv.parse_rules(job.rule_path)
	assert rules[0].mon_fs_signature == 'N/A'
	assert rules[0].vault_fs_signature == 'N/A'


def test_parse_rules_auto_fills_when_signatures_returned(job, monkeypatch):
	write_rule(job, mon_fs_signature='auto', vault_fs_signature='auto')
	monkeypatch.setattr(rv, 'get_fs_signatures', lambda path: ['fake-uuid'])
	rules = rv.parse_rules(job.rule_path)
	assert rules[0].mon_fs_signature == 'fake-uuid'
	assert rules[0].vault_fs_signature == 'fake-uuid'


def test_parse_rules_auto_keeps_auto_when_signatures_empty(job, monkeypatch):
	write_rule(job, mon_fs_signature='auto', vault_fs_signature='auto')
	monkeypatch.setattr(rv, 'get_fs_signatures', lambda path: [])
	rules = rv.parse_rules(job.rule_path)
	assert rules[0].mon_fs_signature == 'auto'
	assert rules[0].vault_fs_signature == 'auto'


def test_parse_rules_none_and_auto_defaults(job):
	write_rule(job)
	lines = open(job.rule_path, encoding='utf-8').read().splitlines()
	cols = lines[1].split('\t')
	# min, max, keep_one, only_sync, keep_n, size_limit
	cols[4] = 'none'
	cols[5] = 'auto'
	cols[6] = 'auto'
	cols[7] = 'none'
	cols[8] = 'none'
	cols[9] = 'auto'
	open(job.rule_path, 'w', encoding='utf-8').write(lines[0] + '\n' + '\t'.join(cols) + '\n')
	rules = rv.parse_rules(job.rule_path)
	assert rules[0].min_shapshot_time == '0'
	assert rules[0].max_shapshot_time == str(rv.DEFAULT_MAX_DELAY)
	assert rules[0].keep_one_complete_backup == str(rv.DEFAULT_KEEP_ONE_COMPLETE_BACKUP)
	assert rules[0].only_sync_attributes == str(rv.DEFAULT_ONLY_SYNC_ATTRIBUTES)
	assert rules[0].keep_n_versions == '0'
	assert rules[0].backup_size_limit == rv.DEFAULT_BACKUP_SIZE_LIMIT


def test_parse_rules_min_and_keep_n_auto(job):
	write_rule(job)
	lines = open(job.rule_path, encoding='utf-8').read().splitlines()
	cols = lines[1].split('\t')
	cols[4] = 'auto'
	cols[8] = 'auto'
	open(job.rule_path, 'w', encoding='utf-8').write(lines[0] + '\n' + '\t'.join(cols) + '\n')
	rules = rv.parse_rules(job.rule_path)
	assert rules[0].min_shapshot_time == str(rv.DEFAULT_SNAPSHOT_DELAY)
	assert rules[0].keep_n_versions == str(rv.DEFAULT_KEEP_N_VERSIONS)


def test_parse_rules_tsvz_defaults_fill_blank_min(job):
	write_rule(job)
	lines = open(job.rule_path, encoding='utf-8').read().splitlines()
	cols = lines[1].split('\t')
	cols[4] = ''
	defaults = [''] * len(cols)
	defaults[0] = TSVZ.DEFAULTS_INDICATOR_KEY
	defaults[4] = '60'
	with open(job.rule_path, 'w', encoding='utf-8') as f:
		f.write(lines[0] + '\n')
		f.write('\t'.join(defaults) + '\n')
		f.write('\t'.join(cols) + '\n')
	rules = rv.parse_rules(job.rule_path)
	assert len(rules) == 1
	assert rules[0].min_shapshot_time == '60'


OLD_HEADER_LINE = ('Job Name (Unique Key)\tPath Monitoring\tVault Path\tMonitoring File System Signature\t'
	'Minium snapshot interval\tMaximum snapshot interval\tKeep 1 Compelete Backup\t'
	'Only Sync Attributes (permissions) \tKeep N versions\tBackup Size Limit\tVault File System Signature')


def _old_rule_file(job, newline='\n'):
	lines = [
		OLD_HEADER_LINE,
		'# The name for the Job\t' + '\t'.join(['d'] * 10),
		'# need to be unique\t' + '\t'.join(['e'] * 10),
		'#_defaults_#\t\t/var/reverbs/\tauto\t60\t86400\tTrue\tTrue\t0\t5%,i5%\tauto',
		'\t'.join(rule_row(job)[:11]),
	]
	with open(job.rule_path, 'w', newline='') as f:
		f.write(newline.join(lines) + newline)
	return lines


@pytest.mark.parametrize('newline', ['\n', '\r\n'])
def test_parse_rules_upgrades_old_header_in_place(job, newline):
	lines = _old_rule_file(job, newline)
	assert rv.parse_rules(job.rule_path)[0].skip_list_file == ''
	got = open(job.rule_path, newline='').read().split(newline)
	assert got[0] == HEADER_12
	assert got[1] == lines[1] + '\t' + rv.SKIP_LIST_COLUMN_DESCRIPTIONS[0]
	assert got[2] == lines[2] + '\t' + rv.SKIP_LIST_COLUMN_DESCRIPTIONS[1]
	assert got[3:5] == lines[3:5] and got[5:] == ['']
	assert rv.upgrade_rule_file_header(job.rule_path) is False


def test_parse_rules_skip_list_value_survives_write_back(job):
	_old_rule_file(job)
	rv.parse_rules(job.rule_path)
	with open(job.rule_path, 'a') as f:
		f.write('\t'.join(rule_row(job, min_snapshot='auto', skip_list_file='skip.txt')) + '\n')
	assert rv.parse_rules(job.rule_path)[0].skip_list_file == 'skip.txt'
	# the auto fill above appended an updated row; reading that row back keeps the value
	assert rv.parse_rules(job.rule_path)[0].skip_list_file == 'skip.txt'


def test_parse_rules_defaults_row_fills_skip_list_and_none_opts_out(job, tmp_path):
	other = create_job(str(tmp_path / 'other'), 'other')
	rows = [
		'\t'.join(rv.REVERB_RULE_TSV_HEADER),
		'\t'.join(['#_defaults_#'] + [''] * 10 + ['shared.txt']),
		'\t'.join(rule_row(job)),
		'\t'.join(rule_row(other, skip_list_file='none')),
	]
	open(job.rule_path, 'w').write('\n'.join(rows) + '\n')
	by_name = {rule.job_name: rule for rule in rv.parse_rules(job.rule_path)}
	assert by_name[job.job_name].skip_list_file == 'shared.txt'
	assert by_name['other'].skip_list_file == 'none'


def test_resolve_skip_list_path(tmp_path):
	rule = str(tmp_path / 'rules' / 'r.tsv')
	assert rv.resolve_skip_list_path('skip.txt', rule) == str(tmp_path / 'rules' / 'skip.txt')
	assert rv.resolve_skip_list_path('../s/skip.txt', rule) == str(tmp_path / 's' / 'skip.txt')
	assert rv.resolve_skip_list_path('/etc/skip', rule) == '/etc/skip'
	for cell in ('', '  ', 'auto', 'none', 'None ', 'AUTO'):
		assert rv.resolve_skip_list_path(cell, rule) is None


def test_sample_rule_file_has_all_14_columns(tmp_path):
	path = tmp_path / 'sample.tsv'
	path.write_text(rv.SAMPLE_REVERB_RULE_FILE.strip() + '\n')
	lines = path.read_text().splitlines()
	assert [cell.strip() for cell in lines[0].split('\t')] == rv.REVERB_RULE_TSV_HEADER
	assert [len(line.split('\t')) for line in lines[1:3]] == [14, 14]
	assert rv.upgrade_rule_file_header(str(path)) is False


def test_upgrade_follows_symlinked_rule_file(job, tmp_path):
	_old_rule_file(job)
	real = tmp_path / 'real.tsv'
	os.replace(job.rule_path, real)
	os.symlink(real, job.rule_path)
	assert rv.upgrade_rule_file_header(job.rule_path) is True
	assert os.path.islink(job.rule_path)
	assert real.read_text().split('\n')[0] == HEADER_12


def test_parse_rules_survives_failed_header_upgrade(job, monkeypatch):
	_old_rule_file(job)
	before = open(job.rule_path, newline='').read()
	def deny(*args, **kwargs):
		raise PermissionError('read-only')
	monkeypatch.setattr(rv.tempfile, 'mkstemp', deny)
	rules = rv.parse_rules(job.rule_path)
	assert [rule.job_name for rule in rules] == [job.job_name]
	assert open(job.rule_path, newline='').read() == before


@pytest.mark.parametrize('kind', ['non_utf8_comment', 'gzip'])
def test_parse_rules_survives_rule_file_it_cannot_decode(job, capsys, kind):
	# TSVZ reads these, but the header upgrade reads the file as UTF-8 text
	lines = _old_rule_file(job)
	if kind == 'gzip':
		import gzip
		rule_path = job.rule_path + '.gz'
		with gzip.open(rule_path, 'wb') as f:
			f.write(('\n'.join(lines) + '\n').encode())
		os.remove(job.rule_path)
	else:
		rule_path = job.rule_path
		with open(rule_path, 'wb') as f:
			f.write(('\n'.join(lines[:3]) + '\n').encode() + b'# caf\xe9\n' + ('\n'.join(lines[3:]) + '\n').encode())
	before = open(rule_path, 'rb').read()
	rules = rv.parse_rules(rule_path)
	assert [rule.job_name for rule in rules] == [job.job_name]
	assert open(rule_path, 'rb').read() == before
	assert 'Cannot upgrade rule file' in capsys.readouterr().out


def test_parse_rules_write_back_rewrites_the_row_in_place(job):
	write_rule(job, min_snapshot='auto')
	before = open(job.rule_path).read().splitlines()
	rv.parse_rules(job.rule_path)
	rv.parse_rules(job.rule_path)
	after = open(job.rule_path).read().splitlines()
	assert len(after) == len(before)
	assert after[1].split('\t')[4] == str(rv.DEFAULT_SNAPSHOT_DELAY)


def test_parse_rules_drops_old_appended_copies(job):
	write_rule(job)
	with open(job.rule_path, 'a') as f:
		f.write('\t'.join(rule_row(job, min_snapshot='auto')) + '\n')
	rv.parse_rules(job.rule_path)
	rows = [line for line in open(job.rule_path).read().splitlines() if line.startswith(job.job_name + '\t')]
	assert len(rows) == 1


def test_parse_rules_slugified_name_does_not_spawn_a_second_job(job):
	row = rule_row(job)
	row[0] = 'My Job'
	open(job.rule_path, 'w').write('\t'.join(rv.REVERB_RULE_TSV_HEADER) + '\n' + '\t'.join(row) + '\n')
	assert [rule.job_name for rule in rv.parse_rules(job.rule_path)] == ['my-job']
	assert [rule.job_name for rule in rv.parse_rules(job.rule_path)] == ['my-job']
	assert 'My Job' not in open(job.rule_path).read()


def test_parse_rules_never_rewrites_a_row_whose_name_collides(job):
	twin = rule_row(job, min_snapshot='auto')
	twin[0] = 'JOB'
	write_rule(job, min_snapshot='auto', extra_rows=[twin])
	before = open(job.rule_path).read()
	assert len(rv.parse_rules(job.rule_path)) == 2
	assert open(job.rule_path).read() == before


def test_rewrite_rule_rows_keeps_other_lines_byte_for_byte(tmp_path):
	path = tmp_path / 'rule.tsv'
	path.write_bytes(b'head\tx\r\n# comment\t\r\nA\t1\r\n\r\nB\t2\r\nA\t3\r\nlast\t9')
	rv.rewrite_rule_rows(str(path), {'A': ['a', '7']})
	assert path.read_bytes() == b'head\tx\r\n# comment\t\r\n\r\nB\t2\r\na\t7\r\nlast\t9'


def test_parse_rules_missing_file_leaves_a_marker_line(tmp_path, capsys):
	with pytest.raises(SystemExit) as exc:
		rv.parse_rules(str(tmp_path / 'nope.tsv'))
	assert exc.value.code == rv.EXIT_ALL_STOPPED
	captured = capsys.readouterr()
	assert 'reverberator EXITING with error: rule file' in captured.out + captured.err


HEADER_12 = '\t'.join(rv.REVERB_RULE_TSV_HEADER[:12])
HEADER_14 = '\t'.join(rv.REVERB_RULE_TSV_HEADER)


def _rule_file(job, header, *rows):
	with open(job.rule_path, 'w', newline='') as f:
		f.write('\n'.join([header] + [row if isinstance(row, str) else '\t'.join(row) for row in rows]) + '\n')


def test_a_12_column_rule_file_is_read_as_it_is(job, capsys):
	_rule_file(job, HEADER_12, rule_row(job))
	before = open(job.rule_path, newline='').read()
	rule, = rv.parse_rules(job.rule_path)
	assert (rule.full_comparison_interval, rule.chain_length) == ('', '')
	assert open(job.rule_path, newline='').read() == before
	# the file's own header was passed, so TSVZ found no mismatch
	assert 'Header mismatch' not in capsys.readouterr().out


def test_new_cells_under_a_12_column_header_are_read(job):
	_rule_file(job, HEADER_12, rule_row(job) + ['12h', '20'])
	rule, = rv.parse_rules(job.rule_path)
	assert (rule.full_comparison_interval, rule.chain_length) == ('12h', '20')


@pytest.mark.parametrize('header', [HEADER_12, HEADER_14])
def test_rows_with_trailing_tabs_or_fewer_cells_are_read(job, tmp_path, header):
	other = create_job(str(tmp_path / 'other'), 'other')
	_rule_file(job, header, '\t'.join(rule_row(job) + ['1d', '', '', '']), '\t'.join(rule_row(other)[:11]))
	by_name = {rule.job_name: rule for rule in rv.parse_rules(job.rule_path)}
	assert (by_name[job.job_name].full_comparison_interval, by_name[job.job_name].chain_length) == ('1d', '')
	assert (by_name['other'].full_comparison_interval, by_name['other'].chain_length) == ('', '')


def test_a_defaults_row_of_11_cells_still_fills_and_leaves_the_new_fields_blank(job):
	_rule_file(job, HEADER_12, '#_defaults_#\t\t/var/reverbs/\tauto\t60\t86400\tTrue\tTrue\t0\t5%,i5%\tauto',
		rule_row(job, min_snapshot=''))
	rule, = rv.parse_rules(job.rule_path)
	assert rule.min_shapshot_time == '60' and (rule.full_comparison_interval, rule.chain_length) == ('', '')


def test_a_defaults_row_can_set_the_new_columns(job):
	_rule_file(job, HEADER_14, '\t'.join(['#_defaults_#'] + [''] * 11 + ['1d', '20']), rule_row(job))
	rule, = rv.parse_rules(job.rule_path)
	assert (rule.full_comparison_interval, rule.chain_length) == ('1d', '20')


@pytest.mark.parametrize('extra', [[], ['12h']])
def test_a_row_written_back_keeps_its_cell_count(job, extra):
	_rule_file(job, HEADER_12, rule_row(job, min_snapshot='auto') + extra)
	rv.parse_rules(job.rule_path)
	row = open(job.rule_path).read().splitlines()[1].split('\t')
	assert len(row) == 12 + len(extra) and row[4] == str(rv.DEFAULT_SNAPSHOT_DELAY) and row[12:] == extra


def test_rule_file_header_is_the_files_own_prefix_of_12_or_more(job):
	for n in (12, 13, 14):
		_rule_file(job, '\t'.join(rv.REVERB_RULE_TSV_HEADER[:n]), rule_row(job))
		assert rv.rule_file_header(job.rule_path) == rv.REVERB_RULE_TSV_HEADER[:n]
	# a cell with trailing blanks still holds its name, as TSVZ judges it
	_rule_file(job, HEADER_12 + ' ', rule_row(job))
	assert rv.rule_file_header(job.rule_path) == rv.REVERB_RULE_TSV_HEADER[:12]


def test_rule_file_header_is_the_whole_header_when_the_file_has_no_known_prefix(job, tmp_path):
	_rule_file(job, '\t'.join(rv.REVERB_RULE_TSV_HEADER[:11]), rule_row(job))
	assert rv.rule_file_header(job.rule_path) == rv.REVERB_RULE_TSV_HEADER
	_rule_file(job, '\t'.join(['x'] * 12), rule_row(job))
	assert rv.rule_file_header(job.rule_path) == rv.REVERB_RULE_TSV_HEADER
	assert rv.rule_file_header(str(tmp_path / 'missing.tsv')) == rv.REVERB_RULE_TSV_HEADER


@pytest.mark.parametrize('text, seconds', [('1d', 86400), ('1h30m', 5400), ('90', 90), ('1.5h', 5400), (' 2m 5S ', 125),
	('1w', 604800), ('2 weeks', 1209600), ('30min', 1800), ('2 hours', 7200), ('1 day', 86400), ('5sec', 5), ('1hr', 3600),
	('1H30Min', 5400), ('1 h 30 min', 5400), ('3 DAYS', 259200), ('1 minute 1 second', 61), ('2hrs', 7200), ('4 mins', 240)])
def test_parse_duration(text, seconds):
	assert rv.parse_duration(text) == seconds


@pytest.mark.parametrize('text', ['', ' ', '-5', '+5', 'h', '12hh', '1d-2h', 'soon', '1e3', '1M', '1h30M', '1 30m', '1\u00a02h',
	'1 5', '1d 2', '1hm', '9' * 400 + 'd', '9' * 400, '1 w d'])
def test_parse_duration_rejects(text):
	with pytest.raises(ValueError):
		rv.parse_duration(text)


@pytest.mark.parametrize('cell, seconds', [('', 0), ('0', 0), (' none ', 0), ('OFF', 0), ('auto', 0), ('1d', 86400),
	('12h', 43200), ('30m', 1800), ('45s', 45), ('1w', 604800), ('2 hours', 7200), (' 1D ', 86400), ('90', 90), ('1h 30m', 5400), ('1.5h', 5400)])
def test_full_comparison_interval_cells(cell, seconds, capsys):
	assert rv.read_full_comparison_interval(cell, 'j') == seconds
	assert 'Full Comparison Interval' not in capsys.readouterr().out


@pytest.mark.parametrize('cell', ['1M', 'soon', '-5', '12hh', 'h', '1d-2h', '1 30m'])
def test_a_bad_full_comparison_interval_is_off_with_an_error(cell, capsys):
	assert rv.read_full_comparison_interval(cell, 'j') == 0
	out = capsys.readouterr().out
	assert 'Full Comparison Interval' in out and '1d, 12h, 30m or 45s' in out


@pytest.mark.parametrize('cell, links, error', [('', 40, False), ('auto', 40, False), ('40', 40, False), (' 20 ', 20, False),
	('0', 0, False), ('00', 0, False), (' 00 ', 0, False), ('-0', 0, False), ('None', 0, False), ('3', 3, False), ('2', 3, True), ('1', 3, True), ('-4', 3, True), ('x', 40, True),
	('20.5', 40, True)])
def test_chain_length_cells(cell, links, error, capsys):
	assert rv.read_chain_length(cell, 'j') == links
	assert ('Chain Length' in capsys.readouterr().out) == error


def _defaults_file(job, header, defaults, *rows):
	_rule_file(job, header, '\t'.join(defaults), *rows)


def test_a_row_written_back_never_writes_the_defaults_rows_new_columns(job):
	_defaults_file(job, HEADER_14, ['#_defaults_#'] + [''] * 11 + ['1d', '20'], rule_row(job, min_snapshot='auto'))
	rule, = rv.parse_rules(job.rule_path)
	assert (rule.full_comparison_interval, rule.chain_length) == ('1d', '20')
	row = open(job.rule_path).read().splitlines()[2].split('\t')
	assert row[4] == str(rv.DEFAULT_SNAPSHOT_DELAY) and len(row) == 12
	# the defaults row changes, and the job follows it
	_defaults_file(job, HEADER_14, ['#_defaults_#'] + [''] * 11 + ['2d', '30'], *open(job.rule_path).read().splitlines()[2:])
	rule, = rv.parse_rules(job.rule_path)
	assert (rule.full_comparison_interval, rule.chain_length) == ('2d', '30')


def test_a_row_written_back_gets_the_defaults_rows_vault_path_and_signature_together(job):
	row = rule_row(job, min_snapshot='auto', vault_fs_signature='')
	row[2] = ''
	_defaults_file(job, HEADER_12, ['#_defaults_#', '', job.vault] + [''] * 7 + ['auto'], '\t'.join(row))
	rule, = rv.parse_rules(job.rule_path)
	written = open(job.rule_path).read().splitlines()[2].split('\t')
	assert rule.vault_path == job.vault and len(written) == 12
	assert written[2] == job.vault and written[10] == rule.vault_fs_signature != ''
	assert written[4] == str(rv.DEFAULT_SNAPSHOT_DELAY)


def test_a_stub_line_whose_name_differs_by_a_leading_space_does_not_cost_the_job_its_row(job):
	_rule_file(job, HEADER_12, rule_row(job, min_snapshot='auto'), ' ' + job.job_name + '\t' * 9 + 'note')
	first, = rv.parse_rules(job.rule_path)
	lines = open(job.rule_path).read().splitlines()
	assert lines[1].split('\t')[:3] == [job.job_name, job.monitor, job.vault] and lines[2].endswith('\tnote')
	again, = rv.parse_rules(job.rule_path)
	assert again == first


def test_a_valid_leading_space_row_is_not_overwritten_by_a_later_stub_line(job):
	row = rule_row(job, min_snapshot='auto')
	row[0] = ' ' + job.job_name
	_rule_file(job, HEADER_12, row, job.job_name + '\t' * 9 + 'note')
	rules = rv.parse_rules(job.rule_path)
	lines = open(job.rule_path).read().splitlines()
	assert [rule.job_name for rule in rules] == [job.job_name]
	# the cleaned name is not written over the cell: the stub line already carries it
	assert lines[1].split('\t')[:3] == [' ' + job.job_name, job.monitor, job.vault] and lines[2].endswith('\tnote')
	assert lines[1].split('\t')[4] == str(rv.DEFAULT_SNAPSHOT_DELAY)
	again = rv.parse_rules(job.rule_path)
	assert again == rules


def test_a_row_longer_than_14_cells_keeps_its_extra_cells_when_written_back(job):
	_rule_file(job, HEADER_14, rule_row(job, min_snapshot='auto') + ['', '', 'note one', 'note two'])
	rv.parse_rules(job.rule_path)
	row = open(job.rule_path).read().splitlines()[1].split('\t')
	assert len(row) == 16 and row[4] == str(rv.DEFAULT_SNAPSHOT_DELAY) and row[14:] == ['note one', 'note two']


def test_a_job_name_written_with_a_leading_space_is_matched_when_written_back(job, capsys):
	row = rule_row(job, min_snapshot='auto')
	row[0] = ' ' + row[0]
	_rule_file(job, HEADER_12, row)
	rv.parse_rules(job.rule_path)
	written = open(job.rule_path).read().splitlines()[1].split('\t')
	assert written[0] == job.job_name and written[4] == str(rv.DEFAULT_SNAPSHOT_DELAY)
	capsys.readouterr()
	rv.parse_rules(job.rule_path)
	assert 'dirty Job Name' not in capsys.readouterr().out


def _asking(monkeypatch):
	asked = []
	monkeypatch.setattr(rv, 'get_fs_signatures', lambda path: asked.append(path) or ['fake-uuid'])
	return asked


@pytest.mark.parametrize('where', ['missing', 'under a file'])
def test_parse_rules_makes_no_vault_path_and_keeps_its_signature_auto(job, monkeypatch, where):
	if where == 'under a file':
		open(os.path.join(job.root, 'blocker'), 'w').write('x')
		vault = os.path.join(job.root, 'blocker', 'vault')
	else:
		vault = os.path.join(job.root, 'pool', 'reverbs')
	row = rule_row(job, min_snapshot='auto', vault_fs_signature='auto')
	row[2] = vault
	with open(job.rule_path, 'w') as f:
		f.write('\t'.join(rv.REVERB_RULE_TSV_HEADER) + '\n' + '\t'.join(row) + '\n')
	asked = _asking(monkeypatch)
	rule, = rv.parse_rules(job.rule_path)
	written = open(job.rule_path).read().splitlines()[1].split('\t')
	assert rule.vault_fs_signature == 'auto' and vault not in asked and not os.path.lexists(vault)
	# the row is still written back for the cells filled
	assert written[4] == str(rv.DEFAULT_SNAPSHOT_DELAY) and written[10] == 'auto'


def test_parse_rules_fills_the_vault_signature_only_once_its_fstab_mount_is_mounted(job, fake_pool, monkeypatch):
	write_fstab(job.vault)
	write_rule(job, vault_fs_signature='auto')
	asked = _asking(monkeypatch)
	rule, = rv.parse_rules(job.rule_path)
	assert rule.vault_fs_signature == 'auto' and job.vault not in asked
	fake_pool.add_mount(job.vault)
	rule, = rv.parse_rules(job.rule_path)
	assert rule.vault_fs_signature == 'fake-uuid'


def test_parse_rules_fills_no_vault_signature_on_a_pool_missing_a_disk(job, fake_pool, monkeypatch):
	a, _ = fake_pool.add(job.vault, ['a', 'b'])
	fake_pool.drop(a)
	write_rule(job, vault_fs_signature='auto')
	asked = _asking(monkeypatch)
	rule, = rv.parse_rules(job.rule_path)
	assert rule.vault_fs_signature == 'auto' and job.vault not in asked


def _write_auto_monitor(job, monitor):
	row = rule_row(job, mon_fs_signature='auto')
	row[1] = monitor
	with open(job.rule_path, 'w') as f:
		f.write('\t'.join(rv.REVERB_RULE_TSV_HEADER) + '\n' + '\t'.join(row) + '\n')


def test_parse_rules_fills_the_monitoring_signature_only_once_its_fstab_mount_is_mounted(job, fake_pool, monkeypatch, capsys):
	# a bare folder under an unmounted mount point is the root disk's: its signature would never match the disk
	write_fstab(job.monitor)
	write_rule(job, mon_fs_signature='auto')
	asked = _asking(monkeypatch)
	capsys.readouterr()
	rule, = rv.parse_rules(job.rule_path)
	out = capsys.readouterr()
	text = out.out + out.err
	assert rule.mon_fs_signature == 'auto' and job.monitor not in asked
	assert open(job.rule_path).read().splitlines()[1].split('\t')[3] == 'auto'
	assert text.count(f'Path Monitoring {job.monitor} which is on a disk that is not there') == 1
	fake_pool.add_mount(job.monitor)
	rule, = rv.parse_rules(job.rule_path)
	assert rule.mon_fs_signature == 'fake-uuid'


def test_parse_rules_fills_no_monitoring_signature_on_a_pool_missing_a_disk(job, fake_pool, monkeypatch):
	a, _ = fake_pool.add(job.monitor, ['a', 'b'])
	fake_pool.drop(a)
	write_rule(job, mon_fs_signature='auto')
	asked = _asking(monkeypatch)
	rule, = rv.parse_rules(job.rule_path)
	assert rule.mon_fs_signature == 'auto' and job.monitor not in asked


def test_parse_rules_keeps_a_file_monitored_path_auto_and_says_the_job_waits(job, monkeypatch, capsys):
	monitor = os.path.join(job.root, 'a_file')
	open(monitor, 'w').write('x')
	_write_auto_monitor(job, monitor)
	asked = _asking(monkeypatch)
	capsys.readouterr()
	rule, = rv.parse_rules(job.rule_path)
	out = capsys.readouterr()
	assert rule.mon_fs_signature == 'auto' and monitor not in asked
	text = out.out + out.err
	assert 'which is not a folder' in text and 'a folder is there, which the job waits for' in text


def test_parse_rules_vault_file_warning_promises_no_folder_made(job, monkeypatch, capsys):
	vault = os.path.join(job.root, 'a_file')
	open(vault, 'w').write('x')
	row = rule_row(job, vault_fs_signature='auto')
	row[2] = vault
	with open(job.rule_path, 'w') as f:
		f.write('\t'.join(rv.REVERB_RULE_TSV_HEADER) + '\n' + '\t'.join(row) + '\n')
	_asking(monkeypatch)
	capsys.readouterr()
	rv.parse_rules(job.rule_path)
	out = capsys.readouterr()
	text = out.out + out.err
	assert f'Vault Path {vault} which is not a folder' in text and 'a folder is there, which the job waits for' in text
	assert 'has made the folder' not in text
