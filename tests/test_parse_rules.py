import os
import pytest
import TSVZ
import reverberator as rv
from tests.harness import write_rule, rule_row, create_job

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
	assert got[0] == '\t'.join(rv.REVERB_RULE_TSV_HEADER)
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


def test_sample_rule_file_has_skip_column(tmp_path):
	path = tmp_path / 'sample.tsv'
	path.write_text(rv.SAMPLE_REVERB_RULE_FILE.strip() + '\n')
	first = path.read_text().splitlines()[0].split('\t')
	assert [cell.strip() for cell in first] == rv.REVERB_RULE_TSV_HEADER
	assert rv.upgrade_rule_file_header(str(path)) is False


def test_upgrade_follows_symlinked_rule_file(job, tmp_path):
	_old_rule_file(job)
	real = tmp_path / 'real.tsv'
	os.replace(job.rule_path, real)
	os.symlink(real, job.rule_path)
	assert rv.upgrade_rule_file_header(job.rule_path) is True
	assert os.path.islink(job.rule_path)
	assert real.read_text().split('\n')[0] == '\t'.join(rv.REVERB_RULE_TSV_HEADER)


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
