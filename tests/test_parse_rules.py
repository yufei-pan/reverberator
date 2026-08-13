import os
import pytest
import reverberator as rv
from tests.harness import write_rule

pytestmark = pytest.mark.unit


def test_parse_rules_missing_file_exits(tmp_path):
	with pytest.raises(SystemExit) as exc:
		rv.parse_rules(str(tmp_path / 'nope.tsv'))
	assert exc.value.code == 1


def test_parse_rules_header_only_exits(tmp_path):
	p = tmp_path / 'empty.tsv'
	p.write_text('\t'.join(rv.REVERB_RULE_TSV_HEADER) + '\n', encoding='utf-8')
	with pytest.raises(SystemExit) as exc:
		rv.parse_rules(str(p))
	assert exc.value.code == 1


def test_parse_rules_empty_job_name_ignored(job):
	write_rule(job)
	lines = open(job.rule_path, encoding='utf-8').read().splitlines()
	blank = '\t'.join([''] + [job.monitor, job.vault, 'N/A', '1', '86400', 'True', 'True', '0', '0', 'N/A'])
	with open(job.rule_path, 'w', encoding='utf-8') as f:
		f.write(lines[0] + '\n' + blank + '\n')
	# TSVZ.readTabularFile skips rows with an empty unique key, so parse_rules
	# sees no rules and sys.exit(1) (same as header-only). The in-loop empty
	# job_name continue is not reachable through TSVZ for a blank first column.
	with pytest.raises(SystemExit) as exc:
		rv.parse_rules(job.rule_path)
	assert exc.value.code == 1


def test_parse_rules_missing_monitor_ignored(job):
	write_rule(job)
	text = open(job.rule_path, encoding='utf-8').read().replace(job.monitor, str(os.path.join(job.root, 'does-not-exist')))
	open(job.rule_path, 'w', encoding='utf-8').write(text)
	assert rv.parse_rules(job.rule_path) == []


def test_parse_rules_vault_subpath_of_monitor_ignored(job):
	nested_vault = os.path.join(job.monitor, 'inside')
	os.makedirs(nested_vault, exist_ok=True)
	write_rule(job)
	text = open(job.rule_path, encoding='utf-8').read().replace(job.vault, nested_vault)
	open(job.rule_path, 'w', encoding='utf-8').write(text)
	assert rv.parse_rules(job.rule_path) == []


def test_parse_rules_slugifies_job_name_and_appends(job):
	write_rule(job)
	text = open(job.rule_path, encoding='utf-8').read().replace('\tjob\t', '\tMy Job!\t', 1)
	# header uses "Job Name" not the value; replace the data-row job name:
	lines = open(job.rule_path, encoding='utf-8').read().splitlines()
	cols = lines[1].split('\t')
	cols[0] = 'My Job!'
	open(job.rule_path, 'w', encoding='utf-8').write(lines[0] + '\n' + '\t'.join(cols) + '\n')
	rules = rv.parse_rules(job.rule_path)
	assert len(rules) == 1
	assert rules[0].job_name == 'my-job'
	updated = open(job.rule_path, encoding='utf-8').read()
	assert 'my-job' in updated


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
