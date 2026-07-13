# Task 6 Report

## Status

DONE

## Changes

- Added `TestWatcherInitFailure.test_watcher_clears_green_light_when_watchfolder_fails`.
- Updated `watcher` to fail closed when `watchFolder` returns false: log, clear `GREEN_LIGHT`, and return `False`.
- Verified `backuper` already catches exceptions, logs the traceback, clears `GREEN_LIGHT`, and persists pending transactions.
- Corrected backup limit docs from bigger-wins to stricter-smaller-wins in `SAMPLE_REVERB_RULE_FILE`, `get_backup_limits_from_str`, and `reverb_rule.tsv`.
- Added the incomplete `V*` startup-cleanup warning to the sample rule text.
- Bumped `reverberator.py` and `pyproject.toml` to `0.23`.
- Narrowed `.gitignore` so `tests/` is not hidden by `test*/`.
- Made `docTest.sh` executable so the requested `./docTest.sh` command works.

## TDD Evidence

- RED: `timeout 5 .venv/bin/python -m unittest tests.test_crash_safety.TestWatcherInitFailure -v` timed out with the old watcher loop, proving the fail-closed test caught the missing behavior.
- GREEN: `.venv/bin/python -m unittest tests.test_crash_safety.TestWatcherInitFailure -v` passed after the watcher change.

## Verification

- `.venv/bin/python -m unittest tests.test_crash_safety -v` passed: 9 tests.
- `./docTest.sh` passed: 66 doctests.

## Concerns

- None.

## Final Whole-Branch Review Fixes

- Distinguished watcher outcomes with explicit sentinels: `init_failed` clears `GREEN_LIGHT`, while `self_destruct` leaves `GREEN_LIGHT` set and lets the watcher wait for filesystem recovery.
- Made `backuper` fail closed when `do_backup` returns `committed=False` while `GREEN_LIGHT` is still set, while still requeueing in-flight entries before shutdown.
- Added regression coverage for watcher init failure, monitor-root self-destruct, and uncommitted backup hard failure requeue/shutdown behavior.

## Final Fix Verification

- `.venv/bin/python -m unittest tests.test_crash_safety -v` passed: 11 tests.
- `./docTest.sh` passed: 66 doctests.
