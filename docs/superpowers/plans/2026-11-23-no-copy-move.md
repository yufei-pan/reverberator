# The no-copy move into a new folder (P3) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or
> superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. The user
> does not review this plan; what it decided on its own is in Calls to confirm at the end.

**Goal:** when the replay is about to copy a regular file whose old copy the batch's own delete put into the version before, and
that old copy is the monitored file byte for byte and in its metadata, hard-link it in place of the copy; everything else is the
copy made today.

**Architecture:** every change stays inside `reverberator.py` (one file, tabs) and `tests/`. Three module functions read (the
names of the batch's deletes, the old copy below one of them, the full compare), one `TreeWriter` verb links and tells the size
books, and `copy_path()`'s two copies go through one closure that picks the link or the copy; the estimate asks the same lookup.
Built in the spec's order (its section 11), its step 3 cut into three commits (Calls to confirm 1).

**Tech Stack:** Python 3.13 standard library. Dev-only: pytest, pytest-xdist, Docker as uid 65534; the test VM for root, loop-image,
mount, mergerfs and power-loss tests.

**Spec:** `docs/superpowers/specs/2026-11-23-no-copy-move-design.md` at 371dbad. Read its section for the task you build: the plan
argues from it and does not repeat its reasoning, its rules or its texts unless it decides something there.

## The questions this plan is written on

Both are open (docs/progress.md, Q24 and Q25). The build starts only once both are answered, on a branch made from the merged
0.55.7; the main session's brief for Task 1 gives both answers (the user's words or pick and the date, or "chief's decision" and
its date), which the approved fields of Task 4's texts carry. A task whose work another answer changes carries the mark.

| Question | Planned on | Tasks another answer changes, and how |
|---|---|---|
| Q24, whether to build the no-copy move now (spec 11) | (a) build it | (b): no task is built and nothing is written: every task carries **[Q24]** |
| Q25, the estimate and a file it expects the copy step to link (spec 3) | (a) the estimate leaves such a file out; the entry is widened | (b): Task 4 builds no `leaving` (no change to `do_backup()`'s estimate call, `get_backup_size_inode()`, `get_unskipped_size_inodes()` or tests/test_folder_times.py); its estimate tests give way to one pin; the two estimate tests of tests/test_moves_into_new_folders.py keep their inodes and bound the other way; 10.2's estimate sentence and README line 31's estimate clause are not written, and 10.1's estimate clause reads as its [Q25] note says. Task 6 does not measure the estimate with and without `leaving`. Task 9's size-limit run expects what today does: only the newest of the five small versions stays, as the estimate charges every copy |

An answer reversed after the build is its own change: the **[Q25]** lines of Tasks 4, 6 and 9 say what it is.

## Global Constraints

- Build in a worktree of its own, on a branch the main session makes from the merged 0.55.7 once Q24 and Q25 are answered (spec
  11, "a precondition"). Line numbers are of `reverberator.py` at e166baa (18,251 lines; r0556 holds the same file) and of
  `tests/` and `README.md` on r0556. 0.55.7 and earlier tasks move them: find each place by its function name, and each README
  or limitations text by the sentence it replaces.
- From 0.55.7 this round uses `VersionLookError` (its plan's Task 5), `real_folders_to(strict=True)` answering False for ENOTDIR
  (its spec section 7), `monitored_there()` in `copy_path()` (its Task 6), the rel `copy_path()` records for each entry's copy
  (its Task 7) and `finish_copies()`'s returned rels read as what the replay applied (its spec section 9). None of them is
  written here.
- `reverberator.py` stays one file, tab-indented. Tests stay in `tests/`. Each task commits, by name, the files its Files block
  names and the docs it changes. Commit messages say what changed and why and end with "; P3 work." then a blank line and
  `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`. Never commit `uv.lock`; never run `uv sync`.
- **What does not change** (spec, Summary): the watcher, the manifest (no table, no statement, no stored format), the change list,
  any command, `TreeWriter.record()`, `pre_record()`, `replay_ops()`, `delete_path()`, `verify()`. Nothing is kept at rest, on disk
  or in memory; per batch only the names, the compare's two block buffers, `links_refused`, whether a compare raised, and the links
  made. The rule behind every choice: when unsure, a copy, never wrong bytes.
- **The one number added:** `COMPARE_BLOCK_BYTES = 256 << 10`, its comment: coreutils' read size (its IO_BUFSIZE: coreutils 9.7's
  `cat` reads 262,144 bytes at a time), so the compare reads as `cp`'s family does. Task 6 measures it against 1 MiB; a size the
  measurement changes gets its reason there.
- **Venues.** No pytest as root on the host (a hook blocks it). Tests that need no root run in a container as uid 65534 through
  the runner the brief names, written here as `RUN <tag> <workers> <pytest args>`. Root (`trusted.*`, a chown, the crash
  harness), loop mounts, real mergerfs and power-loss runs go in the test VM, through its gate (the main session's). A module that
  builds the crash seed (`build_base()`, `prepare()`, `seed_base()`, which chowns `owned.txt`) is root-only too: a chown to
  another owner answers EPERM to uid 65534, so those modules cannot run in the container. Such steps are marked **main session: VM
  gate**: builders write their tests to skip outside the VM with a reason (`needs_root`, `needs_mergerfs`, or the module's own root
  skip) and never run them. The main session runs each marked gate right after its task's commit, as the spec's section 11 has it
  (Task 7's before its commit, its Step 2), and once more on the base, so each new root test is seen to fail there as its task says
  (that run is the base run of Step 2 for a root test): with the commit's `reverberator.py` swapped for its parent's for Tasks 1 and
  4, and, for Task 7, which changes none, with tests/crash_batches.py swapped for its parent's (its helper `link_shape_wrong()` is
  not there, so its tests fail on the import). Task 4's gate is the whole suite as root, as that is the commit where files start
  linking. Task 9 runs the whole set again. A skip at the VM gate counts as a failure.
- **The memory rule:** start a container only while `full avg60` in `/proc/pressure/memory` is not over 5 (RULES: "hold back
  only when its `full avg60` value is over 5") and MemAvailable minus the container's cap is at least 8 GB; with under 5 GB free the
  newest run stops and goes back in the queue (the runner waits).
- **The whole suite:** `RUN t<N>-all auto` (N the task's number: each task's "whole suite" step is this run), then `comm -13
  <out>/r_base_fails.txt <out>/r_t<N>-all_fails.txt` prints nothing: the branch fails nothing its base does not. `r_base_fails.txt`
  is made once, before Task 1, by `RUN base auto` at the branch point.
- **"Fails on the base"** means: the new test, run on the branch before this task's change (the base: the parent commit, so its
  `reverberator.py`, and for a test of a helper the task itself adds, the parent's copy of that helper's file), fails as the task
  says. Write its first failure line in the handback. A new test that does not fail there stops the task: report it. **Pins**
  say `# pin:` and their reason in their first comment line and pass before and after the change; a test that fails says `# FAILS:`
  and why, so every new test of a task carries one of the two (a shape added to a parametrized sweep, as Task 7's
  `MixedBatchManifestLost`, carries it in its class docstring). A test that works through a stand-in (an `os.link` that answers an
  errno, a `read_block()` that clears `GREEN_LIGHT`, a record that raises) also asserts that its stand-in was reached (a call
  counter above 0, or the `same_file()` spy's count), so on a base that never reaches it the test fails, and it cannot pass without
  the code. Names a task adds are read as `rv.<name>`, or imported, inside the tests that use them: one used at a module's top fails
  the collection of the whole module on the base and hides the intended failure. A task that changes no `reverberator.py` (Tasks 5
  and 7 and Task 6's fuzz step) has no earlier code to run its tests on: it writes tests of what Task 4 built, pins, each with its
  reason, run on Task 4's `reverberator.py` with the task's own test files, where they pass; a test of a helper the task itself adds
  (Task 7's `link_shape_wrong()`) fails with that helper's file swapped for its parent's. An edit of an existing test is no new test
  and takes no mark.
- **Every new test carries one layer marker** (`unit`, `inotify`, `process`, `privileged`; the collection fails otherwise).
  tests/test_no_copy_move.py is `unit` as a module (`pytestmark = pytest.mark.unit`); its owner and group cases take
  tests/test_r_readers.py's `needs_root` and run in the VM.
- **Docs travel with the code.** Section 10's texts are written word for word in Task 4's commit, the approved fields with the
  answers the brief gives; 10.1's "is expected to cost" stays until Task 9's measured figure replaces it. `docs/progress.md` is the
  main session's. No lessons entry is required (spec 10); its optional line is the main session's.
- **Measurements** the spec asks of the builder are timed in the container, warm, the figures in the handback (Task 6).
- **Public repo:** nothing tracked names a real mount point, host, job, VM id, disk name or id, or scratch path. Use `/mnt/pool`,
  `/srv/pool`, `/mnt/disk1`, `/mnt/vaults` and the like.
- **Never:** read `/etc/firewatcher/firewatcher.conf`; grep `/etc` recursively; run `systemctl` other than `systemctl show`; run
  `sync`, `syncfs`, `sysctl -w` or a write to `drop_caches` or `/sys`; touch the live service, the main checkout or its `.venv`, any
  vault, or any VM; use a bare `git stash`.
- A task that finds the spec wrong, or a test that does not fail where this plan says it fails, stops and reports with a proposed
  fix rather than following the spec. A test elsewhere in the suite that a link newly breaks is reported with whether the link
  is a true stand-in (spec 1): never weakened silently. Every handback ends with Calls to confirm (RULES.md).

## Review Focus

Five inputs the spec implies but its tests do not exercise, most likely to bite first. Each has its test in the named task.

1. **Two names of one monitored inode moved together** (a hard-linked file in the moved folder): the vault holds a copy per name,
   so each new name has its own old copy. Expected: each linked to its own old copy, two inodes in the new version as a copy
   gives, no two paths of a version on one. Test: `test_two_names_of_one_monitored_inode_each_link_their_own_old_copy`, Task 4.
2. **A FIFO in a moved folder.** Expected: never opened (the batch never blocks), copied as today, the folder's files linked.
   Test: `test_a_fifo_in_a_moved_folder_is_copied_and_never_opened`, Task 4.
3. **A file whose size sits at a block's edge** (0, 1, one block less one, one block, one more, three blocks). Expected: equal
   files compare equal, a last or first byte that differs does not. Test: `test_same_file_compares_at_block_boundaries`, Task 3.
4. **A moved entry whose name is not UTF-8, or holds a newline** (the names are str keys with surrogate escapes). Expected:
   linked as any other. Test: `test_a_moved_folder_whose_names_are_not_utf8_is_linked`, Task 4.
5. **A sparse monitored file whose old copy is dense** (a vault that kept no holes): only one side is sparse, so no hole is
   skipped. Expected: equal, linked. Test: the `dense_old_copy` case of `test_same_file_reads_two_sparse_files_by_their_data`,
   Task 3.

Reviewers also go through the spec's section for the task line by line, its Failure cases and Cost lines included.

---

### Task 1: The size books by rel and the writer's link verb (spec 5; build step 1) [Q24]

Nothing links yet: no caller of `link_kept()` until Task 4.

**Files:**
- Modify: `reverberator.py`: `BatchSizes` (13736: `shared` a dict, `pending()`, `result()`, new `linked()` and `alone()`, the
  docstring's "Nothing but the record's own link and the tree's copy changes that count during a batch" names `link_kept()`'s
  link too); `TreeWriter.__init__()` (`links_refused`) and new `TreeWriter.link_kept()` beside `copy()` (14170); `finish_copies()`
  (8946, its loop before `copy.task.stderr`, 8969); `record_dirty_entries()`'s docstring (11116: a placed link beside the copies
  the commit flushed).
- Modify: `tests/vault_oracle.py`: new `paths_sharing_an_inode()` after `sizes_by_newest_holder()`.
- Create: `tests/test_no_copy_move.py` (unit).
- Modify: `tests/test_tree_writer.py` (its module skips unless root: **main session: VM gate**; `handed_over()` gains `pooled=None`,
  passed to `rv.hand_over()`), `tests/test_tree_writes.py`.

**Interfaces:**
- Produces:
  - `BatchSizes.shared: dict`, `{rel: (size, links)}`; `pending(rel, size, links)` sets `shared[rel]`; `result()` iterates
    `self.shared.items()`.
  - `BatchSizes.linked(self, rel:str, size:int, links:int) -> None`: when `rel` is not in `shared`, `self.size -= size` and
    `self.inodes -= 1`; then, either way, `shared[rel] = (size, links)`.
  - `BatchSizes.alone(self, rel:str, two_renames:bool) -> bool`: `rel` not in `shared`, or the count of names of
    `os.path.join(self.previous, rel)` now (`links_now()` on two renames, `os.lstat().st_nlink` elsewhere) below `shared[rel][1]`.
    Raises OSError.
  - `TreeWriter.links_refused: bool`, False at the writer's making.
  - `TreeWriter.link_kept(self, kept_rel:str, source:str, rel:str, pending:list, kept:tuple) -> bool`: spec 5's five steps in their
    order; `source` is the monitored file's path, `kept` the `(st_dev, st_ino)` the compare read.
    1. `alone(kept_rel)` False answers False with nothing done: no record, no link, no folder. An OSError of it answers False too.
    2. As `copy()` does: `record(rel, True)`, `flush_if_needed()`, `_folders_for_copy(source, rel)`.
    3. A fresh copy name, `partial_copy_path(self.path(rel))`, taken again while one is there as `cp_af_copy_path()` does, and
       `os.link(self.kept_path(kept_rel), temp, follow_symlinks=False)`.
    4. One `lstat()` of the copy name, whose `(st_dev, st_ino)` must be `kept` (a mergerfs `link-exdev` symlink mode makes a symlink
       at the copy name and `os.link()` succeeds: another inode answers False, `links_refused` untouched).
    5. The books told, `linked(kept_rel, st.st_size, links)` from that lstat, `links` being `links_now(temp)` on two renames and
       `st_nlink` elsewhere; `PendingCopy(None, source, temp, self.path(rel))` appended. True.

    An OSError of the link or of the look after it (the lstat and, on two renames, `links_now(temp)`: one `try` covers all three)
    answers False with the copy name removed if made (`discard_temp()`; an OSError of that removal is a JobFailure naming the copy
    name). `links_refused` is set when `os.link()` itself answers EPERM, ENOTSUP, EOPNOTSUPP or ENOSYS. Raises JobFailure (a record, a
    flush, a copy name that cannot be removed) and `_folders_for_copy()`'s NotARealFolder, as `copy()` raises them: step 2 stays
    outside the `try`.
  - `finish_copies()`: an entry whose `task` is None is a link already made: no lines, succeeded; placed and returned as a finished
    copy is (the list 0.55.7 reads as what the replay applied), or left with its row dropped where a folder above its place is no
    longer real.
  - `paths_sharing_an_inode(job_vault:str, folder_name:str) -> list`: each group of two or more rels of the version that are one
    inode, read through `read_view(job_vault, folder_name, inodes)`, as a sorted list of sorted tuples; `[]` when none.

- [ ] **Step 1: Write the tests.** tests/test_no_copy_move.py opens with `import errno, os, shutil, stat, threading, time`, `import pytest`,
  `import reverberator as rv`, `from tests import harness` and `pytestmark = pytest.mark.unit`, and imports no name that Tasks 2 to 4
  add (Global Constraints); `paths_sharing_an_inode` is imported inside the tests that use it:

```python
# tests/test_no_copy_move.py
V1, V2 = 'V1--old', 'V2--new'                           # the folder names of the two versions a_writer() makes
RECORD_CASES = ['folder_deleted_whole', 'top_file_deleted', 'file_then_its_folder', 'copy_before_placement', 'copy_after_placement',
	'renamed_file', 'renamed_folder', 'moved_out_of_a_folder_then_it_removed', 'name_refilled_then_removed',
	'unfold_kept_by_a_hard_link', 'record_copied', 'remove_now']      # the spec's ten kinds, in twelve cases: the copy and the renamed move two each
FILES_OF = {                                            # V1's files of each case, each a few bytes of text of its own
	'folder_deleted_whole': {'d/f': 'f', 'd/s/g': 'g'}, 'top_file_deleted': {'f': 'f'}, 'file_then_its_folder': {'d/f': 'f', 'd/g': 'g'},
	'copy_before_placement': {'f': 'f'}, 'copy_after_placement': {'f': 'f'}, 'renamed_file': {'f': 'f'}, 'renamed_folder': {'d/f': 'f'},
	'moved_out_of_a_folder_then_it_removed': {'D/g': 'g', 'D/h': 'h'}, 'name_refilled_then_removed': {'p': 'p', 'other': 'other'},
	'unfold_kept_by_a_hard_link': {'d/e': 'e', 'd/a': 'a'}, 'record_copied': {'f': 'f', 'g': 'g'}, 'remove_now': {'d/f': 'f', 'g': 'g'},
}

def a_writer(tmp_path, files, pooled=None):
	'''(writer, job_vault, V1's path): a vault of the test's own, V1 holding files ({rel: text}) with no root record (so no root is needed),
	rv.hand_over() onto V2, pooled passed as hand_over() takes it.'''
	job_vault = str(tmp_path / 'vault')
	v1 = os.path.join(job_vault, V1)
	os.makedirs(v1)
	for rel, text in files.items():
		os.makedirs(os.path.dirname(os.path.join(v1, rel)), exist_ok=True)
		with open(os.path.join(v1, rel), 'w') as f:
			f.write(text)
	return rv.hand_over(job_vault, v1, os.path.join(job_vault, V2), pooled=pooled), job_vault, v1

def regular_files(top) -> dict:
	'''{rel: lstat} of each regular file under top that os.walk() reaches without following a link.'''
	found = {}
	for folder, _, names in os.walk(top):
		for name in names:
			path = os.path.join(folder, name)
			if stat.S_ISREG(os.lstat(path).st_mode):
				found[os.path.relpath(path, top)] = os.lstat(path)
	return found

def rm(writer, rel, is_dir=False) -> None:
	'''writer.remove_queued() on an executor of its own, waited for as stop_copies() waits, with its deadline (wait_for_async_commands() is a closure of do_reverb_backup(), not callable here).'''
	mcae = rv.multiCMD.AsyncExecutor(semaphore=rv.BACKUP_SEMAPHORE, quiet=True)
	writer.remove_queued(rel, is_dir, mcae, [])
	deadline = time.monotonic() + rv.COPY_STOP_WAIT_SECONDS
	while mcae.runningThreads and time.monotonic() < deadline:
		mcae.wait(timeout=rv.POLL_WAIT_SECONDS)
	assert not mcae.runningThreads

@pytest.mark.parametrize('pooled', [None, True], ids=['one_rename', 'two_renames'])
@pytest.mark.parametrize('kind', RECORD_CASES)
def test_alone_answers_for_each_kind_of_record(tmp_path, monkeypatch, kind, pooled):     # FAILS: no alone()
	from tests.vault_oracle import paths_sharing_an_inode
	source = str(tmp_path / 'monitored')                 # a file, made first: copy_after_placement copies it, and link_kept() asks whether it is there
	open(source, 'w').close()
	writer, job_vault, _ = a_writer(tmp_path, FILES_OF[kind], pooled)
	reached = []                                         # what the two stand-ins below were asked
	# the kind's calls on the writer; deletes go by rm(writer, rel, is_dir) above:
	#   folder_deleted_whole: rm -r d (d/f, d/s/g)                   top_file_deleted: rm f
	#   file_then_its_folder: rm d/f, then rm -r d                   remove_now: writer.remove_now('d'), writer.remove_now('g')
	#   copy_before_placement: writer.record('f', True)              copy_after_placement: harness.copy_now(writer, source, 'f') (it places the copy itself)
	#   renamed_file: writer.rename('f', 'f2')                       renamed_folder: writer.rename('d', 'd2')
	#   moved_out_of_a_folder_then_it_removed: writer.rename('D/g', 'y'), then rm -r D
	#   name_refilled_then_removed: writer.rename('p', 'q'), writer.rename('other', 'p'), then rm p (mv p q; mv other p; rm p)
	#   unfold_kept_by_a_hard_link: an os.symlink stand-in that answers ENAMETOOLONG for the link whose text is rv.forward_text('d/a', writer.tree_name)
	#     (appending to `reached`), then rm d/e (its record unfolds d, with d/a held by a hard link), then rm -r d
	#   record_copied: an os.link stand-in that answers EMLINK for a link whose source is writer.path('f') (appending to `reached`), then
	#     writer.record('f', True): the record keeps f by a copy, another inode than the tree's, on one rename and on two (a delete's own record
	#     renames f in and makes no link, so it would not reach the stand-in)
	if kind in ('unfold_kept_by_a_hard_link', 'record_copied'):
		assert reached                                   # the stand-in was reached
	in_tree = {(st.st_dev, st.st_ino) for st in regular_files(writer.tree).values()}
	before = regular_files(writer.previous)
	for rel, st in before.items():
		assert writer.sizes.alone(rel, writer.two_renames) == ((st.st_dev, st.st_ino) not in in_tree), rel
	for rel, st in before.items():
		if writer.sizes.alone(rel, writer.two_renames):
			pending = []
			assert writer.link_kept(rel, source, 'new/' + rel, pending, (st.st_dev, st.st_ino)) is True
			writer.place(pending[-1].temp_path, 'new/' + rel)
			assert writer.sizes.alone(rel, writer.two_renames) is False
	assert paths_sharing_an_inode(job_vault, V1) == paths_sharing_an_inode(job_vault, V2) == []

def test_link_kept_does_nothing_for_a_file_the_tree_still_holds(tmp_path, monkeypatch):     # FAILS: no link_kept()
	writer, job_vault, _ = a_writer(tmp_path, {'f': 'f'})
	writer.record('f', True)                             # V1's f is a hard link of the tree's f now: not alone
	st = os.lstat(writer.kept_path('f'))
	source, pending, calls = str(tmp_path / 'monitored'), [], []
	open(source, 'w').close()
	monkeypatch.setattr(os, 'link', lambda *args, **kwargs: calls.append(args))
	assert writer.link_kept('f', source, 'n/f', pending, (st.st_dev, st.st_ino)) is False
	assert calls == [] and pending == []                 # no link attempted, nothing queued
	assert not os.path.lexists(writer.path('n')) and not os.path.lexists(writer.kept_path('n'))        # no record, no folder
	assert os.lstat(writer.kept_path('f')).st_nlink == st.st_nlink

@pytest.mark.parametrize('answer', [errno.EPERM, errno.ENOTSUP, errno.EOPNOTSUPP, errno.ENOSYS, errno.EXDEV, errno.EMLINK, errno.EIO,
	'symlink_at_the_copy_name'])
def test_link_kept_is_false_and_leaves_no_copy_name_when_the_link_or_the_look_fails(tmp_path, monkeypatch, answer):    # FAILS: no link_kept()
	writer, job_vault, _ = a_writer(tmp_path, {'old/x': 'x'})
	writer.remove_now('old')                             # the version before alone holds old/x
	st = os.lstat(writer.kept_path('old/x'))
	source, pending, calls, real_link = str(tmp_path / 'monitored'), [], [], os.link
	open(source, 'w').close()
	def link(a, b, **kwargs):                            # an answer for copy names only: the record's own links go through
		if not b.endswith(rv.PARTIAL_COPY_SUFFIX):
			return real_link(a, b, **kwargs)
		calls.append(b)
		if answer == 'symlink_at_the_copy_name':         # mergerfs's link-exdev=rel-symlink: os.link() succeeds, with a symlink at b
			return os.symlink(a, b)
		raise OSError(answer, os.strerror(answer), a, None, b)
	monkeypatch.setattr(os, 'link', link)
	assert writer.link_kept('old/x', source, 'n/x', pending, (st.st_dev, st.st_ino)) is False
	assert calls and pending == []                       # the stand-in was reached
	assert not [name for name in os.listdir(os.path.join(writer.tree, 'n')) if name.endswith(rv.PARTIAL_COPY_SUFFIX)]
	assert os.lstat(writer.kept_path('old/x')).st_nlink == 1 and writer.sizes.alone('old/x', writer.two_renames) is True
	assert writer.links_refused == (answer in (errno.EPERM, errno.ENOTSUP, errno.EOPNOTSUPP, errno.ENOSYS))

def test_a_finished_link_is_placed_and_one_whose_folder_became_a_link_is_left(tmp_path):     # FAILS: finish_copies() reads None.stderr
	writer, job_vault, _ = a_writer(tmp_path, {'old/a': 'a', 'old/b': 'b'})
	writer.remove_now('old')                             # the version before alone holds old/a and old/b, at other paths than the places below
	version, source = writer.tree, str(tmp_path / 'monitored')
	open(source, 'w').close()
	for folder in ('d1', 'd2'):
		os.mkdir(os.path.join(version, folder))
	temp_a, temp_b = (rv.partial_copy_path(os.path.join(version, folder, name)) for folder, name in (('d1', 'a'), ('d2', 'b')))
	os.link(writer.kept_path('old/a'), temp_a)           # the copy names: links of the old files, as link_kept() makes them
	os.link(writer.kept_path('old/b'), temp_b)
	pending = [rv.PendingCopy(None, source, temp_a, os.path.join(version, 'd1/a')), rv.PendingCopy(None, source, temp_b, os.path.join(version, 'd2/b'))]
	manifest = rv.VaultManifest(job_vault)               # as tests/test_verify_replay.py's finish_copies() tests make one
	manifest.begin()
	try:
		manifest.add('d1/a', dirty=True)
		manifest.add('d2/b', dirty=True)
		shutil.rmtree(os.path.join(version, 'd2'))
		os.symlink('d1', os.path.join(version, 'd2'))   # the second's folder above its place is a link now
		placed = rv.finish_copies(pending, manifest, version, 'job', writer=writer)
		assert placed == ['d1/a'] and pending == []     # the first put in place and returned
		assert os.lstat(os.path.join(version, 'd1/a')).st_ino == os.lstat(writer.kept_path('old/a')).st_ino and not os.path.lexists(temp_a)   # the placement is a rename of the copy name: it is gone
		assert manifest.copies_unsynced is True
		assert manifest.lookup('d2/b') is None           # the second left, its row dropped, not returned
	finally:
		manifest.rollback()
		manifest.close()
```

```python
# tests/test_tree_writer.py: handed_over() gains pooled=None, passed to rv.hand_over()
@pytest.mark.unit
@pytest.mark.parametrize('pooled', [None, True], ids=['one_rename', 'two_renames'])
def test_link_kept_records_its_place_and_queues_a_finished_copy(tmp_path, pooled):     # FAILS: no link_kept()
	writer, job_vault, before = handed_over(str(tmp_path), {'old/x': 'x', 'n/x': 'other'}, pooled)
	writer.remove_now('old')                             # the version before alone holds old/x
	st = os.lstat(writer.kept_path('old/x'))
	kept, source, pending = (st.st_dev, st.st_ino), source_file(str(tmp_path)), []     # source: the monitored file
	assert writer.link_kept('old/x', source, 'n/x', pending, kept) is True
	assert read_view(job_vault, V1)['n/x'] == before['n/x']                       # n/x's old entry recorded first
	record = os.lstat(writer.kept_path('n/x'))           # V1's own n/x: a regular file, on the inode the tree still holds at n/x until the link is placed
	assert stat.S_ISREG(record.st_mode) and record.st_ino == os.lstat(writer.path('n/x')).st_ino
	assert pending == [rv.PendingCopy(None, source, pending[0].temp_path, writer.path('n/x'))]
	assert (os.lstat(pending[0].temp_path).st_dev, os.lstat(pending[0].temp_path).st_ino) == kept
	assert writer.sizes.alone('old/x', writer.two_renames) is False
```

  `tests/test_tree_writes.py`: `test_the_writer_is_where_the_writes_are`'s verbs gain `'link_kept'`, and it asserts
  `'os.link' in names_used(writer['TreeWriter.link_kept'])` (FAILS: no `link_kept`).
- [ ] **Step 2: Run them on the base.** `RUN t1 auto tests/test_no_copy_move.py tests/test_tree_writes.py`: each FAILS, with its own
  first line: `ImportError` of `paths_sharing_an_inode` (the alone test), `AttributeError` of `alone`/`link_kept` (the others),
  `AttributeError: 'NoneType' object has no attribute 'stderr'` (the finished-link test). The new test of tests/test_tree_writer.py is
  root-only: the VM gate shows it failing on the parent's `reverberator.py` (Global Constraints, Venues).
- [ ] **Step 3: Implement** the names above, as their Interfaces say.
- [ ] **Step 4: Run** the tests, then `RUN t1 auto tests/test_no_copy_move.py tests/test_tree_writes.py tests/test_io_errors.py
  tests/test_verify_replay.py`, then the whole suite (`RUN t1-all auto` and its `comm` check, Global Constraints).
- [ ] **Step 5: Commit.** **main session: VM gate** after it: `tests/test_tree_writer.py`, `tests/test_r_sizes.py` (its `Run` builds the
  crash seed), `tests/test_pool_writer.py` (its module skips unless root) and the two root tests of `tests/test_verify_replay.py`
  (`test_the_verification_syncs_an_owner_the_replay_missed_and_a_user_links_own` and
  `test_version_folders_stay_the_daemons_and_keep_the_monitored_roots_metadata_of_their_batch`: they run whole batches with a chown).

**Acceptance:** `alone()` answers "no path of the tree holds this inode" for every record kind, both ways; `link_kept()` is the one
door a link goes through, does nothing for a file the tree still holds, and answers False for a copy name that is not the kept inode;
`finish_copies()` places a link as a copy; nothing calls `link_kept()` yet.

---

### Task 2: Which old copy is looked at (spec 2; build step 2) [Q24]

Read by nothing yet.

**Files:**
- Modify: `reverberator.py`: new `released_names()` and `old_copy()` beside `order_backup_entries_for_replay()` (8111).
- Modify: `tests/test_no_copy_move.py`.

**Interfaces:**
- Consumes: 0.55.7's `real_folders_to(strict=True)` (False for ENOENT and ENOTDIR, `VersionLookError` otherwise).
- Produces:
  - `released_names(backup_entries:dict, monitor_path:str) -> dict`: `{last name: rel}` of the delete entries (a rel is
    `os.path.relpath(path, monitor_path)`, a folder's without its `/`) under no other delete and at or above no move entry's
    `source_path`; a name two of them share maps to None (ambiguous). Two passes over the entries, no sort: the first collects
    `deleted`, the set of the deletes' rels, and `blocked`, the set of each move source's rel and of every folder above it; the second
    keeps a delete whose rel is not in `blocked` and with no folder above it in `deleted` (a set lookup a parent, as `inside_folders()`
    walks them).
  - `old_copy(names:dict, rel:str, st, version_path:str) -> 'str | None'`: `st` is read for `st_size`, `st_mtime_ns`, `st_mode`,
    `st_uid`, `st_gid` only. For each part of `rel` whose name maps to a rel, outermost first: the old path is that rel plus the
    parts after the name (none for the last part); one equal to `rel` is passed over. The first whose folders are real
    (`real_folders_to(version_path, old, strict=True)`) and whose `os.lstat()` is a regular file with those five fields equal is
    returned; else None. FileNotFoundError and NotADirectoryError of the lstat are "not there"; any other OSError, and the folder
    look's `VersionLookError`, are raised.

- [ ] **Step 1: Write the tests.** The module's helpers, which Tasks 4 and 5's tests use too:

```python
from collections import deque
from tests.crash_batches import raw_events

def entries(m, events) -> dict:
	'''Backup entries as change_events_to_backup_entries() gives them (a folder's path ends with /), from events as raw_events() takes
	them, (is_dir, event, rel, moved_from rel or None), the paths under the monitored folder m.'''
	return rv.change_events_to_backup_entries(deque(raw_events(m, events)), m)

def deletes(m, *rels) -> dict:            # a rel ending with / is a folder
	return entries(m, [(rel.endswith('/'), 'delete', rel.rstrip('/'), None) for rel in rels])

def per_row_deletes_of(m, folder, files, subfolders=()) -> dict:
	'''A full comparison's deletes of a folder it did not see: the folder, each file and each subfolder, as one entry a row.'''
	return entries(m, [*((False, 'delete', rel, None) for rel in files), *((True, 'delete', rel, None) for rel in subfolders), (True, 'delete', folder, None)])

def moved(m, to, from_, is_dir=True) -> dict:
	return entries(m, [(is_dir, 'move', to, from_)])

SAME_MTIME_NS = 1_700_000_000_000_000_000

def made(top, rel, text='same') -> str:
	'''A file at top/rel, its folders made, holding text, its mtime_ns SAME_MTIME_NS: the files of one test then differ in no field old_copy() reads (st_size, st_mtime_ns, st_mode, st_uid, st_gid).'''
	path = os.path.join(top, rel)
	os.makedirs(os.path.dirname(path), exist_ok=True)
	with open(path, 'w') as f:
		f.write(text)
	os.utime(path, ns=(SAME_MTIME_NS, SAME_MTIME_NS))
	return path
```

```python
def test_released_names_keeps_the_top_most_deletes_by_their_last_name(tmp_path):     # FAILS: no released_names()
	m = str(tmp_path)
	assert rv.released_names(per_row_deletes_of(m, 'P/big', ['P/big/a', 'P/big/sub/b'], ['P/big/sub']), m) == {'big': 'P/big'}
	assert rv.released_names(deletes(m, 'f.txt', 'd/'), m) == {'f.txt': 'f.txt', 'd': 'd'}
	assert rv.released_names(deletes(m, 'x/src', 'y/src'), m) == {'src': None}
	assert rv.released_names({**moved(m, 'y', 'd/g'), **deletes(m, 'd/')}, m) == {}        # mv d/g y; rm -r d
	assert rv.released_names({**moved(m, 'b', 'a'), **deletes(m, 'a')}, m) == {}           # a delete at a move's source

def test_old_copy_finds_the_file_below_the_deleted_entry_of_its_name(tmp_path, monkeypatch):     # FAILS: no old_copy()
	version = str(tmp_path / 'version')
	for rel in ('P/big/sub/a', 'big/sub/a', 'top.iso', 'notes'):
		made(version, rel)
	st = os.lstat(made(str(tmp_path), 'monitored'))                         # the monitored file: the same five fields as each file of the version
	assert rv.old_copy({'big': 'P/big'}, 'P/new/big/sub/a', st, version) == 'P/big/sub/a'
	assert rv.old_copy({'big': 'P/big'}, 'Q/n/big/sub/a', st, version) == 'P/big/sub/a'     # another parent
	assert rv.old_copy({'big': 'big'}, 'a/b/big/sub/a', st, version) == 'big/sub/a'         # mkdir -p a/b
	assert rv.old_copy({'top.iso': 'top.iso'}, 'n/top.iso', st, version) == 'top.iso'       # a moved file
	assert rv.old_copy({'big': 'big'}, 'r/big/sub/a', st, version) == 'big/sub/a'           # unpacked elsewhere
	for field, value in (('st_size', st.st_size + 1), ('st_mtime_ns', st.st_mtime_ns + 1), ('st_mode', st.st_mode ^ 0o001),
			('st_uid', st.st_uid + 1), ('st_gid', st.st_gid + 1)):      # a key that differs in each of its five fields
		five = {name: getattr(st, name) for name in ('st_size', 'st_mtime_ns', 'st_mode', 'st_uid', 'st_gid')}
		assert rv.old_copy({'big': 'big'}, 'n/big/sub/a', SimpleNamespace(**{**five, field: value}), version) is None, field
	assert rv.old_copy({'big': 'P/big'}, 'n/other/a', st, version) is None                   # a renamed move: no part of the path holds the name
	assert rv.old_copy({'big': None}, 'n/big/sub/a', st, version) is None                    # ambiguous
	assert rv.old_copy({'big': 'P/big'}, 'n/big/missing', st, version) is None               # no file below the entry: ENOENT is "not there"
	assert rv.old_copy({'d': 'd'}, 'd/f', st, version) is None                               # the old path is the new one
	assert rv.old_copy({'notes': 'notes'}, 'n/notes/x', st, version) is None                 # a deleted file's name as a folder of the new path
	os.symlink('big', os.path.join(version, 'L'))
	os.symlink('top.iso', os.path.join(version, 'ln'))
	assert rv.old_copy({'big': 'L'}, 'n/big/sub/a', st, version) is None                     # the old path through a symlink to a folder
	assert rv.old_copy({'top.iso': 'ln'}, 'n/top.iso', st, version) is None                  # the old path a symlink
	real_lstat, reached = os.lstat, []
	def failing(path_ending):                                               # os.lstat answering EIO for the one path
		def lstat(path, *args, **kwargs):
			if path == os.path.join(version, path_ending):
				reached.append(path)
				raise OSError(errno.EIO, os.strerror(errno.EIO), path)
			return real_lstat(path, *args, **kwargs)
		return lstat
	monkeypatch.setattr(os, 'lstat', failing('P/big/sub/a'))
	with pytest.raises(OSError) as raised:                                  # raised, not caught: the copy step chooses the copy for it
		rv.old_copy({'big': 'P/big'}, 'n/big/sub/a', st, version)
	assert reached and raised.value.errno == errno.EIO
	reached.clear()
	monkeypatch.setattr(os, 'lstat', failing('P/big'))
	with pytest.raises(rv.VersionLookError):                                # the strict look at a folder above it (0.55.7)
		rv.old_copy({'big': 'P/big'}, 'n/big/sub/a', st, version)
	assert reached
```

- [ ] **Step 2: Run them on the base:** both FAIL (no `released_names`).
- [ ] **Step 3: Implement** the two functions as their Interfaces say.
- [ ] **Step 4: Run** `RUN t2 auto tests/test_no_copy_move.py`, then the whole suite.
- [ ] **Step 5: Commit.**

**Acceptance:** a file whose path holds a deleted entry's name finds the file at its place below that entry, or None; a look
that cannot answer raises.

---

### Task 3: The full compare, `same_file()` and its seams (spec 4, "`same_file()`") [Q24]

Read by nothing yet but `hash_file()`, whose opener moves out unchanged.

**Files:**
- Modify: `reverberator.py`: `hash_file()` (11674): its inner `opener()` becomes the module function `no_follow_opener()` (its
  comments kept), which `hash_file()` uses; new `COMPARE_BLOCK_BYTES`, `read_block()` and `same_file()` beside it;
  `entry_metadata()` (9159) and `xattr_names()` (9180) take an open fd too.
- Modify: `tests/test_no_copy_move.py`.

**Interfaces:**
- Produces:
  - `no_follow_opener(file:str, flags:int) -> int`: `hash_file()`'s opener as it is.
  - `read_block(f, buffer:bytearray) -> int`: `f.readinto()` into the rest of `buffer` (a memoryview slice) until it is full or a
    call returns 0; the bytes read.
  - `same_file(source:str, kept:str, blocks:tuple) -> 'tuple | None'`: `blocks` two `bytearray(COMPARE_BLOCK_BYTES)`. The kept
    file's `(st_dev, st_ino)` from its handle's `fstat()` when the two are equal in `entry_metadata()` of each handle, in the two
    handles' sizes and in every byte; else None. One `BACKUP_SEMAPHORE` permit, waited for by `acquire(timeout=0.1)` in a loop
    (multiCMD's dispatcher's wait) with `GREEN_LIGHT` looked at before the first acquire and after each timeout (clear: None), given
    back by a `try`/`finally` that starts right after the acquire succeeds and covers the opens and reads. Each file opened once,
    `open(path, 'rb', buffering=0, opener=no_follow_opener)`, then `hash_file()`'s two steps (not a regular file: None;
    `O_NONBLOCK` cleared). Blocks compared with `==` of the bytearrays, a short last block by its slices. Where both fstats'
    `st_blocks * 512` are below their `st_size`: after each block each handle `seek(pos, os.SEEK_DATA)`, `pos` the handle's
    current offset, the next unread byte (ENXIO: its size), and both seek to the nearer of the two. None at the first block or length that
    differs, at any OSError, and when `GREEN_LIGHT` is clear between blocks. Any other exception goes up.
  - `entry_metadata(path:'str | int') -> tuple` and `xattr_names(path:'str | int') -> list`: on an int, `entry_metadata()` takes the
    stat from `os.fstat(fd)` (that branch before its `path.rstrip('/')`, which an int has not) and the values from `os.getxattr(fd,
    name)`; `xattr_names()` calls `os.listxattr(fd)`, no fstat; neither passes `follow_symlinks` (Python raises ValueError for an fd
    with it, checked); the tuple and `xattr_names()`'s ENOTSUP/ENOSYS rule as for a path.

- [ ] **Step 1: Write the tests.** Helpers of tests/test_no_copy_move.py (Task 4's sparse test uses `holes_or_skip()` too); the module's top
  imports are those of Task 1's step, plus `from types import SimpleNamespace` (Task 2's tests):

```python
BLOCK_SIZES = [(0, 0), (0, 1), (1, -1), (1, 0), (1, 1), (3, 0)]          # (blocks, extra): 0, 1, B - 1, B, B + 1, 3 * B, B being rv.COMPARE_BLOCK_BYTES

def buffers() -> tuple:
	return bytearray(rv.COMPARE_BLOCK_BYTES), bytearray(rv.COMPARE_BLOCK_BYTES)     # made inside each test: a module-level read of the constant would fail the collection on the base

def a_pair(folder, size) -> tuple:
	'''(source, kept) in a new folder, `size` random bytes each, kept a shutil.copy2 of source: the same bytes, mode and mtime_ns.'''
	os.makedirs(folder)
	source, kept = os.path.join(folder, 'source'), os.path.join(folder, 'kept')
	with open(source, 'wb') as f:
		f.write(os.urandom(size))
	shutil.copy2(source, kept)
	return source, kept

def poked(path, offset) -> None:
	'''The byte at offset flipped, atime and mtime put back.'''
	before = os.stat(path)
	with open(path, 'r+b') as f:
		f.seek(offset)
		byte = f.read(1)
		f.seek(offset)
		f.write(bytes([byte[0] ^ 0xFF]))
	os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))

def inode_of(path) -> tuple:
	st = os.stat(path)
	return st.st_dev, st.st_ino

def holes_or_skip(folder) -> None:
	'''pytest.skip() when the filesystem under folder keeps no holes (a file made sparse there reads st_blocks * 512 >= st_size).'''
```

```python
@pytest.mark.parametrize('blocks,extra', BLOCK_SIZES)
def test_same_file_compares_at_block_boundaries(tmp_path, blocks, extra):          # Review Focus 3. FAILS: no same_file()
	size = blocks * rv.COMPARE_BLOCK_BYTES + extra
	source, kept = a_pair(str(tmp_path / 'equal'), size)
	assert rv.same_file(source, kept, buffers()) == inode_of(kept)
	for offset in sorted({size - 1, 0}) if size else ():                   # its last byte changed, then its first, each with the mtime set back; size 0 has no byte to change
		source, kept = a_pair(str(tmp_path / f'at{offset}'), size)
		poked(source, offset)
		assert rv.same_file(source, kept, buffers()) is None, offset

@pytest.mark.parametrize('blocks,extra', [(0, 0), (1, -1), (1, 0)], ids=['0', 'B-1', 'B'])
@pytest.mark.parametrize('longer', ['source', 'kept'])
def test_same_file_is_none_for_files_of_unequal_length(tmp_path, blocks, extra, longer):     # FAILS: no same_file()
	size = blocks * rv.COMPARE_BLOCK_BYTES + extra                          # the shorter file's size; the longer holds one byte more
	source, kept = a_pair(str(tmp_path), size + 1)
	long_one, short_one = (source, kept) if longer == 'source' else (kept, source)
	os.truncate(short_one, size)                                            # the shorter is the longer one's first `size` bytes: only the length tells them apart,
	st = os.stat(long_one)                                                  # and a compare that stopped at the first short read would link the longer one
	os.utime(short_one, ns=(st.st_atime_ns, st.st_mtime_ns))
	assert rv.same_file(source, kept, buffers()) is None

def test_same_file_opens_each_file_once_and_answers_the_inode_it_opened(tmp_path, monkeypatch):     # FAILS: no same_file(), no no_follow_opener()
	source, kept = a_pair(str(tmp_path), 3 * rv.COMPARE_BLOCK_BYTES)
	first, opened, real = inode_of(kept), [], rv.no_follow_opener
	def opener(file, flags):
		fd = real(file, flags)
		opened.append(file)
		if file == kept:                                                    # the kept path is replaced, after its open, by another inode of the same bytes and metadata
			shutil.copy2(kept, kept + '.other')
			os.replace(kept + '.other', kept)
		return fd
	monkeypatch.setattr(rv, 'no_follow_opener', opener)
	assert rv.same_file(source, kept, buffers()) == first                  # the inode of the handle it read, not the one now at the path
	assert inode_of(kept) != first and sorted(opened) == sorted([source, kept])      # the replacement happened; one open a path

@pytest.mark.parametrize('field', ['mode', 'mtime'])
def test_same_file_compares_the_mode_and_the_mtime_read_through_its_handles(tmp_path, field):     # FAILS: no same_file()
	source, kept = a_pair(str(tmp_path), 4096)
	assert rv.same_file(source, kept, buffers()) == inode_of(kept)
	if field == 'mode':
		os.chmod(source, 0o600)
	else:
		st = os.stat(source)
		os.utime(source, ns=(st.st_atime_ns, st.st_mtime_ns + 1))
	assert rv.same_file(source, kept, buffers()) is None

def test_same_file_compares_the_user_attributes_read_through_its_handles(tmp_path):     # FAILS: no same_file()
	from tests.test_moves_then_changes import user_xattrs_or_skip
	source, kept = a_pair(str(tmp_path), 4096)
	user_xattrs_or_skip(source)
	os.setxattr(source, 'user.x', b'1')
	assert rv.same_file(source, kept, buffers()) is None                    # on one side only
	os.setxattr(kept, 'user.x', b'2')
	assert rv.same_file(source, kept, buffers()) is None                    # another value
	os.setxattr(kept, 'user.x', b'1')
	assert rv.same_file(source, kept, buffers()) == inode_of(kept)

def test_entry_metadata_and_xattr_names_take_an_open_fd(tmp_path, monkeypatch):     # FAILS: entry_metadata() calls .rstrip() on an int
	from tests.test_moves_then_changes import user_xattrs_or_skip
	source, _ = a_pair(str(tmp_path), 4096)
	user_xattrs_or_skip(source)
	os.setxattr(source, 'user.x', b'1')
	real, calls = os.listxattr, []
	def answering(code):                                                    # os.listxattr answering `code` for an fd, as itself for a path
		def listxattr(path, *args, **kwargs):
			if not isinstance(path, int):
				return real(path, *args, **kwargs)
			calls.append(path)
			raise OSError(code, os.strerror(code))
		return listxattr
	with open(source, 'rb') as f:
		assert rv.entry_metadata(f.fileno()) == rv.entry_metadata(source)
		assert rv.xattr_names(f.fileno()) == rv.xattr_names(source) == ['user.x']
		monkeypatch.setattr(os, 'listxattr', answering(errno.ENOTSUP))
		assert rv.xattr_names(f.fileno()) == [] and calls
		calls.clear()
		monkeypatch.setattr(os, 'listxattr', answering(errno.EIO))
		with pytest.raises(OSError):
			rv.xattr_names(f.fileno())
		assert calls

def test_read_block_fills_its_buffer_from_short_reads():                      # FAILS: no read_block()
	B = rv.COMPARE_BLOCK_BYTES
	data = os.urandom(B * 5 // 2)                                           # 2.5 buffers
	class Short:                                                            # readinto() gives at most 1000 bytes a call
		at = 0
		def readinto(self, view):
			n = min(1000, len(view), len(data) - self.at)
			view[:n] = data[self.at:self.at + n]
			self.at += n
			return n
	f, buffer = Short(), bytearray(B)
	assert [rv.read_block(f, buffer) for _ in range(4)] == [B, B, B // 2, 0]       # the third call's bytes are the tail: buffer[:B // 2] == data[2 * B:]
	assert buffer[:B // 2] == data[2 * B:]

def test_same_file_opens_no_fifo_and_follows_no_link(tmp_path):              # FAILS: no same_file()
	source, kept = a_pair(str(tmp_path / 'fifo'), 4096)
	os.remove(source)
	os.mkfifo(source)                                                       # a FIFO with no writer at the source: a plain open would block for ever
	outcome = []
	worker = threading.Thread(target=lambda: outcome.append(rv.same_file(source, kept, buffers())), daemon=True)   # joined with a timeout, as test_hash_file_refuses_fifo_without_blocking is (tests/test_helpers_cli.py)
	worker.start()
	worker.join(5)
	assert not worker.is_alive() and outcome == [None]
	source, kept = a_pair(str(tmp_path / 'link'), 4096)
	os.rename(kept, kept + '.real')
	os.symlink(kept + '.real', kept)                                        # the kept path a symlink to a copy: never followed
	assert rv.same_file(source, kept, buffers()) is None

@pytest.mark.parametrize('shape', ['data_at_both_ends', 'hole_written_as_zeros', 'other_bytes_in_the_hole', 'sparse_alike_differing',
	'dense_old_copy'])
def test_same_file_reads_two_sparse_files_by_their_data(tmp_path, monkeypatch, shape):       # FAILS: no same_file()
	holes_or_skip(str(tmp_path))                                            # all five run, none skipped, in their venue: where holes are kept (the handback says which filesystem and the skip count)
	# data_at_both_ends: 64 MiB, data in the first and last 4 KiB, a hole between, in both: equal, and a read_block() stand-in
	#   counting bytes (called: above 0) sees under 4 * B read in all
	# hole_written_as_zeros: the source written with zeros where the kept has its hole: equal
	# other_bytes_in_the_hole: the source with other bytes inside the kept's hole: None
	# sparse_alike_differing: both 256 KiB of equal data at 0, a hole to 2 MiB, 256 KiB at 2 MiB that differs, a hole to 4 MiB: None
	# dense_old_copy (Review Focus 5): the kept written dense, the source sparse with the same bytes: equal

def test_a_compare_holds_a_threads_permit(tmp_path, monkeypatch):            # FAILS: no same_file()
	class Counting(threading.Semaphore):                                    # rv.BACKUP_SEMAPHORE for this test, counting its acquire calls
		calls = 0
		def acquire(self, *args, **kwargs):
			self.calls += 1
			return super().acquire(*args, **kwargs)
	sem = Counting(1)
	monkeypatch.setattr(rv, 'BACKUP_SEMAPHORE', sem)
	source, kept = a_pair(str(tmp_path), 3 * rv.COMPARE_BLOCK_BYTES)
	real_read, seen = rv.read_block, {'reads': 0, 'held': []}
	def reading(how):                                                       # a read_block() stand-in: records whether a permit was held while it read
		def read(f, buffer):
			seen['reads'] += 1
			free = sem.acquire(blocking=False)
			if free:
				sem.release()
			seen['held'].append(not free)
			if how == 'ValueError':
				raise ValueError('a stand-in')
			if how == 'OSError':
				raise OSError(errno.EIO, os.strerror(errno.EIO))
			got = real_read(f, buffer)
			if how == 'stop':
				rv.GREEN_LIGHT.clear()                                     # after its first block of three
			return got
		return read
	for how, outcome in (('returns', inode_of(kept)), ('ValueError', ValueError), ('OSError', None), ('stop', None)):
		seen['reads'], seen['held'] = 0, []
		monkeypatch.setattr(rv, 'read_block', reading(how))
		try:
			if outcome is ValueError:
				with pytest.raises(ValueError):
					rv.same_file(source, kept, buffers())
			else:
				assert rv.same_file(source, kept, buffers()) == outcome, how
		finally:
			rv.GREEN_LIGHT.set()
		assert seen['reads'] > 0 and all(seen['held']), how               # the stand-in was reached, with a permit held while it read
		assert sem.acquire(blocking=False) is True and sem.acquire(blocking=False) is False, how      # exactly one permit is there after: one given back twice would show as two
		sem.release()
	monkeypatch.setattr(rv, 'read_block', real_read)
	opens, real_opener = [], rv.no_follow_opener
	monkeypatch.setattr(rv, 'no_follow_opener', lambda file, flags: opens.append(file) or real_opener(file, flags))
	assert sem.acquire(blocking=False) is True                              # the test holds the permit, and GREEN_LIGHT is clear
	before = sem.calls
	rv.GREEN_LIGHT.clear()
	try:
		assert rv.same_file(source, kept, buffers()) is None
	finally:
		rv.GREEN_LIGHT.set()
	assert sem.calls == before and opens == []                              # no acquire, no open: the stop is looked at first
	assert sem.acquire(blocking=False) is False                             # and the test's permit is the one still held
```
- [ ] **Step 2: Run them on the base:** each FAILS (no `COMPARE_BLOCK_BYTES`, no `same_file`).
- [ ] **Step 3: Implement** the names above; `hash_file()` keeps its behaviour, its opener now `no_follow_opener()`.
- [ ] **Step 4: Run** the tests, `RUN t3 auto tests/test_no_copy_move.py tests/test_io_errors.py tests/test_helpers_cli.py
  tests/test_moves_then_changes.py tests/test_compare_scopes.py` (the lease tests of tests/test_io_errors.py among them), then the
  whole suite.
- [ ] **Step 5: Commit.**

**Acceptance:** `same_file()` answers the kept inode only for two files equal in metadata and every byte, reads sparse files by
their data, holds one permit and gives it back however it ends; `hash_file()` is as it was.

---

### Task 4: The copy step links, the estimate leaves its files out, the log line, the docs (spec 3, 4, 6, 10; build step 3) [Q24] [Q25]

One commit: either half alone breaks tests/test_moves_into_new_folders.py's two estimate tests (spec 11, step 3).

**Files:**
- Modify: `reverberator.py`:
  - `do_backup()`: the names, right before its estimate (6399-6407): `released_names(backup_entries, monitor_path)` when `tree is
    None` and the batch holds a delete and a create or a modify, else `{}`; spec 3's `leaving` (its code as the spec gives it) when
    the names are not empty, passed as `get_backup_size_inode(..., leaving=leaving)`; `do_reverb_backup(..., names=names)`; the
    note on `BACKUP_SEMAPHORE` (~6184) gains spec 4's sentence on why no wait closes a circle (multiCMD 1.51's `_HeldPermit`).
  - `get_backup_size_inode()` (11801): `leaving` passed to `get_unskipped_size_inodes()` only for the main walk's create or modify
    entry, every call of the `carried_in` subtraction, and the `written` add-back's create or modify entry; never for an attrib.
    Its docstring says so.
  - `get_unskipped_size_inodes()` (11759): a regular file for which `leaving(rel, st)` is true is charged nothing, the entry
    itself (its rel the one its length rule's call computes, kept in a local) and each walked file (`base + rel` of the walk's
    yield, as its `skip` forms it). Its docstring says so.
  - `do_reverb_backup()` (14633): the keyword `names`, its docstring; the closure `copy_or_link()` beside `copy_path()`; its per-batch
    state (`blocks`, made at the first compare; `compare_raised`; `linked`, a dict `{old rel: size}`), the first two rebound in the
    closure with `nonlocal`, as the module's closures do; `copy_path()`'s two `writer.copy()` calls (14798, 14804) call it, the rel
    each entry's copy was given still recorded beside the call (0.55.7 Task 7); the log line.
- Modify: `tests/crash_batches.py`: `backup_events()` (43) becomes `attempt_events()`, the same call returning `committed`, and
  `backup_events()`, which calls it and asserts it. Written in Step 1, with the tests that use it.
- Modify: `tests/test_moves_into_new_folders.py`: the test at 249 (its comment at 268 included) and the two estimate tests (1052, 1076).
- Modify: `tests/test_folder_times.py` (468): the stand-in `lambda path, *args, **kwargs: sized.append(path) or real_size(path,
  *args, **kwargs)`.
- Modify: `README.md` lines 4, 15, 22, 31, 43, 115 (line 43 found by its last words, "copies X/b). The result is right."); `docs/limitations.md`: the three entries of spec 10.
- Modify: `tests/test_no_copy_move.py`.

**Interfaces:**
- Consumes: Tasks 1-3; 0.55.7's `VersionLookError`; `poll_pools` of `do_reverb_backup()`.
- Produces:
  - `do_reverb_backup(..., names:dict = None)`: None and `{}` both mean no names.
  - `get_backup_size_inode(..., *, version_bytes:int, leaving = None)`; `get_unskipped_size_inodes(path, skip_list, block,
    monitor_path, version_bytes, leaving = None)`; `leaving(rel:str, st:os.stat_result) -> bool`.
  - `copy_or_link(source_path:str, rel:str, mcae) -> None`, a closure of `do_reverb_backup()`, spec 4's nine steps in their
    order: 1 no names or `writer.links_refused`: copy; 2 no part of `rel` maps to a rel in the names (`names.get(part) is not
    None`, one dict lookup a part): copy, with no look on disk; 3-5 in one `try` (`except (OSError, VersionLookError)`: copy):
    `os.lstat()`, not a regular file: copy; `old_copy(names, rel, st, writer.previous)` None: copy; `writer.sizes.alone(old,
    writer.two_renames)` False: copy; 6 `same_file(source_path, writer.kept_path(old), blocks)` in a `try` of its own (`except
    Exception`: None, the batch's first an error line `Comparing <source_path> with <kept path> failed; copying it instead` and one
    with `traceback.format_exc()`); 7 `poll_pools()`, once after each compare, before the link or the copy; 8 `GREEN_LIGHT` clear:
    return, neither link nor copy; 9 `kept` not None and `writer.link_kept(old, source_path, rel, pending, kept)`: `linked[old] =
    writer.sizes.shared[old][0]` (the size `linked()` took from the link's own lstat); else the copy. "Copy" is
    `writer.copy(source_path, rel, mcae, pending)`, as today.
  - The log line, right after the replay's stop check (`Reverb backup interrupted before copy threads finished` returns before
    it): of `linked`, the old rels for which `not writer.sizes.alone(old, writer.two_renames)` (an OSError of that look: not
    counted); when there is one, `backuperTeeLogToTl(path=monitor_path, message=f'Reused {count} files, {format_bytes(size,
    use_1024_bytes=True, to_str=True)}B, from {writer.previous} by hard links in place of copies: each had the bytes, mode, owner,
    group, mtime and extended attributes of a file this batch removed from the version')`, `size` the sum of their sizes.
  - `tests/crash_batches.py`: `attempt_events(job, events:list, **kwargs) -> bool`.

- [ ] **Step 1: Write the helpers and the tests** in tests/test_no_copy_move.py (and the `attempt_events()` split). Every batch runs
  through `do_backup()` with raw events (`attempt_events()`; a delete of the old place and a create of the new unless said), with
  `keep_n_versions=0, backup_size_limit='0'` unless said, and ends with `assert_right()`. The helpers of Task 2 (`entries()`,
  `deletes()`, `per_row_deletes_of()`, `moved()`) serve here too. Each test's first comment line says `FAILS` (and why) or `pin` (and
  why), as the Global Constraints have it; a test that works through a stand-in asserts that it was reached. A file with a `user.x`
  attribute starts with `user_xattrs_or_skip()` (tests/test_moves_then_changes.py).

```python
@pytest.fixture(params=['one_rename', 'pooled', 'no_exchange'])
def renames(request, monkeypatch): ...
	# pooled: rv.hand_over wrapped to call the real one with its fifth positional argument (pooled) True, as do_backup() passes it by
	# position; no_exchange: rv.rename_exchange raising EINVAL, as test_on_a_filesystem_with_no_exchange does
def first_version(job, tree, **options) -> dict: ...    # seed_monitor(); run_backup(); {0: snapshot_tree(job.monitor)}
def batch(job, expected, events, **options) -> bool: ...  # the tree snapshotted, attempt_events(); committed: expected[n] = it
def one_inode(job, old_rel, new_rel) -> bool: ...
	# the newest version's new_rel and the version before's old_rel, by read_view(..., inodes)
def assert_right(job, expected, only_sync_attributes=False): ...
	# check_vault(job.job_vault, expected, set(), free_file_meta=only_sync_attributes) == [], and paths_sharing_an_inode() == []
	# for every version (the ground-truth plugin checks each change list's sizes and that no older version changed)
def lines(monkeypatch) -> list: ...                       # a spy on rv.backuperTeeLogToTl: (message, kwargs) of each line
def estimates(monkeypatch) -> list: ...                   # a spy on rv.get_backup_size_inode: each (bytes, inodes) it returned
def compares(monkeypatch) -> list: ...                    # a spy on rv.same_file() that calls it: the (source, kept) of each call
def replaying(monkeypatch) -> SimpleNamespace: ...        # a wrapper of rv.do_reverb_backup() that sets `.on` True for the length of the call (a finally puts it back):
	# the estimate, which do_backup() makes before that call, finds it False, so a stand-in that must act on the replay or the verification tests `.on`
def cpp(path) -> None: ...                                # the first 100 bytes overwritten with b'N' * 100, atime and mtime put back (Session.apply()'s `cpp`, which a test here cannot call)
def poke(path) -> None: ...                               # b'POKED' written at offset 0 of an r+b open, atime and mtime put back (Session.apply()'s `poke`)
```

  The estimate (spec 3), each through the spy:

```python
@pytest.mark.parametrize('where', ['top', 'below'])          # big to n/big; P/big to P/n/big
def test_the_estimate_charges_no_file_of_an_unchanged_move_into_a_new_folder(job, renames, monkeypatch, where):
	# FAILS: the base charges every file of big
	assert estimates(...)[-1] == (sum of st_blocks * 512 of n's folders, their count)   # n's folders alone
	# then: five small versions (a 1 KiB file each), backup_size_limit the vault's size + 1 MiB, big 4 MiB: after the move all five
	# stay (on the base the 4 MiB charge prunes to the newest)
def test_the_estimate_charges_a_file_changed_in_the_move(job, monkeypatch): ...
	# pin: big/a appended in the batch: charged its size, on the base too
def test_the_estimate_charges_a_file_chmodded_in_the_move(job, monkeypatch): ...     # pin: mode differs: charged
def test_an_attrib_copy_is_charged_whatever_its_path(job, monkeypatch): ...
	# pin: OSA off, a chmod of n/big/a in a batch with names: charged
def test_a_renamed_move_is_charged(job, monkeypatch): ...                            # pin: mkdir n; mv f n/g: charged, copied
@pytest.mark.parametrize('case', ['from_the_top', 'from_below', 'renamed', 'full_comparison', 'its_own_old_place',
	'outrun_by_a_folder_move', 'delete_behind_a_move', 'two_creates_one_old_file', 'two_deletes_one_name'])
def test_the_estimate_is_never_above_what_the_batch_writes(job, renames, monkeypatch, case):
	# marked case by case, as the cases are not alike: from_the_top, from_below, full_comparison (every file of the moved folder) and
	# two_creates_one_old_file (one file) FAIL on the base, where each also asserts one_inode(): a copy is another inode there; renamed,
	# its_own_old_place, outrun_by_a_folder_move, delete_behind_a_move and two_deletes_one_name are pins (the spec's) and pass on the base
	# (outrun: mv d e; mkdir e/sub; mv x e/sub/x; behind: mv d/g y; mkdir n; mv d n/d)
	assert est_bytes <= grown_bytes and est_inodes <= grown_inodes   # grown: sizes_by_newest_holder() after less before, summed
# Q25's four causes (spec 3), each: the estimate leaves the file out, and the replay copies it
def test_a_predicted_link_whose_bytes_differ_is_copied_uncharged(job, monkeypatch): ...       # FAILS: the base charges it. `cpp()` of the monitored n/big/a from a wrapper of rv.get_backup_size_inode, after the real call returns: the file is then another than the estimate's walk saw
@pytest.mark.parametrize('case', ['kept_by_the_length_rule', 'folder_where_a_file_was', 'file_where_a_folder_was'])
def test_a_predicted_link_whose_delete_removes_nothing_is_copied_uncharged(job, monkeypatch, case): ...      # FAILS: the base charges it
def test_a_second_file_that_pairs_with_one_old_file_is_copied_uncharged(job, monkeypatch): ...      # FAILS: the base charges both
def test_a_predicted_link_the_vault_refuses_is_copied_uncharged(job, monkeypatch): ...         # FAILS: the base charges it. os.link EPERM on copy names
def test_a_roll_forward_charges_every_copy(job, monkeypatch):
	# pin: a roll-forward has no names. `from tests.test_r_scan import Cut` (tests/test_r_scan.py:29, a BaseException): a rv.do_reverb_backup stand-in raises it on
	# its first call, after the hand-over, and is taken off again; pytest.raises(Cut) around attempt_events(); then run_backup() rolls forward. The estimate that counts
	# is the last one estimates() saw (the roll-forward's; the cut attempt's was the first): it charges n's files, and the replay copies them (not one_inode)

  The copy step (spec 4):

```python
@pytest.mark.parametrize('osa', [True, False], ids=['osa', 'no_osa'])
def test_an_unchanged_file_moved_into_a_new_folder_is_linked(job, renames, monkeypatch, osa):     # FAILS: a copy is another inode
	assert one_inode(job, 'f.bin', 'n/f.bin') and one 'Reused 1 files' line
@pytest.mark.parametrize('osa', [True, False], ids=['osa', 'no_osa'])
def test_an_unchanged_folder_moved_into_a_new_folder_is_linked(job, renames, monkeypatch, osa):     # FAILS: a copy is another inode
	# big/a (300 KiB), big/sub/b, big/empty (0 bytes), big/x with user.x, big/l -> a: the four files one_inode; n/big/l a symlink, as today
@pytest.mark.parametrize('shape', ['P/big:P/new/big', 'P/big:P/a/b/big', 'P/big:Q/n/big'])
def test_a_folder_moved_below_the_top_is_linked(job, shape): ...       # FAILS: every file one_inode with its own old copy
def test_a_move_made_while_down_that_kept_its_name_is_linked(job): ... # FAILS: mkdir n; mv big n/ with no events, then run_backup()
def test_a_tree_unpacked_elsewhere_under_its_name_is_linked(job): ...  # FAILS: tar cpf outside; rm -r big; mkdir r; tar xpf -C r
def test_a_twin_of_the_same_name_size_mtime_and_tail_is_copied(job, monkeypatch): ...
	# FAILS: the compare is never reached on the base (the compares() spy sees 1 call after). `cpp()` of the monitored n/big/a (300 KiB, so its last
	# 64 KiB are the old copy's) before the batch is taken: other bytes at the same name, size, mtime and tail: copied, never linked
def test_a_poke_before_the_compare_is_copied(job, monkeypatch): ...   # FAILS: the compares() spy sees 1 call after. `poke()` of the monitored n/big/a after the events are made: copied
@pytest.mark.parametrize('into', ['not_yet_compared', 'already_compared'])
def test_a_write_during_the_compare(job, monkeypatch, into):
	# FAILS: the read_block() stand-in is never reached on the base. It writes into the monitored n/big/a (3 blocks) after its first
	# block. not_yet_compared: copied, its expected view the tree after the batch (the copy read the write); already_compared: linked to
	# the old bytes, then a modify batch copies the new ones and that version holds them
def test_a_file_replaced_after_the_compare_opened_it_is_judged_as_opened(job, monkeypatch):
	# FAILS: the stand-in is never reached on the base. A no_follow_opener() stand-in that, after opening the monitored file, renames
	# over its path a copy of the old copy made mode 0o600: no version holds the old copy's bytes under mode 0o600
def test_a_compare_that_raises_is_a_copy(job, monkeypatch):
	# FAILS: no error line on the base. BACKUP_SEMAPHORE a Semaphore(1); a read_block() stand-in raising ValueError for two files: both
	# copied; one error line and one traceback line in all; the batch's later copies finish; one permit there after; committed
@pytest.mark.parametrize('shape', ['data_at_both_ends', 'hole_written_as_zeros', 'other_bytes_in_the_hole', 'sparse_alike_differing'])
def test_a_sparse_file_is_compared_by_its_data(job, monkeypatch, shape):
	# FAILS: the read_block() stand-in, which counts the bytes read, is never reached on the base (above 0 in each shape). Task 3's shapes
	# moved into a new folder: linked, linked, copied, copied; the first reads under 4 * COMPARE_BLOCK_BYTES. It starts with Task 3's `holes_or_skip(job.monitor)`
def test_a_source_gone_before_the_compare_is_copied_as_today(job, monkeypatch): ...
	# FAILS: the stand-in is never reached on the base. An old_copy() stand-in that acts only on its first call made while replaying().on (the estimate asks
	# old_copy() first, in do_backup(), before the hand-over: acting there removes the file before the replay's walk, and the test would pass without the copy
	# step's own handling), removes the monitored file and calls the real one: the copy step's lstat (step 3) has seen the file, the compare's open (step 6)
	# does not, so same_file() answers None and the file is copied as today. Asserts: the stand-in was reached while replaying; the lines() spy holds
	# cp_af_copy_path()'s 'Not copying <source> to <dest>: source no longer exists' and no 'Comparing' line; no os.link to a copy name; the batch commits and
	# assert_right() against the monitored tree after the removal
@pytest.mark.parametrize('field', ['mode', 'mtime', 'xattr', pytest.param('owner', marks=needs_root),
	pytest.param('group', marks=needs_root)])
def test_metadata_that_differs_is_copied(job, field): ...
	# pin: chmod, touch, setfattr user.x, chown 1234, chgrp 1235: not one_inode
def test_two_new_files_and_one_old_file_link_one(job, monkeypatch):
	# FAILS: the first is a copy on the base. rm -r big (big/a); n1/big/a and n2/big/a its cp -p: exactly one of them is one inode with the old big/a and the other
	# a copy of its own (which is first is the replay's order: `[one_inode(job, 'big/a', 'n1/big/a'), one_inode(job, 'big/a', 'n2/big/a')].count(True) == 1`);
	# a compares() spy: 1 call
@pytest.mark.parametrize('case', ['renamed_move', 'two_deletes_one_name', 'out_of_a_folder_it_deletes', 'delete_behind_a_move',
	'unpacked_at_its_own_place'])
def test_what_the_names_do_not_reach_is_copied(job, monkeypatch, case):
	# pin: spec 7 items 2-6 (mkdir n; mv big n/other | x/src, y/src deleted, n/src one's bytes | mkdir n; mv a/b/big n/; rm -r a |
	# mv d/g y; mkdir n; mv d n/d | rm -rf d; tar x at d): copied, and the compares() spy sees no call
@pytest.mark.parametrize('case', ['saved_copy_put_back', 'part_of_a_left_folder_moved_back'])
def test_a_true_stand_in_below_a_deleted_entry_of_its_name_is_linked(job, case): ...      # FAILS: a copy is another inode
	# rm other; mkdir n; cp -a <saved> n/other | mv P/X /out/X; mkdir -p Q/X; mv /out/X/sub Q/X/
@pytest.mark.parametrize('code', [errno.EPERM, errno.ENOTSUP, errno.EOPNOTSUPP, errno.ENOSYS, errno.EXDEV, errno.EMLINK])
def test_a_vault_that_refuses_links_copies_the_rest_without_a_compare(job, monkeypatch, code):
	# FAILS: the compares() spy sees 0 calls on the base. An os.link stand-in raising code for paths ending in rv.PARTIAL_COPY_SUFFIX
	# (asserted reached); a moved folder of three files: the first four codes 1 compare, EXDEV and EMLINK 3; three copies each way
def test_a_pool_disk_gone_during_a_compare_fails_before_the_link(job, fake_pool, monkeypatch):
	# FAILS: no PoolNotReady on the base, where the compare is never reached. The vault on `a, b = fake_pool.add(job.vault, ['a', 'b'])`; ONE file
	# moved, so its compare is the last before the batch's waits (with a folder of files, the walk's poll before the next entry would
	# find the drop and the test would pass without step 7); a same_file() stand-in calls the real one, then `fake_pool.drop(b)`:
	# pytest.raises(rv.PoolNotReady); an os.link spy sees no link to a copy name; no copy name in the tree; the version
	# before's file's st_nlink as before the batch
def test_a_failed_record_at_the_link_fails_the_attempt(job, renames, monkeypatch):
	# FAILS: link_kept() is never reached on the base. A TreeWriter.link_kept wrapper sets `inside` around the real call; a
	# TreeWriter.record stand-in raises JobFailure for the link's rel only the first time it is called while `inside` (and counts its calls
	# there: 1). pytest.raises(rv.JobFailure), no link and no copy for the file. A link_kept() that swallowed the JobFailure and
	# returned False would reach copy(), whose own record is not `inside`, so the attempt would commit and the test would fail.
	# Stand-ins off, run_backup() commits and assert_right()
def test_a_failed_flush_at_the_link_fails_the_attempt(job, monkeypatch):
	# FAILS: link_kept() is never reached on the base. On two renames (pooled, rv.hand_over wrapped as `renames` does) pre_record() records and flushes every
	# create and modify of the batch before the replay (replay_ops() lists them), so the link's own record, inline, finds the entry recorded and leaves no flush
	# pending. The same TreeWriter.link_kept wrapper as the record test's, which sets `inside`, also sets `self.needs_flush = True` before the real call (what an
	# inline record leaves pending on two renames), so the flush runs inside link_kept(). n/f.bin is in the base with other bytes; the batch deletes f.bin and
	# overwrites n/f.bin with a `cp -p` of it (a modify). An rv.flush_or_fail stand-in raises JobFailure the first time it is called while `inside` (and counts
	# that call: 1). flush() clears needs_flush before it raises, so a link_kept() that swallowed the JobFailure would reach copy() with nothing left to flush:
	# the copy is queued and the attempt commits, and the test fails. pytest.raises(rv.JobFailure), n/f.bin neither linked nor copied (still the other bytes);
	# stand-ins off, run_backup() commits and assert_right()
@pytest.mark.parametrize('case', ['kept_by_the_length_rule', 'deleted_symlink_at_the_name'])
def test_an_old_place_with_no_file_is_copied(job, case): ...
	# pin: the length rule's kept delete (as tests/test_long_paths.py builds one); a user's symlink big deleted
def test_a_stop_during_the_compare_links_nothing(job, monkeypatch):
	# FAILS: the read_block() stand-in is never reached on the base, where attempt_events() commits. It clears GREEN_LIGHT:
	# attempt_events() is False, no copy name under the tree; GREEN_LIGHT set, the next attempt (run_backup()) commits and assert_right()
def test_a_failed_look_at_the_version_before_is_a_copy(job, monkeypatch): ...
	# FAILS: the stand-in is never reached on the base. EIO from an os.lstat stand-in on the old path (a counter above 0): copied,
	# committed; the estimate's charge for the file is its size (leaving() answers False on the failed look), the spy's bytes
def test_the_verification_links_too(job, monkeypatch): ...
	# FAILS: a copy is another inode on the base. An iter_tree_entries() stand-in, armed by replaying().on and one-shot, leaves n/big/a out of the first listing made
	# while replaying whose root is n's (compared as `path.rstrip('/')`): that is the replay's walk of n, which the estimate's own walk of n (made before the hand-over)
	# cannot take away; the verification, which lists n after it, finds the file missing and copies it (the stand-in reached): one_inode('big/a', 'n/big/a')
def test_a_roll_forward_links_nothing(job, monkeypatch): ...
	# pin: cut as in test_a_roll_forward_charges_every_copy (the same Cut): n's files not one_inode, and its compares() spy sees no call (a roll-forward has no names)
def test_a_file_whose_path_holds_no_name_costs_no_look(job, monkeypatch): ...
	# pin (spec 4 step 2): a batch with names (big deleted, n/ created holding it) and a new file fresh.txt whose path holds no name; an
	# os.lstat stand-in counts the calls on fresh.txt, and the same batch with rv.released_names patched to return {} counts the same
def test_two_names_of_one_monitored_inode_each_link_their_own_old_copy(job): ...      # FAILS: Review Focus 1: big/a and big/a2 one inode in the tree
def test_a_fifo_in_a_moved_folder_is_copied_and_never_opened(job, monkeypatch): ...
	# FAILS: the folder's files are copies on the base. Review Focus 2: big/p a FIFO: committed, the files linked, the FIFO copied as today
def test_a_moved_folder_whose_names_are_not_utf8_is_linked(job): ...
	# FAILS: a copy is another inode. Review Focus 4: os.fsdecode(b'big\xff') holding 'new\nline'
@pytest.mark.parametrize('osa', [True, False], ids=['osa', 'no_osa'])
def test_a_chmod_of_a_linked_file_in_a_later_batch(job, osa):
	# FAILS: the first batch's link (one_inode) is a copy on the base. Linked, then chmod 0o600 of n/big/a (an attrib batch): osa,
	# synced onto the shared inode and the version before's big/a reads 0o600 (assert_right with only_sync_attributes); no_osa,
	# copied, big/a keeps its mode
```

  The books and the link (spec 5, through `do_backup()`):

```python
@pytest.mark.parametrize('record', ['renamed_in', 'exchanged_in', 'walked_by_the_record'])
def test_the_sizes_after_a_link(job, renames, record): ...   # FAILS: one_inode for each file. The ground-truth plugin's lists
def test_the_sizes_after_a_link_kept_by_an_unfold(job, monkeypatch): ...
	# FAILS: linked, and the stand-in is never reached on the base. The batch holds the rows of a full comparison's deletes of D (D/e,
	# D/a, then D: per_row_deletes_of()), so the record of the first unfolds D (ensure_real(): a delete of D alone exchanges D whole
	# in and unfolds nothing); an os.symlink stand-in answers ENAMETOOLONG for D/a's forward link, which is then held by a hard
	# link (a counter above 0); D moved into n: n/D/a linked to it
def test_a_linked_file_the_tree_lets_go_in_its_batch_counts_in_the_version_before(job, monkeypatch):
	# FAILS: the stand-in's link check never runs on the base. A finish_copies() stand-in removes the monitored n/f.bin after the real call has placed the link
	# (before removing, it asserts that the new version's n/f.bin, the placed link, is the old file's inode: the stand-in's own check); the verification then deletes the
	# version's n/f.bin: sizes right, no Reused line
@pytest.mark.parametrize('code', sorted(rv.NO_HARD_LINK_ERRNOS) + [errno.EIO])
def test_a_link_refused_with_each_errno_is_a_copy(job, monkeypatch, code): ...
	# FAILS: the os.link stand-in is never reached on the base (a counter above 0). Copied, sizes right, no PARTIAL_COPY_SUFFIX name
	# in the tree
@pytest.mark.parametrize('swap', ['another_inode_at_the_kept_path', 'symlink_at_the_copy_name'])
def test_a_kept_file_swapped_after_its_compare_is_a_copy(job, monkeypatch, swap):
	# FAILS: the os.link stand-in is never reached on the base (a counter above 0). The os.link stand-in acts on copy names only (a destination ending with
	# rv.PARTIAL_COPY_SUFFIX), as the other stand-ins here do: on two renames the records link too. For the first case it renames over the kept path a cp -p of it, then
	# links; for the second it makes a symlink to the kept file at the copy name and returns (mergerfs's link-exdev symlink modes): copied, no copy name left, the kept
	# file's st_nlink as it was
def test_a_copy_name_that_cannot_be_removed_fails_the_attempt(job, monkeypatch):
	# FAILS: the stand-ins are never reached on the base, which commits. An os.lstat stand-in answering another inode for the copy name,
	# an os.remove stand-in (what remove_entry() calls) raising EIO for it: pytest.raises(rv.JobFailure); stand-ins off, run_backup()
	# commits, paths_sharing_an_inode() [] for every version
def test_a_batch_of_links_alone_flushes_as_a_batch_of_copies(job, renames, monkeypatch): ...
	# FAILS: the files are not linked on the base. A spy on rv.flush_copies: called; one_inode for each file
def test_a_stop_before_a_link_is_placed_leaves_no_copy_name(job, monkeypatch):
	# FAILS: the wrapper is never reached on the base. A TreeWriter.link_kept wrapper clears GREEN_LIGHT after the real one: no
	# PARTIAL_COPY_SUFFIX name in the tree, the version before's file whole and its st_nlink as before the batch
```

  The log line (spec 6):

```python
def test_one_line_a_batch_names_the_files_and_bytes_linked(job, monkeypatch):
	# FAILS: no such line on the base. A moved folder of three files, 300 KiB in all: exactly one line starting 'Reused 3 files, ' with
	# format_bytes(<the sum>, ..)B and the version before's path, at info level (no flag)
def test_no_reused_line_where_nothing_is_linked(job, monkeypatch): ...          # pin: a batch that links nothing writes no such line, as today
def test_a_link_left_unplaced_is_not_counted(job, monkeypatch): ...
	# FAILS: the stand-in's link check never runs on the base (the spec's pin). The first finish_copies() call that holds a link is wrapped (it asserts that its pending
	# entry is a link, task None): before the real call it removes the version's folder above the link's place with shutil.rmtree (the copy name goes with it), puts a
	# symlink there, and removes the monitored file below that folder, so the batch's verification, which finds a link where the monitored tree has a folder, has no file
	# to link again (it would link the same old file a second time, alone() being True once the copy name is gone, and 'Reused 1 files' would come as well from a mutant
	# that counted every link link_kept() made as from the right code). Asserts: the stand-in was reached; no line starting 'Reused'; the batch commits and
	# assert_right() against the monitored tree as the stand-in left it
def test_one_old_file_linked_twice_counts_once(job, monkeypatch): ...
	# FAILS: no link on the base. n1/big/a and n2/big/a, both cp -p of one deleted file, both queued before the replay's one wait: the replay links the first and, alone()
	# being False then, copies the second. A finish_copies() stand-in removes the version's n1/big/a (the placed link) after the real call, so the verification, which finds
	# it missing, links the same old file again: that second link is the verification's. 'Reused 1 files' (the old file once, though linked twice), the stand-in reached

  tests/test_moves_into_new_folders.py:
  - `test_a_folder_moved_into_an_existing_folder_costs_no_copy_and_into_a_new_one_a_copy` becomes
    `test_a_folder_moved_into_an_existing_or_a_new_folder_costs_no_copy`: for all three cases, at both gaps, `{new: after[new]} ==
    {new: inodes[old]}` and `vault_bytes(job) - size < 200000` (the comment at 268 goes with its branch). FAILS on the base for `new`
    and `nested`.
  - `test_the_size_estimate_counts_what_is_written_under_a_folder_moved_into_a_new_one`: `est_inodes == names_in(n) - linked +
    probes`, `linked` the files of `big` the row neither writes nor changes; its bound stays `written <= est_size <= grew`. FAILS
    on the base (the estimate charges every file).
  - `test_the_size_estimate_counts_the_attribute_copies_under_a_folder_moved_into_a_new_one`: the same formula, `linked` the files of
    `big` the row does not touch or chmod (SEED's `big/a` and `big/sub/b`: only h1 to h3 are changed, and they are copied); its
    bound stays `15 << 20 <= est_size <= grew`. FAILS on the base for the same reason.
  - **[Q25]** (b): both keep `est_inodes == names_in(n) + probes` and bound `written <= grew <= est_size` and
    `15 << 20 <= grew <= est_size`; of the estimate tests above only `test_the_estimate_charges_every_file_the_replay_links` (a move
    into a new folder: the estimate charges `big`'s files, the replay links them) is written.
- [ ] **Step 2: Run them on the base.** `RUN t4 auto tests/test_no_copy_move.py tests/test_moves_into_new_folders.py
  tests/test_folder_times.py`: each test tagged `FAILS` fails with the line its tag names, and each tagged `pin` passes (list both
  sets in the handback; the cases of `test_the_estimate_is_never_above_what_the_batch_writes` are marked one by one, as its comment
  says); so do the changed tests of tests/test_moves_into_new_folders.py: the rewritten test at 249 fails for `new` and
  `nested`, and the two estimate tests fail on their inode counts (the attribute-copy one included: `big/a` and `big/sub/b` are
  linked there too). Tasks 1 to 3's pass. A test that does otherwise stops the task. Then grep tests/ for a batch that holds a
  delete of a name and a create or a modify of a file whose path holds that name, in a new folder or an existing one (a move the
  watcher did not pair, a `cp -p` then `rm`), the file unchanged (tests/test_r_sizes.py,
  tests/test_moves_then_changes.py, tests/test_r_batch.py, tests/test_verify_replay.py, tests/test_long_paths.py are the ones to
  read): each that asserts a copy, an inode or a size that a link changes is listed in the handback, and is adjusted as a true
  stand-in (spec 1), never weakened silently.
- [ ] **Step 3: Implement** the Files block, `copy_or_link()` as its Interfaces say.
- [ ] **Step 4: Run** the tests, then `RUN t4 auto tests/test_no_copy_move.py tests/test_moves_into_new_folders.py
  tests/test_folder_times.py tests/test_estimate_charge.py tests/test_estimate_through_a_take.py tests/test_job_startup.py
  tests/test_r_batch.py tests/test_verify_replay.py tests/test_tree_writes.py tests/test_long_paths.py`, then the whole suite
  (tests/test_job_startup.py's copy assert at 309, a rename made while down, stays as it is). tests/test_r_sizes.py needs root:
  the VM gate.
- [ ] **Step 5: Docs.** Spec 10.1 replaces "A folder or file moved into a new folder is copied whole" whole; 10.2's insertions,
  its links sentences and its Why, Revisit when and Approved additions; 10.3's six README lines; 10.4's sentence, its revisit
  clause dropped and its Approved addition. Each text word for word, `<Q24's answer>` and `<Q25's answer>` as the brief gives them.
  10.3's "(line 17)" is checked against the merged README (the line on a file made in the batch and moved): a moved number is
  written as it now is. The `docs/limitations.md` sentences the texts are placed by ("and a move that falls back to a copy, ..." and
  "Also when the no-copy move into a new folder gets its own design.") are wrapped across lines: find them by their words, not by a
  one-line grep. **[Q25]** (b): 10.2's estimate sentence and line 31's estimate clause are not written, and 10.1's clause reads as
  its [Q25] note says.
- [ ] **Step 6: Commit.** **main session: VM gate** after it: the whole suite as root in the VM (this commit is where files start
  linking, so any module with batches of its own may break; it includes the owner and group cases of
  `test_metadata_that_differs_is_copied` and `tests/test_r_sizes.py`).

**Acceptance:** each unchanged file of a move into a new folder that keeps its name is one inode with its old copy, every other
copy is today's, the estimate leaves exactly the files the lookup finds uncharged, one Reused line a batch that linked, and the
docs say so.

---

### Task 5: The real watcher shows what links (spec 9, tests/test_moves_into_new_folders.py) [Q24]

Tests and their comments only; each new test passes on Task 4's code, so each says `# pin:` and its reason (the real watcher's
batches link what the spec says); the edits of existing tests are no new tests.

**Files:**
- Modify: `tests/test_moves_into_new_folders.py`: `assert_held_as_the_tree()` (230); the module docstring (1-7); a new test after
  the MATRIX test; the `at_once` stress test (338); the found-folder tests at 373, 699, 739, 763, 784;
  `test_on_a_filesystem_with_no_exchange` (974); `test_a_file_moved_out_is_not_taken_for_a_new_folders_file_of_its_name` (398) and
  `test_a_write_with_its_mtime_set_back_in_a_moved_in_file_is_in_a_version` (417); and the comments of the table below.

**Interfaces:**
- Consumes: Task 1's `paths_sharing_an_inode()`; this module's `inodes_of()`, `version_view()`, SHAPES, TIMINGS.

- [ ] **Step 1: Write the tests and changes.**

```python
LINKS = {   # shape: (rels linked, each to its old rel; rels copied)
	'folder': ({'n/big/a': 'big/a', 'n/big/sub/b': 'big/sub/b'}, ()), 'file': ({'n/f.txt': 'f.txt'}, ()),
	'nested': ({'p/q/r/big/a': 'big/a', 'p/q/r/big/sub/b': 'big/sub/b'}, ()), 'file_renamed': ({}, ('n/renamed',)),
	'changed_before': ({'n/big/sub/b': 'big/sub/b'}, ('n/big/a',)), 'changed_between': ({'n/big/sub/b': 'big/sub/b'}, ('n/big/a',)),
	'folder_chmod_in': ({'n/big/sub/b': 'big/sub/b'}, ('n/big/a',)), 'its_own_old_place': ({}, ('big/big/a', 'big/big/sub/b')),
	'a_file_made_in_the_batch': ({}, ('n/made',)),
}

@pytest.mark.parametrize('timing', TIMINGS)
@pytest.mark.parametrize('name', list(LINKS))
def test_what_a_move_into_a_new_folder_links(session, job, name, timing):
	# pin: Task 4's links on the real watcher
	linked, copied = LINKS[name]
	one = session()                                    # the MATRIX test's way: the session's default seed, Only Sync Attributes on
	before = inodes_of(job)
	one.run(dict(SHAPES)[name], timing)
	one.back_up_next()
	after = inodes_of(job)
	assert {new: after[new] for new in linked} == {new: before[old] for new, old in linked.items()}
	assert not {after[rel] for rel in copied} & set(before.values())
```

  - `assert_held_as_the_tree()` gains `paths_sharing_an_inode(job.job_vault, <folder>) == []` for the newest version and
    `previous`; the stress test gains the same after each of its two batches.
  - `..._whose_event_comes_is_a_copy` becomes `..._is_linked` (`n/big/a`, `n/big/sub/b` one inode with `big/a`, `big/sub/b`);
    `..._while_it_is_walked_is_copied` becomes `..._links_its_unchanged_files` (`<into>/a`, written with its mtime set back, copied;
    `<into>/sub/b` linked; `m/x` copied); `..._after_its_parents_walk_listed_it_is_copied` becomes `..._is_linked` (`p/q/big/f0` to
    `f3`); `..._before_its_subfolder_is_listed_is_copied` becomes `..._is_linked` (`m/s/big/a`, `m/s/big/sub/b`);
    `..._moved_on_in_a_later_read_ends_as_the_tree` asserts `n2/big/a` and `n2/big/sub/b` linked.
  - `test_on_a_filesystem_with_no_exchange`: `n/big/a`, `n/big/sub/b` and `n/f.txt` linked; `n/big/z` copied.
  - `test_a_file_moved_out_is_not_taken_for_a_new_folders_file_of_its_name`: the newest `n/f.bin`'s inode is not the old `f.bin`'s.
  - Every comment of this table, and the docstring, say what its test now asserts (linked, or copied where it is). Each is found by
    its test and the words quoted, not by line (the numbers are r0556's); a quote can run over two comment lines of the test (the rows
    of `..._from_outside_while_it_is_walked_is_copied`, `..._made_after_its_parents_walk_listed_it_is_copied` and
    `test_a_file_moved_out_is_not_taken_...` do), so read each comment to its end before rewriting it:

| Test (a rename of it is Task 5's) | Comment, quoted | Now says |
|---|---|---|
| the module docstring | "is copied once with that folder, as on 0.55" | an unchanged file of such a move is linked to its old copy, a changed one copied; the version ends as the tree |
| the SHAPES entry `changed_between` | "the copy of the folder must be made after it" | the poked file is compared in full and copied, its neighbours linked |
| `test_a_move_in_that_the_walk_saw_and_whose_event_comes_is_a_copy` | "the walk got there first, so the copy of the new folder holds it, as on 0.55: the event is discarded" | the walk got there first and the event is discarded; the new folder's unchanged files link to their old copies |
| `test_a_folder_renamed_twice_in_a_new_folder_before_the_walk_lists_it_keeps_its_changed_bytes` | "the copy holds it: the first move, read after that walk, is no move to keep" | the changed file is copied (the compare tells it), the rest linked |
| `test_another_folders_move_out_among_a_folders_rename_events_is_never_its_move` | "the move-out of big is a delete and n is copied, never a move from other/y" | the move-out of big is a delete, n's unchanged files link to big's old copies, never a move from other/y |
| `test_a_write_kept_at_its_size_and_mtime_in_a_folder_the_walk_found_moved_in_is_in_a_version` | "a's copy holds big, and a write in it" | a's walk holds big; the written file is copied (compared in full), the rest linked |
| `test_a_folder_moved_into_a_folder_from_outside_while_it_is_walked_is_copied` | "m's copy holds big, and a write in it made so that only its event can show it" | m's walk holds big; its unchanged files link, the written one is copied |
| `test_a_folder_moved_into_a_new_folder_made_after_its_parents_walk_listed_it_is_copied` | "p's copy holds big, as on 0.55" | p's walk holds big, its files linked |
| `test_a_folder_the_walk_found_moved_in_and_moved_on_in_a_later_read_ends_as_the_tree` | "out of the new folder n whose copy holds it" | out of the new folder n whose walk holds it, its files linked |
| `test_a_folder_moved_into_a_folder_from_outside_before_its_subfolder_is_listed_is_copied` | "so big is copied with m, as on 0.55, and its move-out is its delete" | big is walked with m and its files linked by the name of its delete |
| `test_a_move_out_waiting_at_the_place_a_folder_is_moved_to_is_its_delete_first` | "must not remove the copied one" | must not remove the new folder's file |
| `test_a_take_and_its_copy_between_the_mv_and_its_read` | "the copy holds the folder" | the walk (and its links) holds the folder |
| `test_a_file_moved_out_is_not_taken_for_a_new_folders_file_of_its_name` | "no comparison tells them apart, so the version must get the new file's bytes from a copy" | the name pairs them and the compare of every byte tells them apart, so the version gets the new file's bytes from a copy |
| `test_a_write_with_its_mtime_set_back_in_a_moved_in_file_is_in_a_version` | "nothing tells a comparison of this write but the event, so what holds the file must be a copy made after it" | the compare of every byte tells this write, so the file is copied and the version holds it |

  The comment of the test at 249 (the "whatever the gap, as on 0.55" line) is Task 4's: its branch is rewritten there.
- [ ] **Step 2: Run** `RUN t5 auto tests/test_moves_into_new_folders.py tests/test_watcher_fuzz.py`: all pass. A test that shows
  otherwise (a found folder copied, say) is a finding: report it, do not loosen the assert.
- [ ] **Step 3: Run** the whole suite; commit.

**Acceptance:** on the real watcher every shape links exactly what the spec says, and no version holds two paths on one inode.

---

### Task 6: The builder's measurements and the fuzz's twin step (spec 9; build step 4) [Q24] [Q25]

**Files:**
- Modify: `tests/test_watcher_fuzz.py`: `step()` (45) gains the kind `twin` (weight 3); the round's oracle gains
  `paths_sharing_an_inode()`.
- Measurement scripts stay in the scratch folder, never committed.

- [ ] **Step 1: The twin step.** `twin`: a file of the tree, a new folder `n<k>` (`k` in `range(3)`) under `where()`,
  `shutil.copy2()` of the file into it under its own name, one time in two the copy poked (`f.write(b'POKED')` at offset 0 of an
  `r+b` open of it, then `os.utime()` back to the copy's own `st_atime_ns` and `st_mtime_ns`, as `Session.apply()`'s `poke` does in
  tests/test_moves_into_new_folders.py), then the original removed; logged as `('twin', source, copy, poked)`. After each round,
  every version folder's `paths_sharing_an_inode()` is `[]`, else `fail()`. A pin (`# pin:`: it checks Task 4's links under random
  batches; no `reverberator.py` changes here).
- [ ] **Step 2: Run** `RUN t6 auto tests/test_watcher_fuzz.py` (its default sample of 64 seeds; the longer run is the main session's, Task 9).
- [ ] **Step 3: Measure** (container, uid 65534, warm, each three runs, each figure in a fresh process: `VmHWM` in `/proc/self/status`
  is the process's high-water mark since it started, so a linked and a copied run in one process cannot be told apart): the replay's
  time and `VmHWM` after it, linked against copied (`rv.released_names` patched to return `{}`), for a 1 GiB file and for a folder
  of 10,000 files of 4 KiB moved into a new folder, with `COMPARE_BLOCK_BYTES` 256 KiB and 1 MiB; `released_names()` of a full
  comparison's 1,000,000 per-row deletes; **[Q25]** (b): not this one: `get_backup_size_inode()` over a moved folder of 100,000
  files with `leaving` and without. A linked move much slower than its copy is a finding.
- [ ] **Step 4: Commit** the fuzz step; the figures in the handback.

**Acceptance:** the fuzz draws twins, poked and not, and every round's vault holds no two paths of a version on one inode; the
figures are in the handback.

---

### Task 7: The crash, power-loss and pool tests (spec 9, Crash and The pool) [Q24]

Written by the builder; the tests that need root, a pool or mergerfs skip outside the VM, and **main session: VM gate** runs them, and
runs the modules that build the crash seed before the commit (Step 2); Task 9 runs the set again. The one hand-built test of the
checker needs no root and runs in the container. This task changes no `reverberator.py`: its tests of Task 4's links are pins, run on
Task 4's code, and the tests of its own helper `link_shape_wrong()` fail with tests/crash_batches.py swapped for its parent's (the VM
gate's base run, Global Constraints).

**Files:**
- Modify: `tests/crash_batches.py`: `seed_base()` gains `kept.bin` (`past_inline('KB')`) and `keptdir/k.bin`
  (`past_inline('KD')`); `change_batch3()` makes `reused`, moves `kept.bin` and `keptdir` into it, and its events gain
  `(False, 'delete', 'kept.bin', None), (True, 'delete', 'keptdir', None), (True, 'create', 'reused', None)`; new
  `link_shape_wrong()`.
- Modify: `tests/test_no_copy_move.py`: the hand-built test of `link_shape_wrong()`.
- Modify: `tests/test_crash_harness.py`: `wrong_after_retry()` (452); the `problems` line of `test_every_kill_point_on_the_054_layout`
  (410); `test_the_kill_points_cover_every_kind_of_call` (393); new tests after `test_batch_3_has_an_attribute_change_on_a_shared_inode`
  and after `test_a_daemon_gone_wrong_is_caught`.
- Modify: `tests/test_crash_power_loss.py`: its `problems` (244).
- Modify: `tests/test_pool_cut.py`: `MixedBatch.wrong()` (813); a new shape; `SHAPES` (1045).
- Modify: `tests/test_pool_writer.py`: `wrong_after_retry()` (85); `real_pool()` (738) gains `options=MERGERFS_OPTIONS`; a new test after
  `test_hard_links_on_a_pool_read_as_one_inode_and_their_count_as_it_is`.

**Interfaces:**
- Produces: `link_shape_wrong(job_vault:str) -> list`: a line for each version whose `paths_sharing_an_inode()` is not `[]`, and one
  when `rv.measure_previous(<version before>, <newest>)` differs from `sizes_by_newest_holder()`'s entry for the version before (the
  two newest committed versions).

- [ ] **Step 1: Write the changes.**
  - `wrong_after_retry()` of tests/test_crash_harness.py and of tests/test_pool_writer.py (the judgement of `test_every_kill_point_on_a_pool`
    and of `test_a_filesystem_without_exchange_uses_two_renames`, which run batch 3 on a pool and on two renames), the `problems` line of
    `test_every_kill_point_on_the_054_layout` (it judges by its own `check_vault(..., folder_times=False)`, not by `wrong_after_retry()`,
    and runs batch 3 after the conversion, so it links too), test_crash_power_loss.py's `problems`, and `MixedBatch.wrong()` each add
    `link_shape_wrong(job_vault)`. These are edits of existing judgements: no new test, no mark.
  - `test_the_kill_points_cover_every_kind_of_call`: `'link'` among its kinds (an edit of an existing test: records link too, so it
    passes on the base; the batch-3 test below shows the batch links).
  - `test_batch_3_links_its_two_moves_into_a_new_folder(r_vault)`: # pin: the uncut batch commits, and V3's `reused/kept.bin` and
    `reused/keptdir/k.bin` are one inode with V2's `kept.bin` and `keptdir/k.bin`; so the sweeps cut through `link_kept()`, the
    placement and the commit.
  - The checker is seen to catch what it checks (the existing `test_a_daemon_gone_wrong_is_caught` does so for other faults). Each
    `link_shape_wrong` import is inside its test (Global Constraints).
    - tests/test_no_copy_move.py, `test_link_shape_wrong_names_a_version_holding_two_paths_of_one_inode(tmp_path, monkeypatch)`
      (no root: a hand-built vault): # FAILS: no `link_shape_wrong()`. A vault of two versions as
      `test_the_newest_holder_counts_each_inode_once` builds one, the newest holding `d/x` and `y` as one inode (`os.link`):
      `link_shape_wrong()` has a line naming the newest version and both rels; with `y` its own file, `[]`. Then, with `rv.measure_previous`
      patched to return `(1, 1)` (and called: a counter above 0), the same vault with `y` its own file has a line naming the version
      before and both counts: the size line fires, which no real batch shows while the daemon is right.
    - tests/test_crash_harness.py, two tests of the faults below, each on `plain_r_vault` (`cut_batch(plain_r_vault, fault=...)`; batch 3
      links on Task 4's code) and each asserting `.error is None` first and that its fault fired. The fault is a function of the child's
      `rv`, as `wrong_contents()` is, and writes a line to a file the test names, as the child is a fork and a list does not come back:

      ```python
      def second_name_of_the_kept_inode(rv, fired):
      	real = rv.TreeWriter.link_kept
      	def link_kept(self, kept_rel, source, rel, pending, kept):
      		linked = real(self, kept_rel, source, rel, pending, kept)
      		if linked:     # a second name of the kept file in the version before: the batch never sweeps it (sweep_version_folder() removes what no row tracks under the newest version's touched subtrees, where a second name beside the link would go)
      			os.link(self.kept_path(kept_rel), os.path.join(self.previous, 'kept_twin'))
      			with open(fired, 'a') as f:
      				f.write('x\n')
      		return linked
      	rv.TreeWriter.link_kept = link_kept

      def sizes_not_told(rv, fired):
      	def linked(self, rel, size, links):      # BatchSizes.linked() a no-op: the version before is counted beside the newest
      		with open(fired, 'a') as f:
      			f.write('x\n')
      	rv.BatchSizes.linked = linked
      ```

      `test_a_daemon_that_makes_a_second_name_of_a_kept_inode_is_caught(plain_r_vault, tmp_path)`: # FAILS: no `link_shape_wrong()`;
      `os.path.getsize(fired) > 0` and `link_shape_wrong(job_vault) != []`.
      `test_a_daemon_that_does_not_tell_the_books_of_its_links_is_caught(plain_r_vault, tmp_path)`: # pin: what it checks, the lists check
      every sweep runs, exists already, and on Task 4's code batch 3's moves link, so the no-op is reached (`os.path.getsize(fired) > 0`,
      which is 0 where nothing links); `view_truth.wrong_lists(job_vault) != []`.
  - `class MixedBatchManifestLost(MixedBatch)`, `batch = 'mixed-manifest-lost'`: `again()` removes the vault database first, as
    tests/test_crash_harness.py's `lose_the_manifest()` does; `wrong()` leaves folder times out, as `test_every_kill_point_on_r`
    does over a lost manifest. `SHAPES['mixed-manifest-lost-2'] = (MixedBatchManifestLost, 2)`. Its class docstring says `# pin:` and why
    (its sweeps pass on Task 4's code, and run only in the VM).
  - `test_a_link_into_a_new_folder_on_a_pool_is_made_or_copied_as_mergerfs_answers` (`privileged`, `needs_mergerfs`; # pin: its three
    runs pass on Task 4's code, in the VM),
    parametrized `['linked', 'exdev', 'rel_symlink']`: the old copy on one branch, the new folder made on the other; the options
    that make mergerfs link, answer EXDEV, and (`link-exdev=rel-symlink`) make a symlink, taken from mergerfs's documentation and
    named in the test. Each asserts its own outcome (one inode across the two versions; a copy after the EXDEV; a copy, with no
    symlink at a copy name, after the symlink), never "linked or copied"; then `check_vault()`, the lists, and the times of the
    folders mergerfs made for the link as the batch gave them.
- [ ] **Step 2: Check the seed's consumers.** The seed and batch 3 feed every module that builds the crash vault: find them with
  `grep -ln "build_base\|seed_base\|change_batch3\|apply_batch3\|batch3_of\|prepared(" tests/*.py` (a bare `prepare(` also matches
  other modules' own helpers, which build no crash seed: read each hit). At this commit they are tests/test_r_batch.py,
  tests/test_r_sizes.py, tests/test_r_scan.py and, through its `build_base`, tests/test_first_start.py, tests/test_version_walk.py,
  tests/test_r_readers.py, tests/test_crash_harness.py, tests/test_history_recheck.py, tests/test_pool_writer.py,
  tests/test_pool_cut.py, tests/test_crash_power_loss.py, and `seed_base()` and `change_batch3()` in tests/test_migration.py.
  `seed_base()` chowns `owned.txt` (crash_batches.py:78), which is EPERM as uid 65534, so none of them runs in the container. The
  builder reads each for a count tied to the seed or to batch 3 (files, inodes, bytes, events, versions' contents) and gives it its
  new value, each named in the handback. **main session: VM gate, before Step 3's commit:** those modules run in the VM with the new
  seed (the builder is told what fails and fixes it), then the whole suite in the container.
- [ ] **Step 3: Commit.**

**Acceptance:** batch 3 links two files past the inline size; every crash, power-loss and pool-cut judgement, the 0.54 layout's
sweep and the pool writer's sweeps also find two paths of a version on one inode and books that disagree with the vault, and the
checker is seen to find them; the pool test forces each of mergerfs's three answers.

---

### Task 8: The version number [Q24]

**Files:**
- Modify: `reverberator.py` (`__version__`, 63), `pyproject.toml` (`version`, 3).

- [ ] `__version__` and `version` become the number the main session gives (0.55.8 in the texts). The whole suite; commit.

---

### Task 9: The VM gates and measurements (the main session's) [Q24] [Q25]

**Files:**
- Modify: `docs/limitations.md` (the figure's commit, 10.1's sentence); nothing else is committed here. The figures and the cold
  figure go in P3's row of `docs/progress.md`, which is the main session's.

- [ ] **The VM gates** (each also ran after its task's commit, Global Constraints, Venues): `tests/test_tree_writer.py`,
  `tests/test_r_sizes.py`, `tests/test_pool_writer.py` and the two root tests of `tests/test_verify_replay.py` that run whole batches
  (Task 1); the whole suite as root (Task 4, which includes the owner and group cases); the modules that build the crash seed (Task 7);
  the crash harness and the power cuts with `REVERB_CRASH_FULL=1` (the default stride may miss every link step), and the pool
  writer's sweeps (`test_every_kill_point_on_a_pool`, `test_a_filesystem_without_exchange_uses_two_renames`) with `REVERB_CRASH_FULL=1`
  too (their `kill_points()` reads it); the pool cut, both manifest shapes (`MixedBatch`, the manifest kept, and
  `MixedBatchManifestLost`, the manifest lost), with `REVERB_POOL_CUT=full` (its default sample is `SAMPLE_RUNS = 30` over the shapes,
  5 runs a shape, and may miss every link step); the pool's three runs; the whole suite in the VM as root. A skip counts as a failure.
- [ ] **The longer fuzz run:** `RUN t9 auto tests/test_watcher_fuzz.py` with `REVERB_WATCH_FUZZ=256` (four times the suite's sample of
  64: a failing seed is then a finding, and the run's time is in P3's row).
- [ ] **The real daemon** (spec 9): a scratch job in the container as uid 65534 or in the VM; `mkdir new; mv big new/` for a folder
  of 1,000 files of 100,000 bytes and for a 100 MB file, at the top and below it (below: `big` is `P/big` and the commands run in `P`,
  `cd P`), at gaps of 0, 1 ms and 1 s, as two system calls of one program and as a shell's two commands, each again with a poke
  before, between and after; the size-limit run (five small versions, then the move; **[Q25]** (a): all five stay; (b): only the
  newest stays, as today). The vault's growth (expected under 0.1 MB, a poked file adding its size), the lines, the replay's time
  against today's copy. A VM figure is labelled so.
- [ ] **The figure's commit:** 10.1's "is expected to cost about what a move into an existing folder costs (under 0.1 MB for a
  100 MB folder of 1,000 files)" in `docs/limitations.md` becomes "costs about ... (<the measured figure> for a 100 MB folder of
  1,000 files on the real daemon)", its own commit; a figure off the expected one is a finding first.
- [ ] **After the deploy:** the cold figure from the live backups (the first linked move's `Processing` to `Reused` lines against
  the same job's latest like copy before the deploy), in P3's row.
- [ ] **The gates:** the whole suite in the container fails only `r_base_fails.txt`'s tests; the mergerfs and power-loss tests are
  in the release gate (a standing decision).

---

## Calls to confirm

1. The spec's build step 3 is three commits: Task 3 (`same_file()` and its seams, read by nothing), Task 4 (the copy step, the
   estimate, the log line, every test their change breaks and section 10's texts: the spec's one commit) and Task 5 (real-watcher
   tests that pass on Task 4's code and gain assertions). Each commit's suite passes; the reason is the size of one review.
2. The crash, power-loss and pool tests are a builder task of their own (Task 7): the spec's step 4 names only their runs.
3. Batch 3 seeds `kept.bin` and `keptdir/k.bin` past the inline size and moves both into `reused/`; a new test pins that the uncut
   batch links both, as the `link` kind alone passes on the base (records link too).
4. The pool cut gains a lost-manifest shape (`MixedBatchManifestLost`), the spec's "over a lost one", which that test has not had.
5. `link_shape_wrong()` lives in tests/crash_batches.py, not tests/vault_oracle.py: it calls `measure_previous()`, and the oracle
   shares no code with the daemon. It is added to tests/test_pool_writer.py's `wrong_after_retry()` too: the spec names the crash,
   power-loss and pool-cut judgements, and the pool writer's sweeps run batch 3 on a pool and on two renames as well.
6. `released_names()` marks an ambiguous name with None, and `copy_or_link()`'s step 2 counts only a name that maps to a rel, so an
   ambiguous one costs no lstat (`old_copy()` would pass it over anyway).
7. `do_reverb_backup(names=None)`: None is the empty default.
8. The log line: the size as `format_bytes(size, use_1024_bytes=True, to_str=True)` followed by `B` (the change list's call, with the
   unit the memory lines add), as the spec names `format_bytes()`; the size is the one `linked()` took from the link's own lstat
   (`writer.sizes.shared[old][0]`); `<version>` is the version before's full path (`writer.previous`); "files" for one too, as the
   spec fixes the text; written right after the replay's stop check, before the folders settle, so a stop writes none. For the
   main session: `show_size()` (reverberator.py:15805) is the daemon's own byte count for people ("1.50 KiB", "512 B") where this
   prints "512.00 B" below 1 KiB; using it is a change of the spec's named helper, so it is not made here.
9. `copy_or_link()`'s error line for a compare that raised: `Comparing <source> with <kept path> failed; copying it instead`, then
   the traceback (the spec gives the count, not the words).
10. On the merged 0.55.7, `copy_path()`'s own look at the source is `monitored_there()` (its Task 6), not `os.path.lexists()`: it
    stays the one look a file with no name costs, and 0.55.7 Task 7's record of the rel stays at `copy_or_link()`'s call.
11. Tests the spec does not list: `test_a_finished_link_is_placed_and_one_whose_folder_became_a_link_is_left`,
    `test_link_kept_does_nothing_for_a_file_the_tree_still_holds` and
    `test_link_kept_is_false_and_leaves_no_copy_name_when_the_link_or_the_look_fails` (Task 1: spec 5's first check, its identity check
    and its errnos, `links_refused`, at the writer's door), the direct tests of `same_file()` (Task 3: block edges, unequal lengths,
    the opener's one open a file and the inode of the handle, the metadata split into mode and mtime, user attributes and the fd
    forms), the Review Focus five, `test_no_reused_line_where_nothing_is_linked` and `test_a_link_left_unplaced_is_not_counted` as their
    own tests (the spec's pins), a `VersionLookError` case, a name with no file below it and a deleted file's name as a folder in
    `old_copy()`'s test, the flush case of the failed-record test (a link that swallowed its JobFailure would copy where the record's
    flush never reached the disks), `test_a_file_whose_path_holds_no_name_costs_no_look` (spec 4 step 2 and the spec's Call 22: the goal
    is lightness), and the two tests of the crash checker (Task 7), each of which fails alone for its own fault.
12. `test_alone_answers_for_each_kind_of_record` builds a vault with no root record, so it runs in the container; its twelve cases
    are the spec's ten kinds (the copy and the renamed move two cases each), deletes go by `rm()`, which waits for the removal as
    `stop_copies()` does, and `remove_now()` is its own kind. The spec's "a record copied" is made by `writer.record('f', True)` with
    the `os.link` stand-in answering EMLINK for it (a keep, so on one rename too: a delete's own record renames the file and makes no
    link), and the answer expected is True while the tree still holds f, as another inode.
13. The copied case of `test_a_write_during_the_compare` expects the tree after the batch, as the copy read the write.
14. README line numbers are r0556's; each text is found by the sentence it replaces, and 10.3's "(line 17)" is checked against the
    merged README.
15. tests/test_tree_writer.py's `handed_over()` gains `pooled`; tests/test_pool_writer.py's `real_pool()` gains `options`.
16. The fuzz's `twin` step has weight 3 of the choices, which changes the steps every seed draws.
17. The release number is the main session's (Task 8); the texts say 0.55.8.
18. Every new test carries `# FAILS` or `# pin` in its first comment line and a stand-in test asserts that its stand-in was reached
    (the Global Constraints): the spec says each outcome is forced by its own test; this keeps one from passing without the code.
    Tasks 5 and 7 and the fuzz step change no `reverberator.py`, so their tests of Task 4's links are pins, run on Task 4's code; the
    tests of Task 7's own helper `link_shape_wrong()` fail with its file swapped for its parent's, and the checker's fault test of the
    books is a pin that asserts its fault fired.
19. Task 5 rewrites the reasons of the two comments the spec says stay (the tests at 398 and 418, their comments at 399 and 419: "no
    comparison tells them apart" and "nothing tells a comparison of this write but the event" stop being true with the full compare);
    what they assert, a copy, stays.
20. The VM gates run after each marked task's commit and once on the base (the parent's `reverberator.py`, and for Task 7, which changes
    none, the parent's tests/crash_batches.py), the seed's consumers run in the VM before Task 7's commit (a chown makes them
    root-only), and Task 4's gate is the whole suite as root, as that is the commit where files start linking and any module with
    its own batches could break; the spec's step 4 puts the VM gates at the end and names only the owner and group cases for Task 4.
21. Task 9 runs the pool cut at `REVERB_POOL_CUT=full` and the pool writer's sweeps at `REVERB_CRASH_FULL=1`, and the fuzz at 256
    seeds (four times the suite's 64): the spec leaves a longer run to the main session, and the default samples may miss every link
    step; the main session may sample by the time it has and say so.
22. The plan is not reviewed again before the build: the build's own gates check its tests from here (each new test's run on the base
    and on the task, with its first failure line in the handback; the per-task reviews; the final review). A test that does not fail
    where this plan says it fails, or passes for a reason other than the code's, stops its task as the Global Constraints say.
