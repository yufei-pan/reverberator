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
| Q25, the estimate and a file it expects the copy step to link (spec 3) | (a) the estimate leaves such a file out; the entry is widened | (b): Task 4 builds no `leaving` (no change to `do_backup()`'s estimate call, `get_backup_size_inode()`, `get_unskipped_size_inodes()` or tests/test_folder_times.py); its estimate tests give way to one pin; the two estimate tests of tests/test_moves_into_new_folders.py keep their inodes and bound the other way; 10.2's estimate sentence and README line 31's estimate clause are not written, and 10.1's estimate clause reads as its [Q25] note says |

An answer reversed after the build is its own change: Task 4's **[Q25]** lines say what it is.

## Global Constraints

- Build in a worktree of its own, on a branch the main session makes from the merged 0.55.7 once Q24 and Q25 are answered (spec
  11, "a precondition"). Line numbers are of `reverberator.py` at e166baa (18,251 lines; r0556 holds the same file) and of
  `tests/` and `README.md` on r0556. 0.55.7 and earlier tasks move them: find each place by its function name, and each README
  or limitations text by the sentence it replaces.
- From 0.55.7 this round uses `VersionLookError` (its plan's Task 5), `real_folders_to(strict=True)` answering False for ENOTDIR
  (its spec section 7), `monitored_there()` in `copy_path()` (its Task 6) and the rel `copy_path()` records for each entry's copy
  (its Task 7). None of them is written here.
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
  harness), loop mounts, real mergerfs and power-loss runs go in the test VM, through its gate (the main session's): such steps are
  marked **main session: VM gate**, builders write them to skip outside the VM with a reason (`needs_root`, `needs_mergerfs`, or
  the module's own root skip) and do not run them, and Task 9 runs them; a skip at the VM gate counts as a failure.
- **The memory rule:** start a container only while `full avg60` in `/proc/pressure/memory` is under 5 and MemAvailable minus the
  container's cap is at least 8 GB; under 5 GB free, or at 5, the newest run stops and goes back in the queue (the runner waits).
- **The whole suite:** `RUN t<N>-all auto`, then `comm -13 <out>/r_base_fails.txt <out>/r_t<N>-all_fails.txt` prints nothing: the
  branch fails nothing its base does not. `r_base_fails.txt` is made once, before Task 1, by `RUN base auto` at the branch point.
- **"Fails on the base"** means: the new test, run on the branch before this task's change (the base plus the earlier tasks), fails
  as the task says. Write its first failure line in the handback. A test that does not fail there stops the task: report it.
  **Pins** say `# pin:` in their first comment line and pass before and after the change.
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
- Test: `tests/test_tree_writer.py` (its module skips unless root: **main session: VM gate**), `tests/test_tree_writes.py`.

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
  - `TreeWriter.link_kept(self, kept_rel:str, source:str, rel:str, pending:list, kept:tuple) -> bool`: spec 5's five steps, `kept`
    the `(st_dev, st_ino)` the compare read. True: a `PendingCopy(None, source, temp, self.path(rel))` appended, the books told
    (`linked(kept_rel, st.st_size, links)` from one lstat of the copy name, `links` `links_now(temp)` on two renames, `st_nlink`
    elsewhere). False: nothing linked, no copy name left. Sets `links_refused` when `os.link()` itself answers EPERM, ENOTSUP,
    EOPNOTSUPP or ENOSYS. Raises JobFailure (a record, a flush, a copy name that cannot be removed) and `_folders_for_copy()`'s
    NotARealFolder, as `copy()` raises them.
  - `finish_copies()`: an entry whose `task` is None is a link already made: no lines, succeeded; placed and returned as a finished
    copy is, or left with its row dropped where a folder above its place is no longer real.
  - `paths_sharing_an_inode(job_vault:str, folder_name:str) -> list`: each group of two or more rels of the version that are one
    inode, read through `read_view(job_vault, folder_name, inodes)`, as a sorted list of sorted tuples; `[]` when none.

- [ ] **Step 1: Write the tests.**

```python
# tests/test_no_copy_move.py
RECORD_KINDS = ['folder_deleted_whole', 'top_file_deleted', 'file_then_its_folder', 'copy_before_placement', 'copy_after_placement',
	'renamed_file', 'renamed_folder', 'moved_out_of_a_folder_then_it_removed', 'name_refilled_then_removed',
	'unfold_kept_by_a_hard_link', 'record_copied', 'remove_now']

@pytest.mark.parametrize('pooled', [None, True], ids=['one_rename', 'two_renames'])
@pytest.mark.parametrize('kind', RECORD_KINDS)
def test_alone_answers_for_each_kind_of_record(tmp_path, monkeypatch, kind, pooled):
	# a vault of the test's own, with no root record (so no root needed), V1 holding the files the kind needs, handed over to V2
	# (rv.hand_over(..., pooled=pooled)), then the kind's calls on the writer: deletes by remove_queued() on a
	# multiCMD.AsyncExecutor waited for as wait_for_async_commands() waits; copy_before_placement is writer.record(rel, True),
	# copy_after_placement harness.copy_now(); renamed_* writer.rename(); moved_out_of_a_folder_then_it_removed is mv D/g y; rm -r D;
	# name_refilled_then_removed is mv p q; mv other p; rm p; unfold_kept_by_a_hard_link an os.symlink stand-in answering
	# ENAMETOOLONG for one entry's path while its folder unfolds; record_copied an os.link stand-in answering EMLINK for the record
	tree_inodes = ...                      # (st_dev, st_ino) of every file under writer.tree, by os.walk
	for rel in regular files of writer.previous reached through real folders:
		assert writer.sizes.alone(rel, writer.two_renames) == ((st.st_dev, st.st_ino) not in tree_inodes), rel
	# each rel answered True: writer.link_kept(rel, <its kept path>, 'new/' + rel, pending, (st_dev, st_ino)) is True, then
	# writer.place(pending[-1].temp_path, 'new/' + rel); after it alone() is False, and paths_sharing_an_inode() is [] for V1 and V2

def test_a_finished_link_is_placed_and_one_whose_folder_became_a_link_is_left(tmp_path):
	# finish_copies() of two PendingCopy(None, ...) entries, each temp a hard link of a file (harness.tracked_manifest() tracking
	# both dests): the first placed (dest is the file's inode) and returned, manifest.copies_unsynced True; the second's folder
	# above dest replaced by a symlink first: not placed, its row discarded, not returned
```

```python
# tests/test_tree_writer.py: handed_over() gains pooled=None, passed to rv.hand_over()
@pytest.mark.unit
@pytest.mark.parametrize('pooled', [None, True], ids=['one_rename', 'two_renames'])
def test_link_kept_records_its_place_and_queues_a_finished_copy(tmp_path, pooled):
	# V1 holds old/x and n/x; writer.remove_now('old'), so the version before alone holds old/x; kept its (st_dev, st_ino);
	# source = source_file(str(tmp_path)), pending = []
	assert writer.link_kept('old/x', source, 'n/x', pending, kept) is True
	assert read_view(job_vault, V1)['n/x'] == before['n/x']                       # n/x's old entry recorded first
	assert pending == [rv.PendingCopy(None, source, pending[0].temp_path, writer.path('n/x'))]
	assert (os.lstat(pending[0].temp_path).st_dev, os.lstat(pending[0].temp_path).st_ino) == kept
	assert writer.sizes.alone('old/x', writer.two_renames) is False
```

  `tests/test_tree_writes.py`: `test_the_writer_is_where_the_writes_are`'s verbs gain `'link_kept'`, and it asserts
  `'os.link' in names_used(writer['TreeWriter.link_kept'])`.
- [ ] **Step 2: Run them on the base.** `RUN t1 auto tests/test_no_copy_move.py tests/test_tree_writes.py`: each FAILS (no
  `alone`, no `link_kept`, no `paths_sharing_an_inode`; `finish_copies()` reads `None.stderr`).
- [ ] **Step 3: Implement** the names above. In `link_kept()`, an OSError of `alone()` (before the record) answers False with
  nothing done; one of `os.link(self.kept_path(kept_rel), temp, follow_symlinks=False)` or of the lstat after it answers False
  with the copy name removed if made (`discard_temp()`; an OSError of that removal is a JobFailure naming the copy name). The
  record, the flush and `_folders_for_copy()` stay outside both.
- [ ] **Step 4: Run** the tests, then `RUN t1 auto tests/test_no_copy_move.py tests/test_tree_writes.py tests/test_r_sizes.py
  tests/test_pool_writer.py tests/test_io_errors.py tests/test_verify_replay.py`, then the whole suite.
- [ ] **Step 5: Commit.** **main session: VM gate**: `tests/test_tree_writer.py`.

**Acceptance:** `alone()` answers "no path of the tree holds this inode" for every record kind, both ways; `link_kept()` is the one
door a link goes through; `finish_copies()` places a link as a copy; nothing calls `link_kept()` yet.

---

### Task 2: Which old copy is looked at (spec 2; build step 2) [Q24]

Read by nothing yet.

**Files:**
- Modify: `reverberator.py`: new `released_names()` and `old_copy()` beside `order_backup_entries_for_replay()` (8111).
- Test: `tests/test_no_copy_move.py`.

**Interfaces:**
- Consumes: 0.55.7's `real_folders_to(strict=True)` (False for ENOENT and ENOTDIR, `VersionLookError` otherwise).
- Produces:
  - `released_names(backup_entries:dict, monitor_path:str) -> dict`: `{last name: rel}` of the delete entries (a folder's rel
    without its `/`) under no other delete and at or above no move entry's `source_path`; a name two of them share maps to None
    (ambiguous). One pass, no sort: the deletes' rels a set, each kept when no folder above it is in that set (a set lookup a
    parent, as `inside_folders()` walks them) and it is not in the set of the move sources' rels and every folder above each.
  - `old_copy(names:dict, rel:str, st, version_path:str) -> 'str | None'`: `st` is read for `st_size`, `st_mtime_ns`, `st_mode`,
    `st_uid`, `st_gid` only. For each part of `rel` whose name maps to a rel, outermost first: the old path is that rel plus the
    parts after the name (none for the last part); one equal to `rel` is passed over. The first whose folders are real
    (`real_folders_to(version_path, old, strict=True)`) and whose `os.lstat()` is a regular file with those five fields equal is
    returned; else None. FileNotFoundError and NotADirectoryError of the lstat are "not there"; any other OSError, and the folder
    look's `VersionLookError`, are raised.

- [ ] **Step 1: Write the tests.**

```python
def test_released_names_keeps_the_top_most_deletes_by_their_last_name(tmp_path):
	# entries as change_events_to_backup_entries() gives them, monitored paths with a folder's trailing /
	assert rv.released_names(per_row_deletes_of('P/big'), m) == {'big': 'P/big'}      # P/big/, P/big/a, P/big/sub/, P/big/sub/b
	assert rv.released_names(deletes('f.txt', 'd/'), m) == {'f.txt': 'f.txt', 'd': 'd'}
	assert rv.released_names(deletes('x/src', 'y/src'), m) == {'src': None}
	assert rv.released_names(moved('y', from_='d/g') | deletes('d/'), m) == {}         # mv d/g y; rm -r d
	assert rv.released_names(moved('b', from_='a') | deletes('a'), m) == {}            # a delete at a move's source

def test_old_copy_finds_the_file_below_the_deleted_entry_of_its_name(tmp_path, monkeypatch):
	# a scratch version folder holding P/big/sub/a, big/sub/a, top.iso; st the monitored file's lstat (same five fields)
	assert rv.old_copy({'big': 'P/big'}, 'P/new/big/sub/a', st, version) == 'P/big/sub/a'
	assert rv.old_copy({'big': 'P/big'}, 'Q/n/big/sub/a', st, version) == 'P/big/sub/a'     # another parent
	assert rv.old_copy({'big': 'big'}, 'a/b/big/sub/a', st, version) == 'big/sub/a'         # mkdir -p a/b
	assert rv.old_copy({'top.iso': 'top.iso'}, 'n/top.iso', st, version) == 'top.iso'       # a moved file
	assert rv.old_copy({'big': 'big'}, 'r/big/sub/a', st, version) == 'big/sub/a'           # unpacked elsewhere
	# None: a renamed move ('n/other/a'); {'big': None}; st differing in each of size, mtime_ns, mode, uid, gid (a SimpleNamespace
	# of the five); the old path through a symlink to a folder; the old path a symlink; old == rel ({'d': 'd'}, 'd/f'); a deleted
	# file's name as a folder of the new path ({'notes': 'notes'}, the version holding the file notes, 'n/notes/x')
	# raised: OSError EIO from an os.lstat stand-in on the old path; VersionLookError from one on a folder above it
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
- Test: `tests/test_no_copy_move.py`.

**Interfaces:**
- Produces:
  - `no_follow_opener(file:str, flags:int) -> int`: `hash_file()`'s opener as it is.
  - `read_block(f, buffer:bytearray) -> int`: `f.readinto()` into the rest of `buffer` (a memoryview slice) until it is full or a
    call returns 0; the bytes read.
  - `same_file(source:str, kept:str, blocks:tuple) -> 'tuple | None'`: `blocks` two `bytearray(COMPARE_BLOCK_BYTES)`. The kept
    file's `(st_dev, st_ino)` from its handle's `fstat()` when the two are equal in `entry_metadata()` of each handle, in the two
    handles' sizes and in every byte; else None. One `BACKUP_SEMAPHORE` permit, waited for by `acquire(timeout=0.1)` in a loop
    (multiCMD's dispatcher's wait) with `GREEN_LIGHT` looked at before the first acquire and after each timeout (clear: None), given
    back by `try`/`finally` around the opens and reads. Each file opened once, `open(path, 'rb', buffering=0,
    opener=no_follow_opener)`, then `hash_file()`'s two steps (not a regular file: None; `O_NONBLOCK` cleared). Blocks compared
    with `==` of the bytearrays, a short last block by its slices. Where both fstats' `st_blocks * 512` are below their
    `st_size`: after each block each handle `seek(pos, os.SEEK_DATA)` (ENXIO: its size), and both seek to the nearer of the two.
    None at the first block or length that differs, at any OSError, and when `GREEN_LIGHT` is clear between blocks. Any other
    exception goes up.
  - `entry_metadata(path:'str | int') -> tuple` and `xattr_names(path:'str | int') -> list`: on an int, `os.fstat()`,
    `os.listxattr(fd)`, `os.getxattr(fd, name)` with no `follow_symlinks`; the tuple and `xattr_names()`'s ENOTSUP/ENOSYS rule as
    for a path.

- [ ] **Step 1: Write the tests.**

```python
B = rv.COMPARE_BLOCK_BYTES

@pytest.mark.parametrize('size', [0, 1, B - 1, B, B + 1, 3 * B])
def test_same_file_compares_at_block_boundaries(tmp_path, size):          # Review Focus 3
	# random bytes; kept a shutil.copy2 of source
	assert rv.same_file(source, kept, blocks()) == (os.stat(kept).st_dev, os.stat(kept).st_ino)
	# its last byte changed, then its first, each with the mtime set back: None (size 0 has no byte to change)

def test_same_file_compares_the_metadata_read_through_its_handles(tmp_path, monkeypatch):
	# each made to differ alone: the mode, the mtime, a user.x attribute: None
	assert rv.entry_metadata(fd) == rv.entry_metadata(path)                 # a file with user.x
	# an os.listxattr stand-in raising ENOTSUP for an int: xattr_names(fd) == []; raising EIO: OSError

def test_read_block_fills_its_buffer_from_short_reads():
	# a stand-in whose readinto() gives at most 1000 bytes a call, 2.5 buffers in all: B, B, B // 2, then 0

def test_same_file_opens_no_fifo_and_follows_no_link(tmp_path):
	# a FIFO with no writer at the source: None, at once (an open that blocks would hang the test); the kept path a symlink to a copy: None

@pytest.mark.parametrize('shape', ['data_at_both_ends', 'hole_written_as_zeros', 'other_bytes_in_the_hole', 'sparse_alike_differing',
	'dense_old_copy'])
def test_same_file_reads_two_sparse_files_by_their_data(tmp_path, monkeypatch, shape):
	# data_at_both_ends: 64 MiB, data in the first and last 4 KiB, a hole between, in both: equal, and a read_block() stand-in
	#   counting bytes sees under 4 * B read in all
	# hole_written_as_zeros: the source written with zeros where the kept has its hole: equal
	# other_bytes_in_the_hole: the source with other bytes inside the kept's hole: None
	# sparse_alike_differing: both 256 KiB of equal data at 0, a hole to 2 MiB, 256 KiB at 2 MiB that differs, a hole to 4 MiB: None
	# dense_old_copy (Review Focus 5): the kept written dense, the source sparse with the same bytes: equal
	# skips when the filesystem under the test keeps no holes (a file made sparse reads st_blocks * 512 >= st_size)

def test_a_compare_holds_a_threads_permit(tmp_path, monkeypatch):
	# rv.BACKUP_SEMAPHORE a Semaphore(1) counting its acquire calls
	# a read_block() stand-in: acquire(blocking=False) is False while it reads; after same_file() returns, True (given back)
	# a read_block() stand-in raising ValueError: same_file() raises it, and the permit is back
	# the test holding the permit, GREEN_LIGHT cleared (set again in a finally): same_file() is None, no acquire called, and a
	# no_follow_opener() stand-in counts no open
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
    state (`blocks`, made at the first compare; `compare_raised`; `linked`, a dict `{old rel: size}`); `copy_path()`'s two
    `writer.copy()` calls (14798, 14804) call it, the rel each entry's copy was given still recorded beside the call (0.55.7 Task 7);
    the log line.
- Modify: `tests/crash_batches.py`: `backup_events()` (49) becomes `attempt_events()`, the same call returning `committed`, and
  `backup_events()`, which calls it and asserts it.
- Modify: `tests/test_moves_into_new_folders.py`: the test at 249 and the two estimate tests (1052, 1076).
- Modify: `tests/test_folder_times.py` (468): the stand-in `lambda path, *args, **kwargs: sized.append(path) or real_size(path,
  *args, **kwargs)`.
- Modify: `README.md` lines 4, 15, 22, 31, 43, 115; `docs/limitations.md`: the three entries of spec 10.
- Test: `tests/test_no_copy_move.py`.

**Interfaces:**
- Consumes: Tasks 1-3; 0.55.7's `VersionLookError`; `poll_pools` of `do_reverb_backup()`.
- Produces:
  - `do_reverb_backup(..., names:dict = None)`: None and `{}` both mean no names.
  - `get_backup_size_inode(..., *, version_bytes:int, leaving = None)`; `get_unskipped_size_inodes(path, skip_list, block,
    monitor_path, version_bytes, leaving = None)`; `leaving(rel:str, st:os.stat_result) -> bool`.
  - `copy_or_link(source_path:str, rel:str, mcae) -> None`, a closure of `do_reverb_backup()`, spec 4's nine steps in their
    order: 1 no names or `writer.links_refused`: copy; 2 no part of `rel` maps to a rel in the names (`names.get(part) is not
    None`, one dict lookup a part): copy; 3-5 in one `try` (`except (OSError, VersionLookError)`: copy): `os.lstat()`, not a
    regular file: copy; `old_copy(names, rel, st, writer.previous)` None: copy; `writer.sizes.alone(old, writer.two_renames)`
    False: copy; 6 `same_file(source_path, writer.kept_path(old), blocks)` in a `try` of its own (`except Exception`: None, the
    batch's first an error line `Comparing <source_path> with <kept path> failed; copying it instead` and one with
    `traceback.format_exc()`); 7 `poll_pools()`; 8 `GREEN_LIGHT` clear: return, neither link nor copy; 9 `kept` not None and
    `writer.link_kept(old, source_path, rel, pending, kept)`: `linked[old] = st.st_size`; else the copy. "Copy" is
    `writer.copy(source_path, rel, mcae, pending)`, as today.
  - The log line, right after the replay's stop check (`Reverb backup interrupted before copy threads finished` returns before
    it): of `linked`, the old rels for which `not writer.sizes.alone(old, writer.two_renames)` (an OSError of that look: not
    counted); when there is one, `backuperTeeLogToTl(path=monitor_path, message=f'Reused {count} files, {format_bytes(size,
    use_1024_bytes=True, to_str=True)}B, from {writer.previous} by hard links in place of copies: each had the bytes, mode, owner,
    group, mtime and extended attributes of a file this batch removed from the version')`, `size` the sum of their sizes.
  - `tests/crash_batches.py`: `attempt_events(job, events:list, **kwargs) -> bool`.

- [ ] **Step 1: Write the helpers and the tests** in tests/test_no_copy_move.py. Every batch runs through `do_backup()` with raw
  events (`attempt_events()`; a delete of the old place and a create of the new unless said), with `keep_n_versions=0,
  backup_size_limit='0'` unless said, and ends with `assert_right()`.

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
```

  The estimate (spec 3), each through the spy:

```python
@pytest.mark.parametrize('where', ['top', 'below'])          # big to n/big; P/big to P/n/big
def test_the_estimate_charges_no_file_of_an_unchanged_move_into_a_new_folder(job, renames, monkeypatch, where):
	assert estimates(...)[-1] == (sum of st_blocks * 512 of n's folders, their count)   # n's folders alone
	# then: five small versions (a 1 KiB file each), backup_size_limit the vault's size + 1 MiB, big 4 MiB: after the move all five
	# stay (on the base the 4 MiB charge prunes to the newest)
def test_the_estimate_charges_a_file_changed_in_the_move(job, monkeypatch): ...
	# pin: big/a appended in the batch: charged its size
def test_the_estimate_charges_a_file_chmodded_in_the_move(job, monkeypatch): ...     # pin: mode differs: charged
def test_an_attrib_copy_is_charged_whatever_its_path(job, monkeypatch): ...
	# pin: OSA off, a chmod of n/big/a in a batch with names: charged
def test_a_renamed_move_is_charged(job, monkeypatch): ...                            # pin: mkdir n; mv f n/g: charged, copied
@pytest.mark.parametrize('case', ['from_the_top', 'from_below', 'renamed', 'full_comparison', 'its_own_old_place',
	'outrun_by_a_folder_move', 'delete_behind_a_move', 'two_creates_one_old_file', 'two_deletes_one_name'])
def test_the_estimate_is_never_above_what_the_batch_writes(job, renames, monkeypatch, case):
	# the spec's shapes (outrun: mv d e; mkdir e/sub; mv x e/sub/x; behind: mv d/g y; mkdir n; mv d n/d)
	assert est_bytes <= grown_bytes and est_inodes <= grown_inodes   # grown: sizes_by_newest_holder() after less before, summed
# Q25's four causes (spec 3), each: the estimate leaves the file out (FAILS on the base), and the replay copies it
def test_a_predicted_link_whose_bytes_differ_is_copied_uncharged(job, monkeypatch): ...       # cpp after the estimate's walk
@pytest.mark.parametrize('case', ['kept_by_the_length_rule', 'folder_where_a_file_was', 'file_where_a_folder_was'])
def test_a_predicted_link_whose_delete_removes_nothing_is_copied_uncharged(job, monkeypatch, case): ...
def test_a_second_file_that_pairs_with_one_old_file_is_copied_uncharged(job, monkeypatch): ...
def test_a_predicted_link_the_vault_refuses_is_copied_uncharged(job, monkeypatch): ...         # os.link EPERM on copy names
def test_a_roll_forward_charges_every_copy(job, monkeypatch):
	# cut after the hand-over as tests/test_r_scan.py's commit_cut_at() cuts (a Cut raised from a do_reverb_backup stand-in), then
	# run_backup(): its estimate charges n's files, and the replay copies them (not one_inode)
```

  The copy step (spec 4):

```python
@pytest.mark.parametrize('osa', [True, False], ids=['osa', 'no_osa'])
def test_an_unchanged_file_moved_into_a_new_folder_is_linked(job, renames, monkeypatch, osa):
	assert one_inode(job, 'f.bin', 'n/f.bin') and one 'Reused 1 files' line
@pytest.mark.parametrize('osa', [True, False], ids=['osa', 'no_osa'])
def test_an_unchanged_folder_moved_into_a_new_folder_is_linked(job, renames, monkeypatch, osa):
	# big/a (300 KiB), big/sub/b, big/empty (0 bytes), big/x with user.x, big/l -> a: the four files one_inode; n/big/l a symlink, as today
@pytest.mark.parametrize('shape', ['P/big:P/new/big', 'P/big:P/a/b/big', 'P/big:Q/n/big'])
def test_a_folder_moved_below_the_top_is_linked(job, shape): ...       # every file one_inode with its own old copy
def test_a_move_made_while_down_that_kept_its_name_is_linked(job): ... # mkdir n; mv big n/ with no events, then run_backup()
def test_a_tree_unpacked_elsewhere_under_its_name_is_linked(job): ...  # tar cpf outside; rm -r big; mkdir r; tar xpf -C r
def test_a_twin_of_the_same_name_size_mtime_and_tail_is_copied(job): ...
	# pin: other bytes before the last 64 KiB (cpp): copied
def test_a_poke_before_the_compare_is_copied(job): ...                 # pin: poke after the events are made: copied
@pytest.mark.parametrize('into', ['not_yet_compared', 'already_compared'])
def test_a_write_during_the_compare(job, monkeypatch, into):
	# a read_block() stand-in writes into the monitored n/big/a (3 blocks) after its first block. not_yet_compared: copied, its
	# expected view the tree after the batch (the copy read the write); already_compared: linked to the old bytes, then a modify
	# batch copies the new ones and that version holds them
def test_a_file_replaced_after_the_compare_opened_it_is_judged_as_opened(job, monkeypatch):
	# a no_follow_opener() stand-in that, after opening the monitored file, renames over its path a copy of the old copy made mode 0o600:
	# no version holds the old copy's bytes under mode 0o600
def test_a_compare_that_raises_is_a_copy(job, monkeypatch):
	# BACKUP_SEMAPHORE a Semaphore(1); a read_block() stand-in raising ValueError for two files: both copied; one error line and one
	# traceback line in all; the batch's later copies finish; acquire(blocking=False) True after; committed
@pytest.mark.parametrize('shape', ['data_at_both_ends', 'hole_written_as_zeros', 'other_bytes_in_the_hole', 'sparse_alike_differing'])
def test_a_sparse_file_is_compared_by_its_data(job, monkeypatch, shape):
	# Task 3's shapes moved into a new folder: linked, linked, copied, copied; the first reads under 4 * COMPARE_BLOCK_BYTES
def test_a_source_gone_before_the_compare_is_copied_as_today(job, monkeypatch): ...
	# removed in an old_copy() stand-in: no row, today's lines
@pytest.mark.parametrize('field', ['mode', 'mtime', 'xattr', pytest.param('owner', marks=needs_root),
	pytest.param('group', marks=needs_root)])
def test_metadata_that_differs_is_copied(job, field): ...
	# pin: chmod, touch, setfattr user.x, chown 1234, chgrp 1235: not one_inode
def test_two_new_files_and_one_old_file_link_one(job, monkeypatch):
	# rm -r big (big/a); n1/big/a and n2/big/a its cp -p: the first in replay order linked, the second copied; a same_file() spy: 1 call
@pytest.mark.parametrize('case', ['renamed_move', 'two_deletes_one_name', 'out_of_a_folder_it_deletes', 'delete_behind_a_move',
	'unpacked_at_its_own_place'])
def test_what_the_names_do_not_reach_is_copied(job, monkeypatch, case):
	# pin: spec 7 items 2-6 (mkdir n; mv big n/other | x/src, y/src deleted, n/src one's bytes | mkdir n; mv a/b/big n/; rm -r a |
	# mv d/g y; mkdir n; mv d n/d | rm -rf d; tar x at d): copied, and a same_file() spy sees no call
@pytest.mark.parametrize('case', ['saved_copy_put_back', 'part_of_a_left_folder_moved_back'])
def test_a_true_stand_in_below_a_deleted_entry_of_its_name_is_linked(job, case): ...
	# rm other; mkdir n; cp -a <saved> n/other | mv P/X /out/X; mkdir -p Q/X; mv /out/X/sub Q/X/
@pytest.mark.parametrize('code', [errno.EPERM, errno.ENOTSUP, errno.EOPNOTSUPP, errno.ENOSYS, errno.EXDEV, errno.EMLINK])
def test_a_vault_that_refuses_links_copies_the_rest_without_a_compare(job, monkeypatch, code):
	# an os.link stand-in raising code for paths ending in rv.PARTIAL_COPY_SUFFIX; a same_file() spy; a moved folder of three files:
	# the first four codes 1 compare, EXDEV and EMLINK 3; three copies each way
def test_a_pool_disk_gone_during_a_compare_fails_before_the_link(job, fake_pool, monkeypatch):
	# the vault on fake_pool.add(job.vault, ['a', 'b']); a same_file() stand-in calls the real one, then fake_pool.drop() a branch:
	# pytest.raises(rv.PoolNotReady); no copy name in the tree; the version before's file's st_nlink as before the batch
def test_a_failed_record_at_the_link_fails_the_attempt(job, monkeypatch):
	# a TreeWriter.record stand-in raising JobFailure for the link's rel: pytest.raises(rv.JobFailure), no link and no copy for the
	# file; stand-in off, run_backup() commits and assert_right()
@pytest.mark.parametrize('case', ['kept_by_the_length_rule', 'deleted_symlink_at_the_name'])
def test_an_old_place_with_no_file_is_copied(job, case): ...
	# pin: the length rule's kept delete (as tests/test_long_paths.py builds one); a user's symlink big deleted
def test_a_stop_during_the_compare_links_nothing(job, monkeypatch):
	# a read_block() stand-in clears GREEN_LIGHT: attempt_events() is False, no copy name under the tree; GREEN_LIGHT set, the next
	# attempt (run_backup()) commits and assert_right()
def test_a_failed_look_at_the_version_before_is_a_copy(job, monkeypatch): ...
	# EIO from an os.lstat stand-in on the old path: copied, committed
def test_the_verification_links_too(job, monkeypatch): ...
	# an iter_tree_entries stand-in leaves n/big/a out of the replay's walk of n; the verification copies it: one_inode('big/a', 'n/big/a')
def test_a_roll_forward_links_nothing(job, monkeypatch): ...
	# cut as in test_a_roll_forward_charges_every_copy: n's files not one_inode
def test_two_names_of_one_monitored_inode_each_link_their_own_old_copy(job): ...
	# Review Focus 1: big/a and big/a2 one inode in the tree
def test_a_fifo_in_a_moved_folder_is_copied_and_never_opened(job, monkeypatch): ...
	# Review Focus 2: big/p a FIFO: committed, files linked
def test_a_moved_folder_whose_names_are_not_utf8_is_linked(job): ...
	# Review Focus 4: os.fsdecode(b'big\xff') holding 'new\nline'
@pytest.mark.parametrize('osa', [True, False], ids=['osa', 'no_osa'])
def test_a_chmod_of_a_linked_file_in_a_later_batch(job, osa):
	# linked, then chmod 0o600 of n/big/a (an attrib batch): osa, synced onto the shared inode and the version before's big/a reads
	# 0o600 (assert_right with only_sync_attributes); no_osa, copied, big/a keeps its mode
```

  The books and the link (spec 5, through `do_backup()`):

```python
@pytest.mark.parametrize('record', ['renamed_in', 'exchanged_in', 'walked_by_the_record'])
def test_the_sizes_after_a_link(job, renames, record): ...   # the ground-truth plugin's lists; one_inode for each file
def test_the_sizes_after_a_link_kept_by_an_unfold(job, monkeypatch): ...
	# os.symlink ENAMETOOLONG for its path; its top folder deleted, moved into n: linked
def test_a_linked_file_the_tree_lets_go_in_its_batch_counts_in_the_version_before(job, monkeypatch):
	# the monitored n/f.bin removed in a finish_copies() stand-in after the link was placed; the verification deletes it: sizes right,
	# no Reused line
@pytest.mark.parametrize('code', sorted(rv.NO_HARD_LINK_ERRNOS) + [errno.EIO])
def test_a_link_refused_with_each_errno_is_a_copy(job, monkeypatch, code): ...
	# copied, sizes right, no PARTIAL_COPY_SUFFIX name in the tree
@pytest.mark.parametrize('swap', ['another_inode_at_the_kept_path', 'symlink_at_the_copy_name'])
def test_a_kept_file_swapped_after_its_compare_is_a_copy(job, monkeypatch, swap):
	# an os.link stand-in: first renames over the kept path a cp -p of it, then links; or makes a symlink to the kept file at the copy
	# name and returns (mergerfs's link-exdev symlink modes): copied, no copy name left, the kept file's st_nlink as it was
def test_a_copy_name_that_cannot_be_removed_fails_the_attempt(job, monkeypatch):
	# an os.lstat stand-in answering another inode for the copy name, an os.remove stand-in raising EIO for it: pytest.raises(rv.JobFailure);
	# stand-ins off, run_backup() commits, paths_sharing_an_inode() [] for every version
def test_a_batch_of_links_alone_flushes_as_a_batch_of_copies(job, renames, monkeypatch): ...   # a spy on rv.flush_copies: called
def test_a_stop_before_a_link_is_placed_leaves_no_copy_name(job, monkeypatch):
	# a TreeWriter.link_kept wrapper clears GREEN_LIGHT after the real one: no PARTIAL_COPY_SUFFIX name in the tree, the version
	# before's file whole and its st_nlink as before the batch
```

  The log line (spec 6):

```python
def test_one_line_a_batch_names_the_files_and_bytes_linked(job, monkeypatch):
	# a moved folder of three files, 300 KiB in all: exactly one line starting 'Reused 3 files, ' with format_bytes(..)B and the version
	# before's path, at info level (no flag)
def test_no_reused_line_where_nothing_is_linked(job, monkeypatch): ...          # pin
def test_a_link_left_unplaced_is_not_counted(job, monkeypatch): ...
	# a finish_copies() stand-in first replaces a folder above the link's place by a symlink
def test_one_old_file_linked_twice_counts_once(job, monkeypatch): ...
	# the first link's new place removed from the tree by a stand-in after its placement, a second new file of that old file linking
	# it again: 'Reused 1 files'
```

  tests/test_moves_into_new_folders.py:
  - `test_a_folder_moved_into_an_existing_folder_costs_no_copy_and_into_a_new_one_a_copy` becomes
    `test_a_folder_moved_into_an_existing_or_a_new_folder_costs_no_copy`: for all three cases, at both gaps, `{new: after[new]} ==
    {new: inodes[old]}` and `vault_bytes(job) - size < 200000`.
  - `test_the_size_estimate_counts_what_is_written_under_a_folder_moved_into_a_new_one`: `est_inodes == names_in(n) - linked +
    probes`, `linked` the files of `big` the row neither writes nor changes; its bound stays `written <= est_size <= grew`.
  - `test_the_size_estimate_counts_the_attribute_copies_under_a_folder_moved_into_a_new_one`: the same inode count (the touched and
    chmodded files are not linked); its bound stays `15 << 20 <= est_size <= grew`.
  - **[Q25]** (b): both keep `est_inodes == names_in(n) + probes` and bound `written <= grew <= est_size` and
    `15 << 20 <= grew <= est_size`; of the estimate tests above only `test_the_estimate_charges_every_file_the_replay_links` (a move
    into a new folder: the estimate charges `big`'s files, the replay links them) is written.
- [ ] **Step 2: Run them on the base.** `RUN t4 auto tests/test_no_copy_move.py tests/test_moves_into_new_folders.py
  tests/test_folder_times.py`: every test that asserts a link, a file left uncharged or a Reused line FAILS (the new path's inode is
  a copy's; the estimate charges `big`); those that assert a copy, a charge or a failure pass (pins: say which in the handback),
  as do Tasks 1 to 3's.
- [ ] **Step 3: Implement** the Files block, `copy_or_link()` as its Interfaces say.
- [ ] **Step 4: Run** the tests, then `RUN t4 auto tests/test_no_copy_move.py tests/test_moves_into_new_folders.py
  tests/test_folder_times.py tests/test_estimate_charge.py tests/test_estimate_through_a_take.py tests/test_job_startup.py
  tests/test_r_sizes.py tests/test_r_batch.py tests/test_verify_replay.py tests/test_tree_writes.py tests/test_long_paths.py`, then
  the whole suite (tests/test_job_startup.py's copy assert at 309, a rename made while down, stays as it is).
- [ ] **Step 5: Docs.** Spec 10.1 replaces "A folder or file moved into a new folder is copied whole" whole; 10.2's insertions,
  its links sentences and its Why, Revisit when and Approved additions; 10.3's six README lines; 10.4's sentence, its revisit
  clause dropped and its Approved addition. Each text word for word, `<Q24's answer>` and `<Q25's answer>` as the brief gives them.
  10.3's "(line 17)" is checked against the merged README (the line on a file made in the batch and moved): a moved number is
  written as it now is. **[Q25]** (b): 10.2's estimate sentence and line 31's estimate clause are not written, and 10.1's clause
  reads as its [Q25] note says.
- [ ] **Step 6: Commit.** **main session: VM gate**: the owner and group cases of `test_metadata_that_differs_is_copied`.

**Acceptance:** each unchanged file of a move into a new folder that keeps its name is one inode with its old copy, every other
copy is today's, the estimate leaves exactly the files the lookup finds uncharged, one Reused line a batch that linked, and the
docs say so.

---

### Task 5: The real watcher shows what links (spec 9, tests/test_moves_into_new_folders.py) [Q24]

Tests and their comments only; each passes on Task 4's code.

**Files:**
- Modify: `tests/test_moves_into_new_folders.py`: `assert_held_as_the_tree()` (229); the module docstring (1-7); a new test after
  the MATRIX test; the `at_once` stress test (338); the found-folder tests at 373, 699, 739, 763, 784;
  `test_on_a_filesystem_with_no_exchange` (974); `test_a_file_moved_out_is_not_taken_for_a_new_folders_file_of_its_name` (398); the
  comments the spec names (268, 283, 374-375, 597, 642, 673-674, 700-702, 740-742, 764, 785-786, 808, 888; those at 399 and 419
  stay).

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
	# the shape's steps from SHAPES; inodes_of() before and after
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
  - Every comment the Files block names, and the docstring, say what its test now asserts (linked, or copied where it is).
- [ ] **Step 2: Run** `RUN t5 auto tests/test_moves_into_new_folders.py tests/test_watcher_fuzz.py`: all pass. A test that shows
  otherwise (a found folder copied, say) is a finding: report it, do not loosen the assert.
- [ ] **Step 3: Run** the whole suite; commit.

**Acceptance:** on the real watcher every shape links exactly what the spec says, and no version holds two paths on one inode.

---

### Task 6: The builder's measurements and the fuzz's twin step (spec 9; build step 4) [Q24]

**Files:**
- Modify: `tests/test_watcher_fuzz.py`: `step()` (45) gains the kind `twin` (weight 3); the round's oracle gains
  `paths_sharing_an_inode()`.
- Measurement scripts stay in the scratch folder, never committed.

- [ ] **Step 1: The twin step.** `twin`: a file of the tree, a new folder `n<k>` (`k` in `range(3)`) under `where()`,
  `shutil.copy2()` of the file into it under its own name, one time in two the copy poked (the bytes `POKED` written at 0, its size
  and mtime kept, as `Session.apply()`'s `poke`), then the original removed; logged as `('twin', source, copy, poked)`. After each
  round, every version folder's `paths_sharing_an_inode()` is `[]`, else `fail()`.
- [ ] **Step 2: Run** `RUN t6 auto tests/test_watcher_fuzz.py`, then once `REVERB_WATCH_FUZZ=256` (the seeds and their time in
  the handback; a failing seed is a finding).
- [ ] **Step 3: Measure** (container, uid 65534, warm, each three runs): the replay's time and `VmHWM` (`/proc/self/status`) after
  it, linked against copied (`rv.released_names` patched to return `{}`), for a 1 GiB file and for a folder of 10,000 files of
  4 KiB moved into a new folder, with `COMPARE_BLOCK_BYTES` 256 KiB and 1 MiB; `released_names()` of a full comparison's
  1,000,000 per-row deletes; `get_backup_size_inode()` over a moved folder of 100,000 files with `leaving` and without. A linked
  move much slower than its copy is a finding.
- [ ] **Step 4: Commit** the fuzz step; the figures in the handback.

**Acceptance:** the fuzz draws twins, poked and not, and every round's vault holds no two paths of a version on one inode; the
figures are in the handback.

---

### Task 7: The crash, power-loss and pool tests (spec 9, Crash and The pool) [Q24]

Written by the builder, skipped outside the VM; **main session: VM gate** runs them (Task 9).

**Files:**
- Modify: `tests/crash_batches.py`: `seed_base()` gains `kept.bin` (`past_inline('KB')`) and `keptdir/k.bin`
  (`past_inline('KD')`); `change_batch3()` makes `reused`, moves `kept.bin` and `keptdir` into it, and its events gain
  `(False, 'delete', 'kept.bin', None), (True, 'delete', 'keptdir', None), (True, 'create', 'reused', None)`; new
  `link_shape_wrong()`.
- Modify: `tests/test_crash_harness.py`: `wrong_after_retry()` (452); `test_the_kill_points_cover_every_kind_of_call` (393); a new
  test after `test_batch_3_has_an_attribute_change_on_a_shared_inode`.
- Modify: `tests/test_crash_power_loss.py`: its `problems` (244).
- Modify: `tests/test_pool_cut.py`: `MixedBatch.wrong()` (813); a new shape; `SHAPES` (1045).
- Modify: `tests/test_pool_writer.py`: `real_pool()` (738) gains `options=MERGERFS_OPTIONS`; a new test after
  `test_hard_links_on_a_pool_read_as_one_inode_and_their_count_as_it_is`.

**Interfaces:**
- Produces: `link_shape_wrong(job_vault:str) -> list`: a line for each version whose `paths_sharing_an_inode()` is not `[]`, and one
  when `rv.measure_previous(<version before>, <newest>)` differs from `sizes_by_newest_holder()`'s entry for the version before (the
  two newest committed versions).

- [ ] **Step 1: Write the changes.**
  - `wrong_after_retry()` adds `link_shape_wrong(job_vault)`; so does test_crash_power_loss.py's `problems`, and `MixedBatch.wrong()`.
  - `test_the_kill_points_cover_every_kind_of_call`: `'link'` among its kinds (a pin: records link too).
  - `test_batch_3_links_its_two_moves_into_a_new_folder(r_vault)`: the uncut batch commits, and V3's `reused/kept.bin` and
    `reused/keptdir/k.bin` are one inode with V2's `kept.bin` and `keptdir/k.bin`; so the sweeps cut through `link_kept()`, the
    placement and the commit.
  - `class MixedBatchManifestLost(MixedBatch)`, `batch = 'mixed-manifest-lost'`: `again()` removes the vault database first, as
    tests/test_crash_harness.py's `lose_the_manifest()` does; `wrong()` leaves folder times out, as `test_every_kill_point_on_r`
    does over a lost manifest. `SHAPES['mixed-manifest-lost-2'] = (MixedBatchManifestLost, 2)`.
  - `test_a_link_into_a_new_folder_on_a_pool_is_made_or_copied_as_mergerfs_answers` (`privileged`, `needs_mergerfs`),
    parametrized `['linked', 'exdev', 'rel_symlink']`: the old copy on one branch, the new folder made on the other; the options
    that make mergerfs link, answer EXDEV, and (`link-exdev=rel-symlink`) make a symlink, taken from mergerfs's documentation and
    named in the test. Each asserts its own outcome (one inode across the two versions; a copy after the EXDEV; a copy, with no
    symlink at a copy name, after the symlink), never "linked or copied"; then `check_vault()`, the lists, and the times of the
    folders mergerfs made for the link as the batch gave them.
- [ ] **Step 2: Run** in the container what runs there: `RUN t7 auto tests/test_r_batch.py tests/test_r_sizes.py tests/test_r_scan.py
  tests/test_version_walk.py tests/test_history.py tests/test_io_errors.py tests/test_verify_replay.py` (batch 3 and the seed feed
  them: a count the two new entries change takes its new value, each named in the handback), then the whole suite.
- [ ] **Step 3: Commit.**

**Acceptance:** batch 3 links two files past the inline size; every crash, power-loss and pool-cut judgement also finds two paths
of a version on one inode and books that disagree with the vault; the pool test forces each of mergerfs's three answers.

---

### Task 8: The version number [Q24]

- [ ] `reverberator.py` `__version__` (63) and `pyproject.toml` `version` (3) become the number the main session gives (0.55.8 in
  the texts). The whole suite; commit.

---

### Task 9: The VM gates and measurements (the main session's) [Q24]

- [ ] **The VM gates:** `tests/test_tree_writer.py` (Task 1); the owner and group cases (Task 4); the crash harness and the power
  cuts with `REVERB_CRASH_FULL=1` (Task 7: the default stride may miss every link step); the pool cut, both manifest shapes; the
  pool's three runs; the whole suite in the VM as root. A skip counts as a failure.
- [ ] **The real daemon** (spec 9): a scratch job in the container as uid 65534 or in the VM; `mkdir new; mv big new/` for a folder
  of 1,000 files of 100,000 bytes and for a 100 MB file, at the top and below it, at gaps of 0, 1 ms and 1 s, as two system calls
  of one program and as a shell's two commands, each again with a poke before, between and after; the size-limit run (five small
  versions, then the move). The vault's growth (expected under 0.1 MB, a poked file adding its size), the lines, the replay's time
  against today's copy. A VM figure is labelled so.
- [ ] **The figure's commit:** 10.1's "is expected to cost about what a move into an existing folder costs (under 0.1 MB for a
  100 MB folder of 1,000 files)" becomes "costs about ... (<the measured figure> for a 100 MB folder of 1,000 files on the real
  daemon)", its own commit; a figure off the expected one is a finding first.
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
   shares no code with the daemon.
6. `released_names()` marks an ambiguous name with None, and `copy_or_link()`'s step 2 counts only a name that maps to a rel, so an
   ambiguous one costs no lstat (`old_copy()` would pass it over anyway).
7. `do_reverb_backup(names=None)`: None is the empty default.
8. The log line: the size as `format_bytes(size, use_1024_bytes=True, to_str=True)` followed by `B` (the change list's call, with the
   unit the memory lines add); `<version>` is the version before's full path (`writer.previous`); "files" for one too, as the
   spec fixes the text; written right after the replay's stop check, before the folders settle, so a stop writes none.
9. `copy_or_link()`'s error line for a compare that raised: `Comparing <source> with <kept path> failed; copying it instead`, then
   the traceback (the spec gives the count, not the words).
10. On the merged 0.55.7, `copy_path()`'s own look at the source is `monitored_there()` (its Task 6), not `os.path.lexists()`: it
    stays the one look a file with no name costs, and 0.55.7 Task 7's record of the rel stays at `copy_or_link()`'s call.
11. Tests the spec does not list: `test_a_finished_link_is_placed_and_one_whose_folder_became_a_link_is_left` (Task 1), the direct
    tests of `same_file()` (Task 3), the Review Focus five, `test_no_reused_line_where_nothing_is_linked` and
    `test_a_link_left_unplaced_is_not_counted` as their own tests (the spec's pins), a `VersionLookError` case and a deleted file's
    name as a folder in `old_copy()`'s test.
12. `test_alone_answers_for_each_kind_of_record` builds a vault with no root record, so it runs in the container; its copy kind is
    two cases (before and after placement), deletes go by `remove_queued()` waited for, and `remove_now()` is its own kind.
13. The copied case of `test_a_write_during_the_compare` expects the tree after the batch, as the copy read the write.
14. README line numbers are r0556's; each text is found by the sentence it replaces, and 10.3's "(line 17)" is checked against the
    merged README.
15. tests/test_tree_writer.py's `handed_over()` gains `pooled`; tests/test_pool_writer.py's `real_pool()` gains `options`.
16. The fuzz's `twin` step has weight 3 of the choices, which changes the steps every seed draws.
17. The release number is the main session's (Task 8); the texts say 0.55.8.
