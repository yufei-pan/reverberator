# Progress

The open work on reverberator: every part of an agreed design, release plan or roadmap that is not finished, one row
each. Read this file whole when a session starts, after every compaction, clear or restart, and before saying how far
the work is or that nothing is left. A row changes in the commit that changes its work, and leaves the open list only as
done (with its commit or release) or as dropped (with the user's words and the date). History and reasoning live in the
specs, plans and commit messages, not here.

First written on 2026-11-14, with 0.55.5 live (main 720e518), from every spec and plan in `docs/superpowers/`: each
part's state was taken from the code and the commits, not from notes. An audit against the user's own messages follows.

## The goal, in the user's words

- 2026-11-03: "I want this to be as light and as fast as possible... cause it is an backup solution, so it is designed
  to always in run the background. so every little bit will sum up to a lot over days month years."
- 2026-11-03: "simpler and smarter is better"
- 2026-11-04: "one of the core for reverberator is reuse existing linux features and easy browse / restore. we can
  introduce more efficient methods if that reduces usage for users that do not need to manually browse the folders and
  do not need to able to copy out entire versions from the backup store"

## Open parts

**P1. The deferred entries of `docs/limitations.md`.** Source: the 17 entries whose kind is deferred. State: not
started; each waits for its "Revisit when", most of them the round after 0.55.5. Next: that round takes the entries
that name it. Behind it: a deferral is planned work.

**P2. Remove the 0.54 reader, prune and conversion code.** Source: `specs/2026-11-04-round19-vault-r-design.md` sections
8, 9 ("the 0.54 parts go in a later release") and 12 step 3; `plans/2026-11-05-round20.md`; commit 9ab7949 ("stays for
one more release"). State: not started. Still in 0.55.5: `decrement_stepper`, `VersionMoves`, `vault_chain_hop`,
`parse_chain_text`, `is_prune_temp`, the conversion, 72 lines marked "# goes with the 0.54 reader", the manifest's
`copy_version` column and `monitor_paths` key; six test files build 0.54 vaults (`STILL_054`). About 1,900 lines of code
plus tests. Next: its own round. A lost manifest then needs its layout found another way (`vault_layout()`,
`layout_known()`, `recorded_layout()`, `scan_gets_r_rules()`, `conversion_unfinished()`, the guards in `do_backup()`).
Behind it: the user's pick "Keep it one release" (2026-11-04). Every live vault was converted on 2026-11-06.

**P3. The no-copy move into a new folder: a design round.** Source: `specs/2026-11-12-r0555-design.md`, its opening and
"The user's words"; the known limitation "A folder or file moved into a new folder is copied whole". State: not started,
no design yet. Next: a design study first; 0.55.1's attempt was dropped after five routes that left wrong bytes.
Behind it: 2026-11-12, "continue next phase please" and the pick "Fixes + lightness, one round (Recommended)", offered
with "the no-copy move into a new folder gets its own design round after".

**P4. Remove the backuper's dead branch** at `reverberator.py` ~4988-4995. **P5. Remove the lost-manifest branch of
`drop_untracked_deletes(newest_path=)`.** **P6. Remove `remove_pending_file()`.** Source: round 0.55.5's final review
and its second opinions (parts that can go; not in a spec). State: not started. Next: the round after 0.55.5. Behind
them: "simpler and smarter is better"; ruled "can go, next round" by the main session.

**P7. The live measurement after design R.** Source: `plans/2026-11-05-round20.md`, Rollout; the round 19 spec's real
writes after release. State: open; no result is recorded since 0.55 went live on 2026-11-06. Next: measure on the
current release: writes per backup of the busiest job and per day (the vault disks' lifetime write counters) against
the spec's 24 to 36 MiB a cycle and 0.6 to 0.85 GiB a day, f2fs GC's share, prune times, idle CPU, peak memory.
Behind it: the goal (light), and the spec's targets.

**P8. 0.55.5's memory at the uptime of 0.55.4's baseline.** Source: `plans/2026-11-13-r0555.md`, Task 15 and the
rollout. State: one reading: anonymous 104.8 MB, no swap, peak 158 MB, 95 s after the start's last commit
(2026-11-14). Next: read again at two days' uptime, about 2026-11-16, against 0.55.4's 163 MB anonymous (18 MB in
memory, 145 MB swapped) and 150 MB peak. The README (line 90) says idle memory stays near 35 MB, which the tests
measured: if the live figure stays far above it, find what holds the memory and correct the line. Behind it: the
user's pick "Trim, shrink, 2 arenas (Recommended)" (2026-11-13).

**P9. One pass over the watches per folder move, by an index of paths.** Source: `specs/2026-11-09-round22-stepback.md`
("could go later by an index of paths (the lightness round)"). State: not started; 0.55.5's lightness items (L1 to L10)
did not take it, and the code still makes both passes (`reverberator.py` :2989, :3438, :3652). Next: the next
lightness list. Behind it: the goal (light).

**P10 to P13. Four parts of round 22's first watcher design that the step back never took up.** Source:
`specs/2026-11-08-round22-watcher-design.md`. Its top says it was not built; the step back replaced its watcher work
and says nothing of these. State: open, waiting for the user (question Q2).
- **P10. A tree walk without recursion** (its 2.3): `iter_tree_entries()` recurses by `yield from` (:3783). A tree
  deeper than about 1,000 levels leaves its deepest folders unwatched, and the comparison, restore and vault walks
  through the same function stop at the same depth.
- **P11. The walk follows no link that replaced a folder while it ran** (2.5, item 7): the tree's watches are added
  without `IN_DONT_FOLLOW` (`watch_flags` :2945, `add_watch` :3567), and the listing follows such a link.
- **P12. The walk catches `OSError`, not every `Exception`** (section 7): :3788. The broad catch hides
  `tests/test_inner_mounts.py:91`, which uses `errno` without importing it (a root-only test that passes only through it).
- **P13. "Event name not found, ignoring event" as a DEBUG line** (item 9): still INFO (:3364), one line for every
  chmod or touch of a watched folder.

**P14. Spec text left behind the code** (documentation only). Source: the round 19 spec's sections 2.2 (a folder under
keep is hard-linked, not exchanged), 3 (the staging rule, the lost-manifest row), 4.3 ("No forward rule is used"), 5 (a
filesystem with no exchange is treated as a pool, not only mergerfs), 6 (the estimate changed) and 13 (line numbers),
where the round 20 plan's proposed spec edits were applied only in part; the 0.55.5 spec's L4 summary table (three and
four mount-table reads, not two and three) and its 5.9 (L10 decides "gone" by listing the parent, not by an lstat).
State: open. Next: one docs commit.

**P15. Every test module carries its layer marker.** Source: `specs/2026-08-12-full-test-suite-design.md`, Goals and
"1 Pytest config". State: partly done. Eight modules carry none (`test_crash_power_loss`, `test_r_batch`,
`test_r_readers`, `test_r_scan`, `test_r_sizes`, `test_sysctl_limits`, `test_tree_writes`, `test_version_walk`: 226
tests), so `pytest -m unit` leaves out most of design R's unit tests; `test_crash_safety.py` and
`test_backup_replay_ordering.py` are still `unittest` classes, which the spec said to move "when touching them". Next:
the next round that touches the tests.

## Questions waiting for the user

- **Q1.** `mv q a; rm a` (the round 13 spec: "outside this round, for the user"): the replay alone keeps the old `a`
  until the check after the batch removes it, so the committed version is right; `tests/test_rename_heavy_batches.py:219`
  says "left open". Recommended: Not an issue, as that check runs after every batch.
- **Q2.** P10 to P13: carry them into a round, or drop them.
- **Q3.** Four notes the names-chains spec (2026-10-21, "Left as they are") never wrote down: the commands redirect
  stdout and stderr process-wide while they load the rules (~14814); `get_path_fs_info` logs through the backuper's
  logger in the commands (~11106); folders that cannot be locked (NFS) are not kept apart, and a microsecond window
  between an in-place mkdir and its lock can leave an extra empty moved-aside folder (~16190); a `cp` that outlives the
  stop timeout may write a partial file after the lock is released. Known limitations to write down, or fixes?
- **Q4.** Lines for the shared lessons file that the 0.55.5 spec (section 11) and plan (Task 13) said to propose, never
  asked: sharpen "What a restart rescans follows from what could change while it was down, not from the job it
  resumes." with "; when it rescans everything, drop the saved work it would resume"; add "A record describes an
  object, not a name: move it with the object, and only once the object has moved."; add "When a guarantee moves
  upstream, remove the downstream check that stood in for it." Design R's lesson (its section 15) is in
  `docs/lessons.md` but not in the shared file either.
- **Q5.** Round 22's costs above 0.55.1, accepted by the main session (the step back's item 20) without a pick of the
  user's: move-outs +7 to 8%, moves into new folders +5%, a move out of a new folder about 1 ms, a folder moved out for
  good 0.3 to 0.7 ms, the move-out peak 11.77 MiB against 0.89.
- **Q6.** 0.55.5's calls to confirm at its rollout, not yet answered: RF2-1 ruled Not an issue (a millisecond race, as
  in 0.55.4); the behaviour changes with no pick of their own (the waits for an fstab disk at the job vault or under a
  pool disk, the job vault folder made before the first scan, a too-long link copy left out, a first version locks
  first, pruning a batch earlier under an inode limit, no UNREADABLE for a folder gone mid-walk, restores handle each
  file by its filesystem); docs text beyond the approved wording.
- **Q7.** The upstream report to the f2fs list (a checkpoint inside `symlink(2)` keeps a link with no target) is
  drafted, for the user to send from their own address; whether it went is not known.

## Candidates, never agreed

Kept so they are not lost; none is planned until the user picks it.
- Footprint ideas the 0.55.5 measurement found and did not propose: a compare thread count, the sqlite cache size,
  slimmer watch records, `python -OO`, `PYTHONMALLOC=malloc`.
- One key in place of the restore marker's two (0.55.5's L8: it saves no I/O; "Not this round").
- Size-based skipping (the skip-list spec's non-goal, "a separate, possible later feature").
- Two mergerfs oddities round 22's first design saw on a scratch pool and did not run down: a folder mtime a few ms
  off, and `add_watch` through an open parent making the pool list folders that were not there.
- Cases round 22 reasoned about and never ran: a mount below a new folder whose parent moved out, the overflow
  restart's walk meeting a folder made in the batch, the settle's placement window.

## Closed

Releases, newest first (the spec and plan of each are in `docs/superpowers/`):
- 0.55.5, 2026-11-14 (9fcbcfa; main 720e518): four deferred fixes and the lightness round.
- 0.55.4, 2026-11-11 (60baf6a): round 22's step back, the watcher's always-probed move.
- 0.55.3, 2026-11-10 (9bbb0f8): the flush round, syncs through handles opened before the writes.
- 0.55.2, 2026-11-09 (bca4b9c): the restore sync, the XFS size estimate, refused long links.
- 0.55.1, 2026-11-07: watcher fixes; the no-copy move dropped ("Drop the feature (Recommended)", 2026-11-07).
- 0.55, 2026-11-06: design R with pools P2 (round 20).
- 0.54.1, 2026-11-04 (c6d5b95): backups wait for restores.
- 0.54, 2026-11-04 (eb5f786): folder times kept in every version.
- 0.50 to 0.53, 2026-11-03: rounds 14 to 17 (copy and prune threads, pool power-loss prune); no spec files.
- 0.49 (922413d), 0.48 (cb6ccb3), 0.47 (99a95a1), 0.46 (e7f9c74): rounds 13, 12, 11, 10.
- 0.45 pool disks, 0.44 user links, 0.43 batch replay, 0.42 whole output, 0.41 whole log lines, 0.40 names and chains,
  0.39 status, history and restore, 0.38 reliability, 0.37 skip list; the crash-safety round and the full test suite
  before them.
- The "hard links as well as symlinks" idea (names-chains spec, "Future", noted at the user's request on 2026-10-21):
  built by design R.
