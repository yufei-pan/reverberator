# Progress

The open work on reverberator: every part of an agreed design, release plan or roadmap that is not finished, one row
each. Read this file whole when a session starts, after every compaction, clear or restart, and before saying how far
the work is or that nothing is left. A row changes in the commit that changes its work, and leaves the open list only as
done (with its commit or release) or as dropped (with the user's words and the date). History and reasoning live in the
specs, plans and commit messages, not here.

First written on 2026-11-14, with 0.55.5 live (main 720e518), from every spec and plan in `docs/superpowers/`: each
part's state was taken from the code and the commits, not from notes. An audit against the user's own messages
(2026-11-14) added P16, Q8 (closed the same day) and three candidates, moved P9 to the candidates, and corrected P7, P8,
Q5 and the closed list. On 2026-11-14 the user picked the fixes round as the next work: round 0.55.6, branch `r0556`.

## The goal, in the user's words

- 2026-11-03: "I want this to be as light and as fast as possible... cause it is an backup solution, so it is designed
  to always in run the background. so every little bit will sum up to a lot over days month years."
- 2026-11-03: "simpler and smarter is better"
- 2026-11-04: "one of the core for reverberator is reuse existing linux features and easy browse / restore. we can
  introduce more efficient methods if that reduces usage for users that do not need to manually browse the folders and
  do not need to able to copy out entire versions from the backup store"

## Standing decisions

The user's rulings on how the project is worked, as opposed to what gets built. A line changes only on the user's word.
- Questions go to the user through the question tool, with choices: "why are you not asking me questions via the
  tool?" (2026-10-18).
- While the user is away, work goes on and questions wait for their return: "good night. please continue working and
  ask me questions when I am back" (2026-11-04); "keep working until I ask you for questions thanks." (2026-11-07).
- Work happens in a worktree, never in the checkout the live service runs from: "Separate worktree (Recommended)"
  (2026-10-18).
- Each release is merged and rolled out on the user's pick for it; the agent restarts the live service by the runbook
  (rule-file backup, restart, health check): "I restart it with the runbook (Recommended)" (2026-10-23), the latest
  "Roll out now (Recommended)" (2026-11-14). Twice the pick let a release roll out when green without waiting
  ("Merge, restart, then push (Recommended)", 2026-11-07, for 0.55.1; "Roll it out when green", 2026-11-10, for the
  flush round).
- The repo is public: no private hosts, paths, job names or disk details in tracked files or commit messages, and a
  scrub check of the new commits before every push; the user's name and email stay. Their words: "yeah maybe let's
  also scrub the personally identifiable information from the repo" and "you can note my name and that email is public
  so it is fine to keep." (2026-11-05); "Scrub first, then push (Recommended)" (2026-11-06); "Push after scrub
  (Recommended)" (2026-11-14).
- Main is pushed after a healthy restart onto it: "Push after a healthy restart (Recommended)" (2026-10-28).
- The suite runs in parallel: "yeah set up pytest-xdist so the suite runs in parallel" (2026-11-05).
- pytest never runs as root on the host (a hook the user approved on 2026-11-08); root, loop and mount tests run in
  reverberator's own test VM: "A test VM of its own (Recommended)" (2026-11-09).
- The test VM is stopped and cleaned up after a run once it is not needed: "maybe shutdown / clean after your stuff when
  you do not need it anymore" (2026-11-09). It has 8 GB guaranteed, growing to 16 GB while the host has room: "for vm,
  can we set ballooning memory?" and "Balloon 8–16 GB (Recommended)" (2026-11-11).
- Parallel test runs follow a headroom rule: another capped run starts while at least 8 GB would still be free after it
  and memory pressure (full avg60) is under 5; under 5 GB free, or at 5, the newest run stops and goes back in the
  queue. Their words: "maybe let's dynamically adjust how parallel we run stuff?" and "Headroom rule (Recommended)"
  (2026-11-11).
- Release gates include the mergerfs and power-loss tests: "Bring both back (Recommended)" (2026-11-08).
- A cold measurement comes from the live backups after a deploy, not from flushing the host's page cache: "Use the live
  backups (Recommended)" (2026-11-03).

Decisions of the session that coordinates the user's other sessions ("chief") on how this session uses shared usage
limits are kept outside this public repo, in the agent's private notes beside its memory; read them with this file.

## Open parts

**P1. The deferred entries of `docs/limitations.md`.** Source: the 17 entries whose kind is deferred. State: round
0.55.6 (branch `r0556`) takes the entries whose "Revisit when" names the round after 0.55.5 (15 of the 17); its spec
(`specs/2026-11-14-r0556-design.md`, 0c13d04). The other two wait for upstream fixes. Where the round stands
(2026-11-15): the spec check against the user's words and a second opinion against the code are done (their reports
are in the session's scratch folder, `r0556/`), and the spec is revised from them (1e96eeb, 33 findings: 29 taken or
corrected, 4 rejected with reasons in its commits). Its questions were Q9 to Q15: Q10 to Q12 are closed by chief's
decisions, the rest are below. The plan is written
(`plans/2026-11-15-r0556.md`, 973c57d, 22 tasks) on the recommended options; a table at its top and a [Q<n>] mark on each
task say what another answer changes, Task 18 runs only on Q15 (a), and Task 2 (the healing test) runs second so Q15
can be asked while the round builds. The plan corrects the spec in places (listed in its Calls to confirm; the spec
stays as written). Next: building, by subagent-driven development, on the recommended options: chief said to build
meanwhile while it asks the user Q9, Q13 and Q14 (2026-11-15). Whether that lifts chief's earlier order of the same day
(the spec, its questions and that night's P7 readings before any building) is asked of chief: until it answers, building
waits for P7's 24-hour reading (2026-11-15 23:01 PST), because the worktree sits in the busiest job's tree and a build
there adds to the writes it measures. Behind it: a deferral is planned work; the user's pick 2026-11-14,
"Fixes round (Recommended)".

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
and its second opinions (parts that can go; not in a spec). State: in round 0.55.6 (branch `r0556`), spec in its
check. Behind them: "simpler and smarter is better"; ruled "can go, next round" by the main session: its own
housekeeping, with no pick of the user's.

**P7. The live measurement after design R.** Source: `plans/2026-11-05-round20.md`, Rollout; the round 19 spec's real
writes after release. State: measuring. To measure on the current release: writes per backup of the busiest job and per day (the vault disks' lifetime write counters) against
the spec's 24 to 36 MiB a cycle and 0.6 to 0.85 GiB a day, f2fs GC's share, prune times, idle CPU, peak memory.
First readings, 2026-11-14 23:01 PST, 0.55.5 at 21 hours. Answered: between backups every vault disk writes 0.0 MiB a
minute (0.54.1: 16); prunes take 0.32 s at the median and 1.90 s at most (0.54.1: 14.3 and 26 s); memory is 19 MB
resident, 87 MB in swap, peak 158 MB. Open: since the host's boot 6.1 days earlier, the busiest job's vault disk took
59.5 GiB (9.7 GiB a day), 81% of it moved by f2fs's background GC, mostly node blocks; the other three vault disks 0.28
to 0.48 GiB a day. What wrote it is not known yet: other programs write to the same disks; the busiest job's batches
grew to 5,000 to 31,000 entries as worktrees came and went in its tree; and that job now backs up about once a day
(the measuring agent's reading: its minimum interval never sees an hour of quiet; not verified). Idle CPU was 0.46% of
a core with agents busy in the tree (0.54.1: 0.03%), so not a quiet reading. Next: readings around the busiest job's
next cycle (2026-11-15 about 01:30 PST) and 24 hours after the first (2026-11-15 23:01 PST), both scheduled as
read-only background scripts writing to the session's scratch folder (`p7/snap-a1.txt`, `snap-a2.txt`, `snap-d.txt`;
`delta.py` subtracts two snapshots); then find what the GC moved, and whether the daemon's own share is over the
target. The vault disks are mounted with f2fs `mode=lfs` and `background_gc=on`; whether that drives the GC share is
not checked. A change to those mount options is an fstab change: the user's OK, through chief.
Behind it: the goal (light), the spec's targets, and the user's words 2026-11-04, "ok, let me know the write numbers
when it's done", with their pick 2026-11-06, "Accept them (Recommended)", on two rehearsal numbers over the plan's lines.

**P8. 0.55.5's memory at the uptime of 0.55.4's baseline.** Source: `plans/2026-11-13-r0555.md`, Task 15 and the
rollout. State: two readings on 2026-11-14: 95 s after the start's last commit, anonymous 104.8 MB, none of it in
swap, peak 158 MB; at 14 hours (15:20), anonymous 91.2 MB (18.5 MB in memory, 72.7 MB in swap), resident 30.9 MB, peak
158 MB. Next: read again at two days' uptime, about 2026-11-16, against 0.55.4's 163 MB anonymous (18 MB in memory,
145 MB swapped) and 150 MB peak. The README (line 90) says idle memory stays near 35 MB, which the tests measured: live,
only the resident part is near it, as swap holds the rest. If the anonymous total stays far above it, find what holds
the memory and correct the line. housekeepd takes
the reading (case 572, from 2026-11-16, the user's pick "Leave housekeepd a note (Recommended)"). Behind it: the
user's pick "Trim, shrink, 2 arenas (Recommended)" (2026-11-13).

**P10 to P13. Four parts of round 22's first watcher design that the step back never took up.** Source:
`specs/2026-11-08-round22-watcher-design.md`. Its top says it was not built; the step back replaced its watcher work
and says nothing of these. State: in round 0.55.6 (branch `r0556`), spec in its check. Behind them: the user's
picks 2026-11-14, "Carry all four (Recommended)" and "Fixes round (Recommended)".
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
State: in round 0.55.6 (branch `r0556`), as one docs commit. Behind it: the main session's own housekeeping, with no
pick of the user's.

**P15. Every test module carries its layer marker.** Source: `specs/2026-08-12-full-test-suite-design.md`, Goals and
"1 Pytest config". State: partly done. Eight modules carry none (`test_crash_power_loss`, `test_r_batch`,
`test_r_readers`, `test_r_scan`, `test_r_sizes`, `test_sysctl_limits`, `test_tree_writes`, `test_version_walk`: 226
tests), so `pytest -m unit` leaves out most of design R's unit tests; `test_crash_safety.py` and
`test_backup_replay_ordering.py` are still `unittest` classes, which the spec said to move "when touching them". Next:
round 0.55.6 (branch `r0556`), which touches the tests. Behind it: that spec's goals; no pick of the user's is on record for it.

**P16. Check whether a folder whose own metadata copy failed heals in later versions.** Source: the user's pick
2026-11-03, "Not an issue, check healing (Recommended)", on a folder that keeps the setgid or default ACL it inherited
when its own metadata copy fails (an ERROR line, and the folder listed as unsynced). State: not started; no spec, plan
or commit has a result. Round 18 (0.54) and design R changed how folder metadata is copied since, so the check runs on
the current release. The entry "A folder whose extended attributes alone fail to copy keeps the wrong ones" covers
only the xattr case. State: in round 0.55.6 (branch `r0556`), spec in its check: force such a failure in a test,
then see what the next versions hold. Behind it: that pick, and "Fixes round (Recommended)" (2026-11-14).

**P17. Four notes the names-chains spec (2026-10-21, "Left as they are") never wrote down** (was Q3): the commands
redirect stdout and stderr process-wide while they load the rules (~14814); `get_path_fs_info` logs through the
backuper's logger in the commands (~11106); folders that cannot be locked (NFS) are not kept apart, and a microsecond
window between an in-place mkdir and its lock can leave an extra empty moved-aside folder (~16190); a `cp` that outlives
the stop timeout may write a partial file after the lock is released. State: in round 0.55.6 (branch `r0556`): each
goes down the ladder there; one left as a known limitation comes back to the user as its own question. Behind it: the
main session's call (2026-11-14), told to the user with the round's question.

**P18. Lines for the shared lessons file** (was Q4), which the 0.55.5 spec (section 11) and plan (Task 13) said to
propose and never did: sharpen "What a restart rescans follows from what could change while it was down, not from the
job it resumes." with "; when it rescans everything, drop the saved work it would resume"; add "A record describes an
object, not a name: move it with the object, and only once the object has moved."; add "When a guarantee moves
upstream, remove the downstream check that stood in for it."; and design R's lesson (its section 15), which is in
`docs/lessons.md` only. State: in round 0.55.6 (branch `r0556`): written as the agent rules say (APIs: a lesson that
would change a design in an unrelated repo gets one line in the shared file), listed in its Calls to confirm. Behind
it: the main session's call (2026-11-14).

## Questions waiting for the user

Round 0.55.6's questions, from its spec (`specs/2026-11-14-r0556-design.md` section 26, 1e96eeb, where each is written
out at length). Q9, Q13 and Q14 are with the user: chief asks them and sends the answers (2026-11-15); chief decided
Q10 to Q12 (Closed). Q15 waits for the healing test's results. What waits on each: its
`docs/limitations.md` entry and, for an option other than the recommended one, the part it adds to the plan. The plan
is written on the recommended options and marks the tasks an answer would change. Each recommended known limitation
here leaves a wrong result, which the ladder calls always worth fixing: picking it overrides the ladder.

- **Q9. A file whose read fails only before its last 64 KiB** (D1's rest). The operator sees: when it is the only
  change of a batch or a full comparison, one version that changes nothing at each full comparison and each batch of its
  events, with its UNREADABLE alert; under Keep N each pushes the oldest real version out. The round fixes the rest of
  the entry (a file whose tail fails). Why not fix: a whole-file read at the check (a second read of the first file of
  every batch, uncached for a large one), or a take-back at the commit path, the rollback path the user declined on
  2026-11-13: "Accept the race (Recommended)", over "undoing the version after the copy instead of checking before,
  which adds a rollback path". Revisit when: one file's UNREADABLE alert repeats at full comparisons and `history`
  shows a new version each time. Drops: "Fixes round (Recommended)" (2026-11-14) put this entry's fix in the round.
  - (a) A known limitation (Recommended).
  - (b) The whole-file read at the check.
  - (c) Keep it deferred: the take-back designed in a round of its own.
- **Q13. A name a network filesystem lists but cannot look up, in a batch's scopes** (D13's scope half). The operator
  sees: on CIFS or sshfs with such name trouble, a batch whose events name that very path takes it as deleted: the new
  version lacks it and all under it, with no line; older versions keep it. The watcher's half and the whole-tree walk
  are fixed in the round. Why not fix: the fix lists the parent of every path a batch finds gone, on every delete's path
  (about 8 ms a batch in a folder of 100,000 names, about 0.1 ms in one of 1,000). Revisit when: a job monitors a CIFS
  or sshfs mount. The user's words: "Fixes round (Recommended)" (2026-11-14) put the entry in the round; on another
  rare case (2026-10-26): "if unable to do this cleanly I think it also make sense to put as limitations".
  - (a) A known limitation, the watcher's half built (Recommended).
  - (b) The parent-listing rule in the scope walks.
- **Q14. A restore target that cannot be locked (NFS)** (P17's one case left). The operator sees: two restores run at
  once into one NFS folder both run, where on a local disk the second is refused; two different versions restored there
  leave files of both, each saying done. Why not fix: it needs a second kind of lock (a POSIX lock on a lock file in the
  target) for two runs into one NFS folder at once. Revisit when: restores into an NFS folder are run side by side. The
  user's words: the round's option (2026-11-14), "I'd also check the four names-chains notes myself and come back only
  for any I'd leave as limitations"; this is the one.
  - (a) A known limitation, with one README line (Recommended).
  - (b) A POSIX lock on a lock file in the target where flock fails.
- **Q15. A folder metadata copy that fails once and does not heal** (P16 step 2; asked only with the healing test's
  results, for each case it finds not healing; reasoned: the source's own extended attributes). The operator sees: the
  folder keeps wrong extended attributes in every later version until its metadata is copied again for another reason.
  The user's words: "Not an issue, check healing (Recommended)" (2026-11-03): they ruled the case Not an issue and asked
  only for the check, so a fix goes beyond it.
  - (a) Build step 2 for the cases that did not heal: a mark in the failed folder's row and one retry (Recommended).
  - (b) Widen "A folder whose extended attributes alone fail to copy keeps the wrong ones" (this one overrides the
    ladder).

- **Q7.** The upstream report to the f2fs list (a checkpoint inside `symlink(2)` keeps a link with no target) is
  drafted, for the user to send from their own address (the draft is outside the repo). The user, 2026-11-14: "Not
  yet, keep it open".

## Candidates, never agreed

Kept so they are not lost; none is planned until the user picks it.
- Footprint ideas the 0.55.5 measurement found and did not propose: a compare thread count, the sqlite cache size,
  slimmer watch records, `python -OO`, `PYTHONMALLOC=malloc`.
- One key in place of the restore marker's two (0.55.5's L8: it saves no I/O; "Not this round").
- Size-based skipping (the skip-list spec's non-goal, "a separate, possible later feature").
- One pass over the watches per folder move, by an index of each folder's subfolders held all the time (the round 22
  step back's "could go later by an index of paths"; the code makes both passes, `reverberator.py` :2989, :3438,
  :3652). Not agreed: the user picked "Keep the full check (Recommended)" over such an index on 2026-11-10.
- A way to ask the daemon for a full comparison on demand (offered with 0.43; the user's pick 2026-10-22, "Not now
  (Recommended)").
- Hard links in place of forward links for an older version's unchanged files: noted at the user's request on
  2026-10-21 ("let's also put down a note for a future feature of supporting hard links instead of only using soft
  links"; the names-chains spec, "Future"). Not built: design R refers to unchanged entries by forward links (symlinks)
  and uses hard links only to record moved entries. It would lift the 40-link limit on browsing old versions by hand, at
  about an inode write per unchanged entry per version.
- Two mergerfs oddities round 22's first design saw on a scratch pool and did not run down: a folder mtime a few ms
  off, and `add_watch` through an open parent making the pool list folders that were not there.
- Cases round 22 reasoned about and never ran: a mount below a new folder whose parent moved out, the overflow
  restart's walk meeting a folder made in the batch, the settle's placement window.

## Closed

- Q10, D3 on a pool: (a), widen "A manifest lost in the same cut as a split on a pool" to the cut copy kept over a lost
  manifest on a pool. Chief's decision, 2026-11-15, on the user's words "Support pools with a limitation" (2026-11-04);
  no vault is on a pool. The entry's approved field says "chief's decision, 2026-11-15".
- Q11, what the length rule leaves out: (a), widen "A symlink the vault's filesystem can't hold is left out" to every
  entry kind, and keep the temporary name. Chief's decision, 2026-11-15, on the user's pick "Accept: leave it out, warn
  (Recommended)" (2026-11-09) for the same case in a symlink; no option keeps such entries, and (b) bought about 34 bytes
  of path for a second name form read for good. The entry says it drops the shorter name that "Fixes round
  (Recommended)" (2026-11-14) had planned; its approved field says "chief's decision, 2026-11-15".
- Q12, an xattr change made while down in a folder renamed during the start's walk: (a), a known limitation. Chief's
  decision, 2026-11-15, on the user's words on a rare case, "if unable to do this cleanly I think it also make sense to
  put as limitations" (2026-10-26): both fixes add a walk, or a part with its own state, for a three-way coincidence. The
  entry's approved field says "chief's decision, 2026-11-15".
- `mv q a; rm a` (the round 13 spec, left "for the user"): Not an issue, the user's pick 2026-11-14, "Not an issue
  (Recommended)": the check after every batch removes the old file; the test comment says so.
- P9, one pass over the watches per folder move by an index of paths: not an agreed part (the user's pick 2026-11-10,
  "Keep the full check (Recommended)"); moved to the candidates on 2026-11-14.
- Q8, rule columns 14 and 15 (Chain Length, Copy threads), asked for on 2026-10-27 and 2026-11-04 and inert since
  0.55: kept accepted and ignored, as the README says, the user's pick 2026-11-14, "Keep them ignored (Recommended)".
- Q5, three of round 22's costs above 0.55.1 (move-outs +7 to 8%, a folder moved out for good 0.3 to 0.7 ms, the
  move-out peak 11.77 MiB against 0.89): accepted, the user's pick 2026-11-14, "Accept them (Recommended)".
- Q6, 0.55.5's calls to confirm (RF2-1 Not an issue; the behaviour changes with no pick of their own; docs text beyond
  the approved wording): kept as built, the user's pick 2026-11-14, "Keep them all (Recommended)".
- Q3 and Q4 became rows P17 and P18 (2026-11-14): work for round 0.55.6, not questions for the user.

Releases, newest first (the spec and plan of each are in `docs/superpowers/`):
- 0.55.5, 2026-11-14 (9fcbcfa; main 720e518): four deferred fixes and the lightness round.
- 0.55.4, 2026-11-11 (60baf6a): round 22's step back, the watcher's always-probed move.
- 0.55.3, 2026-11-10 (9bbb0f8): the flush round, syncs through handles opened before the writes.
- 0.55.2, 2026-11-09 (bca4b9c): the restore sync, the XFS size estimate, refused long links.
- 0.55.1, 2026-11-07: watcher fixes; the no-copy move dropped ("Drop the feature (Recommended)", 2026-11-07).
- 0.55, 2026-11-06: design R with pools P2 (round 20).
- 0.54.2, 2026-11-05 (b4baf1f): the watcher's take fixes.
- 0.54.1, 2026-11-04 (c6d5b95): backups wait for restores.
- 0.54, 2026-11-04 (eb5f786): folder times kept in every version.
- 0.50 to 0.53, 2026-11-03: rounds 14 to 17 (copy and prune threads, pool power-loss prune); no spec files.
- 0.49 (922413d), 0.48 (cb6ccb3), 0.47 (99a95a1), 0.46 (e7f9c74): rounds 13, 12, 11, 10.
- 0.45 pool disks, 0.44 user links, 0.43 batch replay, 0.42 whole output, 0.41 whole log lines, 0.40 names and chains,
  0.39 status, history and restore, 0.38 reliability, 0.37 skip list; the crash-safety round and the full test suite
  before them.
