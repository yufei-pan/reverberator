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
(2026-11-15): the spec check against the user's words and a second opinion against the code are done (their reports are
in the session's scratch folder, `r0556/`), and the spec is revised from them (1e96eeb, 33 findings: 29 taken or
corrected, 4 rejected with reasons in its commits). Its questions were Q9 to Q15, all closed (the user's picks and
chief's decisions). The plan is written (`plans/2026-11-15-r0556.md`, 68fc1b0, 22 tasks) on the recommended options; a
table at its top and a [Q<n>] mark on each task say what another answer changes, Task 18 runs only on Q15 (a), and Task
2 (the healing test) runs second so Q15 can be asked while the round builds. The plan corrects the spec in places
(listed in its Calls to confirm; the spec stays as written). Building since 2026-11-16 22:15 PST (chief's decision of
that time), by subagent-driven development, on the recommended options, which Q9 to
Q15's answers all took; the build's ledger (task by task, rulings, deferred minors) is the git-ignored
`.superpowers/sdd/2026-11-15-r0556/progress.md` in the worktree. Where it stands (2026-11-17 11:20 PST): Task 1 (P15)
done and reviewed (71e4e42..1b5febe); Task 2 (P16's healing check) done and reviewed after two fix rounds
(2dc2fd0..8aed9ab), its results asked as Q15 (answered (a) 2026-11-17, so Task 18 is built); Task 3 (P4 to P6) done and
reviewed (926e963); Task 4 (P13) done and reviewed (4670ea0); Task 5 (P10) done and reviewed (c8eb142); Task 6 (P11)
done and reviewed after one fix round (3869779..f255db9); Task 7 (P12, D14, D13's watcher half) done and reviewed (b509e24..a41adcd; the walk's loop in the faster shape the main
session ruled on, a2d3a28, at Task 6's figure); Task 8 (D2, D1) done and reviewed (789edec); Task 9 (D4) done and reviewed after one fix
round (4f712ac..db9bd4b); Task 10 (D8, D7) done and reviewed (2b252b4, 93f6be9); Task 11 (D9, D11) done and reviewed
(8a8dfb7: a one-file batch reads /etc/fstab once, 18 times on a pool before); Task 12 (D10) done and reviewed (8c70fd6); Task 13 (D5, D6) done and reviewed after one fix
round (a15a420..b565fd2); Task 14 (D3 item 1) done and reviewed (102cf04); Task 15 (D3 items 2, 3) done and reviewed after two fix rounds and
a design check's rework (4449b76..07aba64: a link a cut left in staging stays there until the scan after the commit);
Task 16 (D15) done and reviewed after one fix round (46d124f, ee55869: a gate after a burst and a pin counting the
trim at each commit); Task 17 (P14) done and reviewed after one docs fix round (8c127fd, d2070f3); Task 18 (P16 step
2, on Q15's answer) done and reviewed (4652c40, eedbabd); Task 19 not built (every question took its
recommended answer); the round's cleanup done in three passes (88738db..cd8893e) and Task 20's docs (d2081b6; the shared
lessons file's lines committed, not pushed); the flaky watcher test fixed in the test (28e879c: it wrote before the
watcher's settle had removed the moved folder's watches; 22 of 240 runs under load failed before, none after); the final
review done (2026-11-22: with fixes), its fix wave, re-review and residual pass done, every finding fixed or
bucketed (fourteen deferred entries for the round after 0.55.6); the VM gate passed on the last code commit and the
container suite on the version commit; version 0.55.6 at e166baa. Waiting for the user's pick to merge and roll out
(Q19); a history cleanup before the push is done (2026-11-22). The round's record (measurements, Calls to confirm,
the build's rulings): `docs/progress/r0556.md`. Next while Q19 waits: the round after 0.55.6 (0.55.7, its fourteen
deferred entries): its spec (`specs/2026-11-22-r0557-design.md`, 2026-11-22) is written, checked by fresh agents four
times and revised after each (a step back redesigned two parts that drew findings in every round); its questions Q20
to Q23 are decided, each on its recommended option (chief's decisions, 2026-11-22; Closed); its plan is written
(`plans/2026-11-22-r0557.md`, 20 tasks, on those options: a table at its top and a [Q<n>] mark on each task say what
another answer would change). It is built on its own branch after Q19's answer (no build on top of the unreleased round).
It pauses for shared usage limits as those decisions say. Behind it: a deferral is planned work; the user's pick 2026-11-14, "Fixes round (Recommended)".

**P2. Remove the 0.54 reader, prune and conversion code.** Source: `specs/2026-11-04-round19-vault-r-design.md` sections
8, 9 ("the 0.54 parts go in a later release") and 12 step 3; `plans/2026-11-05-round20.md`; commit 9ab7949 ("stays for
one more release"). State: not started. Still in 0.55.5: `decrement_stepper`, `VersionMoves`, `vault_chain_hop`,
`parse_chain_text`, `is_prune_temp`, the conversion, 72 lines marked "# goes with the 0.54 reader", the manifest's
`copy_version` column and `monitor_paths` key; six test files build 0.54 vaults (`STILL_054`). About 1,900 lines of code
plus tests. Next: its own round. A lost manifest then needs its layout found another way (`vault_layout()`,
`layout_known()`, `recorded_layout()`, `scan_gets_r_rules()`, `conversion_unfinished()`, the guards in `do_backup()`).
Behind it: the user's pick "Keep it one release" (2026-11-04). Every live vault was converted on 2026-11-06.

**P3. The no-copy move into a new folder: a design round.** Source: `specs/2026-11-12-r0555-design.md`, its opening and
"The user's words"; the known limitation "A folder or file moved into a new folder is copied whole". State: the design
study is done (2026-11-23, read-only; its brief, report and probes in the git-ignored `.superpowers/p3/` of the
worktree). Its route: leave the watcher as it is and act at the copy. When the replay is about to copy a regular file
and a file that left the version in the same batch compares equal in full, with the same mode, owner, mtime and
extended attributes, the previous version's file is hard-linked to the new place (the state a move leaves); anything
else is copied as today, so no order of events can make a version worse than a copy. It costs a read of both files in
place of a write, and no state at rest. A watcher route cannot reach the case: a probe saw a program's back-to-back
`mkdir` and `rename` arrive as an event in 2 of 300 runs, and every fix of 0.55.1 that filled that gap was fooled. On
the live host the study found it not urgent (its report, outside the repo, has the details). Its spec is written (`specs/2026-11-23-no-copy-move-design.md`, ef89365, 2026-11-23, on Q24's recommended
option with the places the other option changes marked [Q24]); where the code differs from the study it follows the
code (the table of released files is fed where each delete is applied, from what that delete took into the version
before; its Calls to confirm list each departure), and it adds Q25. The spec check is done (a fresh agent with the user's words, and five second opinions against the
code): its main finding is that on a vault with two renames (a pool, or no rename exchange) the deletes are recorded
before the replay, so as written nothing would link there while the estimate stopped charging; the spec was revised
from the findings (a8bef37: the feed also comes from those records; the compares run in parallel where the copies run;
Q24 gained a "not now" option and lists exactly what (a) narrows), and re-checked (no step back needed; new findings on
the candidate choice, the compare's timing, the roll-forward, the estimate's shortfalls and the docs texts). Its second
fix round is done (a1f9d7d); its findings kept landing in the same parts (how a candidate is found, the estimate's
prediction), the spec grew to 140 KB, and the lookup it was given misses the main shape below the top of the monitored
folder, so a fresh agent stepped back on the design (the agent rules' "Step back when findings repeat"). Its answer, which
the main session takes: the route stays, and its table of released files, the feed at the deletes and the search by
size and time go; a file is looked up by the names of the batch's deleted entries, at the same place below the deleted
one in the version before, the size books say whether the tree let it go, and the estimate asks the same lookup. It
finds `mkdir new; mv big new/` anywhere in the tree on every kind of job; a move that renames the entry stays a copy.
The spec is rewritten on it (bb67c8d, 2026-11-23; 100 KB from 140), and Q24 and Q25 here from it, kept in step since. Its fresh spec
check found it reaches the goal and that the size books' rule it rests on holds for every way the writer records an
entry; its findings (builder gaps, wording, the cold measurement taken from live backups as the standing decision says,
the compares bounded by `--threads`, one lstat only where a name matches) are fixed (7bc36d4), and a re-review of
the fix found no wrong result; its points (the compare pool's limits and errors, a link's flush and leftovers, test and
text gaps) are fixed in a second round (221a531), with the compare pool kept only if the build measures it faster
than one compare at a time; the review after that round found the findings repeating in the compare, so the last round
removed the parallel compare for one that runs on the replay's own thread, and cut the spec back to 106 KB with every
decision kept (a28f86b, 2026-11-23); a short check of that round found no bug, and a text pass followed (371dbad). The
spec is settled. Its plan is written (`plans/2026-11-23-no-copy-move.md`, 6fdd367, 9 tasks, on Q24 (a) and Q25 (a), with a table
and [Q24]/[Q25] marks for what the other options change), checked twice (nothing that could give a wrong version; the findings on test strength, venues and buildability fixed
in da6288c and ff87dd7, 114 KB, most of it test code); from here the build's own gates check its tests (each test's run
on the base and on its task, the per-task reviews, the final review). Done as a design round (2026-11-23). The build
waits for Q24 and Q25 and for round 0.55.7's merge, on its own branch, by subagent-driven development. Built as its
own round after 0.55.7, and only after Q24's answer. The main session's calls: build it (the user's pick of 2026-11-12 gave it its own design round), and the
proof is the full compare alone (no inode column: no format change, and an inode cannot show a write through a mapped
page that a compare sees).
Behind it: 2026-11-12, "continue next phase please" and the pick "Fixes + lightness, one round (Recommended)", offered
with "the no-copy move into a new folder gets its own design round after".

**P4. Remove the backuper's dead branch** at `reverberator.py` ~4988-4995. **P5. Remove the lost-manifest branch of
`drop_untracked_deletes(newest_path=)`.** **P6. Remove `remove_pending_file()`.** Source: round 0.55.5's final review
and its second opinions (parts that can go; not in a spec). State: built on branch `r0556` (Task 3, 926e963, reviewed;
41 lines fewer). The review found one more unreachable part of the same kind, the rebuild before `hand_over()` in
`do_backup()`, with tests that reach it by hand: it goes in the round's cleanup before the final review (the main
session's call, as these were). Done with the round's merge. Behind them: "simpler and smarter is better"; ruled "can go, next round" by the main session: its own
housekeeping, with no pick of the user's.

**P7. The live measurement after design R.** Source: `plans/2026-11-05-round20.md`, Rollout; the round 19 spec's real
writes after release. State: measuring. To measure on the current release: writes per backup of the busiest job and per day (the vault disks' lifetime write counters) against
the spec's 24 to 36 MiB a cycle and 0.6 to 0.85 GiB a day, f2fs GC's share, prune times, idle CPU, peak memory.
First readings, 2026-11-14 23:01 PST, 0.55.5 at 21 hours. Answered: between backups every vault disk writes 0.0 MiB a
minute (0.54.1: 16); prunes take 0.32 s at the median and 1.90 s at most (0.54.1: 14.3 and 26 s); memory is 19 MB
resident, 87 MB in swap, peak 158 MB. Idle CPU was 0.46% of a core with agents busy in the tree (0.54.1: 0.03%), so
not a quiet reading. Since the host's boot 6.1 days earlier, by the filesystem's own counters, the busiest job's vault
disk took 60 GiB (9.9 GiB a day): f2fs's background GC moved 48 GiB of it (7.9 GiB a day), collecting sections still
about 93% valid, three in four of its blocks node blocks; every program together wrote 9.4 GiB (1.5 GiB a day); the
checkpoints' own areas 1.9 GiB. The other three vault disks took 0.28 to 0.48 GiB a day. The disk is a member of a
storage pool that other programs write to, and the job's manifest lives on it.
Reading A, 2026-11-15 01:28 to 01:55 PST, around the busiest job's daily batch (01:36: a full comparison, 23,002
entries: 28,347 creates, 14,048 deletes, 1,117 modifies, 2,176 attribute changes; the oldest version pruned): the disk
took 5.17 GiB, the daemon's own data writes were 5.28 GiB, so the daemon was nearly its only writer; the GC moved 88 MiB
(2%) in the window. The files the batch copied are 4.63 GiB at their current sizes (2.3 GiB in one project's agent
folder, 1.0 GiB of release evidence, 0.7 GiB in three archives), which leaves about 0.46 GiB for the rest: inodes,
links, the manifest, the deletes. That split is an estimate: a moved file recorded by a hard link would move bytes from
the first figure to the second. Daemon CPU: 32 s for the batch. Against the targets: the spec's 0.6 to 0.85 GiB a day
was 24 hourly batches of 212 to 1,353 entries at 24 to 36 MiB each; the job now makes one batch a day (Q16, kept), whose
overhead of about 0.46 GiB is under the day target, and whose copied bytes are what the tree changed that day.
Why one batch a day: the minimum interval is a quiet time (a batch starts once the tree has gone that long without an
event, or at the maximum interval; the watcher's rule since the first release), and since 2026-11-12 the tree has had
one hour of quiet: the job's versions came at 11:27 on 11-12 (that quiet hour), 11:27 on 11-13 and 01:36 on 11-15 (the
24-hour maximum), and at the restart on 11-14; until 2026-11-09 it made about 24 a day.
Reading B, 2026-11-15 01:56 to 08:00 PST, hourly: after the batch the GC ran about five hours, one call a minute (its 60
s sleep), each moving one 16 MiB section (8 segments) about 94% valid: 4.09 GiB moved, 93% of the disk's 4.38 GiB of
writes in that time (the rest not attributed); from 07:00 it found nothing to move. With the 88 MiB during the batch,
the GC's tail was about 4.2 GiB against the batch's 5.17 GiB, and it gained 67 free segments (134 MiB) on a disk 6%
full: a section holding a few blocks the batch or the prune invalidated is rewritten whole, and `mode=lfs` reuses space
only through the GC. So `background_gc=on` drives it, not a lack of space; f2fs's valid-ratio threshold for the
background GC is set to 80, yet the GC took sections 94% valid (the threshold is for zoned disks; these are not). More
batches a day would likely mean more such tails (not measured), which bore on Q16 (closed: the user kept the rule). The
other three vault disks took 0.3 to 0.7 GiB each from 04:00 to 05:00 PST, 57 to 93% of it GC, while another job backed
up a database dump (the daemon wrote 192 MiB; the rest is not attributed, and the dump's own folder is on the same
pool).
Reading D, the 24 hours from 2026-11-14 23:01 PST: the busiest job's vault disk took 13.1 GiB, 4.5 GiB of it GC (35%);
the other three vault disks took 0.5 to 1.1 GiB each, 67 to 84% of it GC. The day held two of the job's batches: 01:36
PST (23,002 entries, reading A) and 22:41 PST (19,731 entries, 21 hours after the first, so started by an hour of quiet,
not the one-day maximum), whose GC tail falls after the reading. The daemon wrote 9.1 GiB in all and used 163 s of CPU
(0.19% of a core); in the last 15 hours, the second batch included, 28 s (0.05%; 0.54.1 idle: 0.03%). So the daemon's
own share is under the target: about 0.46 GiB a batch beyond the bytes that changed (reading A), and those bytes are the
tree's own changes, 3.5 to 5 GiB a batch now, which the spec's 24 to 36 MiB a cycle (hourly batches of a quieter tree)
did not foresee. P7 has measured all it set out to: writes, the GC share, prunes, idle CPU, memory. Q17's answer (the
user, 2026-11-17): background GC off on the four vault disks.
Carrying it out (a host change, the user's to run): one root script outside the repo, run by the user. It shows the daemon's state, each vault disk's options,
GC thread and counters; backs /etc/fstab up with a date; changes `background_gc=on,gc_merge` to
`background_gc=off,nogc_merge` in the four vault disks' lines only (checked before it writes); remounts each with
`mount -o remount,background_gc=off,nogc_merge <dir>`; then checks /proc/mounts shows both, the disk's `f2fs_gc-<dev>`
thread is gone, and no f2fs kernel line or daemon ERROR came since, and prints the undo. `nogc_merge` is needed too: in
kernel v7.0's f2fs, with `gc_merge` set the GC thread runs whatever `background_gc` says (`__f2fs_remount()` stops it only
when `bggc_mode == BGGC_MODE_OFF && !test_opt(sbi, GC_MERGE)`; `gc_thread_func()` has no check of the mode). No unmount
and no stop of the daemon: a read-write remount applies only the options given (`f2fs_apply_options()` masks by what was
specified), syncs only when going read-only, and changes nothing the daemon's disk checks key on (a mount's id, device,
root, source and type; the disk's ids); it can run mid-batch, waiting at most for the section the GC is moving. Next
reading, after the next large batch and over the 24 hours after: each vault disk's background GC calls and moved blocks
stay flat; the busiest disk stops writing within minutes of a batch's commit (no five-hour tail), and takes about the
batches' own bytes a day (reading D's 13.1 GiB less its 4.5 GiB of GC); the other three take 0.1 to 0.3 GiB a day; dirty
segments grow and free segments shrink by what partly emptied sections hold, with no foreground GC until free sections
run low (months on disks 6% to 31% full). The row closes with that reading.
Behind it: the goal (light), the spec's targets, and the user's words 2026-11-04, "ok, let me know the write numbers
when it's done", with their pick 2026-11-06, "Accept them (Recommended)", on two rehearsal numbers over the plan's lines.

**P8. 0.55.5's memory at the uptime of 0.55.4's baseline.** Source: `plans/2026-11-13-r0555.md`, Task 15 and the
rollout. State: two readings on 2026-11-14: 95 s after the start's last commit, anonymous 104.8 MB, none of it in
swap, peak 158 MB; at 14 hours (15:20), anonymous 91.2 MB (18.5 MB in memory, 72.7 MB in swap), resident 30.9 MB, peak
158 MB. Next: read again at two days' uptime, about 2026-11-16, against 0.55.4's 163 MB anonymous (18 MB in memory,
145 MB swapped) and 150 MB peak. The README (line 90) says idle memory stays near 35 MB, which the tests measured: live,
only the resident part is near it, as swap holds the rest. If the anonymous total stays far above it, find what holds
the memory and correct the line. A reading at 45 hours (2026-11-15 23:01 PST, 20 minutes after a 19,731-entry batch, so not idle): resident 86 MB
(74 MB of it anonymous), 39 MB in swap, peak 158 MB. housekeepd takes the reading (case 572, from 2026-11-16, the user's pick "Leave housekeepd a note (Recommended)"). Behind it: the
user's pick "Trim, shrink, 2 arenas (Recommended)" (2026-11-13).

**P10 to P13. Four parts of round 22's first watcher design that the step back never took up.** Source:
`specs/2026-11-08-round22-watcher-design.md`. Its top says it was not built; the step back replaced its watcher work
and says nothing of these. State: in round 0.55.6 (branch `r0556`), spec in its check. Behind them: the user's
picks 2026-11-14, "Carry all four (Recommended)" and "Fixes round (Recommended)".
- **P10. A tree walk without recursion** (its 2.3): `iter_tree_entries()` recursed by `yield from`, so a tree
  deeper than about 1,000 levels left its deepest folders unwatched, and the comparison, restore and vault walks
  through the same function stopped at the same depth. Built on branch `r0556` (Task 5, c8eb142, reviewed): both walks
  and `settle()`'s `is_real()` keep a stack, with the same yields in the same order; a tree 1,200 levels deep is
  watched, backed up, listed and restored. Done with the round's merge.
- **P11. The walk follows no link that replaced a folder while it ran** (2.5, item 7): the tree's watches were added
  without `IN_DONT_FOLLOW`, and the listing followed such a link. Built on branch `r0556` (Task 6, 3869779 and its fix
  f255db9, reviewed): each folder below a walk's root is opened with `O_NOFOLLOW` and listed by its handle, its watch
  added with `IN_ONLYDIR | IN_DONT_FOLLOW`; a folder replaced by a link or a file is gone, with one INFO line; the walks
  of folders the tree just made, and the size estimate, follow no link at their root. One case three second opinions
  raised, a folder *above* replaced by a link after the walk entered it, the spec rules Not an issue; one of them adds a
  file protected only by an ancestor folder's mode, which the final review weighs (the build's ledger). Done with the
  round's merge.
- **P12. The walk catches `OSError`, not every `Exception`** (section 7): the broad catch hid
  `tests/test_inner_mounts.py:91`, which used `errno` without importing it. Built on branch `r0556` (Task 7, b509e24 and
  a2d3a28, reviewed): the walk catches only its reads' OSError, so a bug in what it calls fails the backup attempt or
  the watcher's job with its traceback; it lists a parent once when many of its folders vanish (D14), and the watcher
  counts a folder it cannot open unwatched (D13's watcher half). Done with the round's merge.
- **P13. "Event name not found, ignoring event" as a DEBUG line** (item 9): built on branch `r0556` (Task 4, 4670ea0,
  reviewed): no log-file line for every chmod or touch of a watched folder any more, unless DEBUG. Its review found that
  a change to the monitored folder's own metadata alone makes no version (older than this round): a deferred entry in
  `docs/limitations.md` for the round after 0.55.6.

**P14. Spec text left behind the code** (documentation only). Source: the round 19 spec's sections 2.2 (a folder under
keep is hard-linked, not exchanged), 3 (the staging rule, the lost-manifest row), 4.3 ("No forward rule is used"), 5 (a
filesystem with no exchange is treated as a pool, not only mergerfs), 6 (the estimate changed) and 13 (line numbers),
where the round 20 plan's proposed spec edits were applied only in part; the 0.55.5 spec's L4 summary table (three and
four mount-table reads, not two and three) and its 5.9 (L10 decides "gone" by listing the parent, not by an lstat).
State: built on branch `r0556` (Task 17, 8c127fd and its fix d2070f3, reviewed): each edit says the rule the code
follows, with this round's changes in a clause. Done with the round's merge. Behind it: the main session's own
housekeeping, with no pick of the user's.

**P15. Every test module carries its layer marker.** Source: `specs/2026-08-12-full-test-suite-design.md`, Goals and
"1 Pytest config". State: built on branch `r0556` (Task 1, 71e4e42..1b5febe, reviewed): every test carries exactly
one layer by what it does (twenty modules had tests with none, not the eight first counted; about twenty tests had a
wrong or a second layer), the collection fails a module with an unmarked or a two-layer test, and the two `unittest`
modules are pytest functions. A few wording points and one more test's layer wait for the round's cleanup. Done with
the round's merge. Behind it: that spec's goals; no pick of the user's is on record for it.

**P16. Check whether a folder whose own metadata copy failed heals in later versions.** Source: the user's pick
2026-11-03, "Not an issue, check healing (Recommended)", on a folder that keeps the setgid or default ACL it inherited
when its own metadata copy fails (an ERROR line, and the folder listed as unsynced). State: not started; no spec, plan
or commit has a result. Round 18 (0.54) and design R changed how folder metadata is copied since, so the check runs on
the current release. The entry "A folder whose extended attributes alone fail to copy keeps the wrong ones" covers
only the xattr case. State: in round 0.55.6 (branch `r0556`). Step 1, the check, is built and reviewed (Task 2,
2dc2fd0..8aed9ab, tests/test_io_errors.py: 40 results, the same on 0.55.5's code). Its results were Q15, which the
user answered (a) on 2026-11-17: step 2 is plan Task 18 (the failed folder's row is marked, so the next comparison that
meets the folder copies its metadata again, once), not started. Spec section 16's reasoned list ("reasoned, not run")
is superseded by those results. Behind it: that pick, "Fixes round (Recommended)" (2026-11-14), and Q15's answer,
"Build the retry (Recommended)" (2026-11-17).

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

**P19. Check how design R's hard-link records behave on a mergerfs pool set to answer a cross-disk link with a
symlink.** Source: the review of P3's spec (2026-11-23). mergerfs's `link-exdev` option can make a link across its disks
succeed by writing a symlink in its place. A record that hard-links an entry into the version before (`keep_entry()`
through `link_or_copy()`, on a pool) would then leave a symlink to the tree's file there, and a later change of the tree's
file would show in the older version. State: checked 2026-11-23 in the test VM, on mergerfs 2.42.0 (the host's
version), with each `link-exdev` and `rename-exdev` mode (the probe and its logs are in the git-ignored `.superpowers/p19/`
of the worktree). No mode leaves a symlink where a hard link was asked. Under the create policy the pool tests use (pfrd,
not path-preserving), a link or a rename across disks is made on the source's disk: real hard links, which keep the old
bytes when the tree's file is replaced or removed. Under a path-preserving policy (epmfs) with `link-exdev=passthrough`, a
link answers EXDEV and `link_or_copy()` copies (the entry "A copy made where the vault refused a hard link" says so).
With any symlink mode of either option, mergerfs aborts on the call (an assertion of its own), and the pool is gone until
it is mounted again. Under `rename-exdev`, it has first moved the source into `.mergerfs_rename_exdev/` on the source's
disk, so after a remount the file is at neither name. That is an upstream bug; its report is drafted (Q26). So on this
version the record never takes a symlink. Three things are left. Under a path-preserving policy a tree move between
disks gets EXDEV from `os.rename`, which `TreeWriter.rename()` raises, so the attempt fails; what the retry does is not
checked. With `rename-exdev` set to a symlink mode, whether a version then misses the moved-away file, or the retry
brings it back, is not checked either. And a later mergerfs that fixes the abort could make the symlink. Next: backups
with such moves on an epmfs pool in the test VM, with `rename-exdev` at passthrough and at `rel-symlink`, then the
ladder for all three. The candidate fixes: read the pool's `link-exdev` through its control file, or compare the link's inode with
the source's. No vault is on a pool today. Behind it: the main session's call, on the goal (a version must hold the bytes
it backed up).

## Questions waiting for the user

Round 0.55.6's questions, from its spec (`specs/2026-11-14-r0556-design.md` section 26, 1e96eeb, where each is written
out at length), are all closed: the user answered Q9, Q13, Q14 and Q15, and chief decided Q10 to Q12 (2026-11-15).

- **Q19. Roll out 0.55.6** (P1; branch `r0556` at e166baa, gated: the container suite fails only main's 265 root-needing
  tests, and the test VM's whole suite, crash and power-loss runs pass). The round's Calls to confirm are in
  `docs/progress/r0556.md`: the final review's one Important finding and the pool pause rule deferred, not asked; the
  folder-above-a-link case Not an issue; a few behaviour and wording changes.
  - (a) Roll out now by the runbook (Recommended): merge into main, the rule-file backup, the restart, the health check;
    then the scrub of the new commits and the push after a healthy restart (chief's OK for the push).
  - (b) Hold: the branch stays as it is until the user picks a time.
  - What waits on it: the merge, the push, and the round after 0.55.6 (its fourteen deferred entries). The user's
    words behind it: "Fixes round (Recommended)" (2026-11-14); each release rolls out on the user's pick for it
    (standing decisions).

- **Q18. A folder whose metadata copy fails every time, beyond its extended attributes** (P16 step 2, Task 18). Q15
  (a), which the user picked on 2026-11-17, said: "A copy that fails every time is tried once more, then left." Built,
  that holds for a folder whose extended attributes alone fail to copy (its record then matches the monitored folder).
  When the failed copy also leaves the folder's mode, owner or time different (an attribute write failing with a full
  disk or an I/O error before the mode is set; a change of owner the vault's filesystem refuses), every later comparison
  that meets the folder copies it again, fails again, and makes a version that changes nothing, with its ERROR line, as
  0.55.5 does today. Under Keep N Versions each such version pushes the oldest out.
  - (a) Accept it as built and say so in the limitations entry (Recommended: no worse than 0.55.5; the case needs a copy
    that fails every time, which the ERROR line already reports; a stop needs a second mark with its own state).
  - (b) Build a "gave up" mark: after the failed retry the row is marked so no comparison copies the folder again until
    its own metadata changes. One more value and its rules, in the round after 0.55.6.
  - What waits on it: the limitations entry's wording (Task 20). The user's words it would narrow: "then left"
    (2026-11-17), for the mode, owner and time cases.

- **Q24. Whether to build the no-copy move now** (P3; written out in its spec's questions,
  `specs/2026-11-23-no-copy-move-design.md`, 371dbad). The route links a
  file from the version before, in place of a copy, only when the version before alone holds it, it compares equal in
  full, and it has the same mode, owner, group, mtime and extended attributes.
  - (a) Build it (Recommended): on a vault that links (a mergerfs pool's answer is the pool test's to show), with Only
    Sync Attributes on or off, a file under a folder the batch copies is hard-linked from the version before when the
    batch deleted an entry of the same name and the file at the same place below it is the same. It reaches `mkdir new;
    mv big new/` and `mkdir -p a/b; mv big a/b/` anywhere in the tree, to the same or another parent, a moved file as a
    moved folder, a move made while reverberator was down that kept the entry's name, and a tree deleted and unpacked
    elsewhere under its name with its times kept. As after a move, under Only Sync Attributes (the default) a later
    change of a linked file's mode, owner, times or extended attributes also shows at its old place in the version
    before (for an unpack or a `cp -p` then `rm`, the old file's place). Every copy the names do not reach stays a copy
    (the spec's section 7), chiefly: an entry renamed in the move; two deleted entries of one name in one batch; the
    second of two new files matching one old file; a file made in the batch and then moved; a file changed in the move's
    batch; an old place deleted after the copy; a delete and a create of one path; swaps; a cut batch's roll-forward; a
    vault that refuses hard links; a copy fallback, except where its path holds another deleted entry's name and the file
    there is the same. It narrows the entry "A folder or file moved into a new folder is copied whole" and README lines
    15 and 22, adds a sentence to "A move out of a folder that just left the tree is copied" and README lines 4, 43 and
    115, and drops that entry's spent revisit clause. It touches neither the watcher, the manifest, nor how the writer
    records. It is built after 0.55.7.
  - (b) Not now: keep the entry and the design on file, and build it when a size-limited job prunes for such a move, or a
    job over a tree of user files is added. The design study found it not urgent on the live host (its report, outside
    the repo, has the details).
  - Not offered: a search by size and time for a removed file anywhere in the batch, which would add moves that rename
    the entry; with Only Sync Attributes on (the default) it would do nothing, and it needs a table, an index and a bound.
  - What waits on it: the whole build (after 0.55.7), and Q25, which (b) makes moot. The user's words: "Drop the feature
    (Recommended)" (2026-11-07), with "the no-copy move gets its own design later", and on 2026-11-12 the pick "Fixes +
    lightness, one round (Recommended)", offered with "the no-copy move into a new folder gets its own design round
    after". (a) reaches beyond the move they named by the same rule; nothing they said is
    dropped.

- **Q25. The size estimate and a file the no-copy move will link** (P3; asked with Q24, moot under its (b)). With a
  size limit, the estimate before each backup decides how many old versions to prune. From P3's round it charges nothing
  for a file the copy step will find (its place below an entry of the same name the batch deletes holds a file of its
  size, mtime, mode, owner and group), so a move into a new folder no longer prunes for a copy that is never made. Where
  such a file is copied after all, the vault passes its limit by that copy until the next backup prunes, for four causes:
  its bytes or extended attributes differ, or it changed after the estimate looked (then by its whole size); its delete
  removes nothing there (the length rule, or another kind at its
  place); it is the second of two new files matching one removed file; its link fails (a vault that refuses hard links,
  or a mergerfs pool answering EXDEV between its disks: every such file, every time) or a look or read fails.
  - (a) Widen the approved entry "Size estimates leave out a version's own small blocks" to say so (Recommended): a prune
    made for a copy never made removes a version for good, an overshoot lasts until the next prune; no vault has shown a
    refused hard link yet, and the pool test shows which way mergerfs answers.
  - (b) Charge every copy as today: no new overshoot, but under a size limit each move into a new folder still prunes
    older versions for the whole moved size, the harm the round exists to remove.
  - What waits on it: the estimate's part of the spec, its texts (written only on the answer), and the build, which
    starts after both answers. The user's words it would narrow: none; it widens an entry the user approved (2026-10-26,
    "Known limitation (Recommended)"; last widened 2026-11-13, "Widen the entry (Recommended)").

- **Q26. Post a report to mergerfs** (P19). With a path-preserving create policy and a symlink mode of `link-exdev` or
  `rename-exdev`, mergerfs 2.42.0 on Linux 7.0 aborts on a link or a rename across its disks (`ugid.hpp:87: Assertion
  'newuid_ != FUSE_INVALID_UIDGID' failed`), and the pool's mount is dead until it is mounted again. The repro takes four
  lines, as root. A search found no report of it. The draft is outside the repo (the git-ignored `.superpowers/p19/` of
  the worktree), for the user to post from their own account.
  - (a) Post it (Recommended): a crash on a documented option, with a short repro; check the tracker for the assertion
    text just before posting.
  - (b) Not now: keep the draft.
  - What waits on it: nothing in reverberator. The user's words it would touch: none.

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

- Q20 to Q23, round 0.55.7's questions (`specs/2026-11-22-r0557-design.md`, where each is written out at length), each
  decided on its recommended option, the one the spec and plan build: chief's decisions, 2026-11-22. A known limitation's
  approved field says "chief's decision, 2026-11-22"; the plan's Task 18 says what a reversal by the user changes.
  - Q20, a top folder with more than about 2.9 KiB of its own extended attributes on an ext4 or f2fs vault keeps them out of
    its record (a whole-job restore gives it none): (a), a known limitation; such top folders are rare (ACLs and security
    labels take tens of bytes). Reversed by "store them raw".
  - Q21, the wait after a restart for a disk taken out of its pool: (a), the record kept in the state folder too, and
    "Kernels before 6.8 and the pool check" widened. (b) would leave a wrong result in a backup; (a)'s block is loud and a
    remount undoes it, so the README line and the log line say how to let a disk go on purpose. Reversed by "a restart lets
    the disk go".
  - Q22, an entry whose path grows past the 4,095-byte limit: (a), left out before it grows, with its NOT BACKED UP line,
    under the user's pick "Accept: leave it out, warn (Recommended)" (2026-11-09). Reversed by "keep it through folder
    handles".
  - Q23, a disk that joins a pool and leaves it within one batch of a restore's copies: (a), a known limitation (it needs an
    operator to add and remove a disk within one batch of a restore they run). Reversed by "check every restored entry".
- Q15, a folder whose own metadata copy failed (P16, step 2; the healing check's 40 results, Task 2, asked in 5bad9b5):
  setgid is mended at the next full comparison, but a default ACL the folder inherited and its own extended attributes
  usually stay wrong until the folder's own metadata changes. (a), build plan Task 18: the failed folder's row is
  marked, so the next comparison that meets it copies its metadata again, once. The user's answer 2026-11-17 (dialog of
  13:40 to 13:53 PST, through chief), "Build the retry (Recommended)", shown their 2026-11-03 ruling "Not an issue,
  check healing (Recommended)" and that the retry goes beyond it on the check's evidence.
- Q17, f2fs's background GC on the vault disks (P7, readings B and D: after each large batch the busiest vault disk kept
  writing about five hours, the GC rewriting sections still about 94% valid, 4.5 of its 13.1 GiB a day): (a), turn it
  off on the four vault disks only, by fstab and a remount; the other pool members keep it. The user's answer
  2026-11-17 (about 00:05 PST, through chief), "Off on vault disks (Recommended)". P7 says how it is carried out (with
  `nogc_merge`, which kernel v7.0 needs for it to take) and what its next reading should show.
- Q16, the busiest job makes one version a day (P7, reading A: its minimum interval is a quiet time and its tree is
  never quiet for an hour now, so each batch comes at the one-day maximum): (a), keep the rule, one version a day and
  five days of history at Keep 5, no change to the live rule file. The user's pick 2026-11-15 (about 19:12 PST, through
  chief), "Keep the rule (Recommended)".
- Q10, D3 on a pool: (a), widen "A manifest lost in the same cut as a split on a pool" (now "A manifest lost after a cut, on a
  pool") to the cut copy kept over a lost manifest on a pool. Chief's decision, 2026-11-15, on the user's words "Support pools with a limitation" (2026-11-04);
  no vault is on a pool. The entry's approved field says "chief's decision, 2026-11-15".
- Q11, what the length rule leaves out: (a), widen "A symlink the vault's filesystem can't hold is left out" (now "A symlink or a path the vault
  can't hold is left out") to every entry kind, and keep the temporary name. Chief's decision, 2026-11-15, on the user's pick "Accept: leave it out, warn
  (Recommended)" (2026-11-09) for the same case in a symlink; no option keeps such entries, and (b) bought about 34 bytes
  of path for a second name form read for good. The entry says it drops the shorter name that "Fixes round
  (Recommended)" (2026-11-14) had planned; its approved field says "chief's decision, 2026-11-15".
- Q12, an xattr change made while down in a folder renamed during the start's walk: (a), a known limitation. Chief's
  decision, 2026-11-15, on the user's words on a rare case, "if unable to do this cleanly I think it also make sense to
  put as limitations" (2026-10-26): both fixes add a walk, or a part with its own state, for a three-way coincidence. The
  entry's approved field says "chief's decision, 2026-11-15".
- Q9, a file whose read fails only before its last 64 KiB (D1's rest): (a), a known limitation; the round still fixes
  the tail half. The user's pick 2026-11-15 (about 01:37 PST, through chief), "Known limitation (Recommended)", shown
  that it leaves a wrong result the rules call always worth fixing and that "Fixes round (Recommended)" (2026-11-14)
  had put the fix in the round. Revisit when one file's UNREADABLE alert repeats at full comparisons and `history`
  shows a new version each time.
- Q13, a name CIFS or sshfs lists but cannot look up, in a batch's scopes (D13's scope half): (a), a known limitation,
  with the watcher's half and the whole-tree walk built. The user's pick 2026-11-15 (through chief), "Known limitation
  (Recommended)", shown that "Fixes round (Recommended)" had it in the round. Revisit when a job monitors a CIFS or
  sshfs mount.
- Q14, two restores at once into one NFS folder (P17's one case left): (a), a known limitation with one README line.
  The user's pick 2026-11-15 (through chief), "Known limitation (Recommended)". Revisit when restores into an NFS
  folder are run side by side.
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
