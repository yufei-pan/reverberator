# Known limitations and deferred work

Each entry here has the user's OK. Reviewers read this file first and don't raise these entries again.

### The conversion from 0.54 judges links by their text

- **Kind:** known limitation.
- **What the operator sees:** until a job's one-time conversion ends, and during it, a symlink of the user's whose
  text has the shape of a 0.54 chain link (for example `a/U -> ../../V<n-1>--<timestamp>/a/U`) is taken for the
  vault's own link. It reads, restores and converts as the file it names, not as a link. A vault whose manifest was
  lost with a hot journal is read the same way and logs a Note; that case is by reading the code, not tested. Once a
  job is converted, its versions are plain trees and no link is judged by its text.
- **Why:** a 0.54 vault holds nothing that tells such a link from the daemon's own. Telling it would need a new
  per-version record for a format that is going away.
- **Revisit when:** the 0.54 reader goes, a release after 0.55; this entry goes with it.
- **Approved:** 2026-10-22, "Leave it (Recommended)"; 2026-11-04, "Accept for the conversion"; 2026-11-06, "Accept
  (Recommended)" for reading a vault before its conversion.

### World-readable vault database and change lists

- **Kind:** known limitation.
- **What the operator sees:** any local user can read `.reverberator_manifest.sqlite` and the `V<n>--…modified_contents.nsv`
  change lists in a job vault. Together they list every backed-up file name and its size, the names in a job that holds secrets included.
- **Why:** making them root-only (0600) would leave only root able to run status, history and restore. The user chose to
  keep them readable.
- **Revisit when:** a vault is shared with users who must not see other jobs' file names.
- **Approved:** 2026-10-23, the user's choice "Known limitation".

### Size records rounded to 2 decimals

- **Kind:** known limitation, already in 0.43.
- **What the operator sees:** each version's size is stored rounded to 2 decimals in its change list's name (for example
  `11.54_MiB`). After a restart, the vault's total can be off by up to 0.5% per version, so a prune can remove the oldest
  version slightly early.
- **Why:** it is small, it errs toward removing early and never toward growing past the limit, and exact sizes would
  change the change-list name format.
- **Revisit when:** a vault's size limit needs to be met exactly.
- **Approved:** 2026-10-23, the user's choice "Known limitation (Recommended)".

### Versions more than 40 back cannot be browsed by hand

- **Kind:** known limitation.
- **What the operator sees:** a path k versions older than the newest passes through up to k forward links, and every
  symlink in the vault's own path counts as well. Past the kernel's 40 (about 20 while Docker changes mounts),
  browsing by hand gives "too many levels of symbolic links". restore and history work. The live maximum keep-N is 14.
- **Why:** re-pointing links would cost writes on every cycle.
- **Revisit when:** a job keeps more than 20 versions and is browsed by hand.
- **Approved:** 2026-11-04, "Known limitation".

### A SnapRAID fix while reverberator runs

- **Kind:** known limitation.
- **What the operator sees:** a replaced disk is mounted, so jobs resume while `snapraid fix` restores its files.
- **Why:** nothing tells a disk being rebuilt from one that is whole.
- **Revisit when:** it bites.
- **Approved:** 2026-10-23, the user's choice "Known limitation, README says stop it (Recommended)".

### Kernels before 6.8 and the pool check

- **Kind:** known limitation.
- **What the operator sees:** on a kernel before 6.8, a disk of a pool swapped very quickly for another may not pause its
  jobs. This host runs 7.0.
- **Why:** statx gives no unique mount id before 6.8, so the check falls back to mountinfo ids, which the kernel reuses.
- **Revisit when:** reverberator runs on an older kernel.
- **Approved:** 2026-10-26, the user's choice "Known limitation (Recommended)".

### Kernels without f2fs's checkpoint status

- **Kind:** known limitation.
- **What the operator sees:** on a kernel whose f2fs has no `stat/cp_status` in sysfs (before about 6.1), a failed f2fs
  disk (a vault on one SSD, or a pool's disk) is warned of once and taken for whole, so its jobs do not pause; they fail
  on their writes and retry instead. A removed device or a missing f2fs sysfs folder still pauses them. This host runs
  7.0, which has the file.
- **Why:** that file is the only place f2fs reports a checkpoint error; without it a failed f2fs reads like a healthy
  one, and taking a disk that cannot be told for failed would stop its jobs for good.
- **Revisit when:** reverberator runs on such a kernel.
- **Approved:** 2026-11-04, the user's choice "Both (Recommended)".

### A disk that is dying but not yet failed

- **Kind:** known limitation.
- **What the operator sees:** jobs keep writing to a dying disk until its filesystem shuts down (XFS) or flags a
  checkpoint error (f2fs); only then do they pause, as for a missing disk.
- **Why:** catching it earlier needs SMART or I/O-error watching, which is a separate tool.
- **Revisit when:** a disk fails without its filesystem noticing.
- **Approved:** 2026-10-26, the user's choice "Known limitation (Recommended)".

### Two pools out at once are reported one after the other

- **Kind:** known limitation.
- **What the operator sees:** when a vault disk and a monitored disk are both missing, an idle or batching job's waiting
  marker names one pool; once that pool is back, a second marker names the other. Nothing is lost.
- **Why:** each wait is for one path, and a combined wait would add a part for a rare case.
- **Revisit when:** the two-step report confuses.
- **Approved:** 2026-10-26, the user's choice "Known limitation (Recommended)".

### Files written through mmap

- **Kind:** known limitation.
- **What the operator sees:** a write through mmap raises no inotify event, so 0.47 relies on the mtime it moves: an
  attribute-only change whose mtime moved copies the file, and a full comparison (a restart, or the job's Full
  Comparison Interval when set) copies a file whose mtime moved. Every comparison also hashes a file's last 64 KiB, so
  what is left concerns stores before that tail (none, for a file of 64 KiB or less): (1) a second store into a page
  still dirty from an earlier one moves no mtime, so a copy taken between them misses the later store until the mtime
  next moves; (2) an mmap write followed by setting the mtime back is not seen; (3) a copy that a 0.46 or older daemon
  synced after an mmap write (old bytes under the new mtime) stays wrong until the file is written again. And (4) a file
  written only through mmap (a chat app's MMKV files) is backed up only at its next normal write, a restart, or the job's
  Full Comparison Interval if one is set.
- **Why:** no inotify or fanotify flag reports mmap stores (round 10's research: scratchpad r10/mmap/report.md); the
  kernel moves the mtime only on the first store into a clean page.
- **Revisit when:** a kernel interface reports mmap stores, or a job's files are seen stale this way.
- **Approved:** 2026-10-26, "let's defer. let's see if we can catch something, or if we can know if a file is mmaped";
  2026-10-27: "should we trust mtime change as indication of file is changed to just do the copy? this way we only do
  one read and one write not three reads and one write in most cases", then "Keep it, round 11 (Recommended)", and for
  the scheduled comparison "Configurable per job and default off"; 2026-10-28, on what is left after 0.47: "Known
  limitation, as listed (Recommended)". The entry "A file moved and then touched in one batch is copied again" was
  removed the same day ("Remove it (Recommended)"): every touch that moves the mtime now copies the file.

### Swaps in one batch are repaired by copies

- **Kind:** known limitation.
- **What the operator sees:** a swap collapsed in one batch (`mv a t; mv b a; mv t b`) copies both files again instead of
  renaming them, and two folders whole: the replay renames each onto the other's old place, the comparison after the
  batch finds both different and copies them, and nothing is logged at warning or error level. A file swapped with a
  folder keeps one renamed and copies the other, logging `Not renaming … to …: … is a folder in the version, as an earlier
  move of the batch left it; doing delete & copy instead` (or `is not a folder`) at ERROR level, with no traceback
  (firewatcher does not alert on it). The result is right.
- **Why:** renaming them in one step would need a change-list format change.
- **Revisit when:** the change list's format changes for another reason.
- **Approved:** 2026-10-26, the user's choice "Known limitation (Recommended)"; corrected 2026-10-29, "Correct the entry
  (Recommended)".

### A move that another change of the batch outran is copied

- **Kind:** known limitation.
- **What the operator sees:** a move whose source, or the folder it goes into, is not in its place in the version when
  the move replays, because another change of the same batch (a move, a delete, or a folder made after it) replays in
  another order, logs one warning, `Not renaming … to …: its source or the folder it goes into is not in the version;
  copying it instead`, with no traceback (firewatcher does not alert on it), and the entry is copied once more: its files
  are written to the vault again in full, a copy instead of a rename. Some of these shapes also log a warning `Not tracking
  <path>: source no longer exists` for a copy the batch left behind. Examples: `mv d e; mkdir e/sub; mv x e/sub/x` (x
  copied), `mv a/f g; mv a A; mv g h` (h copied), `mkdir x; mv old x/f; mv x y` (y/f copied), `mv D/sub t; rm -r D; mv t
  D` (D's files copied), `mv d D; mv D/k z; rm -r D` (z copied), and, with a new file f, `echo new > f; mv f d/g; mv d D;
  mv D/g h; mkdir d; mv q d/g` (q copied). The result is right.
- **Why:** replaying such moves so the version follows them is a larger change to the batch's collapse and replay, for
  one extra copy in a rare order.
- **Revisit when:** the warning shows up often in the live logs.
- **Approved:** 2026-10-26, the user's choice "Known limitation (Recommended)"; widened 2026-10-29, "Widen the known
  limitation (Recommended)", then for the older collapse shapes "Widen the known limitation (Recommended)".

### One folder renamed back and forth thousands of times in one batch

- **Kind:** known limitation.
- **What the operator sees:** the batch's collapse slows: 12,500 round trips of one folder take 49 s, as every event
  inside it is carried through each rename. The watcher slows too, as each of those moves also walks the folder again:
  for a folder of 5,000 subfolders (37 ms a walk) they add about 460 s of watcher time. Normal use, even 50k moves of
  different paths, stays under a second.
- **Why:** a memo that fixes it does not fit in a small, clean change.
- **Revisit when:** a real workload does this.
- **Approved:** 2026-10-26, the user's choice "Known limitation (Recommended)".

### Size estimates leave out a version's own small blocks

- **Kind:** known limitation.
- **What the operator sees:** with a size limit, the estimate made before a backup leaves out the real folders the
  batch makes in the previous version, about 4 KiB for each folder it touches and each folder above them (a chmod of
  3,030 folders passed a limit by 11.64 MiB on the real daemon) and the version's xattr blocks (a few KB), so a vault can
  go over its limit by that much until the next prune. The links a batch makes are in no size record, so neither `status` nor the limit sees their bytes:
  about 4 KiB each on f2fs, so one file changed in a folder of 5,000 entries took 20.6 MB of disk while the records
  rose 4 KiB, until that version is pruned. With an
  inode limit, the estimate leaves out the links the hand-over and unfolds make, so a batch can pass the limit by that
  many until the next prune: a folder of 100K entries that changes makes 100K links in that version. The sizes
  recorded after each backup are counted, each file by its size plus 4 KiB per folder, and each inode in the newest
  version that holds it, so later prunes are right.
- **Why:** counting folders means working out before each batch which folders and parents become real, on every job,
  for an overshoot that lasts until the next prune. A link's bytes differ by filesystem, so counting them needs a
  figure for each one.
- **Revisit when:** a job sits at its limit and its batches touch thousands of folders, or a vault's disk fills ahead of
  its limit.
- **Approved:** 2026-10-26, "Known limitation (Recommended)"; 2026-11-05, "Extend the entry (Recommended)"; 2026-11-06,
  "Change the text (Recommended)", for the measured overshoot of the folders; 2026-11-06, "Correct the text
  (Recommended)", for the links' bytes.

### A vault down to its only version can pass its size limit

- **Kind:** known limitation, already before 0.47.
- **What the operator sees:** a vault that pruning has brought down to its only version (a new vault, or a size limit
  near the tree's own size) can pass its Backup Size Limit by the size of the next change, as its only version is never
  removed: the backup adds a second version, and the next backup's prune removes the older one.
- **Why:** removing the only version would leave no backup.
- **Revisit when:** a job's size limit is close to its tree's size.
- **Approved:** 2026-10-28, the user's choice "Known limitation (Recommended)".

### Changes made outside the watched folder

- **Kind:** known limitation.
- **What the operator sees:** an xattr-only change made outside the watched folder (straight onto a disk of a mergerfs
  pool, such as /mnt/pool_disks/<disk>/..., or a remote write on a network filesystem) raises no event, and once a
  later batch moves the vault's matched time past it, no full comparison reads it: that xattr is missing from the
  versions until the file changes again. Content changes are still caught, by size and mtime.
- **Why:** round 10's matched time bounds a full comparison's xattr reads to what changed since the vault last matched
  the whole tree, and that bound assumes every change goes through the watched folder.
- **Revisit when:** a job monitors a network filesystem, or files are changed on a pool's disks directly.
- **Approved:** 2026-10-27, the user's choice "Known limitation (Recommended)".

### A copy made where the vault refused a hard link

- **Kind:** known limitation.
- **What the operator sees:** on a vault whose filesystem refuses a hard link, a record is a copy, and that copy holds
  the only copy of an older version's file (a cut batch's record, or a 0.54 conversion's tree). That file can then read
  wrong in two ways: it can hold lost bytes with no alert, when another program's sync of the disk saw the copy's write
  error before the next attempt opened its handles; or it can be lost after a VAULT WRITE ERROR on that disk, when the
  batch's own flush of the record copy fails and the retry does not make the record again and replaces the tree's file.
- **Why:** no other copy of those bytes exists.
- **Revisit when:** a vault ever shows refused hard links.
- **Approved:** 2026-11-09, the user's choice "Known limitation (Recommended)", then "Widen the entry (Recommended)"
  for the second way.

### A copy whose start was lost after a power loss

- **Kind:** known limitation.
- **What the operator sees:** a cut after a checkpoint of the disk (another job's commit, the kernel's periodic one, a
  sync) and before the batch's flush ends can leave a copy all NUL in the tree. The next attempt copies again every file
  the cut batch wrote, except one under an inner mount that is paused at that attempt (not mounted yet after the reboot,
  say): that one stays marked unchecked, and the next full comparison with the mount back reads it by size, mtime and
  last 64 KiB. So a copy whose row did not change (an attribute change with Only Sync Attributes off) and that ends in
  64 KiB of NUL passes and stays all NUL in the newest version. Older versions keep the right copy.
- **Why:** the read-back hashes the tail only, and a paused mount's file cannot be copied again at the retry.
- **Revisit when:** such a loss is seen, or a job with an inner mount turns Only Sync Attributes off and holds files that
  end in zeros. The fix at source: the roll-forward links the previous version's record back over a recorded file it
  cannot copy again, so a paused mount's file keeps its last committed contents.
- **Approved:** 2026-10-27, "Known limitation (Recommended)"; 2026-11-06, the text, "Approve the text (Recommended)".
  0.55.3 narrows it to a file under an inner mount paused at the next attempt.

### A write error in the middle of a copy after the reboot

- **Kind:** known limitation.
- **What the operator sees:** a copy a cut batch placed under an inner mount that is paused at the next attempt cannot
  be copied again then; it stays marked unchecked, and after a reboot the full comparison with the mount back reads it
  by its size, mtime and last 64 KiB. A page lost in the middle of the file to a write error passes, and the copy stays
  wrong until the file changes again.
- **Why:** reading every unchecked copy whole costs a full read of each; a paused mount's file cannot be copied again at
  the retry.
- **Revisit when:** a vault disk keeps working after write errors, so this is met; the fix at source is the same as for
  the entry above.
- **Approved:** 2026-10-27, the user's choice "Known limitation (Recommended)". 0.55.3 narrows it to
  a file under an inner mount paused at the next attempt.

### A clock set back after a read was stamped

- **Kind:** known limitation.
- **What the operator sees:** if the wall clock is set back by more than 10 s after the watcher stamped a read (a fast
  hardware clock corrected after start), xattr-only changes made while nothing watched (the daemon down, an overflow, a
  failed attempt) are not compared until the next batch moves the matched time on. The installed unit waits up to
  ~5 min for chrony to sync before starting (ExecStartPre=-/usr/bin/chronyc waitsync 30 0.1), which closes the usual
  boot case; the repo's unit template documents the same.
- **Why:** the matched time is a wall clock time, compared with ctimes; a boot-clock guard would add a part for a narrow
  case.
- **Revisit when:** the clock is seen stepping back after start.
- **Approved:** 2026-10-27, the user's choices "Known limitation + unit fix (Recommended)" and "Wait in reverberator's unit
  only (Recommended)".

### A paused inner mount or an unwatched folder holds the matched time

- **Kind:** known limitation.
- **What the operator sees:** while an inner mount stays paused, or a folder stays unwatched (unreadable, or a failed
  watch), every batch keeps the vault's matched time where it was, so full comparisons read the xattrs of everything
  changed since then (slow, as before round 10) until the mount is back or the folder is watched again. Nothing is lost.
- **Why:** the matched time claims the whole tree; a time per subtree would add parts for a cost-only case.
- **Revisit when:** a mount stays away for long.
- **Approved:** 2026-10-27, the user's choice "Known limitation (Recommended)".

### An xattr change lost while an inner mount was paused

- **Kind:** known limitation, already in 0.45.
- **What the operator sees:** an xattr-only change on an inner mount whose event was lost while the mount was paused (the
  disk away, then back) falls outside the mount-back scan's bound and the next matched time, so it is missing from the
  versions until the file changes again. No live job has an inner mount.
- **Why:** the mount-back scan compares xattrs by the version-based bound, which does not reach back to the pause.
- **Revisit when:** a job gets an inner mount.
- **Approved:** 2026-10-27, the user's choice "Known limitation (Recommended)".

### A move landing in the same instant a batch is taken

- **Kind:** known limitation.
- **What the operator sees:** when a batch is taken within one inotify read of a move into a new folder or out of the tree
  (mkdir d; mv f d/f), that batch's version, rarely the next one too, still shows f at its old place; later versions are
  right. A batch holding a change inside a folder that is renamed before the watcher handles the rename gives a version
  without the changed file, or without the whole folder when the change was to the folder itself; reproduced with the
  batch taken in that gap, and by reading a rename at any point while the batch runs does the same. The next version is
  right, and nothing is lost for good.
- **Why:** a move's two events can straddle one read, so a move-out is carried into a batch only once a whole read has
  passed; carrying it sooner would break a rename split by the take into a delete and a copy. A batch's comparison reads
  the live tree, so a path renamed away looks deleted; holding such a path back until a later read confirms it would
  change how every version is checked.
- **Revisit when:** it is seen on the live jobs, or a version missing a folder matters in practice.
- **Approved:** 2026-10-27, the user's choice "Known limitation (Recommended)"; widened 2026-11-05, the user's choice
  "Known limitation (Recommended)".

### A disk that hangs while a renamed folder gets its watches

- **Kind:** known limitation.
- **What the operator sees:** a batch waits while the watcher adds the watches of a folder renamed inside the tree. If the
  disk hangs at that moment, the backuper hangs with it: status shows no wait, and after a forced kill no pending
  transactions are left, so the next start compares the whole tree. No wrong result and nothing lost.
- **Why:** the wait is what keeps a rename and its folder's changes in one batch, and a stop already hangs in this state;
  showing it would add parts for a state that already stalls the daemon.
- **Revisit when:** a hung disk during a rename is seen on the live jobs.
- **Approved:** 2026-11-05, the user's choice "Known limitation (Recommended)".

### A failed batch of scans handed back as a whole-tree comparison

- **Kind:** known limitation.
- **What the operator sees:** a batch made only of folder scans that fails while a move-out is still waiting for its pair
  is handed back as a whole-tree comparison instead of its scans: one extra full walk, no wrong result.
- **Why:** telling such a batch apart in the hand-back would add a part for a rare, cost-only case.
- **Revisit when:** it is seen.
- **Approved:** 2026-10-27, the user's choice "Known limitation (Recommended)".

### A rewrite made while down that keeps size and mtime

- **Kind:** known limitation, already in 0.45.
- **What the operator sees:** a file rewritten in place while the daemon is down, at the same size and with its mtime set
  back, changed only before its last 64 KiB, is missed at the restart and kept wrong until it changes again. So is such
  a rewrite made while the daemon ran, when a stop with the vault not there dropped its event: the start's full
  comparison has the same blind spot.
- **Why:** a full comparison checks size, mtime and the tail hash; utime cannot set ctime back, but ctime is not checked.
  Reading the whole file when its ctime is after the matched time would catch it, but making that check affordable
  needed three more parts, for a rare case.
- **Revisit when:** such rewrites are seen in practice.
- **Approved:** 2026-10-27, the user's choice "Defer to round 11 (Recommended)"; then 2026-10-27, on that whole-file
  check: "why do we bother?", then "Drop it, known limitation (Recommended)"; 2026-10-28, on widening it to a rewrite
  made while running whose event a stop dropped: "Widen it (Recommended)".

### A rewritten rule row keeps the defaults it was given

- **Kind:** known limitation, already before 0.47.
- **What the operator sees:** when reverberator fills a rule row's auto cells, it writes that row's resolved columns 1-12
  back: a blank cell takes its #_defaults_# row value and an auto cell reverberator's own default (a cleaned-up Job Name
  or monitored path rewrites the row too), so a later edit of the defaults row no longer reaches that job: edit the job's own row, or clear its cells, to follow
  a changed default. Columns 13 to 15 are never written.
- **Why:** filling in defaults and auto fields is how the rule file records what each job runs with.
- **Revisit when:** a host relies on editing the defaults row for jobs already started.
- **Approved:** 2026-10-28, the user's choice "Known limitation (Recommended)".

### A file edited during a full comparison is copied twice

- **Kind:** known limitation, already before 0.47.
- **What the operator sees:** an edit made while a full comparison runs lands in the comparison's version, and the next
  batch (from the edit's event) copies the file again into one more version: an extra copy and version, no wrong
  result. Jobs with a Full Comparison Interval meet it a little more often.
- **Why:** the fix sits in the replay's core path, a risk not worth an extra version.
- **Revisit when:** it costs noticeable space.
- **Approved:** 2026-10-28, the user's choice "Known limitation (Recommended)".

### A resumed batch of only untracked deletes walks the tree twice

- **Kind:** known limitation.
- **What the operator sees:** after a restart that resumes a pending file holding only a carried move-out's late
  delete, the delete is dropped and the whole tree is compared twice (the empty batch's comparison, then the resumed
  batch's follow-up), with no version; 0.46 made an empty version there instead.
- **Why:** one extra full walk at a rare restart, and no wrong result.
- **Revisit when:** such restarts are frequent.
- **Approved:** 2026-10-28, the user's choice "Known limitation (Recommended)".

### An older pending file replayed after a stop dropped changes

- **Kind:** known limitation.
- **What the operator sees:** a stop while the job's vault path is not a folder, or its disk is not there, writes no
  pending file: the queued changes are dropped with one warning line, as the next start compares the whole tree. A
  pending file already in the job vault, saved by an earlier stop while the vault was there and not loaded since because
  no start got past the vault wait, stays. A later start replays it only when its resume check passes: the newest mtime
  in the monitored tree is at least 1 s older than the file, so a dropped content change, create or delete (each moves
  an mtime, unless a tool such as rsync -a or tar x sets the mtimes back) fails the check and the tree is compared in
  full. What can be missed is an attribute-only change (chmod, chown, an xattr) or one whose mtimes were kept or set
  back, and only in the replayed batch's version: the whole-tree comparison that follows every replayed batch, in the
  same start and from a matched time the replay did not move, puts them in the next version, as any full comparison
  would; a same-size rewrite that kept its mtime and changed only before its last 64 KiB is missed by it too (see "A
  rewrite made while down that keeps size and mtime").
- **Why:** the stop cannot remove the old file from a vault that is not there, and the start that finds it cannot tell it
  from a current one; the case needs a stop with changes queued while the vault was there, a start that never got past
  the vault wait, and a second stop with changes queued.
- **Revisit when:** missed changes are seen after such stops.
- **Approved:** 2026-10-28, the user's choice "Known limitation (Recommended)"; 2026-10-28, on the smaller impact: "Keep
  it, reworded (Recommended)".

### A vouched chmod keeps a checked copy checked

- **Kind:** known limitation.
- **What the operator sees:** under Only Sync Attributes, after a chmod or chown whose record vouches for the vault copy,
  the copy stays recorded checked, and no comparison syncs or reads it back. If a power loss or a metadata write error
  loses the copy's new mode or owner in the seconds after the commit, the vault keeps the old mode or owner while its
  record says the new one, until the file next changes, and restores give the old mode or owner. The data is
  unaffected; folders and symlinks already worked this way.
- **Why:** marking such copies unchecked would make the next full comparison read each one back, the vault reads this round
  removed for a chmod or chown over a large tree, for a loss confined to a few seconds after a commit.
- **Revisit when:** a restore is seen giving an old mode or owner after a power loss or a write error.
- **Approved:** 2026-10-28, the user's choice "Keep checked, known limitation (Recommended)".

### Vault disks mounted outside fstab

- **Kind:** known limitation.
- **What the operator sees:** the disk check reads /etc/fstab and mergerfs pools, and the stop checks the disk, not the
  vault's signature. So a vault on a disk mounted outside fstab (by hand, by a systemd .mount unit, by autofs) that is
  unmounted when reverberator stops gets the job's pending file on the bare mount point, and one that is unmounted when
  it starts gets its Vault Path made there. Both are hidden once the disk mounts, and nothing is lost: the next start
  compares the whole tree. But a start that made the folder there then waits with "vault filesystem not ready" until a
  restart, when the disk mounts without that folder. With an N/A or auto Vault File System Signature and such a disk
  unmounted at start, the job backs up into the bare folder on the disk below until the disk mounts: those versions are
  hidden then and use that disk's space, and an auto signature filled from such a folder is the disk below's. This is
  the same as in 0.47; once the disk mounts, such a job waits on the wrong signature, with repeated FAILED alerts, until
  the cell is set back to auto.
- **Why:** such mounts are not known to reverberator without reading systemd units or autofs maps, and checking the
  signature at a stop runs df and lsblk, which can block on a hung disk.
- **Revisit when:** a host keeps a vault on such a disk.
- **Approved:** 2026-10-28, the user's choice "Known limitation (Recommended)"; then "Fold into that entry
  (Recommended)" for the start; 2026-10-29, on the signature case: "Widen it (Recommended)".

### A disk mounted by hand under an unmounted fstab mount point waits

- **Kind:** known limitation.
- **What the operator sees:** while an fstab mount point is not mounted, a disk mounted some other way below it (by hand,
  by a systemd .mount unit, by autofs) does not count as there. A vault or monitored path on it waits with the FAILED: waiting
  marker naming the fstab point. Put the disk in /etc/fstab, or mount the fstab point first.
- **Why:** a bind mount of a root-disk folder or a tmpfs mounted there must not count (a vault could land on the root
  disk or in RAM), and telling them apart from a disk needs rules on a mount's type, source and root: extra parts for a
  layout this host does not use.
- **Revisit when:** a host mounts a vault or monitored disk that way.
- **Approved:** 2026-10-29, the user's choice "Revert it, known limitation (Recommended)".

### A move into its own old place is copied whole

- **Kind:** known limitation.
- **What the operator sees:** an entry moved into a new folder made at its own old place in one batch (`mv D x; mkdir D;
  mv x D/D`, or `mv site site.old; mv site.new site; mv site.old site/old`) logs one warning, `Not renaming … to …: its new
  place is inside its old one in the version; copying it instead`, and is copied: the next version holds full copies of
  its files in full, so a big folder costs its full size in the vault once. In the swap shape the
  folder that took its old place (site.new) is copied whole too, as the copy replaces all of the version's `site`: both
  folders cost their size once, unless the replacing one was made in that batch (then it is copied anyway). The result is
  right.
- **Why:** the version can never rename an entry into itself; keeping the links needs a replay that parks the entry under
  a temporary name and places it after the entries that make its new folder, a larger change for a shape never seen in
  the live logs.
- **Revisit when:** the warning shows up in the live logs.
- **Approved:** 2026-10-29, the user's choice "Known limitation (Recommended)" (with "One warning, copy (Recommended)"
  for the warning); the swap shape's cost: "Correct the wording (Recommended)".

### A live database's files are copied one at a time

- **Kind:** known limitation.
- **What the operator sees:** a database an application keeps writing (a SQLite file with its `-wal` and `-shm`, a
  PostgreSQL or MySQL data folder) is copied file by file, each when its turn comes, while the application goes on
  writing. A version can then hold the database and its write-ahead log from different moments, or a file copied
  in the middle of a write. Restored, such a copy may lack the newest changes or not open at all. On 2026-11-02
  two hourly versions of snowluma's `messages.db` (93 MiB) were checked: in each of them the database and its
  `-wal` were copied up to 20 minutes apart, and both opened and passed SQLite's integrity check, so the risk is
  real but small in practice.
- **Why:** a consistent copy of files that change together needs one instant for all of them: a filesystem snapshot
  (the sources here are ext4 and mergerfs, which have none) or the database's own copy. A copy made through the
  database (SQLite's backup function) is not byte for byte the source, so the comparison after each batch would
  see a difference and copy it again every time, and it would cover one database kind only. Every file-level
  backup (restic, rsync, borg) has the same limit; the usual answer is to back up a dump.
- **Revisit when:** a monitored folder lives on a filesystem with snapshots, or someone needs a live database backed
  up that cannot be dumped.
- **Approved:** 2026-11-02, "Known limitation + README line (Recommended)", after the user asked "for general user's
  use case, should we accept as limitation? or should we plan / rig something up?". The same day the user chose
  "Skip messages.db" for docker_volumes (in /etc/reverb_skip_docker_volumes.txt, with its -wal and -shm; restic's own
  copies still hold it) and "Leave restic as it is (Recommended)".

### A folder whose extended attributes alone fail to copy keeps the wrong ones

- **Kind:** known limitation.
- **What the operator sees:** when copying a folder's metadata into a version fails, the copy is tried again at the end
  of the batch, and a folder that still fails has its record marked so the next comparison copies its owner and mode
  again. A failure that only ever hits its extended attributes (ACLs among them) is logged with a traceback each time,
  and the version keeps the folder's xattrs as they were, so a restore gives them back that way.
- **Why:** records hold no xattrs, so no comparison can see that they differ; recording them would cost every entry.
- **Revisit when:** such failures are seen in the log.
- **Approved:** 2026-11-04, the user's choice "All three (Recommended)".

### On a mergerfs pool, a folder cloned to another disk can lose setgid

- **Kind:** known limitation.
- **What the operator sees:** on a vault kept on a mergerfs pool, a folder that mergerfs clones onto another disk
  while a batch records into it or writes into it can lose its setgid bit on that disk (a mergerfs bug: upstream
  https://github.com/trapexit/mergerfs/issues/1689); a batch gives such folders back their times only, so the pool may
  show the folder without setgid, and a restore gives it back so.
- **Why:** copying the whole metadata of every folder a batch writes into would cost requests on every vault, for a
  bug of mergerfs that a vault on one disk never meets.
- **Revisit when:** a mergerfs release carries the fix (the issue was closed as completed on 2026-11-05), or a vault
  on a pool relies on setgid folders.
- **Approved:** 2026-11-04, "All three (Recommended)"; narrowed 2026-11-05, "Apply as drafted (Recommended)".

### After a crash, a folder whose row holds no record can keep the backup's time

- **Kind:** known limitation.
- **What the operator sees:** a crash in the one call between a change inside a folder of the previous version and
  giving that folder its times back leaves the backup's time on it. The roll-forward restores it from the folder's
  database row, except when that row holds no record (its vault entry could not be read when it was recorded, or the
  manifest was lost). A restore of that version then gives that one folder that time. Files and other folders are not
  affected.
- **Why:** keeping the time elsewhere would need a durable write per folder.
- **Revisit when:** it is seen.
- **Approved:** 2026-11-04, "Known limitation".

### Vaults on btrfs

- **Kind:** known limitation.
- **What the operator sees:** design R relies on the manifest's fsync also carrying earlier folder changes to the
  disk. Power-cut tests confirm that on f2fs, and ext4 and xfs should hold by reasoning. btrfs should not (reasoned,
  not run): on a btrfs vault, a power cut at the wrong moment could make the next start refuse the vault, or finish a
  commit with a part-applied tree.
- **Why:** a stronger flush before each commit, with its own tests on btrfs, for a filesystem no vault here uses.
- **Revisit when:** a vault goes on btrfs.
- **Approved:** 2026-11-05, "Known limitation (Recommended)".

### A copy lost before the upgrade restores as a broken link

- **Kind:** known limitation.
- **What the operator sees:** a file whose copy was already lost before the conversion to 0.55 restores from the older
  versions that held it as a broken link, with no FAILED line, where 0.54 printed FAILED. The conversion logs one
  error line for each, `<path> of <version> is a chain that leads nowhere (...): its copy was lost before the
  conversion, so it stays the link`. That line raises no alert: firewatcher's patterns do not match it.
- **Why:** keeping the FAILED would mean carrying the 0.54 rule on design R for ever.
- **Revisit when:** such files are found on a real vault.
- **Approved:** 2026-11-06, "Accept, log line only (Recommended)".

### The conversion runs on one thread

- **Kind:** known limitation.
- **What the operator sees:** at a job's first start on 0.55 its backups wait for a one-time conversion that does not
  fill the machine: 2 min 23 s for five versions of about 93,000 entries on a real SSD with nothing cached, where a loop
  image with its data cached took half a minute; 3.5 to 5 minutes for four versions of 183,000 files on a loop image on a
  busier machine; and under 3 s for small jobs.
- **Why:** it runs once, it is the riskiest step, and its code goes with the 0.54 reader a release later.
- **Revisit when:** a job with far more entries is converted.
- **Approved:** 2026-11-06, "Accept (Recommended)".

### history can name a place a file only passed through

- **Kind:** known limitation.
- **What the operator sees:** when one batch moves a folder and also moves a file in or out of it through a name that
  same batch overwrote or removed, `history` can name a place the file passed through, not where it was. A name
  created again between moves, and a target moved and removed in one batch, do the same. In a fuzz of hard batches
  about 108 of 102,855 names read wrong. Restores are right.
- **Why:** the change list keeps one row per chain and no true order, so a fix needs a change list format change.
- **Revisit when:** someone meets it on a real tree, or the format changes for another reason.
- **Approved:** 2026-11-06, "Accept (Recommended)".

### status can show one version fewer during a hand-over

- **Kind:** known limitation.
- **What the operator sees:** on a pool or a filesystem with no exchange, while a batch swaps in the new tree, `status`
  can show one version fewer. history and restore wait through it and read right.
- **Why:** a status that waits could hang behind a backup, and status is what is run when things look stuck.
- **Revisit when:** something reads that count to make a decision.
- **Approved:** 2026-11-06, "Accept (Recommended)".

### A kill can leave a version folder's own time moved

- **Kind:** known limitation.
- **What the operator sees:** on a pool or a filesystem with no exchange, the rename from staging can move the version
  folder's mtime, so the hand-over sets it back. A kill between the skeleton's rename and that call leaves the version
  folder's own mtime moved. No view of the version shows it, and its contents and restores are right.
- **Why:** mending it at the scan is more code for a value nothing reads.
- **Revisit when:** something reads that time.
- **Approved:** 2026-11-06, "Accept (Recommended)".

### A manifest lost in the same cut as a split on a pool

- **Kind:** known limitation.
- **What the operator sees:** on a pool, if the manifest is lost in the same power cut that left a folder record or a
  conversion's rename on one disk and not on another, the repair cannot tell a removed entry from a new one. An older
  version can lose an entry, or part of a version being converted can go with staging, with no error. Two faults at
  once. Reasoned by reading the code, not run.
- **Why:** a fix would need staged links that carry their path, a new format for a layout no vault here uses.
- **Revisit when:** a vault goes back on a pool.
- **Approved:** 2026-11-06, "Accept (Recommended)".

### A monitored tree on a pool: a clone's folder time comes with no event

- **Kind:** known limitation.
- **What the operator sees:** if a monitored tree sits on a mergerfs pool, mergerfs moves the mtime of folders above a
  new entry when it clones the path, and sends no event. A batch can miss that folder time until the next full
  comparison. Only a folder's time is affected.
- **Why:** mergerfs sends no event, so nothing can react sooner.
- **Revisit when:** mergerfs sends one.
- **Approved:** 2026-11-06, "Accept (Recommended)".

### A first version of folders alone on a pool gets no commit flush

- **Kind:** known limitation.
- **What the operator sees:** on a pool, a job's V0 that holds only folders and no files has no copies, so its commit
  does not flush; the job vault's own fsync on each branch follows it. A cut there could lose some of those empty
  folders from V0, and the next comparison would make them again. That outcome is by reading the code, not run.
- **Why:** there are no copies to protect.
- **Revisit when:** a vault goes back on a pool and a first version loses a folder.
- **Approved:** 2026-11-06, "Accept (Recommended)".

### A mergerfs with no forget command

- **Kind:** known limitation.
- **What the operator sees:** after a power cut, on a mergerfs that lacks `invalidate-all-nodes`, a folder in the last
  two versions can show a wrong mtime, and it stays wrong; an attempt may also fail once and go on at the next. With
  the command stubbed out on 2.42, 1 to 10 of 274 cut runs were wrong, and each wrong line looked at closely was a
  folder's time alone. No file data was wrong.
- **Why:** repairing it means reading each folder's time on every disk, for a version of mergerfs not in use here.
- **Revisit when:** someone runs such a mergerfs.
- **Approved:** 2026-11-06, "Accept (Recommended)".

### A FUSE vault with exchange and cached attributes

- **Kind:** known limitation.
- **What the operator sees:** on a vault on a FUSE filesystem that gives RENAME_EXCHANGE and keeps a name's attributes
  for a second, link counts can read stale, so version sizes can read low and Backup Size Limit undercounts, with no
  error. Reasoned, not run. Pools and filesystems with no exchange are covered.
- **Why:** covering it means reading fresh link counts on every batch of every job.
- **Revisit when:** a vault goes on such a filesystem.
- **Approved:** 2026-11-06, "Accept (Recommended)".

### f2fs can keep a symlink with no text

- **Kind:** deferred.
- **What the operator sees:** nothing, today: `is_skeleton()` passes over a link `readlink` cannot read. A checkpoint
  inside symlink(2) followed by a power cut keeps a link that lstat lists and readlink answers ENOENT for, and
  fsck.f2fs does not see it. A later checkpoint heals it.
- **Why:** the proper fix is in the kernel; a report is drafted for the f2fs list.
- **Revisit when:** a kernel carries the fix: then that tolerance in `is_skeleton()` can go.

### A symlink the vault's filesystem can't hold is left out

- **Kind:** known limitation.
- **What the operator sees:** a symlink in the monitored tree whose text or path is longer than the vault's filesystem
  takes is in no version: on an XFS vault, a link text of 1,024 bytes and up (ext4 and f2fs take up to 4,095). Each
  backup that meets it logs `reverberator job <name> NOT BACKED UP: <path>: a symlink whose text or path is longer than
  the vault's filesystem takes; left out of this version`, which alerts, and the rest of the batch is backed up. A
  version that held a link of that name before keeps it; the new version shows none. A restore that meets such a link
  (from a vault on another filesystem to a target on XFS) restores everything else, names the link
  (`FAILED <rel>: not restored: the target's filesystem cannot hold a link that long (its text or its path)`), finishes,
  and exits 1.
- **Why:** a version holds a link as itself, so a vault that cannot hold its text cannot keep it browsable. Before 0.55.2
  the failed copy stopped every backup of the job until the link was gone. Keeping it another way (its text in a file
  with a marker) would add code, and browsing would show a file where the link was.
- **Revisit when:** someone needs such links kept on an XFS vault.
- **Approved:** 2026-11-09, "Accept: leave it out, warn (Recommended)".

### A killed restore copies everything again

- **Kind:** known limitation.
- **What the operator sees:** a folder restore killed (SIGKILL), crashed or cut by a power loss before its sync copies
  everything again when it is run again, rather than keeping what it had copied, and `--accept` is refused (exit 2) until
  that run has finished and synced. A stopped one (Ctrl-C, SIGTERM, SIGHUP) first writes what it restored out to disk,
  saying so, and waits for the disk, which nothing cuts short; the same restore run again keeps that, unless it was itself
  copying everything again, or its write-out failed. A run again that keeps failing for a cause it may fix can never
  finish while the cause stays: the summary and `--accept`'s refusal say to fix the cause and run again, or to remove the
  target and restore it fresh (only for a target a restore made; otherwise to restore into a new folder instead). The
  README's restore paragraph says so.
- **Why:** no run can tell afterwards whether the copies reached the disk. A writeback error is reported to a sync through
  a newly opened handle only if no other sync of that disk met it first, and the daemon's own vault flush is one. Keeping
  the copies could end in a restore that says it is done over files that lost their bytes. The cost is time, never wrong
  data.
- **Revisit when:** big restores get killed often.
- **Approved:** 2026-11-09, "Recopy after a kill (Recommended)", with the Ctrl-C wait "Wait for the disk (Recommended)";
  2026-11-09, "Say the way out (Recommended)" for a rerun that keeps failing.

### mergerfs answers EBADF to a lstat during an rm

- **Kind:** deferred.
- **What the operator sees:** nothing, today: `TreeWriter.removing` keeps the writer's walks out of a folder whose
  removal is queued. lstat of that folder or of a path below it can answer EBADF while `rm -rf` runs through mergerfs
  2.42.
- **Why:** the proper fix is in mergerfs: upstream https://github.com/trapexit/mergerfs/issues/1693.
- **Revisit when:** a mergerfs release carries the fix: then check whether `removing` is still worth keeping.

### A folder or file moved into a new folder is copied whole

- **Kind:** known limitation.
- **What the operator sees:** `mkdir new; mv big new/` inside one quiet time copies what moved, with no line in the log,
  though the vault already holds it: 102.44 MB for a 100 MB folder on the real daemon, at every gap between the two
  commands, against 0.04 MB for a move into an existing folder; a 100 MB file costs 100.11 MB. With a size limit, the copy
  can prune older versions to make room: after five small versions, such a move left only the newest of them. 0.55 and
  0.54.2 do the same. A move into a folder made before the last backup was taken is a move and costs no copy.
- **Why:** the watcher drops the events in a folder made during the batch until the batch's copy of that folder runs, the
  move's arrival with them, so the move becomes a delete of its old place and the copy. 0.55.1 was built to keep the
  arrival as a move; four reviews and the fix passes after them each found an order of events where the version then
  kept a file's old bytes for good where 0.55 is right (the last needs the stale watch of a folder that left the tree, at
  the moved folder's old path), so 0.55.1 copies, as 0.55 does. A copy costs space and time; a wrong version loses a backup.
- **Revisit when:** the no-copy move gets its own design, after the two entries it went through are fixed ("A folder
  renamed twice into a folder whose move is being walked can keep old bytes" and "A folder moved out of the tree from a
  new folder keeps its watch"); sooner if size limits start pruning because of it.
- **Approved:** 2026-11-07, "Drop the feature (Recommended)": 0.55.1 ships with every move into a new folder copied, as
  on 0.55, and the no-copy move gets its own design later.

### A batch with nothing to do still makes two commits

- **Kind:** deferred.
- **What the operator sees:** nothing but cost: a batch whose events collapsed makes two sqlite commits and 10 fdatasyncs,
  in 321 syscalls. `delta_generate_backup_entries` commits even when it read nothing.
- **Why:** a lightness item, older than 0.55. It need not ride on the conversion.
- **Revisit when:** the lightness round after 0.55.1.

### Two folder fsyncs a single-disk job does not need

- **Kind:** deferred.
- **What the operator sees:** nothing but cost: the fsyncs after `swap_current_version` and in `place_change_list` are
  there for a pool's disks. Each is an f2fs checkpoint: 455 KiB and 5 checkpoints per one-file batch, 418 KiB and 3
  without them.
- **Why:** dropping them is safe by reasoning only, as `finish_r_commit()` finishes a lost swap and rename.
- **Revisit when:** the lightness round after 0.55.1, with a power-loss run first.

### A moved file is read back

- **Kind:** deferred.
- **What the operator sees:** nothing but cost: a plain `mv` loses the file's row, so the comparison reads it back
  (since 0.55.3 with no syncfs of its own). A rename of a folder of 2,000 files read 263.3 MB for a
  change that wrote 0.1 MB.
- **Why:** keeping rows, and their unchecked mark, through a move is safe by reasoning only.
- **Revisit when:** the lightness round after 0.55.1, with a power-loss run first.

### Seven mount table reads in a one-file batch

- **Kind:** deferred.
- **What the operator sees:** nothing but cost: about 3.5 ms of a batch's 13 ms of CPU on 162 mounts,
  measured with eight reads; 0.55.3 takes one off (a batch's unit reads no mount table).
- **Why:** a lightness item; the reads sit in separate steps that need one table passed between them.
- **Revisit when:** the lightness round after 0.55.1.

### One du process for a deleted folder's inodes

- **Kind:** deferred.
- **What the operator sees:** nothing but cost: a batch that deletes a folder runs `du --inodes` on the vault's copy of
  it, a process for what a walk gives. 0.55.2 took `du` out of the size estimate's bytes; this count is what is left.
- **Why:** a walk counts each name of a hard-linked file, where `du` counts the file once, so the inode count would
  change with it.
- **Revisit when:** the lightness round.

### A full comparison that meets only what it leaves out commits a version

- **Kind:** deferred.
- **What the operator sees:** a full comparison, such as the one at each start, whose only differences are entries it
  leaves out (an unreadable file, a symlink the vault's filesystem can't hold) commits a version that changes nothing.
  With Keep N Versions, each such version pushes the oldest one out: four comparisons made four versions in a probe.
- **Why:** older than 0.55.2 for unreadable files; the link left out joins it. A batch whose every entry drops out should
  commit nothing.
- **Revisit when:** the round after 0.55.2.

### The root's metadata is written every batch

- **Kind:** deferred.
- **What the operator sees:** nothing but cost: `record_root_meta` writes the xattr each batch, changed or not. A read
  and compare would leave that one unwritten on nearly every batch. The second lsetxattr of a batch, `hand_over`'s, gives
  the new folder its record and stays.
- **Why:** a lightness item.
- **Revisit when:** the lightness round after 0.55.1.

### A folder renamed twice into a folder whose move is being walked can keep old bytes

- **Kind:** deferred.
- **What the operator sees:** a change that keeps a file's size and mtime (`cp -p` of a same-size file), then its folder
  moved into a folder whose own move the watcher is still walking, and renamed again in it after the walk listed the first
  name (`mv other o2; mv big o2/x; mv o2/x o2/big`), can leave the version holding the file's old bytes for good, with no
  line in the log; a restart's comparison does not see it. Seen in forced orders of events only, 225 of 1,365 on 0.55 and
  0.55.1 alike, and never on the real daemon in 8 tries: the second rename has to land while the walk of a big folder has
  not yet passed the first name. A move into a new folder does not reach it: that is copied.
- **Why:** older than 0.55.1. The fix, a folder move whose watch a walk re-pointed before its move-out was read is copied
  wherever it lands, changes what is recorded for a folder that never had a watch, so it needs its own design and gates.
- **Revisit when:** the round right after 0.55.1, as the user decided on 2026-11-07.

### A folder moved out of the tree from a new folder keeps its watch

- **Kind:** deferred.
- **What the operator sees:** after `mkdir n; mkdir n/x; mv n/x /elsewhere/x` in one batch, the watch of `/elsewhere/x`
  stays mapped at `n/x` for as long as that folder exists, so changes there come as deletes, moves and writes under `n/x`
  that cost extra work, and the check after the batch mostly puts the version right. It does not when another folder now at
  `n/x` holds two files of one size, mtime and last 64 KiB (a `tar x` of two same-size files padded alike) and a rename in
  `/elsewhere/x` goes from one of their names to the other: the version renames its file onto the other name, the check
  finds nothing to tell them apart, and that version and every later one keep the wrong bytes for that file, with no line
  in the log; a restart's comparison does not see it either (forced in-process, 3 of 3 on 0.55 and 0.55.1 alike; right
  when the last bytes differ). In the same way, a folder moved
  out of the tree whose old parent is renamed before its move-out expires (`mv keep/s/n2 /out/x; mv keep c/keep2`) keeps
  its watch, re-pointed to `c/keep2/s/n2` where nothing lives, so a write in `/out/x` is recorded there and found gone.
  Both are older than 0.55.1.
- **Why:** the first folder's move-out comes on the watch of a new folder and is discarded, so no expiry removes its
  watches; the second's expiry removes only the watches still mapped under its old path, as removing every watch it took
  also removed a live folder's watch when 0.55.1 tried it. The fix belongs in the discard branch and the expiry, with a
  check of the watch map at the end of the watcher's schedule tests. The no-copy move into a new folder tried during
  0.55.1 kept wrong bytes through the first watch (a folder made at `n/x` and moved into a new folder looked like the
  folder that left), one reason it went.
- **Revisit when:** the round right after 0.55.1, with "A folder renamed twice into a folder whose move is being walked
  can keep old bytes", as both can keep wrong bytes; the event queue overflow's unwatched folder goes with them, and both
  before the no-copy move into a new folder.

### A size record too low after a rename falls back to a copy

- **Kind:** deferred.
- **What the operator sees:** when a whole-tree comparison lands between a rename and the watcher's read of it, the
  version before can keep a change list that says too little (16.00 KiB and 11 inodes where 22.93 KiB and 13 are right),
  so `status` and the limits undercount it by the moved folder until that version is pruned. Contents are right.
- **Why:** older than 0.55.1. The fix is in the fallback; the cause is read, not verified:
  `manifest.move_tree()` runs before the rename, so the rows of what the version already holds at the target are gone.
- **Revisit when:** the lightness round after 0.55.1. Then `tests/test_watcher_fuzz.py` stops leaving this fault out.

### An event queue overflow can leave a new folder unwatched

- **Kind:** deferred.
- **What the operator sees:** an overflow of the kernel's event queue that loses a new folder's create: the full scan
  copies the folder, but nothing walks it, so later writes in it raise no event until a restart.
- **Why:** it needs the queue to overflow, and the fix is a walk of the tree at an overflow, which belongs with the next
  change to the watcher.
- **Revisit when:** the next round that changes the watcher.

