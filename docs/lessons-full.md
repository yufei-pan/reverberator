# Lessons: full entries

Why this project's APIs, formats and agreed behaviours had to change. `lessons.md` has one line per
entry: read that first, and look entries up here by date and name rather than reading this whole. New
entries go last, in the same commit as the change:

```markdown
## YYYY-MM-DD <short name>
- Changed: ...
- Why we had to change: ...
- Original design was wrong because: ...
- Lesson: ...
```

## 2026-10-23 reverberator: a vault link is told by the version's moves, not its text
- Changed: in 0.44 a symlink in a version is the vault's own chain link only when its version's move rows (or, with no move, its `../` count) say so. Absolute links are never chain links. Each version's monitored path is recorded in the manifest meta (`monitor_paths`).
- Why we had to change: a user's symlink whose text had the chain form was followed as the vault's own, so pruning could move another file's copy onto it or delete it.
- Original design was wrong because: it read meaning from a value anyone can write (a link's text), with nothing the daemon alone controls to tell its own links apart.
- Lesson: when a format holds both your own records and users' data of the same shape, mark yours with something only you write, from the first version.

## 2026-10-23 reverberator: pruning hard-links instead of moving, and keeps its books itself
- Changed: pruning hard-links the oldest version's copies into the next version and removes the oldest only at the end; size records are moved copy by copy instead of re-measured; a 0600 `.reverberator_prune_salt` names its temporaries.
- Why we had to change: moving copies one by one left the oldest version incomplete partway through, so a prune cut off (a kill, ENOSPC) could lose a copy that two links named; re-measuring by st_nlink was wrong on mergerfs, whose attribute cache shows a stale link count.
- Original design was wrong because: a destructive step ran before the step that made it safe, and the books trusted a filesystem value the live filesystem does not keep exact.
- Lesson: make the old state whole until the new state is complete, and keep counts you can compute yourself instead of reading them back from the filesystem.

## 2026-10-23 reverberator: the vault scan deletes nothing unless certain, and the commit order puts the commit point last
- Changed: the scan reads the whole vault first and fails the job (FAILED marker) on any error or doubt instead of deleting; an orphan is removed only when current_version or the manifest proves it a crashed attempt. A backup now writes its change list whole, commits the manifest, swaps current_version, then places the list (the commit point).
- Why we had to change: `os.path.exists` read any I/O error as "gone", and on mergerfs one disk out hid change lists while their folders showed, so 0.43 could rm -rf committed versions; the old order let current_version lag a committed list.
- Original design was wrong because: the absence of a marker file was taken as proof, though absence also comes from errors and hidden disks; and the records naming the newest version were written after the commit point.
- Lesson: delete only on positive evidence, never on a missing marker; and write every record that names a new state before the step that commits it.

## 2026-10-24 reverberator: the vault database keeps its journal file, in TRUNCATE mode
- Changed: in 0.45 the vault database runs SQLite `journal_mode = TRUNCATE`, and each job vault keeps a 0-byte `.reverberator_manifest.sqlite-journal` between backups, made and flushed once when the manifest opens.
- Why we had to change: in DELETE mode every commit creates and deletes the journal, and only a folder fsync makes that durable; mergerfs answers fsyncdir with ENOSYS, so after a power loss a stale hot journal could come back or a deletion could be lost.
- Original design was wrong because: it assumed a file name's creation and removal are durable once fsynced, on a stack (a FUSE union) that silently drops the one call that makes them so.
- Lesson: on a filesystem stack you do not control, prefer formats whose durability needs only file fsyncs; make a name once and keep it, rather than creating and removing it per transaction.

## 2026-10-24 reverberator: history and restore exit 1 when a vault disk is missing
- Changed: in 0.45, history and restore still run while a disk of the vault's mergerfs pool is missing, print `Warning: <reason>: <job vault> may be incomplete` on stderr, and exit 1 where they would have exited 0; 2 still means a usage error.
- Why we had to change: a missing disk hides part of every version, so a history or restore that exited 0 looked whole when it was not, and a script could take a partial restore for a full one.
- Original design was wrong because: exit 0 meant "nothing raised", not "the result is whole", and whether the vault could be read whole was never part of the answer.
- Lesson: an exit code should say whether the result is complete, not only whether the run failed; give an incomplete-but-useful result its own non-zero meaning from the start.

## 2026-10-24 reverberator: crash recovery lives in the job's scan only, not in the step that failed
- Changed: 0.45 drops the backup commit's own undo. The job's vault scan resolves every cut-off commit, once every disk of the vault's pool is there: a version whose change list is still in a private `.reverberator-change-list-*` folder is removed and current_version goes back. Two states that round 8 recorded as known limitations, which stopped a job until a hand clean-up, now clean themselves up.
- Why we had to change: the undo ran inside the failing step, where a missing disk could hide a committed list, so it could not tell a crash from a hidden list; and its own gaps left those two hand clean-ups.
- Original design was wrong because: recovery was split between the failing step and the next start, and the part in the failing step ran with the least information.
- Lesson: put crash recovery in one place that runs with full knowledge (the next start's scan), and let the failing step only fail.

## 2026-10-27 reverberator: any batch resumed after a restart is followed by a whole-tree comparison
- Changed: in 0.46 a pending batch resumed at a restart counts as round-tripped even when it holds only scans, so a full comparison follows it; before, a scans-only resume compared its scanned folders and nothing else.
- Why we had to change: a chmod, an xattr change or an mtime-keeping write made elsewhere while the daemon was down was never compared, and the new `matched` key (the time from which the vault matched the whole tree) would have advanced past it for good.
- Original design was wrong because: it judged what a resumed batch needs by the batch's own content ("scans compare their folders whole, so nothing is lost"), when what a restart cannot know is what changed outside the batch while nothing watched.
- Lesson: decide what a restart must compare from what was unwatched (the downtime), never from the shape of the work it resumes.

## 2026-10-27 reverberator: an attribute-only change whose mtime moved is copied
- Changed: under Only Sync Attributes, an attrib whose live mtime differs from the recorded one now copies the file. Round 9 synced the new times onto the old copy whenever its size and tail matched (touch -m).
- Why we had to change: an mmap write raises no event and moves the mtime. A chmod in the same batch then put the new mtime on the old bytes, and every later comparison took the copy as current.
- Original design was wrong because: it read a moved mtime as metadata only, while the mtime is the signal every comparison trusts for contents. Writing it onto bytes it did not come with made that signal lie.
- Lesson: never write a change signal (an mtime, a hash, a version stamp) onto data it did not come with; when in doubt, copy.

## 2026-10-28 reverberator: a vault folder is made only once its disk is there
- Changed: parse_rules no longer creates a missing Vault Path (nor ignores a row whose path cannot be created: the job fails and retries), and fills an auto Vault (or Monitoring) File System Signature only for a folder whose disk is there: the longest /etc/fstab mount point at or above it mounted, every disk of its mergerfs pool there. The backuper creates the path inside its vault wait once the disk is there, every vault wait (and every monitored wait) checks the disk, and a stop writes no pending file where it is not.
- Why we had to change: with the pool unmounted, a start made the Vault Path folder on the root disk under the bare mount point and recorded the root disk's signature for an auto cell, so the job then waited on the wrong disk once the pool mounted; a stop wrote its pending file there too.
- Original design was wrong because: it took "the folder exists, or can be made" for "the disk is there", and the one check that judged the disk (the signature) was itself filled from whatever the folder sat on.
- Lesson: before making or writing into a place that must live on a given disk, check that disk by a source that does not depend on the place (here fstab against the live mount table); never fill an identity check from the thing it is meant to check.

## 2026-10-29 reverberator: the rule-file write-back keeps lines that repeat a job name
- Changed: rewrite_rule_rows() no longer removes the earlier lines that carry the same job name as the row it writes
  back; parse_rules warns at each start, once per repeated name, naming the line used. A repeated name's row keeps its
  name cell as written.
- Why we had to change: the user wants a repeated name warned about with the file left as it is; the write-back
  silently deleted the user's lines whenever it filled in a cell of the winning row.
- Original design was wrong because: it took "TSVZ ignores the earlier lines" for "nobody needs them", and tidied the
  user's file as a side effect of a different job (filling in auto cells).
- Lesson: a write-back changes only the cells it exists to fill; anything else in a user's file it finds odd is
  reported, never edited away.

## 2026-11-03 reverberator 0.53: a prune on a mergerfs pool flushes every disk before it destroys the old state
- Changed: the agreed limitation "No flush before a prune's removal" (2026-10-23: a power loss mid-prune on mergerfs could only bring a link back in either form, no copy lost) is gone. On a pool, a prune makes `.reverberator_pruning` in the job vault say which version it walks (one JSON line, made once with a folder flush and kept, written in place and fsynced) before its walk, flushes every disk of the pool after the walk and the records, clears the marker, removes the oldest version, and flushes again before its change lists go. A prune that finds the marker naming its oldest version (or cannot read it) links back from that version whatever the next one lost; the next backup finishes such a prune before it compares. The scan flushes before it deletes a stale change list. A single filesystem gets none of it.
- Why we had to change: a study on a scratch pool showed one mergerfs request (a rename) lands on one disk and unlinks on another, and after a power loss each disk comes back at its own last checkpoint: unchanged files lost their copy in every later version, newest included, copies hid behind stale links, and the scan could stop with a hint to remove by hand the folder holding the only copies. Nothing detected it.
- Original design was wrong because: "a prune cut off anywhere loses nothing" was argued for one filesystem with one order of writes, and carried over to a union of disks that each keep their own order; the limitation was judged on the guess that the worst case was a link in its old form, never tested by cutting each disk at a different point.
- Lesson: on a union of disks, a step that destroys the old state waits for a flush of every disk the new state touched, and a record that the new state is under way is made durable before its first change. Test crash safety by putting each disk back at its own point, not the whole stack at one.

## 2026-11-04 reverberator 0.54.1: backups wait for restores; status says "waiting since", and `daemon.version` is a string
- Changed: a backup no longer runs while a restore of its job copies. Each job has three lock files in the state folder: `job-<name>.restore.lock` (restores shared while they copy; a batch exclusive from before its prune to its commit, and the job's start around its vault scan), `job-<name>.backup.lock` (new: a waiting batch exclusive; a restore shared only while it takes the restore lock, so restores cannot starve a waiting backup) and `job-<name>.history.lock` (new: history and a restore's picker and prompt shared; only the prune exclusive, non-blocking). A restore asks Continue? holding only the history lock, takes the job lock after, and reads the versions again. The daemon never blocks inside flock: it polls while the job runs, so a stop stays prompt. A lock that cannot be checked postpones the whole backup (FAILED marker after 15 min, "...; backup postponed"). `reverberator status` shows a waiting job as "waiting since <time>: <detail>" (was "waiting for disk since"), and a lock wait's detail is its reason alone ("a restore of <job> is copying"). `status --json` `daemon.version` is the string "0.54.1" (was the number 0.54).
- Why we had to change: the agreed 0.55 layout (the newest version is the one real tree, changed in place by each backup) makes a restore that runs during a backup read a tree being rewritten. The user chose "Backups wait" and to ship the locks first on today's layout.
- Original design was wrong because: the restore lock only kept prunes off a vault, on the assumption that a committed version never changes. That holds only for a layout where each backup builds a new tree beside the old ones. The status phrase assumed every wait is for a disk, and the version was a float, which no three-part version can be.
- Lesson: a lock that guards readers from writers is designed for the layout that will be changed in place, and it is taken after the reader's prompt, never around it: a prompt left open must not hold anything a background writer needs. A writer that waits polls with LOCK_NB under its own stop flag. A gate lock lets a waiting writer go first. A wait's status names its reason and is computed at the source, short enough for the card that shows it. Versions are strings.
