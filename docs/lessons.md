# Lessons

What this project's past changes taught us. Read all of this before changing an API, a format or an
agreed behaviour here. For the full story of a line, find the entry with the same date and name in
`lessons-full.md`.

When one has to change, add the full entry to `lessons-full.md` and one line here, newest last, in the
same commit as the change. Keep this file under 20 KB: at the cap, merge lines before adding.

- **2026-10-23 reverberator: a vault link is told by the version's moves, not its text**: when a format holds both your own records and users' data of the same shape, mark yours with something only you write, from the first version.
- **2026-10-23 reverberator: pruning hard-links instead of moving, and keeps its books itself**: make the old state whole until the new state is complete, and keep counts you can compute yourself instead of reading them back from the filesystem.
- **2026-10-23 reverberator: the vault scan deletes nothing unless certain, and the commit order puts the commit point last**: delete only on positive evidence, never on a missing marker; and write every record that names a new state before the step that commits it.
- **2026-10-24 reverberator: the vault database keeps its journal file, in TRUNCATE mode**: on a filesystem stack you do not control, prefer formats whose durability needs only file fsyncs; make a name once and keep it, rather than creating and removing it per transaction.
- **2026-10-24 reverberator: history and restore exit 1 when a vault disk is missing**: an exit code should say whether the result is complete, not only whether the run failed; give an incomplete-but-useful result its own non-zero meaning from the start.
- **2026-10-24 reverberator: crash recovery lives in the job's scan only, not in the step that failed**: put crash recovery in one place that runs with full knowledge (the next start's scan), and let the failing step only fail.
- **2026-10-27 reverberator: any batch resumed after a restart is followed by a whole-tree comparison**: decide what a restart must compare from what was unwatched (the downtime), never from the shape of the work it resumes.
- **2026-10-27 reverberator: an attribute-only change whose mtime moved is copied**: never write a change signal (an mtime, a hash, a version stamp) onto data it did not come with; when in doubt, copy.
- **2026-10-28 reverberator: a vault folder is made only once its disk is there**: before making or writing into a place that must live on a given disk, check that disk by a source that does not depend on the place (here fstab against the live mount table); never fill an identity check from the thing it is meant to check.
- **2026-10-29 reverberator: the rule-file write-back keeps lines that repeat a job name**: a write-back changes only the cells it exists to fill; anything else in a user's file it finds odd is reported, never edited away.
- **2026-11-03 reverberator 0.53: a prune on a mergerfs pool flushes every disk before it destroys the old state**: on a union of disks, a step that destroys the old state waits for a flush of every disk the new state touched, and a record that the new state is under way is made durable before its first change. Test crash safety by putting each disk back at its own point, not the whole stack at one.
- **2026-11-04 reverberator 0.54.1: backups wait for restores; status says "waiting since", and `daemon.version` is a string**: a lock that guards readers from writers is designed for the layout that will be changed in place, and it is taken after the reader's prompt, never around it: a prompt left open must not hold anything a background writer needs. A writer that waits polls with LOCK_NB under its own stop flag. A gate lock lets a waiting writer go first. A wait's status names its reason and is computed at the source, short enough for the card that shows it. Versions are strings.
