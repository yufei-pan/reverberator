# Round 19-20 design: the newest version is the one real tree, older versions link forward ("R")

Status: agreed with the user on 2026-11-04. Round 19 builds the locks (section 2.8) as 0.54.1; round 20 builds R with
pool support P2 as 0.55, released only once the pool cut test (section 5) passes.

## The user's words and decisions (2026-11-03 / 2026-11-04)
- "I want this to be as light and as fast as possible... cause it is an backup solution, so it is designed to always in
  run the background. so every little bit will sum up to a lot over days month years."; "simpler and smarter is better".
- On browsing old versions: "I personality do not do that, but maybe we should keep that as an option to be able to do?
  one of the core for reverberator is reuse existing linux features and easy browse / restore. we can introduce more
  efficient methods if that reduces usage for users that do not need to manually browse the folders and do not need to
  able to copy out entire versions from the backup store".
- Measured first: the vault SSD wrote ~2.7 GiB per hourly work cycle (~25 TB a year). Chose "Design study first", then
  "R, design review first", then "Second design pass, then spec".
- Pools: "Support pools with a limitation", then "P2 from the start" (R ships only once P2's pool cut test passes; a pool
  limitation is written only if that test shows a residual).
- Restores: "Backups wait". Lighter opt-in format: "Skip it".
- Migration: "Make each version a plain tree". Column 7 Keep 1 Complete Backup False: "Treat False as True".
- Approved known limitations (written to docs/limitations.md when 0.55 lands):
  - "Versions more than 40 back cannot be browsed by hand" ("Known limitation"), replacing "User symlinks past 40 hops";
  - the one-time conversion judges 0.54 links by their text alone ("Accept for the conversion"), widening the existing
    "A user's link written as its own path's chain link" entry for the conversion only;
  - "After a crash, a folder whose row holds no record can keep the backup's time" ("Known limitation").
- A cut backup after the hand-over is always finished and committed ("Always finish it").
- The 0.54 prune and scan code stays one release for unmigrated vaults ("Keep it one release").
- Build: "Locks first, then R".
- 2026-11-05, on the round 20 plan's questions:
  - The rehearsal includes the passwords vault's names and metadata ("Include it, no names shown (Recommended)").
  - A real copy of each vault before the first start ("All four to /mnt/fast (Recommended)").
  - §14's removals and rewordings ("Apply as drafted (Recommended)"): remove the pool prune, bumped times and Copy threads
    auto entries; narrow "A user's link written as its own path's chain link" to the one-time conversion; reword the two
    move entries and the size estimate entry.
  - The setgid entry stays, reworded for 0.55 ("Keep as known limitation (Recommended)").

Background: study `r19/design/report.md`, reviews `r19/opus-review.md` and `r19/step-review.md`, spec check
`r19/spec-check.md` (session scratchpad; the numbers below are from them).

---

# reverberator 0.55: design R, second pass (the spec, revision 2)

I wrote no daemon code, and the repo was not touched. The prototype and results are in scratch:
- Scripts: `<scratchpad>`
  - `r2.py`: writer, scan, reader and the checked walk.
  - `crash.py`: the oracle harness.
  - `recheck.py`: the history-walk test.
  - `powerloss.sh`, `measure.py`, `migrate.py`.
- Results: `…/r19/design2/out/` (`crash_single_r3.jsonl`, `crash_double_r3.jsonl`, `crash_oracle_r3.json`, `powerloss_states.txt`, `measure.jsonl`, `migrate.jsonl`).
- Both loop images were unmounted and deleted, and I checked: no mount, no loop device, no image file, no mount folder.

## 0. In short
**The layout.** The newest version is the one real tree. Each older version V<k> holds real entries only where batch k+1 changed something. Everywhere else it holds a **forward link**: `../…/V<k+1>--<ts>/<its own path>`.

Links point to the **next** version, not to the current one. A path that has not changed for k versions passes through up to k links to reach its copy. That chain is where the browsing limit in §4.5 comes from.

**A backup:**
1. Swaps a fresh folder of forward links with the tree, in one `RENAME_EXCHANGE`.
2. Before changing any path of the tree, records that path's old state into the previous version.
3. Changes the tree in place.
4. Commits.

**A prune** renames the oldest version away and runs `rm -rf` on it. Nothing links into the oldest version.

**Results:**
- **Writes, work job:** today 2,678–2,711 MiB per cycle; R about 20–31 MiB.
- **Crash test:** all 249 kill points pass, with every version exact, folder times included.
- **Code:** about −450 lines in 0.55. About −2,400 once the 0.54 reader and scan go, in a later release (§8).

## 1. Vault layout (API change)
- **Version folders.** Named `V<n>--<ts>/` as today.
  - The newest committed version holds the whole tree: real folders, real files and users' symlinks. It holds no daemon link.
  - An older version V<k> has a real root (owned by root, mode 0755). Each entry in it is either:
    - **real:** what version k had there; or
    - **a forward link:** a symlink at `V<k>/<rel>` whose text is exactly `'../'*(rel.count('/')+1) + '<V<k+1> folder name>/' + rel`. It means the same as version k+1 at this path, for the whole subtree.
  - A real folder in an older version lists exactly version k's entries, with version k's owner, mode, times and xattrs.
- **Shared inodes.** An older version may share inodes with newer versions:
  - a moved entry's source (recorded by hard link);
  - a file whose new copy failed;
  - every version after the migration.
- **Who changes an older version.** Only the batch right after it, which only adds records. One exception: an Only Sync Attributes change is applied in place on the tree's file, so every version sharing that inode when the change landed shows the new attributes. That is today's "shared copy" rule (§2.4).
- **`current_version`.** A link to the newest committed version, as today.
- **Change lists.** The name format is unchanged. The size and inode count now mean what removing that version frees; the newest version's numbers are the whole tree (§6).
- **`.reverberator_staging/`** (new). The daemon's scratch folder on the vault filesystem. It holds:
  - folders being built;
  - links swapped out;
  - link temps;
  - a version being pruned;
  - on a pool, the skeleton or a migrated tree.

  The scan empties it, after the pool repairs (§5). It is kept between backups.
- **The manifest** still describes the newest version, now at schema 3:
  - new meta keys: `layout`='r', `previous_list` (§2.6) and `migrated`;
  - `copy_version` and `monitor_paths` are no longer used.
- **Removed by the migration:** `.reverberator_prune_salt`, `.reverberator_pruning`, and the prune temps left beside links.

## 2. The writer
Notation: n is the newest committed version, N the new one, T the tree, P the previous version's folder.

### 2.1 Hand-over (single filesystem)
This runs where `make_version_folder` runs today, after the comparison and the retention loops:
1. `mkdir V<N>--<ts>`. As today, this fails if something is already there.
2. Create one symlink per top entry of V<n>, with text `../V<N>--<ts>/<entry>`. These links name their own folder, so the folder is an orphan that no reader follows.
3. Copy V<n>'s `trusted.reverberator.root` record and V<n>'s atime and mtime onto it.
4. `RENAME_EXCHANGE(V<N>, V<n>)`. V<n> is now P (the forward links); V<N> is now T (the tree).

There is no window in which a link leads nowhere. `current_version` keeps naming V<n>, which still shows version n whole, until the commit.

**A fixed tree name was rejected.** Older versions must name the newest version's own folder. With a fixed tree name, the newest version's name would have to be a link to the tree:
- `cp -a` would then copy a link;
- the scan's rule that a version folder is never a link would go;
- `current_version` would show a tree that is still being written.

### 2.2 Records: every tree change is recorded first
Every change to T goes through a few primitives: place a copy, remove, rename, make a folder, set folder metadata. Each primitive records first.

P/rel **forwards** when it is a symlink whose text is exactly `fwd(rel)` (the forward text above, with V<N>'s name).

**`ensure_real(folder)`** walks P from its root, one component at a time:
- A component that forwards to a folder in T: unfold it.
- A real folder: continue, noting its times.
- Anything else: return False. Version n has no folder there, so nothing below it needs recording.

**`unfold(rel)`:**
1. `mkdir` a folder in staging.
2. Add one forward link per entry of T/rel. T/rel is still version n's, because P forwarded it.
3. Copy T/rel's owner, mode and xattrs onto it (`copy_file_meta`).
4. `RENAME_EXCHANGE` it with P/rel.
5. Set P/rel's atime and mtime. f2fs bumps the mtime of a folder renamed into another parent.
6. Give P's parent folder its times back.
7. Unlink the old link, which is now in staging.

**`record(rel, keep)`.** Runs before T/rel is replaced or removed:
1. `ensure_real(parent)`.
2. If P/rel forwards:
   - **T/rel is a folder:** `RENAME_EXCHANGE(T/rel, P/rel)`, restore P/rel's times and its parent's, then unlink the self-named link left at T/rel.
   - **T/rel is a file, `keep` set** (the tree keeps it until the new copy replaces it): `link()` it to a staging temp, then rename the temp over P/rel.
   - **T/rel is a file, being deleted:** `rename(T/rel, P/rel)`.
3. Else, if P/rel and T/rel are both real folders: record each entry of T/rel (a merge).
4. Else: nothing to record.

**`hl_record(rel)`.** A move's source:
1. `ensure_real(parent)`.
2. If P/rel forwards:
   - **A file or link:** `link()` it, then rename over P/rel.
   - **A folder:** build a hard-link tree in staging, exchange it in, and restore times.
3. If both sides are real folders: `hl_record` each entry.

**Idempotent.** A record only acts where P still forwards. P's real part is therefore the record set; no separate list is kept.

**P folder times** are given back right after each change in P. After a crash, the roll-forward restores them (§3).

**Invariant:** if P/rel forwards, then T/rel's whole subtree is unchanged since version n. So version n's view is exact at every instant. The oracle checks this at every kill point.

| tree change | recorded first |
|---|---|
| place a copy at rel (create, modify, non-OSA attrib, verification fix) | `record(rel, keep=True)`, before the copy is queued |
| copy temp `.<uuid>.reverberator-partial` beside rel | covered: P/parent is already real, so P never lists the temp |
| make folders down to rel | `ensure_real` of the deepest existing ancestor |
| folder create where T/rel is already a folder (`copy_path` keeps it and copies into it) | `ensure_real(rel)`, then each entry recorded as its copy is queued; an existing subfolder is handled the same way (new) |
| folder create where T/rel is missing or not a folder | `record(rel, keep=False)`; nothing needs recording below a new folder |
| delete (replay, sweep, "Removing <target>…") | `record(rel, keep=False)` |
| move src→dst | `record(dst, False)`, `hl_record(src)`, `ensure_real(parent(dst))` |
| folder attrib, `WrittenFolders.settle`, `touched.folders` | `ensure_real(folder)` |
| file attrib under Only Sync Attributes | none (§2.4) |
| `record_root_meta` on T | none (P got its own copy at the hand-over) |

The folder-create row is the fix for Opus finding 2b. A failed copy of an unreadable file keeps the last copy in both versions (README line 67). The old rule, which swapped the whole folder into P, fails the oracle; the new rule passes (§9).

### 2.3 Moves
A move's source is recorded by hard links before the tree rename. P never refers to a moved path, so every record is a same-path record.

Example: `mv d e; echo new > e/x`. Version n had no e, so recording `e/x` finds nothing. The new copy then replaces T/e/x by rename, and the old inode stays in P/d/x.

Cost: one inode write per entry of a moved folder, and the same again at its prune. If a hard link is refused (`NO_HARD_LINK_ERRNOS`), the record copies instead (`cp -a --reflink=auto`).

### 2.4 Attribute-only changes
- **Only Sync Attributes** (all four live jobs): applied in place on T's file, as today on the shared copy. Older versions that share that inode see the new attributes. That covers versions that forward to the file back to its last change, and older versions that hold a hard link to it. The README already says a restored file "carries the newest mode, owner and times its shared copy has".
- **Without Only Sync Attributes, or when the mtime moved:** record, then copy, as today.
- **Folders:** `ensure_real`, then set T's metadata.
- **A whole-tree folder event** costs 961 MiB, once.

### 2.5 Copies, temps and staging
- Copies stay `cp -a` into a temp beside the destination, as today.
- The record is a hard link made before the copy is queued, so a failed copy keeps the last copy in both versions.
- Temps are not put in staging. Doing so would dirty staging's folder block on every copy, and on a pool it would cross disks.

### 2.6 Commit (one commit point)
1. Write the change list whole in its private folder and fsync it.
2. `pool_guard.require()`.
3. **Commit the manifest** (rows, matched, version=V<N>, `previous_list` = P's current list name and its new name with its size). **This is the commit point.** From here on V<N> is committed: if anything below is cut, the scan finishes it.
4. Swap `current_version`, then fsync the job vault.
5. Rename P's list to its new name.
6. Place V<N>'s list.

If the manifest names V<N> but the list is missing from its private folder, the scan refuses, as today: a missing disk may be hiding it.

### 2.7 Prune
1. Rename V<k> into `.reverberator_staging/<name>`. It stops being a version in that one call.
2. Remove its list.
3. `rm -rf` the staged folder.

After a cut, the scan empties staging and removes a stale list below the oldest version (today's rule). On a pool, every disk is flushed after the rename.

### 2.8 Locks (the user chose "Backups wait")
There are three lock files in the state folder:

| file | taken by |
|---|---|
| `job-<name>.restore.lock` (existing) | restores, shared; a batch, exclusive |
| `job-<name>.backup.lock` (new) | a batch, exclusive, from when it starts waiting until it ends; a restore, shared and only for a moment just before it takes the restore lock |
| `job-<name>.history.lock` (new) | history, and a restore's picker, prompt and copy, shared; only the prune, exclusive and non-blocking (postponed as today) |

**A batch never blocks inside flock.**
- It polls `LOCK_EX|LOCK_NB` on the backup lock and then the restore lock, every POLL_WAIT_SECONDS, while watching GREEN_LIGHT. A stop therefore stays prompt, and the batch's events stay queued as on any stop.
- It logs once: "Waiting for a restore of <job> to finish before backing up".

**No starvation.** A restore arriving while a batch waits blocks on the backup lock. Restores already running drain, then the batch runs.

**Restores lock after the prompt.**
1. A restore takes the history lock, then resolves, lists and asks (picker, free-space check, "Continue? [y/N]") without the restore lock. A restore left at its prompt therefore never holds off backups; it only postpones pruning, as today.
2. It then takes the backup lock (shared, blocking), the restore lock (shared, blocking, with "Waiting for reverberator to finish a backup of <job>"), and releases the backup lock.
3. It re-resolves everything it reads under the lock.
4. `--accept` does the same.

**A lock that cannot be checked** (open or flock fails, other than a missing state folder) postpones the **whole backup**, not only the prune. This follows from "Backups wait". After the 15-minute grace it logs `FAILED: cannot check the restore lock <path>: <error>; backup postponed` and repeats hourly.

**Lock scope.**
- **At a job's start:** the locks are taken before the scan. They are held through a migration, and otherwise released when the scan ends, so a restore can run while the monitored path is gone. A roll-forward's comparison reads the tree without locks, as any batch; it takes them for its prunes and holds them to its commit.
- **A normal batch:** takes them before its retention loops and releases them after its commit or its failure. The comparison before it reads the tree without locks.

## 3. Scan and roll-forward (R vaults). No deletion on inference.
**Scan:**
1. **A commit cut after the manifest named V<n+1>,** with its list complete in a private folder: roll it forward. Swap `current_version`, rename the previous list if it still has its old name (per `previous_list`), then place the new list.
2. Remove other private list folders, as today.
3. Empty `.reverberator_staging` (pools: §5 repairs first).
4. **V<n+1> exists with no list:**
   - **Empty, or every entry is a symlink with text `../<its own folder name>/<entry>`:** a hand-over cut before its exchange. Remove it with `rm -rf` (`remove_orphan` is reused).
   - **Otherwise:** it is the tree of a cut batch. Keep it for the roll-forward.
   - A lone V0 orphan is removed; any other orphan is an error, both as today.
5. Remove a stale list below the oldest version, and move `current_version` forward, both as today.

**Roll-forward.** This is the next attempt, holding the locks from the scan to its commit. A crash during it just repeats it.
1. Walk P's real part, through real folders only. These are the recorded paths.
2. Give each real folder of P back the mtime that version n's manifest row records for it. A rename never moves atime.
   - A folder whose row holds no record keeps its current time. If a crash hit its one-call window, that is the backup's time (a tiny limitation proposed in §14).
3. A self-named link a cut exchange left at T/<recorded folder> needs no step of its own: the comparison and the sweep take it.
4. Mark the rows of every recorded path UNVERIFIED.
5. Run a full comparison that **reads T = V<n+1>**. It says what to replay, with one addition: a saved plain file modify, create or move it did not find, while the monitored path is a regular file, replayed as a modify, as a rewrite that keeps size and mtime shows only to the watcher. No other saved entry is used: it covers the whole tree, and a saved file entry where a folder stands now would fight what it finds. A move the cut batch had not applied becomes a delete and a copy, once. There is no hand-over.
6. Run the same retention loops as a batch, after the comparison and before the first write into the tree, counting the tree as the version being made. Never prune P, never the last version.
7. Sweep the whole tree: tree entries that P does not hold and that no row tracks are removed through `delete()`.
8. **Always commit V<n+1>.** Once the hand-over has happened, the tree carries V<n+1>'s name and P is the forward-link folder. As soon as anything was recorded, the tree also differs from version n: old copies have moved into P and new ones are in place. Undoing this would need a second writer that moves every record back. Finishing the version is the only consistent way forward, at the cost of one version slot after a crash. (Only a cut that came before any record could be undone, by one exchange. That case is not special-cased.)

### 3.1 Vaults not yet migrated (`layout` ≠ 'r')
At start, still under the locks, the 0.54 rules run unchanged before the migration:
- `read_job_vault`'s 0.54 orphan rules, `remove_orphan` and `undo_cut_off_commit`;
- on a pool whose `.reverberator_pruning` names the oldest version, `decrement_stepper` finishes that prune.

These parts (1,927 lines, listed in §8) stay, unused by R, until the release that drops the migration reader.

## 4. Readers
### 4.1 The walk
Used by `resolve_version_entry`, the restore walk, history, `path_kind`, the picker and `--accept`. Starting from V<k>'s root, each component is lstat'd; the kernel never follows anything.
- **A real folder:** continue.
- **A symlink whose text is `fwd(prefix)`** for the folder numbered k+1 (committed or being written): walk the same prefix again from V<k+1>'s root.
- **The last component:** that is the entry.
- **Anything else above the last component:** the path is missing.

Links are judged by their text alone. A user's symlink in V<k> was backed up before V<k+1>'s name existed, so it can never carry the forward text.

### 4.2 history while a backup runs
history holds no lock that a batch needs.
- After reading an entry, it re-reads the forward links it followed. If any of them changed, it walks again. Records only ever turn links into real entries.
- If a walk finds an entry missing or a forward link leading nowhere while the job's backup lock is held (checked with `LOCK_SH|LOCK_NB` and released at once), history waits for the backup to end and walks again. This covers a pool's two-rename moments, including the hand-over window (§5).
- A change list renamed by a commit (ENOENT) is listed again.

**Acceptance test** (prototype `recheck.py`, to become a repo test). The crash batch advances one vault change at each read of the walk, starting from each of 260 points in the backup. Every file of V1 and V2 is resolved (about 80 reads per start). Every read must equal the oracle.
- With the recheck: 0 wrong reads.
- Without it: wrong reads at 15 starting points. This shows the test can fail.

### 4.3 The CLI on a vault not yet migrated (spec check 3.3)
**The rule:** when the manifest's `layout` is not 'r', the same walk follows **0.54 chain links by their text**. A link in V<k> naming the previous version folder plus a clean path is followed backward (`parse_chain_text`, which the migration keeps). No forward rule is used, because no R batch has run yet.

**Why this rule:**
- It is the migration's own rule, so the CLI shows exactly what the vault will be after conversion.
- The CLI never writes to the vault, which keeps the README promise.
- It never returns symlinks for files.
- It works while the daemon waits for a disk.
- No old reader is kept.

During a running migration, already-converted versions simply have no chain links. A transient ENOENT causes a re-walk. The manifest is read with a short retry while it is locked.

### 4.4 Restore
- Files are copied from where the walk lands.
- Whole job: refuse when free space is below the newest version's size. Warn when it is below that size plus the sizes of the versions from the chosen one up.
- **Keep 1 Complete Backup = False** is read as True (the user's choice). The start logs one line: "Keep 1 Complete Backup is False for <job>: from 0.55 its first version is always a complete copy". Rows of 0.54 referenced links (kind 'r') count as different, so the first comparison copies those files. Restore reports a referenced link as today.

### 4.5 Browsing and copying by hand (what is true)
- **The newest version (`current_version`)** is a plain tree. Every tool works.
- **Older versions:**
  - `ls`, `cat`, and `cp` of a single file work.
  - `find`, `du` and `rsync` need `-L` to go into folders that did not change.
  - `cp -a` and `rsync -a` copy forward links as links, which point nowhere once copied out.
  - `cp -aL` and `rsync -aL` give whole files, but they also follow the user's own symlinks.
  - **`rsync -a --copy-unsafe-links V<k>/ dest/` comes closest** (tested):
    - forward links are copied as what they name;
    - users' links that stay inside the version stay links;
    - users' links that are absolute or climb out of the version are copied as what they point to on this machine now;
    - a dangling one is skipped with an error.
  - Today's chain links behave the same, so none of this is a regression. A faithful copy is `reverberator restore --version N`.
- **The 40-link limit.** A path k versions back passes through up to k forward links. Every symlink in the vault's own path (a linked mount point, for example) counts against the kernel's 40. So hand browsing works for versions up to about 40 back, about 20 while Docker changes mounts; restore and history work at any age. The live maximum keep-N is 14. This is now an approved known limitation.

## 5. Pools (mergerfs). R ships only with this, and only after the pool cut test passes.
mergerfs gives EINVAL for `renameat2` flags. A rename can also land on one disk while the removal of its target lands on another.

**Hand-over:**
1. Build `staging/skel-<V<n>>`.
2. Flush every disk.
3. Rename V<n> to V<N>.
4. Flush.
5. Rename the skeleton to V<n>.
6. Flush.

Between steps 3 and 5, V<n> is missing: `current_version` and the older versions' links lead nowhere. history waits, then re-walks (§4.2). Restores wait on the lock. Hand browsing sees broken links for those flushes.

**Unfold, folder record, moved folder:** built in staging, then two renames (P's link moved away, the built folder moved in).

**Records** are always hard links, so the tree keeps every entry until its apply phase.

**Pre-record passes.** Before each apply phase (the replay; the verification's fixes; the sweep plus settle), the batch records every path the phase will change (the §2.2 table), then flushes every disk. Records made inline afterwards are no-ops. The prune flushes after its rename; the commit flushes as today.

**Scan repairs, before staging is emptied:**
- **A skeleton in staging and V<N> with no list:** redo the rename V<n>→V<N>, flush, rename the skeleton in, flush.
- **`staging/m-<name>` present, `<name>` missing, its list present** (a cut migration): rename it into place.

**Roll-forward repairs, per disk:**
- **A name that is a forward link on one disk and a real entry on another:** remove the link on its disk.
- **A version-n row missing under a real P folder while T holds the entry:** put a forward link back. T is unchanged there, because its apply phase had not begun.

**Expected loss after the repair:** none of the previous version, as long as every disk comes back. This is reasoned, not yet tested.

**The pool cut test** (the build's gate):
- Each branch is its own f2fs loop image under mergerfs.
- For each disk, choose a cut step c_i at or after its last flush, independently of the other disks.
- Run the batch; at c_i, run syncfs on disk i.
- At the end, run `f2fs_io shutdown 2` (nosync) on every disk, then remount. Each disk comes back at its own point.
- Run scan plus retry, then the oracle.
- Cover every pair that has a cut at a phase boundary, plus about 2,000 sampled pairs, for 2 and for 3 disks.

A pool limitation is written only if this test shows a residual.

## 6. Sizes (one definition)
**Every inode is counted once, in the newest version that holds it.** A version's size (in its list's name) is what that version alone holds:
- **Newest:** the sum of its file rows' sizes plus 4 KiB per folder row. Its inode count is its rows.
- **An older version:** the entries the tree stopped holding in the batch that recorded them, plus 4 KiB per real folder of its own and one inode per link.

The batch counts at the record primitives, using row sizes:
- `record(keep=False)` and folder exchanges count into P (a folder exchange counts the sum of the rows under it);
- `record(keep=True)` counts into P once its copy is placed;
- a failed copy and `hl_record` count nothing into P, because T still holds the inode.

When T later drops a shared inode, the batch that drops it records it into its own P, which is then the newest holder.

At commit, the previous newest version's list is renamed. Removing the oldest version frees exactly its size, so the size-limit loop (`vault_size -= removed_size`) stays right. The estimate made before a batch is unchanged. `measure_version_usage` and `CopiedSizes` go.

## 7. Migration from 0.54 (decided: each version becomes a plain tree)
**When.** At a job's first 0.55 start, under the locks, after the 0.54 rules in §3.1. It runs when the manifest has no `layout`='r' and versions exist. A manifest that started over determines the layout while it is rebuilt.

**Per version, newest first, for each version holding any 0.54 chain link:**
1. Build `staging/m-<name>`: folders with the version's metadata, and each non-folder hard-linked to its chain end. Chains are followed by their text (accepted by the user). A dangling chain becomes the link itself. A 0.54 prune temp (`is_prune_temp`) is left out.
2. `RENAME_EXCHANGE` it with the version folder. On a pool: two renames with flushes.
3. `rm -rf` the old tree.
4. Add the version to `migrated`.

A version with no chain link (0.54's oldest, which the prune made whole) is left as it is.

**Then a sizes pass (spec check 3.4).**
1. Walk every version, newest first, keeping a set of inodes already seen.
2. A version's size is the bytes and inodes it holds that are not in the set, plus 4 KiB per folder. The newest version's size is the whole tree.
3. Rename each list to that size. A cut reruns the pass; the renames are idempotent.

Then set `layout`='r' and remove the salt and marker files. Until the sizes pass ends, no backup or prune runs, so the size-limit loop never sees 0.54 sizes.

**Crash-resumable.** Each version is swapped in one call, and redoing a version is idempotent. The rows stay valid (same inodes), so no full comparison is needed.

**Cost (measured at the work job's shape):**
- 906–942 MiB per version, for 4 versions: about 3.7 GiB, 22 s on scratch.
- The next 4 prunes each remove a hard-link tree at 732 MiB: about 2.9 GiB over 4 hours.
- Total about 6.6 GiB once.
- docker_volumes about 0.1 GiB, passwords about 0.03 GiB, app_db negligible.

**What the live vaults see:** one log line per version, then normal backups. There is no way back to 0.54.

## 8. What goes and what comes
Line counts are measured with `ast` at HEAD 8a8bcb9, inclusive.

**Removed in 0.55 (802 lines):**

| part | lines |
|---|---:|
| do_referenced_copy | 185 |
| recopy_rels | 50 |
| chain_form_missing_version | 46 |
| batch_rewrites | 44 |
| chain_end | 44 |
| measure_version_usage | 43 |
| copy_threads_auto | 42 |
| retarget_moved_links | 32 |
| CopiedSizes | 31 |
| link_chain_end | 31 |
| retarget_chain_link | 31 |
| referenced_link_text | 27 |
| read_chain_length | 23 |
| kernel_cannot_follow | 21 |
| command_monitor_paths | 19 |
| read_copy_threads | 19 |
| learn_copy_version | 18 |
| recopy_hops | 15 |
| recopy_threshold | 14 |
| sysfs_device_rotational | 14 |
| recopy_size | 13 |
| effective_copy_version | 11 |
| block_device_rotational | 10 |
| manifest_monitor_paths | 9 |
| copied_hop | 8 |
| CopyInterrupted | 2 |

**Kept, unused by R, until the release that drops the 0.54 reader (1,927 lines):**
- `decrement_stepper` and everything it calls (1,747):

  | part | lines |
  |---|---:|
  | decrement_stepper | 734 |
  | VersionMoves | 286 |
  | vault_chain_hop | 101 |
  | VaultMoves | 74 |
  | rows_dropping | 63 |
  | in_row_order | 61 |
  | is_real_folder_under | 58 |
  | PathHashes | 49 |
  | read_change_list_moves | 38 |
  | write_prune_marker | 29 |
  | undo_cut_off_commit | 27 |
  | read_prune_marker | 26 |
  | CommittedMoves | 23 |
  | prune_link_path | 23 |
  | remove_orphan (reused by R) | 23 |
  | read_recorded_monitor_paths | 23 |
  | read_version_moves | 19 |
  | remember_version_moves | 17 |
  | written_under | 17 |
  | forget_real_vault_folders | 16 |
  | change_list_rows_ended | 15 |
  | UnexplainedChainLink | 9 |
  | forget_version_moves | 7 |
  | recorded_monitor_paths | 7 |
  | UnreadablePruneMarker | 2 |

- Also kept: `vault_prune_salt` (90).
- The migration and CLI reader: `parse_chain_text` 43, `is_prune_temp` 31, `is_previous_version_name` 14, `same_inode` 2.

**Shrinks, about −400:**
- `do_reverb_backup` 688 → about 520;
- `do_backup` 358 → about 300;
- VaultManifest 487 → about 430;
- the read_vault_record / read_copied_record / attribs_to_copy group (126) → about 70;
- `resolve_version_entry` 70 → about 65;
- comparisons −20.

**Comes, about +760:**

| part | lines |
|---|---:|
| record primitives and P times | 160 |
| hand-over | 45 |
| R scan rules and pool repairs | 70 |
| roll-forward | 70 |
| walk, recheck, wait, and the 0.54 text rule | 85 |
| sizes | 40 |
| prune | 15 |
| migration with its sizes pass | 140 |
| locks | 50 |
| pools (pre-record passes, per-disk repair) | 80 |
| Keep 1 Complete Backup / 'r' rows | 5 |

**Net:** about −450 lines in 0.55, and about −2,400 once the kept parts go.

**Tests:** 29 files (16,967 lines) touch these parts. The prune tests stay until the later release. The crash harness and the history recheck test become repo tests.

## 9. Crash tests (re-run on a fresh f2fs loop image with the live disk's features and mount options)
**The setup:** a vault built by batches 0–2 (keep-N 3), then a mixed batch 3 that is killed. It has 249 vault-changing calls and contains:
- a prune and a hand-over;
- creates, modifies (b/y.txt twice, one three levels deep), deletes and folder deletes;
- `mv d/g y; rm -r d`;
- a move followed by changes under it;
- folder and file swaps, chained moves;
- a modify-then-delete;
- a folder chmod;
- file↔folder changes and a user-link retarget;
- a non-OSA attrib;
- **(new)** a folder copied over the folder already there, one of its files unreadable;
- the commit.

**The check:** each kept version is read through its links and compared with the oracle: kinds, contents, modes, file and folder mtimes, link texts, root records, lists, `current_version` and leftovers. An unreadable file must keep its last copy.

| run | result |
|---|---|
| single kills at every step (+2 past the end) | 251/251 exact |
| double kills (batch, then retry killed at random) | 500/500 |
| monitored tree changed after the crash | 251/251 |
| f2fs power-loss model (`f2fs_io shutdown 2`, remount) | 251/251 (244 rolled back to before the batch, 7 to after the list fsync) |
| history recheck, interleaved (§4.2) | 260 starting points, 0 wrong reads (15 starting points with wrong reads without the recheck) |

**The oracle catches bugs:**
- the old whole-folder swap for a folder create over an existing folder fails;
- a missing deep unfold fails 30/30;
- a roll-forward without the UNVERIFIED marks fails 128 times.

**Rules the tests forced:**
- folder times are set after every exchange;
- the sweep takes the self-named links a cut exchange left;
- P folder mtimes are restored from rows (otherwise 15 of 186 kill points left the batch's time);
- a normal retry prunes only when it backs something up;
- per-entry records for a folder created over an existing folder.

**Not built:** pools (their test is the build's gate, §5).

## 10. Measured writes (live shape, live V73–V76 change lists, keep-N 5)

| | today (study) | R |
|---|---:|---:|
| whole cycle | 2,678–2,711 MiB | — |
| backup, V73 rows | | 28.5–29.5 MiB |
| backup, V75 rows | | 23.0–23.3 MiB |
| backup, V76 rows | | 18.5–18.7 MiB |
| prune | | 0.2–0.4 MiB (2.6 MiB after a whole-tree event) |
| manifest | | +about 1.5 MiB (not modelled) |
| vault-writing calls | about 2.6M fs calls | 4.5–7.7K |
| whole-tree folder event | | 961 MiB once |

The work job goes from about 64 GiB/day to about 0.5–0.75 GiB/day. These numbers were not re-measured after this revision: the only writer change, per-entry records for a folder created over an existing folder, does not occur in the live batches.

## 11. Review findings, settled
**Opus:**
1. **A change after a move:** fixed by hard-link move records.
2. **Swaps and 2b:** swap only while P forwards, otherwise merge; per-entry records for a folder copied over an existing one (tested).
3. **The scan:** §3.
4. **The repair:** staging plus roll-forward (UNVERIFIED rows, sweep through `delete()`).
5. **Restores:** backups wait, the lock is taken after the prompt, and the backup lock prevents starvation.
6. **Records and temps:** §2.5.
7. **Sizes:** §6.
8. **Folder times:** §2.2 and §3.
9. **Pools:** §5.
- Readers judge links by text alone. The hop limit is an approved limitation. The xattr scheme was dropped.

**Step:**
1. **Pools:** §5 (P2 only).
2. **Non-empty exchange:** not an issue (tested).
3. **Idempotency:** yes, by construction.
4. Same as Opus 2.
5. **Moves:** recorded by hard link.
6. **Hand-over window:** none on one disk; on a pool, readers wait (§5).
7. **Restore race:** restores wait under the lock.
8. **Attribute changes:** §2.4.
9. **Hop limit:** approved, with vault-path links counted.
10. **Root record:** tested.
11. **Folder times:** restored from rows.
12. **xattr scheme:** dropped.
13. **Migration resume:** plus the sizes pass.
14. **Fixed tree name:** rejected.
15. **Per-batch record set:** P is that set.

## 12. Build order
1. **Locks:** backup, restore and history locks; restore locks after its prompt; the batch polls. This works on 0.54's layout and ships alone.
2. **R with pools P2 as one release (0.55):**
   - migration (0.54 rules first, sizes pass);
   - hand-over (single disk and pool), records, commit and sizes, prune;
   - scan and roll-forward;
   - readers (forward walk, recheck, the 0.54 text rule for the CLI);
   - columns 7, 14 and 15;
   - removal of the 802 lines;
   - README and limitations;
   - the crash harness, the recheck test, and **the pool cut test, which must pass before release**.
3. **Later release:** remove the 1,927 kept lines, and their tests, once every vault is migrated.

## 13. README drafts (line numbers are README.md's)
- **Line 7:** drop "(a warning for Copy threads)".
- **Lines 9 and 10:**
  > "14, Chain Length and 15, Copy threads: kept so rule files that have them stay valid; from 0.55 neither has any effect, and any value is accepted without a line."
- **New line after 10:**
  > "Keep 1 Complete Backup (column 7) False is read as True from 0.55: a job's first version is always a complete copy, and the start logs one line saying so."
- **Line 13:**
  > "The newest version is a plain tree: its folders, files and your symlinks as the monitored tree was at that backup. Each older version holds as real entries only what the backup after it changed (files it replaced, removed or moved away, folders whose entries or metadata it changed), and everything else as one link to the same path in the version after it (../V<n+1>--<time>/<path>, a forward link), so a version costs what changed after it. Before a backup changes anything in the tree it moves the old state into the version before (a moved entry by hard links), so every committed version shows exactly what it held at every moment, a crash included (on a mergerfs pool, once the next start's repair has run)."
- **Line 14:**
  > "The first 0.55 start of each job converts its vault once, before backing up: newest version first, each version holding links to an older one is rebuilt beside itself as a plain tree of hard links to the same copies and swapped in in one step, then each change list is renamed to what its version alone holds (one log line per version; work's vault took about a minute and ~3.7 GiB of writes, and its next four prunes ~0.7 GiB each). A start cut off goes on where it stopped. There is no going back to 0.54."
- **Line 20:** "keeps its links to the older copies" → "is moved, not copied again".
- **Line 23:** "the end of its chain in the vault" → "the vault's copy in the newest version".
- **Line 25:**
  > "A symlink the monitored tree holds is backed up as itself. A link in a version is the vault's own only when its text is its own path in the version after it, which no backed-up symlink can be, as that version did not exist when it was backed up."
- **Lines 26–29:**
  > "Pruning renames the oldest version into .reverberator_staging, removes its change list, then deletes it; nothing links into the oldest version, so a prune cut off anywhere loses nothing of the others. Each job vault keeps a .reverberator_staging folder for the backup's own building, which the job's vault scan empties; leave it in place."
- **Line 33:**
  > "A path in a version k versions older than the newest reaches its copy through up to k forward links, and every symlink in the vault's own path counts too, so browsing by hand fails with 'too many levels of symbolic links' in versions more than 40 back (about 20 while Docker changes mounts); restore and history follow them themselves."
- **Line 51:** "and its files lose their links to the older copies" → "and its files are written to the vault again in full".
- **Line 64:** add:
  > "and during a backup, after the tree is handed to the new version and between recording the old state and changing the tree (the hand-over leaves the version before it missing for those flushes, and history waits for it)"
- **Line 66:** add:
  > "When the backup after it starts, the version before it gets a copy of the record."
- **Line 69:** add:
  > "A version folder after the newest with no change list is removed only when it holds nothing but links to itself (a backup cut off before it began); otherwise it is the tree a cut backup was writing, and the job's next attempt finishes and commits it. A commit cut off after its database named the version is finished, not undone."
- **Line 95:** "Chain links are followed to the real file" → "Forward links are followed to the version holding the entry".
- **Line 97:** "(root's, 0755, its commit time)" → "(root's, 0755, its own times)".
- **Line 98:** "the oldest kept version took … (that version holds the whole tree; the others only what changed after it)" → "the newest version took (it holds the whole tree; each older one what the backup after it changed)". The warning uses the newest version's size plus the sizes from the chosen version up.
- **Line 99:**
  > "Retention and backups: a restore picks its version and asks Continue? without holding anything that backups wait for; it then waits for a running backup and holds the job's lock while it copies, and the daemon backs that job up only once it ends (one log line). history holds a lock of its own that only pruning waits for, and reads again what a backup changes under it. Backups wait, so the vault may hold changes for longer."
- **Line 100:**
  > "Vault links: an older version's link is followed only when its text is exactly its own path in the version after it; nothing else in a version is ever followed. Browsing by hand: current_version and the newest version are plain trees; in older versions ls, cat and cp of a file work, find, du and rsync need -L to go into an unchanged folder, cp -a and rsync -a copy forward links as links, cp -aL and rsync -aL also follow your own symlinks, and rsync -a --copy-unsafe-links comes closest (forward links copied as what they name, your links inside the version kept as links, your links that leave it copied as what they point to). reverberator restore gives a faithful copy."

## 14. docs/limitations.md (proposals; each needs the user's OK unless marked approved)
- **Remove (no longer possible):**
  - "A user's link written as its own path's chain link";
  - "A prune cut off on a pool can bring back a file…";
  - "A prune killed or cut by a power loss leaves bumped folder times";
  - "Copy threads auto cannot tell the disks under btrfs or ZFS".
- **Replace "User symlinks past 40 hops…" (approved):**
  > ### Versions more than 40 back cannot be browsed by hand
  > - **Kind:** known limitation.
  > - **What the operator sees:** a path k versions older than the newest passes through up to k forward links, and every symlink in the vault's own path counts as well. Past the kernel's 40 (about 20 while Docker changes mounts), browsing by hand gives "too many levels of symbolic links". restore and history work. The live maximum keep-N is 14.
  > - **Why:** re-pointing links would cost writes on every cycle.
  > - **Revisit when:** a job keeps more than 20 versions and is browsed by hand.
- **Reword "A move that another change of the batch outran is copied":** "losing their chain links" → "a copy instead of a rename".
- **Reword "A move into its own old place is copied whole":** "its files, not links to the older version" → "its files in full".
- **Narrow the setgid entry:** the prune side goes. A backup's records on a pool clone folders too, and only their times are given back.
- **Reword "Size estimates leave out…":** sizes now count files by their sizes plus 4 KiB per folder, and each inode in the newest version that holds it, not du blocks.
- **New, tiny (ask):**
  > ### After a crash, a folder whose row holds no record can keep the backup's time
  > - **What the operator sees:** a crash in the one call between a change inside a folder of the previous version and giving that folder its times back leaves the backup's time on it. The roll-forward restores it from the folder's database row, except when that row holds no record (its vault entry could not be read when it was recorded). A restore of that version then gives that one folder that time. Files and other folders are not affected.
  > - **Why:** keeping the time elsewhere would need a durable write per folder.
  > - **Revisit when:** it is seen.
- **Pool limitation:** written only if the pool cut test shows a residual.

## 15. LESSONS.md draft
```
## 2026-11-0X reverberator 0.55: the newest version is the one real tree, and older versions link forward
- Changed: a backup no longer builds each version as a whole tree of links to the previous one, and a prune no longer hard-links the oldest version's copies into the next one. The newest version is a plain tree; before a backup changes a path of it, it records that path's old state in the version before (folders on the way made real with a link per entry pointing forward, a moved entry by hard links, a folder still forwarded whole by one RENAME_EXCHANGE), handing the tree to the new version's name with one RENAME_EXCHANGE first. A prune renames the oldest away and removes it. A cut backup is rolled forward, never undone; the manifest's commit is the commit point. Change-list sizes count each inode in the newest version holding it. Chain Length and Copy threads have no effect; Keep 1 Complete Backup False reads as True. Backups wait for restores (taken after the restore's prompt, with a gate so restores cannot starve a backup); history has its own lock. Vault layout changed; no going back to 0.54.
- Why we had to change: on the f2fs vault SSD every inode a cycle touches costs a 4 KiB node block; the work job's hourly cycle touched ~650K inodes and wrote 2.7 GiB (~64 GiB/day) to keep 6-9 MiB of changed data, with 2.6M calls. After: ~20-31 MiB and ~5-8K vault writes a cycle.
- Original design was wrong because: a version cost the size of the tree, not of its change; links pointed backward, from the most used version to the one about to be deleted, so every prune rewrote the next version first, with crash machinery (salt, marker, link-back, move tables) to match.
- Lesson: make a version's cost follow what changed: keep the current state as the one real copy, record the old state of only what changes before changing it, point references from older to newer so removing the oldest touches nothing else; record by same path only (hard-link a moved source) so no record needs a path map; kill after every write and check every version against an oracle, readers interleaved with writers too; measure in the units the medium charges (inodes touched), not bytes.
```

---

## Change log (revision 1 → 2)
- **Migration:** materializing is decided. A sizes pass renames every list to R's meaning before any backup (3.4), and the oldest whole version is left as it is.
- **Pools:** P2 only; P1 and its limitation text are dropped. R ships only after the pool cut test, now specified as the build's gate (method in §5). A pool limitation is written only if that test shows a residual.
- **Hop limit:** now an approved limitation. Symlinks in the vault's own path count against the 40.
- **Column 7 False → True:** one log line, 'r' rows copied, and the referenced-V0 walker dropped.
- **Locks, reworked:**
  - a restore locks after its picker and prompt, then re-resolves;
  - a new backup lock gate prevents starvation;
  - the batch polls with `LOCK_NB` and watches GREEN_LIGHT;
  - an unreadable lock postpones the whole backup;
  - lock scope runs from the scan to the commit (3.9).
- **Roll-forward:** why it always commits; that it runs the retention loops counting the tree (3.6); the manifest's commit is the one commit point (3.7).
- **Unmigrated vaults:** the 0.54 scan rules and the pool prune-marker repair run until migration (3.1, 3.2). The contradiction in 3.2 is resolved: R's scan reuses `remove_orphan`.
- **The CLI on an unmigrated vault** follows 0.54 chain links by text, the migration's own rule (3.3).
- **Folder create over an existing folder:** per-entry records as each copy is queued (3.5, Opus 2b). Added to the crash batch, and the old rule now fails the oracle.
- **Folder rows without a record:** a tiny limitation is proposed (3.10).
- **Sizes:** one definition, each inode counted in the newest version holding it (3.11).
- **§1 wording:** Only Sync Attributes in-place changes are named (3.12).
- **Pool hand-over window:** history waits and re-walks (3.13).
- **History recheck:** an acceptance test was built and run, with 0 wrong reads, against 15 starting points with wrong reads without the recheck (3.14).
- **README and limitations:** fixed (lines 7, 13, 20, 51, 64, 69, 97, and the two move entries) (3.15, 3.16).
- **Line counts:** remeasured with `ast`. Keeping the 0.54 parts changes the net to about −450 lines in 0.55 and about −2,400 later (3.17).
- **Browsing:** the copy-out truth is stated; I tested `rsync -a --copy-unsafe-links` and it comes closest. The text now says plainly that links point to the next version, not the current one.
- **Crash tests re-run:** 251/251 single, 500/500 double, 251/251 post-crash, 251/251 power-loss. Both loop images are gone.

## Calls to confirm
1. **Vault layout (API, no downgrade):** the newest version is plain, older versions are forward-linked, there is a new `.reverberator_staging`, and the manifest is schema 3. Links point to the next version, not to the current one; that is what creates the hop limit.
2. **Change-list sizes (API):** a list's size now means what that version alone holds, with each inode counted in the newest version that holds it. A commit renames the previous newest version's list, and the migration renames every list once.
3. **Rule columns (API):** columns 14 and 15 are accepted and have no effect. Column 7 False is read as True (your choice).
4. **Locks (API: two new state files, `job-<name>.backup.lock` and `job-<name>.history.lock`):**
   - a restore takes the job lock only after its picker and prompt, then re-resolves;
   - a waiting backup blocks new restores, so restores cannot starve it;
   - a restore lock that cannot be checked now postpones the **whole backup**, with the FAILED marker after 15 minutes. The marker text ends "; backup postponed".
5. **Roll-forward always commits:** a backup cut after its hand-over always commits its version. This uses one version slot, so one old version may be pruned early. It is your call; I recommend keeping it.
6. **Pushback, keeping the 0.54 code:** your ruling keeps the 0.54 scan rules and the pool prune-marker repair (1,927 lines, mostly `decrement_stepper`) alive until a later release. A cheaper alternative removes them in 0.55: refuse to migrate a 0.54 **pool** vault whose last prune was cut before its flush (no live vault is on a pool), with a FAILED line telling the operator to let 0.54 finish that prune first. I recommend keeping your ruling unless you want the lines gone now.
7. **Limitations:**
   - remove four entries;
   - replace the hop entry (approved; now counts vault-path links);
   - reword the two move entries and the size-estimate entry;
   - narrow the setgid entry;
   - new tiny entry: "a folder whose row holds no record can keep the backup's time after a crash";
   - a pool entry only if P2's test shows a residual.
8. **My calls that changed what gets built:**
   - the whole-job free-space check uses the newest version's size;
   - records are hard links made before the copy is queued, temps stay beside the destination, and staging holds only the daemon's own builds;
   - the tree moves by exchange to the new name, not to a fixed tree name;
   - Only Sync Attributes changes stay in place on the shared inode;
   - history runs lock-free: it re-checks the links it followed, and waits for a running backup when it finds something missing;
   - the CLI reads an unmigrated vault with the migration's text rule;
   - P folder times are restored from rows;
   - a folder move costs one inode write per entry;
   - 'r' rows from 0.54 are copied by the first comparison.
9. **Build order:** locks first; then R and pools P2 as one release, gated by the pool cut test; the 0.54 parts go in a later release.
