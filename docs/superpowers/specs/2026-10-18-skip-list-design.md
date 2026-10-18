# Per-job skip list (gitignore-style excludes)

Date: 2026-10-18  
Status: draft, pending approval  
Scope: `reverberator.py`, `pyproject.toml` / `uv.lock`, sample rule text, `reverb_rule.tsv`, tests

## Intent

Let each job name a skip-list file in the rule TSV. Anything in the monitored tree that matches the file's
gitignore-style patterns is not watched, not copied, and not carried into new versions. The point is to keep caches,
build output and similar churn out of the vault (and off the inotify watch budget) without splitting jobs up.

## Goals

- One optional skip-list file per job, configured in the rule TSV, with a default possible through `#_defaults_#`.
- gitignore pattern semantics, as people already know them.
- Skipped paths never reach the vault through any path that reads the monitored tree: watcher events, the first
  backup, delta generation, recursive folder copies.
- Skipped folders get no inotify watches.
- Adding a pattern for something already backed up drops it from new versions; it lives on in older versions until
  retention prunes them, exactly as if it had been deleted from the source.
- Editing the skip list takes effect on restart, with the vault brought in line with the new patterns.
- Existing rule files (11 columns) keep working with no edits.

## Non-goals

- Live reload of the skip list while running.
- Per-folder `.gitignore`-style files inside the monitored tree; there is one list per job.
- Reading or honouring the monitored tree's own `.gitignore` files.
- Rewriting or pruning older vault versions when patterns change.
- Size-based skipping (a separate, possible later feature).

## Anti-goals (would make this a failure even if it technically works)

- A skip-list problem silently turning into "back up everything": a large cache flooding the vault makes the size
  limit prune real history.
- Upgrading reverberator without using the feature costs a full-tree comparison or changes any behaviour.
- A skipped path being *deleted* from the vault in a way that also removes it from older versions.
- Old rule files failing to parse, or losing the new column's value on the parse-and-write-back round trip.

## Decisions

Made by the user:

- **Syntax:** gitignore style, implemented with the `pathspec` library (`GitIgnoreSpec`), added as a dependency.
- **Already backed-up entries that become skipped:** dropped from new versions (treated like a delete).
- **When edits take effect:** on restart only.
- **Missing or unreadable skip-list file:** that job does not back up, an error is logged, other jobs run.
- **Late mounts:** the list is loaded once the job's filesystems are ready (the monitor and vault fs signature
  flags it already waits on), not in `parse_rules`, so a list on a disk that mounts after boot works. If the file is
  still missing or unreadable at that point, that job stops with an error. No watches are added, no events are
  queued and no backup runs for the job until its list has loaded.
- **Going from patterns to no patterns needs an explicit `none`:** if the vault's recorded state was made with a
  non-empty pattern set and the job now resolves to no patterns (blank cell, a `#_defaults_#` path that was removed,
  or a file that is empty or only comments), the job stops with an error telling the user to set the cell to `none`
  to back up everything. `none` in the cell is accepted and triggers the usual full comparison. A job that has never
  recorded patterns may have an empty list freely. This protects history: un-skipping a large cache by accident
  would otherwise make the size limit prune old versions before anything is copied.

Made by Claude while designing (flagged so they can be checked):

- **Column placement:** new column `Skip List File` (field `skip_list_file`) appended after
  `Vault File System Signature`, so existing columns keep their positions.
- **Empty cell** means no skip list. `auto` also means no skip list; `none` means no skip list and is the explicit
  form the rule above asks for. The `#_defaults_#` row may hold a path; TSVZ fills blank cells from it, so a job then
  needs an explicit `none` to opt out.
- **Relative paths** in the column resolve against the rule file's folder; absolute paths are used as is.
- **Header upgrade:** when `parse_rules` reads a rule file whose header lacks the new column, it rewrites the header
  line (and the sample comment rows, if they are the stock ones) to add it, keeping every other line byte for byte.
  Verified: TSVZ 3.39 with `strict=False` reads an 11-column file without padding rows, and truncates a 12-column
  row appended to an 11-column file back to 11 on read, so the new value is lost unless the header is upgraded first.
- **An unparseable pattern** is treated like an unreadable file: the job is not started.
- **Moves across the boundary:** moving from a backed-up path into a skipped one is a delete of the source; moving
  from a skipped path into a backed-up one is a create at the destination (a folder create copies its contents,
  filtered). A move with both ends skipped is dropped.
- **Folder moves with location-dependent patterns:** when a folder moves between two backed-up locations and the
  spec has patterns whose match depends on location (anchored, or containing a `/` other than a trailing one, e.g.
  `/scratch/`, `projects/*/build/`), the moved subtree is re-checked against the patterns at its new location:
  descendants that became skipped are dropped from the new version and lose their watches; descendants that became
  backed up get watches and are copied. Specs with only location-free patterns (`*.tmp`, `node_modules/`) skip the
  re-check, as a move cannot change their result. This keeps the vault exact without waiting for a full comparison.
- **Change detection:** reverberator records a fingerprint of the job's effective patterns (normalised pattern
  text, not file mtime) with the vault's latest committed state. On startup, if the current fingerprint differs
  from the recorded one, the job ignores its saved pending transactions and does a full comparison (delta
  generation) against the latest version. No recorded fingerprint and no patterns counts as unchanged, so upgrading
  without using the feature changes nothing; no recorded fingerprint with patterns counts as changed.
- **Logging:** dropped events and pruned folders are logged only with `--verbose`; the pattern count and the
  skip-list path are logged once per job at startup.

## Matching rules

- Patterns match paths relative to the monitored folder, with folders carrying a trailing `/` (the convention
  `iter_tree_entries` already uses), so `build/` matches only folders.
- Standard gitignore semantics, including `!` negation and the gitignore rule that a file cannot be re-included
  when a parent folder is excluded. Pruning the walk at a skipped folder is therefore consistent with git.
- Symlinks are matched as files, including symlinks to folders (`iter_tree_entries` already yields those as files).
- The monitored root itself is never skipped.
- Blank lines and `#` comments follow gitignore rules.

## Where it applies

Every place the **monitored tree** is read. None of the places the **vault** is read.

Monitored tree (apply the skip list):

| Place | Today | With skip list |
|---|---|---|
| Initial watches, `initializeFolderWatchers` / `get_all_folders` (`reverberator.py:1276`, `:1339`) | every folder | skipped folders and everything under them get no watch |
| Watcher events, `watchFolder` (`:1049`) | every event queued | events for skipped paths dropped; create/move-in of a folder adds watches only for non-skipped folders; moves across the boundary converted as above; a folder moved into a skipped location has its watches (and its descendants') removed; folder moves re-checked when patterns are location-dependent (see Decisions) |
| Startup resume check, `get_monitor_path_most_recent_change_time` (`:1422`) | walks everything | skips skipped paths, so a busy cache does not defeat resuming pending transactions |
| First backup, complete (`do_backup`, `:2083`) and referenced (`manifest.rebuild(..., tree_path=monitor_path)`, `:2099`) | whole tree | filtered walk |
| Delta generation, `delta_generate_backup_entries` (`:3107`) | whole tree | filtered walk; tracked entries that are now skipped are never seen, so the existing "unseen means deleted" pass drops them from the new version |
| Recursive folder copy, `copy_path` in `do_reverb_backup` (`:3491`) | whole subtree | filtered walk |
| Pending transactions replayed at startup (`load_pending_transactions_for_resume`) | replayed | only replayed when the fingerprint is unchanged (see Decisions), so they were already filtered when queued |

Vault (leave as is): `decrement_stepper` walking a version, `manifest.rebuild(version_path)` listing a version,
`read_vault_record`, `do_referenced_copy` (driven by the manifest), retention.

## Constraints

- Python floor in `pyproject.toml` is `>=3.7`; pick a `pathspec` version compatible with what the project actually
  supports, and raise the floor in `pyproject.toml` if that is needed.
- `pathspec` is not installed in the project venv today; add it to `pyproject.toml` dependencies and `uv.lock`.
- Matching runs on the watcher's hot path and on walks of 500k+ entries: compile the spec once per job, and avoid
  re-matching every descendant of a folder that was already pruned.
- Keep the existing crash-safety rules: the fingerprint must only describe a state that has committed (a crash
  between recording it and committing must not let a later start skip the full comparison).
- The recorded state must tell "made with no patterns" apart from "made with patterns", for the explicit-`none` rule.
- Startup ordering: today `main()` decides whether to replay pending transactions (`load_pending_transactions_for_resume`,
  `:566`) before the job's threads start. With the list loaded after the filesystems are ready, that decision has to
  move after the list loads (fingerprint check) and after the job's watches are in place, so changes made while the
  job waited for a late mount are not missed by a replay.
- Code style follows the file: tabs, the existing naming mix, comment density, doctests on small pure helpers.

## Testing expectations

- Unit: pattern loading (missing file, unreadable file, bad pattern, comments, negation, folder-only, anchored),
  relative-path resolution, header upgrade of an 11-column rule file (rows and comments preserved, new value
  survives the write-back round trip), `#_defaults_#` filling and `none` opting out.
- Delta generation: a newly skipped file and a newly skipped folder are absent from the new version and still
  present in the previous one; a newly un-skipped file is copied.
- Watcher (inotify tests): no watch on skipped folders; events in skipped folders not queued; moves across the
  boundary in both directions; folder created inside a skipped folder gets no watch.
- Watcher: moving a folder between backed-up locations re-checks its subtree under a location-dependent pattern
  (both directions), and does not re-walk under location-free patterns.
- Startup: fingerprint unchanged keeps pending transactions; changed fingerprint discards them and runs a full
  comparison; upgrade with no skip list does not force a full comparison.
- Startup: recorded patterns plus a blank cell, a removed default, or an empty file stops the job with an error;
  `none` is accepted and runs a full comparison; a never-patterned job with an empty list starts normally.
- Late mount: a list that appears when the job's filesystem mounts is loaded and used; one still missing then stops
  the job with an error while other jobs keep running.
- Existing test suite still passes.

## Left to the builder

- Exact data structure for the compiled spec and how it is passed to the watcher/backuper threads (rule namedtuple
  field, job context object, or similar).
- Where the fingerprint is stored (the manifest's `meta` table is the natural home, as it already commits with the
  version it describes), and how the job's threads coordinate loading the list once and sharing it.
- How a skip-list failure stops just that job. It must not clear `GREEN_LIGHT` (which today stops every job); the
  job's watcher and backuper exit and the other jobs carry on. Making other per-job failures behave the same way is
  the separate reliability-fixes design that follows this one.
- How the walker prunes (a predicate argument on `iter_tree_entries`, a wrapper, or similar).
- Version bump (next is 0.37) and README / sample rule wording for the new column.
