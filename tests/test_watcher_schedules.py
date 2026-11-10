'''
Bounded schedule enumeration through the real watcher on real inotify. A shape's steps run inside the watcher's own thread, step
i at the t_i-th visit of a hook (before a read, before each event is handled, before and after each add_watch, at each entry of a
walk), for vectors t of visits that never go down. That reaches orders free scheduling almost never gives: a rename landing
between a new folder's watch and its listing, or between a walk and the read of what it raced. The fuzz and the take points never
found the two that a second review found this way in two minutes.

After the steps, everything settles, a marker goes into every folder, and the newest version must equal the tree: a folder that
left every version, a change a discard threw away, or a folder with no working watch shows. The watch map must be the tree's
too, both ways: each watch held is the one add_watch gives for its path, and each folder has one.

The first step runs at the first visit. The suite runs every vector up to H visits of a short shape, and a deterministic sample
of SAMPLE out of them for a longer one. REVERB_WATCH_SCHED_H, REVERB_WATCH_SCHED_SAMPLE (0 for all) and REVERB_WATCH_SCHED_SHAPES (names, by commas) widen it.
'''
import itertools
import os
import random
import shutil
import time

import pytest

import reverberator as rv
from tests.harness import wait_until, watch_map_errors
from tests.test_moves_into_new_folders import live_view, session, version_view  # session is the fixture

pytestmark = pytest.mark.inotify

# the visits a shape's steps may land at: all of them for a short shape, where the window is a visit or two wide
H = {'moved_into_a_folder_from_outside': 12, 'poke_between': 12, 'cpp_between': 12, 'in_then_poke_mv': 12, 'twice_in_new': 12, 'twice_in_new_sub': 12,
	# review 5's bounds for the shapes of five steps or more: 12 visits
	'out_made_deep_into_new': 12, 'root_ahead': 12, 'c1_collision': 12, 'c2_unwatched_old': 12,
	'sub_back_parent_into_new': 12, 'out_parent_deleted_back': 12, 'found_out': 12, 'back_then_sub_out': 12,
	'sub_of_found_out': 12, 'q3_sub_out': 12, 'new_into_new_then_sub': 12, 'new_into_new_then_sub2': 12,
	'made_at_pending_out_parent_deleted': 12, 'made_at_pending_out_moved': 12, 'cycle_guard': 12, 'cycle_guard_root': 12, 'q3_deep_out': 12,
	'root_put_into_itself_touched': 12, 'back_home_via_new': 12, 'back_home_via_new_sub': 12, 'back_home_via_outside': 12,
	'walk_ahead_taken': 12, 'walk_ahead_taken_sub': 12, 'back_home_under_new': 12, 'c2_then_moved': 12, 'c2_then_into_old': 12,
	'land_ahead_taken': 12,
	# round 22's build: the shapes of the step back's rules
	'nested_out_ancestor': 12, 'moved_sub_out_before_walk': 12, 'back_into_new_then_out': 12, 'pairing_walk_under_new': 12,
	'renamed_in_new_then_out': 12, 'renamed_in_new_then_out_sub': 12, 'out_of_new_then_out': 12, 'out_of_new_then_out_sub': 12}
H_DEFAULT = 16
SAMPLE = int(os.environ.get('REVERB_WATCH_SCHED_SAMPLE', '100'))
BIG = 'p' * 200000
TREE = {'big/a': BIG, 'big/sub/b': BIG, 'big/sub/deep/x': 'x' * 100, 'next/z': 'z' * 100, 'next2/sub/z': 'z' * 100, 'f.txt': 'f' * 300, 'g.txt': 'g' * 300,
	'other/o': 'o', 'keep/k': 'k'}
SHAPES = {
	# a folder made at the old path of the folder the walk of n found, and moved on before its own walk (R1)
	'made_at_a_found_folders_old_path': [('mkdir', 'n'), ('mv', 'big', 'n/big'), ('mv', 'next', 'big'), ('mkdir', 'big/new'), ('mv', 'big/new', 'big/sub'),
		('mv', 'big/sub', 'other/sub')],
	# the same at a top path whose move-out was read before the walk (R1)
	'made_at_an_old_path_read_out_first': [('mv', 'big', '{outside}/big'), ('mkdir', 'n'), ('mv', '{outside}/big', 'n/big'), ('mkdir', 'big'),
		('mv', 'big', 'other/e')],
	# a folder moved into one that came in from outside, while that one is walked, then changed so that only its event shows it (R2)
	'moved_into_a_folder_from_outside': [('mv', '{outside}/d', 'm'), ('mv', 'big', 'm/big'), ('poke', 'm/big/a')],
	# a chain through a new folder made at a found folder's place, as fuzz seed 2854 had it
	'chain_through_a_new_folder': [('mkdir', 'A'), ('mv', 'big', 'A/n2'), ('mkdir', 'M'), ('mv', 'A', 'M/n2'), ('poke', 'M/n2/n2/a')],
	# a change that only its event shows, made between mkdir n and the rename that carries the folder into it: the rename can land
	# right after the new folder's watch, before the walk lists it, and then the walk got there first (the third review's F3)
	'poke_between': [('mkdir', 'n'), ('poke', 'big/a'), ('mv', 'big', 'n/big')],
	# the same as cp -p of a same-size release file does it: other bytes, the same size and mtime
	'cpp_between': [('mkdir', 'n'), ('cpp', 'big/sub/b'), ('mv', 'big', 'n/big')],
	# the same into a folder that came in from outside
	'in_then_poke_mv': [('mv', '{outside}/d', 'm'), ('poke', 'big/a'), ('mv', 'big', 'm/big')],
	# moved on into another new folder, a folder made at its old place, and a change that only its event shows
	'found_twice': [('mkdir', 'n'), ('mv', 'big', 'n/big'), ('mkdir', 'm'), ('mv', 'n/big', 'm/big'), ('mv', 'next', 'big'), ('poke', 'm/big/sub/b')],
	# renamed again inside the new folder: the walk can list the folder at its last name and re-point its own watch there before
	# the first rename's events are read, so the change's event is discarded and the first move must not be kept (the fourth review's F1)
	'twice_in_new': [('mkdir', 'n'), ('poke', 'big/a'), ('mv', 'big', 'n/big'), ('mv', 'n/big', 'n/c')],
	# the same in a subfolder of the new folder
	'twice_in_new_sub': [('mkdir', 'n'), ('mkdir', 'n/s'), ('poke', 'big/a'), ('mv', 'big', 'n/s/big'), ('mv', 'n/s/big', 'n/s/c')],
	# a folder leaves the tree, a folder made at its old path expires its move-out, and its subfolder comes back into a new folder
	# that a walk listed: the subfolder's watch stays where the walk found it (fuzz seed 647, through a skipped folder)
	'out_made_sub_into_new': [('mkdir', 'n'), ('mv', 'big', '{outside}/big'), ('mkdir', 'big'), ('mv', '{outside}/big/sub', 'n/sub'), ('poke', 'n/sub/b')],
	# the same one level deeper, and with no folder made at the old path
	'out_made_deep_into_new': [('mkdir', 'n'), ('mv', 'big', '{outside}/big'), ('mkdir', 'big'), ('mv', '{outside}/big/sub/deep', 'n/deep'), ('write', 'n/deep/w', 'w')],
	'out_sub_into_new': [('mkdir', 'n'), ('mv', 'big', '{outside}/big'), ('mv', '{outside}/big/sub', 'n/sub'), ('poke', 'n/sub/b')],
	'out_deep_into_new': [('mkdir', 'n'), ('mv', 'big', '{outside}/big'), ('mv', '{outside}/big/sub/deep', 'n/deep'), ('write', 'n/deep/w', 'w')],
	# a folder renamed twice into a folder whose move is being walked: the walk can list it at its last name before either rename
	# is read, and a change that only its event shows comes at the new place ahead of the move (F2)
	'twice_old_race': [('mv', 'other', 'o2'), ('poke', 'big/a'), ('mv', 'big', 'o2/x'), ('mv', 'o2/x', 'o2/big')],
	'twice_old_race_sub': [('mv', 'other', 'o2'), ('poke', 'big/sub/b'), ('mv', 'big', 'o2/x'), ('mv', 'o2/x', 'o2/big')],
	# the same at a walk's root: the place a create names holds, by its walk, the folder whose renames are still unread
	'root_ahead': [('mv', 'other', 'o2'), ('poke', 'big/a'), ('mkdir', 'o2/x'), ('rmtree', 'o2/x'), ('mv', 'big', 'o2/x'), ('mv', 'o2/x', 'o2/big')],
	# a walk of a renamed folder lists a folder made where its subfolder left, before that move is read (two watches, one path)
	'c1_collision': [('mv', 'big', 'b2'), ('mv', 'b2/sub', 'b2/s2'), ('mkdir', 'b2/sub'), ('mkdir', 'b2/sub/deep'), ('write', 'b2/sub/deep/w', 'w'), ('poke', 'b2/s2/b')],
	# the same where the folder that left had no watch yet: its move-out names the place of the new folder's watch
	'c2_unwatched_old': [('mv', 'other', 'o2'), ('mkdir', 'o2/u'), ('mv', 'o2/u', 'o2/u2'), ('mkdir', 'o2/u'), ('write', 'o2/u/f', 'x'), ('write', 'o2/u2/g', 'y')],
	# a subfolder taken back from a folder that left the tree, then changed so that only its event shows it
	'out_back_sub': [('mv', 'big', '{outside}/big'), ('mv', '{outside}/big/sub', 'sub2'), ('poke', 'sub2/b')],
	# two folders swapped by one rename (RENAME_EXCHANGE), then changed so that only the events show it
	'exchange': [('exchange', 'big', 'other'), ('poke', 'other/a'), ('write', 'big/new', 'n')],
	'exchange_twice': [('exchange', 'big', 'other'), ('exchange', 'other/sub', 'next2/sub'), ('poke', 'next2/sub/b'), ('write', 'other/sub/new', 'n')],
	# a folder renamed over an empty folder (the empty one is replaced), then renamed on and changed
	'over_empty': [('mkdir', 'e'), ('mv', 'big', 'e'), ('mv', 'e', 'f'), ('poke', 'f/a')],
	# a change in the folder between the create at the place and the move there, which only its event shows: the root put's
	# copy holds it (without the copy the move carries the old bytes over it; 0.55.1 discards the change in newDirWDs)
	'over_empty_poke_between': [('mkdir', 'e'), ('poke', 'big/a'), ('mv', 'big', 'e')],
	'gone_place_poke_between': [('mkdir', 'other/x'), ('rmtree', 'other/x'), ('poke', 'big/a'), ('mv', 'big', 'other/x')],
	# a folder renamed between its walk's open and its watch (fuzz seed 4284): the watch goes only where the folder is once
	# it exists, and a walk's root is opened from its parent's folder
	'open_renamed_into_new': [('mkdir', 'other/m'), ('mkdir', 'n'), ('mv', 'other/m', 'n/m'), ('mkdir', 'n/m/s')],
	'open_renamed_child_into_new': [('mkdir', 'other/m/k'), ('mkdir', 'n'), ('mv', 'other/m/k', 'n/k'), ('mkdir', 'n/k/s')],
	'stale_root_path': [('mkdir', 'other/x'), ('mv', 'other', 'o2'), ('mkdir', 'other/x')],
	# a create's walk finds there a folder whose move in is still queued, after the created folder's own move-out (fuzz seed
	# 2509): that move-out is not the found folder's, or the found folder goes into itself (round 22's first design grew
	# without bound there); 0.55.1 loses the poke in most orders, as the move-out took the found folder's watch with it
	'root_put_into_itself': [('mkdir', 'n'), ('mv', 'n', 'big/n'), ('mv', 'big', 'n')],
	'root_put_into_itself_poke': [('mkdir', 'n'), ('mv', 'n', 'big/n'), ('mv', 'big', 'n'), ('poke', 'n/a')],
	'root_put_into_itself_touched': [('mkdir', 'n'), ('mkdir', 'big/x'), ('mv', 'n', 'big/n'), ('mv', 'big', 'n'), ('poke', 'n/a')],
	'root_put_into_sub': [('mkdir', 'n'), ('mv', 'n', 'big/sub/n'), ('mv', 'big', 'n'), ('poke', 'n/sub/b')],
	'root_put_wrong_mover': [('mkdir', 'n'), ('mv', 'n', 'other/n'), ('mv', 'big', 'n'), ('poke', 'n/a')],
	# a folder leaves the tree and comes back to its place after its parent was renamed, before its move-out expires (fuzz seed 929)
	'sub_back_parent_renamed': [('mv', 'big/sub', '{outside}/sub'), ('mv', 'big', 'b2'), ('mv', '{outside}/sub', 'b2/sub'), ('poke', 'b2/sub/b')],
	'sub_back_parent_into_new': [('mv', 'big/sub', '{outside}/sub'), ('mkdir', 'n'), ('mv', 'big', 'n/big'), ('mv', '{outside}/sub', 'n/big/sub'), ('poke', 'n/big/sub/b')],
	# a folder moved out, its old parent deleted before the move-out expires, then the folder back in with its new parent, which
	# has no MOVE_SELF of its own (fuzz seed 5837)
	'out_parent_deleted_back': [('mv', 'big/sub', '{outside}/d/sub'), ('rmtree', 'big'), ('mkdir', 'n'), ('mv', '{outside}/d', 'n/d'), ('poke', 'n/d/sub/b')],
	# a folder moved out of the tree from a new folder: its watch, at the old place, must go (F3; 0.55.1 keeps one in some orders)
	'found_out': [('mkdir', 'n'), ('mv', 'big', 'n/big'), ('mv', 'n/big', '{outside}/big'), ('mkdir', 'big'), ('write', 'big/w', 'w')],
	'back_then_sub_out': [('mkdir', 'n'), ('mv', 'big', 'n/big'), ('mv', 'n/big', 'big'), ('mv', 'big/sub', '{outside}/sub'), ('poke', 'big/a')],
	'sub_of_found_out': [('mkdir', 'n'), ('mv', 'big', 'n/big'), ('mv', 'n/big/sub', '{outside}/sub'), ('mkdir', 'n/big/sub'), ('mv', 'next', 'n/big/sub/z')],
	'q3_sub_out': [('mkdir', 'n'), ('mv', 'big', 'n/big'), ('mv', 'n/big/sub', '{outside}/sub'), ('rm', '{outside}/sub/b'), ('mkdir', 'big'), ('mkdir', 'big/sub'),
		('write', 'big/sub/b', 'nb')],
	# a folder made in the batch moved into another new folder, then a folder made in it there (cut down from fuzz seed 4284's
	# round 6), and the same with a file moved in and out
	'new_into_new_then_sub': [('mkdir', 'other/m'), ('mkdir', 'other/m/k'), ('mkdir', 'n'), ('mv', 'other/m', 'n/m'), ('mkdir', 'n/m/s'), ('write', 'n/m/s/w', 'w')],
	'new_into_new_then_sub2': [('mkdir', 'other/m'), ('mv', 'f.txt', 'other/m/f'), ('mkdir', 'n'), ('mv', 'other/m', 'n/m'), ('mkdir', 'n/m/s'), ('mv', 'n/m/f', 'keep/f')],
	# a folder made at the place of a folder whose move-out is pending, under a new path (its parent renamed), then moved out
	# too: its move-out takes its own watch, not the first folder's, so its watch does not stay in the tree
	'made_at_pending_out_parent_deleted': [('mv', 'big/sub', '{outside}/sub'), ('mv', 'big', 'b2'), ('mkdir', 'b2/sub'), ('mv', 'b2/sub', '{outside}/sub2'),
		('rmtree', 'b2'), ('write', '{outside}/sub2/w', 'w')],
	'made_at_pending_out_moved': [('mv', 'big/sub', '{outside}/sub'), ('mv', 'big', 'b2'), ('mkdir', 'b2/sub'), ('mv', 'b2/sub', '{outside}/sub2'),
		('mkdir', 'b2/sub'), ('write', 'b2/sub/w', 'w')],
	# a parent held below the folder moved into it: s's watch came through its open folder after its rename into n, which no
	# event said (no MOVE_SELF), so a map of each watch's place still holds s in big when big moves into s
	'cycle_guard': [('mkdir', 'big/s'), ('mkdir', 'n'), ('mv', 'big/s', 'n/s'), ('mv', 'big', 'n/s/big'), ('write', 'n/s/big/w', 'w')],
	# the root put of a create read while the tree holds its parent under the put folder, and another folder at the put
	# folder's old path holds the parent at the same path: the parent's path checks out, and the put would close a cycle
	'cycle_guard_root': [('mkdir', 'big/sub/e'), ('mv', 'big', 'b0'), ('mkdir', 'big'), ('mv', 'b0/sub', 'big/sub'), ('mv', 'b0', 'big/sub/e')],
	'q3_deep_out': [('mkdir', 'n'), ('mv', 'big/sub', 'n/sub'), ('mv', 'n/sub/deep', '{outside}/deep'), ('write', '{outside}/deep/y', 'y'), ('mkdir', 'big/sub'),
		('mkdir', 'big/sub/deep'), ('write', 'big/sub/deep/y', 'ny')],
	# a folder moved into a new folder and back to the very place it left, its parent renamed in between (fuzz seed 14124):
	# its move-out from there is not the last move of it read when it expires, so its watches stay; 0.55.1 loses the write
	# in most orders, and so did revision 1 before the move-out had to be the folder's last one read
	'back_home_via_new': [('mkdir', 'big/n0'), ('mv', 'big/sub/deep', 'big/n0/deep'), ('mv', 'big', 'other/t'), ('mv', 'other/t/n0/deep', 'other/t/sub/deep'),
		('write', 'other/t/sub/deep/w', 'w')],
	'back_home_via_new_sub': [('mkdir', 'big/n0'), ('mv', 'big/sub', 'big/n0/sub'), ('mv', 'big', 'other/t'), ('mv', 'other/t/n0/sub', 'other/t/sub'),
		('write', 'other/t/sub/deep/w', 'w')],
	'back_home_via_outside': [('mv', 'big/sub/deep', '{outside}/deep'), ('mv', '{outside}/deep', 'next/deep'), ('mv', 'big', 'b2'), ('mv', 'next/deep', 'b2/sub/deep'),
		('write', 'b2/sub/deep/w', 'w')],
	# a walk of a new folder finds an old folder moved into it, and in that one a folder made where another left, before
	# that one's move-out is read (fuzz seed 12812): the move-out names the found folder's watch, which had no MOVE_SELF
	# after it, so its expiry leaves that watch alone
	'walk_ahead_taken': [('mkdir', 'big/n'), ('mkdir', 'm'), ('mv', 'big/n', 'm/n'), ('mkdir', 'big/n'), ('mv', 'big', 'm/n/big'), ('write', 'm/n/big/n/w', 'w')],
	'walk_ahead_taken_sub': [('mkdir', 'big/sub/n'), ('mkdir', 'm'), ('mv', 'big/sub/n', 'm/n'), ('mkdir', 'big/sub/n'), ('mv', 'big', 'm/n/big'),
		('write', 'm/n/big/sub/n/w', 'w')],
	# a folder back at its place from outside while its parent is in a folder made in the batch and a higher one moved into
	# another (fuzz seed 12831, which 0.55.1 fails too): its move-in's walk runs at a stale path, and the walk of the other
	# new folder, which meets the folder at its place, says it came back; 0.55.1 loses it in 179 of 1,000 sampled orders
	'back_home_under_new': [('mv', 'big/sub/deep', '{outside}/deep'), ('mkdir', 'm'), ('mkdir', 'big/n'), ('mv', 'big/sub', 'big/n/sub'),
		('mv', '{outside}/deep', 'big/n/sub/deep'), ('mv', 'big', 'm/big')],
	# a move-out names the watch a walk gave a folder at its place before that folder's arrival was read, and its move-in
	# lands that watch where the mover went: no MOVE_SELF of the watch comes before the next event in either folder of the
	# move, so it goes back. c2_unwatched_old's root put, then the folder moved on or into the first one; and
	# fuzz seed 19006's route, which 0.55.1 loses in 225 of 1,000 sampled orders
	'c2_then_moved': [('mv', 'other', 'o2'), ('mkdir', 'o2/u'), ('mv', 'o2/u', 'o2/u2'), ('mkdir', 'o2/u'), ('mv', 'o2/u', 'o2/u3'), ('write', 'o2/u3/f', 'x'),
		('write', 'o2/u2/g', 'y')],
	'c2_then_into_old': [('mv', 'other', 'o2'), ('mkdir', 'o2/u'), ('mv', 'o2/u', 'o2/u2'), ('mkdir', 'o2/u'), ('mv', 'o2/u', 'o2/u2/u'), ('write', 'o2/u2/u/f', 'x')],
	'land_ahead_taken': [('mkdir', 'big/n'), ('mv', 'big/n', 'other/n'), ('mkdir', 'big/n'), ('mkdir', 'm'), ('mv', 'big/n', 'm/n'), ('write', 'm/n/w', 'w')],
	# a folder moved out of the tree, then its old parent renamed and another folder moved onto its place there: its watch,
	# held by its own move-out still, must not report a rename outside the tree as one inside the other folder (a count of
	# the move-outs that hold a watch, as one would clear it at the parent's pairing; the step-back review's finding 1)
	'nested_out_ancestor': [('mv', 'big/sub', '{outside}/sub'), ('mv', 'big', 'other/b2'), ('mv', 'next2/sub', 'other/b2/sub'),
		('mv', '{outside}/sub/b', '{outside}/sub/z'), ('poke', 'other/b2/sub/z')],
	# a subfolder of a folder moved into a new folder leaves the tree before the walk reaches it (rule 1: the watches the
	# move-in moved join newDirWDs, where the subfolder's move-out finds its watch)
	'moved_sub_out_before_walk': [('mkdir', 'n'), ('mv', 'big', 'n/big'), ('mv', 'n/big/sub', '{outside}/sub'), ('mv', 'next2/sub', 'n/big/sub'),
		('write', '{outside}/sub/w', 'w')],
	# a folder back from outside into a new folder, put in place there by a settle, then out again (rule 2: the settle's
	# walk passes newDirWDs; 0.55.1 leaves the stale watch too)
	'back_into_new_then_out': [('mv', 'big', '{outside}/big'), ('mkdir', 'n'), ('mv', '{outside}/big', 'n/big'), ('mkdir', 'big'), ('mv', 'n/big', '{outside}/b2'),
		('mv', 'next2/sub', 'n/big'), ('write', '{outside}/b2/w', 'w')],
	# a folder made in a new folder whose parent is renamed before its create is handled, then moved out of the tree (rule 3:
	# a watch any walk adds below a folder of newDirWDs joins it)
	'pairing_walk_under_new': [('mkdir', 'big/n'), ('mkdir', 'big/n/s'), ('mv', 'big', 'b2'), ('mv', 'b2/n/s', '{outside}/s'), ('mv', 'next2/sub', 'b2/n/s'),
		('write', '{outside}/s/w', 'w')],
	# renamed in a new folder, then out of the tree before the first move-in's walk (the same-read skip's fallback)
	'renamed_in_new_then_out': [('mkdir', 'n'), ('mkdir', 'n/d'), ('mv', 'n/d', 'n/e'), ('mv', 'n/e', '{outside}/e'), ('mkdir', 'n/d'), ('write', '{outside}/e/w', 'w')],
	'renamed_in_new_then_out_sub': [('mkdir', 'n'), ('mkdir', 'n/d/s'), ('mv', 'n/d', 'n/e'), ('mv', 'n/e', '{outside}/e'), ('mkdir', 'n/d/s'),
		('write', '{outside}/e/s/w', 'w')],
	# out of a new folder into the tree, then out of the tree before the settle: the walk found its watch where the events
	# never put it, so its move-out matched none, and the settle's probe finds it at neither path (0.55.1 leaves it too)
	'out_of_new_then_out': [('mkdir', 'n'), ('mkdir', 'n/d'), ('mv', 'n/d', 'other/x'), ('mv', 'other/x', '{outside}/x'), ('mkdir', 'n/d'),
		('write', '{outside}/x/w', 'w')],
	'out_of_new_then_out_sub': [('mkdir', 'n'), ('mkdir', 'n/d/s'), ('mv', 'n/d', 'other/x'), ('mv', 'other/x', '{outside}/x'), ('mkdir', 'n/d/s'),
		('write', '{outside}/x/s/w', 'w')],
	# the same, out of the tree as the move-in's walk adds its watch, before the walk lists it: what it holds was never
	# found, and leaves with it
	'renamed_in_new_out_early': [('mkdir', 'n'), ('mkdir', 'n/d/s'), ('mv', 'n/d', 'n/e'), ('mv', 'n/e', '{outside}/e')],
	'out_of_new_out_early': [('mkdir', 'n'), ('mkdir', 'n/d/s'), ('mv', 'n/d', 'other/x'), ('mv', 'other/x', '{outside}/x')],
	# a swap by one rename, then one of the two renamed: only the first path before finds the other's watch
	'exchange_then_rename': [('exchange', 'big', 'other'), ('mv', 'big', 'b3'), ('poke', 'other/a'), ('write', 'b3/w', 'w')],
	# two swaps through one folder: a watch is at neither of its own paths, only at one another watch held
	'exchange_chain': [('exchange', 'big', 'other'), ('exchange', 'big', 'next'), ('poke', 'other/a'), ('write', 'next/w', 'w')],
	# a folder moved out of the tree, and a symlink to the outside made where its parent was: a probe through the link finds
	# the folder's watch, which must not count
	'out_then_link': [('mv', 'next2/sub', '{outside}/sub'), ('rmtree', 'next2'), ('symlink', '{outside}', 'next2'), ('write', '{outside}/sub/w', 'w')],
	# back from outside under a new name, changed so that only its event shows it, with a take between or not: the settle's
	# copy of a found folder is left to the create that noted it only when no take came between
	'back_as_new_name': [('mv', 'big', '{outside}/big'), ('mv', '{outside}/big', 'big2'), ('poke', 'big2/a')],
	'back_as_new_name_take': [('mv', 'big', '{outside}/big'), ('mv', '{outside}/big', 'big2'), ('take',), ('poke', 'big2/a')],
}
NAMES = [name for name in os.environ.get('REVERB_WATCH_SCHED_SHAPES', ','.join(SHAPES)).split(',') if name]


def vectors(name):
	# the first step at the first visit: before it the watcher only reads an idle tree, so a later start is the same schedule
	steps = len(SHAPES[name])
	bound = int(os.environ.get('REVERB_WATCH_SCHED_H', H.get(name, H_DEFAULT)))
	every = [(0, *rest) for rest in itertools.combinations_with_replacement(range(bound), steps - 1)]
	return every if not SAMPLE or len(every) <= SAMPLE else sorted(random.Random(name).sample(every, SAMPLE))


# two orders of cycle_guard_root that the round 22 tree design pinned for its cycle guard: run whatever the sample
GUARDED = {('cycle_guard_root', (0, 0, 0, 0, 0)), ('cycle_guard_root', (0, 2, 2, 3, 3))}
CASES = [(name, vector) for name in NAMES for vector in vectors(name)]
CASES += sorted(case for case in GUARDED if case[0] in NAMES and case not in CASES)


def folders_of(root):
	return [os.path.relpath(os.path.join(base, name), root) for base, names, _ in os.walk(root) for name in names]


@pytest.fixture
def folders_removed(tmp_path):
	'''Asked for before session, so torn down after its watcher stopped: thousands of schedules would leave millions of inodes.'''
	yield
	shutil.rmtree(tmp_path, ignore_errors=True)


@pytest.mark.parametrize('name,vector', CASES, ids=[f'{name}-{"_".join(map(str, vector))}' for name, vector in CASES])
def test_a_schedule_ends_as_the_tree(folders_removed, session, job, tmp_path, monkeypatch, name, vector):
	outside = tmp_path / 'outside'
	os.makedirs(outside / 'd' / 's')
	(outside / 'd' / 'x').write_text('x')
	(outside / 'd' / 's' / 'y').write_text('y')
	steps = [tuple(arg.replace('{outside}', str(outside)) for arg in step) for step in SHAPES[name]]
	maps = []
	real_init = rv.initializeFolderWatchers
	def init(inotify_obj, monitor_path, wdDic, *args, **kwargs):
		# the latest watch's map: an overflow starts a new watch
		if not maps or maps[-1][1] is not wdDic:
			maps.append((inotify_obj, wdDic))
		return real_init(inotify_obj, monitor_path, wdDic, *args, **kwargs)
	monkeypatch.setattr(rv, 'initializeFolderWatchers', init)
	one = session(TREE)
	state = {'visits': 0, 'done': 0, 'armed': False, 'inside': False}
	log = []
	def visit(where):
		if not state['armed'] or state['inside']:
			return
		state['inside'] = True
		try:
			at = state['visits']
			state['visits'] += 1
			while state['done'] < len(steps) and vector[state['done']] <= at:
				step = steps[state['done']]
				failed = None
				try:
					one.apply(step)
				except BlockingIOError:
					# a take while the watcher holds the queue, which the backuper cannot take then: at the next visit
					break
				except OSError as e:
					failed = os.strerror(e.errno)
				state['done'] += 1
				log.append(('step', at, where, step))
				if failed:
					log.append(('failed', failed))
		finally:
			state['inside'] = False
	class Events(list):
		def __iter__(self):
			for i in range(len(self)):
				visit('event')
				yield self[i]
	real_read, real_add, real_walk = rv.inotify_simple.INotify.read, rv.inotify_simple.INotify.add_watch, rv.iter_tree_entries
	def read(inotify, *args, **kwargs):
		visit('read')
		return Events(real_read(inotify, *args, **kwargs))
	def add_watch(inotify, path, mask):
		visit('add_watch')
		wd = real_add(inotify, path, mask)
		visit('added')
		return wd
	def walk(*args, **kwargs):
		for item in real_walk(*args, **kwargs):
			visit('walk')
			yield item
	monkeypatch.setattr(rv.inotify_simple.INotify, 'read', read)
	monkeypatch.setattr(rv.inotify_simple.INotify, 'add_watch', add_watch)
	monkeypatch.setattr(rv, 'iter_tree_entries', walk)
	real_back_up = one.back_up
	def back_up(batch):
		log.append(('batch', [(e.event, os.path.relpath(e.path, job.monitor), e.moved_from and os.path.relpath(e.moved_from, job.monitor))
			for e in batch if '.probe' not in e.path and e.event != 'attrib']))
		return real_back_up(batch)
	one.back_up = back_up
	state['armed'] = True
	wait_until(lambda: state['done'] == len(steps), timeout=20, message='steps not run')
	state['armed'] = False
	one.back_up_next()
	time.sleep(0.01)
	one.back_up_next()
	for folder in ['.'] + folders_of(job.monitor):
		open(os.path.join(job.monitor, folder, 'mark'), 'w').write('m')
	one.back_up_next()
	version, tree = version_view(job), live_view(job)
	# and the watches are the tree's: each one held is the folder's at its path, and each folder has one
	stale, missing = watch_map_errors(*maps[-1], job.monitor, skip_list=one.skip_list, add_watch=real_add)
	if version != tree or stale or missing:
		detail = {rel: ('MISSING' if rel not in version else 'present', 'MISSING' if rel not in tree else 'present', version.get(rel, [None, None])[1] == tree.get(rel, [None, None])[1])
			for rel in sorted(set(version) | set(tree)) if version.get(rel) != tree.get(rel)}
		pytest.fail(f'{name} {vector}: {detail} stale watches {stale} folders with no watch {missing}\n'
			f'to run it alone: REVERB_WATCH_SCHED_SHAPES={name} -k "{name}-{"_".join(map(str, vector))}"\nsteps and batches:\n'
			+ '\n'.join(map(str, log)), pytrace=False)
