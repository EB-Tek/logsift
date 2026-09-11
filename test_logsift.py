#!/usr/bin/env python3
"""Tests for logsift. Standard library only: python3 -m unittest -v"""

import unittest

from logsift import detect_level, render_table, sift, templatize


class TestTemplatize(unittest.TestCase):
    def test_masks_ipv4_with_and_without_port(self):
        self.assertEqual(templatize("conn from 203.0.113.42"), "conn from <IP>")
        self.assertEqual(templatize("conn from 192.0.2.1:8080"), "conn from <IP>")

    def test_masks_iso_and_syslog_timestamps(self):
        self.assertEqual(templatize("2026-09-10T07:15:02Z boot"), "<TIMESTAMP> boot")
        self.assertEqual(templatize("Sep 10 07:15:02 boot"), "<TIMESTAMP> boot")

    def test_uuid_survives_number_masking(self):
        # regression: masking numbers first would shred the UUID into fragments
        line = "session 3f2504e0-4f89-11d3-9a0c-0305e82c3301 closed"
        self.assertEqual(templatize(line), "session <UUID> closed")

    def test_mac_address_not_split_into_numbers(self):
        self.assertEqual(templatize("nic 00:1b:44:11:3a:b7 up"), "nic <MAC> up")

    def test_two_lines_differing_only_in_variables_share_a_template(self):
        a = templatize("2026-09-10T07:15:02Z login failed for user 4821 from 192.0.2.9")
        b = templatize("2026-09-10T09:41:55Z login failed for user 77 from 203.0.113.7")
        self.assertEqual(a, b)

    def test_genuinely_different_lines_stay_separate(self):
        a = templatize("login failed for user 1")
        b = templatize("disk full on volume 1")
        self.assertNotEqual(a, b)

    def test_masks_numbers_carrying_unit_suffixes(self):
        # regression: "\b\d+\b" never matched "61504ms", so every distinct duration
        # became its own pattern and nothing collapsed
        self.assertEqual(templatize("GET /api/v1/orders 200 61504ms"), "GET <PATH> <NUM> <NUM>")
        self.assertEqual(templatize("disk 85% used"), "disk <NUM> used")
        self.assertEqual(templatize("freed 12MB in 1.5s"), "freed <NUM> in <NUM>")

    def test_single_segment_path_is_left_alone(self):
        # "/x" is ambiguous — it is as likely a flag as a path — so the path mask
        # deliberately requires more than one segment before it fires
        self.assertEqual(templatize("GET /x 200"), "GET /x <NUM>")

    def test_does_not_mask_digits_inside_identifiers(self):
        # "ssh2" and "utun0" are names, not measurements
        self.assertEqual(templatize("proto ssh2 on utun0"), "proto ssh2 on utun0")

    def test_collapses_irregular_whitespace(self):
        self.assertEqual(templatize("a    b\tc"), "a b c")


class TestDetectLevel(unittest.TestCase):
    def test_maps_synonyms_onto_canonical_levels(self):
        self.assertEqual(detect_level("CRITICAL: disk failure"), "error")
        self.assertEqual(detect_level("WARN: retrying"), "warn")
        self.assertEqual(detect_level("[warning] slow query"), "warn")
        self.assertEqual(detect_level("DEBUG: entering loop"), "debug")

    def test_is_case_insensitive(self):
        self.assertEqual(detect_level("Error: nope"), "error")

    def test_defaults_to_info_when_no_marker(self):
        self.assertEqual(detect_level("started listener"), "info")

    def test_does_not_match_inside_a_larger_word(self):
        # "errors" contains "error"; a bare word boundary check would misfire
        self.assertEqual(detect_level("terrorist database sync"), "info")


class TestSift(unittest.TestCase):
    def setUp(self):
        self.lines = [
            "2026-09-10T07:00:00Z INFO login ok for user 1 from 192.0.2.1",
            "2026-09-10T07:00:01Z INFO login ok for user 2 from 192.0.2.2",
            "2026-09-10T07:00:02Z INFO login ok for user 3 from 192.0.2.3",
            "2026-09-10T07:00:03Z ERROR disk full on /var/log",
            "",
            "2026-09-10T07:00:04Z WARN retry 5",
        ]

    def test_groups_repeats_and_ranks_by_count(self):
        patterns, total = sift(self.lines)
        self.assertEqual(total, 5)                 # blank line not counted
        self.assertEqual(patterns[0].count, 3)     # the three logins
        self.assertEqual(len(patterns), 3)

    def test_records_first_and_last_line_numbers(self):
        patterns, _ = sift(self.lines)
        self.assertEqual(patterns[0].first_line, 1)
        self.assertEqual(patterns[0].last_line, 3)

    def test_level_filter_selects_only_that_severity(self):
        patterns, total = sift(self.lines, level_filter="error")
        self.assertEqual(total, 5)                 # total is lines scanned, not kept
        self.assertEqual(len(patterns), 1)
        self.assertIn("disk full", patterns[0].template)

    def test_pattern_takes_the_highest_severity_it_was_seen_at(self):
        # Same template, different severities: only possible when the severity word
        # lives in a masked region (here, the path). Both lines become "read <PATH>",
        # so the group must escalate debug -> error rather than keep the first level.
        lines = ["read /var/log/debug/b.txt", "read /var/log/error/a.txt"]
        patterns, _ = sift(lines)
        self.assertEqual(len(patterns), 1)
        self.assertEqual(patterns[0].count, 2)
        self.assertEqual(patterns[0].level, "error")

    def test_empty_input_is_not_an_error(self):
        patterns, total = sift([])
        self.assertEqual((patterns, total), ([], 0))


class TestRender(unittest.TestCase):
    def test_reports_when_nothing_matched(self):
        self.assertEqual(render_table([], 0, 10), "No matching log lines.")

    def test_notes_how_many_patterns_were_hidden(self):
        # NB: lines differing only by a number collapse into one pattern, which is
        # the whole point of the tool — so distinct patterns need distinct wording.
        words = ["alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "golf",
                 "hotel", "india", "juliet", "kilo", "lima", "mike", "november"]
        patterns, total = sift([f"{w} subsystem ready" for w in words])
        self.assertEqual(len(patterns), len(words))
        out = render_table(patterns, total, shown=5)
        self.assertIn("more patterns", out)


if __name__ == "__main__":
    unittest.main(verbosity=2)
