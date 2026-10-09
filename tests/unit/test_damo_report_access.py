#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0

import argparse
import contextlib
import io
import json
import os
import tempfile
import unittest

import _test_damo_common

_test_damo_common.add_damo_dir_to_syspath()

import _damo_records
import _damo_ascii_color
import _damon
import damo_args_accesses_format
import damo_report_access

class TestDamoShow(unittest.TestCase):
    def test_sorted_access_pattern(self):
        record = _damo_records.DamonRecord.from_kvpairs(
            {
                "kdamond_idx": 0, "context_idx": 0,
                "intervals": {
                    "sample_us": "5ms", "aggr_us": "100ms",
                    "ops_update_us": "1s"
                    },
                "scheme_idx": 0, "target_id": None,
                "snapshots": [
                    {
                        "start_time": "0", "end_time": "1000000000",
                        "regions": [
                            {
                                "start": "4K", "end": "8K",
                                "nr_accesses": {
                                    "samples": 0, "percent": 0
                                    },
                                "age": {
                                    "usec": "1s", "aggr_intervals": 10
                                    }
                                },
                            {
                                "start": "8K", "end": "16K",
                                "nr_accesses": {
                                    "samples": 19, "percent": "95%"
                                    },
                                "age": {
                                    "usec": "100ms", "aggr_intervals": 1
                                    }
                                },
                            {
                                "start": "16K", "end": "22K",
                                "nr_accesses": {
                                    "samples": 10, "percent": 50
                                    },
                                "age": {
                                    "usec": "3s", "aggr_intervals": 30
                                    }
                                },

                            ],
                        "total_bytes": "3221225472"
                        }
                    ]
                })
        sorted_vals = damo_report_access.SortedAccessPatterns([record])
        self.assertEqual(sorted_vals.sz_regions[0], 4096)
        self.assertEqual(sorted_vals.sz_regions[-1], 8192)
        self.assertEqual(sorted_vals.access_rates_percent[0], 0)
        self.assertEqual(sorted_vals.access_rates_percent[-1], 95)
        self.assertEqual(sorted_vals.ages_us[0], 100000)
        self.assertEqual(sorted_vals.ages_us[-1], 3000000)

    def test_format_template(self):
        record = _damo_records.DamonRecord.from_kvpairs(
            {
                "kdamond_idx": 0, "context_idx": 0,
                "intervals": {
                    "sample_us": "5ms", "aggr_us": "100ms",
                    "ops_update_us": "1s"
                    },
                "scheme_idx": 0, "target_id": None,
                "snapshots": [
                    {
                        "start_time": "0", "end_time": "1000000000",
                        "regions": [
                            {
                                "start": "4K", "end": "8K",
                                "nr_accesses": {
                                    "samples": 0, "percent": 0
                                    },
                                "age": {
                                    "usec": "1s", "aggr_intervals": 10
                                    }
                                },
                            {
                                "start": "8K", "end": "16K",
                                "nr_accesses": {
                                    "samples": 19, "percent": "95%"
                                    },
                                "age": {
                                    "usec": "100ms", "aggr_intervals": 1
                                    }
                                },
                            {
                                "start": "16K", "end": "22K",
                                "nr_accesses": {
                                    "samples": 10, "percent": 50
                                    },
                                "age": {
                                    "usec": "3s", "aggr_intervals": 30
                                    }
                                },

                            ],
                        "total_bytes": "3221225472"
                        }
                    ]
                })
        fmt = damo_report_access.ReportFormat()
        fmt.raw_number = False
        fmt.min_chars_for = []
        self.assertEqual(damo_report_access.format_output(
            '<abs start time>', damo_report_access.record_formatters, fmt, record),
            '0 ns')

    def test_rescale(self):
        self.assertEqual(
                damo_report_access.rescale(10, [0, 100], [0, 10], False), 1)
        self.assertEqual(
                damo_report_access.rescale(10, [0, 100], [1, 11], False), 2)
        self.assertEqual(
                damo_report_access.rescale(20, [10, 110], [1, 11], False), 2)

    def probe_record(self, hits_of_regions, nr_accesses_samples=0):
        # A record shaped like tried_regions of a probe-weighted kdamond: the
        # kernel reports nr_accesses as 0, and the per-probe hits carry the
        # access frequency instead.
        regions = []
        for idx, hits in enumerate(hits_of_regions):
            regions.append({
                'start': '%dK' % (idx * 4), 'end': '%dK' % ((idx + 1) * 4),
                'nr_accesses': {'samples': nr_accesses_samples, 'percent': 0},
                'age': {'usec': '1s', 'aggr_intervals': 10},
                'probe_hits': hits,
                })
        return _damo_records.DamonRecord.from_kvpairs(
            {
                "kdamond_idx": 0, "context_idx": 0,
                "intervals": {
                    "sample_us": "5ms", "aggr_us": "100ms",
                    "ops_update_us": "1s"
                    },
                "scheme_idx": 0, "target_id": None,
                "snapshots": [
                    {
                        "start_time": "0", "end_time": "1000000000",
                        "regions": regions,
                        "total_bytes": "12288"
                        }
                    ]
                })

    def test_sorted_regions_by_probe_hits_wsum(self):
        record = self.probe_record([[1, 0], [0, 5], [2, 2]])
        regions = record.snapshots[0].regions

        # probe weights [1, 10]: wsum is 1, 50, 22
        ascending = damo_report_access.sorted_regions(
                regions, ['probe_hits_wsum'], None, [0, 100, 100], [1, 10])
        self.assertEqual([r.probe_hits for r in ascending],
                [[1, 0], [2, 2], [0, 5]])

        descending = damo_report_access.sorted_regions(
                regions, ['probe_hits_wsum'], ['probe_hits_wsum'],
                [0, 100, 100], [1, 10])
        self.assertEqual([r.probe_hits for r in descending],
                [[0, 5], [2, 2], [1, 0]])

        # Without weights every region has the same (zero) wsum, so the input
        # order must be kept rather than shuffled.
        unchanged = damo_report_access.sorted_regions(
                regions, ['probe_hits_wsum'], None, [0, 100, 100])
        self.assertEqual([r.probe_hits for r in unchanged],
                [[1, 0], [0, 5], [2, 2]])

    def test_region_format_keyword_probe_hits_wsum(self):
        record = self.probe_record([[4, 1]])
        snapshot = record.snapshots[0]
        fmt = damo_report_access.ReportFormat()
        fmt.raw_number = False
        fmt.min_chars_for = []
        fmt.probe_weights_of = {(0, 0): [2, 3]}

        self.assertEqual(damo_report_access.format_output(
            '<probe hits wsum>', damo_report_access.region_formatters, fmt,
            record, snapshot, snapshot.regions[0], 0), '11')

        # --raw_number keeps the machine friendly form of the number.
        fmt.probe_weights_of = {(0, 0): [200, 300]}
        fmt.raw_number = False
        self.assertEqual(damo_report_access.format_output(
            '<probe hits wsum>', damo_report_access.region_formatters, fmt,
            record, snapshot, snapshot.regions[0], 0), '1,100')
        fmt.raw_number = True
        self.assertEqual(damo_report_access.format_output(
            '<probe hits wsum>', damo_report_access.region_formatters, fmt,
            record, snapshot, snapshot.regions[0], 0), '1100')

    def test_default_region_format_switches_to_probe_hits_wsum(self):
        # Probe-weighted monitoring: nr_accesses-based columns are all zero,
        # so the default region line must show the weighted hits instead.
        record = self.probe_record([[4, 1]])
        fmt = damo_report_access.ReportFormat()
        fmt.format_region = None
        fmt.probe_weights_of = {(0, 0): [1, 1]}
        damo_report_access.set_formats_region_probe_hits_default(
                fmt, [record], argparse.Namespace(region_box=False))
        self.assertIn('<probe hits wsum>', fmt.format_region)
        self.assertNotIn('<access hz>', fmt.format_region)

    def test_default_region_format_keeps_access_hz_without_probe_weights(self):
        # Weights all zero (or unknown) mean the kernel's own access check is
        # running, so nr_accesses stays meaningful and must keep the column.
        record = self.probe_record([[4, 1]])
        for probe_weights_of in [{(0, 0): [0, 0]}, None]:
            fmt = damo_report_access.ReportFormat()
            fmt.format_region = None
            fmt.probe_weights_of = probe_weights_of
            damo_report_access.set_formats_region_probe_hits_default(
                    fmt, [record], argparse.Namespace(region_box=False))
            self.assertIn('<access hz>', fmt.format_region)
            self.assertNotIn('<probe hits wsum>', fmt.format_region)

    def test_styles_use_probe_hits_wsum_with_probe_weights(self):
        # The box styles set their own region formats, so they must follow the
        # probe weights, too: <access hz> would be all zeros otherwise.
        record = self.probe_record([[4, 1]])
        for style in ['simple-boxes', 'cold', 'hot']:
            fmt = damo_report_access.ReportFormat()
            fmt.probe_weights_of = {(0, 0): [1, 10]}
            damo_report_access.set_formats_handle_styles(
                    fmt, argparse.Namespace(style=style), [record])
            self.assertIn('<probe hits wsum>', fmt.format_region, style)
            self.assertNotIn('<access hz>', fmt.format_region, style)

    def test_styles_keep_access_hz_without_probe_weights(self):
        # Weights all zero (or unknown) mean nr_accesses is meaningful, so the
        # box styles must keep the <access hz> keyword.
        record = self.probe_record([[4, 1]])
        for probe_weights_of in [{(0, 0): [0, 0]}, None]:
            for style in ['simple-boxes', 'cold', 'hot']:
                fmt = damo_report_access.ReportFormat()
                fmt.probe_weights_of = probe_weights_of
                damo_report_access.set_formats_handle_styles(
                        fmt, argparse.Namespace(style=style), [record])
                self.assertIn('<access hz>', fmt.format_region, style)
                self.assertNotIn('<probe hits wsum>', fmt.format_region, style)

    def raw_form_output(self, record, probe_weights_of):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            damo_report_access.pr_records_raw_form(
                    [record], False, probe_weights_of)
        lines = stdout.getvalue().splitlines()
        header = [l for l in lines if l.startswith('# start_addr')]
        regions = [l for l in lines if l.startswith('000000000000-')]
        self.assertEqual(len(header), 1)
        self.assertEqual(len(regions), 1)
        return header[0], regions[0].split()

    def test_raw_form_shows_probe_hits_wsum(self):
        # --raw_form must show the weighted probe hits, too, since
        # nr_accesses is all zero for probe-weighted monitoring.  The nr_accesses
        # value below is deliberately nonzero to prove it is the one hidden.
        record = self.probe_record([[4, 1]], nr_accesses_samples=7)
        header, region = self.raw_form_output(record, {(0, 0): [2, 3]})
        self.assertIn('probe_hits_wsum', header)
        self.assertNotIn('nr_accesses', header)
        # hits [4, 1] weighted by [2, 3] -> 4 * 2 + 1 * 3 = 11
        self.assertEqual(region[-2], '11')
        self.assertEqual(region[-1], '10')  # age

    def test_raw_form_keeps_nr_accesses_without_probe_weights(self):
        # Weights all zero (or unknown) mean nr_accesses is the access
        # frequency, so both the column name and the value must be kept.
        record = self.probe_record([[4, 1]], nr_accesses_samples=7)
        for probe_weights_of in [{(0, 0): [0, 0]}, None]:
            header, region = self.raw_form_output(record, probe_weights_of)
            self.assertIn('nr_accesses', header)
            self.assertNotIn('probe_hits_wsum', header)
            self.assertEqual(region[-2], '7')

    def test_sort_probe_hits_wsum_arg_accepted(self):
        parser = argparse.ArgumentParser()
        damo_report_access.set_argparser(parser)
        try:
            args = parser.parse_args(
                    ['--sort_regions_by', 'probe_hits_wsum',
                     '--sort_regions_dsc', 'probe_hits_wsum'])
        except SystemExit:
            self.fail('--sort_regions_by probe_hits_wsum is not accepted')
        self.assertEqual(args.sort_regions_by, ['probe_hits_wsum'])
        self.assertEqual(args.sort_regions_dsc, ['probe_hits_wsum'])

    def test_min_chars_default_covers_probe_hits_wsum(self):
        # The default region format shows <probe hits wsum>, so its column
        # needs a minimum width like the other defaulted keywords have.
        parser = argparse.ArgumentParser()
        damo_report_access.add_fmt_args(parser)
        args = parser.parse_args([])
        self.assertIn(['<probe hits wsum>', 6], args.min_chars_for)

    def test_probe_legend_lines_labels_shown_access_column(self):
        min_chars = [['<index>', 3], ['<start address>', 12],
                     ['<size>', 11], ['<access hz>', 6],
                     ['<probe hits wsum>', 6], ['<age>', 13]]
        self.assertTrue(damo_report_access.probe_legend_lines(
            min_chars)[1].endswith('access_hz'))
        self.assertTrue(damo_report_access.probe_legend_lines(
            min_chars, '<probe hits wsum>', 'hits_wsum')[1]
            .endswith('hits_wsum'))

    def test_snapshot_head_legend_follows_probe_weights(self):
        # The legend describes the region columns, so it must name the
        # column that the probe-weighted default format actually shows.
        record = self.probe_record([[4, 1]])
        fmt = damo_report_access.ReportFormat()
        fmt.format_snapshot_head = None
        fmt.format_region = None
        fmt.min_chars_for = [['<index>', 3], ['<start address>', 12],
                             ['<size>', 11], ['<access hz>', 6],
                             ['<probe hits wsum>', 6], ['<age>', 13]]
        fmt.probe_weights_of = {(0, 0): [1, 1]}
        damo_report_access.set_fmt_snapshot_head_default(
                fmt, [record], argparse.Namespace(), True, True)
        self.assertTrue(
                fmt.format_snapshot_head.splitlines()[-1].endswith('hits_wsum'))

        fmt.format_snapshot_head = None
        fmt.probe_weights_of = {(0, 0): [0, 0]}
        damo_report_access.set_fmt_snapshot_head_default(
                fmt, [record], argparse.Namespace(), True, True)
        self.assertTrue(
                fmt.format_snapshot_head.splitlines()[-1].endswith('access_hz'))

    def test_probe_weights_of_records(self):
        record = self.probe_record([[4, 1]])
        kdamonds = [_damon.Kdamond('on', 1234, [
            _damon.DamonCtx(probes=[
                _damon.DamonProbe(filters=[], weight=2),
                _damon.DamonProbe(filters=[], weight=0)])])]

        weights = damo_report_access.probe_weights_of_records(
                [record], kdamonds)
        self.assertEqual(weights[(0, 0)], [2, 0])

        # kdamonds unavailable: caller falls back to nr_accesses behavior.
        self.assertIsNone(
                damo_report_access.probe_weights_of_records([record], None))

        # A record referring to a kdamond/context we could not read is skipped
        # rather than aborting the whole report.
        record.context_idx = 7
        self.assertEqual(
                damo_report_access.probe_weights_of_records(
                    [record], kdamonds),
                {})

    def test_probe_weights_of_input_record_file(self):
        record = self.probe_record([[4, 1]])
        kdamond = _damon.Kdamond('on', 1234, [
            _damon.DamonCtx(probes=[
                _damon.DamonProbe(filters=[], weight=1),
                _damon.DamonProbe(filters=[], weight=10)])])
        with tempfile.TemporaryDirectory() as tmpdir:
            record_file = os.path.join(tmpdir, 'rec.data')
            with open(record_file + '.kdamonds', 'w') as f:
                json.dump([kdamond.to_kvpairs()], f)

            self.assertEqual(
                    damo_report_access.probe_weights_of_input(
                        record_file, [record]),
                    {(0, 0): [1, 10]})

            # No sidecar means unknown weights, not an error.
            self.assertIsNone(damo_report_access.probe_weights_of_input(
                os.path.join(tmpdir, 'nope.data'), [record]))

    def test_probe_weights_of_input_live(self):
        record = self.probe_record([[4, 1]])
        expect = [_damon.Kdamond('on', 1234, [
            _damon.DamonCtx(probes=[
                _damon.DamonProbe(filters=[], weight=4)])])]
        orig = _damon.current_kdamonds
        _damon.current_kdamonds = lambda: expect
        try:
            weights = damo_report_access.probe_weights_of_input(None, [record])
        finally:
            _damon.current_kdamonds = orig
        self.assertEqual(weights, {(0, 0): [4]})

    def test_probe_weights_of_input_multiple_record_files(self):
        # Records of multiple input files are merged without telling which
        # file each of them came from, so their per-file kdamonds (whose
        # indices restart at zero for each file) cannot be attributed.  The
        # weights must then be unknown rather than possibly wrong.
        self.assertIsNone(damo_report_access.probe_weights_of_input(
            ['a.data', 'b.data'], [self.probe_record([[4, 1]])]))

    def test_probe_weights_of_records_negative_indices(self):
        # Records of the damon_stat data source carry kdamond_idx -1.  Such
        # indices must not wrap around to the last kdamond/context, whose
        # weights would be attributed to the wrong record.
        record = self.probe_record([[4, 1]])
        kdamonds = [_damon.Kdamond('on', 1234, [
            _damon.DamonCtx(probes=[
                _damon.DamonProbe(filters=[], weight=3)])]),
            _damon.Kdamond('on', 4321, [
                _damon.DamonCtx(probes=[
                    _damon.DamonProbe(filters=[], weight=7)])])]
        for kidx, cidx in [(-1, 0), (0, -1), (-1, -1)]:
            record.kdamond_idx, record.context_idx = kidx, cidx
            self.assertEqual(
                    damo_report_access.probe_weights_of_records(
                        [record], kdamonds),
                    {})

    def test_set_formats_for_input_applies_input_probe_weights(self):
        # The wiring from --input to the formats must actually be in place:
        # the records' probe weights decide the default region format.
        kdamond = _damon.Kdamond('on', 1234, [
            _damon.DamonCtx(probes=[
                _damon.DamonProbe(filters=[], weight=1),
                _damon.DamonProbe(filters=[], weight=10)])])
        with tempfile.TemporaryDirectory() as tmpdir:
            record_file = os.path.join(tmpdir, 'rec.data')
            with open(record_file, 'w'):
                pass
            with open(record_file + '.kdamonds', 'w') as f:
                json.dump([kdamond.to_kvpairs()], f)

            parser = argparse.ArgumentParser()
            damo_report_access.set_argparser(parser)
            args = parser.parse_args(['--input', record_file])
            self.assertIsNone(damo_report_access.handle_args_input(args))

            fmt, err = damo_report_access.set_formats_for_input(
                    args, [self.probe_record([[4, 1]])])
            self.assertIsNone(err)
            self.assertEqual(fmt.probe_weights_of, {(0, 0): [1, 10]})
            self.assertIn('<probe hits wsum>', fmt.format_region)

    def test_format_json_arg_keeps_probe_weights(self):
        # The json/file form of --format replaces the whole ReportFormat.  The
        # probe weights must be carried onto the replacement, or
        # probe-weighted reports would silently fall back to all-zero
        # nr_accesses columns.
        parser = argparse.ArgumentParser()
        damo_report_access.set_argparser(parser)
        fmt_json = json.dumps(
                damo_report_access.ReportFormat.from_args(
                    parser.parse_args([])).to_kvpairs(False))
        args = parser.parse_args(['--format', fmt_json])

        fmt, err = damo_report_access.set_formats(
                args, [self.probe_record([[4, 1]])], {(0, 0): [1, 10]})
        self.assertIsNone(err)
        self.assertEqual(fmt.probe_weights_of, {(0, 0): [1, 10]})
        self.assertIn('<probe hits wsum>', fmt.format_region)

    def test_format_kvpairs_roundtrip_keeps_heatmap_colorset(self):
        # The json/file form of --format restores a ReportFormat from
        # kvpairs.  Restoring must not lose the heatmap colorset (nor replace
        # the heatmap width with it), or rendering fails with 'wrong
        # colorset'.
        parser = argparse.ArgumentParser()
        damo_report_access.set_argparser(parser)
        fmt = damo_report_access.ReportFormat.from_args(parser.parse_args([]))
        fmt.snapshot_heatmap_colorset = 'emotion'
        restored = damo_report_access.ReportFormat.from_kvpairs(
                fmt.to_kvpairs(False))
        self.assertEqual(restored.snapshot_heatmap_colorset, 'emotion')
        self.assertEqual(restored.snapshot_heatmap_width,
                fmt.snapshot_heatmap_width)

    def test_accesses_format_generates_json(self):
        # 'damo args accesses_format' is the source of the json that 'damo
        # report access --format' takes, so it must print it instead of
        # crashing on the (fmt, err) tuple that set_formats() returns.
        parser = argparse.ArgumentParser()
        damo_args_accesses_format.set_argparser(parser)
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            damo_args_accesses_format.main(parser.parse_args([]))
        kvpairs = json.loads(stdout.getvalue())
        self.assertIn('format_region', kvpairs)

    def region_box_format_for(self, record, probe_weights_of):
        patterns = damo_report_access.SortedAccessPatterns(
                [record], probe_weights_of)
        return damo_report_access.RegionBoxFormat(
                patterns,
                damo_report_access.RegionBoxAttr('age', [1, 40], False),
                'right',
                damo_report_access.RegionBoxAttr(
                    'probe_hits_wsum', [0, 9], False),
                'emotion',
                damo_report_access.RegionBoxAttr('size', [1, 1], False))

    def test_region_box_values_accept_probe_hits_wsum(self):
        parser = argparse.ArgumentParser()
        damo_report_access.add_fmt_args(parser)
        try:
            args = parser.parse_args(
                    ['--region_box_values', 'age', 'probe_hits_wsum', 'size'])
        except SystemExit:
            self.fail('--region_box_values probe_hits_wsum is not accepted')
        self.assertEqual(args.region_box_values,
                ['age', 'probe_hits_wsum', 'size'])

    def test_region_box_values_follow_probe_weights(self):
        # The box's color dimension defaults to access_rate, which is always
        # zero while any probe has a weight, so the color would be stuck at
        # the darkest level.  It must switch to the weighted probe hits, like
        # the access column does.
        record = self.probe_record([[4, 1]])
        parser = argparse.ArgumentParser()
        damo_report_access.set_argparser(parser)
        args = parser.parse_args([])
        fmt, err = damo_report_access.set_formats(
                args, [record], {(0, 0): [1, 10]})
        self.assertIsNone(err)
        self.assertEqual(fmt.region_box_values,
                ['age', 'probe_hits_wsum', 'size'])

    def test_region_box_values_keep_access_rate_without_probe_weights(self):
        # Weights all zero (or unknown) mean the kernel's own access check is
        # running, so access_rate keeps carrying the data.
        record = self.probe_record([[4, 1]])
        parser = argparse.ArgumentParser()
        damo_report_access.set_argparser(parser)
        args = parser.parse_args([])
        for probe_weights_of in [{(0, 0): [0, 0]}, None]:
            fmt, err = damo_report_access.set_formats(
                    args, [record], probe_weights_of)
            self.assertIsNone(err)
            self.assertEqual(fmt.region_box_values,
                    ['age', 'access_rate', 'size'])

    def test_sorted_access_patterns_collects_probe_hits_wsum(self):
        # The box color is normalized over the regions, so the sorted weighted
        # hits must be collected the way access rates and ages are.
        record = self.probe_record([[4, 1], [0, 5], [2, 2]])
        patterns = damo_report_access.SortedAccessPatterns(
                [record], {(0, 0): [1, 10]})
        # hits [4, 1], [0, 5], [2, 2] weighted by [1, 10] -> 14, 50, 22
        self.assertEqual(patterns.probe_hits_wsums, [14, 22, 50])

        # Unknown weights cannot score the hits, so they are all zero, which
        # is exactly what nr_accesses-based columns show then.
        patterns = damo_report_access.SortedAccessPatterns([record])
        self.assertEqual(patterns.probe_hits_wsums, [0, 0, 0])

    def test_region_box_color_follows_probe_hits_wsum(self):
        record = self.probe_record([[4, 1], [0, 5], [2, 2]])
        snapshot = record.snapshots[0]
        box_format = self.region_box_format_for(record, {(0, 0): [1, 10]})

        val, minmax = box_format.val_minmax(
                snapshot.regions[1], 'probe_hits_wsum', [1, 10])
        self.assertEqual(val, 50)
        self.assertEqual(minmax, [14, 50])

        # The highest wsum region must get the top color level, the lowest
        # wsum one the bottom level, rather than all regions getting one.
        high = box_format.to_str(snapshot.regions[1], [1, 10])
        low = box_format.to_str(snapshot.regions[0], [1, 10])
        self.assertIn(_damo_ascii_color.color_mode_start_txt('emotion', 9),
                high)
        self.assertIn(_damo_ascii_color.color_mode_start_txt('emotion', 0),
                low)

    def test_box_keyword_uses_record_probe_weights(self):
        # <box> is rendered per region through format_output(), which knows
        # the region's record, so the box color must take that record's probe
        # weights instead of showing every region at the darkest level.
        record = self.probe_record([[4, 1], [0, 5], [2, 2]])
        snapshot = record.snapshots[0]
        fmt = damo_report_access.ReportFormat()
        fmt.raw_number = False
        fmt.min_chars_for = []
        fmt.probe_weights_of = {(0, 0): [1, 10]}
        fmt.region_box_format = self.region_box_format_for(
                record, fmt.probe_weights_of)

        boxes = [damo_report_access.format_output(
            '<box>', damo_report_access.region_formatters, fmt, record,
            snapshot, r, idx) for idx, r in enumerate(snapshot.regions)]
        self.assertIn(_damo_ascii_color.color_mode_start_txt('emotion', 9),
                boxes[1])  # wsum 50
        self.assertIn(_damo_ascii_color.color_mode_start_txt('emotion', 0),
                boxes[0])  # wsum 14

    def test_fmt_records_box_colors_follow_probe_weights(self):
        # fmt_records() builds the box's normalization range itself; it must
        # collect it with the record's probe weights, or every region's real
        # wsum falls outside an all-zero range and the color level overflows.
        record = self.probe_record([[4, 1], [0, 5], [2, 2]])
        parser = argparse.ArgumentParser()
        damo_report_access.set_argparser(parser)
        args = parser.parse_args(['--style', 'simple-boxes'])
        fmt, err = damo_report_access.set_formats(
                args, [record], {(0, 0): [1, 10]})
        self.assertIsNone(err)

        out = damo_report_access.fmt_records(fmt, [record])
        # hits [1, 0], [0, 5], [2, 2] weighted by [1, 10] -> 1, 50, 22
        self.assertIn(_damo_ascii_color.color_mode_start_txt('emotion', 9),
                out)  # wsum 50 is the max
        self.assertIn(_damo_ascii_color.color_mode_start_txt('emotion', 0),
                out)  # wsum 1 is the min

    def test_region_box_description_shows_probe_hits_wsum(self):
        # <region box description> (--region_box) prints the value ranges; the
        # weighted hits must be formatted like the other values, not as None.
        record = self.probe_record([[4, 1], [0, 5], [2, 2]])
        box_format = self.region_box_format_for(record, {(0, 0): [1, 10]})
        desc = box_format.description_msg(False)
        self.assertIn('probe_hits_wsum', desc)
        self.assertIn('14', desc)
        self.assertIn('50', desc)
        self.assertNotIn('None', desc)

if __name__ == '__main__':
    unittest.main()
