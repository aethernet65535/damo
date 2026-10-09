#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0

import argparse
import contextlib
import io
import json
import unittest

import _test_damo_common

_test_damo_common.add_damo_dir_to_syspath()

import _damo_sysinfo
import _damon
import _damon_args
import _damon_sysfs
import damo_args_damon

class TestArgsDamonFromCurrent(unittest.TestCase):
    def parse(self, argv):
        parser = argparse.ArgumentParser()
        damo_args_damon.set_argparser(parser)
        return parser.parse_args(argv)

    def run_main(self, args, current_kdamonds):
        '''Run damo_args_damon.main() as root, reading given kdamonds as the
        current sysfs setup.  Returns its stdout and the load_sysinfo values
        that ensure_initialized() was called with.'''
        orig_root_permission = _damon.ensure_root_permission
        orig_ensure_initialized = _damon.ensure_initialized
        orig_current_kdamonds = _damon.current_kdamonds
        load_sysinfo_calls = []

        def ensure_initialized_spy(args_, load_sysinfo):
            load_sysinfo_calls.append(load_sysinfo)
            return orig_ensure_initialized(args_, load_sysinfo)

        _damon.ensure_root_permission = lambda: None
        _damon.ensure_initialized = ensure_initialized_spy
        _damon.current_kdamonds = lambda: current_kdamonds
        try:
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                damo_args_damon.main(args)
        finally:
            _damon.ensure_root_permission = orig_root_permission
            _damon.ensure_initialized = orig_ensure_initialized
            _damon.current_kdamonds = orig_current_kdamonds
        return stdout.getvalue(), load_sysinfo_calls

    def test_from_current(self):
        _damon._damon_fs = _damon_sysfs
        _damo_sysinfo.system_info = _damo_sysinfo.SystemInfo(
                damo_version=None, kernel_version=None,
                avail_damon_features=[])

        # a setup that could have been read from the sysfs
        with contextlib.redirect_stderr(io.StringIO()):
            kdamonds, err = _damon_args.kdamonds_for(
                    self.parse(['--damos_action', 'stat']))
        self.assertIsNone(err)

        out, load_sysinfo_calls = self.run_main(
                self.parse(['--from_current']), kdamonds)

        # sysinfo loading must be skipped.  Its feature checking stages a
        # probe kdamond, and thus fails while DAMON is running.
        self.assertEqual(load_sysinfo_calls, [False])

        # the output should be a standard kdamonds json, feedable to
        # '--kdamonds' of 'damo start' and friends.
        reloaded, err = _damon_args.kdamonds_from_json_arg(out)
        self.assertIsNone(err)
        self.assertEqual(len(reloaded), 1)
        self.assertEqual(reloaded[0].contexts[0].schemes[0].action, 'stat')

        # parameters only.  Runtime states of the current setup are not
        # configuration.
        kvpairs = json.loads(out)
        self.assertNotIn('state', kvpairs['kdamonds'][0])
        self.assertNotIn('pid', kvpairs['kdamonds'][0])

if __name__ == '__main__':
    unittest.main()
