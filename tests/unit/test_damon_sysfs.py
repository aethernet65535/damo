#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0

import os
import tempfile
import unittest

import _test_damo_common

_test_damo_common.add_damo_dir_to_syspath()

import _damo_fs
import _damon_sysfs

class TestDamonSysfs(unittest.TestCase):
    def test_json_kdamonds_staging(self):
        sysfs_dict = {
                "nr_kdamonds": "1\n",
                "0": {
                    "state": "off\n",
                    "pid": "-1\n",
                    "avail_state_inputs": '\n'.join(['on', 'off', 'commit',
                        'update_schemes_stats', 'update_schemes_tried_regions',
                        'clear_schemes_tried_regions\n']),
                    "contexts": {
                        "nr_contexts": "1\n",
                        "0": {
                            "avail_operations": "vaddr\nfvaddr\npaddr\n",
                            "operations": "paddr\n",
                            "monitoring_attrs": {
                                "intervals": {
                                    "sample_us": "5000\n",
                                    "update_us": "1000000\n",
                                    "aggr_us": "200000\n",
                                    },
                                "nr_regions": {
                                    "max": "1000\n", "min": "10\n"}
                                },
                            "targets": {"nr_targets": "0\n"},
                            "schemes": {
                                "nr_schemes": "1\n",
                                "0": {
                                    "access_pattern": {
                                        "age": {"max": "0\n", "min": "0\n"},
                                        "nr_accesses":
                                        {"max": "0\n", "min": "0\n"},
                                        "sz": {"max": "0\n", "min": "0\n"}},
                                    "action": "stat\n",
                                    "quotas": {
                                        "bytes": "0\n", "ms": "0\n",
                                        "reset_interval_ms": "0\n",
                                        "weights": {
                                            "age_permil": "0\n",
                                            "nr_accesses_permil": "0\n",
                                            "sz_permil": "0\n"
                                            }
                                        },
                                    "watermarks": {
                                        "metric": "none\n", "high": "0\n",
                                        "mid": "0\n", "low": "0\n",
                                        "interval_us": "0\n",
                                        },
                                    "stats": {
                                        "nr_applied": "0\n", "nr_tried": "0\n",
                                        "sz_applied": "0\n", "sz_tried": "0\n",
                                        "qt_exceeds": "0\n",
                                        },
                                    "tried_regions": {},
                                   },
                                },
                            },
                        },
                    }
                }
        expected_dryrun_log = [
                "read 'nr_kdamonds': '0'",
                "write '1' to 'nr_kdamonds'",
                "read '0/contexts/nr_contexts': '0'",
                "write '1' to '0/contexts/nr_contexts'",
                "write 'paddr' to '0/contexts/0/operations'",
                "write '5000' to '0/contexts/0/monitoring_attrs/intervals/sample_us'",
                "write '200000' to '0/contexts/0/monitoring_attrs/intervals/aggr_us'",
                "write '1000000' to '0/contexts/0/monitoring_attrs/intervals/update_us'",
                "write '10' to '0/contexts/0/monitoring_attrs/nr_regions/min'",
                "write '1000' to '0/contexts/0/monitoring_attrs/nr_regions/max'",
                "read '0/contexts/0/targets/nr_targets': '0'",
                "read '0/contexts/0/schemes/nr_schemes': '0'",
                "write '1' to '0/contexts/0/schemes/nr_schemes'",
                "write '0' to '0/contexts/0/schemes/0/access_pattern/sz/min'",
                "write '0' to '0/contexts/0/schemes/0/access_pattern/sz/max'",
                "write '0' to '0/contexts/0/schemes/0/access_pattern/nr_accesses/min'",
                "write '0' to '0/contexts/0/schemes/0/access_pattern/nr_accesses/max'",
                "write '0' to '0/contexts/0/schemes/0/access_pattern/age/min'",
                "write '0' to '0/contexts/0/schemes/0/access_pattern/age/max'",
                "write 'stat' to '0/contexts/0/schemes/0/action'",
                "write '0' to '0/contexts/0/schemes/0/quotas/ms'",
                "write '0' to '0/contexts/0/schemes/0/quotas/bytes'",
                "write '0' to '0/contexts/0/schemes/0/quotas/reset_interval_ms'",
                "write '0' to '0/contexts/0/schemes/0/quotas/weights/sz_permil'",
                "write '0' to '0/contexts/0/schemes/0/quotas/weights/nr_accesses_permil'",
                "write '0' to '0/contexts/0/schemes/0/quotas/weights/age_permil'",
                "write 'none' to '0/contexts/0/schemes/0/watermarks/metric'",
                "write '0' to '0/contexts/0/schemes/0/watermarks/interval_us'",
                "write '0' to '0/contexts/0/schemes/0/watermarks/high'",
                "write '0' to '0/contexts/0/schemes/0/watermarks/mid'",
                "write '0' to '0/contexts/0/schemes/0/watermarks/low'",
                ]

        _damo_fs.debug_dryrun(
                {
                    'nr_kdamonds': '0',
                    '0/contexts/nr_contexts': '0',
                    '0/contexts/0/targets/nr_targets': '0',
                    '0/contexts/0/schemes/nr_schemes': '0',
                    })
        kdamonds = _damon_sysfs.files_content_to_kdamonds(sysfs_dict)
        _damon_sysfs.write_kdamonds_dir('', kdamonds)
        logs = _damo_fs.debug_get_dryrun_logs()
        self.assertEqual(expected_dryrun_log, logs)

    def test_probes_with_perf_event_prep_parsing(self):
        # A kernel with the PMU sampling source exposes a 'perf_event' prep
        # action plus perf_event_attr files alongside it.  Reading the running
        # kdamond config must not blow up on it, and the unknown action must
        # be kept verbatim so a later re-stage does not rewrite it.
        probes_content = {
                "nr_probes": "1\n",
                "0": {
                    "preps": {
                        "nr_preps": "1\n",
                        "0": {
                            "prep_action": "perf_event\n",
                            "type": "7\n",
                            "config": "1\n",
                            "config1": "0\n",
                            "config2": "0\n",
                            "sample_period": "100000\n",
                            "sample_freq": "0\n",
                            "wakeup_events": "1\n",
                            "precise_ip": "0\n",
                            "sample_phys_addr": "N\n",
                            "sample_weight_struct": "N\n",
                            "exclude_kernel": "N\n",
                            "exclude_hv": "N\n",
                            "freq": "N\n",
                            "single_instance": "N\n",
                            },
                        },
                    "filters": {"nr_filters": "0\n"},
                    "weight": "0\n",
                    },
                }

        probes = _damon_sysfs.files_content_to_probes(probes_content)
        self.assertEqual(len(probes), 1)
        self.assertEqual(len(probes[0].preps), 1)
        self.assertEqual(probes[0].preps[0].prep_action, 'perf_event')

        # write-back: keep the action verbatim, and do not rewrite
        # nr_probes/nr_preps since the counts are unchanged -- rewriting them
        # would rebuild the probe and drop its perf_event_attr settings.
        probe_root = os.path.join(tempfile.mkdtemp(), 'probes')
        preps_dir = os.path.join(probe_root, '0', 'preps')
        os.makedirs(preps_dir)
        with open(os.path.join(probe_root, '0', 'weight'), 'w') as f:
            f.write('0\n')

        nr_probes = os.path.join(probe_root, 'nr_probes')
        nr_preps = os.path.join(preps_dir, 'nr_preps')
        nr_filters = os.path.join(probe_root, '0', 'filters', 'nr_filters')
        _damo_fs.debug_dryrun({
            nr_probes: '1\n',
            nr_preps: '1\n',
            nr_filters: '0\n',
            })
        err = _damon_sysfs.write_probes_dir(probe_root, probes)
        self.assertIsNone(err)
        self.assertEqual(_damo_fs.debug_get_dryrun_logs(), [
            "read '%s': '1'" % nr_probes,
            "read '%s': '1'" % nr_preps,
            "write 'perf_event' to '%s'" % os.path.join(preps_dir, '0',
                'prep_action'),
            "read '%s': '0'" % nr_filters,
            "write '0' to '%s'" % os.path.join(probe_root, '0', 'weight'),
            ])

    def test_kdamonds_read_with_perf_event_probe(self):
        # Reproduces the reported crash end to end: reading a kdamond config
        # whose probe carries a 'perf_event' prep action.
        sysfs_dict = {
                "nr_kdamonds": "1\n",
                "0": {
                    "state": "on\n",
                    "pid": "1234\n",
                    "refresh_ms": "0\n",
                    "contexts": {
                        "nr_contexts": "1\n",
                        "0": {
                            "operations": "vaddr\n",
                            "monitoring_attrs": {
                                "intervals": {
                                    "sample_us": "5000\n",
                                    "aggr_us": "100000\n",
                                    "update_us": "1000000\n",
                                    },
                                "nr_regions": {"min": "10\n", "max": "1000\n"},
                                "probes": {
                                    "nr_probes": "1\n",
                                    "0": {
                                        "preps": {
                                            "nr_preps": "1\n",
                                            "0": {
                                                "prep_action":
                                                "perf_event\n",
                                                "type": "7\n",
                                                "config": "1\n",
                                                "sample_period": "100000\n",
                                                },
                                            },
                                        "filters": {"nr_filters": "0\n"},
                                        "weight": "0\n",
                                        },
                                    },
                                },
                            "targets": {"nr_targets": "0\n"},
                            "schemes": {"nr_schemes": "0\n"},
                            },
                        },
                    },
                }

        kdamonds = _damon_sysfs.files_content_to_kdamonds(sysfs_dict)
        self.assertEqual(len(kdamonds), 1)
        probes = kdamonds[0].contexts[0].probes
        self.assertEqual(len(probes), 1)
        self.assertEqual(probes[0].preps[0].prep_action, 'perf_event')

if __name__ == '__main__':
    unittest.main()
