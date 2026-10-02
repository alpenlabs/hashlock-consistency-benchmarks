"""Prevent misleading comparisons from partial proofs or inconsistent workloads."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location("benchmark_runner", Path(__file__).resolve().parents[1] / "run.py")
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class ComparisonTests(unittest.TestCase):
    def setUp(self):
        self.args = SimpleNamespace(wires=1019, instances=7, threads=8, seed=20261001,
                                    mode="prove", approach="both", trials=1, build_only=False,
                                    artifacts=Path("/parameters/v5.0.0"))
        self.sp1 = {
            "status": "complete", "schema_version": 2, "mode": "groth16", "wires": 1019,
            "total_retained_instances": 7, "seed": 20261001, "guest_output_matches_host": True,
            "environment": {"RAYON_NUM_THREADS": "8", "GOMAXPROCS": "8"},
            "verified_stages": ["core", "compressed", "groth16"],
            "groth16_tampered_public_output_rejected": True,
            "timings_s": dict(zip(runner.SP1_PROVE_STAGES, [1, 2, 3, 4, 5]),
                              key_setup=17, groth16_verify=0.01, groth16_negative_verify=0.2),
            "proof_bytes": {"groth16_serialized": 1024},
        }
        self.native = {
            "status": "complete", "mode": "prove", "wires": 1019, "rows": 2038, "seed": "20261001",
            "cpu_workers": 8, "scalar_range_check": False, "proof_verified": True,
            "altered_hash_rejected": True, "altered_point_rejected": True,
            "timings_s": {"setup": 20, "prove": 10, "verify": 0.02, "negative_verification": 0.4},
            "artifact_bytes": {"proof.bin": 196},
        }

    def test_all_sp1_proving_stages_but_no_setup_or_negative_verification(self):
        item = runner.normalize("soldering", self.sp1, self.args, 0)
        self.assertEqual(item["proof_generation_s"], 15)
        self.assertEqual(item["verification_s"], 0.01)
        self.assertEqual(item["setup_s"], 17)

    def test_partial_or_failed_proof_cannot_be_reported_as_complete(self):
        for stage in runner.SP1_PROVE_STAGES:
            with self.subTest(stage=stage):
                broken = copy.deepcopy(self.sp1)
                del broken["timings_s"][stage]
                with self.assertRaises(ValueError):
                    runner.normalize("soldering", broken, self.args, 0)
        for patch in ({"verified_stages": ["core", "compressed"]},
                      {"groth16_tampered_public_output_rejected": False},
                      {"schema_version": 1}, {"status": "running"}, {"mode": "compressed"}):
            with self.subTest(patch=patch), self.assertRaises(ValueError):
                runner.normalize("soldering", dict(self.sp1, **patch), self.args, 0)
        with self.assertRaises(ValueError):
            runner.normalize("soldering", self.sp1, self.args, 1)

    def test_native_checks_both_rows_and_both_tamper_tests(self):
        good = runner.normalize("hashlock", self.native, self.args, 0)
        self.assertEqual(good["rows"], 2038)
        self.assertIsNone(good["retained_instances"])
        self.assertEqual(good["proof_generation_s"], 10)
        for patch in ({"rows": 1019}, {"scalar_range_check": True}, {"proof_verified": False},
                      {"altered_hash_rejected": False}, {"altered_point_rejected": False},
                      {"cpu_workers": 12}, {"wires": 508}):
            with self.subTest(patch=patch), self.assertRaises(ValueError):
                runner.normalize("hashlock", dict(self.native, **patch), self.args, 0)

    def test_execution_is_not_presented_as_proof_generation(self):
        self.args.mode = "check"
        sp1 = dict(self.sp1, mode="execute", verified_stages=[])
        native = dict(self.native, mode="check", constraints_satisfied=True, proof_verified=False)
        for approach, raw in (("soldering", sp1), ("hashlock", native)):
            item = runner.normalize(approach, raw, self.args, 0)
            self.assertIsNone(item["proof_generation_s"])
            self.assertIsNone(item["verification_s"])
            self.assertFalse(item["proof_verified"])

    def test_mismatched_sp1_workload_or_workers_rejected(self):
        for patch in ({"wires": 508}, {"total_retained_instances": 8}, {"seed": 0},
                      {"environment": {"RAYON_NUM_THREADS": "12", "GOMAXPROCS": "8"}}):
            with self.subTest(patch=patch), self.assertRaises(ValueError):
                runner.normalize("soldering", dict(self.sp1, **patch), self.args, 0)

    def test_both_commands_use_same_wire_count_and_repo_local_binaries(self):
        for approach in ("soldering", "hashlock"):
            command = runner.command_for(approach, self.args, Path("/tmp/output") / approach)
            flag = "--wires" if approach == "soldering" else "-wires"
            self.assertEqual(command[command.index(flag) + 1], "1019")
            self.assertTrue(Path(command[0]).is_relative_to(runner.ROOT))
            self.assertNotIn("garbled-snark-verifier", command[0])

    def test_failed_comparison_keeps_failure_without_numeric_proof_result(self):
        with tempfile.TemporaryDirectory() as temp:
            out = Path(temp)
            runner.save_report(out, self.args, [{"trial": 1, "approach": "soldering",
                               "status": "failed", "error": "missing final proof"}])
            self.assertIn("missing final proof", (out / "comparison.md").read_text())
            self.assertIn("failed", (out / "comparison.csv").read_text())
            self.assertEqual(json.loads((out / "comparison.json").read_text())["status"], "failed")

    def test_one_finished_side_is_still_an_incomplete_comparison(self):
        with tempfile.TemporaryDirectory() as temp:
            out = Path(temp)
            runner.save_report(out, self.args, [{"trial": 1, "approach": "soldering", "status": "complete"}])
            self.assertEqual(json.loads((out / "comparison.json").read_text())["status"], "incomplete")

    def test_build_metadata_does_not_require_groth16_parameters(self):
        self.args.build_only = True
        with tempfile.TemporaryDirectory() as temp:
            self.args.artifacts = Path(temp) / "not-downloaded/v5.0.0"
            with mock.patch.object(runner, "capture", return_value={}), mock.patch.object(runner, "sha", return_value="test-hash"):
                result = runner.metadata(self.args, {})
            self.assertNotIn("sp1_artifacts", result)


if __name__ == "__main__":
    unittest.main()
