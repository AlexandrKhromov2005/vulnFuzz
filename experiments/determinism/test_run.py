import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

MODULE_PATH = Path(__file__).with_name("run.py")
SPEC = importlib.util.spec_from_file_location("vf_determinism", MODULE_PATH)
determinism = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(determinism)


class ProfileTests(unittest.TestCase):
    def test_profile_has_no_implicit_host_devices(self):
        arguments = determinism.common_arguments("qemu", "/images/base.qcow2")
        self.assertIn("pc-i440fx-9.2,accel=tcg", arguments)
        self.assertIn("qemu64", arguments)
        self.assertIn("base=2000-01-01T00:00:00,clock=vm", arguments)
        self.assertIn("driver=blkreplay,if=none,image=img-direct,id=img-blkreplay", arguments)
        self.assertEqual(arguments[arguments.index("-net") + 1], "none")
        self.assertEqual(arguments[arguments.index("-serial") + 1], "none")
        self.assertNotIn("-netdev", arguments)
        self.assertNotIn("-enable-kvm", arguments)

    def test_record_and_replay_accept_only_documented_exit_codes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for mode, exit_code in [("record", 1), ("replay", 0), ("replay", 1)]:
                with self.subTest(mode=mode):
                    effect = root / f"{mode}.effect"
                    effect.write_bytes(determinism.EXPECTED_EFFECT)
                    process = {
                        "exit_code": exit_code,
                        "timed_out": False,
                        "wall_ms": 1,
                        "stdout_hex": "",
                        "stderr": "",
                    }
                    with mock.patch.object(determinism, "run_vm", return_value=process):
                        result = determinism.run_mode(
                            "qemu", "base.qcow2", mode, root / "replay.bin", effect, 1
                        )
                    self.assertTrue(result["passed"])

    def test_bad_effect_exit_and_timeout_are_rejected(self):
        cases = [
            (1, False, b"", False),
            (0, False, determinism.EXPECTED_EFFECT, False),
            (1, True, determinism.EXPECTED_EFFECT, False),
            (1, False, determinism.EXPECTED_EFFECT, True),
        ]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for exit_code, timed_out, effect_bytes, expected in cases:
                with self.subTest(exit_code=exit_code, timed_out=timed_out, effect=effect_bytes):
                    effect = root / "record.effect"
                    if effect.exists():
                        effect.unlink()
                    if effect_bytes:
                        effect.write_bytes(effect_bytes)
                    process = {
                        "exit_code": exit_code,
                        "timed_out": timed_out,
                        "wall_ms": 1,
                        "stdout_hex": "",
                        "stderr": "",
                    }
                    with mock.patch.object(determinism, "run_vm", return_value=process) as run_vm:
                        result = determinism.run_mode(
                            "qemu", "base.qcow2", "record", root / "replay.bin", effect, 1
                        )
                    self.assertEqual(result["passed"], expected)
                    arguments = run_vm.call_args.args[0]
                    icount = arguments[arguments.index("-icount") + 1]
                    self.assertIn("rr=record", icount)
                    self.assertNotIn("sleep=off", icount)

    def test_timeout_kills_the_process_group(self):
        result = determinism.run_vm(
            [sys.executable, "-c", "import time; time.sleep(30)"], 0.05
        )
        self.assertTrue(result["timed_out"])
        self.assertEqual(result["exit_code"], -9)


if __name__ == "__main__":
    unittest.main()
