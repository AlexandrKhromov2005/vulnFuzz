import json
from pathlib import Path
import tempfile
import unittest

import snapshot_replay as snapshot


class FakeProcess:
    def __init__(self, returncode=None):
        self.returncode = returncode

    def poll(self):
        return self.returncode


class FakeStream:
    def __init__(self, messages):
        self.messages = [json.dumps(message).encode() + b"\n" for message in messages]
        self.written = []

    def readline(self):
        return self.messages.pop(0) if self.messages else b""

    def write(self, data):
        self.written.append(data)

    def flush(self):
        pass


class FakeSocket:
    def settimeout(self, timeout):
        self.timeout = timeout


class SnapshotProfileTests(unittest.TestCase):
    def test_arguments_use_writable_overlay_and_named_snapshot(self):
        arguments = snapshot.snapshot_arguments(
            "qemu", "overlay.qcow2", "effect", "replay.bin", "qmp.sock", "replay", "mid"
        )
        direct_drive = arguments[arguments.index("file=overlay.qcow2,if=none,id=img-direct")]
        self.assertNotIn("snapshot=on", direct_drive)
        self.assertNotIn("isa-debug-exit", arguments)
        self.assertIn("shift=0,align=off,rr=replay,rrfile=replay.bin,rrsnapshot=mid", arguments)
        self.assertIn("driver=blkreplay,if=none,image=img-direct,id=img-blkreplay", arguments)
        self.assertIn("-S", arguments)

    def test_effect_prefix_timeout_wrong_data_and_early_exit_are_distinct(self):
        with tempfile.TemporaryDirectory() as directory:
            effect = Path(directory) / "effect"
            effect.write_bytes(snapshot.STAGE1)
            snapshot.wait_for_effect(effect, snapshot.STAGE1, FakeProcess(), 0.01)

            effect.write_bytes(b"corrupt")
            with self.assertRaisesRegex(RuntimeError, "unexpected guest effect"):
                snapshot.wait_for_effect(effect, snapshot.STAGE1, FakeProcess(), 0.01)

            effect.write_bytes(b"")
            with self.assertRaisesRegex(RuntimeError, "timed out"):
                snapshot.wait_for_effect(effect, snapshot.STAGE1, FakeProcess(), 0.01)
            with self.assertRaisesRegex(RuntimeError, "exited before"):
                snapshot.wait_for_effect(effect, snapshot.STAGE1, FakeProcess(1), 0.01)

    def test_qmp_events_are_skipped_and_errors_are_not_accepted(self):
        connection = snapshot.QmpConnection.__new__(snapshot.QmpConnection)
        connection.socket = FakeSocket()
        connection.stream = FakeStream([
            {"event": "RESUME"},
            {"return": {"status": "running"}},
        ])
        self.assertEqual(connection.execute("query-status"), {"status": "running"})

        connection.stream = FakeStream([
            {"error": {"class": "GenericError", "desc": "snapshot missing"}},
        ])
        with self.assertRaisesRegex(RuntimeError, "snapshot missing"):
            connection.execute("cont")

    def test_malformed_qmp_json_is_rejected(self):
        connection = snapshot.QmpConnection.__new__(snapshot.QmpConnection)
        connection.socket = FakeSocket()
        connection.stream = FakeStream([])
        connection.stream.messages = [b"not-json\n"]
        with self.assertRaisesRegex(RuntimeError, "malformed QMP response"):
            connection.execute("cont")


if __name__ == "__main__":
    unittest.main()
