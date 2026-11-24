#!/usr/bin/env python3
import argparse
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import sys
import time

from run import (
    MAX_CAPTURE,
    ROOT,
    build_base_image,
    common_arguments,
    load_lock,
    run_checked,
    sha256_file,
)

STAGE1 = b"vf-stage-1\n"
STAGE2 = b"vf-stage-2\n"
RECORD_EFFECT = STAGE1 + STAGE2


class QmpConnection:
    def __init__(self, path, process, timeout):
        self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.socket.settimeout(0.1)
        deadline = time.monotonic() + timeout
        while True:
            try:
                self.socket.connect(str(path))
                break
            except (FileNotFoundError, ConnectionRefusedError):
                if process.poll() is not None or time.monotonic() >= deadline:
                    raise RuntimeError("QEMU did not open its QMP socket")
                time.sleep(0.01)
        self.stream = self.socket.makefile("rwb")
        greeting = self._read_message(deadline)
        if "QMP" not in greeting:
            raise RuntimeError("invalid QMP greeting")
        self.execute("qmp_capabilities", deadline=deadline)

    def _read_message(self, deadline):
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise RuntimeError("QMP response timed out")
            self.socket.settimeout(remaining)
            line = self.stream.readline()
            if not line:
                raise RuntimeError("QMP connection closed unexpectedly")
            try:
                return json.loads(line)
            except json.JSONDecodeError as error:
                raise RuntimeError("malformed QMP response") from error

    def execute(self, command, arguments=None, deadline=None):
        if deadline is None:
            deadline = time.monotonic() + 30
        request = {"execute": command}
        if arguments is not None:
            request["arguments"] = arguments
        self.stream.write(json.dumps(request).encode("utf-8") + b"\n")
        self.stream.flush()
        while True:
            response = self._read_message(deadline)
            if "event" in response:
                continue
            if "error" in response:
                raise RuntimeError(f"QMP {command} failed: {response['error']}")
            if "return" in response:
                return response["return"]

    def hmp(self, command):
        return self.execute("human-monitor-command", {"command-line": command})

    def close(self):
        self.stream.close()
        self.socket.close()


class ManagedVm:
    def __init__(self, arguments, socket_path, timeout):
        self.timeout = timeout
        self.started = time.monotonic()
        self.process = subprocess.Popen(
            arguments,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        self.qmp = None
        self.finished = False
        try:
            self.qmp = QmpConnection(socket_path, self.process, timeout)
        except Exception:
            self.terminate()
            raise

    def execute(self, command, arguments=None):
        return self.qmp.execute(command, arguments, time.monotonic() + self.timeout)

    def hmp(self, command):
        return self.qmp.execute(
            "human-monitor-command",
            {"command-line": command},
            time.monotonic() + self.timeout,
        )

    def finish(self):
        if self.finished:
            return self.result
        if self.process.poll() is None:
            self.execute("quit")
        self.qmp.close()
        try:
            stdout, stderr = self.process.communicate(timeout=self.timeout)
        except subprocess.TimeoutExpired:
            self.terminate()
            raise RuntimeError("QEMU did not exit after QMP quit")
        self.finished = True
        self.result = {
            "exit_code": self.process.returncode,
            "wall_ms": round((time.monotonic() - self.started) * 1000),
            "stdout_hex": stdout[:MAX_CAPTURE].hex(),
            "stderr": stderr[:MAX_CAPTURE].decode("utf-8", errors="replace"),
        }
        return self.result

    def terminate(self):
        if self.process.poll() is None:
            try:
                os.killpg(self.process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        self.process.communicate()
        if self.qmp is not None:
            self.qmp.close()
        self.finished = True

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        if not self.finished:
            self.terminate()


def snapshot_arguments(qemu, overlay, effect, replay_file, socket_path, mode, snapshot):
    return common_arguments(
        qemu, overlay, temporary_snapshot=False, debug_exit=False
    ) + [
        "-debugcon", f"file:{effect}",
        "-icount",
        f"shift=0,align=off,rr={mode},rrfile={replay_file},rrsnapshot={snapshot}",
        "-qmp", f"unix:{socket_path},server=on,wait=off",
        "-S",
    ]


def wait_for_effect(effect, expected, process, timeout):
    deadline = time.monotonic() + timeout
    while True:
        data = effect.read_bytes() if effect.exists() else b""
        if data == expected:
            return
        if not expected.startswith(data):
            raise RuntimeError(f"unexpected guest effect: {data!r}")
        if process.poll() is not None:
            raise RuntimeError(f"QEMU exited before the expected effect: {data!r}")
        if time.monotonic() >= deadline:
            raise RuntimeError(f"guest effect timed out: {data!r}")
        time.sleep(0.005)


def create_overlay(qemu_img, base, overlay):
    run_checked([
        str(qemu_img), "create", "-f", "qcow2", "-F", "qcow2",
        "-b", str(base.resolve()), str(overlay),
    ])


def run_record(qemu, overlay, directory, timeout):
    effect = directory / "record.effect"
    replay_file = directory / "replay.bin"
    arguments = snapshot_arguments(
        qemu, overlay, effect, replay_file, directory / "qmp.sock", "record", "initial"
    )
    with ManagedVm(arguments, directory / "qmp.sock", timeout) as vm:
        vm.execute("cont")
        wait_for_effect(effect, STAGE1, vm.process, timeout)
        vm.execute("stop")
        vm.hmp("savevm mid")
        snapshots = vm.hmp("info snapshots")
        if "initial" not in snapshots or "mid" not in snapshots:
            raise RuntimeError(f"required snapshots are missing: {snapshots}")
        vm.execute("cont")
        wait_for_effect(effect, RECORD_EFFECT, vm.process, timeout)
        vm.execute("stop")
        result = vm.finish()
    result["effect_hex"] = effect.read_bytes().hex()
    result["snapshots"] = snapshots
    result["passed"] = result["exit_code"] == 0 and result["effect_hex"] == RECORD_EFFECT.hex()
    return result


def run_replay(qemu, overlay, directory, snapshot, timeout):
    effect = directory / f"{snapshot}.effect"
    expected = RECORD_EFFECT if snapshot == "initial" else STAGE2
    arguments = snapshot_arguments(
        qemu,
        overlay,
        effect,
        directory / "replay.bin",
        directory / f"{snapshot}.sock",
        "replay",
        snapshot,
    )
    with ManagedVm(arguments, directory / f"{snapshot}.sock", timeout) as vm:
        vm.execute("cont")
        wait_for_effect(effect, expected, vm.process, timeout)
        vm.execute("stop")
        result = vm.finish()
    result["effect_hex"] = effect.read_bytes().hex() if effect.exists() else ""
    result["passed"] = result["exit_code"] == 0 and result["effect_hex"] == expected.hex()
    return result


def main():
    parser = argparse.ArgumentParser(description="Run VF-02 full snapshot replay checks")
    parser.add_argument("--qemu", default="qemu-system-x86_64")
    parser.add_argument("--qemu-img", default="qemu-img")
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--iterations", type=int, default=10)
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument("--require-pinned", action="store_true")
    args = parser.parse_args()
    if args.iterations < 1 or args.timeout <= 0:
        parser.error("iterations must be positive and timeout must be greater than zero")
    if args.work_dir.exists():
        parser.error("work directory must not exist")

    qemu = shutil.which(args.qemu)
    qemu_img = shutil.which(args.qemu_img)
    if not qemu or not qemu_img:
        parser.error("qemu-system-x86_64 and qemu-img are required")
    version = run_checked([qemu, "--version"]).stdout.decode("utf-8", errors="replace").strip()
    lock = load_lock()
    pinned_verified = f"vulnFuzz-{lock['QEMU_COMMIT'][:12]}" in version
    if args.require_pinned and not pinned_verified:
        raise RuntimeError("QEMU was not built by scripts/build-qemu.sh from the pinned commit")

    args.work_dir.mkdir(parents=True)
    base = build_base_image(args.work_dir, qemu_img, "snapshot.S")
    base_hash_before = sha256_file(base)
    iterations = []
    for index in range(args.iterations):
        directory = args.work_dir / f"iteration-{index:02d}"
        directory.mkdir()
        overlay = directory / "record-overlay.qcow2"
        create_overlay(qemu_img, base, overlay)
        record = run_record(qemu, overlay, directory, args.timeout)
        replay_file = directory / "replay.bin"
        replay_results = {}
        for snapshot in ("initial", "mid"):
            replay_directory = directory / snapshot
            replay_directory.mkdir()
            replay_overlay = replay_directory / "overlay.qcow2"
            shutil.copyfile(overlay, replay_overlay)
            shutil.copyfile(replay_file, replay_directory / "replay.bin")
            replay_results[snapshot] = run_replay(
                qemu, replay_overlay, replay_directory, snapshot, args.timeout
            )
        iterations.append({
            "index": index,
            "record": record,
            "initial_replay": replay_results["initial"],
            "mid_replay": replay_results["mid"],
            "overlay_sha256_after_record": sha256_file(overlay),
            "replay_log_sha256": sha256_file(replay_file),
            "passed": record["passed"]
            and replay_results["initial"]["passed"]
            and replay_results["mid"]["passed"],
        })

    base_hash_after = sha256_file(base)
    passed = all(item["passed"] for item in iterations) and base_hash_before == base_hash_after
    report = {
        "schema_version": "vulnFuzz/qemu-snapshot-replay-v1",
        "qemu": {
            "path": qemu,
            "sha256": sha256_file(Path(qemu)),
            "version": version,
            "requested_commit": lock["QEMU_COMMIT"],
            "pinned_source_verified": pinned_verified,
        },
        "base_image_sha256_before": base_hash_before,
        "base_image_sha256_after": base_hash_after,
        "iterations": iterations,
        "snapshot_replay_passed": passed,
        "vf02_complete": False,
        "not_tested": [
            "coverage plugin observations",
            "QMP advance_clock and controlled RNG",
            "Linux guest and runner-level cancel cleanup",
        ],
    }
    report_path = args.work_dir / "report.json"
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({
        "report": str(report_path),
        "snapshot_replay_passed": passed,
        "pinned_source_verified": pinned_verified,
        "vf02_complete": False,
    }, sort_keys=True))
    return 0 if passed else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
        print(f"snapshot replay: {error}", file=sys.stderr)
        sys.exit(2)
