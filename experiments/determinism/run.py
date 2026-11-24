#!/usr/bin/env python3
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
EXPECTED_EFFECT = b"vf-disk-ok\n"
MAX_CAPTURE = 64 * 1024


def sha256_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run_checked(arguments, timeout=60):
    result = subprocess.run(arguments, capture_output=True, timeout=timeout, check=False)
    if result.returncode != 0:
        stderr = result.stderr.decode("utf-8", errors="replace")
        raise RuntimeError(f"{arguments[0]} failed ({result.returncode}): {stderr}")
    return result


def build_base_image(work_dir, qemu_img, source_name="boot.S"):
    object_path = work_dir / "boot.o"
    raw_path = work_dir / "boot.img"
    image_path = work_dir / "base.qcow2"
    run_checked([
        "as", "--32", "-o", str(object_path),
        str(ROOT / "experiments/determinism" / source_name),
    ])
    run_checked(["objcopy", "-O", "binary", "-j", ".text", str(object_path), str(raw_path)])
    if raw_path.stat().st_size != 1024:
        raise RuntimeError("boot fixture must contain exactly two 512-byte sectors")
    with raw_path.open("rb") as raw:
        if raw.read(1024)[510:512] != b"\x55\xaa":
            raise RuntimeError("boot fixture has no BIOS signature")
    run_checked([
        str(qemu_img), "convert", "-f", "raw", "-O", "qcow2",
        str(raw_path), str(image_path),
    ])
    return image_path


def common_arguments(qemu, image, temporary_snapshot=True, debug_exit=True):
    arguments = [
        str(qemu),
        "-no-user-config",
        "-nodefaults",
        "-machine", "pc-i440fx-9.2,accel=tcg",
        "-cpu", "qemu64",
        "-smp", "1",
        "-m", "16M",
        "-rtc", "base=2000-01-01T00:00:00,clock=vm",
        "-display", "none",
        "-monitor", "none",
        "-serial", "none",
        "-parallel", "none",
        "-net", "none",
        "-no-reboot",
        "-boot", "c",
    ]
    if debug_exit:
        arguments += ["-device", "isa-debug-exit,iobase=0xf4,iosize=0x04"]
    snapshot_option = ",snapshot=on" if temporary_snapshot else ""
    arguments += [
        "-drive", f"file={image},if=none{snapshot_option},id=img-direct",
        "-drive", "driver=blkreplay,if=none,image=img-direct,id=img-blkreplay",
        "-device", "ide-hd,drive=img-blkreplay",
    ]
    return arguments


def run_vm(arguments, timeout):
    started = time.monotonic()
    process = subprocess.Popen(
        arguments,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    timed_out = False
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        stdout, stderr = process.communicate()
    return {
        "exit_code": process.returncode,
        "timed_out": timed_out,
        "wall_ms": round((time.monotonic() - started) * 1000),
        "stdout_hex": stdout[:MAX_CAPTURE].hex(),
        "stderr": stderr[:MAX_CAPTURE].decode("utf-8", errors="replace"),
    }


def run_mode(qemu, image, mode, replay_file, effect_file, timeout):
    arguments = common_arguments(qemu, image) + [
        "-debugcon", f"file:{effect_file}",
        "-icount", f"shift=0,align=off,rr={mode},rrfile={replay_file}",
    ]
    result = run_vm(arguments, timeout)
    result["effect_hex"] = effect_file.read_bytes().hex() if effect_file.exists() else ""
    expected_exit_codes = {"record": {1}, "replay": {0, 1}}[mode]
    result["passed"] = (
        not result["timed_out"]
        and result["exit_code"] in expected_exit_codes
        and result["effect_hex"] == EXPECTED_EFFECT.hex()
    )
    return result


def load_lock():
    lock = {}
    for line in (ROOT / "qemu/source.lock").read_text(encoding="utf-8").splitlines():
        if line and not line.startswith("#"):
            key, value = line.split("=", 1)
            lock[key] = value
    return lock


def main():
    parser = argparse.ArgumentParser(description="Run the VF-02 QEMU record/replay spike")
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
    qemu_img_version = run_checked([qemu_img, "--version"]).stdout.decode(
        "utf-8", errors="replace"
    ).strip()
    assembler_version = run_checked(["as", "--version"]).stdout.decode(
        "utf-8", errors="replace"
    ).splitlines()[0]
    objcopy_version = run_checked(["objcopy", "--version"]).stdout.decode(
        "utf-8", errors="replace"
    ).splitlines()[0]
    lock = load_lock()
    pinned_verified = f"vulnFuzz-{lock['QEMU_COMMIT'][:12]}" in version
    if args.require_pinned and not pinned_verified:
        raise RuntimeError("QEMU was not built by scripts/build-qemu.sh from the pinned commit")

    args.work_dir.mkdir(parents=True)
    image = build_base_image(args.work_dir, qemu_img)
    base_hash_before = sha256_file(image)
    iterations = []
    for index in range(args.iterations):
        iteration_dir = args.work_dir / f"iteration-{index:02d}"
        iteration_dir.mkdir()
        replay_file = iteration_dir / "replay.bin"
        record = run_mode(qemu, image, "record", replay_file, iteration_dir / "record.effect", args.timeout)
        replay = run_mode(qemu, image, "replay", replay_file, iteration_dir / "replay.effect", args.timeout)
        iterations.append({
            "index": index,
            "record": record,
            "replay": replay,
            "matched": record["effect_hex"] == replay["effect_hex"],
            "replay_log_sha256": sha256_file(replay_file) if replay_file.exists() else None,
        })

    base_hash_after = sha256_file(image)
    passed = all(
        item["record"]["passed"] and item["replay"]["passed"] and item["matched"]
        for item in iterations
    ) and base_hash_before == base_hash_after
    report = {
        "schema_version": "vulnFuzz/qemu-determinism-v1",
        "qemu": {
            "path": qemu,
            "sha256": sha256_file(Path(qemu)),
            "version": version,
            "requested_commit": lock["QEMU_COMMIT"],
            "pinned_source_verified": pinned_verified,
        },
        "qemu_img": {
            "path": qemu_img,
            "sha256": sha256_file(Path(qemu_img)),
            "version": qemu_img_version,
        },
        "toolchain": {
            "assembler": assembler_version,
            "objcopy": objcopy_version,
        },
        "profile": {
            "arguments": common_arguments(qemu, image)[1:],
            "icount": "shift=0,align=off,rr=<record|replay>,rrfile=<iteration>/replay.bin",
        },
        "base_image_sha256_before": base_hash_before,
        "base_image_sha256_after": base_hash_after,
        "iterations": iterations,
        "deterministic_effect_replay_passed": passed,
        "vf02_complete": False,
        "not_tested": [
            "coverage plugin observations",
            "RAM/device/disk snapshot restore",
            "QMP advance_clock and controlled RNG",
            "timeout/cancel cleanup beyond process-group KILL",
        ],
    }
    report_path = args.work_dir / "report.json"
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({
        "report": str(report_path),
        "deterministic_effect_replay_passed": passed,
        "pinned_source_verified": pinned_verified,
        "vf02_complete": False,
    }, sort_keys=True))
    return 0 if passed else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
        print(f"determinism spike: {error}", file=sys.stderr)
        sys.exit(2)
