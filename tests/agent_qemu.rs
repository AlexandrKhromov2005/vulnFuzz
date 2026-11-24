#![cfg(target_os = "linux")]

use std::{
    fs::{self, File},
    io::{BufRead, BufReader, Write},
    os::unix::net::UnixStream,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use sha2::{Digest, Sha256};
use vulnFuzz::{
    agent::{
        ActionOutput, AgentClient, AgentClientError, AgentErrorCode, ProcessStatus, QemuAgent,
        QemuAgentConfig, QemuAgentError, WireAction,
    },
    model::{EpisodeId, StepId},
};

const READY_MARKER: &str = "vf-agent-ready";

struct TestVm {
    child: Child,
    directory: PathBuf,
    agent_socket: PathBuf,
    qmp_socket: PathBuf,
    console_log: PathBuf,
}

impl TestVm {
    fn start() -> Self {
        let kernel = std::env::var_os("VF_TEST_KERNEL").expect("VF_TEST_KERNEL is required");
        let qemu = std::env::var_os("VF_TEST_QEMU")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("build/qemu/qemu-system-x86_64"));
        let busybox = std::env::var_os("VF_TEST_BUSYBOX")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/usr/bin/busybox"));
        let qemu_img = std::env::var_os("VF_TEST_QEMU_IMG")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("build/qemu/qemu-img"));
        let directory = PathBuf::from("target").join(format!("vf03-qemu-{}", std::process::id()));
        assert!(!directory.exists(), "test directory already exists");
        fs::create_dir_all(&directory).unwrap();
        let initramfs = directory.join("agent.cpio");
        let agent = cargo_binary("vuln-fuzz-agent");
        let status = Command::new("scripts/build-agent-initramfs.sh")
            .arg(agent)
            .arg(busybox)
            .arg(&initramfs)
            .status()
            .unwrap();
        assert!(status.success(), "cannot build agent initramfs");
        let base_image = directory.join("base.qcow2");
        let overlay = directory.join("overlay.qcow2");
        let status = Command::new(&qemu_img)
            .args(["create", "-f", "qcow2"])
            .arg(&base_image)
            .arg("1M")
            .status()
            .unwrap();
        assert!(status.success(), "cannot create base image");
        let status = Command::new(&qemu_img)
            .args(["create", "-f", "qcow2", "-F", "qcow2", "-b"])
            .arg(base_image.canonicalize().unwrap())
            .arg(&overlay)
            .status()
            .unwrap();
        assert!(status.success(), "cannot create CoW overlay");

        let agent_socket = directory.join("agent.sock");
        let qmp_socket = directory.join("qmp.sock");
        let console_log = directory.join("console.log");
        let qemu_stderr = File::create(directory.join("qemu.stderr")).unwrap();
        let arguments = [
            "-no-user-config".into(),
            "-nodefaults".into(),
            "-machine".into(),
            "pc-i440fx-9.2,accel=tcg".into(),
            "-cpu".into(),
            "qemu64".into(),
            "-smp".into(),
            "1".into(),
            "-m".into(),
            "512M".into(),
            "-kernel".into(),
            PathBuf::from(kernel).into_os_string(),
            "-initrd".into(),
            initramfs.clone().into_os_string(),
            "-append".into(),
            "console=ttyS0 rdinit=/init panic=-1 loglevel=3".into(),
            "-display".into(),
            "none".into(),
            "-monitor".into(),
            "none".into(),
            "-serial".into(),
            format!("file:{}", console_log.display()).into(),
            "-parallel".into(),
            "none".into(),
            "-nic".into(),
            "none".into(),
            "-no-reboot".into(),
            "-chardev".into(),
            format!(
                "socket,id=agent,path={},server=on,wait=off",
                agent_socket.display()
            )
            .into(),
            "-device".into(),
            "virtio-serial-pci".into(),
            "-device".into(),
            "virtconsole,chardev=agent".into(),
            "-qmp".into(),
            format!("unix:{},server=on,wait=off", qmp_socket.display()).into(),
            "-blockdev".into(),
            format!(
                "driver=file,filename={},node-name=disk-file",
                overlay.display()
            )
            .into(),
            "-blockdev".into(),
            "driver=qcow2,file=disk-file,node-name=disk0".into(),
            "-device".into(),
            "virtio-blk-pci,drive=disk0".into(),
        ];
        let child = Command::new(qemu)
            .args(arguments)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::from(qemu_stderr))
            .spawn()
            .unwrap();
        Self {
            child,
            directory,
            agent_socket,
            qmp_socket,
            console_log,
        }
    }

    fn connect_agent(&mut self) -> AgentClient<UnixStream> {
        let deadline = Instant::now() + Duration::from_secs(40);
        loop {
            if self.console_log.exists()
                && fs::read_to_string(&self.console_log).is_ok_and(|log| log.contains(READY_MARKER))
            {
                if let Ok(client) =
                    AgentClient::connect(&self.agent_socket, Duration::from_secs(30))
                {
                    return client;
                }
            }
            if let Some(status) = self.child.try_wait().unwrap() {
                panic!("QEMU exited before agent readiness: {status}");
            }
            if Instant::now() >= deadline {
                panic!("guest agent did not become ready");
            }
            thread::sleep(Duration::from_millis(20));
        }
    }

    fn finish(mut self) {
        if self.child.try_wait().unwrap().is_none() {
            qmp_quit(&self.qmp_socket);
        }
        self.reap();
        self.remove_artifacts();
    }

    fn reap(&mut self) {
        if self.child.try_wait().unwrap().is_none() {
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
    }

    fn remove_artifacts(&self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}

impl Drop for TestVm {
    fn drop(&mut self) {
        self.reap();
        if thread::panicking() {
            for name in ["console.log", "qemu.stderr"] {
                let path = self.directory.join(name);
                if let Ok(contents) = fs::read_to_string(path) {
                    eprintln!("{name}:\n{contents}");
                }
            }
        }
        self.remove_artifacts();
    }
}

fn cargo_binary(name: &str) -> PathBuf {
    let output = Command::new(env!("CARGO"))
        .args(["metadata", "--no-deps", "--format-version", "1"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let metadata: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    PathBuf::from(metadata["target_directory"].as_str().unwrap())
        .join("debug")
        .join(name)
}

fn qmp_quit(path: &Path) {
    let deadline = Instant::now() + Duration::from_secs(5);
    let stream = loop {
        match UnixStream::connect(path) {
            Ok(stream) => break stream,
            Err(_) if Instant::now() < deadline => thread::sleep(Duration::from_millis(20)),
            Err(error) => panic!("cannot connect to QMP: {error}"),
        }
    };
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut writer = stream.try_clone().unwrap();
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    assert!(line.contains("QMP"), "invalid QMP greeting: {line}");
    writer
        .write_all(b"{\"execute\":\"qmp_capabilities\"}\n")
        .unwrap();
    writer.flush().unwrap();
    line.clear();
    reader.read_line(&mut line).unwrap();
    assert!(line.contains("return"), "QMP negotiation failed: {line}");
    writer.write_all(b"{\"execute\":\"quit\"}\n").unwrap();
    writer.flush().unwrap();
}

fn episode() -> EpisodeId {
    "episode-0000000000000042".parse().unwrap()
}

fn step(number: u64) -> StepId {
    format!("step-{number:016}").parse().unwrap()
}

fn spawn(process_ref: &str, arguments: &[&[u8]]) -> WireAction {
    WireAction::SpawnProcess {
        action_id: format!("spawn-{process_ref}"),
        process_ref: process_ref.to_owned(),
        argv_hex: arguments
            .iter()
            .map(|value| value.to_vec().into())
            .collect(),
        cwd_hex: b"/tmp/vf-work".to_vec().into(),
    }
}

fn wait(
    client: &mut AgentClient<UnixStream>,
    number: u64,
    process_ref: &str,
) -> vulnFuzz::agent::ProcessWait {
    client
        .wait_process(
            &episode(),
            &step(number),
            number as usize - 1,
            process_ref,
            Duration::from_secs(5),
            true,
        )
        .unwrap()
}

fn read_qmp(reader: &mut BufReader<UnixStream>) -> serde_json::Value {
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    assert!(!line.is_empty(), "QMP client closed unexpectedly");
    serde_json::from_str(&line).unwrap()
}

fn write_qmp(writer: &mut UnixStream, value: serde_json::Value) {
    writer
        .write_all(&serde_json::to_vec(&value).unwrap())
        .unwrap();
    writer.write_all(b"\n").unwrap();
    writer.flush().unwrap();
}

#[test]
fn native_qmp_checkpoint_ignores_events_and_waits_for_job_completion() {
    let directory = PathBuf::from("target").join(format!("vf03-qmp-{}", std::process::id()));
    assert!(!directory.exists());
    fs::create_dir_all(&directory).unwrap();
    let socket = directory.join("qmp.sock");
    let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
    let server = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let mut writer = stream.try_clone().unwrap();
        write_qmp(&mut writer, serde_json::json!({"QMP": {"version": {}}}));
        let mut reader = BufReader::new(stream);
        let capabilities = read_qmp(&mut reader);
        write_qmp(
            &mut writer,
            serde_json::json!({"id": capabilities["id"], "return": {}}),
        );
        let save = read_qmp(&mut reader);
        assert_eq!(save["execute"], "snapshot-save");
        assert_eq!(save["arguments"]["tag"], "checkpoint-A");
        assert_eq!(save["arguments"]["vmstate"], "disk0");
        write_qmp(
            &mut writer,
            serde_json::json!({"event": "JOB_STATUS_CHANGE", "data": {"status": "running"}}),
        );
        write_qmp(
            &mut writer,
            serde_json::json!({"id": save["id"], "return": {}}),
        );
        let running = read_qmp(&mut reader);
        assert_eq!(running["execute"], "query-jobs");
        write_qmp(
            &mut writer,
            serde_json::json!({"id": running["id"], "return": [
                {"id": "vf-checkpoint-1", "status": "running"}
            ]}),
        );
        let concluded = read_qmp(&mut reader);
        write_qmp(
            &mut writer,
            serde_json::json!({"id": concluded["id"], "return": [
                {"id": "vf-checkpoint-1", "status": "concluded"}
            ]}),
        );
        let dismiss = read_qmp(&mut reader);
        assert_eq!(dismiss["execute"], "job-dismiss");
        write_qmp(
            &mut writer,
            serde_json::json!({"id": dismiss["id"], "return": {}}),
        );
    });
    let (agent, _agent_peer) = UnixStream::pair().unwrap();
    let qmp = UnixStream::connect(&socket).unwrap();
    let config = QemuAgentConfig {
        vmstate_device: "disk0".to_owned(),
        writable_devices: vec!["disk0".to_owned()],
        snapshot_timeout: Duration::from_secs(1),
    };
    let mut client =
        QemuAgent::from_client(AgentClient::new(agent), qmp, config, Duration::from_secs(1))
            .unwrap();
    let checkpoint = WireAction::Checkpoint {
        action_id: "checkpoint".to_owned(),
        label: "checkpoint-A".to_owned(),
    };
    assert!(matches!(
        client.execute_wire(&episode(), &step(1), 0, &checkpoint),
        Ok(ActionOutput::Checkpoint { label, .. }) if label == "checkpoint-A"
    ));
    server.join().unwrap();
    drop(client);
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn qemu_checkpoint_rejects_ambiguous_device_configuration() {
    let (agent, _agent_peer) = UnixStream::pair().unwrap();
    let (qmp, _qmp_peer) = UnixStream::pair().unwrap();
    let config = QemuAgentConfig {
        vmstate_device: "vmstate".to_owned(),
        writable_devices: vec!["other-disk".to_owned()],
        snapshot_timeout: Duration::from_secs(1),
    };
    assert!(matches!(
        QemuAgent::from_client(AgentClient::new(agent), qmp, config, Duration::from_secs(1),),
        Err(QemuAgentError::InvalidConfiguration(_))
    ));
}

#[test]
#[ignore = "requires VF_TEST_KERNEL and QEMU; run explicitly for VF-03 VM acceptance"]
fn qemu_guest_agent_executes_binary_scenario_in_isolated_initramfs() {
    let mut vm = TestVm::start();
    let initramfs = vm.directory.join("agent.cpio");
    let base_image = vm.directory.join("base.qcow2");
    let image_digest_before = Sha256::digest(fs::read(&initramfs).unwrap());
    let base_digest_before = Sha256::digest(fs::read(&base_image).unwrap());
    let agent_client = vm.connect_agent();
    let qmp = UnixStream::connect(&vm.qmp_socket).unwrap();
    let config = QemuAgentConfig {
        vmstate_device: "disk0".to_owned(),
        writable_devices: vec!["disk0".to_owned()],
        snapshot_timeout: Duration::from_secs(30),
    };
    let mut client =
        QemuAgent::from_client(agent_client, qmp, config, Duration::from_secs(30)).unwrap();

    let input = [0, 0xff, b'V', b'M', 0, 0x80];
    let write = WireAction::WriteFile {
        action_id: "write".to_owned(),
        path_hex: b"/tmp/vf-work/input-\xff".to_vec().into(),
        data_hex: input.to_vec().into(),
        mode: 0o644,
    };
    client
        .execute_wire(&episode(), &step(1), 0, &write)
        .unwrap();
    let output = client
        .execute_wire(
            &episode(),
            &step(2),
            1,
            &spawn("cat", &[b"/busybox", b"cat", b"/tmp/vf-work/input-\xff"]),
        )
        .unwrap();
    let ActionOutput::SpawnProcess { process, .. } = output else {
        panic!("unexpected spawn result");
    };
    assert!(process.identity.start_generation > 0);
    let result = wait(&mut client, 3, "cat");
    assert_eq!(result.process.status, ProcessStatus::Exited { code: 0 });
    assert_eq!(result.process.stdout.data_hex.as_bytes(), &input);
    assert!(result.process.stdout.complete);

    let output = client
        .execute_wire(
            &episode(),
            &step(4),
            3,
            &spawn("stream", &[b"/busybox", b"cat"]),
        )
        .unwrap();
    let ActionOutput::SpawnProcess { process, .. } = output else {
        panic!("unexpected spawn result");
    };
    assert!(!process.mappings.is_empty());
    let stdin = WireAction::WriteStdin {
        action_id: "stdin".to_owned(),
        process_ref: "stream".to_owned(),
        data_hex: input.to_vec().into(),
        close_after: true,
    };
    client
        .execute_wire(&episode(), &step(5), 4, &stdin)
        .unwrap();
    let stream = wait(&mut client, 6, "stream");
    assert_eq!(stream.process.stdout.data_hex.as_bytes(), &input);

    client
        .execute_wire(
            &episode(),
            &step(7),
            6,
            &spawn("identity", &[b"/busybox", b"id"]),
        )
        .unwrap();
    let identity = wait(&mut client, 8, "identity");
    let identity_output = identity.process.stdout.data_hex.as_bytes();
    assert!(identity_output.starts_with(b"uid=65534"));
    assert!(
        identity_output
            .windows(9)
            .any(|window| window == b"gid=65534")
    );
    assert!(
        !identity_output
            .windows(8)
            .any(|window| window == b"groups=0")
    );

    client
        .execute_wire(
            &episode(),
            &step(9),
            8,
            &spawn("control", &[b"/busybox", b"cat", b"/dev/hvc0"]),
        )
        .unwrap();
    let control = wait(&mut client, 10, "control");
    assert!(!control.timed_out);
    assert_ne!(control.process.status, ProcessStatus::Exited { code: 0 });
    assert!(control.process.stdout.data_hex.is_empty());

    let traversal = WireAction::WriteFile {
        action_id: "traversal".to_owned(),
        path_hex: b"/tmp/vf-work/../escape".to_vec().into(),
        data_hex: b"denied".to_vec().into(),
        mode: 0o600,
    };
    assert!(matches!(
        client.execute_wire(&episode(), &step(11), 10, &traversal),
        Err(QemuAgentError::Client(AgentClientError::Agent(ref error)))
            if error.code == AgentErrorCode::ContractViolation
    ));

    let checkpoint = WireAction::Checkpoint {
        action_id: "checkpoint".to_owned(),
        label: "after-binary-scenario".to_owned(),
    };
    let checkpoint_result = client.execute_wire(&episode(), &step(12), 11, &checkpoint);
    assert!(
        matches!(checkpoint_result, Ok(ActionOutput::Checkpoint { .. })),
        "real QEMU checkpoint failed: {checkpoint_result:?}"
    );
    let duplicate_result = client.execute_wire(&episode(), &step(13), 12, &checkpoint);
    assert!(
        matches!(
            duplicate_result,
            Err(QemuAgentError::Qmp { .. } | QemuAgentError::JobFailed { .. })
        ),
        "duplicate checkpoint unexpectedly succeeded: {duplicate_result:?}"
    );

    client.shutdown(&episode(), &step(14), 13).unwrap();
    let image_digest_after = Sha256::digest(fs::read(&initramfs).unwrap());
    let base_digest_after = Sha256::digest(fs::read(&base_image).unwrap());
    assert_eq!(image_digest_before, image_digest_after);
    assert_eq!(base_digest_before, base_digest_after);
    drop(client);
    vm.finish();
}
