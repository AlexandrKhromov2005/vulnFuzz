use std::{
    ffi::OsString,
    fs,
    io::Write,
    os::unix::{
        ffi::{OsStrExt, OsStringExt},
        fs::{PermissionsExt, symlink},
        net::{UnixListener, UnixStream},
    },
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    thread,
    time::{Duration, Instant},
};

use sha2::{Digest, Sha256};
use vulnFuzz::{
    agent::{
        ActionOutput, AgentClient, AgentClientError, AgentErrorCode, AgentLimits, AgentResponse,
        Codec, Frame, ProcessStatus, ProtocolError, WireAction,
    },
    model::{EpisodeId, StepId},
};

static NEXT_TEMP: AtomicU64 = AtomicU64::new(1);

struct RunningAgent {
    directory: PathBuf,
    workspace: PathBuf,
    socket: PathBuf,
    child: Child,
}

impl RunningAgent {
    fn start(output_limit: usize) -> Self {
        let directory = std::env::temp_dir().join(format!(
            "vuln-fuzz-agent-test-{}-{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        ));
        let workspace = directory.join("work");
        fs::create_dir_all(&workspace).unwrap();
        let socket = directory.join("control.sock");
        let child = Command::new(env!("CARGO_BIN_EXE_vuln-fuzz-agent"))
            .arg("--workspace")
            .arg(&workspace)
            .arg("--socket")
            .arg(&socket)
            .arg("--output-limit")
            .arg(output_limit.to_string())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        Self {
            directory,
            workspace,
            socket,
            child,
        }
    }

    fn connect(&self) -> AgentClient<UnixStream> {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match AgentClient::connect(&self.socket, Duration::from_secs(5)) {
                Ok(client) => return client,
                Err(error) if Instant::now() < deadline => {
                    thread::sleep(Duration::from_millis(10));
                    drop(error);
                }
                Err(error) => panic!("cannot connect to test agent: {error}"),
            }
        }
    }
}

impl Drop for RunningAgent {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = fs::remove_dir_all(&self.directory);
    }
}

fn episode() -> EpisodeId {
    "episode-0000000000000001".parse().unwrap()
}

fn step(number: u64) -> StepId {
    format!("step-{number:016}").parse().unwrap()
}

fn path_bytes(path: &Path) -> Vec<u8> {
    path.as_os_str().as_bytes().to_vec()
}

fn spawn_cat(process_ref: &str, cwd: &Path, extra_argv: Vec<Vec<u8>>) -> WireAction {
    let mut argv = vec![b"/usr/bin/cat".to_vec()];
    argv.extend(extra_argv);
    WireAction::SpawnProcess {
        action_id: format!("spawn-{process_ref}"),
        process_ref: process_ref.to_owned(),
        argv_hex: argv.into_iter().map(Into::into).collect(),
        cwd_hex: path_bytes(cwd).into(),
    }
}

#[test]
fn real_agent_preserves_binary_paths_argv_stdin_and_output() {
    let agent = RunningAgent::start(64 * 1024);
    let mut client = agent.connect();
    let input_path = agent
        .workspace
        .join(OsString::from_vec(b"input-\xff".to_vec()));
    let input = vec![0, 0xff, b'a', 0, 0x80];
    let write = WireAction::WriteFile {
        action_id: "write-binary".to_owned(),
        path_hex: path_bytes(&input_path).into(),
        data_hex: input.clone().into(),
        mode: 0o640,
    };
    let output = client
        .execute_wire(&episode(), &step(1), 0, &write)
        .unwrap();
    assert!(matches!(
        output,
        ActionOutput::WriteFile {
            bytes_written: 5,
            ..
        }
    ));
    assert_eq!(fs::read(&input_path).unwrap(), input);
    assert_eq!(
        fs::metadata(&input_path).unwrap().permissions().mode() & 0o777,
        0o640
    );

    let output = client
        .execute_wire(
            &episode(),
            &step(2),
            1,
            &spawn_cat("file-cat", &agent.workspace, vec![path_bytes(&input_path)]),
        )
        .unwrap();
    let ActionOutput::SpawnProcess { process, .. } = output else {
        panic!("unexpected spawn response");
    };
    assert!(process.identity.pid > 0);
    assert!(process.identity.start_generation > 0);
    assert!(!process.mappings.is_empty());
    let wait = client
        .wait_process(
            &episode(),
            &step(3),
            2,
            "file-cat",
            Duration::from_secs(2),
            true,
        )
        .unwrap();
    assert!(!wait.timed_out);
    assert_eq!(wait.process.status, ProcessStatus::Exited { code: 0 });
    assert_eq!(wait.process.stdout.data_hex.as_bytes(), input);
    assert!(wait.process.stdout.complete);

    let output = client
        .execute_wire(
            &episode(),
            &step(4),
            3,
            &spawn_cat("stdin-cat", &agent.workspace, Vec::new()),
        )
        .unwrap();
    assert!(matches!(output, ActionOutput::SpawnProcess { .. }));
    for (number, data, close) in [(5, vec![0, 0xff, 1], false), (6, Vec::new(), true)] {
        let action = WireAction::WriteStdin {
            action_id: format!("stdin-{number}"),
            process_ref: "stdin-cat".to_owned(),
            data_hex: data.into(),
            close_after: close,
        };
        client
            .execute_wire(&episode(), &step(number), number as usize - 1, &action)
            .unwrap();
    }
    let wait = client
        .wait_process(
            &episode(),
            &step(7),
            6,
            "stdin-cat",
            Duration::from_secs(2),
            true,
        )
        .unwrap();
    assert_eq!(wait.process.stdout.data_hex.as_bytes(), &[0, 0xff, 1]);
    assert_eq!(wait.process.status, ProcessStatus::Exited { code: 0 });

    client.shutdown(&episode(), &step(8), 7).unwrap();
}

#[test]
fn environment_is_binary_safe_and_does_not_use_a_shell() {
    let agent = RunningAgent::start(4096);
    let mut client = agent.connect();
    let set_env = WireAction::SetEnv {
        action_id: "env".to_owned(),
        name: "VF_BINARY".to_owned(),
        value_hex: vec![0xff, 0x80, b'x'].into(),
    };
    client
        .execute_wire(&episode(), &step(1), 0, &set_env)
        .unwrap();
    let spawn = WireAction::SpawnProcess {
        action_id: "env-process".to_owned(),
        process_ref: "env".to_owned(),
        argv_hex: vec![b"/usr/bin/env".to_vec().into()],
        cwd_hex: path_bytes(&agent.workspace).into(),
    };
    client
        .execute_wire(&episode(), &step(2), 1, &spawn)
        .unwrap();
    let wait = client
        .wait_process(&episode(), &step(3), 2, "env", Duration::from_secs(2), true)
        .unwrap();
    assert_eq!(
        wait.process.stdout.data_hex.as_bytes(),
        b"VF_BINARY=\xff\x80x\n"
    );

    let nul_argument = WireAction::SpawnProcess {
        action_id: "nul".to_owned(),
        process_ref: "nul".to_owned(),
        argv_hex: vec![b"/usr/bin/cat".to_vec().into(), vec![0].into()],
        cwd_hex: path_bytes(&agent.workspace).into(),
    };
    let error = client
        .execute_wire(&episode(), &step(4), 3, &nul_argument)
        .unwrap_err();
    assert!(matches!(
        error,
        AgentClientError::Agent(ref error) if error.code == AgentErrorCode::ContractViolation
    ));
}

#[test]
fn large_output_is_drained_hashed_and_truncated() {
    const INPUT_LEN: usize = 256 * 1024;
    const OUTPUT_LIMIT: usize = 1024;
    let agent = RunningAgent::start(OUTPUT_LIMIT);
    let mut client = agent.connect();
    let path = agent.workspace.join("large");
    let input = vec![0x5a; INPUT_LEN];
    let write = WireAction::WriteFile {
        action_id: "large".to_owned(),
        path_hex: path_bytes(&path).into(),
        data_hex: input.clone().into(),
        mode: 0o600,
    };
    client
        .execute_wire(&episode(), &step(1), 0, &write)
        .unwrap();
    client
        .execute_wire(
            &episode(),
            &step(2),
            1,
            &spawn_cat("large", &agent.workspace, vec![path_bytes(&path)]),
        )
        .unwrap();
    let wait = client
        .wait_process(
            &episode(),
            &step(3),
            2,
            "large",
            Duration::from_secs(2),
            true,
        )
        .unwrap();
    assert_eq!(wait.process.status, ProcessStatus::Exited { code: 0 });
    assert_eq!(wait.process.stdout.data_hex.len(), OUTPUT_LIMIT);
    assert_eq!(wait.process.stdout.total_bytes, INPUT_LEN as u64);
    assert!(wait.process.stdout.truncated);
    assert!(wait.process.stdout.complete);
    let mut expected = "sha256:".to_owned();
    for byte in Sha256::digest(&input) {
        expected.push_str(&format!("{byte:02x}"));
    }
    let expected = expected.parse().unwrap();
    assert_eq!(wait.process.stdout.digest, expected);
}

#[test]
fn rejects_workspace_traversal_and_symlink_escapes() {
    let agent = RunningAgent::start(1024);
    let mut client = agent.connect();
    let outside = agent.directory.join("outside");
    fs::create_dir(&outside).unwrap();
    symlink(&outside, agent.workspace.join("directory-link")).unwrap();
    fs::write(outside.join("target"), b"unchanged").unwrap();
    symlink(outside.join("target"), agent.workspace.join("file-link")).unwrap();

    for (number, path) in [
        agent.directory.join("escape"),
        agent.workspace.join("..").join("escape"),
        agent.workspace.join("directory-link").join("escape"),
        agent.workspace.join("file-link"),
    ]
    .into_iter()
    .enumerate()
    {
        let action = WireAction::WriteFile {
            action_id: format!("escape-{number}"),
            path_hex: path_bytes(&path).into(),
            data_hex: b"must not be written".to_vec().into(),
            mode: 0o600,
        };
        let error = client
            .execute_wire(&episode(), &step(number as u64 + 1), number, &action)
            .unwrap_err();
        assert!(matches!(
            error,
            AgentClientError::Agent(ref error) if matches!(
                error.code,
                AgentErrorCode::ContractViolation | AgentErrorCode::IoError
            )
        ));
    }
    assert_eq!(fs::read(outside.join("target")).unwrap(), b"unchanged");
    assert!(!agent.directory.join("escape").exists());
}

#[test]
fn wait_timeout_kills_and_reaps_target() {
    let agent = RunningAgent::start(1024);
    let mut client = agent.connect();
    client
        .execute_wire(
            &episode(),
            &step(1),
            0,
            &spawn_cat("hung", &agent.workspace, Vec::new()),
        )
        .unwrap();
    let wait = client
        .wait_process(
            &episode(),
            &step(2),
            1,
            "hung",
            Duration::from_millis(20),
            true,
        )
        .unwrap();
    assert!(wait.timed_out);
    assert_eq!(wait.process.status, ProcessStatus::Signaled { signal: 9 });
    assert!(agent.workspace.join("core").metadata().is_err());
}

#[test]
fn vm_only_actions_are_explicitly_unsupported() {
    let agent = RunningAgent::start(1024);
    let mut client = agent.connect();
    let checkpoint = WireAction::Checkpoint {
        action_id: "checkpoint".to_owned(),
        label: "state".to_owned(),
    };
    let error = client
        .execute_wire(&episode(), &step(1), 0, &checkpoint)
        .unwrap_err();
    assert!(matches!(
        error,
        AgentClientError::Agent(ref error) if error.code == AgentErrorCode::UnsupportedAction
    ));
}

#[test]
fn client_does_not_retry_after_a_hung_agent() {
    let directory = std::env::temp_dir().join(format!(
        "vuln-fuzz-client-test-{}-{}",
        std::process::id(),
        NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir_all(&directory).unwrap();
    let socket = directory.join("hung.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let codec = Codec::default();
        let _request = codec.read(&mut stream).unwrap();
        thread::sleep(Duration::from_millis(200));
    });
    let stream = UnixStream::connect(&socket).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_millis(20)))
        .unwrap();
    let mut client = AgentClient::new(stream);
    let error = client.shutdown(&episode(), &step(1), 0).unwrap_err();
    assert!(matches!(
        error,
        AgentClientError::Protocol(ProtocolError::Io(ref error))
            if matches!(error.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut)
    ));
    assert!(matches!(
        client.shutdown(&episode(), &step(2), 1),
        Err(AgentClientError::ConnectionUnusable)
    ));
    server.join().unwrap();
    drop(client);
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn client_rejects_a_response_with_foreign_identity() {
    let directory = std::env::temp_dir().join(format!(
        "vuln-fuzz-client-test-{}-{}",
        std::process::id(),
        NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir_all(&directory).unwrap();
    let socket = directory.join("foreign.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let codec = Codec::default();
        let request = codec.read(&mut stream).unwrap();
        let foreign = Frame::request(
            "episode-0000000000000009".parse().unwrap(),
            request.step_id().clone(),
            request.action_index(),
            request.request_id(),
            Vec::new(),
        )
        .unwrap();
        let payload = serde_json::to_vec(&AgentResponse::Error {
            error: vulnFuzz::agent::AgentError::new(
                AgentErrorCode::InternalError,
                "foreign response",
            ),
        })
        .unwrap();
        let response = Frame::response_for(&foreign, payload);
        codec.write(&mut stream, &response).unwrap();
    });
    let mut client = AgentClient::connect(&socket, Duration::from_secs(1)).unwrap();
    assert!(matches!(
        client.shutdown(&episode(), &step(1), 0),
        Err(AgentClientError::Protocol(
            ProtocolError::ResponseIdentityMismatch
        ))
    ));
    server.join().unwrap();
    drop(client);
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn malformed_json_is_an_error_response_not_a_process_action() {
    let directory = std::env::temp_dir().join(format!(
        "vuln-fuzz-client-test-{}-{}",
        std::process::id(),
        NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir_all(&directory).unwrap();
    let workspace = directory.join("work");
    fs::create_dir(&workspace).unwrap();
    let socket = directory.join("agent.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let server_workspace = workspace.clone();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut agent =
            vulnFuzz::agent::Agent::new(server_workspace, AgentLimits::default()).unwrap();
        vulnFuzz::agent::serve_stream(&mut stream, &mut agent).unwrap();
    });
    let mut stream = UnixStream::connect(&socket).unwrap();
    let codec = Codec::default();
    let request = Frame::request(
        episode(),
        step(1),
        0,
        1,
        br#"{"operation":"unknown"}"#.to_vec(),
    )
    .unwrap();
    codec.write(&mut stream, &request).unwrap();
    let response = codec.read(&mut stream).unwrap();
    let AgentResponse::Error { error } = serde_json::from_slice(response.payload()).unwrap() else {
        panic!("malformed JSON unexpectedly succeeded");
    };
    assert_eq!(error.code, AgentErrorCode::InvalidRequest);
    drop(stream);
    server.join().unwrap();
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn agent_stdio_transport_flushes_binary_frames() {
    let directory = std::env::temp_dir().join(format!(
        "vuln-fuzz-stdio-test-{}-{}",
        std::process::id(),
        NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
    ));
    let workspace = directory.join("work");
    fs::create_dir_all(&workspace).unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_vuln-fuzz-agent"))
        .arg("--workspace")
        .arg(&workspace)
        .arg("--stdio")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut input = child.stdin.take().unwrap();
    let mut output = child.stdout.take().unwrap();
    let codec = Codec::default();
    let request = Frame::request(
        episode(),
        step(1),
        0,
        1,
        serde_json::to_vec(&vulnFuzz::agent::AgentOperation::Shutdown).unwrap(),
    )
    .unwrap();
    codec.write(&mut input, &request).unwrap();
    let response = codec.read(&mut output).unwrap();
    assert!(matches!(
        serde_json::from_slice(response.payload()).unwrap(),
        AgentResponse::Success { result }
            if matches!(*result, vulnFuzz::agent::AgentResult::Shutdown)
    ));
    drop(input);
    assert!(child.wait().unwrap().success());
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn unix_socket_permissions_are_not_world_accessible() {
    let agent = RunningAgent::start(1024);
    let deadline = Instant::now() + Duration::from_secs(2);
    while !agent.socket.exists() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(
        fs::metadata(&agent.socket).unwrap().permissions().mode() & 0o777,
        0o600
    );
}

#[test]
fn client_rejects_truncated_agent_response() {
    let (client_stream, mut server_stream) = UnixStream::pair().unwrap();
    let server = thread::spawn(move || {
        let codec = Codec::default();
        let request = codec.read(&mut server_stream).unwrap();
        let response = Frame::response_for(&request, b"{}".to_vec());
        let encoded = codec.encode(&response).unwrap();
        server_stream
            .write_all(&encoded[..encoded.len() - 1])
            .unwrap();
    });
    client_stream
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    let mut client = AgentClient::new(client_stream);
    assert!(matches!(
        client.shutdown(&episode(), &step(1), 0),
        Err(AgentClientError::Protocol(ProtocolError::Truncated))
    ));
    server.join().unwrap();
}

#[test]
fn unknown_process_is_an_agent_error() {
    let agent = RunningAgent::start(1024);
    let mut client = agent.connect();
    let error = client
        .observe_process(&episode(), &step(1), 0, "missing")
        .unwrap_err();
    assert!(matches!(
        error,
        AgentClientError::Agent(ref error) if error.code == AgentErrorCode::ProcessNotFound
    ));
}

#[test]
fn direct_action_conversion_keeps_scenario_bytes() {
    let action = vulnFuzz::model::Action::WriteStdin {
        action_id: "stdin".to_owned(),
        process_ref: "process".to_owned(),
        data_hex: vec![0, 0xff].into(),
        close_after: true,
    };
    let wire = WireAction::from(&action);
    let encoded = serde_json::to_vec(&wire).unwrap();
    assert_eq!(
        serde_json::from_slice::<WireAction>(&encoded).unwrap(),
        wire
    );
}

#[test]
fn protocol_client_can_exchange_fragmented_frames() {
    let (client_stream, mut server_stream) = UnixStream::pair().unwrap();
    let server = thread::spawn(move || {
        let codec = Codec::default();
        let request = codec.read(&mut server_stream).unwrap();
        let response = Frame::response_for(
            &request,
            serde_json::to_vec(&AgentResponse::success(
                vulnFuzz::agent::AgentResult::Shutdown,
            ))
            .unwrap(),
        );
        let encoded = codec.encode(&response).unwrap();
        for byte in encoded {
            server_stream.write_all(&[byte]).unwrap();
        }
        server_stream.flush().unwrap();
    });
    let mut client = AgentClient::new(client_stream);
    client.shutdown(&episode(), &step(1), 0).unwrap();
    server.join().unwrap();
}
