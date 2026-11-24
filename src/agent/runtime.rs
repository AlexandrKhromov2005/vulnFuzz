use std::{
    collections::BTreeMap,
    ffi::{OsStr, OsString},
    fs::{self, OpenOptions},
    io::{self, Read, Write},
    os::unix::{
        ffi::{OsStrExt, OsStringExt},
        fs::{OpenOptionsExt, PermissionsExt},
        process::{CommandExt, ExitStatusExt},
    },
    path::{Component, Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        Arc, Mutex, MutexGuard,
        mpsc::{self, RecvTimeoutError},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use sha2::{Digest, Sha256 as Sha256Hasher};

use crate::model::{HexBytes, HexU64, ProcessIdentity, Sha256};

use super::{
    ActionOutput, AgentError, AgentErrorCode, AgentOperation, AgentResponse, AgentResult,
    CapturedOutput, Codec, Frame, MessageKind, ProcessMapping, ProcessObservation, ProcessStatus,
    ProcessWait, ProtocolError, ProtocolResult, ResponseCache, WireAction,
};

const O_NOFOLLOW: i32 = 0o400000;

unsafe extern "C" {
    fn setgroups(size: usize, groups: *const u32) -> i32;
    fn setgid(gid: u32) -> i32;
    fn setuid(uid: u32) -> i32;
}

#[derive(Debug, Clone)]
pub struct AgentLimits {
    pub max_file_bytes: usize,
    pub max_stdin_bytes: usize,
    pub max_output_bytes: usize,
    pub max_argv: usize,
    pub max_arg_bytes: usize,
    pub max_environment: usize,
    pub max_processes: usize,
    pub stdin_timeout: Duration,
}

impl Default for AgentLimits {
    fn default() -> Self {
        Self {
            max_file_bytes: 4 * 1024 * 1024,
            max_stdin_bytes: 4 * 1024 * 1024,
            max_output_bytes: 64 * 1024,
            max_argv: 128,
            max_arg_bytes: 1024 * 1024,
            max_environment: 256,
            max_processes: 32,
            stdin_timeout: Duration::from_secs(5),
        }
    }
}

#[derive(Debug)]
pub struct Agent {
    workspace: PathBuf,
    limits: AgentLimits,
    environment: BTreeMap<String, Vec<u8>>,
    processes: BTreeMap<String, ProcessHandle>,
    target_uid: u32,
    target_gid: u32,
    clear_target_groups: bool,
    shutdown: bool,
}

impl Agent {
    pub fn new(workspace: impl AsRef<Path>, limits: AgentLimits) -> io::Result<Self> {
        let workspace = workspace.as_ref().canonicalize()?;
        if !workspace.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "agent workspace is not a directory",
            ));
        }
        let (uid, gid) = process_credentials()?;
        let (target_uid, target_gid) = if uid == 0 { (65534, 65534) } else { (uid, gid) };
        Ok(Self {
            workspace,
            limits,
            environment: BTreeMap::new(),
            processes: BTreeMap::new(),
            target_uid,
            target_gid,
            clear_target_groups: uid == 0,
            shutdown: false,
        })
    }

    pub fn workspace(&self) -> &Path {
        &self.workspace
    }

    pub fn target_credentials(&self) -> (u32, u32) {
        (self.target_uid, self.target_gid)
    }

    pub fn shutdown_requested(&self) -> bool {
        self.shutdown
    }

    pub fn handle(&mut self, operation: &AgentOperation) -> Result<AgentResult, AgentError> {
        match operation {
            AgentOperation::Execute { action } => self
                .execute(action)
                .map(|output| AgentResult::Action { output }),
            AgentOperation::ObserveProcess { process_ref } => self
                .observe(process_ref)
                .map(|process| AgentResult::Process { process }),
            AgentOperation::WaitProcess {
                process_ref,
                timeout_ms,
                kill_on_timeout,
            } => self
                .wait(
                    process_ref,
                    Duration::from_millis(*timeout_ms),
                    *kill_on_timeout,
                )
                .map(|wait| AgentResult::Wait { wait }),
            AgentOperation::TerminateProcess { process_ref } => self
                .terminate(process_ref)
                .map(|process| AgentResult::Process { process }),
            AgentOperation::Shutdown => {
                self.shutdown = true;
                Ok(AgentResult::Shutdown)
            }
        }
    }

    pub fn execute(&mut self, action: &WireAction) -> Result<ActionOutput, AgentError> {
        match action {
            WireAction::WriteFile {
                action_id,
                path_hex,
                data_hex,
                mode,
            } => {
                if data_hex.len() > self.limits.max_file_bytes {
                    return Err(contract_error("file payload exceeds the agent limit"));
                }
                if mode & !0o777 != 0 {
                    return Err(contract_error("file mode contains unsupported bits"));
                }
                let path = self.workspace_path(path_hex.as_bytes(), false)?;
                let mut options = OpenOptions::new();
                options
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .mode(*mode)
                    .custom_flags(O_NOFOLLOW);
                let mut file = options.open(&path).map_err(|error| {
                    AgentError::new(
                        AgentErrorCode::IoError,
                        format!("cannot open workspace file {}: {error}", path.display()),
                    )
                })?;
                file.write_all(data_hex.as_bytes())
                    .and_then(|()| file.sync_all())
                    .map_err(|error| {
                        AgentError::new(
                            AgentErrorCode::IoError,
                            format!("cannot write workspace file {}: {error}", path.display()),
                        )
                    })?;
                file.set_permissions(fs::Permissions::from_mode(*mode))
                    .map_err(|error| {
                        AgentError::new(
                            AgentErrorCode::IoError,
                            format!("cannot set workspace file mode: {error}"),
                        )
                    })?;
                Ok(ActionOutput::WriteFile {
                    action_id: action_id.clone(),
                    bytes_written: data_hex.len(),
                    digest: sha256_bytes(data_hex.as_bytes()),
                })
            }
            WireAction::SetEnv {
                action_id,
                name,
                value_hex,
            } => {
                validate_environment(name, value_hex.as_bytes())?;
                if !self.environment.contains_key(name)
                    && self.environment.len() >= self.limits.max_environment
                {
                    return Err(contract_error("environment entry limit exceeded"));
                }
                self.environment
                    .insert(name.clone(), value_hex.as_bytes().to_vec());
                Ok(ActionOutput::SetEnv {
                    action_id: action_id.clone(),
                })
            }
            WireAction::SpawnProcess {
                action_id,
                process_ref,
                argv_hex,
                cwd_hex,
            } => {
                validate_process_ref(process_ref)?;
                if self.processes.contains_key(process_ref) {
                    return Err(AgentError::new(
                        AgentErrorCode::DuplicateProcess,
                        format!("process reference {process_ref:?} is already in use"),
                    ));
                }
                if self.processes.len() >= self.limits.max_processes {
                    return Err(contract_error("process limit exceeded"));
                }
                if argv_hex.is_empty() || argv_hex.len() > self.limits.max_argv {
                    return Err(contract_error("argv is empty or exceeds the agent limit"));
                }
                if argv_hex
                    .iter()
                    .any(|argument| argument.len() > self.limits.max_arg_bytes)
                {
                    return Err(contract_error("argument exceeds the agent limit"));
                }
                let argv = argv_hex
                    .iter()
                    .map(|argument| {
                        if argument.as_bytes().contains(&0) {
                            Err(contract_error("argv cannot contain NUL bytes"))
                        } else {
                            Ok(OsString::from_vec(argument.as_bytes().to_vec()))
                        }
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                if argv[0].is_empty() {
                    return Err(contract_error("argv[0] cannot be empty"));
                }
                let cwd = self.workspace_path(cwd_hex.as_bytes(), true)?;
                let executable_sha256 = sha256_file(Path::new(&argv[0])).map_err(|error| {
                    AgentError::new(
                        AgentErrorCode::SpawnError,
                        format!("cannot hash executable: {error}"),
                    )
                })?;
                let mut command = Command::new(&argv[0]);
                command
                    .args(&argv[1..])
                    .current_dir(&cwd)
                    .env_clear()
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped());
                for (name, value) in &self.environment {
                    command.env(name, OsStr::from_bytes(value));
                }
                if self.clear_target_groups {
                    let target_uid = self.target_uid;
                    let target_gid = self.target_gid;
                    // SAFETY: the closure runs after fork and calls only async-signal-safe
                    // credential syscalls and last_os_error before exec.
                    unsafe {
                        command.pre_exec(move || {
                            // Groups must be cleared before dropping the privileged UID.
                            if setgroups(0, std::ptr::null()) != 0
                                || setgid(target_gid) != 0
                                || setuid(target_uid) != 0
                            {
                                Err(io::Error::last_os_error())
                            } else {
                                Ok(())
                            }
                        });
                    }
                } else {
                    command.uid(self.target_uid).gid(self.target_gid);
                }
                let mut child = command.spawn().map_err(|error| {
                    AgentError::new(
                        AgentErrorCode::SpawnError,
                        format!("cannot spawn argv[0]: {error}"),
                    )
                })?;
                let identity = match read_process_identity(child.id()) {
                    Ok(identity) => identity,
                    Err(error) => {
                        terminate_child(&mut child);
                        return Err(AgentError::new(
                            AgentErrorCode::SpawnError,
                            format!("cannot identify spawned process: {error}"),
                        ));
                    }
                };
                let stdout = match start_output_reader(
                    child.stdout.take().expect("stdout was piped"),
                    self.limits.max_output_bytes,
                ) {
                    Ok(reader) => reader,
                    Err(error) => {
                        terminate_child(&mut child);
                        return Err(io_error("cannot start stdout reader", error));
                    }
                };
                let stderr = match start_output_reader(
                    child.stderr.take().expect("stderr was piped"),
                    self.limits.max_output_bytes,
                ) {
                    Ok(reader) => reader,
                    Err(error) => {
                        terminate_child(&mut child);
                        return Err(io_error("cannot start stderr reader", error));
                    }
                };
                let mappings = match read_process_mappings(identity.pid) {
                    Ok(mappings) => mappings,
                    Err(error) => {
                        terminate_child(&mut child);
                        return Err(AgentError::new(
                            AgentErrorCode::SpawnError,
                            format!("cannot read initial process mappings: {error}"),
                        ));
                    }
                };
                let mut process = ProcessHandle {
                    child,
                    identity,
                    status: ProcessStatus::Running,
                    executable_sha256,
                    mappings,
                    stdout,
                    stderr,
                    stdin_open: true,
                };
                let observation = process.observation(process_ref)?;
                self.processes.insert(process_ref.clone(), process);
                Ok(ActionOutput::SpawnProcess {
                    action_id: action_id.clone(),
                    process: Box::new(observation),
                })
            }
            WireAction::WriteStdin {
                action_id,
                process_ref,
                data_hex,
                close_after,
            } => {
                if data_hex.len() > self.limits.max_stdin_bytes {
                    return Err(contract_error("stdin payload exceeds the agent limit"));
                }
                self.write_stdin(process_ref, data_hex, *close_after)?;
                Ok(ActionOutput::WriteStdin {
                    action_id: action_id.clone(),
                    process_ref: process_ref.clone(),
                    bytes_written: data_hex.len(),
                    closed: *close_after,
                })
            }
            WireAction::AdvanceClock { .. } => Err(AgentError::new(
                AgentErrorCode::UnsupportedAction,
                "advance_clock must be executed by the VM backend, not the guest agent",
            )),
            WireAction::Checkpoint { .. } => Err(AgentError::new(
                AgentErrorCode::UnsupportedAction,
                "checkpoint must be executed by the VM backend, not the guest agent",
            )),
        }
    }

    pub fn observe(&mut self, process_ref: &str) -> Result<ProcessObservation, AgentError> {
        self.process_mut(process_ref)?.observation(process_ref)
    }

    pub fn wait(
        &mut self,
        process_ref: &str,
        timeout: Duration,
        kill_on_timeout: bool,
    ) -> Result<ProcessWait, AgentError> {
        let process = self.process_mut(process_ref)?;
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or_else(|| contract_error("process wait deadline overflow"))?;
        let timed_out =
            loop {
                process.refresh_status()?;
                if process.status != ProcessStatus::Running {
                    break false;
                }
                if Instant::now() >= deadline {
                    if kill_on_timeout {
                        process.child.kill().map_err(|error| {
                            io_error("cannot kill process after timeout", error)
                        })?;
                        let status = process.child.wait().map_err(|error| {
                            io_error("cannot reap process after timeout", error)
                        })?;
                        process.status = process_status(status);
                    }
                    break true;
                }
                thread::sleep(Duration::from_millis(2).min(timeout));
            };
        let observation = process.observation(process_ref)?;
        Ok(ProcessWait {
            process: observation,
            timed_out,
        })
    }

    pub fn terminate(&mut self, process_ref: &str) -> Result<ProcessObservation, AgentError> {
        let process = self.process_mut(process_ref)?;
        process.refresh_status()?;
        if process.status == ProcessStatus::Running {
            process
                .child
                .kill()
                .map_err(|error| io_error("cannot kill process", error))?;
            let status = process
                .child
                .wait()
                .map_err(|error| io_error("cannot reap process", error))?;
            process.status = process_status(status);
        }
        process.observation(process_ref)
    }

    fn write_stdin(
        &mut self,
        process_ref: &str,
        data: &HexBytes,
        close_after: bool,
    ) -> Result<(), AgentError> {
        let timeout = self.limits.stdin_timeout;
        let process = self.process_mut(process_ref)?;
        if !process.stdin_open {
            return Err(AgentError::new(
                AgentErrorCode::ProcessClosed,
                "process stdin is already closed",
            ));
        }
        let mut stdin = process.child.stdin.take().ok_or_else(|| {
            AgentError::new(
                AgentErrorCode::ProcessClosed,
                "process stdin is unavailable",
            )
        })?;
        let bytes = data.as_bytes().to_vec();
        let (sender, receiver) = mpsc::sync_channel(1);
        let writer = thread::Builder::new()
            .name("vf-agent-stdin".to_owned())
            .spawn(move || {
                let result = stdin.write_all(&bytes).and_then(|()| stdin.flush());
                let returned_stdin = if close_after { None } else { Some(stdin) };
                let _ = sender.send((result, returned_stdin));
            })
            .map_err(|error| io_error("cannot start stdin writer", error))?;
        match receiver.recv_timeout(timeout) {
            Ok((result, returned_stdin)) => {
                let _ = writer.join();
                process.child.stdin = returned_stdin;
                process.stdin_open = !close_after;
                result.map_err(|error| io_error("cannot write process stdin", error))
            }
            Err(RecvTimeoutError::Timeout) => {
                process.stdin_open = false;
                terminate_child(&mut process.child);
                process.status = process
                    .child
                    .try_wait()
                    .ok()
                    .flatten()
                    .map_or(ProcessStatus::Signaled { signal: 9 }, process_status);
                Err(AgentError::new(
                    AgentErrorCode::Timeout,
                    "stdin write timed out; the target process was killed",
                ))
            }
            Err(RecvTimeoutError::Disconnected) => Err(io_error(
                "stdin writer disconnected",
                io::Error::new(io::ErrorKind::BrokenPipe, "stdin writer disconnected"),
            )),
        }
    }

    fn process_mut(&mut self, process_ref: &str) -> Result<&mut ProcessHandle, AgentError> {
        self.processes.get_mut(process_ref).ok_or_else(|| {
            AgentError::new(
                AgentErrorCode::ProcessNotFound,
                format!("unknown process reference {process_ref:?}"),
            )
        })
    }

    fn workspace_path(&self, encoded: &[u8], allow_root: bool) -> Result<PathBuf, AgentError> {
        if encoded.contains(&0) {
            return Err(contract_error("guest path cannot contain NUL bytes"));
        }
        let path = Path::new(OsStr::from_bytes(encoded));
        if !path.is_absolute() {
            return Err(contract_error("guest path must be absolute"));
        }
        for component in path.components() {
            if !matches!(component, Component::RootDir | Component::Normal(_)) {
                return Err(contract_error("guest path contains a forbidden component"));
            }
        }
        let relative = path
            .strip_prefix(&self.workspace)
            .map_err(|_| contract_error("guest path is outside the agent workspace"))?;
        if relative.as_os_str().is_empty() && !allow_root {
            return Err(contract_error("workspace root is not a valid file path"));
        }
        let candidate = self.workspace.join(relative);
        let canonical = if allow_root {
            candidate.canonicalize().map_err(|error| {
                AgentError::new(
                    AgentErrorCode::ContractViolation,
                    format!("cannot resolve guest cwd: {error}"),
                )
            })?
        } else {
            let parent = candidate
                .parent()
                .ok_or_else(|| contract_error("workspace file does not have a parent directory"))?;
            let parent = parent.canonicalize().map_err(|error| {
                AgentError::new(
                    AgentErrorCode::ContractViolation,
                    format!("cannot resolve workspace parent: {error}"),
                )
            })?;
            parent.join(
                candidate
                    .file_name()
                    .expect("a non-root path has a file name"),
            )
        };
        if !canonical.starts_with(&self.workspace) {
            return Err(contract_error("guest path escapes the agent workspace"));
        }
        if allow_root && !canonical.is_dir() {
            return Err(contract_error("guest cwd is not a directory"));
        }
        if !allow_root
            && fs::symlink_metadata(&canonical)
                .is_ok_and(|metadata| !metadata.file_type().is_file())
        {
            return Err(contract_error("workspace target is not a regular file"));
        }
        Ok(canonical)
    }
}

impl Drop for Agent {
    fn drop(&mut self) {
        for process in self.processes.values_mut() {
            if process.status == ProcessStatus::Running {
                terminate_child(&mut process.child);
                process.status = ProcessStatus::Signaled { signal: 9 };
            }
        }
    }
}

pub fn serve_stream<S: Read + Write>(stream: &mut S, agent: &mut Agent) -> ProtocolResult<()> {
    let codec = Codec::default();
    let mut cache = ResponseCache::default();
    loop {
        let request = match codec.read(stream) {
            Ok(request) => request,
            Err(ProtocolError::Truncated) => return Ok(()),
            Err(error) => return Err(error),
        };
        if request.kind() != MessageKind::Request {
            return Err(ProtocolError::UnexpectedMessageKind {
                expected: MessageKind::Request,
                actual: request.kind(),
            });
        }
        let response = cache.respond_with(&request, || {
            let response = match serde_json::from_slice::<AgentOperation>(request.payload()) {
                Ok(operation) => match agent.handle(&operation) {
                    Ok(result) => AgentResponse::success(result),
                    Err(error) => AgentResponse::error(error),
                },
                Err(error) => AgentResponse::error(AgentError::new(
                    AgentErrorCode::InvalidRequest,
                    format!("invalid agent JSON payload: {error}"),
                )),
            };
            let payload = serde_json::to_vec(&response).map_err(|error| {
                ProtocolError::Io(io::Error::new(io::ErrorKind::InvalidData, error))
            })?;
            Ok(Frame::response_for(&request, payload))
        })?;
        codec.write(stream, response)?;
        if agent.shutdown_requested() {
            return Ok(());
        }
    }
}

#[derive(Debug)]
struct ProcessHandle {
    child: Child,
    identity: ProcessIdentity,
    status: ProcessStatus,
    executable_sha256: Sha256,
    mappings: Vec<ProcessMapping>,
    stdout: OutputReader,
    stderr: OutputReader,
    stdin_open: bool,
}

impl ProcessHandle {
    fn refresh_status(&mut self) -> Result<(), AgentError> {
        if self.status == ProcessStatus::Running
            && let Some(status) = self
                .child
                .try_wait()
                .map_err(|error| io_error("cannot query process status", error))?
        {
            self.status = process_status(status);
        }
        Ok(())
    }

    fn observation(&mut self, process_ref: &str) -> Result<ProcessObservation, AgentError> {
        self.refresh_status()?;
        match read_process_mappings(self.identity.pid) {
            Ok(mappings) if !mappings.is_empty() => self.mappings = mappings,
            Ok(_) => {}
            Err(error)
                if self.status != ProcessStatus::Running
                    && error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(io_error("cannot read process mappings", error)),
        }
        if self.status != ProcessStatus::Running {
            let deadline = Instant::now() + Duration::from_millis(100);
            while !(self.stdout.capture.lock().complete && self.stderr.capture.lock().complete)
                && Instant::now() < deadline
            {
                thread::sleep(Duration::from_millis(1));
            }
        }
        self.stdout.finish_if_ready();
        self.stderr.finish_if_ready();
        Ok(ProcessObservation {
            process_ref: process_ref.to_owned(),
            identity: self.identity.clone(),
            status: self.status,
            executable_sha256: self.executable_sha256.clone(),
            mappings: self.mappings.clone(),
            stdout: self.stdout.capture.snapshot(),
            stderr: self.stderr.capture.snapshot(),
        })
    }
}

#[derive(Debug)]
struct OutputReader {
    capture: Arc<OutputCapture>,
    thread: Option<JoinHandle<()>>,
}

impl OutputReader {
    fn finish_if_ready(&mut self) {
        if self.thread.as_ref().is_some_and(JoinHandle::is_finished)
            && let Some(thread) = self.thread.take()
        {
            let _ = thread.join();
        }
    }
}

#[derive(Debug)]
struct OutputCapture {
    limit: usize,
    state: Mutex<OutputState>,
}

#[derive(Debug)]
struct OutputState {
    data: Vec<u8>,
    digest: Sha256Hasher,
    total_bytes: u64,
    complete: bool,
    error: Option<String>,
}

impl OutputCapture {
    fn new(limit: usize) -> Self {
        Self {
            limit,
            state: Mutex::new(OutputState {
                data: Vec::new(),
                digest: Sha256Hasher::new(),
                total_bytes: 0,
                complete: false,
                error: None,
            }),
        }
    }

    fn lock(&self) -> MutexGuard<'_, OutputState> {
        self.state.lock().unwrap_or_else(|error| error.into_inner())
    }

    fn append(&self, bytes: &[u8]) {
        let mut state = self.lock();
        state.digest.update(bytes);
        state.total_bytes = state.total_bytes.saturating_add(bytes.len() as u64);
        let remaining = self.limit.saturating_sub(state.data.len());
        let retained = remaining.min(bytes.len());
        state.data.extend_from_slice(&bytes[..retained]);
    }

    fn finish(&self, error: Option<io::Error>) {
        let mut state = self.lock();
        state.complete = true;
        state.error = error.map(|error| error.to_string());
    }

    fn snapshot(&self) -> CapturedOutput {
        let state = self.lock();
        CapturedOutput {
            data_hex: state.data.clone().into(),
            digest: digest_value(state.digest.clone()),
            total_bytes: state.total_bytes,
            truncated: state.total_bytes > state.data.len() as u64,
            complete: state.complete,
            error: state.error.clone(),
        }
    }
}

fn start_output_reader<R: Read + Send + 'static>(
    mut reader: R,
    limit: usize,
) -> io::Result<OutputReader> {
    let capture = Arc::new(OutputCapture::new(limit));
    let thread_capture = Arc::clone(&capture);
    let thread = thread::Builder::new()
        .name("vf-agent-output".to_owned())
        .spawn(move || {
            let mut buffer = [0u8; 8192];
            loop {
                match reader.read(&mut buffer) {
                    Ok(0) => {
                        thread_capture.finish(None);
                        return;
                    }
                    Ok(length) => thread_capture.append(&buffer[..length]),
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                    Err(error) => {
                        thread_capture.finish(Some(error));
                        return;
                    }
                }
            }
        })?;
    Ok(OutputReader {
        capture,
        thread: Some(thread),
    })
}

fn process_status(status: std::process::ExitStatus) -> ProcessStatus {
    if let Some(signal) = status.signal() {
        ProcessStatus::Signaled {
            signal: u32::try_from(signal).unwrap_or(u32::MAX),
        }
    } else {
        ProcessStatus::Exited {
            code: status.code().unwrap_or(-1),
        }
    }
}

fn terminate_child(child: &mut Child) {
    if child.try_wait().ok().flatten().is_none() {
        let _ = child.kill();
        let _ = child.wait();
    }
}

fn process_credentials() -> io::Result<(u32, u32)> {
    let status = fs::read_to_string("/proc/self/status")?;
    let id = |name: &str| {
        status
            .lines()
            .find_map(|line| line.strip_prefix(name))
            .and_then(|line| line.split_ascii_whitespace().nth(1))
            .and_then(|value| value.parse::<u32>().ok())
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("cannot parse effective {name} from /proc/self/status"),
                )
            })
    };
    Ok((id("Uid:")?, id("Gid:")?))
}

fn validate_process_ref(process_ref: &str) -> Result<(), AgentError> {
    if process_ref.is_empty() || process_ref.len() > 128 || process_ref.as_bytes().contains(&0) {
        return Err(contract_error("invalid process reference"));
    }
    Ok(())
}

fn validate_environment(name: &str, value: &[u8]) -> Result<(), AgentError> {
    if name.is_empty()
        || name.as_bytes().contains(&0)
        || name.as_bytes().contains(&b'=')
        || value.contains(&0)
    {
        return Err(contract_error("invalid environment name or value"));
    }
    Ok(())
}

fn contract_error(message: impl Into<String>) -> AgentError {
    AgentError::new(AgentErrorCode::ContractViolation, message)
}

fn io_error(context: &str, error: io::Error) -> AgentError {
    AgentError::new(AgentErrorCode::IoError, format!("{context}: {error}"))
}

fn sha256_bytes(bytes: &[u8]) -> Sha256 {
    digest_value(Sha256Hasher::new_with_prefix(bytes))
}

fn sha256_file(path: &Path) -> io::Result<Sha256> {
    let mut file = fs::File::open(path)?;
    let mut digest = Sha256Hasher::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let length = file.read(&mut buffer)?;
        if length == 0 {
            return Ok(digest_value(digest));
        }
        digest.update(&buffer[..length]);
    }
}

fn digest_value(digest: Sha256Hasher) -> Sha256 {
    let bytes = digest.finalize();
    let mut encoded = String::with_capacity(71);
    encoded.push_str("sha256:");
    for byte in bytes {
        use std::fmt::Write as _;
        write!(encoded, "{byte:02x}").expect("writing to String cannot fail");
    }
    encoded
        .parse()
        .expect("a SHA-256 digest is a valid identifier")
}

fn read_process_identity(pid: u32) -> io::Result<ProcessIdentity> {
    let stat = fs::read(format!("/proc/{pid}/stat"))?;
    let closing = stat.iter().rposition(|byte| *byte == b')').ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "process stat has no command terminator",
        )
    })?;
    let fields = stat
        .get(closing + 1..)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid process stat"))?
        .split(|byte| byte.is_ascii_whitespace())
        .filter(|field| !field.is_empty())
        .collect::<Vec<_>>();
    let start = fields.get(19).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "process stat lacks start time")
    })?;
    let start_generation = std::str::from_utf8(start)
        .ok()
        .and_then(|value| value.parse().ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid process start time"))?;
    Ok(ProcessIdentity {
        pid,
        start_generation,
        tgid: Some(pid),
    })
}

fn read_process_mappings(pid: u32) -> io::Result<Vec<ProcessMapping>> {
    let contents = fs::read(format!("/proc/{pid}/maps"))?;
    contents
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(parse_mapping)
        .collect()
}

fn parse_mapping(line: &[u8]) -> io::Result<ProcessMapping> {
    let mut cursor = 0;
    let addresses = next_mapping_field(line, &mut cursor)?;
    let permissions = next_mapping_field(line, &mut cursor)?;
    let offset = next_mapping_field(line, &mut cursor)?;
    let device = next_mapping_field(line, &mut cursor)?;
    let inode = next_mapping_field(line, &mut cursor)?;
    while line.get(cursor).is_some_and(u8::is_ascii_whitespace) {
        cursor += 1;
    }
    let path = &line[cursor..];
    let separator = addresses
        .iter()
        .position(|byte| *byte == b'-')
        .ok_or_else(|| invalid_mapping("mapping addresses have no separator"))?;
    let start = parse_hex(&addresses[..separator])?;
    let end = parse_hex(&addresses[separator + 1..])?;
    if start >= end {
        return Err(invalid_mapping("mapping range is empty or inverted"));
    }
    Ok(ProcessMapping {
        guest_start: HexU64(start),
        guest_end: HexU64(end),
        permissions: std::str::from_utf8(permissions)
            .map_err(|_| invalid_mapping("mapping permissions are not ASCII"))?
            .to_owned(),
        offset: HexU64(parse_hex(offset)?),
        device: std::str::from_utf8(device)
            .map_err(|_| invalid_mapping("mapping device is not ASCII"))?
            .to_owned(),
        inode: std::str::from_utf8(inode)
            .ok()
            .and_then(|value| value.parse().ok())
            .ok_or_else(|| invalid_mapping("invalid mapping inode"))?,
        path_hex: (!path.is_empty()).then(|| HexBytes::from(path.to_vec())),
    })
}

fn next_mapping_field<'a>(line: &'a [u8], cursor: &mut usize) -> io::Result<&'a [u8]> {
    while line.get(*cursor).is_some_and(u8::is_ascii_whitespace) {
        *cursor += 1;
    }
    let start = *cursor;
    while line
        .get(*cursor)
        .is_some_and(|byte| !byte.is_ascii_whitespace())
    {
        *cursor += 1;
    }
    if start == *cursor {
        return Err(invalid_mapping("mapping has a missing field"));
    }
    Ok(&line[start..*cursor])
}

fn parse_hex(bytes: &[u8]) -> io::Result<u64> {
    std::str::from_utf8(bytes)
        .ok()
        .and_then(|value| u64::from_str_radix(value, 16).ok())
        .ok_or_else(|| invalid_mapping("invalid hexadecimal mapping value"))
}

fn invalid_mapping(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
