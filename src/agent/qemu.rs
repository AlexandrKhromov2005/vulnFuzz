use std::{
    error::Error,
    fmt::{self, Display, Formatter},
    io::{self, BufRead, BufReader, Write},
    ops::{Deref, DerefMut},
    os::unix::net::UnixStream,
    path::Path,
    thread,
    time::{Duration, Instant},
};

use serde_json::{Value, json};

use crate::model::{Action, EpisodeId, StepId};

use super::{ActionOutput, AgentClient, AgentClientError, WireAction};

const MAX_QMP_MESSAGE_LEN: usize = 1024 * 1024;

#[derive(Debug, Clone)]
pub struct QemuAgentConfig {
    pub vmstate_device: String,
    pub writable_devices: Vec<String>,
    pub snapshot_timeout: Duration,
}

#[derive(Debug)]
pub enum QemuAgentError {
    Client(AgentClientError),
    Io(io::Error),
    Json(serde_json::Error),
    Qmp { command: String, message: String },
    InvalidResponse(&'static str),
    InvalidConfiguration(String),
    JobFailed { job_id: String, message: String },
    Timeout(&'static str),
    UnsupportedAction(&'static str),
}

impl Display for QemuAgentError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Client(error) => Display::fmt(error, formatter),
            Self::Io(error) => write!(formatter, "QMP I/O error: {error}"),
            Self::Json(error) => write!(formatter, "invalid QMP JSON: {error}"),
            Self::Qmp { command, message } => write!(formatter, "QMP {command} failed: {message}"),
            Self::InvalidResponse(message) => write!(formatter, "invalid QMP response: {message}"),
            Self::InvalidConfiguration(message) => {
                write!(formatter, "invalid QEMU agent configuration: {message}")
            }
            Self::JobFailed { job_id, message } => {
                write!(formatter, "QEMU job {job_id} failed: {message}")
            }
            Self::Timeout(operation) => write!(formatter, "QEMU operation timed out: {operation}"),
            Self::UnsupportedAction(action) => {
                write!(formatter, "QEMU agent does not support {action}")
            }
        }
    }
}

impl Error for QemuAgentError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Client(error) => Some(error),
            Self::Io(error) => Some(error),
            Self::Json(error) => Some(error),
            _ => None,
        }
    }
}

impl From<AgentClientError> for QemuAgentError {
    fn from(error: AgentClientError) -> Self {
        Self::Client(error)
    }
}

impl From<io::Error> for QemuAgentError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<serde_json::Error> for QemuAgentError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error)
    }
}

pub type QemuAgentResult<T> = Result<T, QemuAgentError>;

#[derive(Debug)]
pub struct QemuAgent {
    client: AgentClient<UnixStream>,
    qmp: QmpConnection,
    config: QemuAgentConfig,
    next_job_id: u64,
}

impl QemuAgent {
    pub fn connect(
        agent_socket: impl AsRef<Path>,
        qmp_socket: impl AsRef<Path>,
        config: QemuAgentConfig,
        io_timeout: Duration,
    ) -> QemuAgentResult<Self> {
        let client = AgentClient::connect(agent_socket, io_timeout)?;
        let qmp = UnixStream::connect(qmp_socket)?;
        Self::from_client(client, qmp, config, io_timeout)
    }

    pub fn from_client(
        client: AgentClient<UnixStream>,
        qmp: UnixStream,
        config: QemuAgentConfig,
        io_timeout: Duration,
    ) -> QemuAgentResult<Self> {
        validate_config(&config)?;
        let qmp = QmpConnection::new(qmp, io_timeout)?;
        Ok(Self {
            client,
            qmp,
            config,
            next_job_id: 1,
        })
    }

    pub fn execute(
        &mut self,
        episode_id: &EpisodeId,
        step_id: &StepId,
        action_index: usize,
        action: &Action,
    ) -> QemuAgentResult<ActionOutput> {
        self.execute_wire(episode_id, step_id, action_index, &action.into())
    }

    pub fn execute_wire(
        &mut self,
        episode_id: &EpisodeId,
        step_id: &StepId,
        action_index: usize,
        action: &WireAction,
    ) -> QemuAgentResult<ActionOutput> {
        match action {
            WireAction::Checkpoint { action_id, label } => {
                if label.is_empty() || label.len() > 128 || label.as_bytes().contains(&0) {
                    return Err(QemuAgentError::InvalidConfiguration(
                        "checkpoint label is empty, too long, or contains NUL".to_owned(),
                    ));
                }
                self.save_checkpoint(label)?;
                Ok(ActionOutput::Checkpoint {
                    action_id: action_id.clone(),
                    label: label.clone(),
                })
            }
            WireAction::AdvanceClock { .. } => {
                Err(QemuAgentError::UnsupportedAction("advance_clock"))
            }
            _ => Ok(self
                .client
                .execute_wire(episode_id, step_id, action_index, action)?),
        }
    }

    fn save_checkpoint(&mut self, label: &str) -> QemuAgentResult<()> {
        let job_id = format!("vf-checkpoint-{}", self.next_job_id);
        self.next_job_id = self
            .next_job_id
            .checked_add(1)
            .ok_or(QemuAgentError::InvalidResponse("snapshot job ID exhausted"))?;
        self.qmp.execute(
            "snapshot-save",
            json!({
                "job-id": job_id,
                "tag": label,
                "vmstate": self.config.vmstate_device,
                "devices": self.config.writable_devices,
            }),
        )?;
        let deadline = Instant::now()
            .checked_add(self.config.snapshot_timeout)
            .ok_or(QemuAgentError::InvalidConfiguration(
                "snapshot timeout overflows the monotonic clock".to_owned(),
            ))?;
        loop {
            let jobs = self.qmp.execute("query-jobs", Value::Null)?;
            let job = jobs
                .as_array()
                .and_then(|jobs| jobs.iter().find(|job| job["id"] == job_id))
                .ok_or(QemuAgentError::InvalidResponse(
                    "snapshot job disappeared before completion",
                ))?;
            match job["status"].as_str() {
                Some("concluded") => {
                    if let Some(error) = job["error"].as_str() {
                        return Err(QemuAgentError::JobFailed {
                            job_id,
                            message: error.to_owned(),
                        });
                    }
                    self.qmp.execute("job-dismiss", json!({ "id": job_id }))?;
                    return Ok(());
                }
                Some("null") | Some("aborting") => {
                    return Err(QemuAgentError::JobFailed {
                        job_id,
                        message: job["error"]
                            .as_str()
                            .unwrap_or("job was aborted")
                            .to_owned(),
                    });
                }
                Some(_) => {}
                None => {
                    return Err(QemuAgentError::InvalidResponse(
                        "snapshot job has no status",
                    ));
                }
            }
            if Instant::now() >= deadline {
                return Err(QemuAgentError::Timeout("snapshot-save"));
            }
            thread::sleep(Duration::from_millis(10));
        }
    }
}

impl Deref for QemuAgent {
    type Target = AgentClient<UnixStream>;

    fn deref(&self) -> &Self::Target {
        &self.client
    }
}

impl DerefMut for QemuAgent {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.client
    }
}

#[derive(Debug)]
struct QmpConnection {
    reader: BufReader<UnixStream>,
    writer: UnixStream,
    next_id: u64,
}

impl QmpConnection {
    fn new(stream: UnixStream, timeout: Duration) -> QemuAgentResult<Self> {
        stream.set_read_timeout(Some(timeout))?;
        stream.set_write_timeout(Some(timeout))?;
        let writer = stream.try_clone()?;
        let mut connection = Self {
            reader: BufReader::new(stream),
            writer,
            next_id: 1,
        };
        let greeting = connection.read_message()?;
        if greeting.get("QMP").is_none() {
            return Err(QemuAgentError::InvalidResponse("missing QMP greeting"));
        }
        connection.execute("qmp_capabilities", Value::Null)?;
        Ok(connection)
    }

    fn execute(&mut self, command: &str, arguments: Value) -> QemuAgentResult<Value> {
        let id = self.next_id;
        self.next_id = self
            .next_id
            .checked_add(1)
            .ok_or(QemuAgentError::InvalidResponse("QMP request ID exhausted"))?;
        let mut request = json!({ "execute": command, "id": id });
        if !arguments.is_null() {
            request["arguments"] = arguments;
        }
        self.writer.write_all(&serde_json::to_vec(&request)?)?;
        self.writer.write_all(b"\n")?;
        self.writer.flush()?;
        loop {
            let response = self.read_message()?;
            if response.get("event").is_some() {
                continue;
            }
            if response["id"] != id {
                return Err(QemuAgentError::InvalidResponse(
                    "QMP response ID does not match the request",
                ));
            }
            if let Some(error) = response.get("error") {
                return Err(QemuAgentError::Qmp {
                    command: command.to_owned(),
                    message: error["desc"]
                        .as_str()
                        .unwrap_or(&error.to_string())
                        .to_owned(),
                });
            }
            return response
                .get("return")
                .cloned()
                .ok_or(QemuAgentError::InvalidResponse("missing QMP return value"));
        }
    }

    fn read_message(&mut self) -> QemuAgentResult<Value> {
        let mut encoded = Vec::new();
        loop {
            let (available_len, found_newline) = {
                let available = self.reader.fill_buf()?;
                if available.is_empty() {
                    return Err(QemuAgentError::Io(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "QMP connection closed",
                    )));
                }
                let length = available
                    .iter()
                    .position(|byte| *byte == b'\n')
                    .map_or(available.len(), |position| position + 1);
                (length, available.get(length - 1) == Some(&b'\n'))
            };
            if encoded.len().saturating_add(available_len) > MAX_QMP_MESSAGE_LEN {
                return Err(QemuAgentError::InvalidResponse(
                    "QMP message exceeds the implementation limit",
                ));
            }
            encoded.extend_from_slice(&self.reader.buffer()[..available_len]);
            self.reader.consume(available_len);
            if found_newline {
                return Ok(serde_json::from_slice(&encoded)?);
            }
        }
    }
}

fn validate_config(config: &QemuAgentConfig) -> QemuAgentResult<()> {
    if config.vmstate_device.is_empty()
        || config.writable_devices.is_empty()
        || config
            .writable_devices
            .iter()
            .any(|device| device.is_empty())
        || !config
            .writable_devices
            .iter()
            .any(|device| device == &config.vmstate_device)
    {
        return Err(QemuAgentError::InvalidConfiguration(
            "vmstate must be named and included in the nonempty writable device list".to_owned(),
        ));
    }
    Ok(())
}
