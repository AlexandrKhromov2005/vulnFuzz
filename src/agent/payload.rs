use serde::{Deserialize, Serialize};

use crate::model::{Action, HexBytes, HexU64, ProcessIdentity, Sha256};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum WireAction {
    WriteFile {
        action_id: String,
        path_hex: HexBytes,
        data_hex: HexBytes,
        mode: u32,
    },
    SetEnv {
        action_id: String,
        name: String,
        value_hex: HexBytes,
    },
    SpawnProcess {
        action_id: String,
        process_ref: String,
        argv_hex: Vec<HexBytes>,
        cwd_hex: HexBytes,
    },
    WriteStdin {
        action_id: String,
        process_ref: String,
        data_hex: HexBytes,
        close_after: bool,
    },
    AdvanceClock {
        action_id: String,
        delta_ns: HexU64,
    },
    Checkpoint {
        action_id: String,
        label: String,
    },
}

impl WireAction {
    pub fn action_id(&self) -> &str {
        match self {
            Self::WriteFile { action_id, .. }
            | Self::SetEnv { action_id, .. }
            | Self::SpawnProcess { action_id, .. }
            | Self::WriteStdin { action_id, .. }
            | Self::AdvanceClock { action_id, .. }
            | Self::Checkpoint { action_id, .. } => action_id,
        }
    }
}

impl From<&Action> for WireAction {
    fn from(action: &Action) -> Self {
        match action {
            Action::WriteFile {
                action_id,
                path,
                data_hex,
                mode,
            } => Self::WriteFile {
                action_id: action_id.clone(),
                path_hex: path.as_bytes().to_vec().into(),
                data_hex: data_hex.clone(),
                mode: *mode,
            },
            Action::SetEnv {
                action_id,
                name,
                value_hex,
            } => Self::SetEnv {
                action_id: action_id.clone(),
                name: name.clone(),
                value_hex: value_hex.clone(),
            },
            Action::SpawnProcess {
                action_id,
                process_ref,
                argv_hex,
                cwd,
            } => Self::SpawnProcess {
                action_id: action_id.clone(),
                process_ref: process_ref.clone(),
                argv_hex: argv_hex.clone(),
                cwd_hex: cwd.as_bytes().to_vec().into(),
            },
            Action::WriteStdin {
                action_id,
                process_ref,
                data_hex,
                close_after,
            } => Self::WriteStdin {
                action_id: action_id.clone(),
                process_ref: process_ref.clone(),
                data_hex: data_hex.clone(),
                close_after: *close_after,
            },
            Action::AdvanceClock {
                action_id,
                delta_ns,
            } => Self::AdvanceClock {
                action_id: action_id.clone(),
                delta_ns: *delta_ns,
            },
            Action::Checkpoint { action_id, label } => Self::Checkpoint {
                action_id: action_id.clone(),
                label: label.clone(),
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum AgentOperation {
    Execute {
        action: WireAction,
    },
    ObserveProcess {
        process_ref: String,
    },
    WaitProcess {
        process_ref: String,
        timeout_ms: u64,
        kill_on_timeout: bool,
    },
    TerminateProcess {
        process_ref: String,
    },
    Shutdown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentErrorCode {
    InvalidRequest,
    ContractViolation,
    IoError,
    SpawnError,
    ProcessNotFound,
    DuplicateProcess,
    ProcessClosed,
    Timeout,
    UnsupportedAction,
    InternalError,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentError {
    pub code: AgentErrorCode,
    pub message: String,
}

impl AgentError {
    pub fn new(code: AgentErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessMapping {
    pub guest_start: HexU64,
    pub guest_end: HexU64,
    pub permissions: String,
    pub offset: HexU64,
    pub device: String,
    pub inode: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_hex: Option<HexBytes>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapturedOutput {
    pub data_hex: HexBytes,
    pub digest: Sha256,
    pub total_bytes: u64,
    pub truncated: bool,
    pub complete: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum ProcessStatus {
    Running,
    Exited { code: i32 },
    Signaled { signal: u32 },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessObservation {
    pub process_ref: String,
    pub identity: ProcessIdentity,
    pub status: ProcessStatus,
    pub executable_sha256: Sha256,
    pub mappings: Vec<ProcessMapping>,
    pub stdout: CapturedOutput,
    pub stderr: CapturedOutput,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessWait {
    pub process: ProcessObservation,
    pub timed_out: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ActionOutput {
    WriteFile {
        action_id: String,
        bytes_written: usize,
        digest: Sha256,
    },
    SetEnv {
        action_id: String,
    },
    SpawnProcess {
        action_id: String,
        process: Box<ProcessObservation>,
    },
    WriteStdin {
        action_id: String,
        process_ref: String,
        bytes_written: usize,
        closed: bool,
    },
    Checkpoint {
        action_id: String,
        label: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AgentResult {
    Action { output: ActionOutput },
    Process { process: ProcessObservation },
    Wait { wait: ProcessWait },
    Shutdown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum AgentResponse {
    Success { result: Box<AgentResult> },
    Error { error: AgentError },
}

impl AgentResponse {
    pub fn success(result: AgentResult) -> Self {
        Self::Success {
            result: Box::new(result),
        }
    }

    pub fn error(error: AgentError) -> Self {
        Self::Error { error }
    }

    pub fn into_result(self) -> Result<AgentResult, AgentError> {
        match self {
            Self::Success { result } => Ok(*result),
            Self::Error { error } => Err(error),
        }
    }
}
