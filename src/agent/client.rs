use std::{
    error::Error,
    fmt::{self, Display, Formatter},
    io::{self, Read, Write},
    os::unix::net::UnixStream,
    path::Path,
    time::Duration,
};

use crate::model::{Action, EpisodeId, StepId};

use super::{
    ActionOutput, AgentOperation, AgentResponse, AgentResult, Codec, Frame, MessageKind,
    ProcessObservation, ProcessWait, ProtocolError, WireAction,
};

#[derive(Debug)]
pub enum AgentClientError {
    Protocol(ProtocolError),
    Json(serde_json::Error),
    Agent(super::AgentError),
    UnexpectedResult,
    ConnectionUnusable,
}

impl Display for AgentClientError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Protocol(error) => Display::fmt(error, formatter),
            Self::Json(error) => write!(formatter, "invalid agent JSON payload: {error}"),
            Self::Agent(error) => write!(formatter, "agent {:?}: {}", error.code, error.message),
            Self::UnexpectedResult => {
                formatter.write_str("agent returned an unexpected result kind")
            }
            Self::ConnectionUnusable => formatter
                .write_str("agent connection is unusable after an ambiguous transport failure"),
        }
    }
}

impl Error for AgentClientError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Protocol(error) => Some(error),
            Self::Json(error) => Some(error),
            Self::Agent(_) | Self::UnexpectedResult | Self::ConnectionUnusable => None,
        }
    }
}

impl From<ProtocolError> for AgentClientError {
    fn from(error: ProtocolError) -> Self {
        Self::Protocol(error)
    }
}

impl From<serde_json::Error> for AgentClientError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error)
    }
}

impl From<super::AgentError> for AgentClientError {
    fn from(error: super::AgentError) -> Self {
        Self::Agent(error)
    }
}

pub type AgentClientResult<T> = Result<T, AgentClientError>;

#[derive(Debug)]
pub struct AgentClient<S> {
    stream: S,
    codec: Codec,
    next_request_id: u64,
    usable: bool,
}

impl<S: Read + Write> AgentClient<S> {
    pub fn new(stream: S) -> Self {
        Self::with_codec(stream, Codec::default())
    }

    pub fn with_codec(stream: S, codec: Codec) -> Self {
        Self {
            stream,
            codec,
            next_request_id: 1,
            usable: true,
        }
    }

    pub fn execute(
        &mut self,
        episode_id: &EpisodeId,
        step_id: &StepId,
        action_index: usize,
        action: &Action,
    ) -> AgentClientResult<ActionOutput> {
        self.execute_wire(episode_id, step_id, action_index, &action.into())
    }

    pub fn execute_wire(
        &mut self,
        episode_id: &EpisodeId,
        step_id: &StepId,
        action_index: usize,
        action: &WireAction,
    ) -> AgentClientResult<ActionOutput> {
        let result = self.call(
            episode_id,
            step_id,
            action_index,
            &AgentOperation::Execute {
                action: action.clone(),
            },
        )?;
        match result {
            AgentResult::Action { output } => Ok(output),
            _ => Err(AgentClientError::UnexpectedResult),
        }
    }

    pub fn observe_process(
        &mut self,
        episode_id: &EpisodeId,
        step_id: &StepId,
        action_index: usize,
        process_ref: &str,
    ) -> AgentClientResult<ProcessObservation> {
        let result = self.call(
            episode_id,
            step_id,
            action_index,
            &AgentOperation::ObserveProcess {
                process_ref: process_ref.to_owned(),
            },
        )?;
        match result {
            AgentResult::Process { process } => Ok(process),
            _ => Err(AgentClientError::UnexpectedResult),
        }
    }

    pub fn wait_process(
        &mut self,
        episode_id: &EpisodeId,
        step_id: &StepId,
        action_index: usize,
        process_ref: &str,
        timeout: Duration,
        kill_on_timeout: bool,
    ) -> AgentClientResult<ProcessWait> {
        let timeout_ms = u64::try_from(timeout.as_millis()).map_err(|_| {
            AgentClientError::Protocol(ProtocolError::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "process wait timeout exceeds u64 milliseconds",
            )))
        })?;
        let result = self.call(
            episode_id,
            step_id,
            action_index,
            &AgentOperation::WaitProcess {
                process_ref: process_ref.to_owned(),
                timeout_ms,
                kill_on_timeout,
            },
        )?;
        match result {
            AgentResult::Wait { wait } => Ok(wait),
            _ => Err(AgentClientError::UnexpectedResult),
        }
    }

    pub fn terminate_process(
        &mut self,
        episode_id: &EpisodeId,
        step_id: &StepId,
        action_index: usize,
        process_ref: &str,
    ) -> AgentClientResult<ProcessObservation> {
        let result = self.call(
            episode_id,
            step_id,
            action_index,
            &AgentOperation::TerminateProcess {
                process_ref: process_ref.to_owned(),
            },
        )?;
        match result {
            AgentResult::Process { process } => Ok(process),
            _ => Err(AgentClientError::UnexpectedResult),
        }
    }

    pub fn shutdown(
        &mut self,
        episode_id: &EpisodeId,
        step_id: &StepId,
        action_index: usize,
    ) -> AgentClientResult<()> {
        match self.call(episode_id, step_id, action_index, &AgentOperation::Shutdown)? {
            AgentResult::Shutdown => Ok(()),
            _ => Err(AgentClientError::UnexpectedResult),
        }
    }

    pub fn into_inner(self) -> S {
        self.stream
    }

    fn call(
        &mut self,
        episode_id: &EpisodeId,
        step_id: &StepId,
        action_index: usize,
        operation: &AgentOperation,
    ) -> AgentClientResult<AgentResult> {
        if !self.usable {
            return Err(AgentClientError::ConnectionUnusable);
        }
        let request_id = self.next_request_id;
        self.next_request_id = match self.next_request_id.checked_add(1) {
            Some(next) => next,
            None => {
                self.usable = false;
                return Err(AgentClientError::ConnectionUnusable);
            }
        };
        let payload = serde_json::to_vec(operation)?;
        let request = Frame::request(
            episode_id.clone(),
            step_id.clone(),
            action_index,
            request_id,
            payload,
        )?;
        if let Err(error) = self.codec.write(&mut self.stream, &request) {
            self.usable = false;
            return Err(error.into());
        }
        let response = match self.codec.read(&mut self.stream) {
            Ok(response) => response,
            Err(error) => {
                self.usable = false;
                return Err(error.into());
            }
        };
        if response.kind() != MessageKind::Response
            || response.episode_id() != request.episode_id()
            || response.step_id() != request.step_id()
            || response.action_index() != request.action_index()
            || response.request_id() != request.request_id()
        {
            self.usable = false;
            return Err(ProtocolError::ResponseIdentityMismatch.into());
        }
        let payload: AgentResponse = match serde_json::from_slice(response.payload()) {
            Ok(payload) => payload,
            Err(error) => {
                self.usable = false;
                return Err(error.into());
            }
        };
        Ok(payload.into_result()?)
    }
}

impl AgentClient<UnixStream> {
    pub fn connect(path: impl AsRef<Path>, io_timeout: Duration) -> io::Result<Self> {
        let stream = UnixStream::connect(path)?;
        stream.set_read_timeout(Some(io_timeout))?;
        stream.set_write_timeout(Some(io_timeout))?;
        Ok(Self::new(stream))
    }
}
