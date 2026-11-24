use std::{
    collections::BTreeMap,
    error::Error,
    fmt::{self, Display, Formatter},
    io::{self, Read, Write},
};

use sha2::{Digest, Sha256};

use crate::model::{EpisodeId, StepId};

mod client;
mod payload;
mod qemu;
mod runtime;

pub use client::{AgentClient, AgentClientError, AgentClientResult};
pub use payload::{
    ActionOutput, AgentError, AgentErrorCode, AgentOperation, AgentResponse, AgentResult,
    CapturedOutput, ProcessMapping, ProcessObservation, ProcessStatus, ProcessWait, WireAction,
};
pub use qemu::{QemuAgent, QemuAgentConfig, QemuAgentError, QemuAgentResult};
pub use runtime::{Agent, AgentLimits, serve_stream};

pub const PROTOCOL_MAJOR: u8 = 1;
pub const PROTOCOL_MINOR: u8 = 0;
pub const HEADER_LEN: usize = 96;
pub const MAX_PAYLOAD_LEN: usize = 16 * 1024 * 1024;

const MAGIC: [u8; 4] = *b"VFAG";
const ID_DIGITS_LEN: usize = 16;
const EPISODE_OFFSET: usize = 28;
const STEP_OFFSET: usize = 44;
const PAYLOAD_LEN_OFFSET: usize = 60;
const DIGEST_OFFSET: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageKind {
    Request,
    Response,
}

impl MessageKind {
    fn wire_value(self) -> u8 {
        match self {
            Self::Request => 1,
            Self::Response => 2,
        }
    }

    fn from_wire(value: u8) -> ProtocolResult<Self> {
        match value {
            1 => Ok(Self::Request),
            2 => Ok(Self::Response),
            other => Err(ProtocolError::UnknownMessageKind(other)),
        }
    }
}

#[derive(Debug)]
pub enum ProtocolError {
    Truncated,
    BadMagic,
    UnsupportedVersion {
        major: u8,
        minor: u8,
    },
    UnknownMessageKind(u8),
    UnknownFlags(u8),
    InvalidHeaderLength(u16),
    NonZeroReserved,
    InvalidIdentifier(&'static str),
    InvalidRequestId,
    InvalidActionIndex,
    InvalidPayloadLimit(usize),
    PayloadTooLarge {
        declared: u64,
        limit: usize,
    },
    LengthOverflow,
    TrailingBytes {
        expected: usize,
        actual: usize,
    },
    PayloadHashMismatch,
    UnexpectedMessageKind {
        expected: MessageKind,
        actual: MessageKind,
    },
    ConflictingRequest,
    ResponseIdentityMismatch,
    Io(io::Error),
}

impl Display for ProtocolError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => formatter.write_str("truncated agent protocol frame"),
            Self::BadMagic => formatter.write_str("invalid agent protocol magic"),
            Self::UnsupportedVersion { major, minor } => {
                write!(
                    formatter,
                    "unsupported agent protocol version {major}.{minor}"
                )
            }
            Self::UnknownMessageKind(kind) => {
                write!(formatter, "unknown agent message kind {kind}")
            }
            Self::UnknownFlags(flags) => write!(formatter, "unknown agent flags {flags:#x}"),
            Self::InvalidHeaderLength(length) => {
                write!(formatter, "invalid agent header length {length}")
            }
            Self::NonZeroReserved => formatter.write_str("agent reserved bytes must be zero"),
            Self::InvalidIdentifier(name) => write!(formatter, "invalid {name}"),
            Self::InvalidRequestId => formatter.write_str("request ID must be nonzero"),
            Self::InvalidActionIndex => {
                formatter.write_str("action index exceeds the host usize range")
            }
            Self::InvalidPayloadLimit(limit) => {
                write!(formatter, "invalid agent payload limit {limit}")
            }
            Self::PayloadTooLarge { declared, limit } => {
                write!(
                    formatter,
                    "agent payload length {declared} exceeds limit {limit}"
                )
            }
            Self::LengthOverflow => formatter.write_str("agent frame length overflows usize"),
            Self::TrailingBytes { expected, actual } => write!(
                formatter,
                "agent frame length mismatch: expected {expected} bytes, got {actual}"
            ),
            Self::PayloadHashMismatch => formatter.write_str("agent payload SHA-256 mismatch"),
            Self::UnexpectedMessageKind { expected, actual } => {
                write!(formatter, "expected {expected:?}, got {actual:?}")
            }
            Self::ConflictingRequest => {
                formatter.write_str("request ID was reused for a different request")
            }
            Self::ResponseIdentityMismatch => {
                formatter.write_str("response identity does not match its request")
            }
            Self::Io(error) => write!(formatter, "agent protocol I/O error: {error}"),
        }
    }
}

impl Error for ProtocolError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for ProtocolError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

pub type ProtocolResult<T> = Result<T, ProtocolError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    episode_id: EpisodeId,
    step_id: StepId,
    action_index: usize,
    request_id: u64,
    kind: MessageKind,
    payload: Vec<u8>,
}

impl Frame {
    pub fn request(
        episode_id: EpisodeId,
        step_id: StepId,
        action_index: usize,
        request_id: u64,
        payload: Vec<u8>,
    ) -> ProtocolResult<Self> {
        if request_id == 0 {
            return Err(ProtocolError::InvalidRequestId);
        }
        Ok(Self {
            episode_id,
            step_id,
            action_index,
            request_id,
            kind: MessageKind::Request,
            payload,
        })
    }

    pub fn response_for(request: &Self, payload: Vec<u8>) -> Self {
        Self {
            episode_id: request.episode_id.clone(),
            step_id: request.step_id.clone(),
            action_index: request.action_index,
            request_id: request.request_id,
            kind: MessageKind::Response,
            payload,
        }
    }

    pub fn episode_id(&self) -> &EpisodeId {
        &self.episode_id
    }

    pub fn step_id(&self) -> &StepId {
        &self.step_id
    }

    pub fn action_index(&self) -> usize {
        self.action_index
    }

    pub fn request_id(&self) -> u64 {
        self.request_id
    }

    pub fn kind(&self) -> MessageKind {
        self.kind
    }

    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    pub fn into_payload(self) -> Vec<u8> {
        self.payload
    }
}

#[derive(Debug, Clone)]
pub struct Codec {
    max_payload_len: usize,
}

impl Codec {
    pub fn new(max_payload_len: usize) -> ProtocolResult<Self> {
        if max_payload_len > MAX_PAYLOAD_LEN {
            return Err(ProtocolError::InvalidPayloadLimit(max_payload_len));
        }
        Ok(Self { max_payload_len })
    }

    pub fn max_payload_len(&self) -> usize {
        self.max_payload_len
    }

    pub fn encode(&self, frame: &Frame) -> ProtocolResult<Vec<u8>> {
        self.check_payload_len(frame.payload.len())?;
        let payload_len =
            u32::try_from(frame.payload.len()).map_err(|_| ProtocolError::PayloadTooLarge {
                declared: frame.payload.len() as u64,
                limit: self.max_payload_len,
            })?;
        let action_index =
            u64::try_from(frame.action_index).map_err(|_| ProtocolError::InvalidActionIndex)?;
        let capacity = HEADER_LEN
            .checked_add(frame.payload.len())
            .ok_or(ProtocolError::LengthOverflow)?;
        let mut encoded = Vec::with_capacity(capacity);
        encoded.extend_from_slice(&MAGIC);
        encoded.push(PROTOCOL_MAJOR);
        encoded.push(PROTOCOL_MINOR);
        encoded.push(frame.kind.wire_value());
        encoded.push(0);
        encoded.extend_from_slice(&(HEADER_LEN as u16).to_le_bytes());
        encoded.extend_from_slice(&0u16.to_le_bytes());
        encoded.extend_from_slice(&frame.request_id.to_le_bytes());
        encoded.extend_from_slice(&action_index.to_le_bytes());
        encoded.extend_from_slice(&encode_identifier(
            frame.episode_id.as_str(),
            "episode-",
            "EpisodeId",
        )?);
        encoded.extend_from_slice(&encode_identifier(
            frame.step_id.as_str(),
            "step-",
            "StepId",
        )?);
        encoded.extend_from_slice(&payload_len.to_le_bytes());
        encoded.extend_from_slice(&Sha256::digest(&frame.payload));
        debug_assert_eq!(encoded.len(), HEADER_LEN);
        encoded.extend_from_slice(&frame.payload);
        Ok(encoded)
    }

    pub fn decode(&self, encoded: &[u8]) -> ProtocolResult<Frame> {
        if encoded.len() < HEADER_LEN {
            return Err(ProtocolError::Truncated);
        }
        let header: &[u8; HEADER_LEN] = encoded[..HEADER_LEN]
            .try_into()
            .expect("the header length was checked");
        let metadata = self.parse_header(header)?;
        let expected = HEADER_LEN
            .checked_add(metadata.payload_len)
            .ok_or(ProtocolError::LengthOverflow)?;
        if encoded.len() < expected {
            return Err(ProtocolError::Truncated);
        }
        if encoded.len() > expected {
            return Err(ProtocolError::TrailingBytes {
                expected,
                actual: encoded.len(),
            });
        }
        let payload = encoded[HEADER_LEN..].to_vec();
        verify_payload(header, &payload)?;
        Ok(metadata.into_frame(payload))
    }

    pub fn read<R: Read>(&self, reader: &mut R) -> ProtocolResult<Frame> {
        let mut header = [0u8; HEADER_LEN];
        read_exact(reader, &mut header)?;
        let metadata = self.parse_header(&header)?;
        let mut payload = vec![0; metadata.payload_len];
        read_exact(reader, &mut payload)?;
        verify_payload(&header, &payload)?;
        Ok(metadata.into_frame(payload))
    }

    pub fn write<W: Write>(&self, writer: &mut W, frame: &Frame) -> ProtocolResult<()> {
        writer.write_all(&self.encode(frame)?)?;
        writer.flush()?;
        Ok(())
    }

    fn check_payload_len(&self, payload_len: usize) -> ProtocolResult<()> {
        if payload_len > self.max_payload_len {
            return Err(ProtocolError::PayloadTooLarge {
                declared: payload_len as u64,
                limit: self.max_payload_len,
            });
        }
        Ok(())
    }

    fn parse_header(&self, header: &[u8; HEADER_LEN]) -> ProtocolResult<HeaderMetadata> {
        if header[..4] != MAGIC {
            return Err(ProtocolError::BadMagic);
        }
        let major = header[4];
        let minor = header[5];
        if major != PROTOCOL_MAJOR || minor != PROTOCOL_MINOR {
            return Err(ProtocolError::UnsupportedVersion { major, minor });
        }
        let kind = MessageKind::from_wire(header[6])?;
        if header[7] != 0 {
            return Err(ProtocolError::UnknownFlags(header[7]));
        }
        let header_len = u16::from_le_bytes([header[8], header[9]]);
        if header_len as usize != HEADER_LEN {
            return Err(ProtocolError::InvalidHeaderLength(header_len));
        }
        if header[10] != 0 || header[11] != 0 {
            return Err(ProtocolError::NonZeroReserved);
        }
        let request_id = read_u64(header, 12);
        if request_id == 0 {
            return Err(ProtocolError::InvalidRequestId);
        }
        let action_index =
            usize::try_from(read_u64(header, 20)).map_err(|_| ProtocolError::InvalidActionIndex)?;
        let episode_id = decode_identifier(
            &header[EPISODE_OFFSET..EPISODE_OFFSET + ID_DIGITS_LEN],
            "episode-",
            "EpisodeId",
        )?;
        let step_id = decode_identifier(
            &header[STEP_OFFSET..STEP_OFFSET + ID_DIGITS_LEN],
            "step-",
            "StepId",
        )?;
        let declared = u32::from_le_bytes(
            header[PAYLOAD_LEN_OFFSET..PAYLOAD_LEN_OFFSET + 4]
                .try_into()
                .expect("fixed payload length field"),
        );
        self.check_payload_len(declared as usize)?;
        let payload_len = usize::try_from(declared).map_err(|_| ProtocolError::LengthOverflow)?;
        HEADER_LEN
            .checked_add(payload_len)
            .ok_or(ProtocolError::LengthOverflow)?;
        Ok(HeaderMetadata {
            episode_id,
            step_id,
            action_index,
            request_id,
            kind,
            payload_len,
        })
    }
}

impl Default for Codec {
    fn default() -> Self {
        Self {
            max_payload_len: MAX_PAYLOAD_LEN,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct RequestKey {
    episode_id: EpisodeId,
    step_id: StepId,
    request_id: u64,
}

impl RequestKey {
    fn for_frame(frame: &Frame) -> Self {
        Self {
            episode_id: frame.episode_id.clone(),
            step_id: frame.step_id.clone(),
            request_id: frame.request_id,
        }
    }
}

#[derive(Debug, Clone)]
struct Exchange {
    request: Frame,
    response: Frame,
}

#[derive(Debug, Clone, Default)]
pub struct ResponseCache {
    exchanges: BTreeMap<RequestKey, Exchange>,
}

impl ResponseCache {
    pub fn respond_with<F>(&mut self, request: &Frame, operation: F) -> ProtocolResult<&Frame>
    where
        F: FnOnce() -> ProtocolResult<Frame>,
    {
        if request.kind != MessageKind::Request {
            return Err(ProtocolError::UnexpectedMessageKind {
                expected: MessageKind::Request,
                actual: request.kind,
            });
        }
        let key = RequestKey::for_frame(request);
        if self.exchanges.contains_key(&key) {
            let exchange = &self.exchanges[&key];
            if &exchange.request != request {
                return Err(ProtocolError::ConflictingRequest);
            }
            return Ok(&exchange.response);
        }
        let response = operation()?;
        if response.kind != MessageKind::Response {
            return Err(ProtocolError::UnexpectedMessageKind {
                expected: MessageKind::Response,
                actual: response.kind,
            });
        }
        if RequestKey::for_frame(&response) != key || response.action_index != request.action_index
        {
            return Err(ProtocolError::ResponseIdentityMismatch);
        }
        self.exchanges.insert(
            key.clone(),
            Exchange {
                request: request.clone(),
                response,
            },
        );
        Ok(&self
            .exchanges
            .get(&key)
            .expect("the exchange was just inserted")
            .response)
    }

    pub fn len(&self) -> usize {
        self.exchanges.len()
    }

    pub fn is_empty(&self) -> bool {
        self.exchanges.is_empty()
    }
}

#[derive(Debug)]
struct HeaderMetadata {
    episode_id: EpisodeId,
    step_id: StepId,
    action_index: usize,
    request_id: u64,
    kind: MessageKind,
    payload_len: usize,
}

impl HeaderMetadata {
    fn into_frame(self, payload: Vec<u8>) -> Frame {
        Frame {
            episode_id: self.episode_id,
            step_id: self.step_id,
            action_index: self.action_index,
            request_id: self.request_id,
            kind: self.kind,
            payload,
        }
    }
}

fn encode_identifier(
    identifier: &str,
    prefix: &'static str,
    name: &'static str,
) -> ProtocolResult<[u8; ID_DIGITS_LEN]> {
    let digits = identifier
        .strip_prefix(prefix)
        .ok_or(ProtocolError::InvalidIdentifier(name))?;
    let bytes = digits.as_bytes();
    let output: [u8; ID_DIGITS_LEN] = bytes
        .try_into()
        .map_err(|_| ProtocolError::InvalidIdentifier(name))?;
    if !output.iter().all(u8::is_ascii_digit) {
        return Err(ProtocolError::InvalidIdentifier(name));
    }
    Ok(output)
}

fn decode_identifier<T: std::str::FromStr>(
    digits: &[u8],
    prefix: &str,
    name: &'static str,
) -> ProtocolResult<T> {
    let digits = std::str::from_utf8(digits).map_err(|_| ProtocolError::InvalidIdentifier(name))?;
    format!("{prefix}{digits}")
        .parse::<T>()
        .map_err(|_| ProtocolError::InvalidIdentifier(name))
}

fn read_u64(header: &[u8; HEADER_LEN], offset: usize) -> u64 {
    u64::from_le_bytes(
        header[offset..offset + 8]
            .try_into()
            .expect("fixed u64 field"),
    )
}

fn verify_payload(header: &[u8; HEADER_LEN], payload: &[u8]) -> ProtocolResult<()> {
    if Sha256::digest(payload).as_slice() != &header[DIGEST_OFFSET..DIGEST_OFFSET + 32] {
        return Err(ProtocolError::PayloadHashMismatch);
    }
    Ok(())
}

fn read_exact<R: Read>(reader: &mut R, buffer: &mut [u8]) -> ProtocolResult<()> {
    reader.read_exact(buffer).map_err(|error| {
        if error.kind() == io::ErrorKind::UnexpectedEof {
            ProtocolError::Truncated
        } else {
            ProtocolError::Io(error)
        }
    })
}
