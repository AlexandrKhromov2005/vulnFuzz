use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt::{self, Display, Formatter},
    str::FromStr,
};

use serde::{Deserialize, Deserializer, Serialize, Serializer, de::DeserializeOwned};
use serde_json::Value;
use sha2::{Digest, Sha256 as Sha256Hasher};

pub const SCHEMA_VERSION: &str = "vulnFuzz/v2";
pub const GUEST_WORKSPACE: &str = "/tmp/vf-work";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContractError(String);

impl ContractError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl Display for ContractError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Error for ContractError {}

impl From<serde_json::Error> for ContractError {
    fn from(error: serde_json::Error) -> Self {
        Self::new(format!("JSON error: {error}"))
    }
}

pub type ContractResult<T> = Result<T, ContractError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HexU64(pub u64);

impl HexU64 {
    pub fn get(self) -> u64 {
        self.0
    }
}

impl Display for HexU64 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "0x{:016x}", self.0)
    }
}

impl FromStr for HexU64 {
    type Err = ContractError;

    fn from_str(value: &str) -> ContractResult<Self> {
        let digits = value
            .strip_prefix("0x")
            .ok_or_else(|| ContractError::new("HexU64 must start with 0x"))?;
        if digits.len() != 16
            || !digits
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(ContractError::new(
                "HexU64 must contain exactly 16 lowercase hexadecimal digits",
            ));
        }
        u64::from_str_radix(digits, 16)
            .map(Self)
            .map_err(|_| ContractError::new("invalid HexU64"))
    }
}

impl Serialize for HexU64 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for HexU64 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        value.parse().map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct HexBytes(Vec<u8>);

impl HexBytes {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl From<Vec<u8>> for HexBytes {
    fn from(value: Vec<u8>) -> Self {
        Self(value)
    }
}

impl Display for HexBytes {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        for byte in &self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl FromStr for HexBytes {
    type Err = ContractError;

    fn from_str(value: &str) -> ContractResult<Self> {
        if !value.len().is_multiple_of(2)
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(ContractError::new(
                "hex bytes must have even length and use lowercase hexadecimal",
            ));
        }
        let bytes = (0..value.len())
            .step_by(2)
            .map(|index| {
                u8::from_str_radix(&value[index..index + 2], 16)
                    .map_err(|_| ContractError::new("invalid hex bytes"))
            })
            .collect::<ContractResult<Vec<_>>>()?;
        Ok(Self(bytes))
    }
}

impl Serialize for HexBytes {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for HexBytes {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        value.parse().map_err(serde::de::Error::custom)
    }
}

macro_rules! sha256_id {
    ($name:ident) => {
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(String);

        impl $name {
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl Display for $name {
            fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }

        impl FromStr for $name {
            type Err = ContractError;

            fn from_str(value: &str) -> ContractResult<Self> {
                validate_sha256(value)?;
                Ok(Self(value.to_owned()))
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_str(&self.0)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                value.parse().map_err(serde::de::Error::custom)
            }
        }
    };
}

fn validate_sha256(value: &str) -> ContractResult<()> {
    let digits = value
        .strip_prefix("sha256:")
        .ok_or_else(|| ContractError::new("SHA-256 must start with sha256:"))?;
    if digits.len() != 64
        || !digits
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ContractError::new(
            "SHA-256 must contain exactly 64 lowercase hexadecimal digits",
        ));
    }
    Ok(())
}

sha256_id!(Sha256);
sha256_id!(VmImageId);
sha256_id!(SnapshotId);
sha256_id!(BinaryId);
sha256_id!(ScenarioId);
sha256_id!(AnalysisRevision);

pub type StateId = SnapshotId;

macro_rules! formatted_id {
    ($name:ident, $prefix:literal, $digits:expr) => {
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(String);

        impl $name {
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl Display for $name {
            fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }

        impl FromStr for $name {
            type Err = ContractError;

            fn from_str(value: &str) -> ContractResult<Self> {
                let digits = value.strip_prefix($prefix).ok_or_else(|| {
                    ContractError::new(concat!("identifier must start with ", $prefix))
                })?;
                let required_length: Option<usize> = $digits;
                let valid_length = match required_length {
                    Some(length) => digits.len() == length,
                    None => !digits.is_empty(),
                };
                if !valid_length || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
                    return Err(ContractError::new(concat!("invalid ", stringify!($name))));
                }
                Ok(Self(value.to_owned()))
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_str(&self.0)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                value.parse().map_err(serde::de::Error::custom)
            }
        }
    };
}

formatted_id!(EpisodeId, "episode-", Some(16));
formatted_id!(StepId, "step-", Some(16));
formatted_id!(MappingId, "map-", Some(16));
formatted_id!(DseTargetId, "dse-target-", None);
formatted_id!(DseAttemptId, "dse-attempt-", None);
formatted_id!(FindingId, "finding-", None);

pub trait ContractArtifact: Serialize + DeserializeOwned + Sized {
    const ARTIFACT: &'static str;

    fn schema_version(&self) -> &str;
    fn artifact(&self) -> &str;
    fn validate_contents(&self) -> ContractResult<()>;

    fn validate(&self) -> ContractResult<()> {
        if self.schema_version() != SCHEMA_VERSION {
            return Err(ContractError::new(format!(
                "unsupported schema version: {}",
                self.schema_version()
            )));
        }
        if self.artifact() != Self::ARTIFACT {
            return Err(ContractError::new(format!(
                "expected artifact {}, got {}",
                Self::ARTIFACT,
                self.artifact()
            )));
        }
        self.validate_contents()
    }

    fn from_json(json: &str) -> ContractResult<Self> {
        let value: Self = serde_json::from_str(json)?;
        value.validate()?;
        Ok(value)
    }

    fn to_json(&self) -> ContractResult<String> {
        self.validate()?;
        Ok(serde_json::to_string_pretty(self)?)
    }
}

fn canonical_hash_without<T: Serialize>(value: &T, omitted_field: &str) -> ContractResult<String> {
    let mut value = serde_json::to_value(value)?;
    let object = value
        .as_object_mut()
        .ok_or_else(|| ContractError::new("canonical value must be an object"))?;
    if object.remove(omitted_field).is_none() {
        return Err(ContractError::new("canonical ID field is missing"));
    }
    canonicalize_numbers(&value)?;
    let canonical = serde_json::to_vec(&value)?;
    let digest = Sha256Hasher::digest(canonical);
    let mut encoded = String::with_capacity(71);
    encoded.push_str("sha256:");
    for byte in digest {
        use fmt::Write;
        write!(encoded, "{byte:02x}").expect("writing to String cannot fail");
    }
    Ok(encoded)
}

fn canonicalize_numbers(value: &Value) -> ContractResult<()> {
    match value {
        Value::Number(number) if number.is_f64() => Err(ContractError::new(
            "floating-point numbers are not supported by Contracts v2",
        )),
        Value::Array(values) => {
            for value in values {
                canonicalize_numbers(value)?;
            }
            Ok(())
        }
        Value::Object(values) => {
            for value in values.values() {
                canonicalize_numbers(value)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestCase {
    pub schema_version: String,
    pub artifact: String,
    pub scenario_id: ScenarioId,
    pub vm: VmConfig,
    pub target: Target,
    pub actions: Vec<Action>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VmConfig {
    pub image_id: VmImageId,
    pub initial_snapshot_id: SnapshotId,
    pub profile: String,
    pub machine: String,
    pub cpu: String,
    pub memory_bytes: u64,
    pub initial_clock_ns: HexU64,
    pub devices: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Target {
    pub path: String,
    pub binary_id: Option<BinaryId>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Action {
    WriteFile {
        action_id: String,
        path: String,
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
        cwd: String,
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

impl Action {
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

impl TestCase {
    pub fn compute_scenario_id(&self) -> ContractResult<ScenarioId> {
        canonical_hash_without(self, "scenario_id")?.parse()
    }

    pub fn refresh_scenario_id(&mut self) -> ContractResult<()> {
        self.scenario_id = self.compute_scenario_id()?;
        Ok(())
    }

    pub fn apply_context_patch(&self, patch: &[PatchOperation]) -> ContractResult<Self> {
        let mut patched = self.clone();
        let mut changed = BTreeSet::new();
        for operation in patch {
            operation.source_id.validate_against(self)?;
            if operation.value_hex.len()
                != usize::try_from(operation.source_id.length)
                    .map_err(|_| ContractError::new("SourceId length exceeds host limits"))?
            {
                return Err(ContractError::new(
                    "ContextPatch value length does not match SourceId",
                ));
            }
            if !changed.insert(operation.source_id.clone()) {
                return Err(ContractError::new("duplicate SourceId in ContextPatch"));
            }
            let action = patched
                .actions
                .get_mut(operation.source_id.action_index)
                .ok_or_else(|| ContractError::new("SourceId action index is out of range"))?;
            match (action, operation.source_id.field.as_str()) {
                (Action::WriteStdin { data_hex, .. }, "stdin")
                | (Action::WriteFile { data_hex, .. }, _)
                | (
                    Action::SetEnv {
                        value_hex: data_hex,
                        ..
                    },
                    _,
                ) => *data_hex = operation.value_hex.clone(),
                (Action::AdvanceClock { delta_ns, .. }, "clock_delta") => {
                    let bytes: [u8; 8] = operation
                        .value_hex
                        .as_bytes()
                        .try_into()
                        .map_err(|_| ContractError::new("clock_delta patch must be 8 bytes"))?;
                    *delta_ns = HexU64(u64::from_le_bytes(bytes));
                }
                _ => return Err(ContractError::new("SourceId does not address its action")),
            }
        }
        patched.refresh_scenario_id()?;
        patched.validate()?;
        Ok(patched)
    }
}

impl ContractArtifact for TestCase {
    const ARTIFACT: &'static str = "test_case";

    fn schema_version(&self) -> &str {
        &self.schema_version
    }

    fn artifact(&self) -> &str {
        &self.artifact
    }

    fn validate_contents(&self) -> ContractResult<()> {
        if self.compute_scenario_id()? != self.scenario_id {
            return Err(ContractError::new("ScenarioId does not match TestCase"));
        }
        if self.vm.memory_bytes == 0
            || self.vm.profile.is_empty()
            || self.vm.machine.is_empty()
            || self.vm.cpu.is_empty()
        {
            return Err(ContractError::new("invalid deterministic VM config"));
        }
        validate_guest_path(&self.target.path, false)?;
        let mut action_ids = BTreeSet::new();
        let mut process_refs = BTreeSet::new();
        for action in &self.actions {
            if action.action_id().is_empty() || !action_ids.insert(action.action_id()) {
                return Err(ContractError::new("Action IDs must be nonempty and unique"));
            }
            match action {
                Action::WriteFile { path, .. } => validate_guest_path(path, true)?,
                Action::SetEnv { name, .. } => {
                    if name.is_empty() || name.contains(['\0', '=']) {
                        return Err(ContractError::new("invalid environment variable name"));
                    }
                }
                Action::SpawnProcess {
                    process_ref,
                    argv_hex,
                    cwd,
                    ..
                } => {
                    if process_ref.is_empty()
                        || argv_hex.is_empty()
                        || !process_refs.insert(process_ref)
                    {
                        return Err(ContractError::new(
                            "process_ref must be nonempty and unique within TestCase",
                        ));
                    }
                    validate_guest_path(cwd, false)?;
                }
                Action::WriteStdin { process_ref, .. } => {
                    if !process_refs.contains(process_ref) {
                        return Err(ContractError::new(
                            "write_stdin refers to a process not spawned by a previous action",
                        ));
                    }
                }
                Action::Checkpoint { label, .. } if label.is_empty() => {
                    return Err(ContractError::new("checkpoint label must not be empty"));
                }
                _ => {}
            }
        }
        Ok(())
    }
}

fn validate_guest_path(path: &str, workspace_only: bool) -> ContractResult<()> {
    if !path.starts_with('/') || path.contains('\0') || path.split('/').any(|part| part == "..") {
        return Err(ContractError::new("invalid guest path"));
    }
    if workspace_only
        && path != GUEST_WORKSPACE
        && !path.starts_with(&format!("{GUEST_WORKSPACE}/"))
    {
        return Err(ContractError::new(
            "guest path escapes the allowed workspace",
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlockId {
    pub binary_id: BinaryId,
    pub start_elf_va: HexU64,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutableRange {
    pub start_elf_va: HexU64,
    pub end_elf_va: HexU64,
    pub file_offset: HexU64,
    pub file_size: HexU64,
    pub memory_size: HexU64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    Validated,
    Speculative,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockSource {
    Static,
    Dynamic,
    Symbol,
    Hint,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Block {
    pub id: BlockId,
    pub end_elf_va: HexU64,
    pub instruction_start_elf_vas: Vec<HexU64>,
    pub confidence: Confidence,
    pub source: BlockSource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EdgeKind {
    Taken,
    Fallthrough,
    Jump,
    Call,
    Continuation,
    Return,
    Unresolved,
}

impl EdgeKind {
    fn canonical_name(self) -> &'static str {
        match self {
            Self::Taken => "taken",
            Self::Fallthrough => "fallthrough",
            Self::Jump => "jump",
            Self::Call => "call",
            Self::Continuation => "continuation",
            Self::Return => "return",
            Self::Unresolved => "unresolved",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Edge {
    pub from: BlockId,
    pub kind: EdgeKind,
    pub site_elf_va: HexU64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to: Option<BlockId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unresolved_reason: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnknownReason {
    Undecodable,
    TruncatedInstruction,
    ConflictingBoundaries,
    Unexplored,
    UnmappedStatic,
}

impl UnknownReason {
    fn canonical_name(self) -> &'static str {
        match self {
            Self::Undecodable => "undecodable",
            Self::TruncatedInstruction => "truncated_instruction",
            Self::ConflictingBoundaries => "conflicting_boundaries",
            Self::Unexplored => "unexplored",
            Self::UnmappedStatic => "unmapped_static",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnknownRegion {
    pub start_elf_va: HexU64,
    pub end_elf_va: HexU64,
    pub reason: UnknownReason,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnalyzerIdentity {
    pub name: String,
    pub version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnalyzerParameters {
    pub isa: String,
    pub static_recursive_descent: bool,
    pub dynamic_block_validation: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnalysisModel {
    pub schema_version: String,
    pub artifact: String,
    pub binary_id: BinaryId,
    pub analysis_revision: AnalysisRevision,
    pub analyzer: AnalyzerIdentity,
    pub parameters: AnalyzerParameters,
    pub executable_ranges: Vec<ExecutableRange>,
    pub blocks: Vec<Block>,
    pub edges: Vec<Edge>,
    pub unknown_regions: Vec<UnknownRegion>,
}

impl AnalysisModel {
    pub fn compute_analysis_revision(&self) -> ContractResult<AnalysisRevision> {
        let mut canonical = self.clone();
        canonical.executable_ranges.sort_by(|left, right| {
            left.start_elf_va
                .cmp(&right.start_elf_va)
                .then_with(|| left.file_offset.cmp(&right.file_offset))
                .then_with(|| left.end_elf_va.cmp(&right.end_elf_va))
        });
        canonical
            .blocks
            .sort_by(|left, right| left.id.cmp(&right.id));
        for block in &mut canonical.blocks {
            block.instruction_start_elf_vas.sort();
        }
        canonical.edges.sort_by(|left, right| {
            left.from
                .cmp(&right.from)
                .then_with(|| left.site_elf_va.cmp(&right.site_elf_va))
                .then_with(|| left.kind.canonical_name().cmp(right.kind.canonical_name()))
                .then_with(|| left.to.cmp(&right.to))
        });
        canonical.unknown_regions.sort_by(|left, right| {
            left.start_elf_va
                .cmp(&right.start_elf_va)
                .then_with(|| left.end_elf_va.cmp(&right.end_elf_va))
                .then_with(|| {
                    left.reason
                        .canonical_name()
                        .cmp(right.reason.canonical_name())
                })
        });
        canonical_hash_without(&canonical, "analysis_revision")?.parse()
    }

    pub fn refresh_analysis_revision(&mut self) -> ContractResult<()> {
        self.analysis_revision = self.compute_analysis_revision()?;
        Ok(())
    }

    pub fn block(&self, id: &BlockId) -> Option<&Block> {
        self.blocks.iter().find(|block| &block.id == id)
    }
}

impl ContractArtifact for AnalysisModel {
    const ARTIFACT: &'static str = "analysis_model";

    fn schema_version(&self) -> &str {
        &self.schema_version
    }

    fn artifact(&self) -> &str {
        &self.artifact
    }

    fn validate_contents(&self) -> ContractResult<()> {
        if self.compute_analysis_revision()? != self.analysis_revision {
            return Err(ContractError::new(
                "AnalysisRevision does not match AnalysisModel",
            ));
        }
        if self.analyzer.name.is_empty()
            || self.analyzer.version.is_empty()
            || self.parameters.isa != "x86_64"
        {
            return Err(ContractError::new("invalid analyzer identity or ISA"));
        }
        for range in &self.executable_ranges {
            checked_range(range.start_elf_va, range.end_elf_va, "executable range")?;
            if range.file_size > range.memory_size {
                return Err(ContractError::new("file_size exceeds memory_size"));
            }
            range
                .file_offset
                .0
                .checked_add(range.file_size.0)
                .ok_or_else(|| ContractError::new("executable file range overflows"))?;
        }
        let mut block_ids = BTreeSet::new();
        for block in &self.blocks {
            if block.id.binary_id != self.binary_id {
                return Err(ContractError::new("foreign BinaryId in block"));
            }
            checked_range(block.id.start_elf_va, block.end_elf_va, "block")?;
            if !block_ids.insert(&block.id)
                || block.instruction_start_elf_vas.is_empty()
                || block.instruction_start_elf_vas[0] != block.id.start_elf_va
                || !block
                    .instruction_start_elf_vas
                    .windows(2)
                    .all(|pair| pair[0] < pair[1])
                || block.instruction_start_elf_vas.last() >= Some(&block.end_elf_va)
            {
                return Err(ContractError::new(
                    "invalid or duplicate block instruction boundaries",
                ));
            }
            if !self.executable_ranges.iter().any(|range| {
                block.id.start_elf_va >= range.start_elf_va && block.end_elf_va <= range.end_elf_va
            }) {
                return Err(ContractError::new("block lies outside executable ranges"));
            }
        }
        for edge in &self.edges {
            let from = self.block(&edge.from).ok_or_else(|| {
                ContractError::new("edge source does not reference a known block")
            })?;
            if edge.site_elf_va < from.id.start_elf_va || edge.site_elf_va >= from.end_elf_va {
                return Err(ContractError::new(
                    "edge site lies outside its source block",
                ));
            }
            match edge.kind {
                EdgeKind::Return | EdgeKind::Unresolved => {
                    if edge.to.is_some()
                        || (edge.kind == EdgeKind::Unresolved && edge.unresolved_reason.is_none())
                    {
                        return Err(ContractError::new("invalid unresolved or return edge"));
                    }
                }
                _ => {
                    let target = edge.to.as_ref().ok_or_else(|| {
                        ContractError::new("resolved edge requires a target BlockId")
                    })?;
                    if self.block(target).is_none() || edge.unresolved_reason.is_some() {
                        return Err(ContractError::new("invalid resolved edge"));
                    }
                }
            }
        }
        for unknown in &self.unknown_regions {
            checked_range(unknown.start_elf_va, unknown.end_elf_va, "unknown region")?;
        }
        Ok(())
    }
}

fn checked_range(start: HexU64, end: HexU64, name: &str) -> ContractResult<()> {
    if start >= end {
        return Err(ContractError::new(format!("invalid {name}")));
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StepOutcome {
    Completed,
    Exited(i32),
    Signaled(u32),
    TimedOut,
    Cancelled,
    UnsupportedRuntime,
    AgentError,
    BackendError,
    SpawnError,
    NotStarted,
}

impl StepOutcome {
    fn simple_name(self) -> Option<&'static str> {
        match self {
            Self::Completed => Some("completed"),
            Self::TimedOut => Some("timed_out"),
            Self::Cancelled => Some("cancelled"),
            Self::UnsupportedRuntime => Some("unsupported_runtime"),
            Self::AgentError => Some("agent_error"),
            Self::BackendError => Some("backend_error"),
            Self::SpawnError => Some("spawn_error"),
            Self::NotStarted => Some("not_started"),
            Self::Exited(_) | Self::Signaled(_) => None,
        }
    }

    pub fn is_target_behavior(self) -> bool {
        matches!(
            self,
            Self::Completed
                | Self::Exited(_)
                | Self::Signaled(_)
                | Self::TimedOut
                | Self::Cancelled
        )
    }
}

impl Serialize for StepOutcome {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeStruct;

        if let Some(name) = self.simple_name() {
            return serializer.serialize_str(name);
        }
        match self {
            Self::Exited(code) => {
                let mut value = serializer.serialize_struct("Outcome", 2)?;
                value.serialize_field("kind", "exited")?;
                value.serialize_field("code", code)?;
                value.end()
            }
            Self::Signaled(signal) => {
                let mut value = serializer.serialize_struct("Outcome", 2)?;
                value.serialize_field("kind", "signaled")?;
                value.serialize_field("signal", signal)?;
                value.end()
            }
            _ => unreachable!("all simple outcomes returned above"),
        }
    }
}

impl<'de> Deserialize<'de> for StepOutcome {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Exited {
            kind: String,
            code: i32,
        }

        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Signaled {
            kind: String,
            signal: u32,
        }

        let value = Value::deserialize(deserializer)?;
        match value {
            Value::String(name) => match name.as_str() {
                "completed" => Ok(Self::Completed),
                "timed_out" => Ok(Self::TimedOut),
                "cancelled" => Ok(Self::Cancelled),
                "unsupported_runtime" => Ok(Self::UnsupportedRuntime),
                "agent_error" => Ok(Self::AgentError),
                "backend_error" => Ok(Self::BackendError),
                "spawn_error" => Ok(Self::SpawnError),
                "not_started" => Ok(Self::NotStarted),
                _ => Err(serde::de::Error::custom("unknown step outcome")),
            },
            Value::Object(_) if value.get("code").is_some() => {
                let outcome: Exited =
                    serde_json::from_value(value).map_err(serde::de::Error::custom)?;
                if outcome.kind != "exited" {
                    return Err(serde::de::Error::custom("invalid exited outcome"));
                }
                Ok(Self::Exited(outcome.code))
            }
            Value::Object(_) if value.get("signal").is_some() => {
                let outcome: Signaled =
                    serde_json::from_value(value).map_err(serde::de::Error::custom)?;
                if outcome.kind != "signaled" || outcome.signal == 0 {
                    return Err(serde::de::Error::custom("invalid signaled outcome"));
                }
                Ok(Self::Signaled(outcome.signal))
            }
            _ => Err(serde::de::Error::custom("invalid step outcome")),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Quality {
    Complete,
    Partial,
    Invalid,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ErrorRecord {
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actual: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoverageSnapshot {
    pub schema_version: String,
    pub artifact: String,
    pub episode_id: EpisodeId,
    pub step_id: StepId,
    pub binary_id: BinaryId,
    pub mapping_id: MappingId,
    pub analysis_revision: AnalysisRevision,
    pub covered_blocks: Vec<BlockId>,
    pub unmapped_guest_vas: Vec<HexU64>,
    pub unknown_overflow: bool,
    pub quality: Quality,
    pub errors: Vec<ErrorRecord>,
}

impl CoverageSnapshot {
    pub fn novelty_blocks(&self) -> Option<&[BlockId]> {
        (self.quality != Quality::Invalid).then_some(&self.covered_blocks)
    }

    pub fn reached(&self, block: &BlockId) -> bool {
        self.quality != Quality::Invalid && self.covered_blocks.contains(block)
    }

    pub fn validate_against(
        &self,
        episode_id: &EpisodeId,
        step_id: &StepId,
        mapping: &MappingRecord,
        model: &AnalysisModel,
    ) -> ContractResult<()> {
        if &self.episode_id != episode_id
            || &self.step_id != step_id
            || self.binary_id != model.binary_id
            || self.mapping_id != mapping.mapping_id
            || self.binary_id != mapping.binary_id
            || self.analysis_revision != model.analysis_revision
        {
            return Err(ContractError::new("foreign identity in CoverageSnapshot"));
        }
        for block in &self.covered_blocks {
            if model.block(block).is_none() {
                return Err(ContractError::new(
                    "covered block is absent from the referenced AnalysisModel",
                ));
            }
        }
        Ok(())
    }
}

impl ContractArtifact for CoverageSnapshot {
    const ARTIFACT: &'static str = "coverage_snapshot";

    fn schema_version(&self) -> &str {
        &self.schema_version
    }

    fn artifact(&self) -> &str {
        &self.artifact
    }

    fn validate_contents(&self) -> ContractResult<()> {
        if self.quality == Quality::Invalid && !self.covered_blocks.is_empty() {
            return Err(ContractError::new(
                "invalid coverage must not contain covered blocks",
            ));
        }
        if self.quality != Quality::Complete && self.errors.is_empty() {
            return Err(ContractError::new(
                "partial or invalid coverage requires a machine-readable reason",
            ));
        }
        if self.quality == Quality::Complete && self.unknown_overflow {
            return Err(ContractError::new("complete coverage cannot overflow"));
        }
        let mut blocks = BTreeSet::new();
        if !self.covered_blocks.iter().all(|block| blocks.insert(block)) {
            return Err(ContractError::new("duplicate covered block"));
        }
        if self
            .covered_blocks
            .iter()
            .any(|block| block.binary_id != self.binary_id)
        {
            return Err(ContractError::new("foreign BinaryId in covered blocks"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AddressSpaceIdentity {
    pub cr3: HexU64,
    pub generation: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asid: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessIdentity {
    pub pid: u32,
    pub start_generation: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tgid: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuestRange {
    pub guest_start: HexU64,
    pub guest_end: HexU64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MappingRecord {
    pub mapping_id: MappingId,
    pub binary_id: BinaryId,
    pub load_bias: HexU64,
    pub address_space: AddressSpaceIdentity,
    pub process: ProcessIdentity,
    pub guest_start: HexU64,
    pub guest_end: HexU64,
    pub executable_ranges: Vec<GuestRange>,
    pub first_seen_step: StepId,
    pub last_seen_step: Option<StepId>,
    pub source: String,
    pub verification: Vec<String>,
}

impl MappingRecord {
    fn validate_contents(&self) -> ContractResult<()> {
        checked_range(self.guest_start, self.guest_end, "guest mapping")?;
        if self.process.pid == 0
            || self.source.is_empty()
            || self.verification.is_empty()
            || self.executable_ranges.is_empty()
        {
            return Err(ContractError::new("unverified or invalid mapping"));
        }
        for range in &self.executable_ranges {
            checked_range(range.guest_start, range.guest_end, "guest executable range")?;
            if range.guest_start < self.guest_start || range.guest_end > self.guest_end {
                return Err(ContractError::new("executable range escapes its mapping"));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectKind {
    Stdout,
    Stderr,
    FileRead,
    FileWrite,
    Process,
    Network,
    Clock,
    Exit,
    Signal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Attribution {
    Confirmed,
    Suspected,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectEvent {
    pub kind: EffectKind,
    pub attribution: Attribution,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub episode_id: Option<EpisodeId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub step_id: Option<StepId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mapping_id: Option<MappingId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data_hex: Option<HexBytes>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest: Option<Sha256>,
    pub truncated: bool,
}

impl EffectEvent {
    fn validate_nested(&self, episode_id: &EpisodeId, step_id: &StepId) -> ContractResult<()> {
        if self.data_hex.is_some() && self.digest.is_some() {
            return Err(ContractError::new(
                "effect cannot contain both data and digest",
            ));
        }
        if self.episode_id.as_ref().is_some_and(|id| id != episode_id)
            || self.step_id.as_ref().is_some_and(|id| id != step_id)
        {
            return Err(ContractError::new("foreign identity in nested effect"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StepResult {
    pub step_id: StepId,
    pub action_index: usize,
    pub action_id: String,
    pub duration_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process_created: Option<bool>,
    pub outcome: StepOutcome,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub coverage: Option<EmbeddedCoverageSnapshot>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mapping: Option<MappingRecord>,
    pub effects: Vec<EffectEvent>,
    pub errors: Vec<ErrorRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EmbeddedCoverageSnapshot {
    pub episode_id: EpisodeId,
    pub step_id: StepId,
    pub binary_id: BinaryId,
    pub mapping_id: MappingId,
    pub analysis_revision: AnalysisRevision,
    pub covered_blocks: Vec<BlockId>,
    pub unmapped_guest_vas: Vec<HexU64>,
    pub unknown_overflow: bool,
    pub quality: Quality,
    pub errors: Vec<ErrorRecord>,
}

impl EmbeddedCoverageSnapshot {
    pub fn as_standalone(&self) -> CoverageSnapshot {
        CoverageSnapshot {
            schema_version: SCHEMA_VERSION.to_owned(),
            artifact: CoverageSnapshot::ARTIFACT.to_owned(),
            episode_id: self.episode_id.clone(),
            step_id: self.step_id.clone(),
            binary_id: self.binary_id.clone(),
            mapping_id: self.mapping_id.clone(),
            analysis_revision: self.analysis_revision.clone(),
            covered_blocks: self.covered_blocks.clone(),
            unmapped_guest_vas: self.unmapped_guest_vas.clone(),
            unknown_overflow: self.unknown_overflow,
            quality: self.quality,
            errors: self.errors.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StateNode {
    pub state_id: StateId,
    pub snapshot_id: SnapshotId,
    pub scenario_id: ScenarioId,
    pub parent_state_id: Option<StateId>,
    pub action_index: usize,
    pub action_id: String,
    pub episode_id: EpisodeId,
    pub step_id: StepId,
    pub analysis_revision: AnalysisRevision,
    pub effects_digest: Sha256,
    pub quality: Quality,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EpisodeResult {
    pub schema_version: String,
    pub artifact: String,
    pub episode_id: EpisodeId,
    pub scenario_id: ScenarioId,
    pub backend: Backend,
    pub qemu_sha256: Sha256,
    pub agent_sha256: Sha256,
    pub outcome: StepOutcome,
    pub steps: Vec<StepResult>,
    pub state_nodes: Vec<StateNode>,
    pub errors: Vec<ErrorRecord>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Backend {
    QemuSystem,
    QemuUser,
}

impl Backend {
    pub fn validate_scenario(self, scenario: &TestCase) -> ContractResult<()> {
        if self == Self::QemuUser
            && scenario.actions.iter().any(|action| {
                matches!(
                    action,
                    Action::AdvanceClock { .. } | Action::Checkpoint { .. }
                )
            })
        {
            return Err(ContractError::new(
                "unsupported_action: advance_clock and checkpoint require qemu-system",
            ));
        }
        Ok(())
    }
}

impl EpisodeResult {
    pub fn validate_against(
        &self,
        scenario: &TestCase,
        model: &AnalysisModel,
    ) -> ContractResult<()> {
        self.validate()?;
        self.backend.validate_scenario(scenario)?;
        if self.scenario_id != scenario.scenario_id {
            return Err(ContractError::new("foreign ScenarioId in EpisodeResult"));
        }
        if scenario
            .target
            .binary_id
            .as_ref()
            .is_some_and(|id| id != &model.binary_id)
        {
            return Err(ContractError::new(
                "target and AnalysisModel BinaryIds differ",
            ));
        }
        for step in &self.steps {
            let action = scenario
                .actions
                .get(step.action_index)
                .ok_or_else(|| ContractError::new("StepResult action index is outside TestCase"))?;
            if step.action_id != action.action_id() {
                return Err(ContractError::new(
                    "StepResult ActionId differs from TestCase",
                ));
            }
            match action {
                Action::SpawnProcess { .. } if step.process_created.is_none() => {
                    return Err(ContractError::new("spawn step lacks process_created"));
                }
                Action::SpawnProcess { .. } => {}
                _ if step.process_created.is_some() => {
                    return Err(ContractError::new(
                        "process_created is only valid for spawn",
                    ));
                }
                _ => {}
            }
            if let Some(coverage) = &step.coverage {
                let mapping = step
                    .mapping
                    .as_ref()
                    .ok_or_else(|| ContractError::new("coverage requires its MappingRecord"))?;
                coverage.as_standalone().validate_against(
                    &self.episode_id,
                    &step.step_id,
                    mapping,
                    model,
                )?;
            }
        }
        for state in &self.state_nodes {
            if state.scenario_id != scenario.scenario_id
                || state.analysis_revision != model.analysis_revision
            {
                return Err(ContractError::new("foreign identity in StateNode"));
            }
        }
        Ok(())
    }
}

impl ContractArtifact for EpisodeResult {
    const ARTIFACT: &'static str = "episode_result";

    fn schema_version(&self) -> &str {
        &self.schema_version
    }

    fn artifact(&self) -> &str {
        &self.artifact
    }

    fn validate_contents(&self) -> ContractResult<()> {
        let mut step_ids = BTreeSet::new();
        let mut action_indexes = BTreeSet::new();
        for step in &self.steps {
            if step.action_id.is_empty()
                || !step_ids.insert(&step.step_id)
                || !action_indexes.insert(step.action_index)
            {
                return Err(ContractError::new("duplicate or empty step identity"));
            }
            if step.coverage.is_some() != step.mapping.is_some() {
                return Err(ContractError::new("coverage and mapping must be paired"));
            }
            if let Some(coverage) = &step.coverage {
                let coverage = coverage.as_standalone();
                coverage.validate()?;
                if coverage.episode_id != self.episode_id || coverage.step_id != step.step_id {
                    return Err(ContractError::new(
                        "foreign EpisodeId or StepId in coverage",
                    ));
                }
                if coverage.mapping_id
                    != step
                        .mapping
                        .as_ref()
                        .expect("paired mapping was checked")
                        .mapping_id
                {
                    return Err(ContractError::new("coverage and mapping identities differ"));
                }
            }
            if let Some(mapping) = &step.mapping {
                mapping.validate_contents()?;
            }
            for effect in &step.effects {
                effect.validate_nested(&self.episode_id, &step.step_id)?;
            }
        }
        for state in &self.state_nodes {
            if state.state_id != state.snapshot_id
                || state.episode_id != self.episode_id
                || state.quality == Quality::Invalid
            {
                return Err(ContractError::new("invalid StateNode identity or quality"));
            }
            let step = self
                .steps
                .iter()
                .find(|step| step.step_id == state.step_id)
                .ok_or_else(|| ContractError::new("StateNode refers to an unknown StepId"))?;
            if state.action_index != step.action_index || state.action_id != step.action_id {
                return Err(ContractError::new(
                    "StateNode action does not match its step",
                ));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CodeObservation {
    pub episode_id: EpisodeId,
    pub step_id: StepId,
    pub mapping_id: MappingId,
    pub block_id: BlockId,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceId {
    pub action_index: usize,
    pub field: String,
    pub offset: u64,
    pub length: u64,
}

impl SourceId {
    pub fn validate_against(&self, scenario: &TestCase) -> ContractResult<()> {
        if self.length == 0 {
            return Err(ContractError::new("SourceId length must be positive"));
        }
        let action = scenario
            .actions
            .get(self.action_index)
            .ok_or_else(|| ContractError::new("SourceId action index is out of range"))?;
        let field_length = match action {
            Action::WriteStdin { data_hex, .. } if self.field == "stdin" => data_hex.len(),
            Action::WriteFile { path, data_hex, .. } if self.field == format!("file:{path}") => {
                data_hex.len()
            }
            Action::SetEnv {
                name, value_hex, ..
            } if self.field == format!("env:{name}") => value_hex.len(),
            Action::AdvanceClock { .. } if self.field == "clock_delta" => 8,
            _ => return Err(ContractError::new("unknown SourceId field for Action")),
        };
        let end = self
            .offset
            .checked_add(self.length)
            .ok_or_else(|| ContractError::new("SourceId range overflows"))?;
        let field_length = u64::try_from(field_length)
            .map_err(|_| ContractError::new("Action field exceeds Contracts v2 limits"))?;
        if end > field_length {
            return Err(ContractError::new(
                "SourceId range exceeds its Action field",
            ));
        }
        if self.field == "clock_delta" && (self.offset != 0 || self.length != 8) {
            return Err(ContractError::new(
                "clock_delta SourceId must cover all 8 bytes",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PatchOperation {
    pub source_id: SourceId,
    pub value_hex: HexBytes,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DseTarget {
    pub dse_target_id: DseTargetId,
    pub condition_elf_va: HexU64,
    pub desired_branch: DesiredBranch,
    pub block_id: BlockId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DesiredBranch {
    Taken,
    Fallthrough,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DseSource {
    pub episode_id: EpisodeId,
    pub step_id: StepId,
    pub scenario_id: ScenarioId,
    pub analysis_revision: AnalysisRevision,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DseLimits {
    pub max_trace_instructions: u64,
    pub max_constraints: u64,
    pub solver_timeout_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SolverResult {
    Sat,
    Unsat,
    Unknown,
    Timeout,
    Unsupported,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SolverObservation {
    pub name: String,
    pub version: String,
    pub result: SolverResult,
    pub duration_ms: u64,
    pub model: BTreeMap<String, HexBytes>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DseAttempt {
    pub schema_version: String,
    pub artifact: String,
    pub dse_attempt_id: DseAttemptId,
    pub target: DseTarget,
    pub source: DseSource,
    pub sources: Vec<SourceId>,
    pub limits: DseLimits,
    pub unsupported_operations: Vec<String>,
    pub solver: SolverObservation,
    pub context_patch: Vec<PatchOperation>,
    pub patched_scenario_id: Option<ScenarioId>,
    pub validation_episode_id: Option<EpisodeId>,
    pub reached: bool,
    pub stop_reason: String,
    pub errors: Vec<ErrorRecord>,
}

impl DseAttempt {
    pub fn validate_against(
        &self,
        scenario: &TestCase,
        model: &AnalysisModel,
    ) -> ContractResult<TestCase> {
        self.validate()?;
        if self.source.scenario_id != scenario.scenario_id
            || self.source.analysis_revision != model.analysis_revision
            || self.target.block_id.binary_id != model.binary_id
            || model.block(&self.target.block_id).is_none()
        {
            return Err(ContractError::new("foreign identity in DseAttempt"));
        }
        for source in &self.sources {
            source.validate_against(scenario)?;
        }
        for operation in &self.context_patch {
            if !self.sources.contains(&operation.source_id) {
                return Err(ContractError::new(
                    "ContextPatch uses an undeclared SourceId",
                ));
            }
        }
        let patched = scenario.apply_context_patch(&self.context_patch)?;
        if self.patched_scenario_id.as_ref() != Some(&patched.scenario_id) {
            return Err(ContractError::new(
                "patched ScenarioId does not match ContextPatch",
            ));
        }
        Ok(patched)
    }
}

impl ContractArtifact for DseAttempt {
    const ARTIFACT: &'static str = "dse_attempt";

    fn schema_version(&self) -> &str {
        &self.schema_version
    }

    fn artifact(&self) -> &str {
        &self.artifact
    }

    fn validate_contents(&self) -> ContractResult<()> {
        if self.limits.max_trace_instructions == 0
            || self.limits.max_constraints == 0
            || self.limits.solver_timeout_ms == 0
            || self.solver.name.is_empty()
            || self.solver.version.is_empty()
            || self.stop_reason.is_empty()
        {
            return Err(ContractError::new("invalid DSE limits or solver identity"));
        }
        if self.solver.result != SolverResult::Sat && !self.solver.model.is_empty() {
            return Err(ContractError::new(
                "non-sat solver result cannot have a model",
            ));
        }
        if self.reached
            && (self.solver.result != SolverResult::Sat || self.validation_episode_id.is_none())
        {
            return Err(ContractError::new(
                "DSE reached requires sat and a concrete validation episode",
            ));
        }
        if self.solver.result == SolverResult::Sat && self.patched_scenario_id.is_none() {
            return Err(ContractError::new(
                "sat DSE result requires a patched scenario",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingLevel {
    StaticHypothesis,
    ObservedAnomaly,
    ReproducibleAnomaly,
    ControlledTrigger,
    DseValidatedTrigger,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MinimalPair {
    pub baseline_scenario_id: ScenarioId,
    pub trigger_scenario_id: ScenarioId,
    pub changed_source: SourceId,
    pub baseline_episodes: Vec<EpisodeId>,
    pub trigger_episodes: Vec<EpisodeId>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnomalyScore {
    pub value: u8,
    pub factors: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CandidateVerdict {
    PotentialUndeclaredBehavior,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Finding {
    pub schema_version: String,
    pub artifact: String,
    pub finding_id: FindingId,
    pub level: FindingLevel,
    pub title: String,
    pub scenario_id: ScenarioId,
    pub action_index: usize,
    pub block_id: BlockId,
    pub mapping_id: MappingId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dse_attempt_id: Option<DseAttemptId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub minimal_pair: Option<MinimalPair>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub observed_episodes: Vec<EpisodeId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub repeated_episodes: Vec<EpisodeId>,
    pub effects: Vec<EffectEvent>,
    pub anomaly_score: AnomalyScore,
    pub candidate_verdict: CandidateVerdict,
    pub limitations: Vec<String>,
}

impl Finding {
    pub fn validate_against_dse(&self, attempt: &DseAttempt) -> ContractResult<()> {
        self.validate()?;
        if self.level == FindingLevel::DseValidatedTrigger
            && (self.dse_attempt_id.as_ref() != Some(&attempt.dse_attempt_id)
                || !attempt.reached
                || attempt.solver.result != SolverResult::Sat
                || attempt.validation_episode_id.is_none()
                || attempt.target.block_id != self.block_id)
        {
            return Err(ContractError::new(
                "Finding lacks matching concrete DSE evidence",
            ));
        }
        Ok(())
    }
}

impl ContractArtifact for Finding {
    const ARTIFACT: &'static str = "finding";

    fn schema_version(&self) -> &str {
        &self.schema_version
    }

    fn artifact(&self) -> &str {
        &self.artifact
    }

    fn validate_contents(&self) -> ContractResult<()> {
        if self.title.is_empty()
            || self.anomaly_score.value > 100
            || self.anomaly_score.factors.is_empty()
            || self.limitations.is_empty()
        {
            return Err(ContractError::new("invalid Finding evidence or score"));
        }
        if self
            .effects
            .iter()
            .any(|effect| effect.data_hex.is_some() && effect.digest.is_some())
        {
            return Err(ContractError::new("invalid Finding effect payload"));
        }
        let has_repeats = !self.observed_episodes.is_empty() && !self.repeated_episodes.is_empty();
        match self.level {
            FindingLevel::StaticHypothesis | FindingLevel::ObservedAnomaly => {}
            FindingLevel::ReproducibleAnomaly => {
                if !has_repeats && self.minimal_pair.is_none() {
                    return Err(ContractError::new(
                        "reproducible anomaly requires independent repeats",
                    ));
                }
            }
            FindingLevel::ControlledTrigger | FindingLevel::DseValidatedTrigger => {
                let pair = self.minimal_pair.as_ref().ok_or_else(|| {
                    ContractError::new("controlled trigger requires a minimal pair")
                })?;
                validate_minimal_pair(pair)?;
            }
        }
        if self.level == FindingLevel::DseValidatedTrigger && self.dse_attempt_id.is_none() {
            return Err(ContractError::new("DSE finding requires DseAttemptId"));
        }
        if let Some(pair) = &self.minimal_pair
            && pair.trigger_scenario_id != self.scenario_id
        {
            return Err(ContractError::new(
                "Finding ScenarioId differs from its trigger scenario",
            ));
        }
        Ok(())
    }
}

fn validate_minimal_pair(pair: &MinimalPair) -> ContractResult<()> {
    if pair.baseline_scenario_id == pair.trigger_scenario_id
        || pair.baseline_episodes.len() < 2
        || pair.trigger_episodes.len() < 2
        || pair.changed_source.length == 0
    {
        return Err(ContractError::new(
            "minimal pair needs distinct scenarios, one changed source and repeats of both sides",
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SolverIdentity {
    pub name: String,
    pub version: String,
    pub sha256: Sha256,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolchainIdentity {
    pub rustc: String,
    pub cargo: String,
    pub qemu: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CampaignConfig {
    pub vm_profile: String,
    pub rng_seed: u64,
    pub max_episodes: u64,
    pub max_target_execs: u64,
    pub max_wall_time_ms: u64,
    pub max_virtual_time_ns: HexU64,
    pub max_solver_calls: u64,
    pub max_solver_time_ms: u64,
    pub max_actions_per_scenario: u64,
    pub max_input_bytes_per_field: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CampaignCounters {
    pub episodes: u64,
    pub target_execs: u64,
    pub solver_calls: u64,
    pub solver_sat: u64,
    pub solver_unsat: u64,
    pub solver_timeouts: u64,
    pub findings: u64,
    pub replay_failures: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CampaignStatus {
    Running,
    Completed,
    Cancelled,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CampaignManifest {
    pub schema_version: String,
    pub artifact: String,
    pub vm_image_id: VmImageId,
    pub initial_snapshot_id: SnapshotId,
    pub target_binary_id: BinaryId,
    pub initial_scenario_id: ScenarioId,
    pub analysis_revisions: Vec<AnalysisRevision>,
    pub tool_sha256: Sha256,
    pub qemu_sha256: Sha256,
    pub agent_sha256: Sha256,
    pub solver: SolverIdentity,
    pub toolchain: ToolchainIdentity,
    pub config: CampaignConfig,
    pub counters: CampaignCounters,
    pub status: CampaignStatus,
    pub stop_reason: String,
}

impl ContractArtifact for CampaignManifest {
    const ARTIFACT: &'static str = "campaign_manifest";

    fn schema_version(&self) -> &str {
        &self.schema_version
    }

    fn artifact(&self) -> &str {
        &self.artifact
    }

    fn validate_contents(&self) -> ContractResult<()> {
        if self.counters.episodes > self.config.max_episodes
            || self.counters.target_execs > self.config.max_target_execs
            || self.counters.solver_calls > self.config.max_solver_calls
            || self
                .counters
                .solver_sat
                .checked_add(self.counters.solver_unsat)
                .and_then(|total| total.checked_add(self.counters.solver_timeouts))
                .is_none_or(|total| total > self.counters.solver_calls)
            || self.stop_reason.is_empty()
        {
            return Err(ContractError::new(
                "invalid campaign counters or stop reason",
            ));
        }
        let mut revisions = BTreeSet::new();
        if !self
            .analysis_revisions
            .iter()
            .all(|revision| revisions.insert(revision))
        {
            return Err(ContractError::new("duplicate AnalysisRevision in manifest"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InterfaceKind {
    Stdin,
    File,
    Env,
    Cwd,
    Clock,
    Network,
    Ipc,
    Process,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HintConfidence {
    Hint,
    Confirmed,
    Unsupported,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InterfaceHint {
    pub kind: InterfaceKind,
    pub episode_id: EpisodeId,
    pub step_id: StepId,
    pub observation: String,
    pub confidence: HintConfidence,
    pub actions: Vec<Action>,
}

impl InterfaceHint {
    pub fn validate_contents(&self) -> ContractResult<()> {
        if self.observation.is_empty()
            || matches!(self.kind, InterfaceKind::Network | InterfaceKind::Ipc)
                != (self.confidence == HintConfidence::Unsupported)
        {
            return Err(ContractError::new(
                "network/IPC hints must be unsupported and other hints must not be unsupported",
            ));
        }
        if self.confidence == HintConfidence::Unsupported && !self.actions.is_empty() {
            return Err(ContractError::new(
                "unsupported source cannot create executable actions",
            ));
        }
        Ok(())
    }
}
