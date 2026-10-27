use std::error::Error;
use capstone::{InsnGroupType, arch::x86::X86OperandType, prelude::*};
use derivative::Derivative;

/// structure useful duplicate of capstone::Instruction
#[derive(Derivative)]
#[derivative(Debug)] 
pub struct Instruction {
    #[derivative(Debug(format_with="std::fmt::LowerHex::fmt"))]
    pub address: u64,
    pub size: u8,
    pub bytes: Vec<u8>,
    pub mnemonic: String,
    pub operands: String,
    pub flow: FlowKind,
    pub target: Option<u64>, // address of branch where execution go next
    pub operands_detail: Vec<Operand>,
}

#[derive(Derivative, Clone)]
#[derivative(Debug)] 
pub enum Operand {
    Reg(String),        // "rdi"
    Imm(i64),
    Mem { base: String, index: String, disp: i64 },  // base="rip", disp=...
    Other,
}

#[derive(Debug)]
pub enum FlowKind {
    Sequential,
    Jump,
    CondJump,
    Call,
    Return,
}

/// Linear decoding of an input prefix; an undecodable suffix is never skipped.
#[derive(Debug)]
pub struct Disassembly {
    pub instructions: Vec<Instruction>,
    pub decoded_bytes: usize,
    /// Undecoded ELF VA range [start, end); empty iff the input was fully decoded.
    pub remaining: std::ops::Range<u64>,
}

impl Disassembly {
    pub fn is_complete(&self) -> bool {
        self.remaining.is_empty()
    }
}

/// Decode file-backed x86-64 bytes at their initial ELF VA (no PIE load bias).
/// Success may contain only a prefix: always inspect remaining/is_complete().
/// Empty input is complete. Address-range overflow returns an error.
pub fn vF_disasm_raw_bytes(bytes: &[u8], address: u64) -> Result<Disassembly, Box<dyn Error>> {
    let end = address.checked_add(u64::try_from(bytes.len())?)
        .ok_or("Disassembly VA + input length overflows u64")?;
    let cs = Capstone::new()
        .x86()
        .mode(arch::x86::ArchMode::Mode64)
        .syntax(arch::x86::ArchSyntax::Intel)
        // switch on for groups
        .detail(true)
        .build()?;

    let cs_insns = cs.disasm_all(bytes, address)?;
    let mut instructions = Vec::with_capacity(cs_insns.len());
    let mut decoded_bytes = 0;

    for insn in cs_insns.iter() {
        let detail = cs.insn_detail(insn)?;
        let groups = detail.groups();
        let is = |g: u32| groups.contains(&InsnGroupId(g as u8));

        let mut flow = FlowKind::Sequential;
        if is(InsnGroupType::CS_GRP_JUMP) {
            flow = if insn.mnemonic().unwrap_or("").eq_ignore_ascii_case("jmp") {
                FlowKind::Jump
            } else {
                FlowKind::CondJump
            };
        } else if is(InsnGroupType::CS_GRP_CALL) {
            flow = FlowKind::Call;
        } else if is(InsnGroupType::CS_GRP_RET) {
            flow = FlowKind::Return;
        }

        let mut target = None;
        if matches!(flow, FlowKind::Jump | FlowKind::CondJump | FlowKind::Call) {
            if let Some(x86) = detail.arch_detail().x86() {
                if let Some(op) = x86.operands().next() {
                    if let X86OperandType::Imm(v) = op.op_type {
                        target = Some(v as u64);
                    }
                }
            }
        }

        let mut operands_detail = Vec::new();
        if let Some(x86) = detail.arch_detail().x86() {
            for op in x86.operands() {
                operands_detail.push(match op.op_type {
                    X86OperandType::Reg(id) => Operand::Reg(cs.reg_name(id).unwrap_or_default()),
                    X86OperandType::Imm(v) => Operand::Imm(v),
                    X86OperandType::Mem(m) => Operand::Mem { base: cs.reg_name(m.base()).unwrap_or_default(), index: cs.reg_name(m.index()).unwrap_or_default(), disp: m.disp() },
                    X86OperandType::Invalid => Operand::Other,
                });
            }
        }

        decoded_bytes += insn.bytes().len();
        instructions.push(Instruction {
            address: insn.address(),
            size: insn.bytes().len() as u8,
            bytes: insn.bytes().to_vec(),
            mnemonic: insn.mnemonic().unwrap_or("").to_string(),
            operands: insn.op_str().unwrap_or("").to_string(),
            flow,
            target,
            operands_detail,
        });
    }

    Ok(Disassembly { instructions, decoded_bytes,
        remaining: address + u64::try_from(decoded_bytes)?..end })
}
