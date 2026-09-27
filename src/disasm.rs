use std::error::Error;
use capstone::{InsnGroupType, arch::x86::X86OperandType, prelude::*};
use derivative::Derivative;

use crate::loader;

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
}

#[derive(Debug)]
pub enum FlowKind {
    Sequential,
    Jump,
    CondJump,
    Call,
    Return,
}

/// function for disassembling section
pub fn vF_disasm_raw_bytes(sect: loader::Section) -> Result<Vec<Instruction>, Box<dyn Error>> {
    let cs = Capstone::new()
        .x86()
        .mode(arch::x86::ArchMode::Mode64)
        .syntax(arch::x86::ArchSyntax::Intel)
        // switch on for groups
        .detail(true)
        .build()?;

    let cs_insns = cs.disasm_all(&sect.bytes, sect.address)?;
    let mut instructions = Vec::with_capacity(cs_insns.len());

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
        instructions.push(Instruction {
            address: insn.address(),
            size: insn.bytes().len() as u8,
            bytes: insn.bytes().to_vec(),
            mnemonic: insn.mnemonic().unwrap_or("").to_string(),
            operands: insn.op_str().unwrap_or("").to_string(),
            flow,
            target,
        });
    }

    Ok(instructions)
}
