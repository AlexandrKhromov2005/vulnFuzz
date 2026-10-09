use goblin::elf::Elf;
use goblin::elf::program_header::PT_LOAD;
use goblin::elf64::dynamic::DT_FLAGS_1;
use std::{error::Error, fs};
use goblin::elf::{section_header::SHF_EXECINSTR};
use derivative::Derivative;

use crate::disasm::{Operand, vF_disasm_raw_bytes};

/// structure for executable section 
/// address - virtual address of section
/// bytes - bytes contained in section
#[derive(Clone, Derivative)] 
#[derivative(Debug)] 
pub(crate) struct Section {
    #[derivative(Debug="ignore")] 
    pub(crate) bytes   : Vec<u8>,
    #[derivative(Debug(format_with="std::fmt::LowerHex::fmt"))]
    pub(crate) address : u64,
}


/// structure for image of binary
/// entry - entrypoint of binary
/// is_pie - flag is binary pie or not
/// sections - array of executable sections in binary
#[derive(Default, Clone, Derivative)]
#[derivative(Debug)] 
pub struct CodeImage {
    pub(crate) sections    : Vec<Section>,
    #[derivative(Debug(format_with="std::fmt::LowerHex::fmt"))]
    entry       : u64,
    is_pie      : bool,
}

/// function for build CodeImage from binary
/// path_to_binary - path to binary file 
pub fn vF_load(path_to_binary : &str) -> Result<CodeImage, Box<dyn Error>> {
    let mut code_image = CodeImage::default();
    let buffer = fs::read(path_to_binary)?; 
    let elf = Elf::parse(&buffer)?;
    code_image.entry = elf.entry; // get entry of efl
    // --- checking for PIE ---
    let is_et_dyn = elf.header.e_type == goblin::elf::header::ET_DYN; // find ET_DYN in binary
    let has_zero_base = elf.program_headers.iter() // check base address is 0x0
        .find(|ph| ph.p_type == PT_LOAD) 
        .map_or(false, |ph| ph.p_vaddr == 0);
    let mut has_pie_flag = false; // check for PIE flag and 
    if let Some(dynamic) = &elf.dynamic {
        for entry in &dynamic.dyns {
            if entry.d_tag == DT_FLAGS_1 {
                // Mask of flag DF_1_PIE is 0x08400000
                if (entry.d_val & 0x08400000) != 0 {
                    has_pie_flag = true;
                    break;
                }
            }
        }
    }

    code_image.is_pie = is_et_dyn && has_zero_base && has_pie_flag;

    // --- get sections ---

    for section in &elf.section_headers {
        if section.sh_flags & u64::from(SHF_EXECINSTR) != 0 {            
            // Extract the raw file offsets
            let start = section.sh_offset as usize;
            let end = start + section.sh_size as usize;
            
            if end <= buffer.len() {
                code_image.sections.push(Section { bytes: buffer[start..end].to_vec(), address: (section.sh_addr) });
            }
        }
    }


    Ok(code_image)
}

pub fn vF_get_section_bytes(code_image : &CodeImage, addr : u64) -> Option<Vec<u8>> {
    for section in &code_image.sections {
        if addr == section.address {
            return Some(section.bytes.clone());
        }
    }

    None    
}

/// helps find _main especially in stripped binary
pub fn vF_find_main(code_image : &CodeImage) -> Option<u64> {
    let mut insns = Vec::new();
    for section in code_image.sections.clone() {
        if section.address <= code_image.entry && code_image.entry < section.address + (section.bytes.len() as u64) {
            insns = vF_disasm_raw_bytes(&section).unwrap();
            break;
        }
    }

    for insn in &insns {
        if insn.mnemonic == "lea" || insn.mnemonic == "mov" {
            if let Some(Operand::Reg(reg)) = insn.operands_detail.iter().find(|x| matches!(x, Operand::Reg(..))) {
                if reg == "rdi" {
                    match insn.mnemonic.as_str() {
                        "mov" => {
                            let Some(Operand::Imm(x)) = insn.operands_detail.iter().find(|x| matches!(x, Operand::Imm(..))) else { continue };
                            return Some(*x as u64);
                        },
                        "lea" => {
                            let Some(Operand::Mem{disp, ..}) = insn.operands_detail.iter().find(|x| matches!(x, Operand::Mem{..})) else { continue };
                            return Some(insn.address + (insn.size as u64) + (*disp as u64));
                        },
                        _ => {},
                    }
                }
            }
        }
    }

    None
}