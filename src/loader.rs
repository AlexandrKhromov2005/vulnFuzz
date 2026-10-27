use goblin::elf::Elf;
use goblin::container::{Container, Ctx, Endian};
use goblin::elf::header::{self, ET_DYN, ET_EXEC};
use goblin::elf::program_header::{ProgramHeader, PF_X, PT_DYNAMIC, PT_INTERP, PT_LOAD};
use goblin::elf64::dynamic::{DF_1_PIE, DT_FLAGS_1, DT_NULL};
use std::{error::Error, fs, path::Path};
use derivative::Derivative;

use crate::disasm::{FlowKind, Operand, vF_disasm_raw_bytes};

/// Offset from begining of file
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileOffset(pub u64);


/// Virtual address from ELF
/// For PIE this address before adding runtime load bias
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ElfVa(pub u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElfKind {
    Executable, // ET_EXEC
    Pie,        // executable ET_DYN
}

/// File part of executable PT_LOAD
/// All ranges checks before CodeImage creation

#[derive(Debug)]
pub struct ExecutableSegment {
    pub address: ElfVa,
    pub file_offset: FileOffset,
    pub file_size: u64,
    pub memory_size: u64,
}

/// Historical name for the file-backed part of an executable PT_LOAD segment.
/// This is NOT an ELF section. Bytes cover [address, address + bytes.len());
/// the zero-filled tail up to memory_size is never stored or disassembled.
/// All addresses are ELF VAs, before any PIE runtime load bias.
#[derive(Clone, Derivative)]
#[derivative(Debug)]
pub struct Section {
    #[derivative(Debug="ignore")]
    pub bytes   : Vec<u8>,
    #[derivative(Debug(format_with="std::fmt::LowerHex::fmt"))]
    pub address : u64,
    pub file_offset: u64,
    pub memory_size: u64,
}


/// File-backed executable PT_LOAD ranges and the entry ELF VA.
/// `sections` retains its historical name; no section table is used.
/// ET_DYN is supported only with PT_INTERP, with or without DF_1_PIE.
#[derive(Default, Clone, Derivative)]
#[derivative(Debug)]
pub struct CodeImage {
    pub(crate) sections    : Vec<Section>,
    #[derivative(Debug(format_with="std::fmt::LowerHex::fmt"))]
    entry       : u64,
    is_pie      : bool,
    has_pie_flag: bool,
}

impl CodeImage {
    /// Entry ELF VA, not a runtime address for PIE.
    pub fn entry(&self) -> u64 {
        self.entry
    }

    pub fn is_pie(&self) -> bool {
        self.is_pie
    }

    /// Whether DT_FLAGS_1 contains DF_1_PIE (0x08000000), independently of other bits.
    /// This flag is evidence, not a prerequisite for the supported ET_DYN profile.
    pub fn has_pie_flag(&self) -> bool {
        self.has_pie_flag
    }

    /// Executable PT_LOAD file ranges, in program-header order.
    pub fn executable_ranges(&self) -> &[Section] {
        &self.sections
    }

    /// Read [addr, addr + len) entirely within ONE executable file range.
    /// Never joins adjacent segments, crosses holes, or reads zero-filled tails.
    /// A zero-length read succeeds at any point from a range's start through its
    /// file end (inclusive), including the start of an empty range. Else None.
    /// `addr` is an ELF VA; runtime PIE addresses require an external load bias.
    pub fn read_va(&self, addr: u64, len: usize) -> Option<&[u8]> {
        addr.checked_add(u64::try_from(len).ok()?)?;
        self.sections.iter().find_map(|section| {
            let offset = usize::try_from(addr.checked_sub(section.address)?).ok()?;
            section.bytes.get(offset..offset.checked_add(len)?)
        })
    }
}

fn file_range(buffer: &[u8], offset: u64, size: u64, label: &str)
    -> Result<std::ops::Range<usize>, Box<dyn Error>>
{
    let end = offset.checked_add(size)
        .ok_or_else(|| format!("{label}: file offset + size overflows u64"))?;
    let start = usize::try_from(offset)
        .map_err(|_| format!("{label}: file offset does not fit usize"))?;
    let end = usize::try_from(end)
        .map_err(|_| format!("{label}: file end does not fit usize"))?;
    if buffer.get(start..end).is_none() {
        return Err(format!("{label}: file range {start:#x}..{end:#x} exceeds file size {:#x}", buffer.len()).into());
    }
    Ok(start..end)
}

/// Load ELF64 little-endian x86-64 ET_EXEC, or ET_DYN with PT_INTERP.
/// Validates every PT_LOAD and copies only PF_X file bytes. Any overlapping
/// nonempty PT_LOAD memory ranges are unsupported, even with identical bytes.
/// Different VAs may refer to the same file bytes. No runtime mapping is built.
pub fn vF_load(path_to_binary: impl AsRef<Path>) -> Result<CodeImage, Box<dyn Error>> {
    let buffer = fs::read(path_to_binary)?;
    let header = Elf::parse_header(&buffer)?;
    if header.e_ident[header::EI_CLASS] != header::ELFCLASS64 {
        return Err("Not an ELF64 file".into());
    }
    if header.e_machine != header::EM_X86_64 {
        return Err("Not an x86-64 binary".into());
    }
    if header.e_ident[header::EI_DATA] != header::ELFDATA2LSB {
        return Err("Not a little-endian binary".into());
    }
    if !matches!(header.e_type, ET_EXEC | ET_DYN) {
        return Err(format!("Unsupported ELF e_type: {} (expected ET_EXEC or ET_DYN)", header.e_type).into());
    }
    if header.e_version != 1 || header.e_ident[header::EI_VERSION] != 1 {
        return Err("Unsupported ELF version".into());
    }
    if header.e_ehsize != 64 || header.e_phentsize != 56 {
        return Err("Invalid ELF64 header or program-header entry size".into());
    }
    if header.e_phnum == 0 || header.e_phnum == 0xffff {
        return Err("Missing or unsupported extended program-header count".into());
    }
    if header.e_phoff < u64::from(header.e_ehsize) {
        return Err("Program-header table overlaps the ELF header".into());
    }
    let table_size = u64::from(header.e_phnum).checked_mul(u64::from(header.e_phentsize))
        .ok_or("Program-header table size overflows u64")?;
    let table = file_range(&buffer, header.e_phoff, table_size, "Program-header table")?;
    let phdrs = ProgramHeader::parse(&buffer, table.start, usize::from(header.e_phnum),
        Ctx::new(Container::Big, Endian::Little))?;

    let mut code_image = CodeImage { entry: header.e_entry, is_pie: header.e_type == ET_DYN,
        ..CodeImage::default() };
    let mut load_ranges = Vec::new();
    for (index, ph) in phdrs.iter().enumerate().filter(|(_, ph)| ph.p_type == PT_LOAD) {
        let label = format!("PT_LOAD[{index}]");
        if ph.p_filesz > ph.p_memsz {
            return Err(format!("{label}: p_filesz exceeds p_memsz").into());
        }
        let end = ph.p_vaddr.checked_add(ph.p_memsz)
            .ok_or_else(|| format!("{label}: VA + p_memsz overflows u64"))?;
        ph.p_vaddr.checked_add(ph.p_filesz)
            .ok_or_else(|| format!("{label}: VA + p_filesz overflows u64"))?;
        let bytes = file_range(&buffer, ph.p_offset, ph.p_filesz, &label)?;
        if ph.p_align > 1 && (!ph.p_align.is_power_of_two()
            || ph.p_vaddr % ph.p_align != ph.p_offset % ph.p_align)
        {
            return Err(format!("{label}: invalid p_align or incongruent VA/file offset").into());
        }
        if ph.p_memsz != 0 {
            load_ranges.push((ph.p_vaddr, end, index));
        }
        if ph.p_flags & PF_X != 0 {
            code_image.sections.push(Section { bytes: buffer[bytes].to_vec(),
                address: ph.p_vaddr, file_offset: ph.p_offset, memory_size: ph.p_memsz });
        }
    }
    load_ranges.sort_unstable_by_key(|range| range.0);
    for pair in load_ranges.windows(2) {
        if pair[1].0 < pair[0].1 {
            return Err(format!("Unsupported overlapping PT_LOAD memory ranges: headers {} and {}",
                pair[0].2, pair[1].2).into());
        }
    }

    let mut has_interp = false;
    let mut has_dynamic = false;
    for (index, ph) in phdrs.iter().enumerate() {
        if ph.p_type == PT_INTERP {
            if has_interp {
                return Err("Multiple PT_INTERP segments are unsupported".into());
            }
            let range = file_range(&buffer, ph.p_offset, ph.p_filesz, &format!("PT_INTERP[{index}]"))?;
            let interp = &buffer[range];
            if interp.len() < 2 || interp.last() != Some(&0) || interp[..interp.len() - 1].contains(&0) {
                return Err("PT_INTERP must contain a nonempty NUL-terminated path".into());
            }
            has_interp = true;
        } else if ph.p_type == PT_DYNAMIC {
            if has_dynamic {
                return Err("Multiple PT_DYNAMIC segments are unsupported".into());
            }
            has_dynamic = true;
            let range = file_range(&buffer, ph.p_offset, ph.p_filesz, &format!("PT_DYNAMIC[{index}]"))?;
            let dynamic = &buffer[range];
            if dynamic.is_empty() || dynamic.len() % 16 != 0 {
                return Err("Invalid ELF64 PT_DYNAMIC size".into());
            }
            // Only flags are needed. Avoid parsing symbols/relocations or sections.
            let mut terminated = false;
            for entry in dynamic.chunks_exact(16) {
                let tag = u64::from_le_bytes(entry[..8].try_into()?);
                let value = u64::from_le_bytes(entry[8..].try_into()?);
                if tag == DT_NULL {
                    terminated = true;
                    break;
                }
                if tag == DT_FLAGS_1 && value & DF_1_PIE != 0 {
                    code_image.has_pie_flag = true;
                }
            }
            if !terminated {
                return Err("PT_DYNAMIC is missing DT_NULL".into());
            }
        }
    }
    if code_image.is_pie && !has_interp {
        return Err("Unsupported ET_DYN profile: PT_INTERP is required (shared libraries and static PIE are unsupported)".into());
    }
    if code_image.read_va(code_image.entry, 1).is_none() {
        return Err(format!("Entry {:#x} is outside the file-backed executable PT_LOAD ranges", code_image.entry).into());
    }
    Ok(code_image)
}

/// Compatibility helper: clone the ENTIRE executable segment file range whose
/// start equals `addr`. An interior VA still returns None; use read_va for slices.
pub fn vF_get_section_bytes(code_image : &CodeImage, addr : u64) -> Option<Vec<u8>> {
    for section in &code_image.sections {
        if addr == section.address {
            return Some(section.bytes.clone());
        }
    }

    None
}

/// Optional hint for the modern glibc x86-64 _start template only:
/// canonical argument/stack setup, mov/lea into rdi, RIP-indirect call, then hlt.
/// Starts at entry (optionally endbr64); other startup variants return None.
/// This does not resolve the call's imported symbol or perform data-flow analysis,
/// so even a matching template is a heuristic hint, not proof of a main symbol.
pub fn vF_find_main(code_image : &CodeImage) -> Option<u64> {
    let section = code_image.sections.iter().find(|section| {
        code_image.entry.checked_sub(section.address)
            .and_then(|offset| usize::try_from(offset).ok())
            .is_some_and(|offset| offset < section.bytes.len())
    })?;
    let offset = usize::try_from(code_image.entry.checked_sub(section.address)?).ok()?;
    let bytes = section.bytes.get(offset..)?;
    let decoded = vF_disasm_raw_bytes(&bytes[..bytes.len().min(128)], code_image.entry).ok()?;
    let mut insns = decoded.instructions.as_slice();
    if insns.first()?.mnemonic == "endbr64" {
        insns = &insns[1..];
    }
    let prologue: &[&[u8]] = &[
        &[0x31, 0xed], &[0x49, 0x89, 0xd1], &[0x5e], &[0x48, 0x89, 0xe2],
        &[0x48, 0x83, 0xe4, 0xf0], &[0x50], &[0x54], &[0x45, 0x31, 0xc0], &[0x31, 0xc9],
    ];
    for expected in prologue {
        if insns.first()?.bytes != *expected {
            return None;
        }
        insns = &insns[1..];
    }
    let argument = insns.first()?;
    let candidate = match (argument.mnemonic.as_str(), argument.operands_detail.as_slice()) {
        ("mov", [Operand::Reg(dst), Operand::Imm(value)]) if dst == "rdi" => u64::try_from(*value).ok()?,
        ("lea", [Operand::Reg(dst), Operand::Mem { base, index, disp }])
            if dst == "rdi" && base == "rip" && index.is_empty() =>
        {
            argument.address.checked_add(u64::from(argument.size))?.checked_add_signed(*disp)?
        },
        _ => return None,
    };
    let call = insns.get(1)?;
    if !matches!(call.flow, FlowKind::Call)
        || !matches!(call.operands_detail.as_slice(), [Operand::Mem { base, index, .. }]
            if base == "rip" && index.is_empty())
        || insns.get(2)?.mnemonic != "hlt"
    {
        return None;
    }
    code_image.read_va(candidate, 1)?;
    Some(candidate)
}
