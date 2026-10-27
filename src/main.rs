use std::{error::Error, path::Path, process::ExitCode};
use vulnFuzz::{disasm, loader};

fn run() -> Result<(), Box<dyn Error>> {
    let mut args = std::env::args_os();
    args.next();
    let path = args.next().ok_or("Usage: vulnFuzz <ELF path>")?;
    if args.next().is_some() {
        return Err("Usage: vulnFuzz <ELF path> (expected exactly one path)".into());
    }
    let code_img = loader::vF_load(&path)
        .map_err(|error| format!("{}: {error}", Path::new(&path).display()))?;
    let entry = code_img.entry();
    println!("entry (ELF VA): {entry:#x}; PIE: {}; DF_1_PIE: {}",
        code_img.is_pie(), code_img.has_pie_flag());
    for range in code_img.executable_ranges() {
        println!("executable PT_LOAD: VA {:#x}..{:#x}, file offset {:#x}, file size {:#x}, memory size {:#x}",
            range.address, range.address + u64::try_from(range.bytes.len())?,
            range.file_offset, range.bytes.len(), range.memory_size);
    }
    let entry_range = code_img.executable_ranges().iter().find(|range| {
        entry.checked_sub(range.address).and_then(|n| usize::try_from(n).ok())
            .is_some_and(|n| n < range.bytes.len())
    }).ok_or("Entry is outside executable file ranges")?;
    let offset = usize::try_from(entry - entry_range.address)?;
    let decoded = disasm::vF_disasm_raw_bytes(&entry_range.bytes[offset..], entry)?;
    println!("disassembly from entry: {} instructions, {} bytes; complete: {}; remaining: {:#x}..{:#x}",
        decoded.instructions.len(), decoded.decoded_bytes, decoded.is_complete(),
        decoded.remaining.start, decoded.remaining.end);
    match loader::vF_find_main(&code_img) {
        Some(address) => println!("main hint (ELF VA): {address:#x}"),
        None => println!("main hint: None (startup template not confirmed)"),
    }
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("vulnFuzz: {error}");
            ExitCode::FAILURE
        },
    }
}
