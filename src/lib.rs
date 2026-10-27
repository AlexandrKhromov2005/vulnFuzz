//! File-backed executable ELF ranges and linear x86-64 disassembly.
//!
//! ```no_run
//! use vulnFuzz::{loader::vF_load, disasm::vF_disasm_raw_bytes};
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let image = vF_load("program.elf")?;
//! println!("entry ELF VA: {:#x}", image.entry());
//! for range in image.executable_ranges() {
//!     let bytes = image.read_va(range.address, range.bytes.len()).ok_or("unmapped VA")?;
//!     let decoded = vF_disasm_raw_bytes(bytes, range.address)?;
//!     println!("{} decoded bytes; remaining: {:?}", decoded.decoded_bytes, decoded.remaining);
//! }
//! # Ok(())
//! # }
//! ```

pub mod loader;
pub mod disasm;
