use std::{error::Error, fs, path::PathBuf, process::Command, sync::atomic::{AtomicUsize, Ordering}};
use goblin::elf::{Elf, header::{ET_DYN, ET_EXEC}, program_header::{PT_LOAD, PT_INTERP, PT_DYNAMIC, PF_R, PF_W, PF_X}};
use goblin::elf64::dynamic::{DF_1_PIE, DT_FLAGS_1};
use vulnFuzz::{disasm::{FlowKind, Operand, vF_disasm_raw_bytes}, loader::{CodeImage, vF_load, vF_find_main, vF_get_section_bytes}};

const BASE: u64 = 0x401000;
const CODE_OFFSET: usize = 0x200;
const START_OFFSET: usize = 16;
const PROLOGUE: &[u8] = &[
    0x31, 0xed, 0x49, 0x89, 0xd1, 0x5e, 0x48, 0x89, 0xe2,
    0x48, 0x83, 0xe4, 0xf0, 0x50, 0x54, 0x45, 0x31, 0xc0, 0x31, 0xc9,
];

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!("vulnFuzz-test-{}-{}",
            std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
        fs::create_dir(&path).expect("create test directory");
        Self(path)
    }

    fn write(&self, name: &str, bytes: &[u8]) -> PathBuf {
        let path = self.0.join(name);
        fs::write(&path, bytes).unwrap();
        path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn put16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn ph(index: usize, field: usize) -> usize { 64 + 56 * index + field }

// Minimal ELF64 with RX code, RW data, and a second RX range separated by holes.
// No section table, dynamic linker, compiler, or local mock_virus is needed.
fn fixture(code: &[u8]) -> Vec<u8> {
    assert!(code.len() <= 0x100);
    let mut bytes = vec![0; 0x500];
    bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    put16(&mut bytes, 16, ET_EXEC);
    put16(&mut bytes, 18, 62);
    put32(&mut bytes, 20, 1);
    put64(&mut bytes, 24, BASE);
    put64(&mut bytes, 32, 64);
    put16(&mut bytes, 52, 64);
    put16(&mut bytes, 54, 56);
    put16(&mut bytes, 56, 3);
    for (i, (flags, offset, va, filesz, memsz)) in [
        (PF_R | PF_X, 0x200, BASE, code.len() as u64, 0x100),
        (PF_R | PF_W, 0x300, BASE + 0x2000, 8, 0x100),
        (PF_R | PF_X, 0x400, BASE + 0x4000, 2, 0x20),
    ].into_iter().enumerate() {
        put32(&mut bytes, ph(i, 0), PT_LOAD);
        put32(&mut bytes, ph(i, 4), flags);
        put64(&mut bytes, ph(i, 8), offset);
        put64(&mut bytes, ph(i, 16), va);
        put64(&mut bytes, ph(i, 32), filesz);
        put64(&mut bytes, ph(i, 40), memsz);
        put64(&mut bytes, ph(i, 48), 0x100);
    }
    bytes[CODE_OFFSET..CODE_OFFSET + code.len()].copy_from_slice(code);
    bytes[0x400..0x402].copy_from_slice(&[0x90, 0xc3]);
    bytes
}

fn pie_fixture(flags: Option<u64>) -> Vec<u8> {
    let mut bytes = fixture(&[0x90, 0xc3]);
    put16(&mut bytes, 16, ET_DYN);
    put16(&mut bytes, 56, 5);
    put32(&mut bytes, ph(3, 0), PT_INTERP);
    put64(&mut bytes, ph(3, 8), 0x480);
    put64(&mut bytes, ph(3, 32), 7);
    bytes[0x480..0x487].copy_from_slice(b"/ld.so\0");
    if let Some(flags) = flags {
        put32(&mut bytes, ph(4, 0), PT_DYNAMIC);
        put64(&mut bytes, ph(4, 8), 0x4c0);
        put64(&mut bytes, ph(4, 32), 32);
        put64(&mut bytes, 0x4c0, DT_FLAGS_1);
        put64(&mut bytes, 0x4c8, flags);
    }
    bytes
}

fn load(bytes: &[u8]) -> Result<CodeImage, Box<dyn Error>> {
    let dir = TempDir::new();
    vF_load(dir.write("fixture.elf", bytes))
}

fn rejects(bytes: &[u8], reason: &str) {
    let error = load(bytes).expect_err("invalid ELF was accepted").to_string();
    assert!(error.contains(reason), "expected {reason:?}, got {error:?}");
}

#[test]
fn executable_ranges_and_va_boundaries() {
    let image = load(&fixture(&[0x90, 0x90, 0xc3])).unwrap();
    assert_eq!(image.entry(), BASE);
    assert!(!image.is_pie());
    assert_eq!(image.executable_ranges().len(), 2);
    let first = &image.executable_ranges()[0];
    assert_eq!((first.address, first.file_offset, first.memory_size), (BASE, 0x200, 0x100));
    assert_eq!(first.bytes, [0x90, 0x90, 0xc3]); // no p_memsz padding
    assert_eq!(image.read_va(BASE, 1), Some(&[0x90][..]));
    assert_eq!(image.read_va(BASE + 2, 1), Some(&[0xc3][..]));
    assert_eq!(image.read_va(BASE, 3), Some(&first.bytes[..]));
    assert_eq!(image.read_va(BASE + 0x4001, 1), Some(&[0xc3][..]));
    for (va, len) in [(BASE - 1, 1), (BASE + 3, 1), (BASE + 2, 2),
        (BASE + 0x1000, 1), (BASE + 0x2000, 1), (BASE, 0x4002), (u64::MAX, 2)]
    {
        assert!(image.read_va(va, len).is_none(), "{va:#x}, {len}");
    }
    for va in [BASE, BASE + 1, BASE + 3] {
        assert_eq!(image.read_va(va, 0), Some(&[][..]));
    }
    assert!(image.read_va(BASE + 4, 0).is_none());
    assert_eq!(vF_get_section_bytes(&image, BASE), Some(first.bytes.clone()));
    assert!(vF_get_section_bytes(&image, BASE + 1).is_none());
}

#[test]
fn adjacent_segments_are_not_joined_and_empty_ranges_are_safe() {
    let mut bytes = fixture(&[0x90, 0xc3]);
    put64(&mut bytes, ph(0, 40), 2);
    put64(&mut bytes, ph(2, 16), BASE + 2);
    put64(&mut bytes, ph(2, 48), 1);
    let image = load(&bytes).unwrap();
    assert!(image.read_va(BASE + 1, 2).is_none());
    assert_eq!(image.read_va(BASE + 2, 1), Some(&[0x90][..]));
    put64(&mut bytes, ph(2, 32), 0);
    put64(&mut bytes, ph(2, 40), 0);
    let image = load(&bytes).unwrap();
    assert_eq!(image.read_va(BASE + 2, 0), Some(&[][..]));
    assert!(image.read_va(BASE + 2, 1).is_none());
}

#[test]
fn pie_profile_uses_interp_and_exact_pie_flag_without_zero_base() {
    for flags in [None, Some(0), Some(0x00400000), Some(DF_1_PIE), Some(DF_1_PIE | 1)] {
        let mut bytes = pie_fixture(flags);
        let image = load(&bytes).unwrap();
        assert!(image.is_pie());
        assert_eq!(image.entry(), BASE); // first PT_LOAD is deliberately nonzero
        assert_eq!(image.has_pie_flag(), flags.is_some_and(|f| f & DF_1_PIE != 0));
        put32(&mut bytes, ph(3, 0), 0);
        rejects(&bytes, "PT_INTERP is required"); // even DF_1_PIE is insufficient
    }
}

#[test]
fn real_non_pie_and_pie_work_without_their_section_tables() {
    let dir = TempDir::new();
    for pie in [false, true] {
        let path = dir.0.join(if pie { "pie" } else { "exec" });
        let output = Command::new("cc")
            .args(if pie { ["-fPIE", "-pie"] } else { ["-fno-pie", "-no-pie"] })
            .arg(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/main.c"))
            .arg("-o").arg(&path).output().expect("cc is required for real ELF fixture tests");
        assert!(output.status.success(), "cc failed: {}", String::from_utf8_lossy(&output.stderr));
        let image = vF_load(&path).unwrap();
        assert_eq!(image.is_pie(), pie);
        assert!(image.read_va(image.entry(), 1).is_some());
        if let Some(main) = vF_find_main(&image) {
            assert!(image.read_va(main, 1).is_some());
        }
        let mut bytes = fs::read(&path).unwrap();
        let elf = Elf::parse(&bytes).unwrap();
        assert!(!elf.section_headers.is_empty());
        let table_start = elf.header.e_phoff as usize;
        let table_end = table_start + usize::from(elf.header.e_phnum) * 56;
        let original_table = bytes[table_start..table_end].to_vec();
        let file_end = elf.program_headers.iter().filter(|p| p.p_type == PT_LOAD)
            .map(|p| (p.p_offset + p.p_filesz) as usize).max().unwrap();
        put64(&mut bytes, 40, 0); // e_shoff
        put16(&mut bytes, 60, 0); // e_shnum
        put16(&mut bytes, 62, 0); // e_shstrndx
        bytes.truncate(file_end.max(table_end));
        assert_eq!(&bytes[table_start..table_end], &original_table);
        let stripped = load(&bytes).unwrap();
        assert_eq!(stripped.entry(), image.entry());
        assert_eq!(stripped.is_pie(), image.is_pie());
        assert_eq!(stripped.has_pie_flag(), image.has_pie_flag());
        assert_eq!(stripped.executable_ranges().len(), image.executable_ranges().len());
        for (a, b) in stripped.executable_ranges().iter().zip(image.executable_ranges()) {
            assert_eq!((a.address, a.file_offset, a.memory_size, &a.bytes),
                (b.address, b.file_offset, b.memory_size, &b.bytes));
            assert!(vF_disasm_raw_bytes(&a.bytes, a.address).unwrap().decoded_bytes > 0);
        }
        assert_eq!(vF_find_main(&stripped), vF_find_main(&image));
    }
}

#[test]
fn section_metadata_is_not_used_to_load_code() {
    let mut bytes = fixture(&[0xc3]);
    put64(&mut bytes, 40, u64::MAX);
    put16(&mut bytes, 60, 1);
    assert_eq!(load(&bytes).unwrap().read_va(BASE, 1), Some(&[0xc3][..]));
}

#[test]
fn rejects_truncation_and_file_or_va_overflow_in_every_load() {
    let original = fixture(&[0x90, 0x90, 0xc3]);
    for len in [0, 4, 16, 63, 64 + 3 * 56 - 1, CODE_OFFSET + 2, 0x307, 0x401] {
        assert!(load(&original[..len]).is_err(), "accepted truncation at {len:#x}");
    }
    for index in 0..3 {
        let mut bytes = original.clone();
        put64(&mut bytes, ph(index, 8), u64::MAX - 1);
        rejects(&bytes, "file offset + size overflows");
        let mut bytes = original.clone();
        put64(&mut bytes, ph(index, 16), u64::MAX - 1);
        rejects(&bytes, "VA + p_memsz overflows");
        let mut bytes = original.clone();
        put64(&mut bytes, ph(index, 40), 0);
        rejects(&bytes, "p_filesz exceeds p_memsz");
        let mut bytes = original.clone();
        put64(&mut bytes, ph(index, 8), 0x500);
        rejects(&bytes, "exceeds file size");
    }
    let mut bytes = original;
    put64(&mut bytes, 32, u64::MAX - 1);
    rejects(&bytes, "Program-header table: file offset + size overflows");
}

#[test]
fn rejects_bad_alignment_and_overlapping_memory_including_non_executable_bss() {
    for index in 0..3 {
        for align in [3, 0x1000] {
            let mut bytes = fixture(&[0xc3]);
            put64(&mut bytes, ph(index, 48), align);
            rejects(&bytes, "invalid p_align");
        }
        for align in [0, 1] {
            let mut bytes = fixture(&[0xc3]);
            put64(&mut bytes, ph(index, 48), align);
            assert!(load(&bytes).is_ok());
        }
    }
    for address in [BASE, BASE + 1, BASE + 0x80] {
        let mut bytes = fixture(&[0xc3]);
        put64(&mut bytes, ph(1, 16), address);
        put64(&mut bytes, ph(1, 48), 1);
        rejects(&bytes, "overlapping PT_LOAD");
    }
}

#[test]
fn rejects_entry_in_bss_holes_data_or_at_file_end() {
    for entry in [BASE - 1, BASE + 2, BASE + 0x80, BASE + 0x1000, BASE + 0x2000] {
        let mut bytes = fixture(&[0x90, 0xc3]);
        put64(&mut bytes, 24, entry);
        rejects(&bytes, "Entry");
    }
}

#[test]
fn rejects_unsupported_elf_and_malformed_auxiliary_headers() {
    let mut bytes = fixture(&[0xc3]);
    bytes[0] = 0;
    assert!(load(&bytes).is_err());
    let mut bytes = fixture(&[0xc3]);
    bytes[4] = 1;
    rejects(&bytes, "Not an ELF64");
    let mut bytes = fixture(&[0xc3]);
    put16(&mut bytes, 18, 183);
    rejects(&bytes, "Not an x86-64");
    let mut bytes = fixture(&[0xc3]);
    bytes[5] = 2;
    bytes[18..20].copy_from_slice(&62u16.to_be_bytes());
    rejects(&bytes, "little-endian");
    for kind in [0, 1, 4] {
        let mut bytes = fixture(&[0xc3]);
        put16(&mut bytes, 16, kind);
        rejects(&bytes, "Unsupported ELF e_type");
    }
    let mut bytes = pie_fixture(Some(DF_1_PIE));
    bytes[0x486] = b'x';
    rejects(&bytes, "NUL-terminated path");
    let mut bytes = pie_fixture(Some(DF_1_PIE));
    put64(&mut bytes, ph(4, 32), 17);
    rejects(&bytes, "PT_DYNAMIC size");
    let mut bytes = pie_fixture(Some(DF_1_PIE));
    put64(&mut bytes, 0x4d0, DT_FLAGS_1);
    rejects(&bytes, "missing DT_NULL");
}

fn startup(argument: &[u8]) -> Vec<u8> {
    let mut code = vec![0xc3; START_OFFSET];
    code.extend_from_slice(PROLOGUE);
    code.extend_from_slice(argument);
    code.extend_from_slice(&[0xff, 0x15, 0, 0, 0, 0, 0xf4]); // call [rip]; hlt
    let mut bytes = fixture(&code);
    put64(&mut bytes, 24, BASE + START_OFFSET as u64);
    bytes
}

#[test]
fn main_hint_starts_at_entry_and_handles_negative_rip_displacement() {
    let mut lea = vec![0x48, 0x8d, 0x3d]; // lea rdi, [rip + signed disp32]
    lea.extend_from_slice(&(-((START_OFFSET + PROLOGUE.len() + 7) as i32)).to_le_bytes());
    let mut bytes = startup(&lea);
    // A misleading earlier mov must not be scanned before entry.
    bytes[CODE_OFFSET..CODE_OFFSET + 7].copy_from_slice(&[0x48, 0xc7, 0xc7, 0x01, 0x10, 0x40, 0]);
    let image = load(&bytes).unwrap();
    assert_eq!(vF_find_main(&image), Some(BASE));
    let decoded = vF_disasm_raw_bytes(&lea, BASE + 0x100).unwrap();
    assert!(matches!(decoded.instructions[0].operands_detail.as_slice(),
        [Operand::Reg(dst), Operand::Mem { base, index, disp }]
        if dst == "rdi" && base == "rip" && index.is_empty() && *disp < 0));
    // CET entry is another supported variant.
    let mut code = vec![0xf3, 0x0f, 0x1e, 0xfa];
    code.extend_from_slice(&[0x31, 0xed]);
    code.extend_from_slice(&PROLOGUE[2..]);
    code.extend_from_slice(&[0x48, 0xc7, 0xc7, 0, 0x10, 0x40, 0]);
    code.extend_from_slice(&[0xff, 0x15, 0, 0, 0, 0, 0xf4]);
    assert_eq!(vF_find_main(&load(&fixture(&code)).unwrap()), Some(BASE));
}

#[test]
fn main_is_optional_and_ambiguous_or_invalid_candidates_are_rejected() {
    for argument in [
        vec![0x48, 0x8d, 0x7b, 1], // lea rdi, [rbx + 1], not RIP
        vec![0x48, 0x8d, 0x0d, 0, 0, 0, 0], // wrong destination
        vec![0x48, 0x8d, 0x3d, 0, 0, 0, 0x80], // signed underflow
        vec![0x48, 0xc7, 0xc7, 0, 0x30, 0x40, 0], // candidate in non-X range
        vec![0x48, 0xc7, 0xc7, 0x80, 0x10, 0x40, 0], // candidate in BSS
    ] {
        assert_eq!(vF_find_main(&load(&startup(&argument)).unwrap()), None);
    }
    let mov = [0x48, 0xc7, 0xc7, 0, 0x10, 0x40, 0];
    assert_eq!(vF_find_main(&load(&startup(&mov)).unwrap()), Some(BASE));
    for code in [&[0x90, 0xc3][..], &mov, &[0x0f][..]] {
        let image = load(&fixture(code)).unwrap();
        assert_eq!(vF_find_main(&image), None);
        assert!(vF_disasm_raw_bytes(code, image.entry()).is_ok());
    }
    let mut bytes = startup(&mov);
    let call_offset = CODE_OFFSET + START_OFFSET + PROLOGUE.len() + mov.len();
    bytes[call_offset] = 0xc3;
    assert_eq!(vF_find_main(&load(&bytes).unwrap()), None);
}

#[test]
fn disassembly_reports_prefix_and_preserves_instruction_and_flow_details() {
    let decoded = vF_disasm_raw_bytes(&[0x90, 0x0f], BASE).unwrap();
    assert_eq!(decoded.decoded_bytes, 1);
    assert_eq!(decoded.remaining, BASE + 1..BASE + 2);
    assert!(!decoded.is_complete());
    assert_eq!(decoded.instructions.len(), 1);
    assert_eq!(decoded.instructions[0].bytes, [0x90]);
    assert_eq!(decoded.instructions[0].address, BASE);
    assert_eq!(decoded.instructions[0].size, 1);
    assert!(matches!(decoded.instructions[0].flow, FlowKind::Sequential));
    let none = vF_disasm_raw_bytes(&[0x0f], BASE).unwrap();
    assert_eq!(none.decoded_bytes, 0);
    assert_eq!(none.remaining, BASE..BASE + 1);
    assert!(!none.is_complete());
    let empty = vF_disasm_raw_bytes(&[], u64::MAX).unwrap();
    assert!(empty.is_complete());
    assert_eq!(empty.decoded_bytes, 0);
    assert!(vF_disasm_raw_bytes(&[0x90], u64::MAX).is_err());
    let decoded = vF_disasm_raw_bytes(&[0xe8, 0, 0, 0, 0, 0x75, 0, 0xeb, 0, 0xc3], BASE).unwrap();
    assert!(decoded.is_complete());
    assert_eq!(decoded.decoded_bytes, 10);
    assert!(matches!(decoded.instructions[0].flow, FlowKind::Call));
    assert_eq!(decoded.instructions[0].target, Some(BASE + 5));
    assert!(matches!(decoded.instructions[1].flow, FlowKind::CondJump));
    assert_eq!(decoded.instructions[1].target, Some(BASE + 7));
    assert!(matches!(decoded.instructions[2].flow, FlowKind::Jump));
    assert!(matches!(decoded.instructions[3].flow, FlowKind::Return));
}

#[test]
fn cli_reports_errors_and_can_disassemble_without_main() {
    let dir = TempDir::new();
    let path = dir.write("without-main", &fixture(&[0x90, 0x0f]));
    let output = Command::new(env!("CARGO_BIN_EXE_vulnFuzz")).arg(&path).output().unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8(output.stdout).unwrap();
    for text in ["entry (ELF VA): 0x401000", "executable PT_LOAD:", "main hint: None", "complete: false", "remaining: 0x401001..0x401002"] {
        assert!(stdout.contains(text), "{stdout}");
    }
    let bad = dir.write("bad", b"not ELF");
    for args in [vec![], vec![path.clone(), path], vec![bad]] {
        let output = Command::new(env!("CARGO_BIN_EXE_vulnFuzz")).args(args).output().unwrap();
        assert!(!output.status.success());
        assert!(!output.stderr.is_empty());
        assert!(!String::from_utf8_lossy(&output.stderr).contains("panicked"));
    }
}

#[cfg(unix)]
#[test]
fn cli_accepts_non_utf8_paths() {
    use std::{ffi::OsString, os::unix::ffi::OsStringExt};
    let dir = TempDir::new();
    let path = dir.0.join(OsString::from_vec(b"elf-\xff".to_vec()));
    fs::write(&path, fixture(&[0xc3])).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_vulnFuzz")).arg(path).output().unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
}
