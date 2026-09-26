mod loader;
mod disasm;

fn main() {
    let path = "./mock_virus/target";
    let code_img = loader::vF_load(path).expect("load failed");
    let insns = disasm::vF_disasm_raw_bytes(code_img.sections[0].clone()).expect("disasm failed");
    println!("{:#?}", insns);
    return ();
}