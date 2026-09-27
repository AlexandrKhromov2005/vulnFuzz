mod loader;
mod disasm;

fn main() {
    let path = "./mock_virus/target";
    let code_img = loader::vF_load(path).expect("load failed");
    //let insns = disasm::vF_disasm_raw_bytes(&code_img.sections[2].clone()).expect("disasm failed");
    //println!("{:#?}", insns);
    let main_addr = loader::vF_find_main(&code_img);
    println!("{:x}", main_addr.unwrap_or_default());
    return ();
}