use goblin::{error, Object};
mod parse_elf;

fn parse_bin (buffer: &Vec<u8>) -> error::Result<()> {
    match Object::parse(&buffer)? {
        Object::Elf(elf) => {
            parse_elf::parse_elf(&elf);
        },
        Object::PE(pe) => {
            println!("pe: {:#?}", &pe);
        },
        Object::COFF(coff) => {
            println!("coff: {:#?}", &coff);
        },
        Object::Mach(mach) => {
            println!("mach: {:#?}", &mach);
        },
        Object::Archive(archive) => {
            println!("archive: {:#?}", &archive);
        },
        Object::Unknown(magic) => { println!("unknown magic: {:#x}", magic) },
        _ => { }
    }
    Ok(())
}

pub fn checksec(buffer: &Vec<u8>) {
    if let Err(e) = parse_bin(&buffer) {
        eprintln!("Error: {}", e);
    }
}
