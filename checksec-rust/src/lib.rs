use goblin::{error, Object};
use goblin::mach::Mach;

use checksec::pe::CheckSecResults as CheckSecResults_pe;
use checksec::elf::CheckSecResults as CheckSecResults_elf; 
use checksec::macho::CheckSecResults as CheckSecResults_macho;

pub enum CheckSecResults {
    Elf(CheckSecResults_elf),
    Pe(CheckSecResults_pe),
    Macho(CheckSecResults_macho),
}

pub fn checksec (buffer: &Vec<u8>) -> error::Result<CheckSecResults> {
    match Object::parse(&buffer)? {
        Object::Elf(elf) => {
            let result = CheckSecResults_elf::parse(&elf, &buffer);
            Ok(CheckSecResults::Elf(result))
        },
        Object::PE(pe) => {
            let result = CheckSecResults_pe::parse(&pe, &buffer);
            Ok(CheckSecResults::Pe(result))
        },
        Object::Mach(mach) => match mach {
            Mach::Binary(mach) => {
                let result = CheckSecResults_macho::parse(&mach); 
                Ok(CheckSecResults::Macho(result))
            }
            _ => { Err(error::Error::Malformed("fat binaries currently not supported".into())) }
        },
        _ => {  Err(error::Error::Malformed("unsupported file type".into())) }
    }
}

