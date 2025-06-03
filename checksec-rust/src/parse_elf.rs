use goblin::elf::Elf;

pub fn parse_elf(elf: &Elf){
    check_has_canary(elf);
}

fn check_has_canary(elf: &Elf){
    for symbol in &elf.dynsyms{
        println!("symbol: {:#?}", &symbol)
    }
}