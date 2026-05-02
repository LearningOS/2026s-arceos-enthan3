use alloc::vec;
use alloc::vec::Vec;
use axhal::mem::{MemoryAddr, VirtAddr, PAGE_SIZE_4K};
use axhal::paging::MappingFlags;
use axmm::AddrSpace;
use std::fs::File;
use std::io::Seek;
use std::io::SeekFrom;
use std::io::{self, Read};

use elf::abi::{PT_INTERP, PT_LOAD};
use elf::endian::AnyEndian;
use elf::parse::ParseAt;
use elf::segment::ProgramHeader;
use elf::segment::SegmentTable;
use elf::ElfBytes;

const ELF_HEAD_BUF_SIZE: usize = 256;

pub struct AppInfo {
    pub entry: usize,
    pub phdr: usize,
    pub phent: usize,
    pub phnum: usize,
    pub heap_base: usize,
}

pub fn load_user_app(fname: &str, uspace: &mut AddrSpace) -> io::Result<AppInfo> {
    let mut file = File::open(fname)?;
    let (phdrs, entry, phoff, phent, phnum) = load_elf_phdrs(&mut file)?;
    let mut phdr_addr = 0;
    let mut heap_base = 0;

    for phdr in &phdrs {
        ax_println!(
            "phdr: offset: {:#X}=>{:#X} size: {:#X}=>{:#X}",
            phdr.p_offset,
            phdr.p_vaddr,
            phdr.p_filesz,
            phdr.p_memsz
        );
        if phdr.p_type != PT_LOAD {
            continue;
        }
        let segment_file_end = phdr.p_offset + phdr.p_filesz;
        if phdr.p_offset <= phoff as u64 && (phoff as u64) < segment_file_end {
            phdr_addr = phdr.p_vaddr as usize + phoff - phdr.p_offset as usize;
        }
        heap_base = heap_base.max((phdr.p_vaddr + phdr.p_memsz) as usize);

        let vaddr = VirtAddr::from(phdr.p_vaddr as usize).align_down_4k();
        let vaddr_end = VirtAddr::from((phdr.p_vaddr + phdr.p_memsz) as usize).align_up_4k();

        ax_println!("{:#x} - {:#x}", vaddr, vaddr_end);
        uspace.map_alloc(
            vaddr,
            vaddr_end - vaddr,
            MappingFlags::READ | MappingFlags::WRITE | MappingFlags::EXECUTE | MappingFlags::USER,
            true,
        )?;

        let mut data = vec![0u8; phdr.p_memsz as usize];
        file.seek(SeekFrom::Start(phdr.p_offset))?;

        let filesz = phdr.p_filesz as usize;
        let mut index = 0;
        while index < filesz {
            let n = file.read(&mut data[index..filesz])?;
            index += n;
        }
        assert_eq!(index, filesz);
        uspace.write(VirtAddr::from(phdr.p_vaddr as usize), &data)?;
    }

    Ok(AppInfo {
        entry,
        phdr: phdr_addr,
        phent,
        phnum,
        heap_base: heap_base.align_up_4k(),
    })
}

fn load_elf_phdrs(file: &mut File) -> io::Result<(Vec<ProgramHeader>, usize, usize, usize, usize)> {
    let mut buf: [u8; ELF_HEAD_BUF_SIZE] = [0; ELF_HEAD_BUF_SIZE];
    file.read(&mut buf)?;

    let ehdr = ElfBytes::<AnyEndian>::parse_elf_header(&buf[..]).unwrap();
    info!("e_entry: {:#X}", ehdr.e_entry);

    let phnum = ehdr.e_phnum as usize;
    // Validate phentsize before trying to read the table so that we can error early for corrupted files
    let entsize = ProgramHeader::validate_entsize(ehdr.class, ehdr.e_phentsize as usize).unwrap();
    let size = entsize.checked_mul(phnum).unwrap();
    assert!(size > 0 && size <= PAGE_SIZE_4K);
    let phoff = ehdr.e_phoff;
    let mut buf = alloc::vec![0u8; size];
    let _ = file.seek(SeekFrom::Start(phoff));
    file.read(&mut buf)?;
    let phdrs = SegmentTable::new(ehdr.endianness, ehdr.class, &buf[..]);

    let phdrs: Vec<ProgramHeader> = phdrs
        .iter()
        .filter(|phdr| phdr.p_type == PT_LOAD || phdr.p_type == PT_INTERP)
        .collect();
    Ok((
        phdrs,
        ehdr.e_entry as usize,
        ehdr.e_phoff as usize,
        ehdr.e_phentsize as usize,
        ehdr.e_phnum as usize,
    ))
}
