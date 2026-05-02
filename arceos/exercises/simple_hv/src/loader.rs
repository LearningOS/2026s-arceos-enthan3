use alloc::vec;
use axhal::mem::{phys_to_virt, MemoryAddr};
use axhal::paging::MappingFlags;
use axmm::AddrSpace;
use std::fs::File;
use std::io::{self, Read};

use crate::VM_ENTRY;

pub fn load_vm_image(fname: &str, uspace: &mut AddrSpace) -> io::Result<()> {
    let buf = load_file(fname)?;
    let map_size = buf.len().align_up_4k();

    uspace
        .map_alloc(
            VM_ENTRY.into(),
            map_size,
            MappingFlags::READ | MappingFlags::WRITE | MappingFlags::EXECUTE | MappingFlags::USER,
            true,
        )
        .unwrap();

    let (paddr, _, _) = uspace
        .page_table()
        .query(VM_ENTRY.into())
        .unwrap_or_else(|_| panic!("Mapping failed for segment: {:#x}", VM_ENTRY));

    ax_println!("paddr: {:#x}", paddr);

    unsafe {
        core::ptr::copy_nonoverlapping(buf.as_ptr(), phys_to_virt(paddr).as_mut_ptr(), buf.len());
    }

    Ok(())
}

fn load_file(fname: &str) -> io::Result<alloc::vec::Vec<u8>> {
    ax_println!("app: {}", fname);
    let mut file = File::open(fname)?;
    let size = file.metadata()?.len() as usize;
    let mut buf = vec![0; size];
    file.read_exact(&mut buf)?;
    Ok(buf)
}
