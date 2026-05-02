#![allow(dead_code)]

use alloc::vec;
use core::ffi::{c_char, c_int, c_void};
use core::sync::atomic::{AtomicUsize, Ordering};

use memory_addr::{MemoryAddr, VirtAddr, VirtAddrRange, PAGE_SIZE_4K};

use arceos_posix_api as api;
use axerrno::LinuxError;
use axhal::arch::TrapFrame;
use axhal::paging::MappingFlags;
use axhal::trap::{register_trap_handler, SYSCALL};
use axtask::current;
use axtask::TaskExtRef;

const SYS_IOCTL: usize = 29;
const SYS_OPENAT: usize = 56;
const SYS_CLOSE: usize = 57;
const SYS_READ: usize = 63;
const SYS_WRITE: usize = 64;
const SYS_WRITEV: usize = 66;
const SYS_EXIT: usize = 93;
const SYS_EXIT_GROUP: usize = 94;
const SYS_SET_ROBUST_LIST: usize = 99;
const SYS_SET_TID_ADDRESS: usize = 96;
const SYS_BRK: usize = 214;
const SYS_MMAP: usize = 222;
const SYS_MPROTECT: usize = 226;

const AT_FDCWD: i32 = -100;
const USER_HEAP_BASE: usize = 0x90_000;
const MMAP_BASE: usize = 0x1000_0000;

static BRK_BASE: AtomicUsize = AtomicUsize::new(0);
static BRK_CURRENT: AtomicUsize = AtomicUsize::new(0);
static BRK_MAPPED_END: AtomicUsize = AtomicUsize::new(0);

pub fn init_brk(heap_base: usize) {
    let heap_base = heap_base.align_up_4k();
    BRK_BASE.store(heap_base, Ordering::Relaxed);
    BRK_CURRENT.store(heap_base, Ordering::Relaxed);
    BRK_MAPPED_END.store(heap_base, Ordering::Relaxed);
}

/// Macro to generate syscall body
///
/// It will receive a function which return Result<_, LinuxError> and convert it to
/// the type which is specified by the caller.
#[macro_export]
macro_rules! syscall_body {
    ($fn: ident, $($stmt: tt)*) => {{
        #[allow(clippy::redundant_closure_call)]
        let res = (|| -> axerrno::LinuxResult<_> { $($stmt)* })();
        match res {
            Ok(_) | Err(axerrno::LinuxError::EAGAIN) => debug!(concat!(stringify!($fn), " => {:?}"),  res),
            Err(_) => info!(concat!(stringify!($fn), " => {:?}"), res),
        }
        match res {
            Ok(v) => v as _,
            Err(e) => {
                -e.code() as _
            }
        }
    }};
}

bitflags::bitflags! {
    #[derive(Debug)]
    /// permissions for sys_mmap
    ///
    /// See <https://github.com/bminor/glibc/blob/master/bits/mman.h>
    struct MmapProt: i32 {
        /// Page can be read.
        const PROT_READ = 1 << 0;
        /// Page can be written.
        const PROT_WRITE = 1 << 1;
        /// Page can be executed.
        const PROT_EXEC = 1 << 2;
    }
}

impl From<MmapProt> for MappingFlags {
    fn from(value: MmapProt) -> Self {
        let mut flags = MappingFlags::USER;
        if value.contains(MmapProt::PROT_READ) {
            flags |= MappingFlags::READ;
        }
        if value.contains(MmapProt::PROT_WRITE) {
            flags |= MappingFlags::WRITE;
        }
        if value.contains(MmapProt::PROT_EXEC) {
            flags |= MappingFlags::EXECUTE;
        }
        flags
    }
}

bitflags::bitflags! {
    #[derive(Debug)]
    /// flags for sys_mmap
    ///
    /// See <https://github.com/bminor/glibc/blob/master/bits/mman.h>
    struct MmapFlags: i32 {
        /// Share changes
        const MAP_SHARED = 1 << 0;
        /// Changes private; copy pages on write.
        const MAP_PRIVATE = 1 << 1;
        /// Map address must be exactly as requested, no matter whether it is available.
        const MAP_FIXED = 1 << 4;
        /// Don't use a file.
        const MAP_ANONYMOUS = 1 << 5;
        /// Don't check for reservations.
        const MAP_NORESERVE = 1 << 14;
        /// Allocation is for a stack.
        const MAP_STACK = 0x20000;
    }
}

#[register_trap_handler(SYSCALL)]
fn handle_syscall(tf: &TrapFrame, syscall_num: usize) -> isize {
    ax_println!("handle_syscall [{}] ...", syscall_num);
    let ret = match syscall_num {
        SYS_IOCTL => sys_ioctl(tf.arg0() as _, tf.arg1() as _, tf.arg2() as _) as _,
        SYS_SET_TID_ADDRESS => sys_set_tid_address(tf.arg0() as _),
        SYS_SET_ROBUST_LIST => 0,
        SYS_OPENAT => sys_openat(
            tf.arg0() as _,
            tf.arg1() as _,
            tf.arg2() as _,
            tf.arg3() as _,
        ),
        SYS_CLOSE => sys_close(tf.arg0() as _),
        SYS_READ => sys_read(tf.arg0() as _, tf.arg1() as _, tf.arg2() as _),
        SYS_WRITE => sys_write(tf.arg0() as _, tf.arg1() as _, tf.arg2() as _),
        SYS_WRITEV => sys_writev(tf.arg0() as _, tf.arg1() as _, tf.arg2() as _),
        SYS_EXIT_GROUP => {
            ax_println!("[SYS_EXIT_GROUP]: system is exiting ..");
            axtask::exit(tf.arg0() as _)
        }
        SYS_EXIT => {
            ax_println!("[SYS_EXIT]: system is exiting ..");
            axtask::exit(tf.arg0() as _)
        }
        SYS_BRK => sys_brk(tf.arg0()),
        SYS_MMAP => sys_mmap(
            tf.arg0() as _,
            tf.arg1() as _,
            tf.arg2() as _,
            tf.arg3() as _,
            tf.arg4() as _,
            tf.arg5() as _,
        ),
        SYS_MPROTECT => sys_mprotect(tf.arg0(), tf.arg1(), tf.arg2() as _),
        _ => {
            ax_println!("Unimplemented syscall: {}", syscall_num);
            -LinuxError::ENOSYS.code() as _
        }
    };
    ret
}

fn sys_brk(addr: usize) -> isize {
    let task = current();
    let mut aspace = task.task_ext().aspace.lock();

    if BRK_BASE.load(Ordering::Relaxed) == 0 {
        let limit = VirtAddrRange::from_start_size(aspace.base(), aspace.size());
        let base = aspace
            .find_free_area(VirtAddr::from(USER_HEAP_BASE), PAGE_SIZE_4K, limit)
            .map_or(USER_HEAP_BASE, |addr| addr.as_usize());
        BRK_BASE.store(base, Ordering::Relaxed);
        BRK_CURRENT.store(base, Ordering::Relaxed);
        BRK_MAPPED_END.store(base, Ordering::Relaxed);
    }

    let base = BRK_BASE.load(Ordering::Relaxed);
    let current = BRK_CURRENT.load(Ordering::Relaxed);
    if addr == 0 {
        return current as isize;
    }
    if addr < base {
        return current as isize;
    }

    let mapped_end = BRK_MAPPED_END.load(Ordering::Relaxed);
    if addr > mapped_end {
        let new_mapped_end = addr.align_up_4k();
        if aspace
            .map_alloc(
                VirtAddr::from(mapped_end),
                new_mapped_end - mapped_end,
                MappingFlags::READ | MappingFlags::WRITE | MappingFlags::USER,
                true,
            )
            .is_err()
        {
            return current as isize;
        }
        BRK_MAPPED_END.store(new_mapped_end, Ordering::Relaxed);
    }

    BRK_CURRENT.store(addr, Ordering::Relaxed);
    addr as isize
}

fn sys_mprotect(addr: usize, length: usize, prot: i32) -> isize {
    syscall_body!(sys_mprotect, {
        if !addr.is_aligned_4k() {
            return Err(LinuxError::EINVAL);
        }
        let _ = length;
        MmapProt::from_bits(prot).ok_or(LinuxError::EINVAL)?;
        Ok(0)
    })
}

#[allow(unused_variables)]
fn sys_mmap(
    addr: *mut usize,
    length: usize,
    prot: i32,
    flags: i32,
    fd: i32,
    _offset: isize,
) -> isize {
    syscall_body!(sys_mmap, {
        if length == 0 || _offset < 0 || !(_offset as usize).is_aligned_4k() {
            return Err(LinuxError::EINVAL);
        }

        let prot = MmapProt::from_bits(prot).ok_or(LinuxError::EINVAL)?;
        let flags = MmapFlags::from_bits(flags).ok_or(LinuxError::EINVAL)?;
        if !flags.intersects(MmapFlags::MAP_PRIVATE | MmapFlags::MAP_SHARED) {
            return Err(LinuxError::EINVAL);
        }
        if !flags.contains(MmapFlags::MAP_ANONYMOUS) && fd < 0 {
            return Err(LinuxError::EBADF);
        }

        let map_size = length.align_up_4k();
        let task = current();
        let mut aspace = task.task_ext().aspace.lock();
        let start = if flags.contains(MmapFlags::MAP_FIXED) {
            let start = VirtAddr::from(addr as usize);
            if !start.is_aligned_4k() {
                return Err(LinuxError::EINVAL);
            }
            start
        } else {
            let hint = if addr.is_null() {
                VirtAddr::from(MMAP_BASE)
            } else {
                VirtAddr::from(addr as usize).align_up_4k()
            };
            let limit = VirtAddrRange::from_start_size(aspace.base(), aspace.size());
            aspace
                .find_free_area(hint, map_size, limit)
                .ok_or(LinuxError::ENOMEM)?
        };

        aspace
            .map_alloc(start, map_size, MappingFlags::from(prot), true)
            .map_err(LinuxError::from)?;

        if !flags.contains(MmapFlags::MAP_ANONYMOUS) {
            if api::sys_lseek(fd, _offset as _, 0) < 0 {
                return Err(LinuxError::EINVAL);
            }

            let file = api::get_file_like(fd)?;
            let mut buf = vec![0; length];
            let mut offset = 0;
            while offset < length {
                let n = file.read(&mut buf[offset..])?;
                if n == 0 {
                    break;
                }
                offset += n;
            }
            aspace
                .write(start, &buf[..offset])
                .map_err(LinuxError::from)?;
        }

        Ok(start.as_usize() as isize)
    })
}

fn sys_openat(dfd: c_int, fname: *const c_char, flags: c_int, mode: api::ctypes::mode_t) -> isize {
    assert_eq!(dfd, AT_FDCWD);
    api::sys_open(fname, flags, mode) as isize
}

fn sys_close(fd: i32) -> isize {
    api::sys_close(fd) as isize
}

fn sys_read(fd: i32, buf: *mut c_void, count: usize) -> isize {
    api::sys_read(fd, buf, count)
}

fn sys_write(fd: i32, buf: *const c_void, count: usize) -> isize {
    api::sys_write(fd, buf, count)
}

fn sys_writev(fd: i32, iov: *const api::ctypes::iovec, iocnt: i32) -> isize {
    unsafe { api::sys_writev(fd, iov, iocnt) }
}

fn sys_set_tid_address(tid_ptd: *const i32) -> isize {
    let curr = current();
    curr.task_ext().set_clear_child_tid(tid_ptd as _);
    curr.id().as_u64() as isize
}

fn sys_ioctl(_fd: i32, _op: usize, _argp: *mut c_void) -> i32 {
    ax_println!("Ignore SYS_IOCTL");
    0
}
