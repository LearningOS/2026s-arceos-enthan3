#![no_std]

use allocator::{AllocError, BaseAllocator, ByteAllocator, PageAllocator};
use core::alloc::Layout;
use core::ptr::NonNull;

/// Early memory allocator
/// Use it before formal bytes-allocator and pages-allocator can work!
/// This is a double-end memory range:
/// - Alloc bytes forward
/// - Alloc pages backward
///
/// [ bytes-used | avail-area | pages-used ]
/// |            | -->    <-- |            |
/// start       b_pos        p_pos       end
///
/// For bytes area, 'count' records number of allocations.
/// When it goes down to ZERO, free bytes-used area.
/// For pages area, it will never be freed!
///
pub struct EarlyAllocator<const SIZE: usize> {
    start: usize,
    end: usize,
    b_pos: usize,
    p_pos: usize,
    allocations: usize,
    used_pages: usize,
}

impl<const SIZE: usize> EarlyAllocator<SIZE> {
    pub const fn new() -> Self {
        Self {
            start: 0,
            end: 0,
            b_pos: 0,
            p_pos: 0,
            allocations: 0,
            used_pages: 0,
        }
    }
}

impl<const SIZE: usize> BaseAllocator for EarlyAllocator<SIZE> {
    fn init(&mut self, start: usize, size: usize) {
        assert!(SIZE.is_power_of_two());
        let end = align_down(start.saturating_add(size), SIZE);
        let start = align_up(start, SIZE);
        assert!(start <= end);

        self.start = start;
        self.end = end;
        self.b_pos = start;
        self.p_pos = end;
        self.allocations = 0;
        self.used_pages = 0;
    }

    fn add_memory(&mut self, start: usize, size: usize) -> allocator::AllocResult {
        if self.start == self.end {
            self.init(start, size);
            return Ok(());
        }

        let end = align_down(start.saturating_add(size), SIZE);
        let start = align_up(start, SIZE);
        if start >= end {
            return Err(AllocError::InvalidParam);
        }

        if self.allocations == 0 && self.used_pages == 0 && end == self.start {
            self.start = start;
            self.b_pos = start;
            Ok(())
        } else if self.allocations == 0 && self.used_pages == 0 && start == self.end {
            self.end = end;
            self.p_pos = end;
            Ok(())
        } else {
            Err(AllocError::MemoryOverlap)
        }
    }
}

impl<const SIZE: usize> ByteAllocator for EarlyAllocator<SIZE> {
    fn alloc(&mut self, layout: Layout) -> allocator::AllocResult<NonNull<u8>> {
        if layout.size() == 0 {
            return Ok(NonNull::dangling());
        }

        let start = align_up(self.b_pos, layout.align());
        let end = start
            .checked_add(layout.size())
            .ok_or(AllocError::NoMemory)?;
        if end > self.p_pos {
            return Err(AllocError::NoMemory);
        }

        self.b_pos = end;
        self.allocations += 1;
        NonNull::new(start as *mut u8).ok_or(AllocError::NoMemory)
    }

    fn dealloc(&mut self, _pos: NonNull<u8>, layout: Layout) {
        if layout.size() == 0 {
            return;
        }
        if self.allocations > 0 {
            self.allocations -= 1;
            if self.allocations == 0 {
                self.b_pos = self.start;
            }
        }
    }

    fn total_bytes(&self) -> usize {
        self.end - self.start
    }

    fn used_bytes(&self) -> usize {
        self.b_pos - self.start
    }

    fn available_bytes(&self) -> usize {
        self.p_pos - self.b_pos
    }
}

impl<const SIZE: usize> PageAllocator for EarlyAllocator<SIZE> {
    const PAGE_SIZE: usize = SIZE;

    fn alloc_pages(
        &mut self,
        num_pages: usize,
        align_pow2: usize,
    ) -> allocator::AllocResult<usize> {
        if num_pages == 0
            || !align_pow2.is_power_of_two()
            || align_pow2 < SIZE
            || align_pow2 % SIZE != 0
        {
            return Err(AllocError::InvalidParam);
        }

        let size = num_pages.checked_mul(SIZE).ok_or(AllocError::NoMemory)?;
        let start = self
            .p_pos
            .checked_sub(size)
            .map(|pos| align_down(pos, align_pow2))
            .ok_or(AllocError::NoMemory)?;
        if start < self.b_pos {
            return Err(AllocError::NoMemory);
        }

        self.p_pos = start;
        self.used_pages += num_pages;
        Ok(start)
    }

    fn dealloc_pages(&mut self, pos: usize, num_pages: usize) {
        let _ = (pos, num_pages);
    }

    fn total_pages(&self) -> usize {
        (self.end - self.start) / SIZE
    }

    fn used_pages(&self) -> usize {
        self.used_pages
    }

    fn available_pages(&self) -> usize {
        (self.p_pos - self.b_pos) / SIZE
    }
}

#[inline]
const fn align_down(pos: usize, align: usize) -> usize {
    pos & !(align - 1)
}

#[inline]
const fn align_up(pos: usize, align: usize) -> usize {
    align_down(pos.saturating_add(align - 1), align)
}
