//! Memory map preservation, user-buffer validation, and shared-memory handles.
//!
//! This module does not implement real page tables yet. It provides the
//! no-std-friendly host-mode contracts needed by the MVK: bounded memory map
//! storage, explicit user range validation, allocator phase tracking, and
//! sealable shared-memory metadata.

use crate::capability::TaskId;
use crate::error::{KernelError, KernelResult};
use crate::syscall::{UserBuffer, USER_BUFFER_READ, USER_BUFFER_WRITE};

/// Maximum boot memory map entries preserved by the skeleton.
pub const MAX_MEMORY_REGIONS: usize = 64;

/// Maximum shared-memory regions tracked by the skeleton.
pub const MAX_SHARED_REGIONS: usize = 32;

/// Default lower bound for userspace mappings.
pub const DEFAULT_USER_LOWER_BOUND: u64 = 0x0000_0000_0000_1000;

/// Default upper bound for canonical user addresses on the initial target.
pub const DEFAULT_USER_UPPER_BOUND: u64 = 0x0000_8000_0000_0000;

/// Default maximum userspace buffer accepted for copy/pin operations.
pub const DEFAULT_MAX_USER_BUFFER_LEN: u64 = 16 * 1024 * 1024;

/// Physical address wrapper used by memory-map APIs.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
pub struct PhysicalAddress(pub u64);

/// Virtual address wrapper used by mapping and validation APIs.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
pub struct VirtualAddress(pub u64);

/// Kinds of memory regions the kernel tracks from boot onward.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemoryRegionKind {
    /// RAM available after boot reservations are applied.
    Usable,
    /// Firmware, bootloader, or unknown reserved memory.
    Reserved,
    /// Kernel executable text.
    KernelText,
    /// Kernel read-only data.
    KernelReadOnly,
    /// Kernel writable data.
    KernelData,
    /// Kernel or task stack region.
    Stack,
    /// Userspace range owned by a task.
    User,
    /// MMIO region.
    Mmio,
    /// Guard page or unmapped sentinel range.
    Guard,
    /// Bootloader-provided handoff data.
    Bootloader,
    /// Device-owned DMA or aperture range.
    Device,
}

/// Bitset describing mapping permissions and special handling.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MemoryPermissions {
    bits: u32,
}

impl MemoryPermissions {
    /// Mapping may be read.
    pub const READ: Self = Self { bits: 1 << 0 };
    /// Mapping may be written.
    pub const WRITE: Self = Self { bits: 1 << 1 };
    /// Mapping may be executed.
    pub const EXECUTE: Self = Self { bits: 1 << 2 };
    /// Mapping is accessible from userspace.
    pub const USER: Self = Self { bits: 1 << 3 };
    /// Mapping is device/MMIO memory.
    pub const DEVICE: Self = Self { bits: 1 << 4 };
    /// Mapping has been sealed against further writes.
    pub const SEALED: Self = Self { bits: 1 << 5 };

    /// Empty permissions set.
    pub const fn empty() -> Self {
        Self { bits: 0 }
    }

    /// Builds permissions from raw bits after rejecting unknown flags.
    pub const fn from_bits(bits: u32) -> KernelResult<Self> {
        if bits & !Self::known_bits() == 0 {
            Ok(Self { bits })
        } else {
            Err(KernelError::ReservedBits)
        }
    }

    /// Returns all known permission bits.
    pub const fn known_bits() -> u32 {
        Self::READ.bits
            | Self::WRITE.bits
            | Self::EXECUTE.bits
            | Self::USER.bits
            | Self::DEVICE.bits
            | Self::SEALED.bits
    }

    /// Returns raw permission bits.
    pub const fn bits(self) -> u32 {
        self.bits
    }

    /// Returns `true` when all bits in `other` are present.
    pub const fn contains(self, other: Self) -> bool {
        self.bits & other.bits == other.bits
    }

    /// Returns a permission set containing bits from both operands.
    pub const fn union(self, other: Self) -> Self {
        Self {
            bits: self.bits | other.bits,
        }
    }

    /// Returns `true` when the permissions are safe for userspace mapping.
    pub const fn is_user_mapping(self) -> bool {
        self.contains(Self::USER)
    }
}

/// One boot or virtual memory map entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MemoryRegion {
    /// Base address of the region.
    pub start: u64,
    /// Region length in bytes.
    pub len: u64,
    /// Region classification.
    pub kind: MemoryRegionKind,
    /// Access permissions and special flags.
    pub permissions: MemoryPermissions,
}

impl MemoryRegion {
    /// Empty sentinel region used to initialize bounded arrays.
    pub const EMPTY: Self = Self {
        start: 0,
        len: 0,
        kind: MemoryRegionKind::Reserved,
        permissions: MemoryPermissions::empty(),
    };

    /// Creates a region after basic range validation.
    pub const fn new(
        start: u64,
        len: u64,
        kind: MemoryRegionKind,
        permissions: MemoryPermissions,
    ) -> KernelResult<Self> {
        if len == 0 {
            return Err(KernelError::InvalidArgument);
        }
        if start.checked_add(len).is_none() {
            return Err(KernelError::InvalidArgument);
        }
        Ok(Self {
            start,
            len,
            kind,
            permissions,
        })
    }

    /// Exclusive end address.
    pub const fn end(self) -> u64 {
        self.start + self.len
    }

    /// Returns `true` if the region overlaps `other`.
    pub const fn overlaps(self, other: Self) -> bool {
        self.start < other.end() && other.start < self.end()
    }

    /// Returns `true` if this region fully contains the range.
    pub const fn contains_range(self, start: u64, len: u64) -> bool {
        if let Some(end) = start.checked_add(len) {
            start >= self.start && end <= self.end()
        } else {
            false
        }
    }
}

/// Bounded boot memory map with overlap validation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemoryMap {
    regions: [MemoryRegion; MAX_MEMORY_REGIONS],
    len: usize,
}

impl MemoryMap {
    /// Creates an empty memory map.
    pub const fn new() -> Self {
        Self {
            regions: [MemoryRegion::EMPTY; MAX_MEMORY_REGIONS],
            len: 0,
        }
    }

    /// Number of active memory regions.
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Returns `true` when the map has no entries.
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Active memory map entries.
    pub fn regions(&self) -> &[MemoryRegion] {
        &self.regions[..self.len]
    }

    /// Adds a region, rejecting overlaps and capacity overflow.
    pub fn push(&mut self, region: MemoryRegion) -> KernelResult<()> {
        if self.len == MAX_MEMORY_REGIONS {
            return Err(KernelError::CapacityExceeded);
        }
        if self
            .regions()
            .iter()
            .any(|existing| existing.overlaps(region))
        {
            return Err(KernelError::Overlap);
        }
        self.regions[self.len] = region;
        self.len += 1;
        Ok(())
    }

    /// Finds the first region containing the range.
    pub fn find_containing(&self, start: u64, len: u64) -> Option<MemoryRegion> {
        self.regions()
            .iter()
            .copied()
            .find(|region| region.contains_range(start, len))
    }

    /// Totals bytes of regions with `kind`.
    pub fn total_by_kind(&self, kind: MemoryRegionKind) -> u64 {
        self.regions()
            .iter()
            .filter(|region| region.kind == kind)
            .map(|region| region.len)
            .sum()
    }
}

impl Default for MemoryMap {
    fn default() -> Self {
        Self::new()
    }
}

/// Allocator initialization phase.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AllocatorPhase {
    /// No allocator is available.
    Uninitialized,
    /// Boot bump allocation is available.
    BootBump,
    /// Frame allocator is available.
    Frame,
    /// Kernel heap/slab allocation is available.
    Heap,
}

/// Required user-buffer access direction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BufferAccess {
    /// Kernel reads from userspace memory.
    Read,
    /// Kernel writes to userspace memory.
    Write,
    /// Kernel both reads and writes userspace memory.
    ReadWrite,
}

/// Validated userspace buffer range.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidatedUserBuffer {
    /// Validated starting address.
    pub ptr: u64,
    /// Validated byte length.
    pub len: u64,
    /// Access required by the kernel operation.
    pub access: BufferAccess,
}

/// ABI-safe shared memory handle.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SharedMemoryHandle {
    /// Registry-assigned shared-memory identifier. Zero is invalid.
    pub id: u64,
    /// Owning task.
    pub owner_task: TaskId,
    /// Permission bits for consumers.
    pub permissions: u32,
}

impl SharedMemoryHandle {
    /// Invalid zero handle.
    pub const fn invalid() -> Self {
        Self {
            id: 0,
            owner_task: 0,
            permissions: 0,
        }
    }
}

/// Metadata for one shared range.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SharedRegion {
    /// Public handle metadata.
    pub handle: SharedMemoryHandle,
    /// Shared range start.
    pub start: u64,
    /// Shared range byte length.
    pub len: u64,
    /// Whether writes are permanently disabled.
    pub sealed: bool,
}

impl SharedRegion {
    const EMPTY: Self = Self {
        handle: SharedMemoryHandle::invalid(),
        start: 0,
        len: 0,
        sealed: true,
    };
}

/// Memory pressure and allocator diagnostics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MemoryStats {
    /// Total usable RAM preserved from the boot map.
    pub usable_bytes: u64,
    /// Number of active memory map regions.
    pub region_count: usize,
    /// Active shared-memory region count.
    pub shared_region_count: usize,
    /// Current allocator phase.
    pub allocator_phase: AllocatorPhase,
}

/// Frame allocator contract for future platform-specific implementations.
pub trait FrameAllocator {
    /// Allocates one physical frame and returns its base address.
    fn allocate_frame(&mut self) -> KernelResult<PhysicalAddress>;

    /// Releases a previously allocated physical frame.
    fn deallocate_frame(&mut self, frame: PhysicalAddress) -> KernelResult<()>;
}

/// Host-mode memory manager skeleton.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemoryManager {
    map: MemoryMap,
    allocator_phase: AllocatorPhase,
    user_lower_bound: u64,
    user_upper_bound: u64,
    max_user_buffer_len: u64,
    minimum_user_alignment: u64,
    shared_regions: [SharedRegion; MAX_SHARED_REGIONS],
    next_shared_id: u64,
}

impl MemoryManager {
    /// Creates a manager with conservative userspace validation bounds.
    pub const fn new() -> Self {
        Self {
            map: MemoryMap::new(),
            allocator_phase: AllocatorPhase::Uninitialized,
            user_lower_bound: DEFAULT_USER_LOWER_BOUND,
            user_upper_bound: DEFAULT_USER_UPPER_BOUND,
            max_user_buffer_len: DEFAULT_MAX_USER_BUFFER_LEN,
            minimum_user_alignment: 1,
            shared_regions: [SharedRegion::EMPTY; MAX_SHARED_REGIONS],
            next_shared_id: 1,
        }
    }

    /// Returns the preserved memory map.
    pub const fn memory_map(&self) -> &MemoryMap {
        &self.map
    }

    /// Mutable access to the preserved memory map for boot setup.
    pub fn memory_map_mut(&mut self) -> &mut MemoryMap {
        &mut self.map
    }

    /// Current allocator phase.
    pub const fn allocator_phase(&self) -> AllocatorPhase {
        self.allocator_phase
    }

    /// Advances the allocator phase in the boot-defined order.
    pub fn set_allocator_phase(&mut self, phase: AllocatorPhase) -> KernelResult<()> {
        let valid = self.allocator_phase == phase
            || matches!(
                (self.allocator_phase, phase),
                (AllocatorPhase::Uninitialized, AllocatorPhase::BootBump)
                    | (AllocatorPhase::BootBump, AllocatorPhase::Frame)
                    | (AllocatorPhase::Frame, AllocatorPhase::Heap)
            );
        if !valid {
            return Err(KernelError::InvalidState);
        }
        self.allocator_phase = phase;
        Ok(())
    }

    /// Sets the accepted userspace address range.
    pub fn set_user_bounds(&mut self, lower: u64, upper: u64) -> KernelResult<()> {
        if lower == 0 || lower >= upper {
            return Err(KernelError::InvalidArgument);
        }
        self.user_lower_bound = lower;
        self.user_upper_bound = upper;
        Ok(())
    }

    /// Sets the maximum copy/pin length accepted for userspace buffers.
    pub fn set_max_user_buffer_len(&mut self, max_len: u64) -> KernelResult<()> {
        if max_len == 0 {
            return Err(KernelError::InvalidArgument);
        }
        self.max_user_buffer_len = max_len;
        Ok(())
    }

    /// Sets the minimum alignment required for userspace buffer pointers.
    pub fn set_minimum_user_alignment(&mut self, alignment: u64) -> KernelResult<()> {
        if alignment == 0 || !alignment.is_power_of_two() {
            return Err(KernelError::InvalidArgument);
        }
        self.minimum_user_alignment = alignment;
        Ok(())
    }

    /// Validates a raw user range without interpreting buffer direction flags.
    pub fn validate_user_range(&self, ptr: u64, len: u64) -> KernelResult<()> {
        if ptr == 0 || len == 0 {
            return Err(KernelError::InvalidUserBuffer);
        }
        if len > self.max_user_buffer_len {
            return Err(KernelError::BufferTooLarge);
        }
        let end = ptr.checked_add(len).ok_or(KernelError::InvalidUserBuffer)?;
        if ptr < self.user_lower_bound || end > self.user_upper_bound {
            return Err(KernelError::BufferOutOfRange);
        }
        if ptr & (self.minimum_user_alignment - 1) != 0 {
            return Err(KernelError::InvalidUserBuffer);
        }
        Ok(())
    }

    /// Validates a syscall user buffer before a subsystem can read or write it.
    pub fn validate_user_buffer(
        &self,
        buffer: UserBuffer,
        access: BufferAccess,
    ) -> KernelResult<ValidatedUserBuffer> {
        if buffer.reserved != 0 || buffer.has_unknown_flags() {
            return Err(KernelError::ReservedBits);
        }
        let required = match access {
            BufferAccess::Read => USER_BUFFER_READ,
            BufferAccess::Write => USER_BUFFER_WRITE,
            BufferAccess::ReadWrite => USER_BUFFER_READ | USER_BUFFER_WRITE,
        };
        if buffer.flags & required != required {
            return Err(KernelError::PermissionDenied);
        }
        self.validate_user_range(buffer.ptr, buffer.len)?;
        Ok(ValidatedUserBuffer {
            ptr: buffer.ptr,
            len: buffer.len,
            access,
        })
    }

    /// Registers a sealable shared-memory range after validating ownership range.
    pub fn share_region(
        &mut self,
        owner_task: TaskId,
        start: u64,
        len: u64,
        permissions: MemoryPermissions,
    ) -> KernelResult<SharedMemoryHandle> {
        self.validate_user_range(start, len)?;
        if permissions.contains(MemoryPermissions::SEALED) {
            return Err(KernelError::Sealed);
        }
        let slot = self
            .shared_regions
            .iter_mut()
            .find(|region| region.handle.id == 0)
            .ok_or(KernelError::CapacityExceeded)?;

        let handle = SharedMemoryHandle {
            id: self.next_shared_id,
            owner_task,
            permissions: permissions.bits(),
        };
        self.next_shared_id = self
            .next_shared_id
            .checked_add(1)
            .ok_or(KernelError::Internal)?;
        *slot = SharedRegion {
            handle,
            start,
            len,
            sealed: false,
        };
        Ok(handle)
    }

    /// Marks a shared-memory handle as sealed against further writes.
    pub fn seal_shared_region(&mut self, handle: SharedMemoryHandle) -> KernelResult<()> {
        let region = self
            .shared_regions
            .iter_mut()
            .find(|region| region.handle.id == handle.id && region.handle.id != 0)
            .ok_or(KernelError::NotFound)?;
        region.sealed = true;
        region.handle.permissions &= !MemoryPermissions::WRITE.bits();
        region.handle.permissions |= MemoryPermissions::SEALED.bits();
        Ok(())
    }

    /// Looks up a shared-memory region by handle.
    pub fn shared_region(&self, handle: SharedMemoryHandle) -> KernelResult<SharedRegion> {
        self.shared_regions
            .iter()
            .copied()
            .find(|region| region.handle.id == handle.id && region.handle.id != 0)
            .ok_or(KernelError::NotFound)
    }

    /// Returns current memory diagnostics.
    pub fn stats(&self) -> MemoryStats {
        MemoryStats {
            usable_bytes: self.map.total_by_kind(MemoryRegionKind::Usable),
            region_count: self.map.len(),
            shared_region_count: self
                .shared_regions
                .iter()
                .filter(|region| region.handle.id != 0)
                .count(),
            allocator_phase: self.allocator_phase,
        }
    }
}

impl Default for MemoryManager {
    fn default() -> Self {
        Self::new()
    }
}
