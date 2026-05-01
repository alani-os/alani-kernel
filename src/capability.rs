//! Capability handles and deny-by-default authority checks.
//!
//! The kernel skeleton uses compact bitsets and a bounded handle registry so
//! host-mode tests can exercise attenuation, revocation, and authorization
//! without depending on a future security crate implementation.

use crate::error::{KernelError, KernelResult};

/// Maximum capability records held by the host-mode registry.
pub const MAX_CAPABILITY_RECORDS: usize = 64;

/// Stable task identifier used in capability ownership metadata.
pub type TaskId = u64;

/// Kernel-recognized authority bits.
///
/// Capabilities are represented as bit positions inside [`CapabilitySet`].
/// New public authority bits must be added deliberately because unknown bits
/// are rejected at trust boundaries.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Capability {
    /// Spawn a new task.
    TaskSpawn = 0,
    /// Inspect, cancel, or join another task.
    TaskManage = 1,
    /// Map or unmap user memory.
    MemoryMap = 2,
    /// Create, export, or seal shared memory handles.
    MemoryShare = 3,
    /// Enumerate devices.
    DeviceList = 4,
    /// Open a device handle.
    DeviceOpen = 5,
    /// Call an opened device operation.
    DeviceCall = 6,
    /// Invoke model or accelerator inference.
    CognitionInfer = 7,
    /// Query or mutate cognitive memory.
    CognitionMemory = 8,
    /// Derive, revoke, attest, or otherwise administer capabilities.
    SecurityManage = 9,
    /// Append records to the audit stream.
    AuditAppend = 10,
    /// Query audit records.
    AuditQuery = 11,
    /// Verify audit ranges and proofs.
    AuditVerify = 12,
    /// Read or emit debug trace data.
    DebugTrace = 13,
    /// Run privileged kernel maintenance tasks.
    KernelMaintenance = 14,
}

impl Capability {
    /// Returns the bit mask for this capability.
    pub const fn bit(self) -> u64 {
        1u64 << (self as u8)
    }

    /// Stable human-readable name for diagnostics and docs.
    pub const fn name(self) -> &'static str {
        match self {
            Self::TaskSpawn => "task.spawn",
            Self::TaskManage => "task.manage",
            Self::MemoryMap => "memory.map",
            Self::MemoryShare => "memory.share",
            Self::DeviceList => "device.list",
            Self::DeviceOpen => "device.open",
            Self::DeviceCall => "device.call",
            Self::CognitionInfer => "cognition.infer",
            Self::CognitionMemory => "cognition.memory",
            Self::SecurityManage => "security.manage",
            Self::AuditAppend => "audit.append",
            Self::AuditQuery => "audit.query",
            Self::AuditVerify => "audit.verify",
            Self::DebugTrace => "debug.trace",
            Self::KernelMaintenance => "kernel.maintenance",
        }
    }
}

/// Mask of all currently defined capability bits.
pub const KNOWN_CAPABILITY_BITS: u64 = Capability::TaskSpawn.bit()
    | Capability::TaskManage.bit()
    | Capability::MemoryMap.bit()
    | Capability::MemoryShare.bit()
    | Capability::DeviceList.bit()
    | Capability::DeviceOpen.bit()
    | Capability::DeviceCall.bit()
    | Capability::CognitionInfer.bit()
    | Capability::CognitionMemory.bit()
    | Capability::SecurityManage.bit()
    | Capability::AuditAppend.bit()
    | Capability::AuditQuery.bit()
    | Capability::AuditVerify.bit()
    | Capability::DebugTrace.bit()
    | Capability::KernelMaintenance.bit();

/// Compact set of authority bits carried by tasks and handles.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CapabilitySet {
    bits: u64,
}

impl CapabilitySet {
    /// Empty set used for deny-by-default callers.
    pub const EMPTY: Self = Self { bits: 0 };

    /// Constructs a set containing a single capability.
    pub const fn single(capability: Capability) -> Self {
        Self {
            bits: capability.bit(),
        }
    }

    /// Constructs a set from raw bits after rejecting reserved authority bits.
    pub const fn from_bits(bits: u64) -> KernelResult<Self> {
        if bits & !KNOWN_CAPABILITY_BITS == 0 {
            Ok(Self { bits })
        } else {
            Err(KernelError::ReservedBits)
        }
    }

    /// Constructs a set from known bits without validation.
    ///
    /// Use this only for constants built from [`Capability`] values.
    pub const fn from_known_bits(bits: u64) -> Self {
        Self { bits }
    }

    /// Returns the raw authority mask.
    pub const fn bits(self) -> u64 {
        self.bits
    }

    /// Returns `true` when no authority is present.
    pub const fn is_empty(self) -> bool {
        self.bits == 0
    }

    /// Returns `true` when this set contains the capability.
    pub const fn contains(self, capability: Capability) -> bool {
        self.bits & capability.bit() != 0
    }

    /// Returns `true` when all capabilities in `required` are present.
    pub const fn contains_all(self, required: Self) -> bool {
        self.bits & required.bits == required.bits
    }

    /// Returns a set with an additional known capability.
    pub const fn with(self, capability: Capability) -> Self {
        Self {
            bits: self.bits | capability.bit(),
        }
    }

    /// Returns the intersection of two capability sets.
    pub const fn intersect(self, other: Self) -> Self {
        Self {
            bits: self.bits & other.bits,
        }
    }

    /// Derives an attenuated set from a parent authority set.
    pub const fn derive(self, requested: Self) -> KernelResult<Self> {
        if self.contains_all(requested) {
            Ok(requested)
        } else {
            Err(KernelError::MissingCapability)
        }
    }

    /// Ensures that a caller holds `required`.
    pub const fn require(self, required: Capability) -> KernelResult<()> {
        if self.contains(required) {
            Ok(())
        } else {
            Err(KernelError::MissingCapability)
        }
    }
}

/// ABI-safe capability handle metadata.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CapabilityHandle {
    /// Registry-assigned handle identifier. Zero is invalid.
    pub id: u64,
    /// Attenuated rights represented by [`CapabilitySet::bits`].
    pub rights: u64,
    /// Task that owns this handle.
    pub owner_task: TaskId,
    /// Monotonic generation used to avoid stale-handle reuse.
    pub generation: u32,
}

impl CapabilityHandle {
    /// Returns an invalid zero handle.
    pub const fn invalid() -> Self {
        Self {
            id: 0,
            rights: 0,
            owner_task: 0,
            generation: 0,
        }
    }

    /// Returns the handle rights as a validated capability set.
    pub const fn rights(self) -> KernelResult<CapabilitySet> {
        CapabilitySet::from_bits(self.rights)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CapabilityRecord {
    handle: CapabilityHandle,
    revoked: bool,
}

impl CapabilityRecord {
    const EMPTY: Self = Self {
        handle: CapabilityHandle::invalid(),
        revoked: true,
    };
}

/// Bounded capability registry used by the MVK host-mode kernel skeleton.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapabilityRegistry {
    records: [CapabilityRecord; MAX_CAPABILITY_RECORDS],
    next_id: u64,
    next_generation: u32,
}

impl CapabilityRegistry {
    /// Creates an empty registry.
    pub const fn new() -> Self {
        Self {
            records: [CapabilityRecord::EMPTY; MAX_CAPABILITY_RECORDS],
            next_id: 1,
            next_generation: 1,
        }
    }

    /// Issues a new root handle for a task.
    ///
    /// This is intended for bootstrapping and tests; production issuance should
    /// be mediated by the security subsystem and audited by the caller.
    pub fn issue(
        &mut self,
        owner_task: TaskId,
        rights: CapabilitySet,
    ) -> KernelResult<CapabilityHandle> {
        let slot = self
            .records
            .iter_mut()
            .find(|record| record.handle.id == 0 || record.revoked)
            .ok_or(KernelError::CapacityExceeded)?;

        let handle = CapabilityHandle {
            id: self.next_id,
            rights: rights.bits(),
            owner_task,
            generation: self.next_generation,
        };
        self.next_id = self.next_id.checked_add(1).ok_or(KernelError::Internal)?;
        self.next_generation = self.next_generation.checked_add(1).unwrap_or(1);
        *slot = CapabilityRecord {
            handle,
            revoked: false,
        };
        Ok(handle)
    }

    /// Derives a child handle from an existing parent handle.
    ///
    /// Requested rights must be a subset of parent rights; otherwise the method
    /// fails closed with [`KernelError::MissingCapability`].
    pub fn derive(
        &mut self,
        parent: CapabilityHandle,
        owner_task: TaskId,
        requested: CapabilitySet,
    ) -> KernelResult<CapabilityHandle> {
        let parent_rights = self.resolve(parent)?;
        let child_rights = parent_rights.derive(requested)?;
        self.issue(owner_task, child_rights)
    }

    /// Revokes a handle.
    pub fn revoke(&mut self, handle: CapabilityHandle) -> KernelResult<()> {
        let record = self
            .records
            .iter_mut()
            .find(|record| {
                !record.revoked
                    && record.handle.id == handle.id
                    && record.handle.generation == handle.generation
            })
            .ok_or(KernelError::NotFound)?;
        record.revoked = true;
        Ok(())
    }

    /// Resolves a live handle to its rights.
    pub fn resolve(&self, handle: CapabilityHandle) -> KernelResult<CapabilitySet> {
        if handle.id == 0 {
            return Err(KernelError::NotFound);
        }

        let record = self
            .records
            .iter()
            .find(|record| {
                !record.revoked
                    && record.handle.id == handle.id
                    && record.handle.generation == handle.generation
            })
            .ok_or(KernelError::NotFound)?;
        CapabilitySet::from_bits(record.handle.rights)
    }

    /// Returns `true` when the handle is live and contains `required`.
    pub fn handle_contains(
        &self,
        handle: CapabilityHandle,
        required: Capability,
    ) -> KernelResult<bool> {
        Ok(self.resolve(handle)?.contains(required))
    }
}

impl Default for CapabilityRegistry {
    fn default() -> Self {
        Self::new()
    }
}
