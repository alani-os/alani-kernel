//! Device registry and mediation contracts.
//!
//! Drivers live behind this small boundary: a descriptor declares class,
//! lifecycle, supported operations, DMA behavior, and required capabilities.
//! Host-mode tests can register mock devices without using unsafe register
//! access or platform-specific code.

use crate::capability::{Capability, CapabilitySet};
use crate::error::{KernelError, KernelResult};

/// Maximum devices tracked by the host-mode registry.
pub const MAX_DEVICES: usize = 32;

/// Stable device identifier.
pub type DeviceId = u64;

/// Device classes from the device model.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeviceClass {
    /// Early or runtime console.
    Console,
    /// Timer source.
    Timer,
    /// Block storage.
    Block,
    /// Entropy source.
    Entropy,
    /// Simulated network endpoint.
    NetworkSim,
    /// Simulated sensor endpoint.
    SensorSim,
    /// Model or tensor accelerator.
    Accelerator,
    /// Cognitive memory device.
    Memory,
    /// Audit persistence device.
    AuditStorage,
}

/// Device lifecycle states.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeviceLifecycle {
    /// Discovered but not probed.
    Discovered,
    /// Probe is in progress.
    Probed,
    /// Registered for use.
    Registered,
    /// Configured and available.
    Configured,
    /// Opened by a caller.
    Open,
    /// Suspended.
    Suspended,
    /// Removed or unavailable.
    Removed,
}

/// DMA policy declared by a device.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DmaPolicy {
    /// Device does not perform DMA.
    None,
    /// Device may DMA only pinned, bounded user buffers.
    PinnedUser,
    /// Device may DMA only kernel-owned buffers.
    KernelOnly,
}

/// Device operation identifiers used by generic device calls.
#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeviceOperation {
    /// Query device metadata.
    Query = 0,
    /// Read from device.
    Read = 1,
    /// Write to device.
    Write = 2,
    /// Submit an operation.
    Submit = 3,
    /// Cancel an operation.
    Cancel = 4,
    /// Reset the device.
    Reset = 5,
    /// Query device health.
    Health = 6,
}

impl DeviceOperation {
    /// Converts a raw opcode to a known generic operation.
    pub const fn from_raw(raw: u64) -> Option<Self> {
        match raw {
            0 => Some(Self::Query),
            1 => Some(Self::Read),
            2 => Some(Self::Write),
            3 => Some(Self::Submit),
            4 => Some(Self::Cancel),
            5 => Some(Self::Reset),
            6 => Some(Self::Health),
            _ => None,
        }
    }
}

/// Static metadata for one device.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeviceDescriptor {
    /// Stable device identifier.
    pub id: DeviceId,
    /// Device class.
    pub class: DeviceClass,
    /// Current lifecycle state.
    pub lifecycle: DeviceLifecycle,
    /// Capabilities required to open or operate the device.
    pub required_capabilities: CapabilitySet,
    /// Supported operation bits indexed by [`DeviceOperation`] values.
    pub supported_operations: u32,
    /// Maximum input buffer size in bytes.
    pub max_input_len: u32,
    /// Maximum output buffer size in bytes.
    pub max_output_len: u32,
    /// DMA behavior declaration.
    pub dma_policy: DmaPolicy,
}

impl DeviceDescriptor {
    /// Empty descriptor used for registry initialization.
    pub const EMPTY: Self = Self {
        id: 0,
        class: DeviceClass::Console,
        lifecycle: DeviceLifecycle::Removed,
        required_capabilities: CapabilitySet::EMPTY,
        supported_operations: 0,
        max_input_len: 0,
        max_output_len: 0,
        dma_policy: DmaPolicy::None,
    };

    /// Returns `true` when this descriptor supports `operation`.
    pub const fn supports(self, operation: DeviceOperation) -> bool {
        self.supported_operations & (1u32 << (operation as u32)) != 0
    }

    /// Returns `true` when the descriptor is callable by normal tasks.
    pub const fn is_available(self) -> bool {
        matches!(
            self.lifecycle,
            DeviceLifecycle::Registered | DeviceLifecycle::Configured | DeviceLifecycle::Open
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DeviceSlot {
    occupied: bool,
    descriptor: DeviceDescriptor,
}

impl DeviceSlot {
    const EMPTY: Self = Self {
        occupied: false,
        descriptor: DeviceDescriptor::EMPTY,
    };
}

/// Bounded device registry with duplicate-ID and authorization checks.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeviceRegistry {
    slots: [DeviceSlot; MAX_DEVICES],
}

impl DeviceRegistry {
    /// Creates an empty registry.
    pub const fn new() -> Self {
        Self {
            slots: [DeviceSlot::EMPTY; MAX_DEVICES],
        }
    }

    /// Registers a device descriptor.
    pub fn register(&mut self, descriptor: DeviceDescriptor) -> KernelResult<()> {
        if descriptor.id == 0 {
            return Err(KernelError::InvalidArgument);
        }
        if self.get(descriptor.id).is_some() {
            return Err(KernelError::Duplicate);
        }
        let slot = self
            .slots
            .iter_mut()
            .find(|slot| !slot.occupied)
            .ok_or(KernelError::CapacityExceeded)?;
        *slot = DeviceSlot {
            occupied: true,
            descriptor,
        };
        Ok(())
    }

    /// Looks up a registered device.
    pub fn get(&self, id: DeviceId) -> Option<DeviceDescriptor> {
        self.slots
            .iter()
            .find(|slot| slot.occupied && slot.descriptor.id == id)
            .map(|slot| slot.descriptor)
    }

    /// Returns the number of registered devices.
    pub fn len(&self) -> usize {
        self.slots.iter().filter(|slot| slot.occupied).count()
    }

    /// Returns `true` when the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Validates that a caller may open a device.
    pub fn authorize_open(
        &self,
        id: DeviceId,
        caller: CapabilitySet,
    ) -> KernelResult<DeviceDescriptor> {
        caller.require(Capability::DeviceOpen)?;
        let descriptor = self.get(id).ok_or(KernelError::NotFound)?;
        if !descriptor.is_available() {
            return Err(KernelError::Busy);
        }
        if !caller.contains_all(descriptor.required_capabilities) {
            return Err(KernelError::MissingCapability);
        }
        Ok(descriptor)
    }

    /// Validates a generic device call before a driver sees user buffers.
    pub fn authorize_call(
        &self,
        id: DeviceId,
        operation: DeviceOperation,
        caller: CapabilitySet,
        input_len: u64,
        output_len: u64,
    ) -> KernelResult<DeviceDescriptor> {
        caller.require(Capability::DeviceCall)?;
        let descriptor = self.get(id).ok_or(KernelError::NotFound)?;
        if !descriptor.is_available() {
            return Err(KernelError::Busy);
        }
        if !descriptor.supports(operation) {
            return Err(KernelError::InvalidArgument);
        }
        if !caller.contains_all(descriptor.required_capabilities) {
            return Err(KernelError::MissingCapability);
        }
        if input_len > u64::from(descriptor.max_input_len)
            || output_len > u64::from(descriptor.max_output_len)
        {
            return Err(KernelError::BufferTooLarge);
        }
        Ok(descriptor)
    }
}

impl Default for DeviceRegistry {
    fn default() -> Self {
        Self::new()
    }
}
