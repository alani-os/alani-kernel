//! Deterministic kernel initialization phase tracking.
//!
//! The real boot path will live behind platform-specific code. This module
//! models the normative initialization order so host tests can verify phase
//! ordering and boot diagnostics before QEMU or hardware support exists.

use crate::error::{KernelError, KernelResult};

/// Ordered kernel initialization phases.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BootPhase {
    /// Bootloader handoff and manifest parsing.
    LoaderHandoff,
    /// Early console setup.
    EarlyConsole,
    /// CPU feature validation.
    CpuFeatures,
    /// Boot memory map preservation.
    MemoryMap,
    /// Page table setup.
    Paging,
    /// Interrupt descriptor setup.
    Interrupts,
    /// Allocator initialization.
    Allocator,
    /// Timer initialization.
    Timer,
    /// Scheduler initialization.
    Scheduler,
    /// Device discovery and registration.
    Devices,
    /// Security and policy initialization.
    Security,
    /// Audit and observability handoff.
    Audit,
    /// Syscall table activation.
    Syscalls,
    /// Init runtime spawn.
    RuntimeSpawn,
}

impl BootPhase {
    /// Stable phase name for logs and diagnostics.
    pub const fn name(self) -> &'static str {
        match self {
            Self::LoaderHandoff => "loader_handoff",
            Self::EarlyConsole => "early_console",
            Self::CpuFeatures => "cpu_features",
            Self::MemoryMap => "memory_map",
            Self::Paging => "paging",
            Self::Interrupts => "interrupts",
            Self::Allocator => "allocator",
            Self::Timer => "timer",
            Self::Scheduler => "scheduler",
            Self::Devices => "devices",
            Self::Security => "security",
            Self::Audit => "audit",
            Self::Syscalls => "syscalls",
            Self::RuntimeSpawn => "runtime_spawn",
        }
    }
}

/// Number of deterministic boot phases.
pub const BOOT_PHASE_COUNT: usize = 14;

/// Normative deterministic initialization order.
pub const BOOT_SEQUENCE: [BootPhase; BOOT_PHASE_COUNT] = [
    BootPhase::LoaderHandoff,
    BootPhase::EarlyConsole,
    BootPhase::CpuFeatures,
    BootPhase::MemoryMap,
    BootPhase::Paging,
    BootPhase::Interrupts,
    BootPhase::Allocator,
    BootPhase::Timer,
    BootPhase::Scheduler,
    BootPhase::Devices,
    BootPhase::Security,
    BootPhase::Audit,
    BootPhase::Syscalls,
    BootPhase::RuntimeSpawn,
];

/// Boot progress tracker.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BootProgress {
    completed: [bool; BOOT_PHASE_COUNT],
    next_index: usize,
}

impl BootProgress {
    /// Creates a tracker with no phases completed.
    pub const fn new() -> Self {
        Self {
            completed: [false; BOOT_PHASE_COUNT],
            next_index: 0,
        }
    }

    /// Returns the next phase expected by the deterministic order.
    pub fn next_expected(&self) -> Option<BootPhase> {
        BOOT_SEQUENCE.get(self.next_index).copied()
    }

    /// Marks the next phase complete, rejecting out-of-order calls.
    pub fn complete(&mut self, phase: BootPhase) -> KernelResult<()> {
        let expected = self.next_expected().ok_or(KernelError::InvalidState)?;
        if expected != phase {
            return Err(KernelError::InvalidState);
        }
        self.completed[self.next_index] = true;
        self.next_index += 1;
        Ok(())
    }

    /// Returns `true` when all boot phases have completed.
    pub const fn is_complete(&self) -> bool {
        self.next_index == BOOT_PHASE_COUNT
    }

    /// Number of completed phases.
    pub const fn completed_count(&self) -> usize {
        self.next_index
    }
}

impl Default for BootProgress {
    fn default() -> Self {
        Self::new()
    }
}
