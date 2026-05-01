//! Fault records, panic diagnostics, and a bounded diagnostic ring.
//!
//! Fatal invariants may still panic in the final kernel, but this module gives
//! subsystems a typed diagnostic path to use before escalation.

use crate::capability::TaskId;
use crate::error::{KernelError, KernelStatus};
use crate::syscall::TraceContext;

/// Maximum fault records retained by the host-mode diagnostic ring.
pub const MAX_FAULT_RECORDS: usize = 64;

/// Fault taxonomy for kernel diagnostics.
#[repr(u16)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FaultKind {
    /// Kernel panic path.
    Panic,
    /// Page or address translation fault.
    PageFault,
    /// Unknown or invalid syscall.
    InvalidSyscall,
    /// Capability or policy denial.
    CapabilityDenied,
    /// Device mediation or driver failure.
    DeviceError,
    /// Nested fatal fault.
    DoubleFault,
    /// Internal invariant violation.
    InvariantViolation,
}

/// Diagnostic severity.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FaultSeverity {
    /// Informational diagnostic.
    Info,
    /// Recoverable warning.
    Warning,
    /// Recoverable error.
    Error,
    /// Fatal condition.
    Fatal,
}

/// Kernel initialization or runtime phase associated with a fault.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FaultPhase {
    /// Before boot handoff parsing.
    PreBoot,
    /// During deterministic boot initialization.
    Boot,
    /// During normal task execution.
    Runtime,
    /// During shutdown or panic handling.
    Shutdown,
}

/// One structured diagnostic fault record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FaultRecord {
    /// Monotonic diagnostic sequence.
    pub sequence: u64,
    /// Fault kind.
    pub kind: FaultKind,
    /// Fault severity.
    pub severity: FaultSeverity,
    /// Task associated with the fault, or zero when not task-specific.
    pub task_id: TaskId,
    /// Address associated with the fault, if any.
    pub address: u64,
    /// Stable status code associated with the fault.
    pub status: KernelStatus,
    /// Kernel phase where the fault occurred.
    pub phase: FaultPhase,
    /// Trace context associated with the fault.
    pub trace: TraceContext,
    /// Stable reason label.
    pub reason: &'static str,
}

impl FaultRecord {
    /// Empty sentinel record for ring initialization.
    pub const EMPTY: Self = Self {
        sequence: 0,
        kind: FaultKind::InvariantViolation,
        severity: FaultSeverity::Info,
        task_id: 0,
        address: 0,
        status: KernelStatus::Ok,
        phase: FaultPhase::PreBoot,
        trace: TraceContext::empty(),
        reason: "",
    };

    /// Creates a record from a typed kernel error.
    pub const fn from_error(
        kind: FaultKind,
        severity: FaultSeverity,
        task_id: TaskId,
        address: u64,
        error: KernelError,
        phase: FaultPhase,
        trace: TraceContext,
    ) -> Self {
        Self {
            sequence: 0,
            kind,
            severity,
            task_id,
            address,
            status: error.status(),
            phase,
            trace,
            reason: error.reason(),
        }
    }
}

/// Bounded fault reporter used before a persistent diagnostic backend exists.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FaultReporter {
    records: [FaultRecord; MAX_FAULT_RECORDS],
    cursor: usize,
    count: usize,
    next_sequence: u64,
}

impl FaultReporter {
    /// Creates an empty reporter.
    pub const fn new() -> Self {
        Self {
            records: [FaultRecord::EMPTY; MAX_FAULT_RECORDS],
            cursor: 0,
            count: 0,
            next_sequence: 1,
        }
    }

    /// Number of retained fault records.
    pub const fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` when no faults are retained.
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Records a fault and assigns a monotonic sequence.
    pub fn record(&mut self, mut record: FaultRecord) {
        record.sequence = self.next_sequence;
        self.next_sequence = self.next_sequence.wrapping_add(1);
        self.records[self.cursor] = record;
        self.cursor = (self.cursor + 1) % MAX_FAULT_RECORDS;
        if self.count < MAX_FAULT_RECORDS {
            self.count += 1;
        }
    }

    /// Records a typed error with common fields.
    pub fn record_error(
        &mut self,
        kind: FaultKind,
        severity: FaultSeverity,
        task_id: TaskId,
        error: KernelError,
        phase: FaultPhase,
        trace: TraceContext,
    ) {
        self.record(FaultRecord::from_error(
            kind, severity, task_id, 0, error, phase, trace,
        ));
    }

    /// Returns the most recent fault record.
    pub fn last(&self) -> Option<FaultRecord> {
        if self.count == 0 {
            return None;
        }
        let index = if self.cursor == 0 {
            MAX_FAULT_RECORDS - 1
        } else {
            self.cursor - 1
        };
        Some(self.records[index])
    }

    /// Builds and records a final panic diagnostic.
    pub fn record_panic(
        &mut self,
        task_id: TaskId,
        phase: FaultPhase,
        trace: TraceContext,
        reason: &'static str,
    ) {
        self.record(FaultRecord {
            sequence: 0,
            kind: FaultKind::Panic,
            severity: FaultSeverity::Fatal,
            task_id,
            address: 0,
            status: KernelStatus::Internal,
            phase,
            trace,
            reason,
        });
    }
}

impl Default for FaultReporter {
    fn default() -> Self {
        Self::new()
    }
}
