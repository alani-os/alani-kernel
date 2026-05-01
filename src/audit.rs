//! Structured audit handoff records and an in-memory host-mode audit log.
//!
//! The kernel skeleton treats audit events as structured data with explicit
//! data classification. Security denials and authority changes are never
//! sampled away by this layer.

use crate::capability::TaskId;
use crate::error::KernelStatus;
use crate::syscall::{SyscallNumber, TraceContext};

/// Maximum audit events retained by the host-mode ring buffer.
pub const MAX_AUDIT_EVENTS: usize = 128;

/// Security and operational audit event taxonomy.
#[repr(u16)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuditEventKind {
    /// A task was spawned.
    TaskSpawn,
    /// A task changed lifecycle state.
    TaskStateChanged,
    /// A memory mapping or unmapping was requested.
    MemoryMap,
    /// Shared memory was created or sealed.
    MemoryShare,
    /// A device was opened.
    DeviceOpen,
    /// A device operation was called.
    DeviceCall,
    /// A cognitive inference syscall was mediated.
    CognitionInfer,
    /// Cognitive memory was queried or mutated.
    CognitiveMemory,
    /// A capability was derived or revoked.
    CapabilityChanged,
    /// A security decision was made.
    SecurityDecision,
    /// An audit append operation was requested.
    AuditAppend,
    /// Audit records were queried.
    AuditQuery,
    /// Audit range verification was requested.
    AuditVerify,
    /// A fault or panic diagnostic was emitted.
    Fault,
}

/// Severity assigned to an audit event.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuditSeverity {
    /// Informational event.
    Info,
    /// Expected operational state change.
    Notice,
    /// Suspicious or denied action.
    Warning,
    /// Security or integrity relevant failure.
    Critical,
}

/// Data classification for attached diagnostic fields.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DataClass {
    /// Safe for public release.
    Public,
    /// Operational metadata that should be visible to operators.
    Operational,
    /// Sensitive content that requires policy-controlled redaction.
    Sensitive,
    /// Secret material that must not be exported.
    Secret,
}

/// One structured audit event.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuditEvent {
    /// Monotonic audit sequence.
    pub sequence: u64,
    /// Event kind.
    pub kind: AuditEventKind,
    /// Event severity.
    pub severity: AuditSeverity,
    /// Task associated with the event, or zero when not task-specific.
    pub task_id: TaskId,
    /// Syscall associated with the event, if any.
    pub syscall: Option<SyscallNumber>,
    /// Result status associated with the event.
    pub status: KernelStatus,
    /// Propagated trace context.
    pub trace: TraceContext,
    /// Classification of attached fields.
    pub data_class: DataClass,
    /// Stable reason label.
    pub reason: &'static str,
}

impl AuditEvent {
    /// Empty event used to initialize the ring buffer.
    pub const EMPTY: Self = Self {
        sequence: 0,
        kind: AuditEventKind::SecurityDecision,
        severity: AuditSeverity::Info,
        task_id: 0,
        syscall: None,
        status: KernelStatus::Ok,
        trace: TraceContext::empty(),
        data_class: DataClass::Public,
        reason: "",
    };
}

/// Sink trait for future audit backends.
pub trait AuditSink {
    /// Appends an event to a backend.
    fn append(&mut self, event: AuditEvent);
}

/// Bounded in-memory audit log used in host-mode tests and skeleton dispatch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditLog {
    events: [AuditEvent; MAX_AUDIT_EVENTS],
    cursor: usize,
    count: usize,
    next_sequence: u64,
}

impl AuditLog {
    /// Creates an empty audit log.
    pub const fn new() -> Self {
        Self {
            events: [AuditEvent::EMPTY; MAX_AUDIT_EVENTS],
            cursor: 0,
            count: 0,
            next_sequence: 1,
        }
    }

    /// Number of retained events.
    pub const fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` when no events are retained.
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Appends an event and assigns a monotonic sequence.
    pub fn append(&mut self, mut event: AuditEvent) {
        event.sequence = self.next_sequence;
        self.next_sequence = self.next_sequence.wrapping_add(1);
        self.events[self.cursor] = event;
        self.cursor = (self.cursor + 1) % MAX_AUDIT_EVENTS;
        if self.count < MAX_AUDIT_EVENTS {
            self.count += 1;
        }
    }

    /// Records a syscall outcome using descriptor-provided audit metadata.
    pub fn record_syscall(
        &mut self,
        kind: AuditEventKind,
        task_id: TaskId,
        syscall: SyscallNumber,
        status: KernelStatus,
        trace: TraceContext,
        reason: &'static str,
    ) {
        let severity = if status.is_ok() {
            AuditSeverity::Notice
        } else if status == KernelStatus::PermissionDenied {
            AuditSeverity::Critical
        } else {
            AuditSeverity::Warning
        };
        self.append(AuditEvent {
            sequence: 0,
            kind,
            severity,
            task_id,
            syscall: Some(syscall),
            status,
            trace,
            data_class: DataClass::Operational,
            reason,
        });
    }

    /// Returns the most recently appended event, if any.
    pub fn last(&self) -> Option<AuditEvent> {
        if self.count == 0 {
            return None;
        }
        let index = if self.cursor == 0 {
            MAX_AUDIT_EVENTS - 1
        } else {
            self.cursor - 1
        };
        Some(self.events[index])
    }

    /// Returns an event by chronological index among retained entries.
    pub fn get(&self, index: usize) -> Option<AuditEvent> {
        if index >= self.count {
            return None;
        }
        let oldest = if self.count == MAX_AUDIT_EVENTS {
            self.cursor
        } else {
            0
        };
        let physical = (oldest + index) % MAX_AUDIT_EVENTS;
        Some(self.events[physical])
    }

    /// Returns the sequence assigned to the next appended event.
    pub const fn next_sequence(&self) -> u64 {
        self.next_sequence
    }
}

impl AuditSink for AuditLog {
    fn append(&mut self, event: AuditEvent) {
        Self::append(self, event);
    }
}

impl Default for AuditLog {
    fn default() -> Self {
        Self::new()
    }
}
